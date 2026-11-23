#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Opt-in kernel integration tests; make check remains the prerequisite."""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time


AUDIT_CASES = {
    "zero": 1, "mixed": 1, "v1": 2, "v2": 1, "noop": 8,
    "unknown-bits": 1, "failures": 0, "collision": 0, "compat-capset": 1,
    "stale": 2, "threads": 64, "race": 512, "preexec": 0, "exec": 1,
}
KERNEL_CASES = ("exit", "threads", "bounding", "ambient", "procfs")


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def source_root(build):
    for line in (build / "Makefile").read_text().splitlines():
        if line.startswith("abs_top_srcdir = "):
            return Path(line.split(" = ", 1)[1]).resolve()
    raise RuntimeError("Cannot find abs_top_srcdir; configure the build first")


def inventory(build):
    source = source_root(build)
    paths = set()
    for root, dirs, files in os.walk(source):
        dirs[:] = [d for d in dirs if not d.startswith(".") and
                   d not in ("autom4te.cache", "__pycache__") and
                   (source == build or (Path(root) / d).resolve() != build)]
        for name in files:
            if Path(name).suffix in (".c", ".h", ".am", ".ac", ".py", ".i"):
                paths.add(Path(root) / name)
    for name in ("config.h", "config.status", "Makefile",
                 "tests/privileged/Makefile"):
        paths.add(build / name)
    # Include both libtool launchers and real ELF files, plus the selected
    # local library. No installed system libcap-ng is used by these helpers.
    for directory, pattern in (("src/.libs", "libcap-ng.*"),
                               ("tests/privileged", "kernel_workload"),
                               ("tests/privileged/.libs", "kernel_workload"),
                               ("tests/privileged", "cap_audit_live"),
                               ("tests/privileged/.libs", "cap_audit_live"),
                               ("utils/cap-audit", "cap-audit"),
                               ("utils/cap-audit/.libs", "cap-audit"),
                               ("utils/cap-audit", "cap_audit.bpf.o")):
        paths.update(p for p in (build / directory).glob(pattern) if p.is_file())
    return {str(p): digest(p) for p in sorted(paths)}


def prepare(args):
    if os.geteuid() == 0:
        raise RuntimeError("Run prepare as your regular user, not root")
    directory = args.build_dir / "tests/privileged"
    directory.mkdir(parents=True, exist_ok=True)
    receipt = directory / "prepared.json"
    receipt.unlink(missing_ok=True)
    commands = [[sys.executable,
                 str(Path(__file__).resolve().with_name("test_runner.py"))],
                ["make", "-j" + str(args.jobs)],
                ["make", "-j" + str(args.jobs), "check"],
                ["make", "-j" + str(args.jobs), "-C", "tests/privileged",
                 "integration-helpers"]]
    log = directory / "prepare.log"
    with log.open("w") as stream:
        for command in commands:
            print("Running " + " ".join(command), flush=True)
            subprocess.run(command, cwd=args.build_dir, stdout=stream,
                           stderr=subprocess.STDOUT, check=True)
    results = collections.Counter()
    # The binding link check runs make clean after its recursive tests, so
    # counting surviving .trs files would silently omit a binding test.
    for status, count in re.findall(
            r"^# (PASS|SKIP|XFAIL|FAIL|XPASS|ERROR):\s+(\d+)\s*$",
            log.read_text(), re.MULTILINE):
        results[status] += int(count)
    if not results["PASS"] or any(results[key] for key in ("FAIL", "ERROR", "XPASS")):
        raise RuntimeError("Unit-test summaries have no passes or contain failures")
    data = {"schema": 1, "build": str(args.build_dir),
            "source": str(source_root(args.build_dir)),
            "prepared_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "unit_tests": dict(results), "files": inventory(args.build_dir)}
    # Reconfiguring with cap-audit disabled can leave old binaries behind.
    # Availability must follow the tested configuration, not file existence.
    data["cap_audit_enabled"] = "integration_cap_audit = yes" in (
        directory / "Makefile").read_text().splitlines()
    receipt.write_text(json.dumps(data, indent=2) + "\n")
    print("Prepared: {} (unit results: {})".format(receipt, dict(results)))


def verify_build(build):
    path = build / "tests/privileged/prepared.json"
    if not path.is_file():
        raise RuntimeError("No prepared build; run prepare as a regular user first")
    receipt = json.loads(path.read_text())
    if receipt.get("schema") != 1 or receipt.get("build") != str(build):
        raise RuntimeError("Preparation receipt is for a different build")
    current = inventory(build)
    if current != receipt["files"]:
        changed = sorted(p for p in set(current) | set(receipt["files"])
                         if current.get(p) != receipt["files"].get(p))
        raise RuntimeError("Build or sources changed; rerun prepare. First change: "
                           + changed[0])
    return receipt


def read_context(path):
    try:
        return Path(path).read_text().strip()
    except OSError as error:
        return str(error)


def host_context():
    # Values are diagnostic context, never distro/version-based feature gates.
    paths = ("/etc/os-release", "/proc/self/status", "/proc/self/uid_map",
             "/proc/sys/kernel/unprivileged_bpf_disabled",
             "/proc/sys/kernel/perf_event_paranoid",
             "/proc/sys/user/max_mnt_namespaces",
             "/sys/kernel/security/lockdown", "/sys/kernel/security/lsm",
             "/sys/fs/selinux/enforce", "/sys/module/apparmor/parameters/enabled")
    return {"architecture": platform.machine(), "kernel": platform.release(),
            "python": platform.python_version(), "euid": os.geteuid(),
            "context": {p: read_context(p) for p in paths},
            "btf_readable": os.access("/sys/kernel/btf/vmlinux", os.R_OK)}


def execute(command, log, library_path=None):
    # A new process group lets timeout/interrupt cleanup include fixture threads
    # and children. Closing the helpers' BPF fds detaches their probes.
    env = os.environ.copy()
    for name in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT"):
        env.pop(name, None)
    if library_path is not None:
        env["LD_LIBRARY_PATH"] = str(library_path)
    with log.open("w") as stream:
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT,
                                   start_new_session=True, env=env)
        try:
            status = process.wait(timeout=45)
        except subprocess.TimeoutExpired:
            status = 124
        finally:
            # Also stop descendants if the leader exited unexpectedly.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    return status, log.read_text(errors="replace")


def copy_program(source, directory):
    # Run the actual ELF, not a libtool launcher which would reintroduce the
    # private build directory through LD_LIBRARY_PATH after staging.
    with source.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            source = source.parent / ".libs" / source.name
    target = directory / source.name
    # Copy contents only: retain neither build-user ownership nor file caps,
    # ACLs or set-ID bits. The staged file belongs to the runner's UID.
    shutil.copyfile(source, target)
    target.chmod(0o700)


def records(text):
    result = {"EXP": collections.defaultdict(list),
              "OBS": collections.defaultdict(list)}
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] in result:
            if len(fields) != 6:
                raise AssertionError("Malformed event record: " + line)
            tag, tid, pid, e, p, i = fields
            tid, pid = int(tid), int(pid)
            masks = tuple(int(m, 16) for m in (e, p, i))
            if (pid <= 0 or tid < 0 or (tag == "EXP" and tid == 0) or
                    any(m < 0 or m >= 1 << 64 for m in masks)):
                raise AssertionError("Invalid event record: " + line)
            result[tag][(tid, pid)].append(masks)
    return result


def compare_events(text, case):
    data = records(text)
    if sum(map(len, data["EXP"].values())) != AUDIT_CASES[case]:
        raise AssertionError("Wrong number of independent capget observations")
    if case == "threads" and len(data["EXP"]) != 2:
        raise AssertionError("Two distinct capset callers were not exercised")
    grouped = {}
    for tag in ("EXP", "OBS"):
        by_pid = collections.defaultdict(list)
        for (tid, pid), values in data[tag].items():
            if tag == "EXP" and case != "threads" and pid in by_pid:
                raise AssertionError("Unexpected concurrent capset callers")
            by_pid[pid].extend(values)
        # Production CAPSET events carry TGID but leave TID zero. Concurrent
        # callers have no defined cross-thread order: compare complete triples
        # and multiplicities, not independently aggregated capability bits.
        grouped[tag] = ({p: collections.Counter(v) for p, v in by_pid.items()}
                        if case == "threads" else dict(by_pid))
    if grouped["EXP"] != grouped["OBS"]:
        raise AssertionError(
            "BPF mask triples, process IDs, counts, or order differ from capget")
    if case == "race":
        values = {m[0] for group in data["EXP"].values() for m in group}
        if len(values) < 2:
            return "Raced workload sampled only one mask; repeat this run"
    return None


def compare_cli(text, case):
    if "Application exited with status 77" in text:
        return "Workload prerequisite unavailable; see log"
    if "Application exited with status 0" not in text:
        raise AssertionError("Audited workload did not exit successfully")
    obj, _ = json.JSONDecoder().raw_decode(text[text.index("{\n"):])
    expected = [(pid, m) for (_, pid), v in records(text)["EXP"].items() for m in v]
    observed = [(int(pid), tuple(int(m, 16) for m in (e, p, i)))
                for pid, e, p, i in re.findall(
        r"\[CAPSET\] pid=(\d+) effective=0x([0-9a-f]+) "
        r"permitted=0x([0-9a-f]+) inheritable=0x([0-9a-f]+)", text)]
    if len(expected) != AUDIT_CASES[case] or observed != expected:
        raise AssertionError("CLI masks/counts differ from capget")
    if (obj["successful_capset_calls"] != len(expected) or
            obj["capability_drop_observed"] != bool(expected)):
        raise AssertionError("CLI success count or operational phase is incorrect")
    return None


class Run:
    def __init__(self, args, receipt):
        self.args = args
        if args.output:
            args.output.mkdir(parents=True, exist_ok=False)
            self.directory = args.output
        else:
            self.directory = Path(tempfile.mkdtemp(prefix="libcap-ng-integration-"))
        self.directory = self.directory.resolve()
        self.results = []
        self.receipt = receipt
        (self.directory / "environment.json").write_text(
            json.dumps(host_context(), indent=2) + "\n")
        print("Results: " + str(self.directory), flush=True)

    def stage(self, directory):
        self.fixtures = directory
        build = self.args.build_dir
        copy_program(build / "tests/privileged/kernel_workload", directory)
        if self.receipt["cap_audit_enabled"]:
            copy_program(build / "tests/privileged/cap_audit_live", directory)
            copy_program(build / "utils/cap-audit/cap-audit", directory)
        # Root loses DAC overrides in the exec fixtures. Both binaries and
        # their local library must remain readable without those capabilities,
        # even when the original build is in another user's private home.
        for source in (build / "src/.libs").glob("libcap-ng.so*"):
            shutil.copyfile(source, directory / source.name)

    def result(self, name, status, reason, applicable=True):
        self.results.append(dict(name=name, status=status, reason=reason,
                                 applicable=applicable))
        print("{} {}: {}".format(status, name, reason), flush=True)
        return status == "PASS"

    def test(self, name, command, validator=None):
        try:
            status, text = execute([str(c) for c in command],
                                   self.directory / (name + ".log"),
                                   self.fixtures)
        except PermissionError as error:
            return self.result(name, "SKIP", "Execution unavailable: " + str(error))
        if status == 77:
            reason = next((line for line in text.splitlines()
                           if "UNAVAILABLE:" in line or "SKIP:" in line), text[-500:])
            return self.result(name, "SKIP", reason or "Prerequisite unavailable")
        if status:
            detail = text.strip().splitlines()[-1][:300] if text.strip() else "no output"
            return self.result(name, "FAIL", "exit {}: {}; see {}.log".format(
                status, detail, name))
        try:
            incomplete = validator(text) if validator else None
            if incomplete:
                return self.result(name, "SKIP", incomplete)
        except (AssertionError, ValueError, KeyError) as error:
            return self.result(name, "FAIL", str(error) + "; see " + name + ".log")
        return self.result(name, "PASS", "checks passed")

    def finish(self):
        failed = any(r["status"] == "FAIL" for r in self.results)
        incomplete = any(r["status"] == "SKIP" and r["applicable"]
                         for r in self.results)
        outcome = "FAIL" if failed else "INCOMPLETE" if incomplete else "PASS"
        report = {"outcome": outcome, "mode": self.args.action,
                  "suite": self.args.suite, "prepared_build": self.receipt,
                  "results": self.results}
        (self.directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(outcome + (" (prerequisites only; tests were not run)"
                         if self.args.action == "probe" else ""))
        return 1 if failed else 2 if incomplete else 0


def integrate(args):
    receipt = verify_build(args.build_dir)
    if args.action == "run" and os.geteuid() != 0:
        raise RuntimeError(
            "Run requires root; probe can inspect the current user's access")
    run = Run(args, receipt)
    with tempfile.TemporaryDirectory(prefix="fixtures-", dir=run.directory) as path:
        run.stage(Path(path))
        return run_suites(run)


def run_suites(run):
    args = run.args
    helpers = run.fixtures
    if not run.test("probe-exec", [helpers / "kernel_workload", "probe-exec"]):
        return run.finish()
    if args.suite in ("all", "kernel"):
        run.test("probe-caps", [helpers / "kernel_workload", "probe-caps"])
        mount_ok = run.test("probe-mount", [helpers / "kernel_workload", "probe-mount"])
        if args.action == "run":
            for case in KERNEL_CASES:
                if case == "procfs" and not mount_ok:
                    run.result("kernel-procfs", "SKIP",
                               "Private mount namespace unavailable")
                    continue
                run.test("kernel-" + case, [helpers / "kernel_workload", case])
    if args.suite in ("all", "cap-audit"):
        helper = helpers / "cap_audit_live"
        if not run.receipt["cap_audit_enabled"]:
            run.result("probe-bpf", "SKIP",
                       "cap-audit not built; configure --enable-cap-audit and prepare")
        else:
            ready = run.test("probe-bpf", [helper, "--probe", "unused"])
            if ready and args.action == "run":
                for case in AUDIT_CASES:
                    if (case in ("collision", "compat-capset") and
                            platform.machine() != "x86_64"):
                        run.result("bpf-" + case, "SKIP",
                                   "x86_64 compat fixture does not apply", False)
                        continue
                    run.test("bpf-" + case, [helper, "--trace", case],
                             lambda text, case=case: compare_events(text, case))
                for case in ("zero", "mixed", "v1", "failures", "collision",
                             "compat-capset"):
                    if (case in ("collision", "compat-capset") and
                            platform.machine() != "x86_64"):
                        continue
                    command = [helpers / "cap-audit",
                               "-v", "-j", "--", helper, "--work", case]
                    run.test("cli-" + case, command,
                             lambda text, case=case: compare_cli(text, case))
    return run.finish()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "probe", "run"))
    parser.add_argument("--build-dir", type=Path, default=Path.cwd())
    parser.add_argument("--suite", choices=("all", "kernel", "cap-audit"),
                        default="all")
    parser.add_argument("--output", type=Path,
                        help="new directory for retained run diagnostics")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    args = parser.parse_args()
    args.build_dir = args.build_dir.resolve()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    os.umask(0o077)
    # SIGINT becomes KeyboardInterrupt automatically; give SIGTERM the same
    # process-group cleanup path instead of leaving a detached tracer running.
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.action == "prepare":
            prepare(args)
            return 0
        return integrate(args)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print("ERROR: {}".format(error), file=sys.stderr)
        if args.action == "prepare":
            print("Build/test diagnostics: " +
                  str(args.build_dir / "tests/privileged/prepare.log"),
                  file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted; active fixture process group stopped", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
