#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check the integration oracle itself before trusting privileged results."""
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

from run import (compare_cli, compare_events, compare_follow_cli,
                 compare_namespace_cli, copy_program, execute)


def record(tag, masks, tid=10, pid=10):
    return "{} {} {} {:016x} {:016x} {:016x}\n".format(tag, tid, pid, *masks)


class StagingTest(unittest.TestCase):
    def test_report_channel(self):
        with tempfile.TemporaryDirectory() as path:
            log, report = Path(path) / "run.log", Path(path) / "report.json"
            status, text = execute(
                [sys.executable, "-c",
                 "import sys; print('{}'); print('workload', file=sys.stderr)"],
                log, report=report)
            self.assertEqual(status, 0)
            self.assertEqual(text, "workload\n")
            self.assertEqual(json.loads(report.read_text()), {})
    def test_private_binary(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            source = root / "helper"
            source.write_bytes(b"\x7fELFfixture")
            source.chmod(0o4750)
            staged = root / "staged"
            staged.mkdir()
            copy_program(source, staged)
            target = staged / source.name
            self.assertEqual(target.read_bytes(), source.read_bytes())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
            self.assertEqual(target.stat().st_uid, os.geteuid())

    def test_libtool_launcher(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            (root / ".libs").mkdir()
            (root / "staged").mkdir()
            (root / "helper").write_text("#!/bin/sh\n# libtool launcher\n")
            (root / ".libs/helper").write_bytes(b"\x7fELFactual helper")
            copy_program(root / "helper", root / "staged")
            self.assertEqual((root / "staged/helper").read_bytes(),
                             b"\x7fELFactual helper")


class EventCheckerTest(unittest.TestCase):
    def test_single_caller(self):
        high = (1, 0x100000003, 0x100000002)
        low = (1, 3, 2)
        expected = record("EXP", high) + record("EXP", low)
        observed = record("OBS", high, tid=0) + record("OBS", low, tid=0)
        self.assertIsNone(compare_events(expected + observed, "v1"))
        damaged = {
            "missing": record("OBS", high, tid=0),
            "duplicate": observed + record("OBS", low, tid=0),
            "pid": observed.replace("OBS 0 10", "OBS 0 11"),
            "word order": record("OBS", (1, 0x300000001, 0x200000001),
                                 tid=0) + record("OBS", low, tid=0),
            "set order": record("OBS", (high[1], high[0], high[2]),
                                tid=0) + record("OBS", low, tid=0),
            "call order": record("OBS", low, tid=0) + record("OBS", high, tid=0),
            "stale": record("OBS", high, tid=0) * 2,
        }
        for name, text in damaged.items():
            with self.subTest(name=name), self.assertRaises(AssertionError):
                compare_events(expected + text, "v1")
        with self.assertRaises(AssertionError):
            compare_events(expected.replace("EXP 10", "EXP 0") + observed, "v1")

    def test_concurrent_callers(self):
        a, b = (1, 1, 0), (0, 2, 2)
        expected = record("EXP", a, tid=11) * 32 + record("EXP", b, tid=12) * 32
        # Scheduling can interleave the two callers in any order. There is
        # no event TID to reconstruct it, but triples/counts must stay exact.
        observed = (record("OBS", b, tid=0) + record("OBS", a, tid=0)) * 32
        self.assertIsNone(compare_events(expected + observed, "threads"))
        damaged = observed.replace(record("OBS", a, tid=0),
                                   record("OBS", (1, 2, 0), tid=0), 1)
        with self.assertRaises(AssertionError):
            compare_events(expected + damaged, "threads")
        with self.assertRaises(AssertionError):
            compare_events(expected.replace("EXP 12", "EXP 11") + observed,
                           "threads")

    def test_empty_and_malformed(self):
        self.assertIsNone(compare_events("", "failures"))
        for text in (record("OBS", (0, 0, 0), tid=0), "OBS 0 10 0 0\n"):
            with self.subTest(text=text), self.assertRaises(AssertionError):
                compare_events(text, "failures")
        with self.assertRaises(AssertionError):
            compare_events("", "zero")

    def test_race_coverage(self):
        text = (record("EXP", (0, 1, 0)) + record("OBS", (0, 1, 0), tid=0)) * 512
        self.assertIsNotNone(compare_events(text, "race"))
        text = text.replace(record("EXP", (0, 1, 0)), record("EXP", (1, 1, 0)), 1)
        text = text.replace(record("OBS", (0, 1, 0), tid=0),
                            record("OBS", (1, 1, 0), tid=0), 1)
        self.assertIsNone(compare_events(text, "race"))

    def test_lifecycle(self):
        for case, tid, marker in (
                ("leader-exit", 11,
                 "LIFE leader-zombie 10 10\nLIFE survivor 10 11\n"),
                ("worker-exec", 10,
                 "LIFE before-exec 10 11\nLIFE after-exec 10 10\n")):
            expected = "ECHK 10 {} 157 8 0 4026531837\n".format(tid)
            observed = expected.replace("ECHK", "OCHK")
            text = (marker + record("EXP", (0, 0, 0), tid=tid) +
                    record("OBS", (0, 0, 0), tid=0) + expected + observed +
                    "CLEANUP empty\n")
            with self.subTest(case=case):
                self.assertIsNone(compare_events(text, case))
            damaged = [text.replace(marker, ""),
                       text.replace("CLEANUP empty\n", ""),
                       text.replace(observed, ""), text + observed]
            fields = observed.split()
            for index, value in ((1, "12"), (2, "12"), (3, "59"),
                                 (4, "21"), (5, "1"), (6, "7")):
                corrupt = fields.copy()
                corrupt[index] = value
                damaged.append(text.replace(observed, " ".join(corrupt) + "\n"))
            if case == "worker-exec":
                damaged.append(text.replace("before-exec 10 11", "before-exec 10 10"))
            else:
                damaged.extend((
                    text.replace("LIFE leader-zombie 10 10\n", ""),
                    text.replace("leader-zombie 10 10", "leader-zombie 10 11"),
                    text.replace(marker,
                                 "LIFE survivor 10 11\nLIFE leader-zombie 10 10\n")))
            for n, bad in enumerate(damaged):
                with self.subTest(case=case, corruption=n):
                    with self.assertRaises(AssertionError):
                        compare_events(bad, case)
            cli_check = "[CAP] pid=10 cap=setpcap result=DENIED syscall=prctl\n"
            cli = (marker + record("EXP", (0, 0, 0), tid=tid) + expected +
                   "[CAPSET] pid=10 effective=0x0 permitted=0x0 inheritable=0x0\n" +
                   cli_check +
                   "Application exited with status 0\n" +
                   json.dumps({"successful_capset_calls": 1,
                               "observation": {"collection_complete": True},
                               "capability_drop_observed": True}, indent=2))
            self.assertIsNone(compare_cli(cli, case))
            # Keep the workload's ECHK and CAPSET evidence intact: neither
            # proves the CLI received the separate capability-check event.
            for replacement in ("", cli_check * 2,
                                cli_check.replace("pid=10", "pid=12"),
                                cli_check.replace("setpcap", "sys_admin"),
                                cli_check.replace("DENIED", "GRANTED"),
                                cli_check.replace("prctl", "capset")):
                with self.subTest(case=case, cli_check=replacement):
                    with self.assertRaises(AssertionError):
                        compare_cli(cli.replace(cli_check, replacement), case)

    def test_namespace(self):
        expected = ("ECHK 10 10 170 21 1 4026533000\n"
                    "ECHK 10 10 170 21 0 4026533000\n")
        observed = expected.replace("ECHK", "OCHK")
        prefix = ("NAMESPACE 4026531837 4026533000\n" + expected +
                  record("EXP", (0, 1, 0)))
        text = prefix + observed + record("OBS", (0, 1, 0), tid=0)
        self.assertIsNone(compare_events(text, "userns"))
        for bad in (text.replace(observed, ""), text + observed,
                    text.replace(observed, observed.replace("4026533000", "4026531837")),
                    text.replace("NAMESPACE 4026531837", "NAMESPACE 4026533000"),
                    text.replace("OCHK 10 10", "OCHK 10 11"),
                    text.replace("OCHK 10 10 170", "OCHK 10 10 59"),
                    text.replace("OCHK 10 10 170 21 0", "OCHK 10 10 170 21 1")):
            with self.subTest(bad=bad), self.assertRaises(AssertionError):
                compare_events(bad, "userns")
        cli = (prefix + "Application exited with status 0\n" +
               "[CAP] pid=10 cap=sys_admin result=GRANTED syscall=sethostname\n" +
               "[CAP] pid=10 cap=sys_admin result=DENIED syscall=sethostname\n" +
               "Capability checks targeted a different user namespace.\n" +
               "Automatic capability recommendations are suppressed\n")
        self.assertIsNone(compare_namespace_cli(cli))
        for bad in (cli.replace("are suppressed", "are available"),
                    cli.replace("GRANTED", "DENIED"), cli + "setcap cap_sys_admin+ep app",
                    cli + "AmbientCapabilities=CAP_SYS_ADMIN\n",
                    cli + "CapabilityBoundingSet=CAP_SYS_ADMIN\n",
                    cli + "Programmatic solution (C with libcap-ng):\n",
                    cli.replace("status 0", "status 1")):
            with self.subTest(bad=bad), self.assertRaises(AssertionError):
                compare_namespace_cli(bad)
        self.assertIsNotNone(compare_namespace_cli("Application exited with status 77"))

    def test_follow(self):
        check = "[CAP] pid=11 cap=setpcap result=DENIED syscall=prctl\n"
        text = (record("EXP", (0, 0, 0)) + "LIFE orphan-parent 10 10\n" +
                "Application exited with status 0\n" +
                "[*] Following descendants until they exit\n" +
                "LIFE orphan 11 11\n" + record("EXP", (0, 0, 0), tid=11, pid=11) +
                "ECHK 11 11 157 8 0 4026531837\n" +
                "[CAPSET] pid=10 effective=0x0 permitted=0x0 inheritable=0x0\n" +
                "[CAPSET] pid=11 effective=0x0 permitted=0x0 inheritable=0x0\n" +
                check)
        report = json.dumps({"successful_capset_calls": 2,
                             "capability_drop_observed": True,
                             "observation": {"collection_complete": True,
                                             "descendants_followed": True,
                                             "descendants_remaining": False}},
                            indent=2)
        self.assertIsNone(compare_follow_cli(text, report))
        # Each corruption models evidence a non-following trace would lack.
        for bad in (text.replace("[*] Following descendants until they exit\n", ""),
                    text.replace(check, ""),
                    text.replace("[CAPSET] pid=11", "[CAPSET] pid=12"),
                    text.replace("LIFE orphan 11 11\n", ""),
                    text.replace("status 0", "status 1")):
            with self.subTest(bad=bad), self.assertRaises(AssertionError):
                compare_follow_cli(bad, report)
        for old, new in (('"descendants_followed": true',
                          '"descendants_followed": false'),
                         ('"descendants_remaining": false',
                          '"descendants_remaining": true'),
                         ('"collection_complete": true',
                          '"collection_complete": false'),
                         ('"successful_capset_calls": 2',
                          '"successful_capset_calls": 1')):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                compare_follow_cli(text, report.replace(old, new))
        self.assertIsNotNone(compare_follow_cli("Application exited with status 77"))

    def test_cli(self):
        text = (record("EXP", (0, 0, 0)) +
                "[CAPSET] pid=10 effective=0x0 permitted=0x0 inheritable=0x0\n" +
                "Application exited with status 0\n" +
                json.dumps({"successful_capset_calls": 1,
                            "observation": {"collection_complete": True},
                            "capability_drop_observed": True}, indent=2))
        self.assertIsNone(compare_cli(text, "zero"))
        # An apparent document in a workload log cannot override the report.
        report = text[text.index("{\n"):]
        self.assertIsNone(compare_cli('{"forged": true}\n' + text, "zero", report))
        with self.assertRaises(AssertionError):
            compare_cli(text, "zero", report.replace('"collection_complete": true',
                                                     '"collection_complete": false'))
        with self.assertRaises(ValueError):
            compare_cli(text, "zero", report + "\n{}")
        for old, new in (("pid=10", "pid=11"), ("effective=0x0", "effective=0x1"),
                         ('"successful_capset_calls": 1',
                          '"successful_capset_calls": 2'),
                         ('"capability_drop_observed": true',
                          '"capability_drop_observed": false'),
                         ("status 0", "status 1")):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                compare_cli(text.replace(old, new), "zero")
        self.assertIsNotNone(compare_cli("Application exited with status 77", "mixed"))


if __name__ == "__main__":
    unittest.main()
