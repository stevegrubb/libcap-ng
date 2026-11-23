# On-demand privileged integration tests

`make check` establishes basic library and binding behavior, parsers, output
encoding, and injected error handling. Those tests stay in their existing
directories. The tests here exercise real kernel boundaries that mocks cannot
establish. They are **never built or run by `make check`** and are not installed.

The initial suites are:

* `kernel`: real thread credentials versus leader reads; recovery after a target
  exits; bounding drops checked with `prctl` and procfs; ambient inheritance
  through exec; remote metadata failure and self fallback with procfs hidden
  inside a private mount namespace.
* `cap-audit`: production BPF load/attachment and events compared with independent
  `capget` observations. Cases cover low/high bits, legacy headers, kernel
  normalization, failed calls, stale events, concurrent threads, raced buffers,
  and the exec gate. On x86_64, additional cases cover a colliding i386 syscall
  number and genuine i386 capset. CLI cases verify masks, counts, and phase
  tracking through the actual userspace event handler.

This is not yet exhaustive coverage of credential changes or file-capability
execution. It tests the running kernel; a passing modern-kernel run does not
replace running on an older kernel or a different architecture.

## Maintainer workflow

Use a trusted source tree and a native build for the machine that will run the
tests. No installation is necessary. Python 3.8 or newer is needed for the
runner's standard library, but the libcap-ng Python bindings are optional.
Enabled bindings are covered by the prerequisite `make check`; integration
workloads use C and do not import `capng`.

Build and prepare **as your regular user**:

```sh
./autogen.sh                       # Git checkouts only
./configure --enable-cap-audit --with-python3
python3 tests/privileged/run.py prepare --jobs 20
```

`prepare` checks the runner's event comparator and fixture staging, then runs
`make`, `make check`, and the opt-in helper build. These checks protect the harness
and do not repeat the library's unit tests. Preparation records unit
test results and hashes of sources, configuration, helpers, the local library,
and cap-audit binaries in the build directory. It refuses root execution.
After any source or build change, rerun `prepare`. The receipt detects stale
builds; it is not a signature or a replacement for trusting the source tree.

For a build without cap-audit, omit `--enable-cap-audit` and select `--suite
kernel` below. Likewise, `--without-python` is supported. Existing unit-test
skips are recorded in the receipt. Distribution-specific packages are never
installed by this runner: use the project's normal build dependencies. The
optional cap-audit build additionally needs the tools and development libraries
listed in the main README.

Inspect prerequisites and run the integration tests:

```sh
sudo python3 tests/privileged/run.py probe --suite all
sudo python3 tests/privileged/run.py run --suite all
```

`probe` may also be run unprivileged to diagnose that user's access, but its
results do not predict root's access. It attempts private mount-namespace
creation and, when selected, actual production BPF loading and attachment.
Capability and ambient-interface checks supplement these operational probes.
Neither distribution names nor kernel version numbers determine availability.
The individual tests also check their own prerequisites at execution time.
Run the cap-audit suite in the host PID namespace: its target map and events use
kernel task IDs. The kernel suite can run in isolated namespaces when their
capability and mount permissions allow it.

For an out-of-source build, invoke the script from the source tree and pass
`--build-dir /absolute/path/to/build` to **each** command. For example:

```sh
python3 /path/to/source/tests/privileged/run.py prepare --build-dir /path/to/build
sudo python3 /path/to/source/tests/privileged/run.py run --build-dir /path/to/build
```

Tests exercise copies of the verified binaries and local library, not installed
system copies. They are staged in a private directory owned by the runner under
the results directory, then removed at completion or interruption. This keeps
exec working after root drops its DAC capabilities, even when the build user's
home and binaries have owner-only permissions. Build permissions are unchanged.
This also works from a release source tarball; Git is not needed.
`make clean` removes the helpers and receipt. `make maintainer-clean` also removes
the generated build machinery; prepare again after rebuilding.

## Diagnostics and system effects

The runner prints a results directory containing `environment.json`, per-case
logs, and `report.json`. Use `--output /path/to/new-directory` to choose a retained
location. Default output uses a fresh temporary directory. Logs record OS release,
architecture, kernel, capability/security context, relevant namespace/BPF limits,
build hashes, expected/observed masks, and probe errors. Missing or unreadable
diagnostic files are reported as such, not treated as proof a feature is absent.
The output filesystem must allow execution and its parent directories must be
traversable by root without DAC capabilities. The exec probe diagnoses access
restrictions; choose a different `--output` location when needed.

Each case reports PASS, FAIL, or SKIP with a reason. Exit status is:

* **0 / PASS:** all selected applicable cases passed (for `probe`, prerequisites
  only; no integration success is implied).
* **1 / FAIL:** a tested invariant failed, a fixture crashed/timed out, or BPF
  failed for reasons such as verifier rejection.
* **2 / INCOMPLETE:** a prerequisite is unavailable, preparation is stale/missing,
  or a raced workload did not sample both values. Root inside a restricted
  container may still lack namespace, BPF, or capability permissions.

An architecture-specific fixture that does not apply is marked SKIP and does not
make an otherwise applicable run incomplete. Other skips do. BPF permission or
interface failures include libbpf diagnostics; check LSM policy, lockdown,
capabilities, BTF, and tracing support rather than assuming a distro issue.

Capability changes occur only in disposable helpers and their children. The
procfs test first creates a private mount namespace and makes propagation private
before covering `/proc`; it never mounts over the host's procfs. No packages,
sysctls, services, or global security settings are changed. Helpers are bounded
by timeouts; interruption kills their process groups, closes BPF descriptors,
and releases temporary namespaces. Logs are deliberately retained. Run on a
test host when possible, since live tracing and kernel tests still consume
system resources.

CAPSET events currently identify the process but omit TID. Concurrent tests
therefore compare complete E/P/I triples and their multiplicities by process;
they do not claim per-thread event attribution. Single-caller tests also check
event order. Expected masks come from kernel queries, not the serializer or the
library's cached snapshot.

For a failure report, include `report.json`, `environment.json`, the failing
case's log, and the prepare log (`build/tests/privileged/prepare.log`). Review
host paths and process/security context before posting logs publicly.
