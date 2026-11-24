# Repository Guidelines

Libcap-ng provides a Linux capabilities library and utilities for inspecting
and auditing capability use. The project uses autotools and optional Python 3
bindings. See [README.md](README.md) for dependencies and feature details.

## Repository Layout

- `src/`: libcap-ng, its public header, and the ambient-dropping library.
- `src/test/`: library tests.
- `utils/`: pscap, netcap, filecap, and shared procfs and output helpers.
- `utils/test/`: utility tests.
- `utils/cap-audit/`: BPF tracing, event handling, capability analysis,
  service handling, and output generation.
- `utils/cap-audit/test/`: cap-audit unit tests, including simulated BPF tests.
- `tests/privileged/`: optional kernel and live BPF integration tests.
- `bindings/src/`: SWIG interface; `bindings/python3/` builds the bindings.
  Tests live in `bindings/python3/test/` and `bindings/test/`.
- `docs/`: library man pages and their checks. Utility man pages live in
  `utils/` and `utils/cap-audit/` alongside their sources.
- `m4/`: autotools macros; `.github/workflows/`: CI configuration.

## Building

Bootstrap Git checkouts with `./autogen.sh`. For a development build with
cap-audit and Python bindings enabled:

```sh
./autogen.sh
./configure --enable-cap-audit --with-python3
make
make check
```

For a minimal configuration, use `./configure --without-python`; cap-audit is
disabled by default. A default build does not cover most cap-audit tests.
Build and run ordinary tests unprivileged. Installation is not needed for tests.

Cap-audit needs additional tools, development libraries, and kernel type
information. See the README's cap-audit section for dependencies and the
`--with-vmlinux-h=provided --with-vmlinux-h-path=/path/to/vmlinux.h` workflow.
Use a supplied header when the build must not depend on the running kernel's
BTF data. Netcap advanced mode and VSOCK support depend on available kernel
headers; check the configure summary for enabled features.

Edit `configure.ac` and `Makefile.am`, not generated `configure` or `Makefile`
files. Edit `bindings/src/capng_swig.i`, not generated SWIG wrappers.
`vmlinux.h`, `cap_audit.bpf.o`, and `cap_audit.skel.h` in the cap-audit build
directory are generated build products; do not hand-edit or commit them.

## Testing

Run `make check` for the affected build configuration. Keep ordinary
builds and `make check` unprivileged; do not add tests that require host-root
access or live BPF attachment to that target.

Place regression tests alongside the affected component. Cover relevant
failure and recovery paths, not just successful calls. Prefer independent
observations over comparing two outputs derived from the same cached state.
Synchronize lifecycle tests on observable events rather than fixed sleeps.

The BPF unit test executes production logic with simulated kernel helpers and
types. It does not establish verifier acceptance, CO-RE relocation correctness,
or live attachment. User-namespace workload checks likewise validate fixture
behavior without proving that tracing works.

Privileged integration tests are separate, opt-in, and never built or run by
`make check`. Follow [the maintainer guide](tests/privileged/README.md) for
unprivileged preparation, explicit privileged execution, and retained results.
Rerun preparation after source or build changes. Report unavailable
prerequisites as incomplete coverage, not a pass; a successful probe only
checks prerequisites.

## Portability and Compatibility

Preserve glibc and musl support and optional kernel-header features. Avoid assuming that build-host kernel headers
guarantee runtime kernel support. Match validation to the configurations and
architectures affected by a change.

The current CI covers glibc, musl, and LTO builds, but does not enable Python
bindings or cap-audit. A green CI run does not establish coverage of those
optional components. Consult `.github/workflows/build.yml` for the actual jobs.

Preserve public API and ABI compatibility. Update affected man pages when
changing documented behavior, and keep text, JSON, and YAML output consistent
where they describe the same information.

## Code Style and Contributions

Follow Linux Kernel C style: tabs with 8-column stops, lines around 80 columns,
and kernel-style braces. Match the surrounding code and keep changes focused.
Discuss substantial new features with the maintainers before implementing them.

Explain non-obvious assumptions, ordering requirements, and failure handling
in comments at the relevant code. Comments should explain why the behavior is
needed; reviewers do not have the context of development conversations.

Make one commit per bug or distinct issue. Use a concise summary followed by
paragraphs explaining what was wrong, how it was fixed, and any added or updated
tests. Describe user-visible behavior with familiar capability terminology.

Leave `ChangeLog` updates to project maintainers. Contributor changes should
describe their impact in commit messages and affected documentation instead;
editing `ChangeLog` creates avoidable conflicts when cherry-picking fixes to
older releases.
