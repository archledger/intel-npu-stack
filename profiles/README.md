# Production profiles

`fedora/44/lunar-lake-x86_64.toml` is qualified for release 0.1.0 on kernels
`[7.2.5, 7.3.0)`. Its `qualification` table names the evidence record by
SHA-256, and `release/kernel-probes.json` records the kernels that evidence
covers. Release 0.1.0, published on 2026-09-26, serves it on the stable
channel.
`fedora/44/lunar-lake-x86_64-kernel-7.2.4.toml` is an unqualified test
candidate.

A production profile requires independently reviewed source, license, package, disposable-VM lifecycle, real-hardware, suspend/resume, rollback, signature, and provenance evidence. Test fixtures are not qualification evidence. Never copy `fixture-only-not-hardware-evidence` or any other fixture identity into this directory.

Candidate generation uses `cargo run -p xtask --locked -- generate-fedora-profile`
with explicit `--rpms` and `--output` paths. The input directory contains exactly
the fourteen runtime RPMs, without development, debug or source RPMs. Save the
JSON written to standard output as external build evidence. It binds all package
digests, the provider source lock and the generated profile bytes. Keep this
evidence outside the project source archive to avoid a tools-RPM self-reference.

Generation is deterministic, refuses an existing output and cannot emit a
qualified profile. Both stable and experimental channels reject candidates,
including when experimental risk is acknowledged. A generated candidate's
single-kernel window identifies its test target, not a supported kernel range.

Promotion is a reviewed change that sets the kernel window, adds the
qualification record and records the kernels the evidence covers (see [kernel
probes](../docs/kernel-probes.md)). Repository presence alone does not imply
support. Validate this nested directory explicitly with `validate-profiles
profiles/fedora/44`; the general directory validator deliberately checks only
direct TOML children.
