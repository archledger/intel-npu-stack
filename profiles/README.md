# Production profiles

This directory contains no installable profile. The Fedora 44 Lunar Lake
candidate under `fedora/44/` records an unqualified package matrix.

A production profile requires independently reviewed source, license, package, disposable-VM lifecycle, real-hardware, suspend/resume, rollback, signature, and provenance evidence. Test fixtures are not qualification evidence. Never copy `fixture-only-not-hardware-evidence` or any other fixture identity into this directory.

Candidate generation uses `cargo run -p xtask --locked -- generate-fedora-profile`
with explicit `--rpms` and `--output` paths. The input directory contains exactly
the fourteen runtime RPMs, without development, debug or source RPMs. Save the
JSON written to standard output as external build evidence. It binds all package
digests, the provider source lock and the generated profile bytes. Keep this
evidence outside the project source archive to avoid a tools-RPM self-reference.

Generation is deterministic, refuses an existing output and cannot emit a
qualified profile. Both stable and experimental channels reject candidates,
including when experimental risk is acknowledged. The initial numeric kernel
window, `7.1.13 <= kernel < 7.1.14`, identifies the observed Fedora test target;
it does not establish support for that kernel. The distro-owned Level Zero
1.28.6 deviation remains unqualified.

Promotion requires the qualification workflow defined by the approved design.
Repository presence alone does not imply support. Validate this nested directory
explicitly with `validate-profiles profiles/fedora/44`; the general directory
validator deliberately checks only direct TOML children.
