# Fedora candidate tools

The metadata-only `intel-npu-stack` RPM selects exact provider versions. The tools
subpackage owns the CLI, the two `intel-npu-*-probe` executables under
`/usr/libexec/intel-npu-stack`, documentation, dependency notices, and
`/usr/share/intel-npu-stack/installed-manifest.toml`. Neither package has activation
scripts. Removing these packages does not itself remove their dependencies.

The empty metapackage is `noarch`; its requirements explicitly select x86-64
providers. The tools package remains x86-64. This corrects the original plan's
architecture tag for a package containing no machine code. Identical license
texts share hardlinks while retaining every notice path and byte.

The manifest binds the twelve runtime providers to their NEVRs, architectures,
RPM SHA-256 values, critical installed-file hashes and provider source lock. It
remains a candidate and records that firmware activation requires a reboot.
The tools RPM's own digest belongs in external release evidence to avoid a
self-referential digest.

Build inputs are a deterministic project source tar, the complete Cargo.lock
vendor tar and the installed manifest. Build and verification run without network
access in the pinned Fedora tools builder. RPM compilation uses Fedora's
Rust/Cargo 1.98.0-1.fc44; the separate repository quality gate retains Rust 1.85
to check the declared minimum version. Native helpers use the packaged Level Zero
1.28.6 and OpenVINO 2026.2.0 SDKs under `/usr`.

The vendor check verifies the complete locked registry set and every vendored
file checksum before copying notices. Dependency license choices are MIT,
with Unicode-3.0 additionally retained for unicode-ident. The source bundle and
notice directory preserve the offered alternatives too. Project source remains
Apache-2.0; provider RPMs retain their own license terms.

The CLI also links Fedora's Rust standard library. Its copyright HTML, license
texts and vendor inventory are copied from the pinned compiler packages. The
tools license expression conservatively includes the additional terms declared
by that exact `rust-std-static` RPM. The complete source and redistribution review
remains part of the release evidence gate.

Package validation requires real extracted payloads, exact provider requirements,
file ownership, executable modes, absence of scripts, license ownership, matching
manifest bytes and successful packaged CLI/native controls. These gates do not
establish VM lifecycle, hardware support, qualification or stable release status.
