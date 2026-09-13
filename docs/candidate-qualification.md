<!-- SPDX-License-Identifier: Apache-2.0 -->
# Candidate qualification tools

`xtask` can prepare a separately identified kernel candidate and collect
observations from the running host. These developer commands preserve
`status = "candidate"`. Public stable and experimental channel selection
continues to reject candidates.

## Retarget one kernel patch

`retarget-candidate` requires an existing unqualified profile, a distinct ID,
an exact kernel release and a new output path. It changes only `id`,
`kernel.min` and `kernel.max_exclusive`; the upper bound is the next patch.
Provider RPM hashes, installed-file hashes, licenses and source evidence
comments remain intact. Existing output paths are refused.

The Fedora 44 candidate
`profiles/fedora/44/lunar-lake-x86_64-kernel-7.2.4.toml` covers
`[7.2.4, 7.2.5)`. It derives from the accepted release candidate whose SHA256
is `ecfd55e29ab0fafd40f6456579676b95766b7e9db897661d37a3a3e8c72ebd59`.
Its provider bindings refer to the accepted signed test RPMs. The older
`lunar-lake-x86_64.toml` is retained as recorded historical input; its earlier
provider bindings must not be substituted for the final accepted set.

## Metadata-only preflight

From the repository root:

```sh
cargo run --locked --offline -p xtask -- collect-candidate \
  --profile profiles/fedora/44/lunar-lake-x86_64-kernel-7.2.4.toml \
  --profile-sha256 dbd218879246a9db5cf49429e203d7fd49b18aae333f1ab227b29e1163077b1d \
  --mode preflight
```

This uses production Linux fact discovery and native RPM/package-file
inspection. It checks the actual OS, architecture, PCI IDs, loaded kernel
module, kernel range and normal-user identity. It never opens accelerator
devices, launches runtime helpers or samples hardware activity counters.
The command accepts no alternate filesystem root or helper executable paths.

Preflight always includes a required blocked `qualification.probes` check
with `PREFLIGHT_ONLY`. Exit 1 is expected, including when its metadata checks
pass: no hardware result has been collected. Missing packages are reported as
`PACKAGE_NOT_INSTALLED`. Invalid input, digest mismatch, incompatible platform
or root invocation returns exit 2 before runtime inspection.

## Explicit hardware observations

After package installation, firmware/initramfs review, activation and
operator authorization, the same command can use
`--mode probe --accept-hardware-probes`. It first requires passing metadata
checks and no pending reboot or relogin. An unmet prerequisite produces a
blocked `PREFLIGHT_NOT_READY` check without opening the device or launching
runtime helpers.

When ready, production doctor orchestration checks normal-user device access,
Level Zero discovery and direct OpenVINO NPU inference. It uses the fixed
installed probe paths, bounded subprocess execution and sanitized structured
results. The returned JSON binds the exact profile bytes and observed kernel
release. Store the collector executable hash, source manifest, command and
each observation together as evidence.

Every observation has `qualification_complete = false`, including a successful
probe. One run does not establish cold-boot, reboot, suspend/resume, upgrade,
removal or rollback behavior. Firmware activation flags use package install
times and boot time; they do not prove which firmware bytes an initramfs
loaded. Inspect and verify the boot image separately before recording firmware
activation evidence.

The observation contains a nested diagnostic report. Its `status` or `doctor`
command field identifies the reused diagnostic schema; the outer `mode`
distinguishes metadata-only preflight from hardware probes. Exit 0 indicates
passing/degraded probe diagnostics, not qualification or release readiness.

## Release artifacts

A changed profile requires a separately built profile RPM and corresponding
release metadata. The 7.2.4 preparation includes an unsigned data-only profile
RPM, built twice identically. It is excluded from the initial 14-signed-runtime
RPM hardware pilot. The candidate file is supplied directly to the collector
with its pinned digest.

The old isolated test key's private half was destroyed. New profile/repository
signatures require separately authorized signing. An unsigned preparation
manifest and an observation cannot replace a signed installer release or the
independent qualification and promotion gates.
