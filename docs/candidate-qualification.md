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

`profiles/fedora/44/lunar-lake-x86_64.toml` records the current matched provider
set with accepted build digests. For a signed qualification pilot, first bind
the signed RPM identities with `generate-release-profile.py`, then retarget the
result to the exact observed kernel. Both operations preserve candidate status.

The September 19 hardware candidate covers `[7.2.5, 7.2.6)` and has SHA256
`4cc29b602f6e7af6e6ff053a74c097f56e69609282031d6aaf4621f4b5ac437c`.
Its signed-input and collector records are retained with the hardware evidence.

The repository's `lunar-lake-x86_64-kernel-7.2.4.toml` describes the earlier
1.35.0 pilot and remains historical input. Its provider bindings must not be
mixed with the current 1.38.0 set. See [hardware validation](hardware-validation.md)
for the observed cases and remaining gaps.

## Metadata-only preflight

From the repository root, supply the candidate file for the installed package
set and its independently verified SHA256. Set `CANDIDATE_PROFILE` to the
reviewed local file path and `CANDIDATE_SHA256` to the expected digest recorded
for that file:

```sh
: "${CANDIDATE_PROFILE:?Set the reviewed candidate file path}"
: "${CANDIDATE_SHA256:?Set its expected SHA256 from the input record}"
cargo run --locked --offline -p xtask -- collect-candidate \
  --profile "$CANDIDATE_PROFILE" \
  --profile-sha256 "$CANDIDATE_SHA256" \
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
release metadata. The current 7.2.5 hardware pilot supplies its candidate file
directly to the collector with the pinned digest. The profile RPM and optional
development package are excluded from that 14-runtime-package pilot.

The earlier 7.2.4 preparation produced an unsigned data-only profile RPM twice
with identical bytes. That is retained historical evidence for the earlier
profile, not a release artifact for the current 7.2.5 candidate.

Qualification keys' private halves were destroyed after signing. New profile
and repository signatures require separately authorized signing. An unsigned
preparation manifest and an observation cannot replace a signed installer
release or the independent qualification and promotion gates.
