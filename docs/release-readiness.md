<!-- SPDX-License-Identifier: Apache-2.0 -->
# Release readiness

The first release targets Fedora 44 x86_64 on allowlisted Intel Lunar Lake
hardware. The project provides diagnostics, verified installer/VM lifecycle
machinery, candidate package recipes and hardware observation tooling. The
public repository is a source preview, not a supported, production-signed
installable release.

A usable release must let a normal user install a verified package set, confirm
NPU operation, and remove or roll back that installation using documented
distribution package transactions. Publishing source alone does not establish
these properties.

## Required evidence

| Boundary | Acceptance criterion | Current gap |
|---|---|---|
| Source and notices | Every redistributed source and binary input has exact provenance and the required notices. | Phase 3A passed for the frozen inputs: 61 validated raw, bound and supplemental SPDX documents. Carry the original notices and GNU runtime addendum with the release. |
| Native packages | Two independent builds of the final inputs produce matching RPM/SRPM bytes; package ownership, dependencies, notices and extracted payload checks pass. | Phase 3A passed: 28 binary RPMs and four SRPMs, with all 32 independent comparisons identical. See the exact inputs in the build audit. |
| Tools and profile | Tools use the accepted provider SDK and manifest; the candidate records final provider and critical-file digests without a self-hash cycle. | Final tools pair and fourteen-RPM candidate passed. The candidate remains external to the tools archive, unqualified and unavailable to stable selection. |
| Installation lifecycle | Clean Fedora VMs pass dry run, install, repeat install, failure, reboot-pending, removal, upgrade and rollback scenarios. | Gate 3 passed all ten planned disposable-VM scenarios plus corrupted-RPM refusal/recovery. Production installer and authenticated bootstrap execution are covered by the retained exact-source records. See [VM lifecycle evidence](fedora-vm-lifecycle.md); this does not qualify the ASUS hardware. |
| Automation | Pinned, least-privilege CI validates source, packages and lifecycle behavior; untrusted changes cannot publish or access qualification secrets. | Hosted source/native CI, CodeQL, DCO and dependency-review checks are defined in the [CI workflow](ci.md). These run contract tests rather than physical NPU qualification or full provider release builds. A daily issue-only [upstream watcher](ci.md#upstream-watcher) observes new primary-component releases. Protected hardware, reproducible release-build, separately permissioned candidate preparation and manually approved publication workflows remain separate work. |
| Hardware | The exact candidate passes normal-user discovery and inference, cold boot, reboot, suspend/resume, upgrade, removal and rollback on the target hardware. | The 7.2.4 candidate's 14-runtime-package pilot is installed. Normal-user discovery/direct NPU inference passed before reboot and after user-confirmed cold boot and tested warm reboot; payloads and boot image were verified. Hardware suspend/resume and final removal/restoration are deferred by maintainer decision, not passed. See [hardware validation](hardware-validation.md). The candidate remains unqualified. |
| Distribution | Signed artifacts, checksums, SBOMs, provenance, support matrix, installation/troubleshooting instructions and rollback resources refer to the exact qualified digests. | Source publication is authorized. A new signed 7.2.4 release envelope, production signing, final qualification/promotion and public release assets remain. The disposable pilot signing key has expired; prior signatures are historical test evidence, not production trust. |

## Evidence reuse and interruption

Retain completed evidence with its source revision, source lock, input hashes,
builder image, commands and artifact digests. A later review can consume the same
passing evidence when its inputs and acceptance criteria still match. A task or
documentation heading changing is not a reason to rebuild.

Input changes, incomplete records, failed checks or artifact differences require
the affected evidence to be produced again. Review the impact explicitly and
preserve the earlier results. Never relabel historical artifacts as outputs of
newer source, normalize unexplained differences, or omit a required check.

The current provider build gate requires empty output and build roots. It has no
resume mode. Retained compiled output from an interrupted build may support a
separately verified recovery, but it is not a completed package or acceptance
result. Diagnose failures before choosing another execution attempt.

## Using diagnostics

The installed commands and their exit statuses are documented in
[Runtime status and doctor](runtime-doctor.md). Stable mode requires a qualified
profile. Experimental diagnostics require explicit risk acknowledgement and do
not promote a candidate or establish release readiness.

Package recipes and evidence requirements are described in
[Fedora provider strategy](fedora-44-provider-strategy.md),
[build and audit](fedora-44-build-and-audit.md), and
[candidate tools packaging](../packaging/fedora/44/rpm/intel-npu-stack/README.md).
The [installer documentation](install-fedora.md) records the test-only bootstrap
and native transaction behavior. Its non-routable example endpoint is not a
public installation service. Final commands must bind the actual qualified,
production-signed assets before an end-user release is published.
