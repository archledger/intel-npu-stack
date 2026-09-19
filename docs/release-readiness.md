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
| Source and notices | Every redistributed source and binary input has exact provenance and the required notices. | The tools release 3 refresh passed source/static binding, SPDX schema/reference/license checks and aggregation: 37 bound or supplemental SPDX documents, with raw documents retained in the component bundles. Carry the original notices and GNU runtime addendum with the release. |
| Native packages | Two independent builds of the final inputs produce matching RPM/SRPM bytes; package ownership, dependencies, notices and extracted payload checks pass. | The matched set has 31 binary RPMs and five SRPMs; all 36 independent artifact comparisons passed. The updated tools/metapackage 0.1.0-3 pair also passed payload, dependency, notice and hardening checks. |
| Tools and profile | Tools use the accepted provider SDK and manifest; the candidate records final provider and critical-file digests without a self-hash cycle. | Canonical fourteen-RPM candidate generation passed with tools release 3. Provider profile bytes stayed unchanged. The separate hardware candidate covers kernel 7.2.5 and remains unqualified; signing and retargeting do not promote it. |
| Installation lifecycle | Clean Fedora VMs pass dry run, install, repeat install, failure, reboot-pending, removal, upgrade and rollback scenarios. | The fresh tools release 3 fixture passed all eleven scenarios against updated artifact digests, including exact rollback identity counts and cleanup verification. See [VM lifecycle evidence](fedora-vm-lifecycle.md); VM results do not qualify physical hardware. |
| Automation | Pinned, least-privilege CI validates source, packages and lifecycle behavior; untrusted changes cannot publish or access qualification secrets. | Hosted source/native CI, CodeQL, DCO, dependency review, the issue-only upstream watcher and separately permissioned candidate preparation are active. The protected release workflow provides signing, assembly, verification and approval-gated publication. Physical qualification and accepted artifact production remain independently evidenced gates. |
| Hardware | The exact candidate passes normal-user discovery and inference, cold boot, reboot, suspend/resume, upgrade, removal and rollback on the target hardware. | On kernel 7.2.5, the matched 1.38.0 stack with tools release 3 passed normal-user NPU checks, warm reboot, removal, old-stack rollback, current-stack restoration and repeat installation. Cold boot and suspend/resume remain incomplete. [Issue #20](https://github.com/archledger/intel-npu-stack/issues/20) still affects unbounded graphs; a [static-batch compilation workaround](npu-compiler-triage.md) is verified. See [hardware validation](hardware-validation.md). |
| Distribution | Signed artifacts, checksums, SBOMs, provenance, support matrix, installation/troubleshooting instructions and rollback resources refer to the exact qualified digests. | Production signing trust and the protected workflow are configured. The refreshed dry run verified 16 RPM signatures and the complete 12-package rollback set, using a disposable key and synthetic qualification fixture. Genuine qualification/promotion, final pinned installer/bootstrap assets and real release publication remain; pilot signatures are not production release trust. |

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
