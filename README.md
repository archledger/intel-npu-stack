# intel-npu-stack

`intel-npu-stack` is an application-neutral Linux project for describing, selecting, installing, and verifying qualified Intel NPU software stacks. It groups the compatibility boundary into firmware, Level Zero, Intel NPU userspace driver/compiler, OpenVINO runtime/NPU plugin, and distribution-owned kernel/device access.

## Current status

**Release 0.1.0 is published** for Fedora 44 x86_64 on allowlisted Intel
Lunar Lake hardware, kernels `[7.2.5, 7.3.0)`:
[GitHub release](https://github.com/archledger/intel-npu-stack/releases/tag/v0.1.0)
and [release site](https://archledger.github.io/intel-npu-stack/0.1.0/). No
other platform is supported.

Implemented components include strict platform profiles, bounded `status`
discovery, crash-isolated `doctor` inference, an authenticated installer with
reviewed native DNF replay, deterministic release assembly, and developer-only
candidate qualification tooling.

The Fedora 44 candidate has passed package, source/notice, dependency, SBOM and
independent reproducibility review. All planned disposable-VM lifecycle
scenarios passed, plus corrupted-RPM refusal/recovery. On Lunar Lake hardware,
the matched 1.38.0 stack passed normal-user NPU inference, upgrade, warm
reboot, removal, rollback, restoration and repeat installation on kernel 7.2.5,
and suspend/resume and a user-confirmed cold boot on kernel 7.2.7.

The Fedora 44 Lunar Lake profile is qualified for release 0.1.0 on kernels
`[7.2.5, 7.3.0)`. The protected release workflow published 0.1.0 on
2026-09-26 as an immutable GitHub release, with build provenance and its
Pages site. See [Fedora installer and bootstrap](docs/install-fedora.md) for
the install command.

## Documentation

- [Runtime status and doctor](docs/runtime-doctor.md)
- [Fedora installer and bootstrap](docs/install-fedora.md)
- [Build, provenance and audit evidence](docs/fedora-44-build-and-audit.md)
- [Disposable-VM lifecycle](docs/fedora-vm-lifecycle.md)
- [Candidate qualification tooling](docs/candidate-qualification.md)
- [Hardware validation progress and deferred tests](docs/hardware-validation.md)
- [Release readiness](docs/release-readiness.md)
- [Continuous integration and repository controls](docs/ci.md)
- [Contributing](CONTRIBUTING.md)

Project-authored source is licensed under Apache-2.0. Third-party components retain their own licenses and redistribution terms.
