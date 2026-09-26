# intel-npu-stack

`intel-npu-stack` is an application-neutral Linux project for describing, selecting, installing, and verifying qualified Intel NPU software stacks. It groups the compatibility boundary into firmware, Level Zero, Intel NPU userspace driver/compiler, OpenVINO runtime/NPU plugin, and distribution-owned kernel/device access.

## Current status

**Source preview; no supported or production-signed public release yet.**

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

Candidate profiles remain unqualified. Profile promotion, the release
repository settings and release publication remain separate work; publishing
this source does not complete those gates.

No stable platform profile is published yet. Fedora 44 x86_64 on allowlisted Lunar Lake hardware is the first planned qualification target, but remains unsupported until all VM, hardware, provenance, signing, rollback, and release gates pass.

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
