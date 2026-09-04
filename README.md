# intel-npu-stack

`intel-npu-stack` is an application-neutral Linux project for describing, selecting, installing, and verifying qualified Intel NPU software stacks. It groups the compatibility boundary into firmware, Level Zero, Intel NPU userspace driver/compiler, OpenVINO runtime/NPU plugin, and distribution-owned kernel/device access.

The current implementation is read-only. It defines strict platform profiles and provides bounded `status` discovery plus crash-isolated `doctor` inference without installing packages or changing system configuration. Native distribution packaging and installation remain later reviewed phases. See [Runtime status and doctor](docs/runtime-doctor.md) for the diagnostic boundary.

No stable platform profile is published yet. Fedora 44 x86_64 on allowlisted Lunar Lake hardware is the first planned qualification target, but remains unsupported until all VM, hardware, provenance, signing, rollback, and release gates pass.

Project-authored source is licensed under Apache-2.0. Third-party components retain their own licenses and redistribution terms.
