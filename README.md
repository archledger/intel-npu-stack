# intel-npu-stack

`intel-npu-stack` is an application-neutral Linux project for describing, selecting, installing, and verifying qualified Intel NPU software stacks. It groups the compatibility boundary into firmware, Level Zero, Intel NPU userspace driver/compiler, OpenVINO runtime/NPU plugin, and distribution-owned kernel/device access.

Phase 1 is read-only. It defines strict platform profiles and diagnostic contracts without installing packages, changing system configuration, or claiming that an NPU works. Runtime probing and native distribution packaging belong to later reviewed phases.

No stable platform profile is published yet. Fedora 44 x86_64 on allowlisted Lunar Lake hardware is the first planned qualification target, but remains unsupported until all VM, hardware, provenance, signing, rollback, and release gates pass.

Project-authored source is licensed under Apache-2.0. Third-party components retain their own licenses and redistribution terms.
