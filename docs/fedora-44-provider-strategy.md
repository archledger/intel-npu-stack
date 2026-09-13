<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fedora 44 Provider Strategy

## Status and scope

The Phase 3A evidence review passed on 2026-09-11 for the exact inputs in
[the build audit](fedora-44-build-and-audit.md). This document defines a
candidate-only provider build for Fedora 44 x86_64 on
Intel Lunar Lake PCI `8086:643e`. It is not qualification evidence, an install
instruction, or stable-channel authority. No artifact described here may be
selected by a stable installer until the later disposable-VM and hardware
qualification gates bind the exact RPM and repository digests.

The package set remains application-neutral. It provides ordinary Level Zero
and OpenVINO NPU capability without any consumer model, command, service, or
configuration.

## Compatibility boundary

Intel Linux NPU driver `v1.35.0` is the matrix authority. It names OpenVINO
`2026.2`, Level Zero `v1.28.2`, and NPU compiler `npu_ud_2026_28_rc1`. Fedora 44
updates instead provide `oneapi-level-zero-1.28.6-1.fc44`. The candidate uses
that newer distro-owned loader and headers rather than forcing a downgrade.
This is an explicit, unqualified deviation: only the later complete hardware
gate can establish whether it is suitable for promotion.

The Fedora kernel, `intel_vpu` module, and device-node policy remain
distribution-owned. This project does not build a kernel, DKMS module, or
replacement device-access service.

## Package identity and coexistence

- The userspace driver keeps Fedora's `intel-npu-driver` identity and upgrades
  Fedora's older NEVR through DNF. It does not install a parallel copy under
  `/opt`.
- OpenVINO keeps Fedora's existing shared runtime and plugin package identities.
  Its CPU and GPU plugins remain enabled alongside the NPU plugin so installing
  NPU support does not silently remove existing acceleration capabilities.
- The compiler is built from the pinned source tree as Fedora's
  `intel-npu-compiler` subpackage. No Ubuntu archive, Debian package, or
  upstream binary installer is accepted.
- `intel-npu-stack-firmware` owns only
  `/usr/lib/firmware/updates/intel/vpu/vpu_40xx_v1.bin` plus its license. It
  does not replace the distro-owned base firmware file.
- The metapackage owns metadata only and requires exact provider
  NEVRs. It does not use `Conflicts` or `Obsoletes` to remove unrelated GPU or
  CPU providers.

## Source boundary

All source records are exact Git object identities. Source archives are
uncompressed deterministic Git tar streams. Gitlinks are never silently
initialized: each is classified as bundled, replaced by an exact Fedora 44
BuildRequires NEVR, or unreachable under an explicit `OPTION=OFF` build
control.

The NPU compiler and OpenVINO commits contain Git LFS pointers. Networked cache
population fetches those objects explicitly at the pinned commit. Offline
bundling suppresses system/global Git configuration, rejects local content
filters and archive commands, reads canonical LFS pointers itself, and replaces
them only with cache objects whose size and SHA-256 match the pointer. It never
runs Git LFS, a repository filter, a checkout, or fetched code.

Fedora dist-git snapshots are references only. Because their committed trees
contain no explicit license file for the packaging metadata, their records are
`NOASSERTION` and `external_only`; the bundler verifies their identities and
hashes but does not publish their archives.

## Build dependency dispositions

The Linux NPU driver uses the locked NPU ELF and Level Zero NPU extension
sources. Its googletest and yaml-cpp gitlinks are replaced by Fedora
`gtest-devel-0:1.17.0-2.fc44`, `gmock-devel-0:1.17.0-2.fc44`, and
`yaml-cpp-devel-0:0.8.0-5.fc44`.

OpenVINO preserves the Fedora CPU/GPU feature surface. Its pinned oneDNN CPU,
oneDNN GPU, and MLAS trees are bundled because Fedora's package already treats
those forks as private plugin build inputs. The matching Level Zero NPU
extension and compiler flatbuffers tree are also bundled. The remaining active
gitlinks are replaced by these Fedora 44 dependencies:

- `gflags-devel-0:2.2.2-19.fc44`
- `json-devel-0:3.12.0-2.fc44`
- `ocl-icd-devel-0:2.3.4-2.fc44`
- `oneapi-level-zero-devel-0:1.28.6-1.fc44`
- `onnx-devel-0:1.17.0-12.fc44`
- `opencl-headers-0:3.0-35.20250708git8a97ebc.fc44`
- `protobuf-devel-0:3.19.6-20.fc44`
- `pugixml-devel-0:1.16-1.fc44`
- `pybind11-devel-0:3.0.4-2.fc44`
- `snappy-devel-0:1.2.2-4.fc44`
- `xbyak-devel-0:7.24.2-3.fc44`
- `zlib-ng-compat-devel-0:2.3.3-3.fc44`

NCC style checks, tests, telemetry, ARM Compute Library, KleidiAI, libxsmm,
RISC-V Xbyak, NPU internal tools, NPU protopipe, and downloaded NPU compiler
libraries are disabled. The production spec must assert the corresponding
CMake cache values rather than relying on defaults.

The source-built NPU compiler uses its pinned ELF, LLVM/MLIR fork, and NPU cost
model. `gtest-parallel` is unreachable because private tests are disabled. Its
prebuilt activation-kernel objects are Git LFS inputs committed by hash in the
compiler tree; the source bundle materializes only objects matching those
SHA-256 pointers. The package build and later SBOM must retain that distinction
instead of describing those objects as locally compiled source.

## License and redistribution decisions

Verbatim upstream license and third-party notice evidence is stored under
`packaging/fedora/44/licenses/`. The sealed source lock and final source/package
audits bind the exact retained bytes, including the compiler root license.
`allowed` means only that the reviewed terms permit the planned source
and/or binary redistribution when their notice conditions are preserved; it is
not a claim about patent suitability or hardware qualification.

The Lunar Lake firmware is redistributed unmodified under the conditions in
the pinned `firmware/bin/COPYRIGHT`. Its binary SHA-256 is
`4eee75549d47ee4999b7a42a76fcb8a1005aac4aa4c66145c1470fe8f35c16bc`.

## Activation and rollback

Installing or removing the firmware override sets reboot pending; no RPM
scriptlet reloads `intel_vpu`, terminates NPU clients, or reboots the machine.
Rollback removes the metapackage and firmware override, downgrades the shared
providers to the recorded Fedora repository NEVRs through DNF, and reboots once
to reactivate distro firmware. Exact rollback commands belong to Phase 3B and
must be generated from the installed manifest, not hard-coded here.
