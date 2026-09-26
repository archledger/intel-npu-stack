<!-- SPDX-License-Identifier: Apache-2.0 -->
# Hardware validation progress

Status as of **2026-09-26**: the matched Fedora 44 Lunar Lake pilot passed
upgrade, warm reboot, normal-user NPU diagnostics, removal, rollback,
restoration and repeat installation on kernel **7.2.5-200.fc44.x86_64**, then
suspend/resume and a user-confirmed cold boot on kernel
**7.2.7-200.fc44.x86_64** with the same installed packages. The profile is
still a candidate: this is candidate evidence rather than a supported public
release.

## Current matched-stack observations

The installed set has 14 signed runtime packages: driver and firmware 1.38.0,
Level Zero 1.32.0, OpenVINO/compiler 2026.2.0-2, and tools/metapackage 0.1.0-3.
The optional development and profile RPMs are excluded from this hardware pilot.
Its separately identified profile covers `[7.2.5, 7.2.6)` and stays a candidate.

| Case | Observed result |
|---|---|
| Upgrade from the 1.35.0 pilot | Passed: exactly 14 runtime upgrades; all 421 regular payload files and 34 symlinks verified, with no unrelated package changes. |
| Firmware activation | Passed: rebuilt and verified the current-kernel initramfs, retained the original image, then verified an actual warm reboot into the new stack. |
| Native probe output | Hardware testing found SDK compatibility warnings on stdout. [PR #30](https://github.com/archledger/intel-npu-stack/pull/30) isolates the JSON response and preserves SDK diagnostics on stderr. The corrected tools passed independent RPM pair builds and hardware validation. |
| Normal-user NPU operation | The frozen collector passed all 15 checks, including eight validated NPU-only iterations. Three additional fresh-process enumeration/inference pairs passed strict JSON parsing and completed 24 NPU-only iterations. |
| Removal | Removed exactly 13 project-owned packages while retaining the loader. Helpers and the firmware override were absent, and metadata-only collection correctly reported missing packages. Unrelated inventory was preserved. |
| Rollback and old-stack reboot | Restored all 14 old runtime packages, including the Fedora 1.28.6 loader, and the original current-kernel boot image. After reboot, all 15 collector checks and eight NPU-only iterations passed. |
| Restoration and new-stack reboot | Reinstalled the 14-package matched set with tools release 3 and restored its verified boot image. The final reboot, 15 collector checks and eight NPU-only iterations passed. The complete non-key package identity set returned to its pre-removal state. |
| Repeat installation | The actual native installation was a no-op; the complete inventory, installation times and boot image stayed unchanged. |
| Cold boot | Passed on kernel 7.2.7, see below. Firmware advertises timer wake from S4 but not from S5, so the power-on was a physical action by the maintainer. Warm reboots are not relabeled as cold boots. |
| Suspend/resume | Passed on kernel 7.2.7 in three cycles, see below. |

The collector was frozen from source `006d413`; the corrected native tools were
built twice from `bdeecab` and merged as `6741714`. Every observation records its
actual collector, helper, profile and package hashes. Qualification-only signing
keys were used, and their private halves were destroyed after signing. These
signatures do not establish production release trust.

The retained hardware archive `hardware-evidence-20260919.tar.gz` has SHA256
`fcce8df6d2f0b6deb5e675a740f73d92856206c8e7858a44a84674496fc52010`.
Original boot images and full host inventories remain in private recovery storage.

### Compiler crash and the batch-layout route

The matched-stack retest of [issue #20](https://github.com/archledger/intel-npu-stack/issues/20#issuecomment-5743015085)
used compile-only processes and public model weights. All seven CPU controls
compiled. YuNet, FLIR and BlazeFace compiled on NPU in three of three attempts
each. The four previously deterministic crashers, glintr100, liveness_vit,
face_landmark and the TFLite mesh, each received SIGSEGV in three of three NPU
compile attempts after model import. The three successful BlazeFace attempts do
not establish that its earlier intermittent failure is fixed.

The neutral graph passing does not establish support for those other model
graphs. The helper output fix and the compiler crash are separate issues.

Subsequent [compiler triage](npu-compiler-triage.md) reduced the crash to a
six-node, 24-byte-constant graph and found a working static-batch compilation
workaround for all four original crashers. It identified an ABI error in an
earlier research harness and corrected the input-rank diagnosis: those four
inputs have known rank 4 with dynamic batch,
rather than unranked inputs that cannot be reshaped. Without a batch layout the
original unbounded graphs still crash. On September 26 all four compiled and
ran on NPU with a batch layout declared on their inputs, keeping a dynamic
batch; the triage page records that route and its limits. Application
readiness is separate work.
The older intermittent static BlazeFace observation remains unconfirmed
independently of that faulty research harness.

## Suspend/resume and cold boot on kernel 7.2.7, September 26

The same 14 packages stayed installed, with their installation times
unchanged since September 19 and `rpm -V` clean. The kernel 7.2.7 boot image
contains `intel_vpu` and the 1.38.0 firmware override byte-identical to the
package, and the kernel loaded that firmware at boot. The frozen collector
probed against a test profile retargeted from the signed candidate; it differs
only in its identifier and the kernel window `[7.2.7, 7.2.8)`. Every probe
below passed all 15 checks with NPU activity.

| Case | Observed result |
|---|---|
| Activation on 7.2.7 | Passed on the running boot without a power transition: kernel, packages, boot images and loaded firmware matched the pinned target, and the probe passed. |
| Suspend/resume | Passed three RTC-timed `s2idle` cycles of 32 to 35 seconds. Two statically reshaped public ONNX models, glintr100 and FLIR, stayed compiled and resident on the NPU across each cycle. Each cycle resumed in the same boot with one more successful suspend and no new failure in the kernel's suspend statistics, no NPU kernel errors, identical outputs before and after, and probes passing before and after. The first inference after resume took 7.7 to 9.6 ms for glintr100 and 1.8 to 2.3 ms for FLIR. |
| Cold boot | Passed: the maintainer shut down from the menu, waited more than ten seconds and pressed the power button. The previous boot's journal ended in `poweroff.target` with no reboot. The new boot matched the pinned identity and the probe passed. |

The retained archive `hardware-evidence-20260926-k727.tar.gz` has SHA256
`91def96fb42e21dd9f5cab01f39cf13445245aa0ed3d9696b1f5cb90fc81b2fe` and extends
the September 19 archive. Raw journal captures, which carry network
identifiers, remain in private storage. The two qualification-only package
keys were removed from the test host after these runs.

## Earlier 1.35.0 pilot, September 13

The target class is an Intel Core Ultra 200V-series NPU (`8086:643e`) with the
distribution-owned `intel_vpu` module. The installed pilot contains 14 signed
runtime packages: Intel NPU driver/firmware 1.35.0, NPU compiler and OpenVINO
2026.2.0, Level Zero loader 1.28.6 and the project tools/metapackage. The unsigned
profile RPM and optional development package were not installed in this pilot.

The candidate remains `status = "candidate"` with kernel range
`[7.2.4, 7.2.5)`. The frozen developer collector uses actual production platform,
package, device, process and protocol implementations. It requires a pinned
profile digest and explicit probe acknowledgement, refuses incompatible/root
execution, and requires metadata/activation readiness before probing.

All hardware reports keep `qualification_complete = false`. Public channel
selection has not been relaxed or bypassed to publish this source.

### Historical results

| Case | Evidence status |
|---|---|
| Signed native installation | Passed: 14 runtime RPMs installed through the reviewed native transaction. |
| Package/firmware verification | Passed: 421 regular payloads and 34 packaged symlinks; helper/profile hashes and original/current initramfs verified. The existing image already contained firmware matching the candidate; no image regeneration was needed. |
| Pre-reboot non-disruptive observations | Passed: normal-user accelerator access, Level Zero and OpenVINO NPU discovery, then three fresh processes with eight NPU-only iterations each. These did not waive the collector's activation gate. |
| Cold-boot runtime observation | Passed: the maintainer confirmed the observed boot was a cold boot. The subsequent frozen collector passed all 15 checks, eight validated NPU-only iterations and positive activity. The power-off/on itself was user-confirmed rather than agent-instrumented. |
| Warm-reboot runtime observation | Passed: an explicitly authorized normal reboot was executed, a new boot verified, and the frozen collector again passed all 15 checks/eight NPU-only iterations. |
| Repeat installation | Native no-op preview passed; it did not reinstall packages. |
| Hardware suspend/resume | **Deferred by the maintainer** while working remotely. No passing hardware result is claimed. |
| Hardware removal/restoration | Preview selected the exact 14-package set. **Execution deferred by the maintainer**; the pilot remains installed. |
| Disposable-VM lifecycle | Separately passed all ten planned scenarios, including removal/rollback/upgrade, plus corrupted-RPM refusal/recovery. VM results do not substitute for deferred hardware cases. |

The graph is `intel-npu-stack-neutral-v1`, built in memory, with eight validated
iterations and tolerance0.001 per invocation. Execution devices were exactly
`[NPU]`; there was no CPU fallback. Busy-counter increases support activity
observation and are not performance benchmarks. Package inventories and boot
image/backup contents stayed unchanged during each observation.

### Earlier corrections and retained limitations

- Installer preparation was corrected for realistic Fedora metadata sizes and
  the verified signing-key symlink layout. The primary bootstrap command was
  corrected to bind `install.sh`, which separately binds the installer binary.
- A pilot wrapper propagated its private backup umask to DNF. Six state files
  were restored to their native package-declared0644 modes without changing
  contents, and the future DNF wrapper explicitly uses umask0022. The failing
  and corrected evidence remains retained.
- The disposable NPU signing key expired after the pre-reboot phase and is no
  longer listed in the later native key inventory. Expiry and absence were
  observed separately; the absence mechanism was not established. Installed
  payloads remained exact. New installation/release signing must establish
  valid trust rather than treating this expired test key as production trust.
- An independent existing vendor-key timestamp refresh was preserved. No
  unrelated package changes were undone during verification.

### Earlier evidence provenance

Detailed sanitized receipts and rollback material remain in the maintainer's
controlled evidence store and are not bundled into public source. Archive
digests identify the retained observations without publishing host credentials,
private boot images, raw journals, or full machine inventories:

| Evidence archive | SHA256 |
|---|---|
| `2026-09-12-phase3b-vm-final.tar.gz` | `fed40d34aed078014b14245c6522b88d2804f79bf77f5d0e57184b16e186908f` |
| `2026-09-13-postboot-remote1.tar.gz` | `0c246c21d2eaf51e737d446ec0230988b82356cd90da5d064f781e846b05446e` |
| `2026-09-13-warmboot-remote1.tar.gz` | `1a87a19247590caa83068431c26cbf04db16219b88d6cad87b2c3dab86616e74` |

The software gate for the prepared collector source passed 335 Rust tests,
three native tests, formatting, Clippy, documentation/profile checks and the
relevant Python suites. Later documentation-only publication updates do not
relabel earlier observations as runs of changed executable code.

Deferred hardware cases, reviewed promotion, production signing, CI/repository
controls and distribution remain tracked in [release readiness](release-readiness.md).
