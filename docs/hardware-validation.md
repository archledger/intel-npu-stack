<!-- SPDX-License-Identifier: Apache-2.0 -->
# Hardware validation progress

Status as of **2026-09-13**: a controlled Fedora 44 Lunar Lake pilot works on
kernel **7.2.4-200.fc44.x86_64**. This is recorded candidate evidence, not a
completed hardware qualification or a supported public release.

## Candidate and observed scope

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

## Results

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

## Corrections and retained limitations

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

## Evidence provenance

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
