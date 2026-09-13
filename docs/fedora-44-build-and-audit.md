<!-- SPDX-License-Identifier: Apache-2.0 -->
# Fedora 44 build and release audit

Phase 3A passed on 2026-09-11 for the frozen candidate below. Installation,
VM lifecycle, hardware qualification, signing and publication have not passed.
The repository profile remains a historical development fixture; the final
candidate is the separately generated, checksum-bound evidence artifact.

## Evidence identity and retention

The final source is the 420-file gate21 snapshot at base commit
`d1e2d0c6e7553c635281fd197cca7436181d913b` plus its recorded uncommitted changes.
This commit alone does not identify the build source. The exact tools source
tar SHA-256 is
`49ef2baf2a581dc023d93aedf54a6b69d7416bbb1b79d533c5cceea7696ebfb6`.
The vendor tar SHA-256 is
`e893f800b53e592d9df7ca5786bfb6d5c5bdf30f952e0914b2c4fc27fde966ad`.
The final tools SDK image is
`sha256:98a4e12402bd7df6732f971b7a6c4fb5339fe70221054152096ef9b8ee2534c1`.

The retained evidence contains OpenVINO pair4, driver pair5, firmware pair6,
tools pair4, quality22, final component SBOM bundles and final aggregate3.
The aggregate terminal result is `passed: true`, `release_ready: false`,
verified at `2026-09-11T17:17:45.472985+00:00`. Its scope includes 64 actual
artifact instances, 32 identical comparisons, 61 SPDX documents, fourteen
runtime candidate bindings, 420 source hashes and eleven signed rollback RPMs.
These records must be included in the eventual release evidence; they are not
yet published at a public URL.

Pair comparison document SHA-256 values:

| Component | Comparison SHA-256 |
|---|---|
| OpenVINO | `91a3dc5ef3b7c93edb3ebdf3ef844ccd9eeff1dcfffcaf5eb95792520f815b00` |
| Driver | `9d34433b5941ec95a70a1055381468d7d7f43a993c21bda77f37e41d2c11f68d` |
| Firmware | `140e017df251d573fc6dde691ac60bcf906b25da61a81eae0e77c5704a2032fd` |
| Tools | `01c88de0311ad97893b2c81eeb3f5490cb5218077109897c16e22aa51b92fa7d` |

The shared evidence exports include `2026-09-11-tools4-quality22-driver-bundle`,
`2026-09-11-tools-source-firmware-bundle`,
`2026-09-11-tools-final-bundle-candidate`,
`2026-09-11-runtime-source-addendum`, and `2026-09-11-final-aggregate3`.
Source/build caches remain separate from these audit records.

## Final runtime candidate

The candidate remains unqualified. Its SHA256 is `2c91fad76dcf67681bf8ae425b526906976c69cdbedd3060a94aa15209b9644f`. The provider source lock is `2653ffaf0ee336e3bf28086dd27e8cced9761dc1830a34b44f91434445e9e8ed`; the manifest embedded in tools is `a5a41ac2e2390a8fbb573c7359f9cf6b134415e32e1e407abadc083d3d17b8d3`. The candidate is generated outside the tools source archive and RPM, avoiding an impossible self-RPM hash cycle.

| Package | Exact NEVR | RPM SHA256 |
|---|---|---|
| intel-npu-compiler | `0:2026.2.0-1.intelnpu.fc44` | `b4896cb744d39fe6f3ed02cb05e7306f82f2256e2581024d11fa58bd1bfae056` |
| intel-npu-driver | `0:1.35.0-1.intelnpu.fc44` | `fe61bf40595679a56ec3d73e2528e3aeb9ef3604e285373a356892d252b33ad7` |
| intel-npu-stack | `0:0.1.0-1.intelnpu.fc44` | `8807d1bc9a140e011ee306c7e170729b20a4414809675875de6e0c9fd84bbb89` |
| intel-npu-stack-firmware | `0:1.35.0-1.intelnpu.fc44` | `8b2c0181293cb4d8373841decf15cc0dc251aba25181961371f6cef8baf39950` |
| intel-npu-stack-tools | `0:0.1.0-1.intelnpu.fc44` | `a7a484f7a7d8ee76fa955a1f41aa27a7f8e702eba21d2378b8efb961537f3499` |
| libopenvino-ir-frontend | `0:2026.2.0-1.intelnpu.fc44` | `a7b2fa09de4153d5442168a5d6a2cd00be36a1c4e43d8406be7400deba3b9ae8` |
| libopenvino-onnx-frontend | `0:2026.2.0-1.intelnpu.fc44` | `4489ec6b166fa8b5b7fc554333dfed0b9e9625d50856a336924220383c258113` |
| libopenvino-paddle-frontend | `0:2026.2.0-1.intelnpu.fc44` | `69a11b3fd9885e001d1dad28812a2129f737e51a806e078a9c12d42d52e8725b` |
| libopenvino-pytorch-frontend | `0:2026.2.0-1.intelnpu.fc44` | `623df46fdf834509040dd522342dd24645035c17879796a1b8c9e4b47bfaac1c` |
| libopenvino-tensorflow-frontend | `0:2026.2.0-1.intelnpu.fc44` | `542948c34d2e60cbcead49ae53bff4fcee5f72cec3a74910e43b02fdaafc00c8` |
| libopenvino-tensorflow-lite-frontend | `0:2026.2.0-1.intelnpu.fc44` | `ee02fe1ef40d07662c2f3e34518cda31d4b6f6d0af5fd8f6d74cd7bb3566b3fc` |
| oneapi-level-zero | `0:1.28.6-1.fc44` | `0b61bf4cc439afa7f47ab403d9d69fbc390fda36fa1cb41892c88e7c6eb02a2a` |
| openvino | `0:2026.2.0-1.intelnpu.fc44` | `964c32809395c0bce820fd410e00b6415dcacebff355d888e4e05e81a5f1cfea` |
| openvino-plugins | `0:2026.2.0-1.intelnpu.fc44` | `9cee06382be12cb890ed3789050472bed2503efe23a0da227afb948252924d77` |

## Matched evidence

- Frozen source: 420 files in gate21, freshly confirmed unchanged locally. The complete quality22 gate uses a fresh Cargo target and passes 211 Rust tests and three native tests, including the production driver header regression. Formatting, Clippy, documentation, profiles, source lock and stdlib notices pass.
- OpenVINO: 20 binary RPMs and one SRPM are byte-identical across independent builds. Final acceptance, source preparation, CPU consumer, compiler harness, source/debug bindings and SPDX bundle pass.
- Driver: three binary RPMs and one SRPM are byte-identical. Both builds pass 60 shared, 118 driver and 184 ELF tests. The dependency guard confirms 27 production objects use production firmware headers, excluding restored test fixtures.
- Firmware: one binary RPM and one SRPM are byte-identical. All three regular payload files bind to exact source members or independently regenerated notice JSON. The full original Intel firmware redistribution text is retained.
- Tools: four binary RPMs and one SRPM are byte-identical. All 513 regular payload files, three executables and four debug files bind to exact source/generated/notice or ELF identity evidence. The source audit records 40 actual Cargo libraries and 19 Fedora Rust sysroot libraries.
- Source/static SPDX: four component bundles have official SPDX 2.3 schema and reference checks. Raw RPM package metadata remains unchanged. Exact custom-license texts are supplied; external Fedora package declarations remain metadata references, with NOASSERTION where a file-level conclusion is not established.
- Common GNU runtime: the approved exact GCC and glibc source RPMs were acquired and their RPM header/payload digests verified. They are unsigned Koji source RPMs; no cryptographic RPM signature is claimed. GCC source-notice coverage records all 298 possible archive members, including explicit alternative source matches and thin wrappers. Seven glibc startup/nonshared files preserve their exact additional linking permission. Fedora patches do not modify the reviewed glibc sources or GCC runtime notices. The source addendum binds actual native link dependencies and the CLI compiler-driver expansion to exact prebuilt-input hashes.
- Runtime archives: libc_nonshared has four recorded members, each matched to its source notice. libdl.a, libpthread.a and librt.a are verified empty compatibility archives. Recording a linker-read archive does not assert all its members survive linking.
- Redistribution scope: project-authored code uses Apache-2.0; third-party choices and full notices remain separately recorded. The GCC runtime exception applies to eligible target-code combinations; the recorded GCC/Rust/LLVM compilation inputs and original runtime notices are preserved. Glibc startup/soft-fp additional permissions apply to compiled combinations, not standalone modification/source distribution. Full original license text and source RPMs remain available as evidence. No generic public-domain license text is invented from Fedora metadata.
- Fedora owns the kernel, intel_vpu module and Level Zero loader. The Level Zero 1.28.6 deviation from Intel's 1.28.2 matrix remains explicitly unqualified. Distro-only reference source archives are not redistribution inputs.
- Candidate generation validates exact ownership and requirements of fourteen runtime RPMs. Stable promotion is refused; overwrite and duplicate-ID negative controls pass. Cached eleven signed Fedora rollback RPMs are available; availability does not prove a rollback transaction.

## Errors retained and corrected

Quality21 reused a Cargo target after frozen-source timestamps moved backward; it ran 210 stale tests. Quality22 uses a fresh target and explicitly verifies the new test executed. No affected RPM evidence is borrowed from quality21.

Initial driver debug binding assumed equal pre/post RPM build IDs. RPM's recorded find-debuginfo step deliberately reseeds them. The final proof instead checks execution headers and every allocated section apart from the expected build-ID note, then independently checks final runtime/debug IDs and CRCs.

The tools audit adapter initially assumed the provider controller's comparison layout. The final adapter reads the actual tools compare directory and build log. The first profile validation correctly rejected two identical IDs in one directory; the final candidate validates separately and retains duplicate rejection as a negative control.

The OpenVINO link collector encountered phony compdb aliases as well as real link commands. The final capture preserves the matching records, requires one actual command, and validates complete Ninja dependency records for all fifteen targets. No package was rebuilt for these audit corrections.

## Phase 3A exit decision

The final aggregate audit passed at 2026-09-11T17:17:45.472985+00:00 with exit 0: 28 project binary RPMs, four SRPMs, 32 independent byte-identical comparisons across 64 artifact instances, 61 SPDX documents, 14 runtime candidate RPMs, 14,892 unique regular payload paths, 420 unchanged source files, and eleven signed Fedora rollback RPMs. The raw Syft custom-license text is supplied by each corresponding bound document, with identical package metadata required. Signature checks bind the exact Fedora 44 fingerprint and both header/payload digests.

**Phase 3A: PASS for the exact frozen inputs described here.** Reviewed source policy permits the planned redistribution with the retained original notices and exceptions; the three Fedora dist-git reference archives remain external-only. All redistribution evidence must travel with the release, including the GNU runtime addendum and its exact notice/source records. This is the engineering release-evidence decision for these inputs, not a claim that the external compiler was rebuilt or that the hardware is qualified.

The normal native package identities and dependency/ownership checks support the proposed DNF replacement boundary. Actual removal, upgrade and rollback transactions are Phase 3B acceptance criteria; cached rollback files alone do not satisfy them.

The 420-file gate21 snapshot and corresponding RPMs remain immutable. Later documentation and installer changes are a new source state. Provider rebuilds are required only when their relevant source, recipe, dependency, tool or configuration changes; these documentation edits do not relabel existing RPMs as outputs from a newer tree. New installer/profile packaging must receive its own matching build and validation evidence.

Full public-use readiness remains incomplete: bootstrap and VM lifecycle, CI protections, independent hardware qualification, signed distribution and protected publication remain. Stable selection must continue to refuse this candidate. No host installation or hardware retry is part of this evidence review.

## Isolated audit tools

The comparison image is
`sha256:99fc00fcdb448ef5e332b02b97c9d8fc9f372a3dfd14e6b5215b17b073d6ed77`.
It contains Syft 1.51.1 and Fedora diffoscope 324-1.fc44. Syft's official
[release](https://github.com/anchore/syft/releases/tag/v1.51.1) tarball digest is
`8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3`.
The archive was checked against GitHub's release-asset digest and the downloaded
checksum list. Signature and certificate files were retained, but cryptographic
signature verification has not been completed; checksum verification must not
be described as signature verification.

Fedora diffoscope and rpmlint require conflicting Python magic providers.
The comparison image therefore uses diffoscope's provider; the original build
image retains rpmlint and all package checks. Its digest is
`sha256:4e60efdebefc073b07c6ac4fdb2ea02ecf86ee74874c8b0ad1532f99a9791016`.
No build or comparison may pull an image, access the network, or install host
packages. Each invocation must use its recorded immutable image identifier.


## Provider pair gate

`scripts/check-fedora-packages.sh` accepts an explicit recipe (`firmware`,
`driver`, or `openvino`), canonical source-cache and empty output directories,
a tested xtask executable, two immutable image digests, source epoch, job count
and CPU set. It uses `podman` by default; `--runtime docker` selects the cached
Docker images on archhost. It never pulls images or enables container networking.
The provider gate rebuilds source archives from the offline Git cache, verifies
the source lock, stages three independent source roots, and runs a notice
preflight before either full build.

The two host build directories are mounted at the same `/work` container path.
RPM 6 records the macro-expanded spec in the SRPM, including build paths, and
the binary RPM records the SRPM signature. The first real firmware regression
showed that different internal paths changed both artifacts despite identical
file payloads. A stable container path fixes the input environment; no difference
is hidden from the comparison.

Each build verifies the complete expected RPM name set, versions and architecture,
rejects package scripts and ownership outside `/usr`, binds every regular payload
and symlink to RPM headers, checks all SRPM inputs against their sealed hashes,
verifies package-owned notices, and runs rpmlint. The comparison produces raw
SPDX for every binary RPM, requires its package identity and RPM SHA256, and
compares both binary and source RPMs. Either a tool error or unequal artifact
bytes fails the gate, even when the other check reports success.

The result is explicitly a provider-pair result with `release_ready = false`.
It does not replace the existing full provider dependency/ELF inspectors or the
remaining source/static dependency and redistribution audit. The tools recipe
requires a newly generated installed-provider manifest and follows the native
provider outputs; it cannot use the historical manifest as final release evidence.

## Original-notice lint review

The provider gate runs unfiltered rpmlint 2.8.0 and saves its original stdout,
stderr and exit code under each build's `rpmlint/` directory. `result.json`
records the separate lint-policy decision. Two reviewed `incorrect-fsf-address`
findings may pass that policy because the original notice bytes must be preserved:

| Package and architecture | Installed notice | Required SHA256 |
| --- | --- | --- |
| `openvino.x86_64` | `/usr/share/licenses/openvino/src/plugins/intel_cpu/thirdparty/onednn/third_party/ittnotify/ittptmark64.S` | `15e6b25d6e6ef3f4f5866423d71d22d7026e4ed0a6a707e7d6777abcf4b620ad` |
| `intel-npu-driver.x86_64` | `/usr/share/licenses/intel-npu-driver/linux-uapi/GPL-2.0` | `f6b78c087c3ebdf0f3c13415070dd480a3f35d8fc76f3d02180a407c1c812f79` |

The wrapper independently verifies the complete package notice inventory against
the prepared manifest, including payload bytes, RPM headers, license flags and
modes. It binds that result to the actual RPM SHA256. Every diagnostic field must
match exactly. Different bytes, missing verification, additional errors, malformed
output, tool failures and threshold failures remain blocking. It adds no rpmlint
filter and never edits either notice. A policy pass preserves rpmlint's original
nonzero exit code; it does not make an earlier failed run pass or replace package,
source, reproducibility or release acceptance.
