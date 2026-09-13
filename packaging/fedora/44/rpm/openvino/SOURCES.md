<!-- SPDX-License-Identifier: Apache-2.0 -->

# OpenVINO 2026.2 Fedora source assembly

The RPM build consumes only archives emitted by the sealed Fedora 44 source
lock. Network dependency resolution and upstream Ubuntu compiler archives are
not inputs.

`npu-compiler-archive-build.patch` replaces Git metadata and `git lfs pull`
assumptions with the exact compiler and compiler-ELF commits from the sealed
source lock. It rejects missing or malformed commit inputs during configure or
build. It also maps Fedora's system GTest and Level Zero targets to the target
names expected by the source-built NPU compiler.

| Archive | Destination | Purpose |
|---|---|---|
| `openvino.tar` | build root | OpenVINO `2026.2.0` |
| `npu-compiler.tar` | `thirdparty/npu-compiler` | compiler tag `npu_ud_2026_28_rc1` |
| `npu-compiler-elf-openvino.tar` | compiler `thirdparty/elf` | compiler ELF support |
| `intel-npu-compiler-llvm.tar` | compiler `thirdparty/llvm-project` | source-built LLVM/MLIR |
| `intel-npu-nn-cost-model.tar` | compiler `thirdparty/vpucostmodel` | NPU cost models |
| `level-zero-npu-extensions.tar` | NPU plugin `thirdparty/level-zero-ext` | NPU Level Zero headers |
| `openvino-flatbuffers.tar` | OpenVINO `thirdparty/flatbuffers/flatbuffers` | exact FlatBuffers source |
| `openvino-mlas.tar` | CPU plugin `thirdparty/mlas` | exact MLAS source |
| `openvino-onnx.tar` | OpenVINO `thirdparty/onnx/onnx` | exact ONNX source built against bundled Protobuf |
| `openvino-onednn-cpu.tar` | CPU plugin `thirdparty/onednn` | exact CPU oneDNN source |
| `openvino-onednn-gpu.tar` | GPU plugin `thirdparty/onednn_gpu` | exact GPU oneDNN source |
| `openvino-protobuf.tar` | OpenVINO `thirdparty/protobuf/protobuf` | exact Protobuf 3.21.12 source required by OpenVINO 2026.2 |

Fedora supplies the remaining system dependencies listed in
`provider-sources.toml`. The spec sets every corresponding system/disabled
option explicitly. The NPU compiler is added as an OpenVINO extra module and
built from source; `ENABLE_INTEL_NPU_COMPILER=OFF` specifically disables
OpenVINO's Ubuntu-only prebuilt compiler downloader.

The shared provider preserves Intel CPU and GPU plugins alongside NPU. GPU
uses the sealed oneDNN source and the exact system OpenCL headers/ICD loader
declared in the source lock. Its nested oneDNN build runs first with the same
job limit, preventing nested workers from overlapping the main build. Native
installation requires the GPU plugin and copyright document; the package
inspector rejects either CPU or GPU omission. The new GPU-enabled package
still requires clean-build and runtime qualification evidence.

`patches/0011-localize-clamp-intersection-types.patch` gives the private
NPU37XX and NPU50XX clamp result structures translation-unit identity. Their
different field layouts previously shared one global C++ type name, which the
actual GCC 16.2.1 LTO objects reproduce as an ODR error. Field layouts, arithmetic,
and callers are unchanged. After the build, `check-clamp-odr.py` requires LTO
metadata in both real objects and performs a strict partial LTO link. The
original objects fail; isolated objects compiled from the patched sources pass.

`patches/0001-use-target-core-includes.patch` removes a redundant per-source
copy of the core developer interface's includes. In the Fedora 44 builder
(CMake 4.3.0, GCC 16.2.1), that copy emits `-isystem /usr/include` for five core
sources, including `model.cpp`. The header directory then precedes libstdc++
and its `cstdlib` wrapper cannot resolve `#include_next <stdlib.h>`. The core
target already links the developer interface and inherits the required headers.
This agrees with GCC's documented [include_next search rule](https://gcc.gnu.org/onlinedocs/cpp/Wrapper-Headers.html).

The spec runs `check-core-includes.py` against Ninja's actual core compile
commands after configuration and before the full build. It rejects an empty
core command set or an explicit system include for `/usr/include`. The initial
regression run caught all five affected commands in the retained Fedora build.
The patch and regression script are RPM sources alongside the sealed archives.

`patches/0002-preserve-format-security.patch` restores explicit `-Wformat` in
OpenVINO's extra-module warning flags. Its `-Wno-all` disables the format
checking required by Fedora's `-Werror=format-security`, causing GCC 16.2.1 to
reject even safe source. The security error flag remains enabled. Before
configuration, `check-format-security.py` exercises the actual upstream CMake
macro and requires safe C/C++ to compile and unsafe format-string calls to fail
specifically on the format-security diagnostic.

`patches/0003-initialize-descriptor-before-copy.patch` makes the NPU50XX IDU
pass construct its local descriptor before copying the operation property.
The actual payload has 352 bytes; GCC 16.2.1's optimized copy-constructor path
diagnoses the field write at byte 91 against the 64-byte SmallVector-owning
object instead. Preconstructing the schema-sized payload avoids that analysis
path without changing the descriptor type, encoded bytes, or warning flags.
The exact unpatched translation unit reproduces the failure; the patched
translation unit compiles with the same generated command.

After the full build, `check-descriptor-copy.py` compiles that translation unit
to a separate temporary object and runs `descriptor-copy-probe.cpp` against
the actual descriptor implementation and built LLVM support libraries. Its
16 cases check literal encodings for every IDU mode, preservation of neighboring
bytes, payload size, and independence from the original descriptor. Run this
check serially with Ninja idle. It is additional to the compiler suite required
before RPM acceptance.

`patches/0004-remove-unused-repeating-call-counter.patch` removes the unused
counter from the output-validation loop in `ensureValidRepeatingCall`.
The loop already uses `OperandRange2D` for traversal; the counter is never
read in either release or assertion-enabled builds. Range advancement and
duplicate-output rejection are preserved. GCC 16.2.1 rejects the original
translation unit under `-Werror=unused-but-set-variable`.
After the full build, `check-repeating-calls.py` compiles that actual pass
with the generated release flags and again with assertions enabled, using
temporary proof objects and preserving warning checks. Run it serially.

`patches/0005-name-range-owners.patch` names MLIR attribute handles and LLVM
array views before their loops. Their lifetimes now explicitly cover iteration,
avoiding GCC 16.2.1 dangling-reference diagnostics while preserving bounds
checks, element references, and the optional empty-array fallback.
`patches/0006-use-injected-constructor-names.patch` removes template arguments
from constructor/destructor names, preserving their bodies and specializations.

`patches/0007-remove-absent-transpose-fq-disable.patch` removes a disable call
for `TransposeFQ`, which is absent from the sealed OpenVINO 2026.2.0 source.
The NPU compiler's validation configuration names another OpenVINO revision
that contains this pass. The patch records both immutable revisions and leaves
the distinct `TransposeFQReduction` and `TransposeFuse` passes unchanged.
After building, `check-compatibility.py` compiles all eleven affected translation
units using the actual generated release commands and disposable proof outputs.
The original source fails these compiles in the September 7 diagnostic log.
Run the check with Ninja idle; it does not replace the runtime compiler suite.

The `%build` section places `TMPDIR` under the RPM build volume. Fedora's flags
retain `-flto=auto` even with OpenVINO's `ENABLE_LTO=OFF`; linking libopenvino
exceeded the container's old 1 GiB `/tmp` tmpfs. A targeted RPM relink with
unchanged flags and disk-backed temporary storage passed, along with the
existing descriptor and repeating-call checks. Preserve adequate temporary
disk capacity when configuring a new builder.

The final link commands now explicitly use `-fno-lto`, matching the intended
`ENABLE_LTO=OFF` configuration. That CMake option alone does not override
Fedora's injected `-flto=auto`. With the pinned GCC 16.2.1/binutils 2.46.1,
the `vpux-opt` LTO link failed on executable-code and debug references even
though the required definitions existed in its inputs. The exact same
objects, libraries, order, and other flags linked successfully with a final
`-fno-lto`; the resulting executable passed `ldd -r` and `--version`.
This establishes an LTO-dependent link failure, not a specific upstream bug ID.

The spec sets the executable, module, and shared-library link flags for its
RelWithDebInfo configuration. GCC's fat objects retain native machine code,
so they support this link mode without discarding the retained compile work.
Compilation optimization, debug information, hardening, and warning flags
remain enabled. Runtime performance and package qualification still require
their separate gates; successful linking does not establish either.
Before building, `check-native-links.py` reads Ninja's expanded commands for
every C/C++ linker rule and requires the last LTO option to be `-fno-lto`.
The original graph fails this check; missing overrides and later LTO
re-enablement also fail. Run it only when Ninja is idle.
See [GCC's LTO option documentation](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)
for native linking of fat objects and link-time option precedence.

Large links share a single Ninja job pool. The spec sets
`CMAKE_JOB_POOL_LINK=link_job_pool` for parent targets and
`LLVM_PARALLEL_LINK_JOBS=1` for the bundled LLVM scope. LLVM defines that pool;
`CMAKE_JOB_POOLS` is cleared to avoid defining it twice through OpenVINO's
global pool initialization. Compile parallelism retains the selected host's
CPU budget. This addresses the observed concurrent-link saturation of 22 GiB
RAM plus 8 GiB swap and an OOM kill on archhost.

Before Ninja starts, `check-link-pool.py` validates the actual generated graph:
all C/C++ executable, module and shared-library links must use the same pool
with depth one. It rejects missing assignments, duplicate pool definitions,
larger depths and separate pools that would allow overlapping links.

`patches/0008-link-wrapper-metadata-directly.patch` makes the VPUMI37XX metadata
serialization source a direct input to `level_zero_wrapper`, with the dialect's
include paths. Under the pinned GCC/binutils LTO link, archive selection left
native references to ELF support and a Hashtable destructor unresolved even
though their definitions were present. The failure reproduced with one link
running and with either thin or regular archives. Including the same object
directly passed; its link map showed the required ELF definitions being
selected through plugin references. The patched real target also links.
Existing dependencies and warning flags remain; the original dialect copy
continues to compile with its strict flags. Generated-header prerequisites
remain reachable through the target's transitive build dependencies.

`patches/0009-normalize-compiler-test-names.patch` makes the compiler test
generator compatible with system GoogleTest's parameter-name rules. The
original harness aborts before discovery on `mobilenet-v2_VPUX.3720`. The
patch replaces punctuation with underscores and appends the parameter index
to avoid collisions; model parameters and test assertions are unchanged.
`check-compiler-test-names.py` compiles the actual header using its generated
flags and registers three cases, including spellings that normalize identically.

The RPM check invokes `check-compiler-tests.py` with the built
`vpuxCompilerL0Test` and the original bundled functional/scripts configs.
It runs every `simple_function` case: these construct their own model and
need neither external model files nor NPU hardware. The verified suite has
33 cases across 11 suites and three target families. Other model cases need
an external model corpus and are outside this self-contained check.
Each run retains its log, GTest XML and summary under the build directory;
the gate rejects zero cases, failures, errors, disabled cases and skips.
Real GoogleTest fixtures exercise the check's passing, failed, skipped and
empty-selection paths. This replaces a CTest label that returned success
without running any tests; it does not replace later hardware qualification.

Local laptop builds use a total four-CPU budget: `podman run --cpus=4` and
`rpmbuild --define '_smp_build_ncpus 4'`. Do not run another CPU-heavy project
build alongside it. Podman's CPU quota limits aggregate CPU time rather than
pinning four particular cores. This limit favors interactive responsiveness;
it is not a measured guarantee of desktop latency or build completion time.

Resume a retained RPM build through `rpmbuild -bc --short-circuit`, preserving
the original topdir and the selected host's authorized job limit. Invoking the generated CMake build
directly omits RPM environment variables: the retained Fedora linker command
failed with `environment variable 'RPM_ARCH' not defined` through
`redhat-package-notes`. Keep the RPM entry point rather than reconstructing
selected environment variables by hand.

Archhost remote builds use the same Fedora image filesystem and configuration
under Docker. The user authorized ten logical CPUs and ten jobs there, leaving
six logical CPUs outside the build CPU set. Its verified CPU topology permits
`--cpus=10 --cpuset-cpus=3-7,11-15`, with
`rpmbuild --define '_smp_build_ncpus 10'`. Keep the laptop build stopped.
Preserve `/work` and `/sources` mount paths when transferring a retained tree.

The September 7 migration reproduced a persistent Ninja 1.13.2 dependency-log
recovery warning on an isolated copy: an invalid duplicate path record remained
after recovery truncation, producing the same warning on the next invocation.
Preserve the corrupt `.ninja_deps` as evidence and regenerate that dependency
cache once; do not repeatedly resume against the invalid log. Never run a
second Ninja process against an active build tree. A diagnostic `-k 0` build
may collect independent failures, but its failing status still blocks package
acceptance and does not replace any test or validation gate.


Native RPM installation uses `CPACK_GENERATOR=RPM`; this selects OpenVINO's
GNU library/include directories and versioned plugin/CMake locations. Patch
0010 preserves that generator inside the NPU subproject, excludes standalone
CiD/CiP archives from its CPack registration, and adds a selectable native
compiler component. The spec installs the explicit runtime and development
components and preserves their upstream copyright documents. The selected
install traversal does not include the private static npu_elf build archive. Compiler libraries are installed through
CMake beside the NPU plugin, so normal install-time RPATH handling applies.
`check-install-layout.py` rejects unexpected/missing payloads, archive paths,
and absolute/escaping links before RPM's debug processing. CMake development
metadata is under `lib64/cmake/openvino2026.2.0`, as defined by this upstream
version; IR has no public unversioned development link.

The RPM check also runs `check-installed-compiler.py`: the same real cases
against the staged runtime/loader/compiler. It retains glibc loader traces and
requires actual initialization from the candidate directories, preventing an
accidental pass against development-tree libraries. Module payloads are
validated by their exact package path and digest; optional module SONAMEs must
match when present. Runtime and loader shared libraries still require their
exact SONAMEs. The inspector rejects executables/PIE payloads and does not
invent SONAME providers for modules in dependency-closure checks.

Patch 0012 removes the anonymous namespace around the shared descriptor helper
and base templates inside `vpux::VPURegMapped::detail`. Generated named register
types inherit these templates across translation units; translation-unit-local
bases otherwise give the same register incompatible type identities. Fresh
compilation of unchanged DMA composers and their real callers reproduced the
GCC LTO ODR errors for both NPU40XX and NPU50XX. An isolated header overlay with
this correction passed both strict links without changing fields or operations.
`check-descriptor-odr.py` requires actual LTO object sections and links each real
composer/caller pair with ODR and type-mismatch diagnostics treated as errors.

Patch 0013 gives LLVM's `GenericSchedulerBase` an out-of-line anchor using
its existing inherited virtual slot, following `MachineSchedStrategy`'s
convention. Fresh unmodified MachineScheduler/WindowScheduler compiles have
matching class layouts and native vtable relocations, but their strict LTO
link diagnoses a pure-virtual/scheduleTree mismatch. The anchor makes the
vtable belong to its implementation translation unit; exact fresh patched
compiles pass that strict link with the original warning and optimization
flags. No fields or scheduling operations change. `check-scheduler-odr.py`
requires both actual LTO objects and rejects ODR/type-mismatch diagnostics.
This is a reproduced compiler interaction; no upstream GCC bug identifier
or broader claim about the compiler is established by this evidence.

Patch 0014 constructs GPU broadcast output shapes directly from the selected
inference branch. The original source fails under the pinned GCC 16.2.1 with
`-Werror=free-nonheap-object` during replacement of a preinitialized result
vector. The patch keeps the shape inference calls, lock scopes, dynamic fallback
and output format logic. `check-gpu-broadcast.py` recompiles the actual source
with generated flags and requires warnings as errors without suppressing this
diagnostic. Isolated candidate verification and complete package acceptance
must pass before this correction is treated as release-qualified; GPU hardware
inference tests remain a separate gate.

The GPU component also installs its pinned `kernel_selector/cache/cache.json`
tuning data beside the plugin. The Linux kernel selector looks up that exact
path. `openvino-plugins` owns it and the staged-layout check requires it; the
install-layout regression suite covers present, missing, and unrelated data.
Package acceptance must bind the extracted cache bytes to the sealed source.

Debug extraction and DWARF compression use one worker via the supported
`_find_debuginfo_opts` job override. Compilation retains its separate job budget.
The pinned tools previously inherited ten debug workers, exhausting the
22 GiB RAM and 8 GiB swap budgets with sustained IO waiting. All debug data,
DWZ limits, strict build IDs and separate-debug validation remain enabled.
The RPM expansion regression executes the generated debug command against an
argument recorder to verify the effective job override and retained checks.

The compiler has its own `%license` directory. `install-provider-notices.py`
requires 14 exact source files covering the compiler, ELF library, cost model,
LLVM, MLIR, and LLVM Support's embedded notices. It copies whole files without
newline normalization and records their SHA-256 values. Missing files, symlinked
inputs, source/output overlap, and an existing output fail before installation.
The native layout gate still runs before these additional notice files are
installed; its existing runtime/development checks remain intact.

The compiler's License field includes its bundled LLVM terms separately from
OpenVINO's main package. LLVM's top-level Apache-with-exception and legacy NCSA
notices are retained together: they are not a blanket choice between licenses
for every file. The reviewed Support notices include BSD-2-Clause (xxHash),
BSD-3-Clause and Spencer-94 (regex), ISC (strlcpy), and Unicode-DFS-2015
(ConvertUTF). BLAKE3's full dual-license text is retained, with its Apache-2.0
option used in the aggregate expression. `LicenseRef-LLVM-MD5` identifies the
exact public-domain dedication and fallback permission text in the retained
MD5 source; it must be included as extracted licensing information in SPDX
output. This identifier is not a substitution with a differently worded BSD
license. These are reviewed minimum notices for the pinned graph; source-level
and binary-level closure review is still a separate release gate.

The upstream NPU compiler LICENSE has no final newline. The source-lock evidence
now preserves that byte sequence, replacing the earlier copy with an added
newline. The upstream commit and source archive digest did not change.

The shared notice collector runs at the end of `%prep`, before compilation.
Source45 carries the sealed source lock and Source46 carries its exact license
evidence files at their repository-relative paths. All twelve bundled source
archives must match both the lock and the explicit notice coverage map. The
prepared notice manifest records archive, spec, source-lock and notice hashes.
The install phase copies the verified OpenVINO and compiler notice groups into
their respective package-owned license directories.
