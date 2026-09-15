# SPDX-License-Identifier: Apache-2.0

Name:           intel-npu-driver
Version:        1.38.0
Release:        1.intelnpu.fc44
Summary:        Intel Neural Processing Unit userspace driver

License:        MIT AND Apache-2.0 AND (GPL-2.0-only WITH Linux-syscall-note)
URL:            https://github.com/intel/linux-npu-driver
Source0:        linux-npu-driver.tar
Source1:        level-zero-npu-extensions.tar
Source2:        npu-compiler-elf-driver.tar
Source3:        install-provider-notices.py
Source4:        provider-sources.toml
Source5:        provider-license-evidence.tar
Source6:        linux-uapi-GPL-2.0
Source7:        linux-uapi-Linux-syscall-note
Source8:        check-driver-headers.py
Source9:        level-zero.tar
Patch0:         0001-use-system-gtest-for-npu-elf-tests.patch
Patch1:         0002-keep-production-firmware-headers-for-driver.patch

ExclusiveArch:  x86_64

BuildRequires:  python3

BuildRequires:  cmake
BuildRequires:  gcc-c++
BuildRequires:  glibc-devel
BuildRequires:  gmock-devel = 1.17.0-2.fc44
BuildRequires:  gtest-devel = 1.17.0-2.fc44
BuildRequires:  libudev-devel
BuildRequires:  ninja-build
BuildRequires:  openssl-devel
BuildRequires:  patch
BuildRequires:  yaml-cpp-devel = 0.8.0-5.fc44

Requires:       oneapi-level-zero%{?_isa} = 1.32.0-1.intelnpu.fc44

Provides:       bundled(level-zero-npu-extensions) = 0^20260711gitf9ad3bf
Provides:       bundled(openvino-npu-compiler-elf) = 0^20260711gita301d97

%description
The Intel NPU userspace driver implements the Level Zero interface for Intel
client Neural Processing Units. This package does not include firmware,
kernel modules, validation applications, or compiler/runtime consumers.

%prep
%autosetup -N -n linux-npu-driver

rm -rf third_party/level-zero-npu-extensions third_party/npu_compiler_elf third_party/level-zero
tar -xf %{SOURCE1}
tar -xf %{SOURCE2}
tar -xf %{SOURCE9}
mv level-zero-npu-extensions third_party/level-zero-npu-extensions
mv npu-compiler-elf-driver third_party/npu_compiler_elf
mv level-zero third_party/level-zero

%autopatch -p1

/usr/bin/python3 %{SOURCE3} --kind driver \
    --source "$PWD" --archives "$(dirname -- '%{SOURCE0}')" --spec %{_specdir}/intel-npu-driver.spec \
    --source-lock %{SOURCE4} --license-evidence %{SOURCE5} \
    --output ../provider-notices

%build
%cmake \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_LIBDIR=%{_lib} \
    -DENABLE_COMPILATION_FLAGS_OVERRIDE=OFF \
    -DENABLE_ELF_TESTS=ON \
    -DENABLE_GOOGLETEST_FROM_SUBMODULE=OFF \
    -DENABLE_LEVEL_ZERO_FROM_SUBMODULE=OFF \
    -DENABLE_NPU_ALT_DEPENDENCY_PATH_OVERRIDE=OFF \
    -DENABLE_NPU_COMPILER_BUILD=OFF \
    -DENABLE_NPU_PERFETTO_BUILD=OFF \
    -DENABLE_OFFLINE_COMPILATION_SUPPORT=OFF \
    -DENABLE_OPENVINO_PACKAGE=OFF \
    -DENABLE_TOOLS_BUILD=OFF \
    -DENABLE_VALIDATION_BUILD=OFF \
    -DENABLE_YAML_CPP_FROM_SUBMODULE=OFF \
    -DFETCHCONTENT_SOURCE_DIR_LEVEL_ZERO=$PWD/third_party/level-zero
%cmake_build

%install
%cmake_install
mkdir -p %{buildroot}%{_licensedir}
cp -a ../provider-notices/intel-npu-driver %{buildroot}%{_licensedir}/
rm -rf %{buildroot}/lib/firmware %{buildroot}%{_prefix}/lib/firmware
rm -f \
    %{buildroot}%{_libdir}/liballocator_utils.so \
    %{buildroot}%{_libdir}/libze_intel_npu.so \
    %{buildroot}%{_libdir}/libze_loader.so \
    %{buildroot}%{_libdir}/libze_loader.so.1 \
    %{buildroot}%{_libdir}/libze_loader.so.1.* \
    %{buildroot}%{_libdir}/libze_validation_layer.so* \
    %{buildroot}%{_libdir}/libze_tracing_layer.so*

# DWARF paths are rooted under the CMake build directory. Stage matching
# source paths there so find-debuginfo can create a complete debugsource RPM.
mkdir -p redhat-linux-build/third_party/npu_compiler_elf
cp -a third_party/npu_compiler_elf/. \
    redhat-linux-build/third_party/npu_compiler_elf/
cp -a umd/. redhat-linux-build/umd/

%check
/usr/bin/python3 %{SOURCE8} redhat-linux-build
redhat-linux-build/bin/npu_shared_tests
# These four suites cross the Task 3 package boundary: they require either the
# separately packaged NPU compiler or a compiled validation blob that is not in
# the source lock. Run every self-contained mocked Level Zero test here.
redhat-linux-build/bin/ze_intel_npu_tests \
    --gtest_filter=-GraphExecution.*:CompilerInDriver.*:GraphNativeTest.*:CommandListGraphApiTest.*
/usr/bin/ctest \
    --test-dir redhat-linux-build/third_party/npu_compiler_elf \
    --output-on-failure \
    --force-new-ctest-process \
    -j%{_smp_build_ncpus}

%files
%license %{_licensedir}/intel-npu-driver
%doc README.md
%{_libdir}/libze_intel_npu.so.1
%{_libdir}/libze_intel_npu.so.%{version}

%changelog
* Mon Sep 15 2026 Intel NPU Stack maintainers <maintainers@example.invalid> - 1.38.0-1.intelnpu.fc44
- Upgrade to the v1.38.0 source pin. Build the in-tree Intel-matched Level Zero
  1.32.0 loader for linking from the source lock and require the separate
  oneapi-level-zero 1.32.0 candidate at runtime.
* Fri Sep 04 2026 Intel NPU Stack maintainers <maintainers@example.invalid> - 1.35.0-1.intelnpu.fc44
- Build the source-locked Fedora 44 candidate userspace driver.
