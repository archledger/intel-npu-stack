# SPDX-License-Identifier: Apache-2.0

%global so_ver 2620
# Large DWARF payloads exceed the builder memory budget when processed together.
# Keep compilation parallel while serializing debug extraction and compression.
%global _find_debuginfo_opts %{?_find_debuginfo_opts} -j1

Name:           openvino
Version:        2026.2.0
Release:        1.intelnpu.fc44
Summary:        Toolkit for optimizing and deploying AI inference

License:        Apache-2.0 AND MIT AND BSL-1.0 AND HPND AND BSD-3-Clause AND (GPL-2.0-only OR BSD-3-Clause)
URL:            https://github.com/openvinotoolkit/openvino
Source0:        openvino.tar
Source1:        npu-compiler.tar
Source2:        npu-compiler-elf-openvino.tar
Source3:        intel-npu-compiler-llvm.tar
Source4:        intel-npu-nn-cost-model.tar
Source5:        level-zero-npu-extensions.tar
Source6:        openvino-flatbuffers.tar
Source7:        openvino-mlas.tar
Source8:        openvino-onednn-cpu.tar
Source9:        openvino-onednn-gpu.tar
Source10:       openvino-protobuf.tar
Source11:       npu-compiler-archive-build.patch
Source12:       openvino-onnx.tar
Source13:       0001-use-target-core-includes.patch
Source14:       check-core-includes.py
Source15:       0002-preserve-format-security.patch
Source16:       check-format-security.py
Source17:       0003-initialize-descriptor-before-copy.patch
Source18:       check-descriptor-copy.py
Source19:       descriptor-copy-probe.cpp
Source20:       0004-remove-unused-repeating-call-counter.patch
Source21:       check-repeating-calls.py
Source22:       0005-name-range-owners.patch
Source23:       0006-use-injected-constructor-names.patch
Source24:       0007-remove-absent-transpose-fq-disable.patch
Source25:       check-compatibility.py
Source26:       check-link-pool.py
Source27:       0008-link-wrapper-metadata-directly.patch
Source28:       check-native-links.py
Source29:       0009-normalize-compiler-test-names.patch
Source30:       check-compiler-test-names.py
Source31:       compiler-test-names-probe.cpp
Source32:       check-compiler-tests.py
Source33:       0010-native-compiler-install-component.patch
Source34:       check-install-layout.py
Source35:       check-installed-compiler.py
Source36:       0011-localize-clamp-intersection-types.patch
Source37:       check-clamp-odr.py
Source38:       0012-share-register-descriptor-template-types.patch
Source39:       check-descriptor-odr.py
Source40:       0013-anchor-generic-scheduler-vtable.patch
Source41:       check-scheduler-odr.py
Source42:       0014-construct-gpu-broadcast-results-directly.patch
Source43:       check-gpu-broadcast.py

ExclusiveArch:  x86_64

BuildRequires:  cmake = 4.3.0-1.fc44
BuildRequires:  gcc = 16.2.1-2.fc44
BuildRequires:  gcc-c++ = 16.2.1-2.fc44
BuildRequires:  gflags-devel = 2.2.2-19.fc44
BuildRequires:  glibc-devel = 2.43-8.fc44
BuildRequires:  gmock-devel = 1.17.0-2.fc44
BuildRequires:  gtest-devel = 1.17.0-2.fc44
BuildRequires:  json-devel = 3.12.0-2.fc44
BuildRequires:  libedit-devel = 3.1-59.20260512cvs.fc44
BuildRequires:  libffi-devel = 3.5.2-2.fc44
BuildRequires:  libstdc++-static = 16.2.1-2.fc44
BuildRequires:  libxml2-devel = 2.12.10-6.fc44
BuildRequires:  libzstd-devel = 1.5.7-5.fc44
BuildRequires:  ncurses-devel = 6.6-1.fc44
BuildRequires:  ninja-build = 1.13.2-2.fc44
BuildRequires:  ocl-icd-devel = 2.3.4-2.fc44
BuildRequires:  oneapi-level-zero-devel = 1.28.6-1.fc44
BuildRequires:  opencl-headers = 3.0-35.20250708git8a97ebc.fc44
BuildRequires:  patch = 2.8-4.fc44
BuildRequires:  pugixml-devel = 1.16-1.fc44
BuildRequires:  python3 = 3.14.7-1.fc44
BuildRequires:  python3-pyyaml = 6.0.3-3.fc44
BuildRequires:  snappy-devel = 1.2.2-4.fc44
BuildRequires:  tbb-devel = 2022.3.0-3.fc44
BuildRequires:  xbyak-devel = 7.24.2-3.fc44
BuildRequires:  zlib-ng-compat-devel = 2.3.3-3.fc44

Requires:       libopenvino-ir-frontend%{?_isa} = %{version}-%{release}
Requires:       libopenvino-onnx-frontend%{?_isa} = %{version}-%{release}
Requires:       libopenvino-paddle-frontend%{?_isa} = %{version}-%{release}
Requires:       libopenvino-pytorch-frontend%{?_isa} = %{version}-%{release}
Requires:       libopenvino-tensorflow-frontend%{?_isa} = %{version}-%{release}
Requires:       libopenvino-tensorflow-lite-frontend%{?_isa} = %{version}-%{release}

%description
OpenVINO is an open-source toolkit for optimizing and deploying deep learning
models from cloud to edge. This Fedora build includes the source-built Intel
NPU runtime path and contains no Ubuntu compiler binaries.

%package devel
Summary:        Development files for OpenVINO
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
Headers, CMake metadata, and development links for OpenVINO applications.

%package plugins
Summary:        OpenVINO runtime plugins
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       intel-npu-compiler%{?_isa} = %{version}-%{release}

%description plugins
OpenVINO automatic, heterogeneous, Intel CPU, GPU, and NPU runtime plugins.

%package -n intel-npu-compiler
Summary:        Source-built OpenVINO Intel NPU compiler
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       intel-npu-driver%{?_isa} = 1.35.0-1.intelnpu.fc44

%description -n intel-npu-compiler
The Intel NPU compiler and compiler loader built from the sealed source graph.

%package -n libopenvino-ir-frontend
Summary:        OpenVINO IR frontend
Requires:       %{name}%{?_isa} = %{version}-%{release}
%description -n libopenvino-ir-frontend
OpenVINO frontend for Intermediate Representation models.

%package -n libopenvino-onnx-frontend
Summary:        OpenVINO ONNX frontend
Requires:       %{name}%{?_isa} = %{version}-%{release}
%description -n libopenvino-onnx-frontend
OpenVINO frontend for ONNX models.

%package -n libopenvino-paddle-frontend
Summary:        OpenVINO Paddle frontend
Requires:       %{name}%{?_isa} = %{version}-%{release}
%description -n libopenvino-paddle-frontend
OpenVINO frontend for PaddlePaddle models.

%package -n libopenvino-pytorch-frontend
Summary:        OpenVINO PyTorch frontend
Requires:       %{name}%{?_isa} = %{version}-%{release}
%description -n libopenvino-pytorch-frontend
OpenVINO frontend for PyTorch models.

%package -n libopenvino-tensorflow-frontend
Summary:        OpenVINO TensorFlow frontend
Requires:       %{name}%{?_isa} = %{version}-%{release}
%description -n libopenvino-tensorflow-frontend
OpenVINO frontend for TensorFlow models.

%package -n libopenvino-tensorflow-lite-frontend
Summary:        OpenVINO TensorFlow Lite frontend
Requires:       %{name}%{?_isa} = %{version}-%{release}
%description -n libopenvino-tensorflow-lite-frontend
OpenVINO frontend for TensorFlow Lite models.

%prep
%autosetup -N -n openvino

rm -rf \
    src/plugins/intel_cpu/thirdparty/mlas \
    src/plugins/intel_cpu/thirdparty/onednn \
    src/plugins/intel_gpu/thirdparty/onednn_gpu \
    src/plugins/intel_npu/thirdparty/level-zero-ext \
    thirdparty/flatbuffers/flatbuffers \
    thirdparty/npu-compiler \
    thirdparty/onnx/onnx \
    thirdparty/protobuf/protobuf

tar -xf %{SOURCE7}
mv openvino-mlas src/plugins/intel_cpu/thirdparty/mlas
tar -xf %{SOURCE8}
mv openvino-onednn-cpu src/plugins/intel_cpu/thirdparty/onednn
tar -xf %{SOURCE9}
mv openvino-onednn-gpu src/plugins/intel_gpu/thirdparty/onednn_gpu
tar -xf %{SOURCE5}
mv level-zero-npu-extensions src/plugins/intel_npu/thirdparty/level-zero-ext
tar -xf %{SOURCE6}
mv openvino-flatbuffers thirdparty/flatbuffers/flatbuffers
tar -xf %{SOURCE10}
mv openvino-protobuf thirdparty/protobuf/protobuf
tar -xf %{SOURCE12}
mv openvino-onnx thirdparty/onnx/onnx

tar -xf %{SOURCE1}
mv npu-compiler thirdparty/npu-compiler
rm -rf \
    thirdparty/npu-compiler/thirdparty/elf \
    thirdparty/npu-compiler/thirdparty/llvm-project \
    thirdparty/npu-compiler/thirdparty/vpucostmodel
tar -xf %{SOURCE2}
mv npu-compiler-elf-openvino thirdparty/npu-compiler/thirdparty/elf
tar -xf %{SOURCE3}
mv intel-npu-compiler-llvm thirdparty/npu-compiler/thirdparty/llvm-project
tar -xf %{SOURCE4}
mv intel-npu-nn-cost-model thirdparty/npu-compiler/thirdparty/vpucostmodel

/usr/bin/patch --batch --forward --fuzz=0 -p1 \
    -d thirdparty/npu-compiler < %{SOURCE11}
/usr/bin/patch --batch --forward --fuzz=0 -p1 < %{SOURCE13}
/usr/bin/patch --batch --forward --fuzz=0 -p1 < %{SOURCE15}
/usr/bin/patch --batch --forward --fuzz=0 -p1 \
    -d thirdparty/npu-compiler < %{SOURCE17}
/usr/bin/patch --batch --forward --fuzz=0 -p1 \
    -d thirdparty/npu-compiler < %{SOURCE20}
/usr/bin/patch --batch --forward --fuzz=0 -p1 \
    -d thirdparty/npu-compiler < %{SOURCE22}
/usr/bin/patch --batch --forward --fuzz=0 -p1 \
    -d thirdparty/npu-compiler < %{SOURCE23}
/usr/bin/patch --batch --forward --fuzz=0 -p1 \
    -d thirdparty/npu-compiler < %{SOURCE24}
/usr/bin/patch --batch --forward --fuzz=0 -p1 \
    -d thirdparty/npu-compiler < %{SOURCE27}
/usr/bin/patch --batch --forward --fuzz=0 -p1 \
    -d thirdparty/npu-compiler < %{SOURCE29}

/usr/bin/patch --batch --forward --fuzz=0 -p1 \
    -d thirdparty/npu-compiler < %{SOURCE33}
/usr/bin/patch --batch --forward --fuzz=0 -p1 \
    -d thirdparty/npu-compiler < %{SOURCE36}
/usr/bin/patch --batch --forward --fuzz=0 -p1 \
    -d thirdparty/npu-compiler < %{SOURCE38}
/usr/bin/patch --batch --forward --fuzz=0 -p1 \
    -d thirdparty/npu-compiler < %{SOURCE40}
/usr/bin/patch --batch --forward --fuzz=0 -p1 < %{SOURCE42}

%build
# Keep temporary storage on disk for both native and diagnostic LTO links.
# Keep linker scratch files on the build volume, outside container /tmp tmpfs.
mkdir -p %{_tmppath}/openvino-link
export TMPDIR=%{_tmppath}/openvino-link
# ExternalProject's nested oneDNN build must obey the same job budget.
export CMAKE_BUILD_PARALLEL_LEVEL=%{_smp_build_ncpus}
/usr/bin/python3 %{SOURCE16} %{_vpath_srcdir}
# Override Fedora's LTO flags at final link; retain optimized fat-object inputs.
%cmake \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCPACK_GENERATOR=RPM \
    -DCMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO=-fno-lto \
    -DCMAKE_MODULE_LINKER_FLAGS_RELWITHDEBINFO=-fno-lto \
    -DCMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO=-fno-lto \
    -DCMAKE_JOB_POOLS= \
    -DCMAKE_JOB_POOL_LINK=link_job_pool \
    -DLLVM_PARALLEL_LINK_JOBS=1 \
    -DCMAKE_COMPILE_WARNING_AS_ERROR=OFF \
    -DCMAKE_DISABLE_FIND_PACKAGE_ONNX=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DENABLE_AUTO=ON \
    -DENABLE_AUTO_BATCH=OFF \
    -DENABLE_CLANG_FORMAT=OFF \
    -DENABLE_CPPLINT=OFF \
    -DENABLE_COVERAGE=OFF \
    -DENABLE_GAPI_PREPROCESSING=OFF \
    -DENABLE_HETERO=ON \
    -DENABLE_INTEL_CPU=ON \
    -DENABLE_INTEL_GPU=ON \
    -DENABLE_INTEL_NPU=ON \
    -DENABLE_INTEL_NPU_COMPILER=OFF \
    -DENABLE_INTEL_NPU_INTERNAL=OFF \
    -DENABLE_INTEL_NPU_PROTOPIPE=OFF \
    -DENABLE_INTEGRITYCHECK=OFF \
    -DENABLE_JS=OFF \
    -DENABLE_LTO=OFF \
    -DENABLE_MLAS_FOR_CPU=ON \
    -DENABLE_NCC_STYLE=OFF \
    -DENABLE_NPU_PLUGIN_ENGINE=ON \
    -DENABLE_ONEDNN_FOR_GPU=ON \
    -DENABLE_OV_IR_FRONTEND=ON \
    -DENABLE_OV_JAX_FRONTEND=OFF \
    -DENABLE_OV_ONNX_FRONTEND=ON \
    -DENABLE_OV_PADDLE_FRONTEND=ON \
    -DENABLE_OV_PYTORCH_FRONTEND=ON \
    -DENABLE_OV_TF_FRONTEND=ON \
    -DENABLE_OV_TF_LITE_FRONTEND=ON \
    -DENABLE_PRECOMPILED_HEADERS=OFF \
    -DENABLE_PROFILING_ITT=OFF \
    -DENABLE_PYTHON=OFF \
    -DENABLE_SAMPLES=OFF \
    -DENABLE_SYSTEM_FLATBUFFERS=OFF \
    -DENABLE_SYSTEM_LEVEL_ZERO=ON \
    -DENABLE_SYSTEM_LIBS_DEFAULT=ON \
    -DENABLE_SYSTEM_OPENCL=ON \
    -DENABLE_SYSTEM_PROTOBUF=OFF \
    -DENABLE_SYSTEM_PUGIXML=ON \
    -DENABLE_SYSTEM_SNAPPY=ON \
    -DENABLE_SYSTEM_TBB=ON \
    -DENABLE_SYSTEM_ZLIB=ON \
    -DENABLE_TESTS=OFF \
    -DENABLE_WHEEL=OFF \
    -DENABLE_ZEROAPI_BACKEND=ON \
    -DONNX_BUILD_PYTHON=OFF \
    -Dprotobuf_BUILD_TESTS=OFF \
    -DTHREADING=TBB \
    -DGPU_RT_TYPE=OCL \
    -DOPENVINO_EXTRA_MODULES=%{_vpath_srcdir}/thirdparty/npu-compiler \
    -DBUILD_COMPILER_FOR_DRIVER=ON \
    -DENABLE_DRIVER_COMPILER_ADAPTER=OFF \
    -DENABLE_NPU_MONO=OFF \
    -DENABLE_PREBUILT_LLVM_MLIR_LIBS=OFF \
    -DENABLE_PRIVATE_TESTS=OFF \
    -DNPU_COMPILER_SOURCE_COMMIT=6a7a7c531f54baed1dddfda1b80299413c4c6943 \
    -DNPU_LOADER_SOURCE_COMMIT=0c96256285114a596988bfa6e4face817165396c
/usr/bin/python3 %{SOURCE26} %{_vpath_builddir}
/usr/bin/python3 %{SOURCE28} %{_vpath_builddir}
/usr/bin/python3 %{SOURCE14} %{_vpath_builddir}
# Finish the nested build first so its workers cannot overlap main-build jobs.
%cmake_build --target onednn_gpu_build
%cmake_build
/usr/bin/python3 %{SOURCE37} %{_vpath_builddir}
/usr/bin/python3 %{SOURCE39} %{_vpath_builddir}
/usr/bin/python3 %{SOURCE41} %{_vpath_builddir}
/usr/bin/python3 %{SOURCE43} %{_vpath_builddir}
/usr/bin/python3 %{SOURCE18} %{_vpath_srcdir} %{_vpath_builddir} %{SOURCE19}
/usr/bin/python3 %{SOURCE21} %{_vpath_srcdir} %{_vpath_builddir}
/usr/bin/python3 %{SOURCE25} %{_vpath_srcdir} %{_vpath_builddir}
/usr/bin/python3 %{SOURCE30} %{_vpath_srcdir} %{_vpath_builddir} %{SOURCE31}

%install
# Install only the native runtime/development payload; standalone CiD and
# developer archives are separate upstream distribution components.
for component in core core_dev ir onnx paddle pytorch tensorflow tensorflow_lite multi hetero cpu gpu npu npu_compiler; do
    DESTDIR=%{buildroot} /usr/bin/cmake --install %{_vpath_builddir} --component "$component"
done
/usr/bin/python3 %{SOURCE34} %{buildroot}

%check
/usr/bin/python3 %{SOURCE32} \
    %{_vpath_srcdir}/bin/intel64/RelWithDebInfo/vpuxCompilerL0Test \
    %{_vpath_srcdir}/thirdparty/npu-compiler/src/vpux_driver_compiler/test/functional/scripts \
    %{_vpath_builddir}/compiler-test-results

/usr/bin/python3 %{SOURCE35} \
    %{_vpath_srcdir}/bin/intel64/RelWithDebInfo/vpuxCompilerL0Test \
    %{_vpath_srcdir}/thirdparty/npu-compiler/src/vpux_driver_compiler/test/functional/scripts \
    %{buildroot} %{SOURCE32} %{_vpath_builddir}/installed-compiler-test-results

%files
%license LICENSE
%doc README.md
%doc %{_docdir}/libopenvino-%{version}
%{_libdir}/libopenvino.so.%{version}
%{_libdir}/libopenvino.so.%{so_ver}
%{_libdir}/libopenvino_c.so.%{version}
%{_libdir}/libopenvino_c.so.%{so_ver}

%files devel
%doc %{_docdir}/libopenvino-devel-%{version}
%{_includedir}/openvino
%{_includedir}/npu_driver_compiler.h
%{_libdir}/libopenvino.so
%{_libdir}/libopenvino_c.so
%{_libdir}/libopenvino_*_frontend.so
%{_libdir}/cmake/openvino%{version}
%{_libdir}/pkgconfig/openvino.pc

%files plugins
%doc %{_docdir}/libopenvino-auto-plugin-%{version}
%doc %{_docdir}/libopenvino-hetero-plugin-%{version}
%doc %{_docdir}/libopenvino-intel-cpu-plugin-%{version}
%doc %{_docdir}/libopenvino-intel-gpu-plugin-%{version}
%dir %{_libdir}/openvino-%{version}
%{_libdir}/openvino-%{version}/libopenvino_auto_plugin.so
%{_libdir}/openvino-%{version}/libopenvino_hetero_plugin.so
%{_libdir}/openvino-%{version}/libopenvino_intel_cpu_plugin.so
%{_libdir}/openvino-%{version}/libopenvino_intel_gpu_plugin.so
%{_libdir}/openvino-%{version}/cache.json
%{_libdir}/openvino-%{version}/libopenvino_intel_npu_plugin.so

%files -n intel-npu-compiler
%{_libdir}/openvino-%{version}/libopenvino_intel_npu_compiler.so
%{_libdir}/openvino-%{version}/libopenvino_intel_npu_compiler_loader.so

%files -n libopenvino-ir-frontend
%doc %{_docdir}/libopenvino-ir-frontend-%{version}
%{_libdir}/libopenvino_ir_frontend.so.%{version}
%{_libdir}/libopenvino_ir_frontend.so.%{so_ver}

%files -n libopenvino-onnx-frontend
%doc %{_docdir}/libopenvino-onnx-frontend-%{version}
%{_libdir}/libopenvino_onnx_frontend.so.%{version}
%{_libdir}/libopenvino_onnx_frontend.so.%{so_ver}

%files -n libopenvino-paddle-frontend
%doc %{_docdir}/libopenvino-paddle-frontend-%{version}
%{_libdir}/libopenvino_paddle_frontend.so.%{version}
%{_libdir}/libopenvino_paddle_frontend.so.%{so_ver}

%files -n libopenvino-pytorch-frontend
%doc %{_docdir}/libopenvino-pytorch-frontend-%{version}
%{_libdir}/libopenvino_pytorch_frontend.so.%{version}
%{_libdir}/libopenvino_pytorch_frontend.so.%{so_ver}

%files -n libopenvino-tensorflow-frontend
%doc %{_docdir}/libopenvino-tensorflow-frontend-%{version}
%{_libdir}/libopenvino_tensorflow_frontend.so.%{version}
%{_libdir}/libopenvino_tensorflow_frontend.so.%{so_ver}

%files -n libopenvino-tensorflow-lite-frontend
%doc %{_docdir}/libopenvino-tensorflow-lite-frontend-%{version}
%{_libdir}/libopenvino_tensorflow_lite_frontend.so.%{version}
%{_libdir}/libopenvino_tensorflow_lite_frontend.so.%{so_ver}

%changelog
* Fri Sep 04 2026 Intel NPU Stack maintainers <maintainers@example.invalid> - 2026.2.0-1.intelnpu.fc44
- Build OpenVINO and the Intel NPU compiler from the sealed Fedora source graph.
