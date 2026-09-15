# SPDX-License-Identifier: Apache-2.0

Name:           oneapi-level-zero
Version:        1.32.0
Release:        1.intelnpu.fc44
Summary:        Intel-matched Level Zero loader for the NPU stack candidate

License:        MIT
URL:            https://github.com/oneapi-src/level-zero
Source0:        level-zero.tar
Source1:        install-provider-notices.py
Source2:        provider-sources.toml
Source3:        provider-license-evidence.tar

ExclusiveArch:  x86_64

BuildRequires:  cmake
BuildRequires:  gcc-c++
BuildRequires:  glibc-devel
BuildRequires:  ninja-build
BuildRequires:  patch
BuildRequires:  python3

%description
The Level Zero loader, validation layer, and tracing layer built from the
Intel-matched level-zero v1.32.0 source pin required by Intel NPU driver
v1.38.0. This package keeps Fedora's oneapi-level-zero identity and upgrades
its NEVR; it is an unqualified candidate and installs no firmware, kernel
module, driver, or consumer application.

%prep
%autosetup -n level-zero

/usr/bin/python3 %{SOURCE1} --kind loader \
    --source "$PWD" --archives "$(dirname -- '%{SOURCE0}')" --spec %{_specdir}/oneapi-level-zero.spec \
    --source-lock %{SOURCE2} --license-evidence %{SOURCE3} \
    --output ../provider-notices

%build
%cmake \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_LIBDIR=%{_lib}
%cmake_build --target ze_loader ze_validation_layer ze_tracing_layer

%install
%cmake_install
mkdir -p %{buildroot}%{_licensedir}
cp -a ../provider-notices/oneapi-level-zero %{buildroot}%{_licensedir}/
# Runtime package only: no SDK headers, samples, tests, or null driver.
rm -rf %{buildroot}%{_includedir}
rm -f \
    %{buildroot}%{_libdir}/libze_loader.so \
    %{buildroot}%{_libdir}/libze_validation_layer.so \
    %{buildroot}%{_libdir}/libze_tracing_layer.so

%files
%license %{_licensedir}/oneapi-level-zero
%{_libdir}/libze_loader.so.1
%{_libdir}/libze_loader.so.%{version}
%{_libdir}/libze_validation_layer.so.1
%{_libdir}/libze_validation_layer.so.%{version}
%{_libdir}/libze_tracing_layer.so.1
%{_libdir}/libze_tracing_layer.so.%{version}

%changelog
* Mon Sep 15 2026 Intel NPU Stack maintainers <maintainers@example.invalid> - 1.32.0-1.intelnpu.fc44
- Build the Intel-matched Level Zero loader candidate from the source lock.
