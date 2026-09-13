# SPDX-License-Identifier: Apache-2.0

%global _find_debuginfo_opts %{?_find_debuginfo_opts} -j1
%global _vpath_srcdir native

Name:           intel-npu-stack-tools
Version:        0.1.0
Release:        1.intelnpu.fc44
Summary:        Read-only Intel NPU stack status and diagnostic tools
License:        Apache-2.0 AND Artistic-2.0 AND BSD-3-Clause AND ISC AND MIT AND MPL-2.0 AND Unicode-3.0 AND (Apache-2.0 WITH LLVM-exception)
Source0:        intel-npu-stack-0.1.0.tar
Source1:        cargo-vendor.tar
Source2:        installed-manifest.toml
ExclusiveArch:  x86_64

BuildRequires:  rust = 1.98.0-1.fc44
BuildRequires:  cargo = 1.98.0-1.fc44
BuildRequires:  rust-std-static = 1.98.0-1.fc44
BuildRequires:  cmake = 4.3.0-1.fc44
BuildRequires:  gcc = 16.2.1-2.fc44
BuildRequires:  gcc-c++ = 16.2.1-2.fc44
BuildRequires:  ninja-build = 1.13.2-2.fc44
BuildRequires:  python3 = 3.14.7-1.fc44
BuildRequires:  oneapi-level-zero-devel = 1.28.6-1.fc44
BuildRequires:  openvino-devel = 2026.2.0-1.intelnpu.fc44
BuildRequires:  util-linux-core = 2.41.5-1.fc44

Requires:       oneapi-level-zero%{?_isa} = 1.28.6-1.fc44
Requires:       openvino%{?_isa} = 2026.2.0-1.intelnpu.fc44

%description
Read-only status CLI, isolated native probes, documentation and a manifest
binding the exact candidate providers. No package scripts activate hardware
or firmware.

%package -n intel-npu-stack
Summary:        Exact provider set for the experimental Intel NPU stack
License:        Apache-2.0
BuildArch:      noarch
Requires:       intel-npu-stack-tools(x86-64) = %{version}-%{release}
Requires:       intel-npu-driver(x86-64) = 1.35.0-1.intelnpu.fc44
Requires:       intel-npu-stack-firmware = 1.35.0-1.intelnpu.fc44
Requires:       oneapi-level-zero(x86-64) = 1.28.6-1.fc44
Requires:       openvino(x86-64) = 2026.2.0-1.intelnpu.fc44
Requires:       openvino-plugins(x86-64) = 2026.2.0-1.intelnpu.fc44
Requires:       intel-npu-compiler(x86-64) = 2026.2.0-1.intelnpu.fc44

%description -n intel-npu-stack
Metadata-only package selecting the exact candidate provider versions.
This candidate has not passed VM or hardware qualification and is not a
stable release. Dependencies restrict installation to x86-64 providers.

%prep
%setup -q -n intel-npu-stack-0.1.0
tar -xf %{SOURCE1}
mkdir .cargo
cat > .cargo/config.toml <<'CONFIG'
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "vendor"
[net]
offline = true
CONFIG
python3 packaging/fedora/44/rpm/intel-npu-stack/check-vendor-licenses.py vendor Cargo.lock vendor-licenses
cmp packaging/fedora/44/installed-manifest.toml %{SOURCE2}
python3 packaging/fedora/44/rpm/intel-npu-stack/install-stdlib-notices.py \
    packaging/fedora/44/licenses/rust-stdlib-1.98.0 / rust-stdlib-licenses

%build
export CARGO_NET_OFFLINE=true
export CARGO_BUILD_JOBS=%{_smp_build_ncpus}
export CARGO_PROFILE_RELEASE_DEBUG=2
export CARGO_PROFILE_RELEASE_STRIP=false
export RUSTFLAGS="-C relocation-model=pie -C link-arg=-Wl,-z,relro,-z,now"
/usr/bin/cargo build --offline --locked --release -p stack-cli --bin intel-npu-stack
%cmake -DINTEL_NPU_SDK_PREFIX=/usr -DBUILD_TESTING=ON -DCMAKE_SKIP_RPATH=ON
%cmake_build

%install
install -Dpm0755 target/release/intel-npu-stack %{buildroot}%{_bindir}/intel-npu-stack
%cmake_install
install -Dpm0644 %{SOURCE2} %{buildroot}%{_datadir}/intel-npu-stack/installed-manifest.toml
cp packaging/fedora/44/rpm/intel-npu-stack/README.md TOOLS-PACKAGING.md
mkdir -p %{buildroot}%{_datadir}/licenses/%{name}
cp -pr LICENSE NOTICE vendor-licenses rust-stdlib-licenses %{buildroot}%{_datadir}/licenses/%{name}/
# Preserve every notice path and byte while sharing identical license text.
hardlink -t %{buildroot}%{_datadir}/licenses/%{name}

%check
test "$(target/release/intel-npu-stack version)" = '0.1.0'
ctest --test-dir %{__cmake_builddir} --output-on-failure --no-tests=error

%files -n intel-npu-stack

%files
%license %{_datadir}/licenses/%{name}
%doc README.md docs/runtime-doctor.md TOOLS-PACKAGING.md
%{_bindir}/intel-npu-stack
%dir %{_libexecdir}/intel-npu-stack
%{_libexecdir}/intel-npu-stack/intel-npu-level-zero-probe
%{_libexecdir}/intel-npu-stack/intel-npu-openvino-probe
%dir %{_datadir}/intel-npu-stack
%{_datadir}/intel-npu-stack/installed-manifest.toml

%changelog
* Wed Sep 09 2026 Wisbendji Fimerlus <archledger236@gmail.com> - 0.1.0-1.intelnpu.fc44
- Package candidate tools and exact provider metadata for isolated validation.
