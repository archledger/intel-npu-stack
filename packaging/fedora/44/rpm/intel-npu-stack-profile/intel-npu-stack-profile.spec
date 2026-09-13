# SPDX-License-Identifier: Apache-2.0

# Data-only release artifact: the immutable, release-bound platform profile.
# Built reproducibly (fixed SOURCE_DATE_EPOCH, sorted archive) from the exact
# release profile bytes; no scripts, services, dependencies or hardware
# activation are shipped by this package.

Name:           intel-npu-stack-profile
Version:        0.1.0
Release:        1.intelnpu.fc44
Summary:        Immutable Intel NPU stack platform profile for Fedora 44
License:        Apache-2.0
Source0:        intel-npu-stack-profile-0.1.0.tar
BuildArch:      noarch
AutoReqProv:    no
BuildRequires:  python3 >= 3.11

%description
One immutable platform profile binding the exact signed provider set of an
Intel NPU stack release for Fedora 44 on x86_64. The installer authenticates
the profile against the release manifest; this package only owns the profile
data file under /usr/share/intel-npu-stack/profiles. It performs no
activation, ships no services and requires no other packages.

%prep
%setup -q -n intel-npu-stack-profile-0.1.0

%build

%install
install -D -m 0644 -T profiles/fedora-44-lunar-lake-x86_64.toml \
    %{buildroot}%{_datadir}/intel-npu-stack/profiles/fedora-44-lunar-lake-x86_64.toml

%check
python3 -c "import pathlib, tomllib; tomllib.loads(pathlib.Path('profiles/fedora-44-lunar-lake-x86_64.toml').read_text())"

%files
%license LICENSE
%dir %{_datadir}/intel-npu-stack
%dir %{_datadir}/intel-npu-stack/profiles
%{_datadir}/intel-npu-stack/profiles/fedora-44-lunar-lake-x86_64.toml

%changelog
* Fri Sep 11 2026 Intel NPU Stack release assembly <release@example.invalid> - 0.1.0-1.intelnpu.fc44
- Initial immutable candidate profile for Fedora 44 Lunar Lake x86_64.
