# SPDX-License-Identifier: Apache-2.0

Name:           intel-npu-stack-firmware
Version:        1.35.0
Release:        1.intelnpu.fc44
Summary:        Source-locked Intel Lunar Lake NPU firmware override

License:        LicenseRef-Intel-firmware
URL:            https://github.com/intel/linux-npu-driver
Source0:        linux-npu-driver.tar

BuildArch:      noarch
ExclusiveArch:  x86_64

Provides:       intel-npu-firmware = %{version}

%description
The exact Intel Lunar Lake NPU firmware from the reviewed Linux NPU driver
source is installed as a firmware-class override. Activation requires a later
reboot; this package intentionally has no module reload or reboot script.

%prep
%autosetup -n linux-npu-driver

%build

%install
install -Dm0644 firmware/bin/vpu_40xx_v1.bin \
    %{buildroot}/usr/lib/firmware/updates/intel/vpu/vpu_40xx_v1.bin
install -Dm0644 firmware/bin/COPYRIGHT \
    %{buildroot}%{_licensedir}/%{name}/COPYRIGHT

%files
%license %{_licensedir}/%{name}/COPYRIGHT
/usr/lib/firmware/updates/intel/vpu/vpu_40xx_v1.bin

%changelog
* Fri Sep 04 2026 Intel NPU Stack maintainers <maintainers@example.invalid> - 1.35.0-1.intelnpu.fc44
- Package only the source-locked Lunar Lake firmware override.
