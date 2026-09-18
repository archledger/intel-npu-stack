# SPDX-License-Identifier: Apache-2.0

Name:           intel-npu-stack-firmware
Version:        1.38.0
Release:        1.intelnpu.fc44
Summary:        Source-locked Intel Lunar Lake NPU firmware override

License:        LicenseRef-Intel-firmware
URL:            https://github.com/intel/linux-npu-driver
Source0:        linux-npu-driver.tar
Source1:        install-provider-notices.py
Source2:        provider-sources.toml
Source3:        provider-license-evidence.tar

BuildArch:      noarch
ExclusiveArch:  x86_64

BuildRequires:  python3

Provides:       intel-npu-firmware = %{version}

%description
The exact Intel Lunar Lake NPU firmware from the reviewed Linux NPU driver
source is installed as a firmware-class override. Activation requires a later
reboot; this package intentionally has no module reload or reboot script.

%prep
%autosetup -n linux-npu-driver

/usr/bin/python3 %{SOURCE1} --kind firmware \
    --source "$PWD" --archives "$(dirname -- '%{SOURCE0}')" --spec %{_specdir}/intel-npu-stack-firmware.spec \
    --source-lock %{SOURCE2} --license-evidence %{SOURCE3} \
    --output ../provider-notices

%build

%install
install -Dm0644 firmware/bin/vpu_40xx_v1.bin \
    %{buildroot}/usr/lib/firmware/updates/intel/vpu/vpu_40xx_v1.bin
mkdir -p %{buildroot}%{_licensedir}
cp -a ../provider-notices/intel-npu-stack-firmware %{buildroot}%{_licensedir}/

%files
%license %{_licensedir}/%{name}
/usr/lib/firmware/updates/intel/vpu/vpu_40xx_v1.bin

%changelog
* Tue Sep 15 2026 Intel NPU Stack maintainers <maintainers@example.invalid> - 1.38.0-1.intelnpu.fc44
- Upgrade the firmware override to the v1.38.0 Linux NPU driver source pin.
* Fri Sep 04 2026 Intel NPU Stack maintainers <maintainers@example.invalid> - 1.35.0-1.intelnpu.fc44
- Package only the source-locked Lunar Lake firmware override.
