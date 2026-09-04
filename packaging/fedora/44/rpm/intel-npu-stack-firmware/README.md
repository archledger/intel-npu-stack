<!-- SPDX-License-Identifier: Apache-2.0 -->

# Intel NPU Firmware Override RPM

This package owns only
`/usr/lib/firmware/updates/intel/vpu/vpu_40xx_v1.bin` and its governing
`COPYRIGHT` file. The firmware bytes come from the source-locked Linux NPU
driver `v1.35.0` archive and must have SHA-256
`4eee75549d47ee4999b7a42a76fcb8a1005aac4aa4c66145c1470fe8f35c16bc`.

The package is intentionally script-free. Installing, upgrading, or removing
it does not reload `intel_vpu`, stop workloads, or reboot the device. The later
transaction layer records reboot pending and performs rollback as one reviewed
DNF transaction.
