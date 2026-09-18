<!-- SPDX-License-Identifier: Apache-2.0 -->

# Intel NPU Firmware Override RPM

This package owns only
`/usr/lib/firmware/updates/intel/vpu/vpu_40xx_v1.bin` and its governing
`COPYRIGHT` file. The firmware bytes come from the source-locked Linux NPU
driver `v1.38.0` archive and must have SHA-256
`cdfe2ebd66aaec21d896134c93d82d60de2d8eede75a2c62898aeb9006e5a26f`.

The package is intentionally script-free. Installing, upgrading, or removing
it does not reload `intel_vpu`, stop workloads, or reboot the device. The later
transaction layer records reboot pending and performs rollback as one reviewed
DNF transaction.
