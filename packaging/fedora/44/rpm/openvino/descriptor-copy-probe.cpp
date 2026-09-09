// SPDX-License-Identifier: Apache-2.0
#include "vpux/compiler/NPU50XX/dialect/NPUReg50XX/descriptors.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>

using Descriptor = vpux::NPUReg50XX::Descriptors::DpuInvariantRegister;
using Field = vpux::NPUReg50XX::Fields::idu_cmx_mux_mode;

__attribute__((noinline)) Descriptor update(const Descriptor& original, uint8_t mode) {
    Descriptor copy;
    copy = original;
    copy.write<Field>(mode);
    return copy;
}

int main() {
    // The reviewed field is bits 28..29 of the register at byte offset 88.
    // Literal byte expectations also ensure adjacent bits remain intact.
    const uint8_t seeds[] = {0x00, 0xff, 0xa5, 0x5a};
    const uint8_t expected[][4] = {
            {0x00, 0x10, 0x20, 0x30},
            {0xcf, 0xdf, 0xef, 0xff},
            {0x85, 0x95, 0xa5, 0xb5},
            {0x4a, 0x5a, 0x6a, 0x7a},
    };
    for (size_t pattern = 0; pattern != 4; ++pattern) {
        Descriptor original;
        auto bytes = original.getStorage();
        if (bytes.size() != 352) {
            return 1;
        }
        std::fill(bytes.begin(), bytes.end(), seeds[pattern]);
        for (uint8_t mode = 0; mode != 4; ++mode) {
            auto copy = update(original, mode);
            auto result = copy.getStorage();
            if (result.size() != bytes.size() || result.data() == bytes.data()) {
                return 2;
            }
            for (size_t index = 0; index != bytes.size(); ++index) {
                if (bytes[index] != seeds[pattern] ||
                    result[index] != (index == 91 ? expected[pattern][mode] : seeds[pattern])) {
                    return 3;
                }
            }
            if (copy.read<Field>() != mode) {
                return 4;
            }
        }
    }
    std::puts("PASS: 16 descriptor-copy cases preserve payload size, field bits, neighbors, and original");
}
