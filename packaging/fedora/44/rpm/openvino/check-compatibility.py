#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Compile the eleven GCC 16 / OpenVINO 2026.2 compatibility regression TUs.

Run after Ninja is idle and generated headers exist. Preserve the generated
release flags, compile real source, and write only disposable proof objects.
The September 7 diagnostic build fails each TU before patches 0005-0007.
"""

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


source = Path(sys.argv[1]).resolve()
build = Path(sys.argv[2]).resolve()
environment = dict(os.environ, LC_ALL="C")
cases = (
    (
        'src/vpux_compiler/src/dialect/VPUIP/IR/types/iti_buffer.cpp',
        'build-modules/npu-compiler/src/vpux_compiler/src/dialect/VPUIP/IR/CMakeFiles/npu_compiler_dialect_vpuip.dir/types/iti_buffer.cpp.o',
    ),
    (
        'src/vpux_compiler/src/dialect/VPUIP/IR/ops/sw_kernel.cpp',
        'build-modules/npu-compiler/src/vpux_compiler/src/dialect/VPUIP/IR/CMakeFiles/npu_compiler_dialect_vpuip.dir/ops/sw_kernel.cpp.o',
    ),
    (
        'src/vpux_compiler/src/dialect/VPU/utils/nce_sparsity.cpp',
        'build-modules/npu-compiler/src/vpux_compiler/src/dialect/VPU/utils/CMakeFiles/npu_compiler_dialect_vpu_utils.dir/nce_sparsity.cpp.o',
    ),
    (
        'src/vpux_compiler/src/dialect/IE/transforms/passes/adapt_shapes_for_scale_shift.cpp',
        'build-modules/npu-compiler/src/vpux_compiler/src/dialect/IE/transforms/CMakeFiles/npu_compiler_dialect_ie_transforms.dir/passes/adapt_shapes_for_scale_shift.cpp.o',
    ),
    (
        'src/vpux_compiler/src/dialect/IE/transforms/passes/adjust_fake_qdq_params.cpp',
        'build-modules/npu-compiler/src/vpux_compiler/src/dialect/IE/transforms/CMakeFiles/npu_compiler_dialect_ie_transforms.dir/passes/adjust_fake_qdq_params.cpp.o',
    ),
    (
        'src/vpux_compiler/src/dialect/IE/transforms/passes/convert_to_scale_shift.cpp',
        'build-modules/npu-compiler/src/vpux_compiler/src/dialect/IE/transforms/CMakeFiles/npu_compiler_dialect_ie_transforms.dir/passes/convert_to_scale_shift.cpp.o',
    ),
    (
        'src/vpux_compiler/src/dialect/const/passes/apply_swizzling.cpp',
        'build-modules/npu-compiler/src/vpux_compiler/src/dialect/const/CMakeFiles/npu_compiler_dialect_const.dir/passes/apply_swizzling.cpp.o',
    ),
    (
        'src/vpux_compiler/src/conversion/passes/IE2VPU/convert_IE_to_VPU_NCE.cpp',
        'build-modules/npu-compiler/src/vpux_compiler/src/conversion/CMakeFiles/npu_compiler_conversion.dir/passes/IE2VPU/convert_IE_to_VPU_NCE.cpp.o',
    ),
    (
        'src/vpux_compiler/src/NPU50XX/conversion/impl/convert_IE_to_VPU_NCE_strategy.cpp',
        'build-modules/npu-compiler/src/vpux_compiler/src/NPU50XX/CMakeFiles/npu_compiler_npu50xx.dir/conversion/impl/convert_IE_to_VPU_NCE_strategy.cpp.o',
    ),
    (
        'src/vpux_compiler/src/NPU37XX/conversion/impl/convert_IE_to_VPU_NCE_strategy.cpp',
        'build-modules/npu-compiler/src/vpux_compiler/src/NPU37XX/CMakeFiles/npu_compiler_npu37xx.dir/conversion/impl/convert_IE_to_VPU_NCE_strategy.cpp.o',
    ),
    (
        'src/vpux_compiler/src/frontend/IE.cpp',
        'build-modules/npu-compiler/src/vpux_compiler/src/frontend/CMakeFiles/npu_compiler_frontend.dir/IE.cpp.o',
    ),
)


def run(args):
    result = subprocess.run(
        args, cwd=build, env=environment, capture_output=True, text=True,
        check=False,
    )
    if result.returncode:
        sys.exit(f"FAIL: compatibility compile check\n{result.stdout}{result.stderr}")
    return result.stdout


with tempfile.TemporaryDirectory(prefix="npu-compatibility-") as directory:
    root = Path(directory)
    for number, (relative, target) in enumerate(cases):
        commands = run(["ninja", "-t", "commands", target]).splitlines()
        matches = []
        for command in commands:
            args = shlex.split(command)
            if "-c" in args and Path(args[args.index("-c") + 1]) == source / "thirdparty/npu-compiler" / relative:
                matches.append(args)
        if len(matches) != 1:
            sys.exit(f"FAIL: expected one compile command for {relative}, found {len(matches)}")
        command = matches[0].copy()
        output = root / f"{number}.o"
        command[command.index("-o") + 1] = str(output)
        for flag in ("-MF", "-MT", "-MQ"):
            if flag in command:
                command[command.index(flag) + 1] = str(output.with_suffix(".d") if flag == "-MF" else output)
        run(command)
        print(f"PASS: actual compatibility TU compiles: {relative}", flush=True)
