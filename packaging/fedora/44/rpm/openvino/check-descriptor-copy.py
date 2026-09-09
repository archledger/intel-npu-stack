#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Compile the actual affected pass and verify copied descriptor payload bytes.

Run serially after the build: generated headers and LLVM support are required.
All proof outputs are temporary; no Ninja build outputs are overwritten.
"""

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


source = Path(sys.argv[1]).resolve()
build = Path(sys.argv[2]).resolve()
probe = Path(sys.argv[3]).resolve()
compiler = source / "thirdparty/npu-compiler"
relative = "src/vpux_compiler/src/NPU50XX/dialect/NPUReg50XX/passes/setup_idu_cmx_mux_mode.cpp"
target = (
    "build-modules/npu-compiler/src/vpux_compiler/src/NPU50XX/dialect/"
    "NPUReg50XX/CMakeFiles/npu_compiler_dialect_npureg50xx.dir/"
    "passes/setup_idu_cmx_mux_mode.cpp.o"
)
environment = dict(os.environ, LC_ALL="C")


def run(args):
    result = subprocess.run(
        args, cwd=build, env=environment, capture_output=True, text=True,
        check=False,
    )
    if result.returncode:
        sys.exit(f"FAIL: descriptor copy check\n{result.stdout}{result.stderr}")
    return result.stdout


commands = run(["ninja", "-t", "commands", target]).splitlines()
matches = []
for command in commands:
    args = shlex.split(command)
    if "-c" in args and Path(args[args.index("-c") + 1]) == compiler / relative:
        matches.append(args)
if len(matches) != 1:
    sys.exit(f"FAIL: expected one affected pass compile command, found {len(matches)}")

with tempfile.TemporaryDirectory(prefix="npu-descriptor-copy-") as directory:
    root = Path(directory)
    command = matches[0].copy()
    command[command.index("-o") + 1] = str(root / "pass.o")
    for flag in ("-MF", "-MT", "-MQ"):
        if flag in command:
            command[command.index(flag) + 1] = str(root / ("pass.d" if flag == "-MF" else "pass.o"))
    run(command)
    print("PASS: actual NPU50XX pass compiles with the generated build flags", flush=True)

    # Use the same headers/defines/optimization for a linked runtime probe.
    flags = []
    skip = False
    for arg in matches[0]:
        if skip:
            skip = False
        elif arg in ("-o", "-MF", "-MT", "-MQ", "-c"):
            skip = True
        elif arg not in ("-MD", "-MMD", "-MP"):
            flags.append(arg)
    libraries = build / "build-modules/npu-compiler/thirdparty/llvm-project/llvm/lib"
    binary = root / "descriptor-copy"
    run(flags + [
        str(probe), str(compiler / "thirdparty/elf/core/src/utils/log.cpp"),
        "-o", str(binary), str(libraries / "libLLVMSupport.a"),
        str(libraries / "libLLVMDemangle.a"), "-lz", "-lzstd", "-ltinfo",
        "-ldl", "-lpthread",
    ])
    print(run([str(binary)]).strip())
