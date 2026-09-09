#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Check scheduler vtable identity using the actual built LTO objects."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

build = Path(sys.argv[1]).resolve(strict=True)
objects = [build / (
    "build-modules/npu-compiler/thirdparty/llvm-project/llvm/lib/CodeGen/"
    f"CMakeFiles/LLVMCodeGen.dir/{name}.cpp.o"
) for name in ("MachineScheduler", "WindowScheduler")]
environment = dict(os.environ, LC_ALL="C")
for obj in objects:
    sections = subprocess.run(
        ["readelf", "--wide", "--sections", str(obj)],
        env=environment, capture_output=True, text=True, check=True,
    ).stdout
    if ".gnu.lto_" not in sections:
        sys.exit(f"FAIL: scheduler ODR check requires actual LTO input: {obj}")

with tempfile.TemporaryDirectory(prefix="llvm-scheduler-odr-") as directory:
    result = subprocess.run(
        ["/usr/bin/g++", "-r", "-nostdlib", "-no-pie", "-flto=1",
         "-flinker-output=nolto-rel", "-Werror=odr", "-Werror=lto-type-mismatch",
         *map(str, objects), "-o", str(Path(directory) / "scheduler.o")],
        env=environment, capture_output=True, text=True,
    )
    if result.returncode:
        sys.exit(f"FAIL: architecture scheduler ODR link\n{result.stdout}{result.stderr}")
print("PASS: actual MachineScheduler/WindowScheduler objects pass strict LTO ODR linking")
