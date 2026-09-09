#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Check architecture-private clamp types using the actual built LTO objects."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

build = Path(sys.argv[1]).resolve(strict=True)
objects = [build / (
    f"build-modules/npu-compiler/src/vpux_compiler/src/NPU{arch}/"
    f"CMakeFiles/npu_compiler_npu{arch.lower()}.dir/dialect/VPU/impl/ppe_factory.cpp.o"
) for arch in ("37XX", "50XX")]
environment = dict(os.environ, LC_ALL="C")
for obj in objects:
    sections = subprocess.run(
        ["readelf", "--wide", "--sections", str(obj)],
        env=environment, capture_output=True, text=True, check=True,
    ).stdout
    if ".gnu.lto_" not in sections:
        sys.exit(f"FAIL: clamp ODR check requires actual LTO input: {obj}")

with tempfile.TemporaryDirectory(prefix="npu-clamp-odr-") as directory:
    result = subprocess.run(
        ["/usr/bin/g++", "-r", "-nostdlib", "-no-pie", "-flto=1",
         "-flinker-output=nolto-rel", "-Werror=odr", "-Werror=lto-type-mismatch",
         *map(str, objects), "-o", str(Path(directory) / "clamp.o")],
        env=environment, capture_output=True, text=True,
    )
    if result.returncode:
        sys.exit(f"FAIL: architecture clamp ODR link\n{result.stdout}{result.stderr}")
print("PASS: actual NPU37XX/NPU50XX clamp objects pass strict LTO ODR linking")
