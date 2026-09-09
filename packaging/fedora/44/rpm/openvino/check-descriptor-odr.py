#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Check descriptor type identity across actual DMA composer and caller objects."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

build = Path(sys.argv[1]).resolve(strict=True)
root = build / "build-modules/npu-compiler/src/vpux_compiler/src"
environment = dict(os.environ, LC_ALL="C")
for arch in ("40", "50"):
    objects = [
        root / f"NPU{arch}XX/dialect/NPUReg{arch}XX/"
        f"CMakeFiles/npu_compiler_dialect_npureg{arch}xx.dir/composers/dma_composer.cpp.o",
        root / "conversion/CMakeFiles/npu_compiler_conversion.dir/rewriters/"
        f"VPUASM2NPUReg{arch}XX/dma_rewriter.cpp.o",
    ]
    for obj in objects:
        sections = subprocess.run(
            ["readelf", "--wide", "--sections", str(obj)],
            env=environment, capture_output=True, text=True, check=True,
        ).stdout
        if ".gnu.lto_" not in sections:
            sys.exit(f"FAIL: descriptor ODR check requires actual LTO input: {obj}")
    with tempfile.TemporaryDirectory(prefix=f"npu{arch}-descriptor-odr-") as directory:
        result = subprocess.run(
            ["/usr/bin/g++", "-r", "-nostdlib", "-no-pie", "-flto=1",
             "-flinker-output=nolto-rel", "-Werror=odr", "-Werror=lto-type-mismatch",
             *map(str, objects), "-o", str(Path(directory) / "descriptor.o")],
            env=environment, capture_output=True, text=True,
        )
        if result.returncode:
            sys.exit(f"FAIL: NPU{arch}XX descriptor ODR link\n{result.stdout}{result.stderr}")
    print(f"PASS: actual NPU{arch}XX DMA composer/caller pass strict LTO ODR linking")
