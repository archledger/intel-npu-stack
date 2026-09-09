#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Compile the real repeating-call pass with and without assertions.

Run serially after the build so its generated headers are available.
Only temporary proof objects are written, never Ninja's outputs.
"""

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


source = Path(sys.argv[1]).resolve()
build = Path(sys.argv[2]).resolve()
relative = "src/vpux_compiler/src/dialect/VPUIP/transforms/passes/legalize_repeating_func_calls.cpp"
target = (
    "build-modules/npu-compiler/src/vpux_compiler/src/dialect/VPUIP/transforms/"
    "CMakeFiles/npu_compiler_dialect_vpuip_transforms.dir/"
    "passes/legalize_repeating_func_calls.cpp.o"
)
environment = dict(os.environ, LC_ALL="C")


def run(args):
    result = subprocess.run(
        args, cwd=build, env=environment, capture_output=True, text=True,
        check=False,
    )
    if result.returncode:
        sys.exit(f"FAIL: repeating-call compile check\n{result.stdout}{result.stderr}")
    return result.stdout


commands = run(["ninja", "-t", "commands", target]).splitlines()
matches = []
for command in commands:
    args = shlex.split(command)
    if "-c" in args and Path(args[args.index("-c") + 1]) == source / "thirdparty/npu-compiler" / relative:
        matches.append(args)
if len(matches) != 1:
    sys.exit(f"FAIL: expected one repeating-call compile command, found {len(matches)}")

with tempfile.TemporaryDirectory(prefix="npu-repeating-calls-") as directory:
    root = Path(directory)
    for name, extra in (("release", []), ("assertions", ["-UNDEBUG"])):
        command = matches[0].copy()
        command[command.index("-o") + 1] = str(root / f"{name}.o")
        for flag in ("-MF", "-MT", "-MQ"):
            if flag in command:
                command[command.index(flag) + 1] = str(root / (f"{name}.d" if flag == "-MF" else f"{name}.o"))
        run(command + extra)
        print(f"PASS: actual repeating-call pass compiles ({name})", flush=True)
