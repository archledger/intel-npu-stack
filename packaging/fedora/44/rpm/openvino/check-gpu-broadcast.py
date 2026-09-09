#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Compile the actual GPU broadcast source with its generated production flags."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

build = Path(sys.argv[1]).resolve(strict=True)
target = "src/plugins/intel_gpu/src/graph/CMakeFiles/openvino_intel_gpu_graph.dir/broadcast.cpp.o"
environment = dict(os.environ, LC_ALL="C")
commands = subprocess.run(
    ["ninja", "-t", "commands", target], cwd=build, env=environment,
    capture_output=True, text=True, check=True,
).stdout.splitlines()
matches = []
for command in commands:
    args = shlex.split(command)
    if "-c" in args and args[args.index("-c") + 1].endswith("/intel_gpu/src/graph/broadcast.cpp"):
        matches.append(args)
if len(matches) != 1:
    sys.exit(f"FAIL: expected one GPU broadcast compile command, found {len(matches)}")
args = matches[0]
if "-Werror" not in args or any(arg in args for arg in (
    "-Wno-free-nonheap-object", "-Wno-error=free-nonheap-object",
)):
    sys.exit("FAIL: GPU broadcast regression requires original warnings as errors")
with tempfile.TemporaryDirectory(prefix="gpu-broadcast-") as directory:
    obj = Path(directory) / "broadcast.o"
    args[args.index("-o") + 1] = str(obj)
    for flag in ("-MF", "-MT", "-MQ"):
        if flag in args:
            args[args.index(flag) + 1] = str(obj.with_suffix(".d") if flag == "-MF" else obj)
    result = subprocess.run(args, cwd=build, env=environment, capture_output=True, text=True)
    if result.returncode:
        sys.exit(f"FAIL: actual GPU broadcast compilation\n{result.stdout}{result.stderr}")
print("PASS: actual GPU broadcast source compiles with production warning flags")
