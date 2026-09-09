#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Check the generated Fedora core commands before the expensive source build."""

import shlex
import subprocess
import sys
from pathlib import Path


commands = subprocess.run(
    ["ninja", "-C", sys.argv[1], "-t", "commands", "openvino_core_obj"],
    check=True,
    capture_output=True,
    text=True,
).stdout.splitlines()
core_commands = []
for command in commands:
    args = shlex.split(command)
    if "-o" not in args:
        continue
    output = args[args.index("-o") + 1]
    if output.startswith("src/core/CMakeFiles/openvino_core_obj.dir/"):
        core_commands.append((output, args))

if not core_commands:
    sys.exit("FAIL: no OpenVINO core compile commands found")

failures = []
for source, args in core_commands:
    system_paths = [
        args[index + 1] if arg == "-isystem" else arg[len("-isystem") :]
        for index, arg in enumerate(args)
        if arg.startswith("-isystem")
    ]
    if any(Path(path) == Path("/usr/include") for path in system_paths):
        failures.append(source)

if failures:
    sys.exit(
        "FAIL: explicit -isystem /usr/include breaks libstdc++ include_next in "
        f"{len(failures)} core commands, including {failures[0]}"
    )

print(f"PASS: {len(core_commands)} core commands preserve system header order")
