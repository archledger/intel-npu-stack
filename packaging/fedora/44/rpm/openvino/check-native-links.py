#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Reject generated C/C++ links that re-enable LTO in this native-link build.

Run only with Ninja idle, immediately after CMake and before the real build.
Ninja's compilation database expands the actual selected linker rules so the
check observes option order, including flags inherited from Fedora.
"""

import json
from pathlib import Path
import re
import shlex
import subprocess
import sys


build = Path(sys.argv[1]).resolve()
rule_pattern = r"C(?:XX)?_(?:SHARED_LIBRARY|MODULE_LIBRARY|EXECUTABLE)_LINKER__\S+"
rules = re.findall(rf"^rule ({rule_pattern})$", (build / "CMakeFiles/rules.ninja").read_text(), re.MULTILINE)
expected = len(re.findall(rf"^build .*: {rule_pattern}", (build / "build.ninja").read_text(), re.MULTILINE))
if not rules or not expected:
    sys.exit("FAIL: no generated C/C++ link rules or edges")
result = subprocess.run(["ninja-build", "-C", str(build), "-t", "compdb", *rules],
                        check=True, text=True, capture_output=True)
commands = json.loads(result.stdout)
if len(commands) != expected:
    sys.exit(f"FAIL: expected {expected} link commands, received {len(commands)}")
failures = []
for entry in commands:
    args = shlex.split(entry["command"])
    # Current CMake Unix linker rules start ': && <compiler> ... && :'.
    if args[:2] != [":", "&&"] or "&&" not in args[2:]:
        sys.exit(f"FAIL: unsupported link rule for {entry['output']}")
    args = args[2:args.index("&&", 2)]
    modes = [a for a in args if a in ("-flto", "-fno-lto") or a.startswith("-flto=")]
    if not modes or modes[-1] != "-fno-lto":
        failures.append(f"{entry['output']}: {modes}")
if failures:
    sys.exit("FAIL: native links require effective -fno-lto; " + "\n".join(failures[:5]))
print(f"PASS: all {len(commands)} generated C/C++ links explicitly disable LTO")
