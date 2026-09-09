#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Compile the actual name generator and register colliding model spellings.

Run with Ninja idle. GoogleTest validates the generated suffixes and rejects
duplicates before executing the three fixture cases.
"""

from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


source, build, probe = (Path(arg).resolve() for arg in sys.argv[1:])
commands = subprocess.check_output(
    ["ninja-build", "-C", str(build), "-t", "commands", "vpuxCompilerL0Test"], text=True
)
args = next(
    shlex.split(line)
    for line in commands.splitlines()
    if " -c " in line and line.endswith("/functional/vcl_tests_common.cpp")
)
with tempfile.TemporaryDirectory(prefix="compiler-test-names-", dir=build) as directory:
    root = Path(directory)
    obj, executable, report = root / "probe.o", root / "probe", root / "result.xml"
    args[args.index("-o") + 1] = str(obj)
    args[args.index("-c") + 1] = str(probe)
    args.append("-I" + str(source / "thirdparty/npu-compiler/src/vpux_driver_compiler/test/functional"))
    subprocess.run(args, cwd=build, check=True)
    subprocess.run(
        [args[0], "-fno-lto", str(obj), "-lgtest_main", "-lgtest", "-pthread", "-o", str(executable)],
        check=True,
    )
    subprocess.run([str(executable), "--gtest_output=xml:" + str(report)], check=True)
    result = ET.parse(report).getroot()
    assert result.get("tests") == "3", "Expected all three registration cases"
    assert all(result.get(key) == "0" for key in ("failures", "disabled", "errors"))
    assert not result.findall(".//skipped"), "Registration cases must not skip"
print("PASS: actual compiler name generator registers three distinct valid cases")
