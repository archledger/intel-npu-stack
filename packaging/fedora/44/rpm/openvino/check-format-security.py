#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the actual extra-module warning macro with Fedora security flags."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile


source = Path(sys.argv[1]).resolve()
macro = source / "cmake/developer_package/compile_flags/functions.cmake"
environment = dict(os.environ, LC_ALL="C")


def run(*args):
    return subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=environment,
        check=False,
    )


with tempfile.TemporaryDirectory(prefix="openvino-format-check-") as directory:
    root = Path(directory)
    (root / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\n"
        "project(format_security_regression LANGUAGES C CXX)\n"
        f'include("{macro}")\n'
        "ov_dev_package_no_errors()\n"
        "add_library(safe_c OBJECT safe.c)\n"
        "add_library(safe_cxx OBJECT safe.cpp)\n"
        "add_library(unsafe_c OBJECT unsafe.c)\n"
        "add_library(unsafe_cxx OBJECT unsafe.cpp)\n"
    )
    for extension in ("c", "cpp"):
        (root / f"safe.{extension}").write_text(
            '#include <stdio.h>\nint emit(const char *s) { return printf("%s", s); }\n'
        )
        (root / f"unsafe.{extension}").write_text(
            "#include <stdio.h>\nint emit(const char *s) { return printf(s); }\n"
        )
    build = str(root / "build")
    configured = run(
        "cmake", "-S", str(root), "-B", build, "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
        "-DCMAKE_C_FLAGS=-Wall -Werror=format-security",
        "-DCMAKE_CXX_FLAGS=-Wall -Werror=format-security",
    )
    if configured.returncode:
        sys.exit("FAIL: format regression configuration\n" + configured.stdout)
    safe = run(
        "cmake", "--build", build, "--parallel", "2",
        "--target", "safe_c", "safe_cxx",
    )
    if safe.returncode:
        sys.exit("FAIL: safe C/C++ must compile with format security\n" + safe.stdout)
    for target in ("unsafe_c", "unsafe_cxx"):
        unsafe = run("cmake", "--build", build, "--target", target)
        if (
            unsafe.returncode == 0
            or "format not a string literal" not in unsafe.stdout
            or "-Werror=format-security" not in unsafe.stdout
        ):
            sys.exit(f"FAIL: {target} must trigger format-security error\n{unsafe.stdout}")
    print("PASS: safe C/C++ compile; unsafe C/C++ fail on format-security")
