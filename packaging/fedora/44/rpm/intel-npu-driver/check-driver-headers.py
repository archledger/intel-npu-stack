#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Reject test-only firmware headers in the production npu_elf archive."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess


def parse_dependencies(node, text):
    lines = text.splitlines()
    match = re.fullmatch(re.escape(node) + r': #deps (\d+), deps mtime \d+ \(VALID\)', lines[0] if lines else '')
    if not match:
        raise ValueError('missing or stale Ninja dependencies: ' + node)
    paths = [line[4:] for line in lines[1:] if line.startswith('    ')]
    if len(paths) != int(match[1]):
        raise ValueError('incomplete Ninja dependencies: ' + node)
    return paths


def validate_dependencies(records):
    if not records:
        raise ValueError('no production npu_elf objects inspected')
    firmware = set()
    for node, paths in records.items():
        for path in paths:
            if '/third_party/npu_compiler_elf/3rdparty/nnrt_api/' in path:
                raise ValueError('production object uses test NNRT header: ' + node + ': ' + path)
            if '/third_party/npu_compiler_elf/3rdparty/nnrt/' in path:
                raise ValueError('production object uses bundled NNRT header: ' + node + ': ' + path)
            if '/firmware/include/api/' in path:
                firmware.add(path)
    if not firmware:
        raise ValueError('no production firmware header dependencies recorded')
    return len(firmware)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    args = parser.parse_args()
    build = args.build.resolve(strict=True)
    ninja = shutil.which('ninja-build') or shutil.which('ninja')
    if not ninja or not (build / 'build.ninja').is_file():
        raise ValueError('Ninja and a completed driver build are required')
    commands = json.loads(subprocess.check_output([ninja, '-t', 'compdb'], cwd=build, text=True))
    objects = sorted({row['output'] for row in commands
                      if '/CMakeFiles/npu_elf.dir/' in row['output'] and row['output'].endswith('.o')})
    records = {node: parse_dependencies(node, subprocess.check_output(
        [ninja, '-t', 'deps', node], cwd=build, text=True)) for node in objects}
    count = validate_dependencies(records)
    print(f'PASS: {len(objects)} production ELF archive objects use {count} firmware headers; no test NNRT headers')


if __name__ == '__main__':
    main()
