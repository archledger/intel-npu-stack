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
    """elf npu_elf objects may use elf's bundled NNRT headers (upstream ships
    them inside the gitlink-pinned submodule); driver objects must use the
    driver's own firmware headers and neither bundled nor test-restored ones.
    The historic nnrt_api test-restore path can no longer occur but stays
    rejected so a regression fails closed."""
    elf_objects = {node: paths for node, paths in records.items()
                   if '/CMakeFiles/npu_elf.dir/' in node}
    driver_objects = {node: paths for node, paths in records.items()
                      if '/CMakeFiles/ze_intel_npu.dir/' in node}
    if not elf_objects or not driver_objects:
        raise ValueError('both npu_elf and ze_intel_npu objects are required')
    firmware = set()
    for family, objects in (('npu_elf', elf_objects), ('ze_intel_npu', driver_objects)):
        for node, paths in objects.items():
            for path in paths:
                if '/third_party/npu_compiler_elf/3rdparty/nnrt_api/' in path:
                    raise ValueError('production object uses test NNRT header: ' + node + ': ' + path)
                if family == 'ze_intel_npu' and '/third_party/npu_compiler_elf/3rdparty/nnrt/' in path:
                    raise ValueError('driver object uses bundled NNRT header: ' + node + ': ' + path)
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
                      if ('/CMakeFiles/npu_elf.dir/' in row['output']
                          or '/CMakeFiles/ze_intel_npu.dir/' in row['output'])
                      and row['output'].endswith('.o')})
    records = {node: parse_dependencies(node, subprocess.check_output(
        [ninja, '-t', 'deps', node], cwd=build, text=True)) for node in objects}
    count = validate_dependencies(records)
    print(f'PASS: {len(objects)} production ELF and driver objects use {count} firmware headers; no test NNRT headers, no bundled headers in driver objects')


if __name__ == '__main__':
    main()
