#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Reject archive layout, missing components, and unsafe staged RPM payloads."""
import os
from pathlib import Path, PurePosixPath
import stat
import sys

root = Path(sys.argv[1]).resolve(strict=True)
version = '2026.2.0'
lib = 'usr/lib64/'
plugins = lib + 'openvino-' + version + '/'
frontends = ['ir', 'onnx', 'paddle', 'pytorch', 'tensorflow', 'tensorflow_lite']
libraries = ['openvino', 'openvino_c'] + ['openvino_' + x + '_frontend' for x in frontends]
expected = {lib + 'lib' + name + '.so' + suffix for name in libraries
            for suffix in ['', '.2620', '.' + version]}
expected |= {plugins + 'libopenvino_' + name + '.so' for name in
             ['auto_plugin', 'hetero_plugin', 'intel_cpu_plugin', 'intel_gpu_plugin', 'intel_npu_plugin',
              'intel_npu_compiler', 'intel_npu_compiler_loader']}
# The GPU kernel selector loads upstream tuning data beside its plugin.
expected.add(plugins + 'cache.json')
# IR is an internal frontend with no public unversioned development link.
expected.remove(lib + 'libopenvino_ir_frontend.so')
expected |= {'usr/include/npu_driver_compiler.h', lib + 'pkgconfig/openvino.pc'}
expected |= {'usr/share/doc/' + name + '-' + version + '/copyright' for name in
             ['libopenvino', 'libopenvino-devel', 'libopenvino-auto-plugin',
              'libopenvino-hetero-plugin', 'libopenvino-intel-cpu-plugin',
              'libopenvino-intel-gpu-plugin'] +
             ['libopenvino-' + x.replace('_', '-') + '-frontend' for x in frontends]}
prefixes = ['usr/include/openvino/', lib + 'cmake/openvino' + version + '/']
seen = set()
for base, dirs, files in os.walk(root, followlinks=False):
    for name in dirs + files:
        path = Path(base) / name
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        rel = path.relative_to(root).as_posix()
        if not (stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
            raise SystemExit('Unsupported staged file type: ' + rel)
        if rel not in expected and not any(rel.startswith(p) for p in prefixes):
            raise SystemExit('Unexpected staged path: ' + rel)
        if path.is_symlink():
            target = os.readlink(path)
            if PurePosixPath(target).is_absolute():
                raise SystemExit('Absolute staged symlink: ' + rel)
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root / 'usr'):
                raise SystemExit('Escaping staged symlink: ' + rel)
        seen.add(rel)
missing = expected - seen
missing |= {prefix for prefix in prefixes if not any(p.startswith(prefix) for p in seen)}
if missing:
    raise SystemExit('Missing staged paths: ' + ', '.join(sorted(missing)))
print(f'Native RPM layout PASS: {len(seen)} files; all runtime/development components present')
