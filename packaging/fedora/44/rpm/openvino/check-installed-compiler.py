#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Run real compiler cases and prove that the staged libraries were loaded."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary, config, root, checker = [Path(arg).resolve(strict=True) for arg in sys.argv[1:5]]
parent = Path(sys.argv[5]).resolve()
parent.mkdir(parents=True, exist_ok=True)
evidence = Path(tempfile.mkdtemp(prefix='run-', dir=parent))
lib = root / 'usr/lib64'
plugins = lib / 'openvino-2026.2.0'
env = dict(os.environ, LD_LIBRARY_PATH=str(lib) + ':' + str(plugins),
           LD_DEBUG='libs', LD_DEBUG_OUTPUT=str(evidence / 'loader-trace'))
command = ['/usr/bin/python3', str(checker), str(binary), str(config), str(evidence / 'tests')]
with (evidence / 'tests.log').open('x') as log:
    result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
initialized = set()
for trace in evidence.glob('loader-trace.*'):
    for line in trace.read_text().splitlines():
        if 'calling init:' in line:
            initialized.add(line.split('calling init:', 1)[1].strip())
required = {str(lib / 'libopenvino.so.2620'),
            str(plugins / 'libopenvino_intel_npu_compiler_loader.so'),
            str(plugins / 'libopenvino_intel_npu_compiler.so')}
missing = sorted(required - initialized)
summary = {'exit_code': result.returncode, 'missing_staged_libraries': missing,
           'initialized_libraries': sorted(initialized)}
(evidence / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print('Installed compiler evidence:', evidence)
if result.returncode or missing:
    raise SystemExit('Installed compiler check failed: ' + json.dumps(summary))
print('PASS: self-contained compiler cases used the staged runtime, loader and compiler')
