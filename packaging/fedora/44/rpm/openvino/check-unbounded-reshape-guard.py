#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Require the unbounded Reshape input guard in the prepared compiler source."""
from pathlib import Path
import sys

source = Path(sys.argv[1]).resolve(strict=True) / 'thirdparty/npu-compiler/src/vpux_compiler/src/frontend/IE.cpp'
text = source.read_text(encoding='utf-8')

unguarded = 'mlir::dyn_cast<Core::BoundedTensorType>(inputs[0].getType()).getBounds()'
guarded_throw = 'VPUX_THROW_WHEN(boundedInputType == nullptr,'
guarded_call = 'boundedInputType.getBounds()'

if unguarded in text:
    raise SystemExit(f'check-unbounded-reshape-guard: unguarded bounds dereference present in {source}')
if text.count(guarded_throw) != 1 or text.count(guarded_call) != 1:
    raise SystemExit(f'check-unbounded-reshape-guard: guard not found exactly once in {source}')
print('check-unbounded-reshape-guard: ok')
