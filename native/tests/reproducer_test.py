#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the issue #20 reproducer on CPU: the batch-layout modes, the compile-only modes and argument refusals.

NPU behavior is hardware qualification and is not run here; CPU makes the deterministic parts testable in CI.
"""
from pathlib import Path
import subprocess
import sys
import unittest

BINARY = Path(sys.argv.pop(1)).resolve(strict=True)


def run(*args):
    return subprocess.run([BINARY, *args], capture_output=True, text=True, timeout=120)


class Reproducer(unittest.TestCase):
    def test_layout_modes_name_the_tensors_set_the_batch_layout_and_infer_a_batch_of_three(self):
        # Rows (1, 3), (-2, 2) and (0.5, 1.5) have the means 2, 0 and 1.
        for mode, shapes in [('unbounded-layout', 'INPUT [?,2] OUTPUT [?,1]'),
                             ('bounded-layout', 'INPUT [1..4,2] OUTPUT [1..4,1]')]:
            with self.subTest(mode):
                result = run(mode, 'CPU')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [
                    shapes, 'LAYOUT [N,...] INPUT_NAMES input OUTPUT_NAMES output', 'COMPILE_OK',
                    'INFER_OK [3,1] 2 0 1'])

    def test_the_original_modes_only_compile(self):
        for mode, shapes in [('static', 'INPUT [1,2] OUTPUT [1,1]'), ('bounded', 'INPUT [1..4,2] OUTPUT [1..4,1]'),
                             ('unbounded', 'INPUT [?,2] OUTPUT [?,1]')]:
            with self.subTest(mode):
                result = run(mode, 'CPU')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [shapes, 'COMPILE_OK'])

    def test_other_modes_and_devices_are_refused_before_anything_runs(self):
        for args in [('static-layout', 'CPU'), ('layout', 'CPU'), ('-layout', 'CPU'), ('unbounded-layoutx', 'CPU'),
                     ('Unbounded-layout', 'CPU'), ('unbounded-layout', 'GPU'), ('unbounded-layout',),
                     ('unbounded-layout', 'CPU', 'prefix', 'extra')]:
            with self.subTest(args):
                result = run(*args)
                self.assertEqual((result.returncode, result.stdout), (64, ''))


if __name__ == '__main__':
    unittest.main()
