#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the real helper entry point with a noisy substitute SDK."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

BINARY = Path(sys.argv.pop(1)).resolve(strict=True)


class ProbeOutput(unittest.TestCase):
    def test_sdk_and_shutdown_messages_are_confined_to_stderr(self):
        for mode in ['enumerate', 'infer']:
            for throwing in [False, True]:
                with self.subTest(mode=mode, throwing=throwing):
                    env = {'NOISY_PROBE_THROW': '1'} if throwing else {}
                    result = subprocess.run([BINARY, mode], env=env, capture_output=True, check=True)
                    report = json.loads(result.stdout)
                    self.assertEqual(report['mode'], mode)
                    self.assertEqual(report['outcome'], 'fail' if throwing else 'pass')
                    self.assertEqual(result.stdout.count(b'\n'), 1)
                    for message in [b'SDK buffered warning', b'SDK C++ warning',
                                    b'SDK descriptor warning', b'SDK shutdown warning']:
                        self.assertIn(message, result.stderr)

    def test_invalid_arguments_do_not_start_the_sdk(self):
        result = subprocess.run([BINARY, 'invalid'], capture_output=True)
        self.assertEqual(result.returncode, 64)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'')

    def test_unavailable_diagnostic_channel_fails_before_sdk_calls(self):
        result = subprocess.run([BINARY, 'infer'], stdout=subprocess.PIPE,
                                preexec_fn=lambda: os.close(2))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')

    def test_protocol_write_failure_is_not_reported_as_success(self):
        with open('/dev/full', 'wb') as full:
            result = subprocess.run([BINARY, 'infer'], stdout=full, stderr=subprocess.PIPE)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
