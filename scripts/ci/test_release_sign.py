#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rollback input contract for the production signing path."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import release_sign as signer


class RollbackContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'rollback-rpms').mkdir()
        names = ['intel-npu-compiler', 'intel-npu-driver', 'libopenvino-ir-frontend',
                 'libopenvino-onnx-frontend', 'libopenvino-paddle-frontend',
                 'libopenvino-pytorch-frontend', 'libopenvino-tensorflow-frontend',
                 'libopenvino-tensorflow-lite-frontend', 'oneapi-level-zero',
                 'openvino', 'openvino-devel', 'openvino-plugins']
        self.rows = []
        for name in names:
            data = name.encode()
            filename = name + '-1-1.fc44.x86_64.rpm'
            (self.root / 'rollback-rpms' / filename).write_bytes(data)
            self.rows.append({'name': name, 'filename': filename,
                              'sha256': hashlib.sha256(data).hexdigest()})

    def copy(self, rows):
        (self.root / 'rollback-index.json').write_text(json.dumps(rows))
        output = self.root / 'output'
        signer.copy_rollback(self.root, output)
        return output

    def test_complete_twelve_package_baseline_is_copied(self):
        output = self.copy(self.rows)
        self.assertEqual(len(list(output.glob('*.rpm'))), 12)
        self.assertEqual(json.loads((output / 'rollback-index.json').read_text()), self.rows)

    def test_old_eleven_package_baseline_is_refused(self):
        rows = [row for row in self.rows if row['name'] != 'oneapi-level-zero']
        with self.assertRaisesRegex(signer.SigningRefused, 'rollback package set'):
            self.copy(rows)

    def test_duplicate_cannot_replace_missing_loader(self):
        rows = [row for row in self.rows if row['name'] != 'oneapi-level-zero']
        with self.assertRaisesRegex(signer.SigningRefused, 'rollback package set'):
            self.copy(rows + [rows[0]])

    def test_changed_rollback_bytes_are_refused(self):
        (self.root / 'rollback-rpms' / self.rows[0]['filename']).write_bytes(b'changed')
        with self.assertRaisesRegex(signer.SigningRefused, 'digest drift'):
            self.copy(self.rows)


if __name__ == '__main__':
    unittest.main()
