# SPDX-License-Identifier: Apache-2.0
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from prepare_native_sdk import download, extract_source, extract_wheel


class SdkChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_verified_cached_asset_does_not_use_network(self):
        data = b'accepted asset'
        digest = hashlib.sha256(data).hexdigest()
        (self.root / digest).write_bytes(data)
        with patch('urllib.request.urlopen', side_effect=AssertionError('network')):
            self.assertEqual(download({'url': 'https://example.invalid/asset', 'sha256': digest}, self.root).read_bytes(), data)

    def test_corrupt_cache_is_refused(self):
        digest = hashlib.sha256(b'original').hexdigest()
        (self.root / digest).write_bytes(b'corrupt')
        with patch('urllib.request.urlopen', side_effect=AssertionError('network')):
            with self.assertRaises(ValueError):
                download({'url': 'https://example.invalid/asset', 'sha256': digest}, self.root)

    def test_wheel_sdk_layout_is_preserved(self):
        archive = self.root / 'sdk.whl'
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('openvino/cmake/OpenVINOConfig.cmake', 'config')
            z.writestr('openvino/libs/libopenvino.so.2620', 'library')
            z.writestr('openvino/include/openvino/openvino.hpp', 'header')
            z.writestr('openvino/python_binding.so', 'not needed')
        dest = self.root / 'sdk'
        extract_wheel(archive, dest)
        self.assertEqual((dest / 'openvino/cmake/OpenVINOConfig.cmake').read_text(), 'config')
        self.assertFalse((dest / 'openvino/python_binding.so').exists())

    def test_wheel_traversal_is_refused(self):
        archive = self.root / 'bad.whl'
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('openvino/include/../../../escape', 'bad')
        with self.assertRaises(ValueError):
            extract_wheel(archive, self.root / 'sdk')
        self.assertFalse((self.root / 'escape').exists())

    def test_source_archive_traversal_is_refused(self):
        archive = self.root / 'bad.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            item = tarfile.TarInfo('../escape')
            item.size = 3
            tar.addfile(item, io.BytesIO(b'bad'))
        with self.assertRaises(ValueError):
            extract_source(archive, self.root / 'source')
        self.assertFalse((self.root / 'escape').exists())


if __name__ == '__main__':
    unittest.main()
