# SPDX-License-Identifier: Apache-2.0
"""The production ELF archive must use the driver's firmware API headers."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('driver_headers', Path(__file__).with_name('check-driver-headers.py'))
headers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(headers)


class DriverHeaderTests(unittest.TestCase):
    def test_production_firmware_headers_are_accepted(self):
        self.assertEqual(headers.validate_dependencies({'hpi.cpp.o': [
            '/source/firmware/include/api/vpu_nnrt_api.h', '/usr/include/stdint.h']}), 1)

    def test_restored_test_headers_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'test NNRT header'):
            headers.validate_dependencies({'hpi.cpp.o': [
                '/source/firmware/include/api/vpu_nnrt_api.h',
                '/source/third_party/npu_compiler_elf/3rdparty/nnrt_api/api/vpu_nnrt_api.h']})

    def test_bundled_upstream_headers_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'bundled NNRT header'):
            headers.validate_dependencies({'hpi.cpp.o': [
                '/source/firmware/include/api/vpu_nnrt_api.h',
                '/source/third_party/npu_compiler_elf/3rdparty/nnrt/details/api/vpu_nnrt_api.h']})

    def test_missing_production_header_evidence_is_rejected(self):
        for records in [{}, {'hpi.cpp.o': ['/usr/include/stdint.h']}]:
            with self.subTest(records=records), self.assertRaises(ValueError):
                headers.validate_dependencies(records)

    def test_stale_and_incomplete_dependency_records_are_rejected(self):
        for text in ['a.o: #deps 1, deps mtime 1 (STALE)\n    /a.h\n',
                     'a.o: #deps 2, deps mtime 1 (VALID)\n    /a.h\n']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                headers.parse_dependencies('a.o', text)


if __name__ == '__main__':
    unittest.main()
