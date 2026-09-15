# SPDX-License-Identifier: Apache-2.0
"""The production ELF archive must use the driver's firmware API headers."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('driver_headers', Path(__file__).with_name('check-driver-headers.py'))
headers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(headers)


class DriverHeaderTests(unittest.TestCase):
    ELF_OBJECT = '/build/third_party/npu_compiler_elf/CMakeFiles/npu_elf.dir/hpi.cpp.o'
    DRIVER_OBJECT = '/build/umd/CMakeFiles/ze_intel_npu.dir/device.cpp.o'

    def test_production_firmware_headers_are_accepted(self):
        self.assertEqual(headers.validate_dependencies({
            self.ELF_OBJECT: ['/usr/include/stdint.h'],
            self.DRIVER_OBJECT: ['/source/firmware/include/api/vpu_nnrt_api.h']}), 1)

    def test_elf_bundled_upstream_headers_are_allowed(self):
        self.assertEqual(headers.validate_dependencies({
            self.ELF_OBJECT: [
                '/source/third_party/npu_compiler_elf/3rdparty/nnrt/details/api/vpu_nnrt_api_40xx.h'],
            self.DRIVER_OBJECT: ['/source/firmware/include/api/vpu_nnrt_api.h']}), 1)

    def test_restored_test_headers_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'test NNRT header'):
            headers.validate_dependencies({
                self.ELF_OBJECT: [
                    '/source/third_party/npu_compiler_elf/3rdparty/nnrt_api/api/vpu_nnrt_api.h'],
                self.DRIVER_OBJECT: ['/source/firmware/include/api/vpu_nnrt_api.h']})

    def test_driver_bundled_headers_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'bundled NNRT header'):
            headers.validate_dependencies({
                self.ELF_OBJECT: ['/usr/include/stdint.h'],
                self.DRIVER_OBJECT: [
                    '/source/third_party/npu_compiler_elf/3rdparty/nnrt/details/api/vpu_nnrt_api.h']})

    def test_missing_production_header_evidence_is_rejected(self):
        for records in [{}, {self.ELF_OBJECT: ['/usr/include/stdint.h']},
                        {self.ELF_OBJECT: ['/usr/include/stdint.h'],
                         self.DRIVER_OBJECT: ['/usr/include/stdint.h']}]:
            with self.subTest(records=records), self.assertRaises(ValueError):
                headers.validate_dependencies(records)

    def test_stale_and_incomplete_dependency_records_are_rejected(self):
        for text in ['a.o: #deps 1, deps mtime 1 (STALE)\n    /a.h\n',
                     'a.o: #deps 2, deps mtime 1 (VALID)\n    /a.h\n']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                headers.parse_dependencies('a.o', text)


if __name__ == '__main__':
    unittest.main()
