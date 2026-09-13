#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Observe exact notice transport through real RPM headers and payloads."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent

class NoticeRpm(unittest.TestCase):
    def test_debugsource_covers_compiler_licenses(self):
        with tempfile.TemporaryDirectory() as temporary:
            spec = Path(temporary)/'query.spec'
            # Query mode does not add the debug packages that build mode adds.
            # Expand the installed RPM macro explicitly without compiling.
            spec.write_text((HERE/'openvino/openvino.spec').read_text()+'\n%debug_package\n')
            result = subprocess.run(
                ['rpmspec', '-q', '--queryformat', '%{NAME}\t%{LICENSE}\n', str(spec)],
                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        licenses = dict(row.split('\t', 1) for row in result.stdout.splitlines())
        # This source RPM's debugsource payload includes both OpenVINO and
        # compiler/LLVM source files, unlike the OpenVINO runtime package.
        self.assertIn('Apache-2.0 WITH LLVM-exception', licenses['intel-npu-compiler'])
        self.assertIn('LicenseRef-LLVM-MD5', licenses['intel-npu-compiler'])
        self.assertEqual(licenses['openvino-debugsource'], licenses['intel-npu-compiler'])
        self.assertNotEqual(licenses['openvino-debugsource'], licenses['openvino'])

    def test_real_rpm_notice_transport_and_refusals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for folder in ['SOURCES', 'SPECS', 'BUILD', 'BUILDROOT', 'RPMS', 'SRPMS']:
                (root/folder).mkdir()
            text = b'Copyright fixture\r\nPermission granted for transport test.\r\n'
            files = {'LICENSE': hashlib.sha256(text).hexdigest(), 'dependency/LICENSE': hashlib.sha256(text).hexdigest()}
            (root/'SOURCES/notice').write_bytes(text)
            (root/'SOURCES/SHA256.json').write_text(json.dumps(files, sort_keys=True)+'\n')
            manifest = root/'manifest.json'
            manifest.write_text(json.dumps({'schema_version': 1, 'packages': {'notice-fixture': files}}))
            for case in ['good', 'unflagged', 'changed', 'missing', 'symlink']:
                top = root/case
                top.mkdir()
                spec = top/'fixture.spec'
                install = 'install -Dm0644 %{SOURCE0} %{buildroot}/usr/share/licenses/notice-fixture/LICENSE\nmkdir -p %{buildroot}/usr/share/licenses/notice-fixture/dependency\nln %{buildroot}/usr/share/licenses/notice-fixture/LICENSE %{buildroot}/usr/share/licenses/notice-fixture/dependency/LICENSE\ninstall -m0644 %{SOURCE1} %{buildroot}/usr/share/licenses/notice-fixture/SHA256.json\n'
                if case == 'changed':
                    install += 'echo changed >> %{buildroot}/usr/share/licenses/notice-fixture/LICENSE\n'
                if case == 'missing':
                    install += 'rm %{buildroot}/usr/share/licenses/notice-fixture/dependency/LICENSE\n'
                if case == 'symlink':
                    install += 'rm %{buildroot}/usr/share/licenses/notice-fixture/dependency/LICENSE\nln -s ../LICENSE %{buildroot}/usr/share/licenses/notice-fixture/dependency/LICENSE\n'
                spec.write_text('''%global debug_package %{nil}
Name: notice-fixture
Version: 1
Release: 1
Summary: Notice transport regression
License: MIT
Source0: notice
Source1: SHA256.json
BuildArch: noarch
%description
Tests only notice transport in an isolated RPM.
%install
'''+install+'%files\n'+('' if case == 'unflagged' else '%license ')+'/usr/share/licenses/notice-fixture\n')
                build = subprocess.run(['rpmbuild', '-bb', '--define', '_topdir '+str(top), '--define', '_sourcedir '+str(root/'SOURCES'), '--define', '_tmppath '+str(top), str(spec)], capture_output=True, text=True)
                self.assertEqual(build.returncode, 0, build.stdout+build.stderr)
                rpm = next((top/'RPMS').rglob('*.rpm'))
                result = subprocess.run([sys.executable, str(HERE/'verify-provider-notice-rpm.py'), '--rpm', str(rpm), '--manifest', str(manifest)], capture_output=True, text=True)
                if case == 'good':
                    self.assertEqual(result.returncode, 0, result.stderr)
                    evidence = json.loads(result.stdout)
                    self.assertEqual(evidence['verified_notices'], 2)
                    self.assertEqual(evidence['verified_hardlinks'], 1)
                    self.assertEqual(evidence['package'], 'notice-fixture')
                else:
                    self.assertNotEqual(result.returncode, 0, case)

if __name__ == '__main__':
    unittest.main()
