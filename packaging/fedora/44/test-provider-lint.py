#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Keep reviewed notice findings distinct from arbitrary lint failures."""
import copy
import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('provider_lint', HERE/'lint-provider-rpms.py')
LINT = importlib.util.module_from_spec(SPEC)
if SPEC.origin and Path(SPEC.origin).exists():
    SPEC.loader.exec_module(LINT)

ITT = 'src/plugins/intel_cpu/thirdparty/onednn/third_party/ittnotify/ittptmark64.S'
ITT_SHA = '15e6b25d6e6ef3f4f5866423d71d22d7026e4ed0a6a707e7d6777abcf4b620ad'
GPL_SHA = 'f6b78c087c3ebdf0f3c13415070dd480a3f35d8fc76f3d02180a407c1c812f79'


class ProviderLint(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(LINT, 'assess'), 'approved exact-notice assessment is not implemented')
        self.inventory = [{'package': 'openvino', 'architecture': 'x86_64', 'sha256': '1'*64}]
        self.notices = {'openvino': {'package': 'openvino', 'rpm_sha256': '1'*64,
                        'verified_notices': 1, 'notice_sha256': {ITT: ITT_SHA}, 'verified_hardlinks': 0}}
        self.error = 'openvino.x86_64: E: incorrect-fsf-address /usr/share/licenses/openvino/'+ITT

    def output(self, errors=None, count=1, badness=None):
        errors = [self.error] if errors is None else errors
        return ('rpmlint: 2.8.0\nchecks: 32, packages: '+str(count)+'\n'+ '\n'.join(errors)+
                '\n '+str(count)+' packages and 0 specfiles checked; '+str(len(errors))+
                ' errors, 0 warnings, 0 filtered, '+str(len(errors) if badness is None else badness)+
                ' badness; has taken 1.0 s \n').encode()

    def assess(self, output=None, code=64, stderr=b''):
        return LINT.assess(self.output() if output is None else output, stderr, code,
                           self.inventory, self.notices)

    def test_exact_notice_retains_raw_error_and_records_review(self):
        result = self.assess()
        self.assertEqual(result['raw_exit_code'], 64)
        self.assertEqual(result['errors'], 1)
        self.assertEqual(result['reviewed_exceptions'][0]['sha256'], ITT_SHA)
        self.assertTrue(result['lint_policy_passed'])

    def test_driver_exception_is_separately_bound(self):
        self.inventory = [{'package': 'intel-npu-driver', 'architecture': 'x86_64', 'sha256': '2'*64}]
        self.notices = {'intel-npu-driver': {'package': 'intel-npu-driver', 'rpm_sha256': '2'*64,
                        'verified_notices': 1, 'notice_sha256': {'linux-uapi/GPL-2.0': GPL_SHA}, 'verified_hardlinks': 0}}
        self.error = 'intel-npu-driver.x86_64: E: incorrect-fsf-address /usr/share/licenses/intel-npu-driver/linux-uapi/GPL-2.0'
        self.assertEqual(self.assess()['reviewed_exceptions'][0]['sha256'], GPL_SHA)

    def test_missing_changed_or_stale_notice_evidence_blocks(self):
        original = copy.deepcopy(self.notices)
        for change in ['missing', 'bytes', 'rpm', 'inventory']:
            with self.subTest(change=change):
                self.notices = copy.deepcopy(original)
                if change == 'missing': self.notices.clear()
                if change == 'bytes': self.notices['openvino']['notice_sha256'][ITT] = '3'*64
                if change == 'rpm': self.notices['openvino']['rpm_sha256'] = '3'*64
                if change == 'inventory': self.notices['openvino']['verified_notices'] = 2
                with self.assertRaises(ValueError): self.assess()

    def test_wrong_package_arch_path_diagnostic_and_extra_errors_block(self):
        errors = [self.error.replace('openvino.x86_64', 'other.x86_64'),
                  self.error.replace('x86_64', 'aarch64'), self.error+'-copy',
                  self.error.replace('incorrect-fsf-address', 'invalid-license'),
                  self.error+'\nopenvino.x86_64: E: invalid-license Bad']
        for error in errors:
            with self.subTest(error=error), self.assertRaises(ValueError):
                self.assess(self.output(errors=error.splitlines()))

    def test_duplicate_and_unparsed_error_blocks(self):
        for errors in [[self.error, self.error], [self.error, 'unparsed: E: fatal']]:
            with self.subTest(errors=errors), self.assertRaises(ValueError):
                self.assess(self.output(errors=errors))

    def test_crash_truncation_count_or_summary_mismatch_blocks(self):
        cases = [(self.output(), 1, b''), (self.output(), 66, b''), (self.output(), 0, b''),
                 (self.output(), 64, b'Traceback: failure'), (b'', 0, b''),
                 (self.output().split(b' packages and')[0], 64, b''),
                 (self.output(count=2), 64, b''), (self.output(badness=5), 64, b''),
                 (self.output()+b'Traceback: failure\n', 64, b''),
                 (self.output().replace(b'1 errors', b'2 errors'), 64, b'')]
        for output, code, stderr in cases:
            with self.subTest(output=output, code=code, stderr=stderr), self.assertRaises(ValueError):
                self.assess(output, code, stderr)

    def test_clean_success_requires_complete_lint_run(self):
        self.notices.clear()
        result = self.assess(self.output(errors=[]), 0)
        self.assertTrue(result['lint_policy_passed'])
        self.assertEqual(result['reviewed_exceptions'], [])
        with self.assertRaises(ValueError): self.assess(self.output(errors=[]), 64)


class RealNoticeLint(unittest.TestCase):
    def test_actual_rpm_verification_and_raw_lint_evidence(self):
        cases = [('openvino', ITT, ITT_SHA,
                  HERE/'licenses/source-notices/openvino-onednn-cpu/third_party/ittnotify/ittptmark64.S',
                  '(BSD-3-Clause OR GPL-2.0-only)'),
                 ('intel-npu-driver', 'linux-uapi/GPL-2.0', GPL_SHA,
                  HERE/'licenses/linux-uapi-GPL-2.0', 'GPL-2.0-only')]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for package, relative, digest, source, license in cases:
                with self.subTest(package=package):
                    top = root/package
                    top.mkdir()
                    self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), digest)
                    (top/'notice').write_bytes(source.read_bytes())
                    sidecar = top/'SHA256.json'
                    sidecar.write_text(json.dumps({relative: digest}))
                    manifest = top/'manifest.json'
                    manifest.write_text(json.dumps({'schema_version': 1, 'packages': {package: {relative: digest}}}))
                    spec = top/(package+'.spec')
                    spec.write_text('''%global debug_package %{nil}
Name: '''+package+'''
Version: 1
Release: 1
Summary: Original notice transport regression
License: '''+license+'''
URL: https://github.com/intel/linux-npu-driver
Source0: notice
Source1: SHA256.json
ExclusiveArch: x86_64
%description
An isolated test of exact original notice transport and lint review.
%build
echo 'int main(void) { return 0; }' > fixture.c
%{__cc} $RPM_OPT_FLAGS fixture.c -o lint-fixture $RPM_LD_FLAGS
%install
install -Dm0644 %{SOURCE0} %{buildroot}/usr/share/licenses/%{name}/'''+relative+'''
install -m0644 %{SOURCE1} %{buildroot}/usr/share/licenses/%{name}/SHA256.json
install -Dm0755 lint-fixture %{buildroot}/usr/bin/lint-fixture
%files
%license /usr/share/licenses/%{name}
/usr/bin/lint-fixture
%changelog
* Fri Sep 11 2026 Test Fixture <fixture@example.invalid> - 1-1
- Verify notice transport in isolated test packages.
''')
                    build = subprocess.run(['rpmbuild', '-ba', '--define', '_topdir '+str(top),
                                            '--define', '_sourcedir '+str(top), '--define', '_tmppath '+str(top),
                                            str(spec)], capture_output=True, text=True)
                    self.assertEqual(build.returncode, 0, build.stdout+build.stderr)
                    rpm = next((top/'RPMS').rglob('*.rpm'))
                    srpm = next((top/'SRPMS').glob('*.rpm'))
                    output = top/'review'
                    command = [sys.executable, str(HERE/'lint-provider-rpms.py'), '--manifest', str(manifest),
                               '--output', str(output), str(rpm), str(srpm)]
                    result = subprocess.run(command, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                    evidence = json.loads((output/'result.json').read_text())
                    self.assertEqual(evidence['raw_exit_code'], 64)
                    self.assertEqual(evidence['errors'], 1)
                    self.assertEqual([row['architecture'] for row in evidence['rpms']], ['x86_64', 'src'])
                    self.assertEqual(evidence['reviewed_exceptions'][0]['sha256'], digest)
                    self.assertEqual(evidence['notice_verification'][package]['rpm_sha256'],
                                     hashlib.sha256(rpm.read_bytes()).hexdigest())
                    self.assertIn(b': E: incorrect-fsf-address ', (output/'stdout.log').read_bytes())
                    # A caller cannot replace the full RPM verifier with a claimed
                    # cached pass. A stale prepared inventory must fail the CLI.
                    manifest.write_text(json.dumps({'schema_version': 1, 'packages': {package: {relative: '0'*64}}}))
                    command[command.index(str(output))] = str(top/'stale-review')
                    stale = subprocess.run(command, capture_output=True, text=True)
                    self.assertNotEqual(stale.returncode, 0)
                    rejected = json.loads((top/'stale-review/result.json').read_text())
                    self.assertFalse(rejected['lint_policy_passed'])
                    self.assertEqual(rejected['raw_exit_code'], 64)
                    self.assertIn('notice header digest differs', rejected['failure'])


if __name__ == '__main__':
    unittest.main()
