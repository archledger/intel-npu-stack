#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Contracts for the production signing path: rollback inputs, the keyless inputs
check, passphrase handling and the signing payload-identity gate."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import release_sign as signer

TOOLS = all(shutil.which(tool) for tool in ['gpg', 'gpgconf', 'rpmbuild', 'rpmsign', 'rpmkeys'])
TOOLS_REASON = 'gpg, rpmbuild, rpmsign and rpmkeys are required (installed in the Fedora quality job)'

RUNTIME = sorted(signer.RUNTIME_PACKAGES) if hasattr(signer, 'RUNTIME_PACKAGES') else []


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


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


class InputsContract(unittest.TestCase):
    """The keyless inputs check refuses malformed release inputs before any key use."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.inputs = Path(self.tmp.name) / 'inputs'
        rows = []
        for name in RUNTIME + ['openvino-devel']:
            filename = name + '-1-1.fc44.x86_64.rpm'
            digest = write(self.inputs / 'unsigned-rpms' / filename, ('rpm ' + name).encode())
            rows.append({'name': name, 'filename': filename, 'sha256': digest,
                         'role': 'devel' if name == 'openvino-devel' else 'runtime'})
        self.rows = rows
        self.save_index(rows)
        self.profile = Path(self.tmp.name) / 'profile.toml'
        self.profile.write_text('status = "qualified"\n')
        shutil.copyfile(self.profile, self.inputs / 'candidate.toml')
        (self.inputs / 'package-index.json').write_text(json.dumps({'openvino': {'component': 'openvino'}}))
        (self.inputs / 'source-policy.json').write_text('{}')
        (self.inputs / 'notices').mkdir()
        spdx = write(self.inputs / 'evidence/spdx/openvino/openvino.spdx.json', b'{"spdx": 1}')
        (self.inputs / 'spdx-index.json').write_text(json.dumps({'openvino/openvino.spdx.json': {'sha256': spdx}}))
        rollback = []
        for name in sorted(signer.ROLLBACK_PACKAGES):
            filename = name + '-0-1.fc44.x86_64.rpm'
            rollback.append({'name': name, 'filename': filename,
                             'sha256': write(self.inputs / 'rollback-rpms' / filename, name.encode())})
        (self.inputs / 'rollback-index.json').write_text(json.dumps(rollback))

    def save_index(self, rows):
        (self.inputs / 'index.json').write_text(json.dumps(rows))

    def test_complete_inputs_pass_and_report_counts(self):
        result = signer.validate_inputs(self.inputs, self.profile)
        self.assertTrue(result['passed'])
        self.assertEqual(result['packages'], len(RUNTIME) + 1)
        self.assertEqual(result['roles'], {'devel': 1, 'runtime': len(RUNTIME)})
        self.assertEqual(result['rollback_packages'], 12)
        self.assertEqual(result['spdx_documents'], 1)

    def test_missing_role_is_refused_naming_the_row(self):
        del self.rows[-1]['role']
        self.save_index(self.rows)
        with self.assertRaisesRegex(signer.SigningRefused, r'openvino-devel.*role'):
            signer.validate_inputs(self.inputs, self.profile)

    def test_unknown_role_is_refused(self):
        self.rows[0]['role'] = 'profile'
        self.save_index(self.rows)
        with self.assertRaisesRegex(signer.SigningRefused, 'role'):
            signer.validate_inputs(self.inputs, self.profile)

    def test_duplicate_package_is_refused(self):
        self.save_index(self.rows + [dict(self.rows[0])])
        with self.assertRaisesRegex(signer.SigningRefused, 'duplicate'):
            signer.validate_inputs(self.inputs, self.profile)

    def test_digest_drift_is_refused(self):
        (self.inputs / 'unsigned-rpms' / self.rows[0]['filename']).write_bytes(b'changed')
        with self.assertRaisesRegex(signer.SigningRefused, 'digest mismatch'):
            signer.validate_inputs(self.inputs, self.profile)

    def test_missing_runtime_package_is_refused(self):
        self.save_index([row for row in self.rows if row['name'] != 'intel-npu-driver'])
        with self.assertRaisesRegex(signer.SigningRefused, 'intel-npu-driver'):
            signer.validate_inputs(self.inputs, self.profile)

    def test_candidate_different_from_profile_is_refused(self):
        (self.inputs / 'candidate.toml').write_text('status = "candidate"\n')
        with self.assertRaisesRegex(signer.SigningRefused, 'candidate.toml'):
            signer.validate_inputs(self.inputs, self.profile)

    def test_unsafe_spdx_path_is_refused(self):
        (self.inputs / 'spdx-index.json').write_text(json.dumps({'../escape.json': {'sha256': '0' * 64}}))
        with self.assertRaisesRegex(signer.SigningRefused, 'SPDX'):
            signer.validate_inputs(self.inputs, self.profile)

    def test_check_inputs_mode_needs_no_key(self):
        with mock.patch('builtins.print') as printed:
            self.assertEqual(signer.main(['--check-inputs', '--inputs', str(self.inputs),
                                          '--profile', str(self.profile)]), 0)
        self.assertTrue(json.loads(printed.call_args.args[0])['passed'])


class PassphraseContract(unittest.TestCase):
    """The passphrase reaches gpg only as a file path; Python never holds it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.marker = 'MARKER-' + hashlib.sha256(os.urandom(16)).hexdigest()[:16]
        self.passphrase = self.root / 'passphrase'
        # Written by the shell so the test itself does not construct argv from it.
        subprocess.run(['sh', '-c', 'umask 077; printf %s "$1" > "$2"', 'sh', self.marker, str(self.passphrase)],
                       check=True)

    def test_rpmsign_passes_the_file_through_extra_args(self):
        command = signer.rpmsign_command(self.root / 'x.rpm', self.root / 'gnupg',
                                         'A' * 40, str(self.passphrase))
        joined = ' '.join(command)
        self.assertIn('_gpg_sign_cmd_extra_args --batch --no-tty --pinentry-mode loopback '
                      '--passphrase-file ' + str(self.passphrase), command)
        self.assertNotIn('_gpg_passphrase', joined)
        self.assertNotIn(self.marker, joined)

    def test_detached_signing_argv_never_carries_the_passphrase(self):
        seen = []
        with mock.patch.object(signer, 'run', side_effect=lambda argv, **kw: seen.append(argv)):
            signer.detach_sign(self.root / 'data', self.root / 'data.asc', self.root / 'gnupg',
                               'A' * 40, str(self.passphrase))
        self.assertEqual(len(seen), 1)
        self.assertIn('--passphrase-file', seen[0])
        self.assertNotIn(self.marker, ' '.join(map(str, seen[0])))

    def test_environment_passphrase_is_refused_and_removed(self):
        with mock.patch.dict(os.environ, {'RELEASE_SIGNING_PASSPHRASE': self.marker}):
            with self.assertRaises(SystemExit) as refused:
                signer.main(['--check-inputs', '--inputs', str(self.root), '--profile', str(self.root)])
            self.assertNotIn('RELEASE_SIGNING_PASSPHRASE', os.environ)
        self.assertEqual(refused.exception.code, 1)

    def test_unsafe_or_open_passphrase_files_are_refused(self):
        spaced = self.root / 'with space'
        spaced.write_text('x')
        os.chmod(spaced, 0o600)
        with self.assertRaisesRegex(signer.SigningRefused, 'passphrase file'):
            signer.check_passphrase_file(str(spaced))
        with self.assertRaisesRegex(signer.SigningRefused, 'passphrase file'):
            signer.check_passphrase_file('relative/passphrase')
        os.chmod(self.passphrase, 0o644)
        with self.assertRaisesRegex(signer.SigningRefused, 'passphrase file'):
            signer.check_passphrase_file(str(self.passphrase))
        os.chmod(self.passphrase, 0o600)
        self.assertEqual(signer.check_passphrase_file(str(self.passphrase)), str(self.passphrase))

    def test_payload_identity_gate_refuses_changed_payload(self):
        digests = iter([{'header_sha256': 'a' * 64, 'payload_sha256': 'b' * 64, 'unchanged_cpio_sha256': 'c' * 64},
                        {'header_sha256': 'a' * 64, 'payload_sha256': 'd' * 64, 'unchanged_cpio_sha256': 'c' * 64}])
        with mock.patch.object(signer, 'payload_digests', side_effect=lambda path: next(digests)), \
                mock.patch.object(signer, 'run', return_value=subprocess.CompletedProcess(
                    [], 0, 'Header SHA256 digest: OK\nPayload SHA256 digest: OK\n' + 'a' * 40, '')):
            with self.assertRaisesRegex(signer.SigningRefused, 'payload'):
                signer.sign_rpm(self.root / 'x.rpm', self.root / 'gnupg', 'A' * 40, None, self.root / 'db')


@unittest.skipUnless(TOOLS, TOOLS_REASON)
class SigningIntegration(unittest.TestCase):
    """Real rpmsign/gpg with throwaway ed25519 keys (protected and unprotected)."""

    def setUp(self):
        # Short path: gpg-agent sockets live under GNUPGHOME.
        self.root = Path(tempfile.mkdtemp(prefix='rs-', dir='/tmp'))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.rpm = self.build_rpm()

    def gpg_home(self, name, protected):
        home = self.root / name
        home.mkdir(mode=0o700)
        self.addCleanup(subprocess.run, ['gpgconf', '--homedir', str(home), '--kill', 'all'],
                        capture_output=True)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'GNUPGHOME': str(home)}
        passphrase = None
        if protected:
            passphrase = str(home / 'passphrase')
            subprocess.run(['sh', '-c', 'umask 077; head -c 24 /dev/urandom | base64 > "$1"', 'sh', passphrase],
                           check=True)
            secret = ['--passphrase-file', passphrase]
        else:
            secret = ['--passphrase', '']
        subprocess.run(['gpg', '--batch', '--pinentry-mode', 'loopback', *secret, '--quick-generate-key',
                        'intel-npu-stack test <test@example.invalid>', 'ed25519', 'sign', '1d'],
                       env=env, check=True, capture_output=True)
        listing = subprocess.run(['gpg', '--batch', '--with-colons', '--list-secret-keys'], env=env,
                                 check=True, capture_output=True, text=True).stdout
        fingerprint = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')][0]
        public = self.root / (name + '.asc')
        public.write_text(subprocess.run(['gpg', '--batch', '--armor', '--export', fingerprint], env=env,
                                         check=True, capture_output=True, text=True).stdout)
        dbpath = self.root / (name + '-rpmdb')
        dbpath.mkdir()
        subprocess.run(['rpmkeys', '--dbpath', str(dbpath), '--import', str(public)], check=True)
        return home, fingerprint, passphrase, dbpath

    def build_rpm(self):
        top = self.root / 'rpmbuild'
        for leaf in ['BUILD', 'SPECS', 'RPMS', 'SRPMS', 'SOURCES']:
            (top / leaf).mkdir(parents=True)
        spec = top / 'SPECS/signing-probe.spec'
        spec.write_text('Name: signing-probe\nVersion: 1\nRelease: 1\nSummary: probe\nLicense: Apache-2.0\n'
                        'BuildArch: noarch\n%description\nprobe\n%install\nmkdir -p %{buildroot}/usr/share/probe\n'
                        'echo probe > %{buildroot}/usr/share/probe/file\n%files\n/usr/share/probe/file\n')
        subprocess.run(['rpmbuild', '-bb', '--define', '_topdir ' + str(top), str(spec)], check=True,
                       capture_output=True, env={'PATH': '/usr/bin:/bin', 'HOME': str(self.root)})
        return next((top / 'RPMS').rglob('*.rpm'))

    def signed_copy(self, name):
        target = self.root / (name + '.rpm')
        shutil.copyfile(self.rpm, target)
        return target

    def test_protected_key_signs_through_the_passphrase_file(self):
        home, fingerprint, passphrase, dbpath = self.gpg_home('protected', True)
        target = self.signed_copy('protected')
        before = signer.payload_digests(target)
        after = signer.sign_rpm(target, home, fingerprint, signer.check_passphrase_file(passphrase), dbpath)
        self.assertEqual(before, after)
        self.assertNotEqual(signer.sha(target), signer.sha(self.rpm))
        check = subprocess.run(['rpmkeys', '--dbpath', str(dbpath), '--checksig', '--verbose', str(target)],
                               capture_output=True, text=True).stdout
        self.assertIn(fingerprint.lower(), check.lower())
        self.assertEqual(after['unchanged_cpio_sha256'],
                         signer.query(target, '%{PAYLOADSHA256ALT}'))

    def test_wrong_passphrase_is_refused_without_hanging(self):
        home, fingerprint, passphrase, dbpath = self.gpg_home('wrong', True)
        wrong = self.root / 'wrong-passphrase'
        subprocess.run(['sh', '-c', 'umask 077; printf wrong > "$1"', 'sh', str(wrong)], check=True)
        target = self.signed_copy('wrong')
        with self.assertRaises(signer.SigningRefused):
            signer.sign_rpm(target, home, fingerprint, str(wrong), dbpath)

    def test_unprotected_key_still_signs(self):
        home, fingerprint, _, dbpath = self.gpg_home('plain', False)
        target = self.signed_copy('plain')
        signer.sign_rpm(target, home, fingerprint, None, dbpath)
        signature = self.root / 'data.asc'
        data = self.root / 'data'
        data.write_text('release metadata\n')
        signer.detach_sign(data, signature, home, fingerprint, None)
        signer.verify_detached(signature, data, home, fingerprint)
        data.write_text('changed\n')
        with self.assertRaises(signer.SigningRefused):
            signer.verify_detached(signature, data, home, fingerprint)


if __name__ == '__main__':
    unittest.main()
