#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Contract for scripts/ci/release-keyring.sh with throwaway keys."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / 'release-keyring.sh'
GPG = shutil.which('gpg') and shutil.which('gpgconf')


def fstype(path):
    return subprocess.run(['stat', '-f', '-c', '%T', str(path)], capture_output=True, text=True).stdout.strip()


SHM_TMPFS = Path('/dev/shm').is_dir() and fstype('/dev/shm') == 'tmpfs'


@unittest.skipUnless(GPG, 'gpg and gpgconf are required (installed in the Fedora quality job)')
class KeyringContract(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='rk-', dir='/tmp'))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.home = Path('/dev/shm') / ('rk-test-' + os.urandom(6).hex())
        self.addCleanup(self.destroy)
        self.key = self.make_key('release', protected=True)

    def destroy(self):
        subprocess.run(['bash', str(SCRIPT), 'destroy'], env=self.env({}), capture_output=True)

    def make_key(self, name, protected):
        home = self.root / name
        home.mkdir(mode=0o700)
        self.addCleanup(subprocess.run, ['gpgconf', '--homedir', str(home), '--kill', 'all'], capture_output=True)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'GNUPGHOME': str(home)}
        passfile = home / 'pass'
        subprocess.run(['sh', '-c', 'umask 077; head -c 24 /dev/urandom | base64 > "$1"', 'sh', str(passfile)],
                       check=True)
        secret = ['--passphrase-file', str(passfile)] if protected else ['--passphrase', '']
        subprocess.run(['gpg', '--batch', '--pinentry-mode', 'loopback', *secret, '--quick-generate-key',
                        name + ' <' + name + '@example.invalid>', 'ed25519', 'sign', '1d'],
                       env=env, check=True, capture_output=True)
        listing = subprocess.run(['gpg', '--batch', '--with-colons', '--list-secret-keys'], env=env,
                                 check=True, capture_output=True, text=True).stdout
        fingerprint = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')][0]
        armored = subprocess.run(['gpg', '--batch', '--pinentry-mode', 'loopback', *secret, '--armor',
                                  '--export-secret-keys', fingerprint], env=env, check=True,
                                 capture_output=True, text=True).stdout
        public = self.root / (name + '.asc')
        public.write_text(subprocess.run(['gpg', '--batch', '--armor', '--export', fingerprint], env=env,
                                         check=True, capture_output=True, text=True).stdout)
        return {'fingerprint': fingerprint, 'secret': armored, 'passphrase': passfile.read_text(),
                'public': public}

    def env(self, extra):
        return {'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'RELEASE_GNUPGHOME': str(self.home),
                'RELEASE_PUBLIC_KEY': str(self.key['public']), **extra}

    def import_key(self, **overrides):
        values = {'RELEASE_SIGNING_KEY': self.key['secret'], 'RELEASE_SIGNING_PASSPHRASE': self.key['passphrase'],
                  'RELEASE_SIGNING_FINGERPRINT': self.key['fingerprint'], **overrides}
        return subprocess.run(['bash', str(SCRIPT), 'import'], env=self.env(values), capture_output=True,
                              text=True, timeout=120)

    @unittest.skipUnless(SHM_TMPFS, '/dev/shm is not a tmpfs here; see test_non_tmpfs_is_refused')
    def test_import_writes_owner_only_passphrase_and_destroy_removes_it(self):
        result = self.import_key()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('passphrase_file=' + str(self.home / 'passphrase'), result.stdout)
        passphrase = self.home / 'passphrase'
        self.assertEqual(passphrase.stat().st_mode & 0o777, 0o600)
        self.assertEqual(passphrase.read_text(), self.key['passphrase'])
        self.assertEqual(self.home.stat().st_mode & 0o777, 0o700)
        self.assertNotIn(self.key['passphrase'].strip(), result.stdout + result.stderr)
        self.destroy()
        self.assertFalse(self.home.exists())

    @unittest.skipUnless(SHM_TMPFS, '/dev/shm is not a tmpfs here')
    def test_refusals_leave_no_keyring_behind(self):
        other = self.make_key('other', protected=True)
        cases = {
            'fingerprint': {'RELEASE_SIGNING_FINGERPRINT': other['fingerprint']},
            'empty passphrase': {'RELEASE_SIGNING_PASSPHRASE': ''},
            'wrong passphrase': {'RELEASE_SIGNING_PASSPHRASE': 'wrong'},
            'second secret key': {'RELEASE_SIGNING_KEY': self.key['secret'] + '\n' + other['secret']},
        }
        for label, override in cases.items():
            with self.subTest(label):
                result = self.import_key(**override)
                self.assertNotEqual(result.returncode, 0, label)
                self.assertIn('release keyring refused', result.stderr)
                self.assertFalse(self.home.exists(), label)

    @unittest.skipUnless(SHM_TMPFS, '/dev/shm is not a tmpfs here')
    def test_committed_key_mismatch_is_refused(self):
        other = self.make_key('committed', protected=False)
        result = subprocess.run(['bash', str(SCRIPT), 'import'], capture_output=True, text=True, timeout=120,
                                env={**self.env({'RELEASE_SIGNING_KEY': self.key['secret'],
                                                 'RELEASE_SIGNING_PASSPHRASE': self.key['passphrase'],
                                                 'RELEASE_SIGNING_FINGERPRINT': self.key['fingerprint']}),
                                     'RELEASE_PUBLIC_KEY': str(other['public'])})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('committed release public key', result.stderr)
        self.assertFalse(self.home.exists())

    @unittest.skipUnless(SHM_TMPFS, '/dev/shm is not a tmpfs here')
    def test_existing_home_is_refused(self):
        self.home.mkdir(mode=0o700)
        result = self.import_key()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('already exists', result.stderr)

    def test_non_tmpfs_is_refused(self):
        disk = Path(tempfile.mkdtemp(prefix='rk-disk-', dir='/var/tmp'))
        self.addCleanup(shutil.rmtree, disk, True)
        if fstype(disk) == 'tmpfs':
            self.skipTest('/var/tmp is a tmpfs here')
        result = subprocess.run(['bash', str(SCRIPT), 'import'], capture_output=True, text=True, timeout=60,
                                env={**self.env({'RELEASE_SIGNING_KEY': self.key['secret'],
                                                 'RELEASE_SIGNING_PASSPHRASE': self.key['passphrase'],
                                                 'RELEASE_SIGNING_FINGERPRINT': self.key['fingerprint']}),
                                     'RELEASE_GNUPGHOME': str(disk / 'gnupg')})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('is not a tmpfs', result.stderr)
        self.assertFalse((disk / 'gnupg').exists())

    def test_shared_memory_is_tmpfs_on_this_runner(self):
        # Records the assumption the release job depends on; fails loudly where it does not hold.
        self.assertTrue(SHM_TMPFS, '/dev/shm must be a tmpfs for the release keyring')


if __name__ == '__main__':
    unittest.main()
