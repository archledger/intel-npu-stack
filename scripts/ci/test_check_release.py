# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the publication verifier against a synthetic signed
production release tree built with a throwaway key."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_release import ReleaseRefused, check_release  # noqa: E402

RELEASE = '0.1.0'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


class ThrowawayKey:
    def __init__(self, home):
        self.home = Path(home)
        self.home.mkdir(parents=True, exist_ok=True)
        self.env = {**os.environ, 'GNUPGHOME': str(self.home)}
        subprocess.run(['gpg', '--batch', '--pinentry-mode', 'loopback',
                        '--passphrase', '', '--quick-generate-key',
                        'Publication verifier test <test@example.invalid>',
                        'ed25519', 'sign', '1d'],
                       env=self.env, check=True, capture_output=True)
        listing = subprocess.run(['gpg', '--batch', '--with-colons', '--list-keys'],
                                 env=self.env, capture_output=True, text=True).stdout
        self.fingerprint = next(line.split(':')[9] for line in listing.splitlines()
                                if line.startswith('fpr:'))
        self.public = self.home / 'public.asc'
        with self.public.open('wb') as stream:
            subprocess.run(['gpg', '--batch', '--armor', '--export', self.fingerprint],
                           env=self.env, check=True, stdout=stream)

    def sign(self, path, output=None):
        subprocess.run(['gpg', '--batch', '--pinentry-mode', 'loopback',
                        '--passphrase', '', '--armor', '--detach-sign',
                        '--local-user', self.fingerprint,
                        '--output', str(output or (str(path) + '.sig')), str(path)],
                       env=self.env, check=True, capture_output=True)


def build_rpm(root, key):
    top = Path(root) / 'rpmbuild'
    for leaf in ['BUILD', 'SOURCES', 'SPECS', 'RPMS', 'SRPMS', 'tmp']:
        (top / leaf).mkdir(parents=True, exist_ok=True)
    spec = top / 'SPECS/verifier-fixture.spec'
    write(spec, '\n'.join([
        'Name: verifier-fixture', 'Version: 1.0.0', 'Release: 1',
        'Summary: Publication verifier fixture', 'License: MIT',
        'BuildArch: noarch', '%description', 'Fixture.', '%install',
        'mkdir -p %{buildroot}/usr/share/verifier-fixture',
        'printf "fixture\\n" > %{buildroot}/usr/share/verifier-fixture/data',
        '%files', '/usr/share/verifier-fixture/data', '']))
    subprocess.run(['rpmbuild', '-bb', '--define', '_topdir ' + str(top),
                    '--define', '_tmppath ' + str(top / 'tmp'), str(spec)],
                   check=True, capture_output=True)
    rpm = next((top / 'RPMS').rglob('*.rpm'))
    target = Path(root) / 'packages' / rpm.name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(rpm, target)
    subprocess.run(['rpmsign', '--define', '_gpg_path ' + str(key.home),
                    '--define', '_openpgp_sign_id ' + key.fingerprint,
                    '--addsign', str(target)],
                   env=key.env, check=True, capture_output=True)
    return target


def build_tree(root, key):
    root = Path(root)
    rpm = build_rpm(root, key)
    write(root / 'profile.toml', '\n'.join([
        'schema_version = 1', 'id = "fedora-44-verifier-fixture"',
        f'stack_release = "{RELEASE}"', 'status = "qualified"',
        'package_manager = "rpm"', '',
        '[qualification]',
        'evidence_id = "verifier-fixture-evidence"',
        'evidence_sha256 = "' + 'a' * 64 + '"',
        'qualified_at = "2026-09-18T00:00:00Z"',
        'hardware_class = "fixture"',
        'test_suite_version = "1"', '']))
    release = {
        'schema_version': 1, 'stack_release': RELEASE,
        'profile_sha256': sha(root / 'profile.toml'),
        'repository': {'id': 'intel-npu-stack-' + RELEASE,
                       'base_url': f'https://example.invalid/intel-npu-stack/{RELEASE}/fedora/44/x86_64/',
                       'repomd_sha256': ''},
        'packages': [{'name': 'verifier-fixture', 'nevr': '0:1.0.0-1',
                      'arch': 'noarch', 'filename': rpm.name,
                      'sha256': sha(rpm), 'role': 'runtime'}],
    }
    write(root / 'release.json', json.dumps(release, indent=2, sort_keys=True) + '\n')
    key.sign(root / 'release.json')
    repomd = root / 'repodata/repomd.xml'
    write(repomd, '<repomd/>\n')
    key.sign(repomd, output=str(repomd) + '.asc')
    for relative in ['evidence/spdx/doc.spdx.json', 'evidence/notices/LICENSE',
                     'evidence/rollback/rollback-index.json']:
        write(root / relative, '{}\n')
    files = [p for p in sorted(root.rglob('*')) if p.is_file()
             and p.name not in {'checksums.sha256', 'assembly-manifest.json'}]
    write(root / 'checksums.sha256',
          '\n'.join(f'{sha(p)}  {p.relative_to(root).as_posix()}' for p in files) + '\n')
    manifest = {
        'passed': True, 'test_only': False, 'release_ready': False,
        'package_count': 1,
        'output_digests': {p.relative_to(root).as_posix(): sha(p)
                           for p in sorted(root.rglob('*')) if p.is_file()
                           and p.name != 'assembly-manifest.json'},
    }
    write(root / 'assembly-manifest.json', json.dumps(manifest, indent=2) + '\n')
    return root


def reseal(root, *, checksums=True):
    """Recompute the assembly output digests (and optionally the checksums
    file) after an intended mutation so later gates are exercised. The
    checksums file is written before the digests are recorded, mirroring the
    assembler's order."""
    root = Path(root)
    if checksums:
        files = [p for p in sorted(root.rglob('*')) if p.is_file()
                 and p.name not in {'checksums.sha256', 'assembly-manifest.json'}]
        (root / 'checksums.sha256').write_text(
            '\n'.join(f'{sha(p)}  {p.relative_to(root).as_posix()}' for p in files) + '\n')
    manifest_path = root / 'assembly-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    manifest['output_digests'] = {p.relative_to(root).as_posix(): sha(p)
                                  for p in sorted(root.rglob('*')) if p.is_file()
                                  and p.name != 'assembly-manifest.json'}
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')


class PublicationVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory()
        cls.base = Path(cls.workspace.name)
        cls.key = ThrowawayKey(cls.base / 'keyring')
        cls.tree = build_tree(cls.base / 'tree', cls.key)

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def copy_tree(self):
        target = Path(tempfile.mkdtemp(dir=self.base))
        shutil.copytree(self.tree, target / 'tree')
        return target / 'tree'

    def refusal(self, tree, message):
        output = Path(tree) / 'publication-manifest.json'
        with self.assertRaises(ReleaseRefused) as caught:
            check_release(tree, tree / 'profile.toml', output,
                          production_key=self.key.public)
        self.assertIn(message, str(caught.exception))
        self.assertFalse(output.exists())

    def test_verifies_a_signed_production_tree(self):
        tree = self.copy_tree()
        output = Path(tree) / 'publication-manifest.json'
        result = check_release(tree, tree / 'profile.toml', output,
                               production_key=self.key.public)
        self.assertTrue(result['passed'])
        self.assertTrue(result['publication_ready'])
        self.assertEqual(result['release_key_fingerprint'], self.key.fingerprint)
        self.assertEqual(result['package_count'], 1)
        self.assertEqual(result['rpm_signatures_verified'], 1)
        written = json.loads(output.read_text())
        self.assertEqual(written, result)

    def test_candidate_profile_is_refused(self):
        tree = self.copy_tree()
        text = (tree / 'profile.toml').read_text().replace(
            'status = "qualified"', 'status = "candidate"')
        (tree / 'profile.toml').write_text(text)
        self.refusal(tree, 'qualified profile')

    def test_missing_qualification_record_is_refused(self):
        tree = self.copy_tree()
        text = (tree / 'profile.toml').read_text()
        (tree / 'profile.toml').write_text(text.replace(
            '[qualification]', '[not_qualification]'))
        self.refusal(tree, 'qualification evidence')

    def test_test_only_assembly_is_refused(self):
        tree = self.copy_tree()
        manifest = json.loads((tree / 'assembly-manifest.json').read_text())
        manifest['test_only'] = True
        (tree / 'assembly-manifest.json').write_text(json.dumps(manifest))
        self.refusal(tree, 'production assembly')

    def test_tampered_package_is_refused(self):
        tree = self.copy_tree()
        rpm = next((tree / 'packages').glob('*.rpm'))
        with rpm.open('ab') as stream:
            stream.write(b'tampered')
        self.refusal(tree, 'digest drift')

    def test_missing_release_signature_is_refused(self):
        tree = self.copy_tree()
        (tree / 'release.json.sig').unlink()
        reseal(tree)
        self.refusal(tree, 'signature is missing')

    def test_signature_from_a_different_key_is_refused(self):
        tree = self.copy_tree()
        other = ThrowawayKey(Path(self.base) / 'other-keyring')
        (tree / 'release.json.sig').unlink()
        other.sign(tree / 'release.json')
        reseal(tree)
        self.refusal(tree, 'not from the pinned release key')

    def test_missing_evidence_is_refused(self):
        tree = self.copy_tree()
        shutil.rmtree(tree / 'evidence/rollback')
        reseal(tree)
        self.refusal(tree, 'required evidence is missing')

    def test_checksums_drift_is_refused(self):
        tree = self.copy_tree()
        (tree / 'evidence/notices/LICENSE').write_text('changed\n')
        reseal(tree, checksums=False)
        self.refusal(tree, 'checksums drift')

    def test_assembly_output_digest_drift_is_refused(self):
        tree = self.copy_tree()
        manifest = json.loads((tree / 'assembly-manifest.json').read_text())
        manifest['output_digests']['profile.toml'] = '0' * 64
        (tree / 'assembly-manifest.json').write_text(json.dumps(manifest))
        self.refusal(tree, 'assembly output digest drift')

    def test_profile_metadata_mismatch_is_refused(self):
        tree = self.copy_tree()
        release = json.loads((tree / 'release.json').read_text())
        release['profile_sha256'] = '0' * 64
        (tree / 'release.json').write_text(json.dumps(release))
        self.refusal(tree, 'profile bytes')


if __name__ == '__main__':
    unittest.main()
