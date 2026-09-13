#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministic release assembly contract tests.

These tests use tiny synthetic inputs; native signed repositories and real
build evidence are exercised separately in disposable containers. Assembly
performs no subprocess and no publication; it composes and verifies bytes.
"""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[4]
ASSEMBLE = REPO/'packaging/fedora/44/repository/assemble.py'

BASE_URL = 'https://downloads.example.invalid/intel-npu-stack/0.1.0/fedora/44/x86_64/'
REPOSITORY_ID = 'intel-npu-stack-0.1.0'
RELEASE = '0.1.0'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


def make_input(root, *, profile_status='candidate', cycle=False):
    """Builds a complete synthetic assembly input tree."""
    packages = {
        'intel-npu-stack-0.1.0-1.intelnpu.fc44.noarch.rpm': b'signed metapackage bytes\n',
        'intel-npu-stack-tools-0.1.0-1.intelnpu.fc44.x86_64.rpm': b'signed tools bytes\n',
        'intel-npu-stack-profile-0.1.0-1.intelnpu.fc44.noarch.rpm': b'signed profile rpm bytes\n',
    }
    (root/'repository/packages').mkdir(parents=True, exist_ok=True)
    for name, data in packages.items():
        (root/'repository/packages'/name).write_bytes(data)
    repomd = b'<synthetic signed repomd/>\n'
    (root/'repository/repodata').mkdir(parents=True, exist_ok=True)
    (root/'repository/repodata/repomd.xml').write_bytes(repomd)
    (root/'repository/repodata/repomd.xml.asc').write_bytes(b'-----BEGIN PGP SIGNATURE-----\n')
    (root/'repository/repodata/primary.xml.zst').write_bytes(b'synthetic primary metadata\n')

    identities = []
    roles = {'intel-npu-stack': 'runtime', 'intel-npu-stack-tools': 'runtime',
             'intel-npu-stack-profile': 'profile'}
    nevrs = {'intel-npu-stack': ('0:0.1.0-1.intelnpu.fc44', 'noarch'),
             'intel-npu-stack-tools': ('0:0.1.0-1.intelnpu.fc44', 'x86_64'),
             'intel-npu-stack-profile': ('0:0.1.0-1.intelnpu.fc44', 'noarch')}
    for filename, data in packages.items():
        name = filename.rsplit('-', 2)[0]
        nevr, arch = nevrs[name]
        identities.append({'name': name, 'nevr': nevr, 'arch': arch, 'filename': filename,
                           'role': roles[name], 'unsigned_sha256': sha(b'unsigned '+name.encode()),
                           'signed_sha256': sha(data), 'unchanged_cpio_sha256': sha(b'cpio '+name.encode())})
    write_json(root/'signed-identity.json', {'passed': True, 'test_only': True,
                                             'primary_fingerprint': '1EB5A90BFC6D62690BD80767D981218E0FD4DBF3',
                                             'repomd_sha256': sha(repomd),
                                             'packages': identities})

    package_index = {
        'intel-npu-stack': {'component': 'intel-npu-stack',
                            'declared_license': 'Apache-2.0',
                            'regular_files': {'/usr/share/doc/intel-npu-stack/README':
                                              {'sha256': sha(b'readme'), 'size': 6}}},
        'intel-npu-stack-tools': {'component': 'intel-npu-stack-tools',
                                  'declared_license': 'Apache-2.0',
                                  'regular_files': {'/usr/bin/intel-npu-stack':
                                                    {'sha256': sha(b'tools-payload'), 'size': 13}}},
    }
    write_json(root/'aggregate/package-index.json', package_index)

    spdx_bytes = b'{"spdxVersion": "SPDX-2.3", "name": "synthetic"}\n'
    for key in ['intel-npu-stack/bound/intel-npu-stack.spdx.json',
                'intel-npu-stack/bound/intel-npu-stack-tools.spdx.json']:
        (root/'evidence/spdx'/key).parent.mkdir(parents=True, exist_ok=True)
        (root/'evidence/spdx'/key).write_bytes(spdx_bytes)
    write_json(root/'aggregate/spdx-index.json', {
        'intel-npu-stack/bound/intel-npu-stack.spdx.json': {'sha256': sha(spdx_bytes)},
        'intel-npu-stack/bound/intel-npu-stack-tools.spdx.json': {'sha256': sha(spdx_bytes)}})

    notice = b'Apache License 2.0 notice text\n'
    (root/'evidence/notices/packaging/fedora/44/licenses/example-notice.txt').parent.mkdir(parents=True, exist_ok=True)
    (root/'evidence/notices/packaging/fedora/44/licenses/example-notice.txt').write_bytes(notice)
    write_json(root/'aggregate/source-policy.json', [
        {'name': 'example-source', 'archive_sha256': sha(b'archive'), 'license_expression': 'Apache-2.0',
         'license_files': ['packaging/fedora/44/licenses/example-notice.txt'], 'redistribution': 'allowed'}])
    (root/'evidence/rollback').mkdir(parents=True, exist_ok=True)
    (root/'evidence/rollback/intel-npu-stack-0.0.9-1.fc44.noarch.rpm').write_bytes(b'rollback bytes\n')
    write_json(root/'evidence/rollback/rollback-index.json', [
        {'filename': 'intel-npu-stack-0.0.9-1.fc44.noarch.rpm', 'sha256': sha(b'rollback bytes\n'),
         'name': 'intel-npu-stack', 'nevr': '0:0.0.9-1.fc44'}])

    profile_digest = sha(b'unsigned intel-npu-stack-profile')
    if cycle:
        component_digest = identities[2]['signed_sha256']
    else:
        component_digest = sha(packages['intel-npu-stack-tools-0.1.0-1.intelnpu.fc44.x86_64.rpm'])
    profile = (
        '# SPDX-License-Identifier: Apache-2.0\n'
        'schema_version = 1\n'
        'id = "fedora-44-lunar-lake-x86_64"\n'
        f'stack_release = "{RELEASE}"\n'
        f'status = "{profile_status}"\n'
        'package_manager = "rpm"\n'
        'conflicts = []\n'
        '\n[platform]\nid = "fedora"\nversion_id = "44"\narch = "x86_64"\n'
        '\n[[hardware]]\nvendor = "8086"\ndevice = "643e"\n'
        '\n[kernel]\nmin = "7.1.13"\nmax_exclusive = "7.1.14"\nmodule = "intel_vpu"\n'
        '\n[components.tools]\nversion = "0.1.0-1.intelnpu.fc44"\n'
        'source = "https://example.invalid/tools.git"\n'
        f'sha256 = "{component_digest}"\n'
        '\n[components.tools.provider]\npackage = "intel-npu-stack-tools"\n'
        'version = "0:0.1.0-1.intelnpu.fc44"\nactivation = "immediate"\n'
        '\n[components.tools.provider.license]\nredistribution = "allowed"\n'
    )
    (root/'profile.toml').write_text(profile)
    (root/'release-metadata.sig').write_bytes(b'-----BEGIN PGP SIGNATURE-----\ntest\n')
    build_evidence = {
        'profile_filename': 'intel-npu-stack-profile-0.1.0-1.intelnpu.fc44.noarch.rpm',
        'source_profile_sha256': sha((root/'profile.toml').read_bytes()),
        'unsigned_sha256': profile_digest,
        'signed_sha256': sha(packages['intel-npu-stack-profile-0.1.0-1.intelnpu.fc44.noarch.rpm']),
        'installed_profile_path': '/usr/share/intel-npu-stack/profiles/fedora-44-lunar-lake-x86_64.toml',
        'builds': [profile_digest, profile_digest],
        'reproducible': True,
    }
    write_json(root/'profile-rpm-build.json', build_evidence)
    return root


def run_assemble(input_root, output, *, base_url=BASE_URL, repository_id=REPOSITORY_ID,
                 release=RELEASE):
    return subprocess.run(
        [sys.executable, str(ASSEMBLE), '--input-root', str(input_root), '--output', str(output),
         '--base-url', base_url, '--repository-id', repository_id, '--release-version', release],
        capture_output=True, text=True)


def assemble_ok(input_root, output):
    result = run_assemble(input_root, output)
    assert result.returncode == 0, (result.stdout, result.stderr)
    return json.loads((output/'assembly-manifest.json').read_text())


class AssemblyContract(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.base = Path(self.workspace.name)

    def tearDown(self):
        self.workspace.cleanup()

    def output_tree(self, output):
        return {str(path.relative_to(output)): sha(path.read_bytes())
                for path in sorted(output.rglob('*')) if path.is_file()}

    def test_assembles_the_exact_release_from_accepted_inputs(self):
        make_input(self.base/'input')
        output = self.base/'release'
        manifest = assemble_ok(self.base/'input', output)
        release = json.loads((output/'release.json').read_text())
        self.assertEqual(release['schema_version'], 1)
        self.assertEqual(release['stack_release'], RELEASE)
        self.assertEqual(release['profile_sha256'], sha((self.base/'input/profile.toml').read_bytes()))
        self.assertEqual(release['repository'],
                         {'id': REPOSITORY_ID, 'base_url': BASE_URL,
                          'repomd_sha256': sha(b'<synthetic signed repomd/>\n')})
        by_name = {package['name']: package for package in release['packages']}
        self.assertEqual(sorted(by_name), ['intel-npu-stack', 'intel-npu-stack-profile',
                                           'intel-npu-stack-tools'])
        self.assertEqual(by_name['intel-npu-stack']['role'], 'runtime')
        self.assertEqual(by_name['intel-npu-stack-profile']['role'], 'profile')
        self.assertEqual(by_name['intel-npu-stack-tools']['sha256'],
                         sha(b'signed tools bytes\n'))
        self.assertEqual(by_name['intel-npu-stack-profile']['sha256'],
                         sha(b'signed profile rpm bytes\n'))
        self.assertEqual((output/'profile.toml').read_bytes(),
                         (self.base/'input/profile.toml').read_bytes())
        self.assertEqual((output/'release.json.sig').read_bytes(),
                         b'-----BEGIN PGP SIGNATURE-----\ntest\n')
        for name in ['intel-npu-stack-0.1.0-1.intelnpu.fc44.noarch.rpm',
                     'intel-npu-stack-tools-0.1.0-1.intelnpu.fc44.x86_64.rpm',
                     'intel-npu-stack-profile-0.1.0-1.intelnpu.fc44.noarch.rpm']:
            self.assertEqual((output/'packages'/name).read_bytes(),
                             (self.base/'input/repository/packages'/name).read_bytes())
        self.assertEqual((output/'repodata/repomd.xml').read_bytes(), b'<synthetic signed repomd/>\n')
        self.assertTrue((output/'repodata/repomd.xml.asc').is_file())
        self.assertTrue((output/'evidence/spdx/intel-npu-stack/bound/intel-npu-stack-tools.spdx.json').is_file())
        self.assertTrue((output/'evidence/notices/packaging/fedora/44/licenses/example-notice.txt').is_file())
        self.assertTrue((output/'evidence/rollback/rollback-index.json').is_file())
        checksum_lines = (output/'checksums.sha256').read_text().splitlines()
        recorded_paths = [line.split('  ', 1)[1] for line in checksum_lines]
        self.assertEqual(recorded_paths, sorted(recorded_paths))
        recorded = set(recorded_paths)
        self.assertIn('release.json', recorded)
        self.assertIn('packages/intel-npu-stack-tools-0.1.0-1.intelnpu.fc44.x86_64.rpm', recorded)
        self.assertEqual(manifest['release_ready'], False)
        self.assertTrue(manifest['test_only'])

    def test_assembly_is_reproducible(self):
        make_input(self.base/'input')
        first, second = self.base/'release1', self.base/'release2'
        assemble_ok(self.base/'input', first)
        assemble_ok(self.base/'input', second)
        self.assertEqual(self.output_tree(first), self.output_tree(second))

    def refusal(self, mutate, *, base_url=BASE_URL, repository_id=REPOSITORY_ID):
        make_input(self.base/'input')
        mutate(self.base/'input')
        result = run_assemble(self.base/'input', self.base/'release', base_url=base_url,
                              repository_id=repository_id)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.base/'release/release.json').exists())

    def test_missing_required_component_is_refused(self):
        def mutate(root):
            path = root/'repository/packages/intel-npu-stack-tools-0.1.0-1.intelnpu.fc44.x86_64.rpm'
            path.unlink()
        self.refusal(mutate)

    def test_stale_signed_digest_is_refused(self):
        def mutate(root):
            (root/'repository/packages/intel-npu-stack-0.1.0-1.intelnpu.fc44.noarch.rpm'
             ).write_bytes(b'tampered\n')
        self.refusal(mutate)

    def test_extra_payload_is_refused(self):
        def mutate(root):
            (root/'repository/packages/unlisted-1-1.fc44.noarch.rpm').write_bytes(b'extra\n')
        self.refusal(mutate)

    def test_wrong_profile_hash_is_refused(self):
        def mutate(root):
            (root/'profile.toml').write_text('# drifted\n')
        self.refusal(mutate)

    def test_false_qualification_is_refused(self):
        def mutate(root):
            profile = root/'profile.toml'
            profile.write_text(profile.read_text().replace('candidate', 'qualified'))
        self.refusal(mutate)

    def test_profile_self_hash_cycle_is_refused(self):
        self.refusal(lambda root: make_input(root, cycle=True))

    def test_conflicting_payload_ownership_is_refused(self):
        def mutate(root):
            index = json.loads((root/'aggregate/package-index.json').read_text())
            index['intel-npu-stack']['regular_files']['/usr/bin/intel-npu-stack'] = {
                'sha256': sha(b'conflict'), 'size': 5}
            write_json(root/'aggregate/package-index.json', index)
        self.refusal(mutate)

    def test_missing_spdx_document_is_refused(self):
        def mutate(root):
            (root/'evidence/spdx/intel-npu-stack/bound/intel-npu-stack.spdx.json').unlink()
        self.refusal(mutate)

    def test_colliding_spdx_basenames_bind_by_full_key(self):
        """Real bundles ship distinct native-build-inputs.spdx.json per provider."""
        def mutate(root):
            first = b'{"spdxVersion": "SPDX-2.3", "name": "openvino native"}\n'
            second = b'{"spdxVersion": "SPDX-2.3", "name": "driver native"}\n'
            for key, data in [('openvino/native-build-inputs.spdx.json', first),
                              ('driver/bound/native-build-inputs.spdx.json', second)]:
                (root/'evidence/spdx'/key).parent.mkdir(parents=True, exist_ok=True)
                (root/'evidence/spdx'/key).write_bytes(data)
            write_json(root/'aggregate/spdx-index.json', {
                'openvino/native-build-inputs.spdx.json': {'sha256': sha(first)},
                'driver/bound/native-build-inputs.spdx.json': {'sha256': sha(second)}})
        make_input(self.base/'input')
        mutate(self.base/'input')
        assemble_ok(self.base/'input', self.base/'release')
        output = self.base/'release'
        self.assertEqual((output/'evidence/spdx/openvino/native-build-inputs.spdx.json').read_bytes(),
                         b'{"spdxVersion": "SPDX-2.3", "name": "openvino native"}\n')
        self.assertEqual((output/'evidence/spdx/driver/bound/native-build-inputs.spdx.json').read_bytes(),
                         b'{"spdxVersion": "SPDX-2.3", "name": "driver native"}\n')

    def test_unsafe_spdx_key_is_refused(self):
        def mutate(root):
            index = json.loads((root/'aggregate/spdx-index.json').read_text())
            index['../escape.spdx.json'] = {'sha256': sha(b'escape')}
            write_json(root/'aggregate/spdx-index.json', index)
        self.refusal(mutate)

    def test_missing_notice_file_is_refused(self):
        def mutate(root):
            (root/'evidence/notices/packaging/fedora/44/licenses/example-notice.txt').unlink()
        self.refusal(mutate)

    def test_repomd_digest_drift_is_refused(self):
        def mutate(root):
            identity = json.loads((root/'signed-identity.json').read_text())
            identity['repomd_sha256'] = sha(b'other')
            write_json(root/'signed-identity.json', identity)
        self.refusal(mutate)

    def test_plain_http_base_url_is_refused(self):
        self.refusal(lambda root: None, base_url='http://downloads.example.invalid/0.1.0/')

    def test_moving_alias_base_url_is_refused(self):
        self.refusal(lambda root: None,
                     base_url='https://downloads.example.invalid/intel-npu-stack/latest/')

    def test_invalid_repository_id_is_refused(self):
        self.refusal(lambda root: None, repository_id='intel npu')

    def test_missing_release_signature_is_refused(self):
        def mutate(root):
            (root/'release-metadata.sig').unlink()
        self.refusal(mutate)

    def test_empty_release_signature_is_refused(self):
        def mutate(root):
            (root/'release-metadata.sig').write_bytes(b'')
        self.refusal(mutate)

    def test_oversized_release_signature_is_refused(self):
        def mutate(root):
            (root/'release-metadata.sig').write_bytes(b'x'*65537)
        self.refusal(mutate)

    def test_existing_output_is_refused(self):
        make_input(self.base/'input')
        (self.base/'release').mkdir()
        (self.base/'release/existing.txt').write_text('kept')
        result = run_assemble(self.base/'input', self.base/'release')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.base/'release/existing.txt').read_text(), 'kept')


if __name__ == '__main__':
    unittest.main(verbosity=2)
