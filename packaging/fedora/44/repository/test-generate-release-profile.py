#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Candidate-to-release profile generation contract tests.

These tests use tiny synthetic inputs; the real accepted candidate and the
native signed-identity record are exercised separately in disposable
containers. Generation performs no subprocess, no build and no signing; it
only verifies and rewrites component digests.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile
import tomllib
import unittest

REPO = Path(__file__).resolve().parents[4]
GENERATE = REPO/'packaging/fedora/44/repository/generate-release-profile.py'

STACK_RELEASE = '0.1.0'
LOADER_UNSIGNED = hashlib.sha256(b'unsigned loader rpm').hexdigest()
LOADER_SIGNED = hashlib.sha256(b'signed loader rpm').hexdigest()
FIRMWARE_UNSIGNED = hashlib.sha256(b'unsigned firmware rpm').hexdigest()
FIRMWARE_SIGNED = hashlib.sha256(b'signed firmware rpm').hexdigest()
PROFILE_UNSIGNED = hashlib.sha256(b'unsigned profile rpm').hexdigest()
PROFILE_SIGNED = hashlib.sha256(b'signed profile rpm').hexdigest()
TOOLS_UNSIGNED = hashlib.sha256(b'unsigned tools rpm').hexdigest()
TOOLS_SIGNED = hashlib.sha256(b'signed tools rpm').hexdigest()
META_UNSIGNED = hashlib.sha256(b'unsigned meta rpm').hexdigest()
META_SIGNED = hashlib.sha256(b'signed meta rpm').hexdigest()
LOADER_FILE = hashlib.sha256(b'loader payload file').hexdigest()
FIRMWARE_FILE = hashlib.sha256(b'firmware payload file').hexdigest()
LOADER_EVIDENCE = hashlib.sha256(b'loader license evidence').hexdigest()
FIRMWARE_EVIDENCE = hashlib.sha256(b'firmware license evidence').hexdigest()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


def candidate_text():
    return (
        '# SPDX-License-Identifier: Apache-2.0\n'
        '# Generated candidate; no channel may select it.\n'
        'schema_version = 1\n'
        'id = "fedora-44-synthetic-x86_64"\n'
        f'stack_release = "{STACK_RELEASE}"\n'
        'status = "candidate"\n'
        'package_manager = "rpm"\n'
        'conflicts = []\n'
        '\n[platform]\nid = "fedora"\nversion_id = "44"\narch = "x86_64"\n'
        '\n[[hardware]]\nvendor = "8086"\ndevice = "643e"\n'
        '\n[kernel]\nmin = "7.1.13"\nmax_exclusive = "7.1.14"\nmodule = "intel_vpu"\n'
        '\n[components.loader]\nversion = "1.28.6"\n'
        'source = "https://example.invalid/level-zero.git"\n'
        f'sha256 = "{LOADER_UNSIGNED}"\n'
        '\n[components.loader.provider]\npackage = "oneapi-level-zero"\n'
        'version = "0:1.28.6-1.fc44"\nactivation = "immediate"\n'
        '\n[[components.loader.provider.files]]\n'
        'path = "/usr/lib64/libze_loader.so.1.28.6"\n'
        f'sha256 = "{LOADER_FILE}"\n'
        '\n[components.loader.license]\nexpression = "MIT"\n'
        f'redistribution = "external_only"\nevidence_sha256 = "{LOADER_EVIDENCE}"\n'
        '\n[components.firmware]\nversion = "1.35.0"\n'
        'source = "https://example.invalid/linux-npu-driver.git"\n'
        f'sha256 = "{FIRMWARE_UNSIGNED}"\n'
        '\n[components.firmware.provider]\npackage = "intel-npu-stack-firmware"\n'
        'version = "0:1.35.0-1.intelnpu.fc44"\nactivation = "reboot"\n'
        '\n[[components.firmware.provider.files]]\n'
        'path = "/usr/lib/firmware/updates/intel/vpu/vpu_40xx_v1.bin"\n'
        f'sha256 = "{FIRMWARE_FILE}"\n'
        '\n[components.firmware.license]\nexpression = "LicenseRef-Intel-firmware"\n'
        f'redistribution = "allowed"\nevidence_sha256 = "{FIRMWARE_EVIDENCE}"\n'
    )


def identity_packages():
    return [
        {'name': 'oneapi-level-zero', 'nevr': '0:1.28.6-1.fc44', 'arch': 'x86_64',
         'filename': 'oneapi-level-zero-1.28.6-1.fc44.x86_64.rpm', 'role': 'runtime',
         'unsigned_sha256': LOADER_UNSIGNED, 'signed_sha256': LOADER_SIGNED,
         'unchanged_cpio_sha256': sha(b'loader cpio')},
        {'name': 'intel-npu-stack-firmware', 'nevr': '0:1.35.0-1.intelnpu.fc44', 'arch': 'noarch',
         'filename': 'intel-npu-stack-firmware-1.35.0-1.intelnpu.fc44.noarch.rpm', 'role': 'runtime',
         'unsigned_sha256': FIRMWARE_UNSIGNED, 'signed_sha256': FIRMWARE_SIGNED,
         'unchanged_cpio_sha256': sha(b'firmware cpio')},
        {'name': 'intel-npu-stack', 'nevr': '0:0.1.0-1.intelnpu.fc44', 'arch': 'noarch',
         'filename': 'intel-npu-stack-0.1.0-1.intelnpu.fc44.noarch.rpm', 'role': 'runtime',
         'unsigned_sha256': META_UNSIGNED, 'signed_sha256': META_SIGNED,
         'unchanged_cpio_sha256': sha(b'meta cpio')},
        {'name': 'intel-npu-stack-tools', 'nevr': '0:0.1.0-1.intelnpu.fc44', 'arch': 'x86_64',
         'filename': 'intel-npu-stack-tools-0.1.0-1.intelnpu.fc44.x86_64.rpm', 'role': 'runtime',
         'unsigned_sha256': TOOLS_UNSIGNED, 'signed_sha256': TOOLS_SIGNED,
         'unchanged_cpio_sha256': sha(b'tools cpio')},
        {'name': 'intel-npu-stack-profile', 'nevr': '0:0.1.0-1.intelnpu.fc44', 'arch': 'noarch',
         'filename': 'intel-npu-stack-profile-0.1.0-1.intelnpu.fc44.noarch.rpm', 'role': 'profile',
         'unsigned_sha256': PROFILE_UNSIGNED, 'signed_sha256': PROFILE_SIGNED,
         'unchanged_cpio_sha256': sha(b'profile cpio')},
    ]


def identity_record(packages=None):
    return {'passed': True, 'test_only': True,
            'primary_fingerprint': '1EB5A90BFC6D62690BD80767D981218E0FD4DBF3',
            'repomd_sha256': sha(b'synthetic repomd'),
            'packages': identity_packages() if packages is None else packages}


class Workspace(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.base = Path(self.workspace.name)

    def tearDown(self):
        self.workspace.cleanup()

    def make_inputs(self, *, candidate=None, identity=None):
        root = self.base/'input'
        root.mkdir(parents=True, exist_ok=True)
        (root/'profile-candidate.toml').write_text(
            candidate_text() if candidate is None else candidate)
        write_json(root/'signed-identity.json',
                   identity_record() if identity is None else identity)
        return root

    def run_generate(self, root, output=None, record=None):
        output = output or (self.base/'release-profile.toml')
        argv = [sys.executable, str(GENERATE), '--candidate', str(root/'profile-candidate.toml'),
                '--identity', str(root/'signed-identity.json'), '--output', str(output)]
        if record is not None:
            argv += ['--record', str(record)]
        return subprocess.run(argv, capture_output=True, text=True), output

    def generate_ok(self, root, record=None):
        result, output = self.run_generate(root, record=record)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        return output

    def refusal(self, mutate=None, *, candidate=None, identity=None):
        root = self.make_inputs(candidate=candidate, identity=identity)
        if mutate is not None:
            mutate(root)
        result, output = self.run_generate(root)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(output.exists())
        return result.stderr


class GenerationContract(Workspace):
    def test_rewrites_component_digests_to_signed_providers(self):
        root = self.make_inputs()
        output = self.generate_ok(root)
        candidate_bytes = (root/'profile-candidate.toml').read_bytes()
        document = tomllib.loads(output.read_text())
        self.assertEqual(document['status'], 'candidate')
        self.assertEqual(document['components']['loader']['sha256'], LOADER_SIGNED)
        self.assertEqual(document['components']['firmware']['sha256'], FIRMWARE_SIGNED)
        self.assertEqual(document['components']['loader']['provider']['files'][0]['sha256'],
                         LOADER_FILE)
        self.assertEqual(document['components']['firmware']['provider']['files'][0]['sha256'],
                         FIRMWARE_FILE)
        self.assertEqual(document['components']['loader']['license']['evidence_sha256'],
                         LOADER_EVIDENCE)
        original = candidate_bytes.decode().split('\n')
        rewritten = output.read_text().split('\n')
        self.assertEqual(len(original), len(rewritten))
        changed = [(before, after) for before, after in zip(original, rewritten)
                   if before != after]
        self.assertEqual(sorted(changed), sorted([
            (f'sha256 = "{LOADER_UNSIGNED}"', f'sha256 = "{LOADER_SIGNED}"'),
            (f'sha256 = "{FIRMWARE_UNSIGNED}"', f'sha256 = "{FIRMWARE_SIGNED}"')]))

    def test_generation_is_deterministic(self):
        root = self.make_inputs()
        first = self.base/'first.toml'
        result, _ = self.run_generate(root, output=first, record=self.base/'record1.json')
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        root2 = self.make_inputs()
        second = self.base/'second.toml'
        result, _ = self.run_generate(root2, output=second, record=self.base/'record2.json')
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual((self.base/'record1.json').read_bytes(),
                         (self.base/'record2.json').read_bytes())

    def test_record_captures_every_binding(self):
        root = self.make_inputs()
        record_path = self.base/'generation.json'
        output = self.generate_ok(root, record=record_path)
        record = json.loads(record_path.read_text())
        self.assertTrue(record['passed'])
        self.assertTrue(record['test_only'])
        self.assertEqual(record['scope'],
                         'candidate-to-release profile digest rewrite from the passed '
                         'signed-identity inventory; no build, signing or qualification')
        self.assertEqual(record['stack_release'], STACK_RELEASE)
        self.assertEqual(record['profile_id'], 'fedora-44-synthetic-x86_64')
        self.assertEqual(record['candidate_sha256'], sha((root/'profile-candidate.toml').read_bytes()))
        self.assertEqual(record['signed_identity_sha256'],
                         sha((root/'signed-identity.json').read_bytes()))
        self.assertEqual(record['output_sha256'], sha(output.read_bytes()))
        self.assertEqual(record['primary_fingerprint'], '1EB5A90BFC6D62690BD80767D981218E0FD4DBF3')
        self.assertEqual(sorted(record['components']), ['firmware', 'loader'])
        self.assertEqual(record['components']['loader'],
                         {'package': 'oneapi-level-zero', 'nevr': '0:1.28.6-1.fc44',
                          'unsigned_sha256': LOADER_UNSIGNED, 'signed_sha256': LOADER_SIGNED})

    def test_non_candidate_status_is_refused(self):
        message = self.refusal(candidate=candidate_text().replace(
            'status = "candidate"', 'status = "qualified"'))
        self.assertIn('candidate', message)

    def test_stale_candidate_digest_is_refused(self):
        message = self.refusal(candidate=candidate_text().replace(
            LOADER_UNSIGNED, sha(b'a different unsigned loader rpm')))
        self.assertIn('unsigned', message)

    def test_unknown_provider_is_refused(self):
        message = self.refusal(candidate=candidate_text().replace(
            'package = "oneapi-level-zero"', 'package = "ghost-package"'))
        self.assertIn('ghost-package', message)

    def test_nevr_mismatch_is_refused(self):
        message = self.refusal(candidate=candidate_text().replace(
            'version = "0:1.28.6-1.fc44"', 'version = "0:1.28.5-1.fc44"'))
        self.assertIn('NEVR', message)

    def test_profile_package_provider_is_refused(self):
        swapped = (candidate_text()
                   .replace('package = "oneapi-level-zero"', 'package = "intel-npu-stack-profile"')
                   .replace(LOADER_UNSIGNED, PROFILE_UNSIGNED))
        message = self.refusal(candidate=swapped)
        self.assertIn('runtime', message)

    def test_unpassed_identity_is_refused(self):
        identity = identity_record()
        identity['passed'] = False
        message = self.refusal(identity=identity)
        self.assertIn('passed', message)

    def qualified_text(self):
        return candidate_text().replace(
            'status = "candidate"', 'status = "qualified"') + (
            '\n[qualification]\n'
            'evidence_id = "synthetic-evidence"\n'
            'evidence_sha256 = "' + 'a' * 64 + '"\n'
            'qualified_at = "2026-09-18T00:00:00Z"\n'
            'hardware_class = "synthetic"\ntest_suite_version = "1"\n')

    def production_identity(self):
        identity = identity_record()
        identity['test_only'] = False
        identity['production_ready'] = True
        return identity

    def test_production_identity_rewrites_a_qualified_profile(self):
        identity = self.production_identity()
        record_path = self.base/'generation.json'
        root = self.make_inputs(candidate=self.qualified_text(), identity=identity)
        self.generate_ok(root, record=record_path)
        record = json.loads(record_path.read_text())
        self.assertTrue(record['passed'])
        self.assertFalse(record['test_only'])
        self.assertEqual(record['profile_status'], 'qualified')

    def test_production_identity_refuses_a_candidate_profile(self):
        identity = self.production_identity()
        message = self.refusal(identity=identity)
        self.assertIn('qualified', message)

    def test_test_identity_refuses_a_qualified_profile(self):
        message = self.refusal(candidate=self.qualified_text())
        self.assertIn('candidate', message)

    def test_incomplete_production_identity_is_refused(self):
        identity = identity_record()
        identity['test_only'] = False
        message = self.refusal(identity=identity)
        self.assertIn('production-ready', message)

    def test_invalid_identity_digest_is_refused(self):
        identity = identity_record()
        identity['packages'][0]['signed_sha256'] = 'not-a-digest'
        self.refusal(identity=identity)

    def test_unexpected_digest_formatting_is_refused(self):
        message = self.refusal(candidate=candidate_text().replace(
            f'sha256 = "{LOADER_UNSIGNED}"', f'sha256="{LOADER_UNSIGNED}"'))
        self.assertIn('loader', message)

    def test_missing_component_digest_is_refused(self):
        lines = candidate_text().split('\n')
        lines.remove(f'sha256 = "{FIRMWARE_UNSIGNED}"')
        message = self.refusal(candidate='\n'.join(lines))
        self.assertIn('firmware', message)

    def test_existing_output_is_refused(self):
        root = self.make_inputs()
        output = self.base/'release-profile.toml'
        output.write_text('precious\n')
        result, _ = self.run_generate(root, output=output)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_text(), 'precious\n')

    def test_existing_record_is_refused(self):
        root = self.make_inputs()
        record = self.base/'generation.json'
        record.write_text('precious\n')
        result, _ = self.run_generate(root, record=record)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base/'release-profile.toml').exists())
        self.assertEqual(record.read_text(), 'precious\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
