#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Contract for the committed installer trust seam and the release-time metadata pin."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import release_trust as trust

REPO = Path(__file__).resolve().parents[2]
TRUST = REPO / 'crates/stack-install/src/trust.rs'
ZEROS = '0' * 64
DIGEST = 'ab' * 32


class CommittedTrust(unittest.TestCase):
    """Guards on the committed trust.rs: everything but the metadata digest is pinned."""

    @unittest.skipUnless(shutil.which('gpg'), 'gpg is required')
    def test_committed_values_pass_every_rule(self):
        values = trust.check_committed(REPO)
        self.assertEqual(values['version'], '0.1.0')
        self.assertEqual(values['base_url'], 'https://archledger.github.io/intel-npu-stack/0.1.0/')
        self.assertEqual(values['primary_fingerprint'], '1085FBE578732D1CF0C50417A8FE2F718B8763D8')
        self.assertEqual(values['metadata_sha256'], ZEROS)

    def test_parse_reads_the_five_items(self):
        values = trust.parse_trust(TRUST.read_text())
        self.assertEqual(set(values), {'version', 'base_url', 'metadata_sha256', 'primary_fingerprint',
                                       'keyring'})
        self.assertEqual(values['keyring'], 'trust/release-public.asc')

    def test_parse_refuses_duplicates_and_missing_items(self):
        text = TRUST.read_text()
        with self.assertRaisesRegex(trust.TrustRefused, 'VERSION'):
            trust.parse_trust(text + '\npub(crate) const VERSION: &str = "0.1.0";\n')
        with self.assertRaisesRegex(trust.TrustRefused, 'PRIMARY_FINGERPRINT'):
            trust.parse_trust(text.replace('PRIMARY_FINGERPRINT', 'OTHER_FINGERPRINT'))

    def test_read_cli_prints_one_field(self):
        if not shutil.which('gpg'):
            self.skipTest('gpg is required')
        result = subprocess.run(['python3', str(Path(trust.__file__)), 'read', '--repo', str(REPO),
                                 '--field', 'base-url'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'https://archledger.github.io/intel-npu-stack/0.1.0/\n')


class KeyInspection(unittest.TestCase):
    LISTING = ('pub:-:255:22:A8FE2F718B8763D8:1789084800:1852156800::-:::scSC::::::23::0:\n'
               'fpr:::::::::1085FBE578732D1CF0C50417A8FE2F718B8763D8:\n')

    def test_a_failed_gpg_inspection_is_refused_even_with_a_fingerprint(self):
        failed = subprocess.CompletedProcess([], 2, self.LISTING, 'gpg: read_block: read error: Invalid packet\n')
        with mock.patch.object(trust.subprocess, 'run', return_value=failed), \
                self.assertRaisesRegex(trust.TrustRefused, 'could not inspect'):
            trust.pinned_fingerprint(TRUST)
        passed = subprocess.CompletedProcess([], 0, self.LISTING, '')
        with mock.patch.object(trust.subprocess, 'run', return_value=passed):
            self.assertEqual(trust.pinned_fingerprint(TRUST), '1085FBE578732D1CF0C50417A8FE2F718B8763D8')


class MetadataPin(unittest.TestCase):
    def test_pin_changes_exactly_one_line(self):
        original = TRUST.read_text()
        pinned = trust.pin_metadata(original, DIGEST)
        before, after = original.splitlines(), pinned.splitlines()
        self.assertEqual(len(before), len(after))
        changed = [i for i, (a, b) in enumerate(zip(before, after)) if a != b]
        self.assertEqual(len(changed), 1)
        self.assertIn(DIGEST, after[changed[0]])
        values = trust.parse_trust(pinned)
        self.assertEqual(values['metadata_sha256'], DIGEST)
        self.assertEqual({k: v for k, v in values.items() if k != 'metadata_sha256'},
                         {k: v for k, v in trust.parse_trust(original).items() if k != 'metadata_sha256'})

    def test_pin_refuses_an_already_pinned_or_ambiguous_source(self):
        pinned = trust.pin_metadata(TRUST.read_text(), DIGEST)
        with self.assertRaisesRegex(trust.TrustRefused, 'metadata'):
            trust.pin_metadata(pinned, 'cd' * 32)
        doubled = TRUST.read_text() + '\n// "' + ZEROS + '"\n'
        with self.assertRaisesRegex(trust.TrustRefused, 'exactly one'):
            trust.pin_metadata(doubled, DIGEST)

    def test_pin_refuses_a_malformed_digest(self):
        for bad in ['AB' * 32, 'ab' * 31, ZEROS]:
            with self.subTest(bad), self.assertRaises(trust.TrustRefused):
                trust.pin_metadata(TRUST.read_text(), bad)


@unittest.skipUnless(shutil.which('gpg'), 'gpg is required')
class CommittedRules(unittest.TestCase):
    """check_committed refuses each broken rule in a scratch copy of the repository files."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        for relative in ['Cargo.toml', 'crates/stack-install/src/trust.rs',
                         'crates/stack-install/src/trust/release-public.asc',
                         'packaging/fedora/44/repository/assemble.py']:
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / relative, target)
        self.trust = self.repo / 'crates/stack-install/src/trust.rs'

    def edit(self, old, new):
        text = self.trust.read_text()
        self.assertIn(old, text)
        self.trust.write_text(text.replace(old, new))

    def test_scratch_copy_passes(self):
        trust.check_committed(self.repo)

    def test_pinned_metadata_is_refused_in_source(self):
        self.trust.write_text(trust.pin_metadata(self.trust.read_text(), DIGEST))
        with self.assertRaisesRegex(trust.TrustRefused, 'metadata'):
            trust.check_committed(self.repo)

    def test_base_url_without_the_version_segment_is_refused(self):
        self.edit('intel-npu-stack/0.1.0/', 'intel-npu-stack/latest/')
        with self.assertRaisesRegex(trust.TrustRefused, 'BASE_URL'):
            trust.check_committed(self.repo)

    def test_fingerprint_must_match_the_committed_key(self):
        self.edit('1085FBE578732D1CF0C50417A8FE2F718B8763D8', '0000000000000000000000000000000000000000')
        with self.assertRaisesRegex(trust.TrustRefused, 'PRIMARY_FINGERPRINT'):
            trust.check_committed(self.repo)

    def test_version_must_match_the_workspace(self):
        cargo = self.repo / 'Cargo.toml'
        cargo.write_text(cargo.read_text().replace('version = "0.1.0"', 'version = "0.2.0"', 1))
        with self.assertRaisesRegex(trust.TrustRefused, 'VERSION'):
            trust.check_committed(self.repo)


if __name__ == '__main__':
    unittest.main()
