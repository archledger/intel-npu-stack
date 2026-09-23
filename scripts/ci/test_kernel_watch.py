# SPDX-License-Identifier: Apache-2.0
"""Contract for the issue-only Fedora kernel watcher."""
import json
from pathlib import Path
import tempfile
import unittest

import check_kernels as watcher

REPO_ROOT = Path(__file__).resolve().parents[2]


def update(nvrs, status='stable', alias='FEDORA-2026-0000000000', release='F44', date='2026-09-23 01:08:39'):
    return {'alias': alias, 'status': status, 'date_stable': date if status == 'stable' else None,
            'date_submitted': date, 'release': {'name': release}, 'builds': [{'nvr': nvr} for nvr in nvrs]}


BODHI = {'updates': [
    update(['kernel-7.2.7-200.fc44'], alias='FEDORA-2026-ca91e91bf0'),
    update(['kernel-7.2.6-200.fc44'], alias='FEDORA-2026-1649616d86'),
    update(['kernel-7.3.0-200.fc44'], status='testing', alias='FEDORA-2026-aaaaaaaaaa'),
    update(['kernel-7.2.4-200.fc44', 'kernel-headers-7.2.4-200.fc44'], alias='FEDORA-2026-d567c45298'),
    update(['kernel-7.2.8-200.fc44'], status='obsolete'),
    update(['kernel-7.2.9-200.fc43'], release='F43'),
    update(['kernel-$(id)-200.fc44']),
    {'status': 'stable', 'builds': 'not-a-list'},
]}

QUALIFIED = '''schema_version = 1
id = "fedora-44-lunar-lake-x86_64"
status = "qualified"

[platform]
id = "fedora"
version_id = "44"

[kernel]
min = "7.2.5"
max_exclusive = "7.3.0"
module = "intel_vpu"
'''


class Parsing(unittest.TestCase):
    def test_only_fedora_44_kernel_packages_parse(self):
        self.assertEqual(watcher.parse_kernel_nvr('kernel-7.2.7-200.fc44'), ((7, 2, 7), '7.2.7-200.fc44'))
        for nvr in ['kernel-headers-7.2.4-200.fc44', 'kernel-7.2.7-200.fc43', 'kernel-7.2-200.fc44',
                    'kernel-$(id)-200.fc44', 'kernel-7.2.7-200.fc44 ', 'x' * 300, None, 42]:
            with self.subTest(nvr):
                self.assertIsNone(watcher.parse_kernel_nvr(nvr))

    def test_bodhi_observations_keep_stable_and_testing_only(self):
        observed = watcher.kernels_from_bodhi(BODHI)
        self.assertEqual([item['kernel'] for item in observed],
                         ['7.3.0-200.fc44', '7.2.7-200.fc44', '7.2.6-200.fc44', '7.2.4-200.fc44'])
        self.assertEqual(observed[0]['status'], 'testing')
        self.assertEqual(observed[1]['update'], 'FEDORA-2026-ca91e91bf0')

    def test_malformed_bodhi_document_yields_no_kernels(self):
        for document in [{}, {'updates': 'x'}, [], {'updates': [None, 1, 'x']}]:
            with self.subTest(document):
                self.assertEqual(watcher.kernels_from_bodhi(document), [])


class Policy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.profiles = Path(self.tmp.name) / 'profiles'
        (self.profiles / 'fedora/44').mkdir(parents=True)
        (self.profiles / 'fedora/44/qualified.toml').write_text(QUALIFIED)
        (self.profiles / 'fedora/44/candidate.toml').write_text(
            QUALIFIED.replace('qualified', 'candidate').replace('7.3.0', '7.2.6'))
        self.kernels = watcher.kernels_from_bodhi(BODHI)

    def test_only_qualified_fedora_44_profiles_define_the_window(self):
        windows = watcher.qualified_windows(self.profiles)
        self.assertEqual(windows, [{'id': 'fedora-44-lunar-lake-x86_64', 'min': '7.2.5', 'max_exclusive': '7.3.0'}])

    def test_probe_and_requalification_findings(self):
        findings = watcher.scan(self.kernels, watcher.qualified_windows(self.profiles), {'7.2.6-200.fc44'}, set())
        by_kernel = {finding['kernel']: finding for finding in findings}
        self.assertEqual(by_kernel['7.2.7-200.fc44']['observation'], 'probe-required')
        self.assertEqual(by_kernel['7.3.0-200.fc44']['observation'], 'requalification-required')
        self.assertNotIn('7.2.6-200.fc44', by_kernel)  # probed
        self.assertNotIn('7.2.4-200.fc44', by_kernel)  # below every window
        self.assertEqual(by_kernel['7.2.7-200.fc44']['dedup_key'], 'kernel:fedora-44:7.2.7-200.fc44')

    def test_open_issues_deduplicate(self):
        keys = watcher.existing_keys([{'title': '[kernel-watch] kernel:fedora-44:7.2.7-200.fc44'},
                                      {'title': 'unrelated kernel:fedora-44:'}, {'title': None}])
        self.assertEqual(keys, {'kernel:fedora-44:7.2.7-200.fc44'})
        findings = watcher.scan(self.kernels, watcher.qualified_windows(self.profiles), {'7.2.6-200.fc44'}, keys)
        self.assertNotIn('7.2.7-200.fc44', {finding['kernel'] for finding in findings})

    def test_no_qualified_profile_means_nothing_to_watch(self):
        (self.profiles / 'fedora/44/qualified.toml').unlink()
        self.assertEqual(watcher.qualified_windows(self.profiles), [])
        self.assertEqual(watcher.scan(self.kernels, [], set(), set()), [])

    def test_probe_registry_counts_only_passing_probes(self):
        registry = Path(self.tmp.name) / 'kernel-probes.json'
        registry.write_text(json.dumps({'schema_version': 1, 'probes': [
            {'kernel': '7.2.6-200.fc44', 'result': 'pass', 'evidence_sha256': 'a' * 64},
            {'kernel': '7.2.7-200.fc44', 'result': 'fail', 'evidence_sha256': 'b' * 64}]}))
        self.assertEqual(watcher.load_probes(registry), {'7.2.6-200.fc44'})
        registry.write_text(json.dumps({'schema_version': 2, 'probes': []}))
        with self.assertRaises(ValueError):
            watcher.load_probes(registry)


class Report(unittest.TestCase):
    def test_failed_query_is_reported_not_swallowed(self):
        def failing(url, timeout):
            raise OSError('network down')
        report = watcher.build_report(failing, REPO_ROOT / 'profiles', REPO_ROOT / 'release/kernel-probes.json', set())
        self.assertEqual(report['findings'], [{'observation': 'check-failed',
                                               'note': 'Bodhi query failed; scheduled runs are advisory'}])

    def test_committed_registry_and_profiles_load(self):
        self.assertIsInstance(watcher.load_probes(REPO_ROOT / 'release/kernel-probes.json'), set)
        report = watcher.build_report(lambda url, timeout: BODHI, REPO_ROOT / 'profiles',
                                      REPO_ROOT / 'release/kernel-probes.json', set())
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['observed_kernels'][0]['kernel'], '7.3.0-200.fc44')


if __name__ == '__main__':
    unittest.main()
