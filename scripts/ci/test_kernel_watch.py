# SPDX-License-Identifier: Apache-2.0
"""Contract for the issue-only Fedora kernel watcher."""
import json
from pathlib import Path
import tempfile
import unittest
import urllib.parse

import check_kernels as watcher

REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = 'e' * 64
PROFILE = 'fedora-44-lunar-lake-x86_64'


def update(nvrs, status='stable', alias='FEDORA-2026-0000000000', release='F44', date='2026-09-23 01:08:39',
           reached_testing=True):
    return {'alias': alias, 'status': status, 'date_stable': date if status == 'stable' else None,
            'date_testing': date if reached_testing else None, 'date_submitted': date,
            'release': {'name': release}, 'builds': [{'nvr': nvr} for nvr in nvrs]}


UPDATES = [
    update(['kernel-7.2.7-200.fc44'], alias='FEDORA-2026-ca91e91bf0'),
    update(['kernel-7.2.6-200.fc44'], alias='FEDORA-2026-1649616d86'),
    update(['kernel-7.3.0-200.fc44'], status='testing', alias='FEDORA-2026-aaaaaaaaaa'),
    update(['kernel-7.2.5-200.fc44'], alias='FEDORA-2026-9ce2715225'),
    update(['kernel-7.2.4-200.fc44', 'kernel-headers-7.2.4-200.fc44'], alias='FEDORA-2026-d567c45298'),
    update(['kernel-7.2.8-200.fc44'], status='obsolete', reached_testing=False),
    update(['kernel-7.2.5-100.fc44'], status='obsolete', alias='FEDORA-2026-bbbbbbbbbb'),
    update(['kernel-7.2.9-200.fc43'], release='F43'),
    update(['kernel-$(id)-200.fc44']),
    {'status': 'stable', 'builds': 'not-a-list'},
]
BODHI = {'updates': UPDATES, 'page': 1, 'pages': 1}

QUALIFIED = f'''schema_version = 1
id = "fedora-44-lunar-lake-x86_64"
status = "qualified"

[platform]
id = "fedora"
version_id = "44"

[kernel]
min = "7.2.5"
max_exclusive = "7.3.0"
module = "intel_vpu"

[qualification]
evidence_id = "fixture"
evidence_sha256 = "{EVIDENCE}"
'''


def probe(kernel, result='pass', source='probe', evidence='b' * 64, recorded='2026-09-24', profile=PROFILE):
    return {'kernel': kernel, 'profile': profile, 'result': result, 'source': source, 'evidence_sha256': evidence,
            'recorded': recorded}


def paged(pages):
    """A fetch function serving Bodhi-style pages keyed by the page query parameter."""
    requested = []

    def fetch(url, timeout):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        requested.append(query)
        return pages[int(query['page'][0]) - 1]
    return fetch, requested


class Parsing(unittest.TestCase):
    def test_only_fedora_44_kernel_packages_parse(self):
        self.assertEqual(watcher.parse_kernel_nvr('kernel-7.2.7-200.fc44'), ((7, 2, 7), '7.2.7-200.fc44'))
        self.assertEqual(watcher.parse_kernel_nvr('kernel-7.3.0-0.rc1.20.fc44'), ((7, 3, 0), '7.3.0-0.rc1.20.fc44'))
        for nvr in ['kernel-headers-7.2.4-200.fc44', 'kernel-7.2.7-200.fc43', 'kernel-7.2-200.fc44',
                    'kernel-7.3.0-0.rc1-x.fc44', 'kernel-7.3.0-0..1.fc44',
                    'kernel-$(id)-200.fc44', 'kernel-7.2.7-200.fc44 ', 'x' * 300, None, 42]:
            with self.subTest(nvr):
                self.assertIsNone(watcher.parse_kernel_nvr(nvr))

    def test_bodhi_observations_keep_builds_that_reached_a_repository(self):
        observed = watcher.kernels_from_bodhi(BODHI)
        self.assertEqual([item['kernel'] for item in observed],
                         ['7.3.0-200.fc44', '7.2.7-200.fc44', '7.2.6-200.fc44', '7.2.5-200.fc44', '7.2.5-100.fc44',
                          '7.2.4-200.fc44'])
        self.assertEqual(observed[0]['status'], 'testing')
        self.assertEqual(observed[1]['update'], 'FEDORA-2026-ca91e91bf0')
        # Superseded while in updates-testing: still installable, still observed; never pushed: ignored.
        self.assertEqual(observed[4]['status'], 'obsolete')

    def test_the_most_published_status_of_a_build_wins(self):
        document = {'updates': [update(['kernel-7.2.7-200.fc44'], status='obsolete'),
                                update(['kernel-7.2.7-200.fc44'], status='stable', alias='FEDORA-2026-ca91e91bf0'),
                                update(['kernel-7.2.7-200.fc44'], status='testing')]}
        self.assertEqual(watcher.kernels_from_bodhi(document)[0]['status'], 'stable')

    def test_profile_kernel_releases_follow_the_schema_parser(self):
        for value, version in [('7.2.5', (7, 2, 5)), ('7.3.0-foo-bar', (7, 3, 0)), ('7.2.5-200.fc44', (7, 2, 5)),
                               ('07.02.05', (7, 2, 5))]:
            self.assertEqual(watcher.parse_version(value), version)
        for value in ['', ' 7.2.5', '7.2.5 ', '7.2.5-', '7.2.5-a b', '7.2', '7.2.5.1', '7.x.5', '7.2.+5',
                      str(2 ** 64) + '.0.0', None, 7]:
            with self.subTest(value), self.assertRaises(ValueError):
                watcher.parse_version(value)

    def test_malformed_bodhi_document_yields_no_kernels(self):
        for document in [{}, {'updates': 'x'}, [], {'updates': [None, 1, 'x']}]:
            with self.subTest(document):
                self.assertEqual(watcher.kernels_from_bodhi(document), [])


class Pagination(unittest.TestCase):
    def test_every_page_is_fetched_with_the_status_filter(self):
        fetch, requested = paged([{'updates': UPDATES[:2], 'page': 1, 'pages': 3},
                                  {'updates': UPDATES[2:4], 'page': 2, 'pages': 3},
                                  {'updates': UPDATES[4:], 'page': 3, 'pages': 3}])
        document = watcher.fetch_updates(fetch)
        self.assertEqual([query['page'] for query in requested], [['1'], ['2'], ['3']])
        self.assertEqual(requested[0]['status'], ['stable', 'testing', 'obsolete'])
        self.assertEqual(requested[0]['releases'], ['F44'])
        self.assertEqual(watcher.kernels_from_bodhi(document), watcher.kernels_from_bodhi(BODHI))

    def test_no_matching_update_is_one_request(self):
        fetch, requested = paged([{'updates': [], 'page': 1, 'pages': 0}])
        self.assertEqual(watcher.fetch_updates(fetch), {'updates': []})
        self.assertEqual(len(requested), 1)

    def test_missing_or_excessive_page_counts_are_refused(self):
        for document in [{'updates': []}, {'updates': [], 'pages': '2'}, {'updates': [], 'pages': True},
                         {'updates': [], 'pages': watcher.MAX_PAGES + 1}, {'pages': 1}, []]:
            with self.subTest(document), self.assertRaises(ValueError):
                watcher.fetch_updates(lambda url, timeout: document)

    def test_a_failed_page_fails_the_whole_query(self):
        def fetch(url, timeout):
            if 'page=2' in url:
                raise OSError('network down')
            return {'updates': UPDATES, 'page': 1, 'pages': 2}
        with tempfile.TemporaryDirectory() as tmp:
            report = watcher.build_report(fetch, Path(tmp), REPO_ROOT / 'release/kernel-probes.json', set())
        self.assertEqual(report['findings'][0]['observation'], 'check-failed')
        self.assertEqual(report['observed_kernels'], [])


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
        self.windows = watcher.qualified_windows(self.profiles)
        self.registry = Path(self.tmp.name) / 'kernel-probes.json'

    def load(self, probes):
        self.registry.write_text(json.dumps({'schema_version': 1, 'probes': probes}))
        return watcher.load_probes(self.registry, self.windows)

    def add_profile(self, name, evidence):
        (self.profiles / 'fedora/44' / (name + '.toml')).write_text(
            QUALIFIED.replace(PROFILE, name).replace(EVIDENCE, evidence))
        self.windows = watcher.qualified_windows(self.profiles)

    def test_only_qualified_fedora_44_profiles_define_the_window(self):
        self.assertEqual(self.windows, [{'id': PROFILE, 'min': '7.2.5', 'max_exclusive': '7.3.0',
                                         'evidence_sha256': EVIDENCE}])

    def test_profile_ids_must_be_unique(self):
        (self.profiles / 'fedora/44/copy.toml').write_text(QUALIFIED)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            watcher.qualified_windows(self.profiles)

    def test_evidence_is_kept_per_profile(self):
        other = 'fedora-44-other-x86_64'
        self.add_profile(other, 'f' * 64)
        probed = self.load([probe('7.2.5-200.fc44', source='qualification', evidence=EVIDENCE),
                            probe('7.2.6-200.fc44', source='qualification', evidence=EVIDENCE),
                            probe('7.2.5-200.fc44', source='qualification', evidence='f' * 64, profile=other),
                            probe('7.2.6-200.fc44', source='qualification', evidence='f' * 64, profile=other),
                            probe('7.2.7-200.fc44')])
        findings = {f['kernel']: f for f in watcher.scan(self.kernels, self.windows, probed, set())}
        self.assertEqual(findings['7.2.7-200.fc44']['observation'], 'probe-required')
        self.assertEqual(findings['7.2.7-200.fc44']['windows'], [other + ' [7.2.5, 7.3.0)'])
        with self.assertRaisesRegex(ValueError, 'qualification record'):
            self.load([probe('7.2.5-200.fc44', source='qualification', evidence=EVIDENCE, profile=other)])

    def test_probe_and_requalification_findings(self):
        probed = self.load([probe('7.2.5-200.fc44', source='qualification', evidence=EVIDENCE),
                            probe('7.2.6-200.fc44', source='qualification', evidence=EVIDENCE)])
        findings = watcher.scan(self.kernels, self.windows, probed, set())
        by_kernel = {finding['kernel']: finding for finding in findings}
        self.assertEqual(set(by_kernel), {'7.2.5-100.fc44', '7.2.7-200.fc44', '7.3.0-200.fc44'})
        self.assertEqual(by_kernel['7.2.7-200.fc44']['observation'], 'probe-required')
        self.assertEqual(by_kernel['7.3.0-200.fc44']['observation'], 'requalification-required')
        self.assertEqual(by_kernel['7.2.7-200.fc44']['dedup_key'], 'kernel:fedora-44:7.2.7-200.fc44')

    def test_without_recorded_evidence_kernels_every_window_kernel_needs_a_probe(self):
        findings = watcher.scan(self.kernels, self.windows, self.load([]), set())
        self.assertEqual({finding['kernel'] for finding in findings if finding['observation'] == 'probe-required'},
                         {'7.2.5-100.fc44', '7.2.5-200.fc44', '7.2.6-200.fc44', '7.2.7-200.fc44'})

    def test_open_issues_deduplicate(self):
        keys = watcher.existing_keys([{'title': '[kernel-watch] kernel:fedora-44:7.2.7-200.fc44'},
                                      {'title': 'unrelated kernel:fedora-44:'}, {'title': None}])
        self.assertEqual(keys, {'kernel:fedora-44:7.2.7-200.fc44'})
        findings = watcher.scan(self.kernels, self.windows, set(), keys)
        self.assertNotIn('7.2.7-200.fc44', {finding['kernel'] for finding in findings})

    def test_no_qualified_profile_means_nothing_to_watch(self):
        (self.profiles / 'fedora/44/qualified.toml').unlink()
        self.assertEqual(watcher.qualified_windows(self.profiles), [])
        self.assertEqual(watcher.scan(self.kernels, [], set(), set()), [])

    def test_qualified_profile_without_evidence_digest_is_refused(self):
        (self.profiles / 'fedora/44/qualified.toml').write_text(QUALIFIED.replace(EVIDENCE, 'not-a-digest'))
        with self.assertRaisesRegex(ValueError, 'evidence'):
            watcher.qualified_windows(self.profiles)

    def test_only_passing_records_count(self):
        self.assertEqual(self.load([probe('7.2.6-200.fc44'), probe('7.2.7-200.fc44', result='fail'),
                                    probe('7.2.6-200.fc44', profile='fedora-44-other-x86_64')]),
                         {(PROFILE, '7.2.6-200.fc44'), ('fedora-44-other-x86_64', '7.2.6-200.fc44')})

    def test_malformed_probe_records_are_refused(self):
        cases = {
            'schema': None,
            'missing evidence': {key: value for key, value in probe('7.2.7-200.fc44').items()
                                 if key != 'evidence_sha256'},
            'uppercase evidence': probe('7.2.7-200.fc44', evidence='B' * 64),
            'short evidence': probe('7.2.7-200.fc44', evidence='b' * 63),
            'missing date': {key: value for key, value in probe('7.2.7-200.fc44').items() if key != 'recorded'},
            'bad date': probe('7.2.7-200.fc44', recorded='2026-02-30'),
            'unknown result': probe('7.2.7-200.fc44', result='skipped'),
            'unknown source': probe('7.2.7-200.fc44', source='guess'),
            'extra field': {**probe('7.2.7-200.fc44'), 'note': 'x'},
            'bad kernel': probe('7.2.7-200.fc43'),
            'bad profile': probe('7.2.7-200.fc44', profile='fedora 44'),
            'missing profile': {key: value for key, value in probe('7.2.7-200.fc44').items() if key != 'profile'},
            'duplicate kernel': [probe('7.2.7-200.fc44'), probe('7.2.7-200.fc44', result='fail')],
            'failed qualification': probe('7.2.6-200.fc44', result='fail', source='qualification', evidence=EVIDENCE),
            'foreign qualification evidence': probe('7.2.6-200.fc44', source='qualification'),
        }
        for label, record in cases.items():
            with self.subTest(label), self.assertRaises(ValueError):
                if record is None:
                    self.registry.write_text(json.dumps({'schema_version': 2, 'probes': []}))
                    watcher.load_probes(self.registry, self.windows)
                else:
                    self.load(record if isinstance(record, list) else [record])

    def test_qualification_records_outside_every_window_keep_only_their_shape(self):
        # A superseded series stays valid history once its profile is no longer qualified.
        self.assertEqual(self.load([probe('7.1.13-200.fc44', source='qualification')]), {(PROFILE, '7.1.13-200.fc44')})
        self.assertEqual(self.load([probe('7.2.5-200.fc44', source='qualification', profile='fedora-44-retired')]),
                         {('fedora-44-retired', '7.2.5-200.fc44')})


class Report(unittest.TestCase):
    def test_failed_query_is_reported_not_swallowed(self):
        def failing(url, timeout):
            raise OSError('network down')
        report = watcher.build_report(failing, REPO_ROOT / 'profiles', REPO_ROOT / 'release/kernel-probes.json', set())
        self.assertEqual(report['findings'], [{'observation': 'check-failed',
                                               'note': 'Bodhi query failed; scheduled runs are advisory'}])

    def test_committed_registry_and_profiles_load(self):
        windows = watcher.qualified_windows(REPO_ROOT / 'profiles')
        self.assertIsInstance(watcher.load_probes(REPO_ROOT / 'release/kernel-probes.json', windows), set)
        report = watcher.build_report(lambda url, timeout: BODHI, REPO_ROOT / 'profiles',
                                      REPO_ROOT / 'release/kernel-probes.json', set())
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['observed_kernels'][0]['kernel'], '7.3.0-200.fc44')


if __name__ == '__main__':
    unittest.main()
