# SPDX-License-Identifier: Apache-2.0
"""Contract for the issue-only Fedora kernel watcher."""
import contextlib
import hashlib
import json
from pathlib import Path
import tempfile
import tomllib
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

[components.npu_firmware]
version = "1.38.0"

[components.npu_firmware.provider]
package = "intel-npu-stack-firmware"
version = "0:1.38.0-1.intelnpu.fc44"
activation = "reboot"

[qualification]
evidence_id = "fixture"
evidence_sha256 = "{EVIDENCE}"
'''
COMPONENTS = hashlib.sha256(json.dumps(tomllib.loads(QUALIFIED)['components'], sort_keys=True,
                                       separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def probe(kernel, result='pass', source='probe', evidence='b' * 64, recorded='2026-09-24', profile=PROFILE,
          components=COMPONENTS):
    return {'kernel': kernel, 'profile': profile, 'components_sha256': components, 'result': result,
            'source': source, 'evidence_sha256': evidence, 'recorded': recorded}


def qualification(kernel, profile=PROFILE, evidence=EVIDENCE, components=COMPONENTS):
    return probe(kernel, source='qualification', evidence=evidence, profile=profile, components=components)


def actions(finding):
    return [(action['profile'], action['window'], action['action']) for action in finding['actions']]


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
            report = watcher.build_report(fetch, Path(tmp), REPO_ROOT / 'release/kernel-probes.json', {})
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

    def findings(self, probes):
        outcomes, _ = self.load(probes)
        return {finding['kernel']: finding for finding in watcher.scan(self.kernels, self.windows, outcomes, {})}

    def add_profile(self, name, evidence, window=('7.2.5', '7.3.0')):
        text = QUALIFIED.replace(PROFILE, name).replace(EVIDENCE, evidence)
        text = text.replace('min = "7.2.5"', f'min = "{window[0]}"').replace('max_exclusive = "7.3.0"',
                                                                         f'max_exclusive = "{window[1]}"')
        (self.profiles / 'fedora/44' / (str(len(self.windows)) + '.toml')).write_text(text)
        self.windows = watcher.qualified_windows(self.profiles)

    def test_only_qualified_fedora_44_profiles_define_the_window(self):
        self.assertEqual(self.windows, [{'id': PROFILE, 'min': '7.2.5', 'max_exclusive': '7.3.0',
                                         'evidence_sha256': EVIDENCE, 'components_sha256': COMPONENTS}])

    def test_components_digest_is_the_canonical_component_set(self):
        document = tomllib.loads(QUALIFIED)
        self.assertEqual(watcher.components_digest(document), COMPONENTS)
        reordered = QUALIFIED.replace('package = "intel-npu-stack-firmware"\n', '').replace(
            'activation = "reboot"', 'activation = "reboot"\npackage = "intel-npu-stack-firmware"')
        self.assertEqual(watcher.components_digest(tomllib.loads(reordered)), COMPONENTS)
        changed = QUALIFIED.replace('0:1.38.0-1.intelnpu.fc44', '0:1.38.0-2.intelnpu.fc44')
        self.assertNotEqual(watcher.components_digest(tomllib.loads(changed)), COMPONENTS)
        with self.assertRaisesRegex(ValueError, 'component'):
            watcher.components_digest({'components': {}})

    def test_profile_ids_must_be_unique(self):
        (self.profiles / 'fedora/44/copy.toml').write_text(QUALIFIED)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            watcher.qualified_windows(self.profiles)

    def test_profile_ids_follow_the_schema_text_rules(self):
        unusual = 'Fedora 44 Lunar Lake (x86_64) \u00e9 ' + 'x' * 200
        self.add_profile(unusual, 'f' * 64)
        self.assertIn(unusual, [window['id'] for window in self.windows])
        outcomes, _ = self.load([qualification('7.2.5-200.fc44', profile=unusual, evidence='f' * 64)])
        self.assertEqual(outcomes, {(unusual, '7.2.5-200.fc44'): 'pass'})
        for bad in ['', ' leading', 'trailing ', 'bell\x07', 'x' * 4097]:
            with self.subTest(bad):
                self.assertFalse(watcher.valid_profile_id(bad))
        (self.profiles / 'fedora/44/bad.toml').write_text(QUALIFIED.replace(PROFILE, 'bad\\u0007id'))
        with self.assertRaisesRegex(ValueError, 'invalid id'):
            watcher.qualified_windows(self.profiles)

    def test_probe_and_requalification_findings(self):
        findings = self.findings([qualification('7.2.5-200.fc44'), qualification('7.2.6-200.fc44')])
        self.assertEqual(set(findings), {'7.2.5-100.fc44', '7.2.7-200.fc44', '7.3.0-200.fc44'})
        self.assertEqual(findings['7.2.7-200.fc44']['observation'], 'probe-required')
        self.assertEqual(actions(findings['7.2.7-200.fc44']), [(PROFILE, '[7.2.5, 7.3.0)', 'probe-required')])
        self.assertEqual(findings['7.3.0-200.fc44']['observation'], 'requalification-required')
        self.assertEqual(findings['7.2.7-200.fc44']['dedup_key'], 'kernel:fedora-44:7.2.7-200.fc44')

    def test_evidence_is_kept_per_profile(self):
        other = 'fedora-44-other-x86_64'
        self.add_profile(other, 'f' * 64)
        findings = self.findings([qualification('7.2.5-200.fc44'), qualification('7.2.6-200.fc44'),
                                  qualification('7.2.5-200.fc44', profile=other, evidence='f' * 64),
                                  qualification('7.2.6-200.fc44', profile=other, evidence='f' * 64),
                                  probe('7.2.7-200.fc44')])
        self.assertEqual(actions(findings['7.2.7-200.fc44']), [(other, '[7.2.5, 7.3.0)', 'probe-required')])

    def test_requalification_is_tracked_per_profile(self):
        later = 'fedora-44-next-x86_64'
        self.add_profile(later, 'f' * 64, ('7.3.0', '7.4.0'))
        findings = self.findings([qualification('7.2.5-200.fc44'), qualification('7.2.6-200.fc44'),
                                  probe('7.2.7-200.fc44')])
        self.assertEqual(findings['7.3.0-200.fc44']['observation'], 'probe-required, requalification-required')
        self.assertEqual(actions(findings['7.3.0-200.fc44']),
                         [(PROFILE, '[7.2.5, 7.3.0)', 'requalification-required'),
                          (later, '[7.3.0, 7.4.0)', 'probe-required')])
        # A kernel below a profile's window is no action for that profile.
        self.assertNotIn('7.2.7-200.fc44', findings)

    def test_failed_probes_are_reported_as_failed(self):
        findings = self.findings([qualification('7.2.5-200.fc44'), qualification('7.2.6-200.fc44'),
                                  probe('7.2.7-200.fc44', result='fail')])
        self.assertEqual(findings['7.2.7-200.fc44']['observation'], 'probe-failed')

    def test_records_bind_to_the_current_component_set_and_evidence(self):
        stale = [probe('7.2.7-200.fc44', components='c' * 64),
                 qualification('7.2.5-200.fc44', evidence='b' * 64),
                 qualification('7.2.6-200.fc44', components='c' * 64)]
        outcomes, stale_records = self.load(stale)
        self.assertEqual(outcomes, {})
        self.assertEqual([(r['kernel'], r['reason']) for r in stale_records],
                         [('7.2.7-200.fc44', 'component set changed'),
                          ('7.2.5-200.fc44', 'qualification evidence changed'),
                          ('7.2.6-200.fc44', 'component set changed')])
        findings = self.findings(stale)
        self.assertEqual({k for k, f in findings.items() if f['observation'] == 'probe-required'},
                         {'7.2.5-100.fc44', '7.2.5-200.fc44', '7.2.6-200.fc44', '7.2.7-200.fc44'})

    def test_records_for_profiles_that_are_not_qualified_keep_only_their_shape(self):
        # A superseded or retired profile's history stays valid and inert.
        self.assertEqual(self.load([qualification('7.2.5-200.fc44', profile='fedora-44-retired'),
                                    probe('7.1.13-200.fc44', profile='fedora-44-retired')]), ({}, []))

    def test_without_recorded_evidence_kernels_every_window_kernel_needs_a_probe(self):
        findings = self.findings([])
        self.assertEqual({k for k, f in findings.items() if f['observation'] == 'probe-required'},
                         {'7.2.5-100.fc44', '7.2.5-200.fc44', '7.2.6-200.fc44', '7.2.7-200.fc44'})

    def test_open_issues_are_kept_and_refreshed_not_duplicated(self):
        issues = watcher.open_issues([{'number': 41, 'title': '[kernel-watch] kernel:fedora-44:7.2.7-200.fc44'},
                                      {'number': 12, 'title': '[kernel-watch] kernel:fedora-44:7.2.7-200.fc44'},
                                      {'number': 13, 'title': 'unrelated kernel:fedora-44:'},
                                      {'number': 'x', 'title': '[kernel-watch] kernel:fedora-44:7.2.6-200.fc44'},
                                      {'title': None}])
        self.assertEqual(issues, {'kernel:fedora-44:7.2.7-200.fc44': 12})
        outcomes, _ = self.load([qualification('7.2.5-200.fc44'), qualification('7.2.6-200.fc44'),
                                 probe('7.2.7-200.fc44', result='fail')])
        findings = {f['kernel']: f for f in watcher.scan(self.kernels, self.windows, outcomes, issues)}
        # The issue opened as probe-required is refreshed with the failed probe, not left stale or duplicated.
        self.assertEqual((findings['7.2.7-200.fc44']['issue'], findings['7.2.7-200.fc44']['observation']),
                         (12, 'probe-failed'))
        self.assertIsNone(findings['7.3.0-200.fc44']['issue'])

    def test_no_qualified_profile_means_nothing_to_watch(self):
        (self.profiles / 'fedora/44/qualified.toml').unlink()
        self.assertEqual(watcher.qualified_windows(self.profiles), [])
        self.assertEqual(watcher.scan(self.kernels, [], {}, {}), [])

    def test_qualified_profile_without_evidence_or_components_is_refused(self):
        (self.profiles / 'fedora/44/qualified.toml').write_text(QUALIFIED.replace(EVIDENCE, 'not-a-digest'))
        with self.assertRaisesRegex(ValueError, 'evidence'):
            watcher.qualified_windows(self.profiles)
        text = QUALIFIED.split('[components.npu_firmware]')[0] + '[qualification]' + QUALIFIED.split('[qualification]')[1]
        (self.profiles / 'fedora/44/qualified.toml').write_text(text)
        with self.assertRaisesRegex(ValueError, 'component'):
            watcher.qualified_windows(self.profiles)

    def test_malformed_probe_records_are_refused(self):
        def without(field):
            return {key: value for key, value in probe('7.2.7-200.fc44').items() if key != field}
        cases = {
            'schema': None,
            'missing evidence': without('evidence_sha256'),
            'uppercase evidence': probe('7.2.7-200.fc44', evidence='B' * 64),
            'short evidence': probe('7.2.7-200.fc44', evidence='b' * 63),
            'missing components': without('components_sha256'),
            'bad components': probe('7.2.7-200.fc44', components='Z' * 64),
            'missing date': without('recorded'),
            'bad date': probe('7.2.7-200.fc44', recorded='2026-02-30'),
            'unknown result': probe('7.2.7-200.fc44', result='skipped'),
            'unknown source': probe('7.2.7-200.fc44', source='guess'),
            'extra field': {**probe('7.2.7-200.fc44'), 'note': 'x'},
            'bad kernel': probe('7.2.7-200.fc43'),
            'bad profile': probe('7.2.7-200.fc44', profile=' fedora-44'),
            'missing profile': without('profile'),
            'duplicate record': [probe('7.2.7-200.fc44'), probe('7.2.7-200.fc44', result='fail')],
            'failed qualification': probe('7.2.6-200.fc44', result='fail', source='qualification', evidence=EVIDENCE),
        }
        for label, record in cases.items():
            with self.subTest(label), self.assertRaises(ValueError):
                if record is None:
                    self.registry.write_text(json.dumps({'schema_version': 2, 'probes': []}))
                    watcher.load_probes(self.registry, self.windows)
                else:
                    self.load(record if isinstance(record, list) else [record])
        # The same kernel and profile may be probed again on a changed component set.
        outcomes, stale = self.load([probe('7.2.7-200.fc44', components='c' * 64, result='fail'),
                                     probe('7.2.7-200.fc44')])
        self.assertEqual((outcomes, len(stale)), ({(PROFILE, '7.2.7-200.fc44'): 'pass'}, 1))

    def test_requalification_keeps_the_previous_evidence_record(self):
        outcomes, stale = self.load([qualification('7.2.5-200.fc44', evidence='a' * 64),
                                     qualification('7.2.5-200.fc44')])
        self.assertEqual(outcomes, {(PROFILE, '7.2.5-200.fc44'): 'pass'})
        self.assertEqual([(r['kernel'], r['reason']) for r in stale],
                         [('7.2.5-200.fc44', 'qualification evidence changed')])

    def test_conflicting_records_for_the_current_stack_are_refused(self):
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            self.load([probe('7.2.7-200.fc44', evidence='a' * 64, result='fail'), probe('7.2.7-200.fc44')])
        outcomes, _ = self.load([probe('7.2.7-200.fc44', evidence='a' * 64), probe('7.2.7-200.fc44')])
        self.assertEqual(outcomes, {(PROFILE, '7.2.7-200.fc44'): 'pass'})


class Report(unittest.TestCase):
    def test_failed_query_is_reported_not_swallowed(self):
        def failing(url, timeout):
            raise OSError('network down')
        report = watcher.build_report(failing, REPO_ROOT / 'profiles', REPO_ROOT / 'release/kernel-probes.json', {})
        self.assertEqual(report['findings'], [{'observation': 'check-failed',
                                               'note': 'Bodhi query failed; scheduled runs are advisory'}])

    def test_committed_registry_and_profiles_load(self):
        windows = watcher.qualified_windows(REPO_ROOT / 'profiles')
        outcomes, stale = watcher.load_probes(REPO_ROOT / 'release/kernel-probes.json', windows)
        self.assertEqual((type(outcomes), type(stale)), (dict, list))
        report = watcher.build_report(lambda url, timeout: BODHI, REPO_ROOT / 'profiles',
                                      REPO_ROOT / 'release/kernel-probes.json', {})
        self.assertEqual(report['schema_version'], 1)
        self.assertEqual(report['observed_kernels'][0]['kernel'], '7.3.0-200.fc44')
        self.assertEqual(report['stale_records'], [])

    def test_components_digest_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / 'profile.toml'
            profile.write_text(QUALIFIED)
            output = Path(tmp) / 'digest.txt'
            with open(output, 'w') as stream, contextlib.redirect_stdout(stream):
                self.assertEqual(watcher.main(['--components-digest', str(profile)]), 0)
            self.assertEqual(output.read_text(), COMPONENTS + '\n')


if __name__ == '__main__':
    unittest.main()
