# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import unittest
from unittest.mock import Mock

from check_upstream import (
    API_ROOT as API,
    WATCHED,
    compare_tags,
    dedup_key,
    existing_keys,
    fetch_latest,
    load_pinned,
    scan,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


class FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.requested = []

    def get(self, url, timeout):
        self.requested.append(url)
        for prefix, body in self.responses.items():
            if url.startswith(prefix):
                response = Mock()
                response.status = 200
                response.read_bytes.return_value = json.dumps(body).encode()
                if isinstance(body, list):
                    response.read_bytes.return_value = json.dumps(body).encode()
                return response
        raise AssertionError('unexpected URL ' + url)


class VersionComparison(unittest.TestCase):
    def test_semver_newer_older_and_equal(self):
        self.assertEqual(compare_tags('v1.35.0', 'v1.36.0'), 'newer')
        self.assertEqual(compare_tags('2026.2.0', '2026.2.0'), 'same')
        self.assertEqual(compare_tags('v1.28.6', 'v1.28.2'), 'older')

    def test_non_semver_tags_compare_by_difference(self):
        self.assertEqual(compare_tags('npu_ud_2026_28_rc1', 'npu_ud_2026_30_rc1'), 'different')
        self.assertEqual(compare_tags('npu_ud_2026_28_rc1', 'npu_ud_2026_28_rc1'), 'same')

    def test_mixed_shapes_do_not_crash(self):
        self.assertEqual(compare_tags('v1.0.0', 'not-a-version'), 'different')


class PinnedSources(unittest.TestCase):
    def test_real_manifest_pins_every_watched_component(self):
        pinned = load_pinned(REPO_ROOT / 'packaging/fedora/44/provider-sources.toml')
        self.assertEqual(set(pinned), set(WATCHED))
        driver = pinned['linux-npu-driver']
        self.assertEqual(driver['tag'], 'v1.35.0')
        self.assertEqual(driver['commit'], 'fd49947db934dc67dda6f4287cec2664a303df27')
        self.assertEqual(pinned['openvino']['tag'], '2026.2.0')

    def test_missing_watched_source_is_refused(self):
        with self.assertRaises(ValueError):
            load_pinned(REPO_ROOT / 'scripts/ci/test_upstream_watch.py')


class FetchLatest(unittest.TestCase):
    def test_release_endpoint_is_preferred_and_resolves_commit(self):
        session = FakeSession({
            'https://api.github.com/repos/intel/linux-npu-driver/releases/latest':
                {'tag_name': 'v1.36.0', 'html_url': 'https://example.invalid/v1.36.0',
                 'target_commitish': 'main', 'draft': False, 'prerelease': False},
            'https://api.github.com/repos/intel/linux-npu-driver/git/ref/tags/v1.36.0':
                {'object': {'sha': 'abc123', 'type': 'commit'}},
        })
        release = fetch_latest(session, 'intel/linux-npu-driver')
        self.assertEqual(release['tag'], 'v1.36.0')
        self.assertEqual(release['commit'], 'abc123')
        self.assertEqual(release['source'], 'release')

    def test_annotated_release_tag_resolves_through_the_tag_object(self):
        session = FakeSession({
            'https://api.github.com/repos/x/y/releases/latest':
                {'tag_name': 'v2.0.0', 'html_url': 'u', 'target_commitish': 'main'},
            'https://api.github.com/repos/x/y/git/ref/tags/v2.0.0':
                {'object': {'sha': 'tagobj1', 'type': 'tag'}},
            'https://api.github.com/repos/x/y/git/tags/tagobj1':
                {'object': {'sha': 'commit99', 'type': 'commit'}},
        })
        release = fetch_latest(session, 'x/y')
        self.assertEqual(release['commit'], 'commit99')

    def test_unresolvable_release_tag_records_unknown_commit(self):
        session = FakeSession({
            'https://api.github.com/repos/x/y/releases/latest':
                {'tag_name': 'v2.0.0', 'html_url': 'u', 'target_commitish': 'main'},
            'https://api.github.com/repos/x/y/git/ref/tags/v2.0.0': {'message': 'Not Found'},
        })
        release = fetch_latest(session, 'x/y')
        self.assertEqual(release['commit'], '')

    def test_draft_or_prerelease_releases_are_ignored_via_tags(self):
        session = FakeSession({
            'https://api.github.com/repos/x/y/releases/latest': {'message': 'Not Found'},
            'https://api.github.com/repos/x/y/tags?per_page=10': [
                {'name': 'v2.0.0', 'object': {'sha': 'dead00', 'type': 'commit'}},
                {'name': 'v1.9.0', 'object': {'sha': 'beef00', 'type': 'commit'}},
            ],
        })
        release = fetch_latest(session, 'x/y')
        self.assertEqual(release['tag'], 'v2.0.0')
        self.assertEqual(release['commit'], 'dead00')
        self.assertEqual(release['source'], 'tags')

    def test_annotated_tags_resolve_to_their_commit(self):
        session = FakeSession({
            'https://api.github.com/repos/x/y/releases/latest': {'message': 'Not Found'},
            'https://api.github.com/repos/x/y/tags?per_page=10': [
                {'name': 'v3.0.0', 'object': {'sha': 'tagobj1', 'type': 'tag'}},
            ],
            'https://api.github.com/repos/x/y/git/tags/tagobj1':
                {'object': {'sha': 'commit99', 'type': 'commit'}},
        })
        release = fetch_latest(session, 'x/y')
        self.assertEqual(release['commit'], 'commit99')


class Findings(unittest.TestCase):
    def pinned(self):
        return load_pinned(REPO_ROOT / 'packaging/fedora/44/provider-sources.toml')

    def session_with(self, overrides):
        responses = {}
        for component in self.pinned().values():
            repository = component['repository']
            responses[f'{API}/repos/{repository}/releases/latest'] = {
                'tag_name': component['tag'], 'html_url': 'u',
                'target_commitish': 'main', 'draft': False, 'prerelease': False}
            responses[f'{API}/repos/{repository}/git/ref/tags/{component["tag"]}'] = {
                'object': {'sha': component['commit'], 'type': 'commit'}}
        responses.update(overrides)
        return FakeSession(responses)

    def test_newer_release_produces_update_available(self):
        session = self.session_with({
            'https://api.github.com/repos/intel/linux-npu-driver/releases/latest':
                {'tag_name': 'v1.36.0', 'html_url': 'u', 'target_commitish': 'main'},
            'https://api.github.com/repos/intel/linux-npu-driver/git/ref/tags/v1.36.0':
                {'object': {'sha': 'abc', 'type': 'commit'}},
        })
        findings = scan(session, self.pinned(), open_keys=set())
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['component'], 'linux-npu-driver')
        self.assertEqual(finding['observation'], 'update-available')
        self.assertIn('dedup_key', finding)

    def test_matching_release_is_silent(self):
        session = self.session_with({})
        self.assertEqual(scan(session, self.pinned(), open_keys=set()), [])

    def test_non_semver_difference_requires_manual_review(self):
        session = self.session_with({
            'https://api.github.com/repos/openvinotoolkit/npu_compiler/releases/latest':
                {'message': 'Not Found'},
            'https://api.github.com/repos/openvinotoolkit/npu_compiler/tags?per_page=10': [
                {'name': 'npu_ud_2026_30_rc1', 'object': {'sha': 'newcommit', 'type': 'commit'}},
            ],
        })
        findings = scan(session, self.pinned(), open_keys=set())
        self.assertEqual(findings[0]['observation'], 'update-available')
        self.assertIn('manual', findings[0]['note'])

    def test_existing_open_issue_suppresses_duplicate(self):
        key = dedup_key('intel/linux-npu-driver', 'v1.36.0')
        session = self.session_with({
            'https://api.github.com/repos/intel/linux-npu-driver/releases/latest':
                {'tag_name': 'v1.36.0', 'html_url': 'u', 'target_commitish': 'main'},
            'https://api.github.com/repos/intel/linux-npu-driver/git/ref/tags/v1.36.0':
                {'object': {'sha': 'abc', 'type': 'commit'}},
        })
        self.assertEqual(scan(session, self.pinned(), open_keys={key}), [])

    def test_failed_upstream_query_is_reported_not_swallowed(self):
        session = self.session_with({
            'https://api.github.com/repos/openvinotoolkit/openvino/releases/latest':
                {'message': 'Not Found'},
            'https://api.github.com/repos/openvinotoolkit/openvino/tags?per_page=10': [],
        })
        findings = scan(session, self.pinned(), open_keys=set())
        self.assertEqual(findings[0]['component'], 'openvino')
        self.assertEqual(findings[0]['observation'], 'check-failed')


class Deduplication(unittest.TestCase):
    def test_key_format_is_stable_and_titles_round_trip(self):
        key = dedup_key('intel/linux-npu-driver', 'v1.36.0')
        self.assertEqual(key, 'upstream:intel/linux-npu-driver:v1.36.0')

    def test_existing_keys_extract_from_open_issue_titles(self):
        issues = [
            {'title': '[upstream-update] upstream:intel/linux-npu-driver:v1.36.0', 'state': 'open'},
            {'title': 'unrelated work', 'state': 'open'},
        ]
        self.assertEqual(existing_keys(issues), {'upstream:intel/linux-npu-driver:v1.36.0'})


if __name__ == '__main__':
    unittest.main()
