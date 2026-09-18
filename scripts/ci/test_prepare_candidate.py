# SPDX-License-Identifier: Apache-2.0
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from prepare_candidate import (
    archive_url,
    apply_commit_pin,
    apply_pin,
    component_gitlinks,
    download_digest,
    finding_from_issue,
    load_lock_source,
    prepare_update,
    qualified_profiles,
    update_gitlink_stanza,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

ISSUE_BODY = """## Upstream release observation

- Component: linux-npu-driver
- Repository: intel/linux-npu-driver
- Pinned tag: v1.35.0
- Pinned commit: fd49947db934dc67dda6f4287cec2664a303df27
- Latest tag: v1.38.0
- Latest commit: aea583dcd86a4723a8d3bb06ad94b2f80c6f2
- Release: https://github.com/intel/linux-npu-driver/releases/tag/v1.38.0

Observation `update-available`: a newer official release exists but is not qualified."""


class FakeSession:
    def __init__(self, payload):
        self.payload = payload

    def get(self, url, timeout):
        response = Mock()
        response.read_bytes.return_value = self.payload
        return response


class IssueParsing(unittest.TestCase):
    def test_finding_round_trips_from_a_real_watcher_issue(self):
        finding = finding_from_issue(
            '[upstream-update] upstream:intel/linux-npu-driver:v1.38.0', ISSUE_BODY)
        self.assertEqual(finding['component'], 'linux-npu-driver')
        self.assertEqual(finding['repository'], 'intel/linux-npu-driver')
        self.assertEqual(finding['latest_tag'], 'v1.38.0')
        self.assertEqual(finding['latest_commit'], 'aea583dcd86a4723a8d3bb06ad94b2f80c6f2')
        self.assertEqual(finding['pinned_tag'], 'v1.35.0')

    def test_title_key_must_match_the_body(self):
        with self.assertRaises(ValueError):
            finding_from_issue(
                '[upstream-update] upstream:intel/linux-npu-driver:v9.9.9', ISSUE_BODY)

    def test_malformed_or_foreign_issues_are_refused(self):
        for title in ['[upstream-update] not-a-key', 'Regular issue', '']:
            with self.assertRaises(ValueError):
                finding_from_issue(title, ISSUE_BODY)
        with self.assertRaises(ValueError):
            finding_from_issue('[upstream-update] upstream:x/y:z', 'no fields here')


class QualifiedProfileGuard(unittest.TestCase):
    def test_real_profiles_directory_has_none_qualified(self):
        self.assertEqual(qualified_profiles(REPO_ROOT / 'profiles'), [])

    def test_qualified_profile_blocks_preparation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'a.toml').write_text('status = "candidate"\n')
            (root / 'b.toml').write_text('status = "qualified"\n')
            self.assertEqual([p.name for p in qualified_profiles(root)], ['b.toml'])


class LockEditing(unittest.TestCase):
    lock = REPO_ROOT / 'packaging/fedora/44/provider-sources.toml'

    def test_current_pins_load_for_every_watched_component(self):
        for component in ['linux-npu-driver', 'openvino', 'level-zero', 'npu-compiler']:
            source = load_lock_source(self.lock.read_text(), component)
            self.assertRegex(source['commit'], r'^[0-9a-f]{40}$')
            self.assertTrue(source['tag'])
        # The source's own commit is returned, never a gitlink commit; the
        # exact pin value is branch state, so only the shape is asserted here.
        driver = load_lock_source(self.lock.read_text(), 'linux-npu-driver')
        self.assertRegex(driver['tag'], r'^v\d+\.\d+\.\d+$')
        self.assertEqual(driver['kind'], 'git_tag')
        self.assertIsNone(driver['tag_object'])

    def test_pin_update_rewrites_only_the_intended_lines(self):
        import tomllib
        original = self.lock.read_text()
        updated, changed = apply_pin(
            original, 'linux-npu-driver', tag='v1.38.0',
            commit='aea583dcd86a4723a8d3bb06ad94b2f80c6f2',
            tag_object=None, archive_sha256='f' * 64)
        self.assertTrue(changed)
        before = tomllib.loads(original)
        after = tomllib.loads(updated)
        self.assertEqual(
            after['sources'][[s['name'] for s in after['sources']].index('linux-npu-driver')],
            {**before['sources'][[s['name'] for s in before['sources']].index('linux-npu-driver')],
             'tag': 'v1.38.0', 'commit': 'aea583dcd86a4723a8d3bb06ad94b2f80c6f2',
             'archive_sha256': 'f' * 64})
        # Every OTHER source record, including every gitlink, is byte-identical.
        def fingerprint(document):
            return [{k: v for k, v in source.items() if k != 'tag'}
                    for source in document['sources'] if source['name'] != 'linux-npu-driver']
        self.assertEqual(fingerprint(before), fingerprint(after))
        # And the edited file remains valid TOML with unchanged gitlinks.
        driver = next(s for s in after['sources'] if s['name'] == 'linux-npu-driver')
        self.assertTrue(driver['gitlinks'])
        self.assertIn('googletest', driver['gitlinks'][0]['path'])

    def test_annotated_tag_update_sets_kind_and_tag_object(self):
        original = self.lock.read_text()
        updated, _ = apply_pin(
            original, 'npu-compiler', tag='npu_ud_2026_30_rc1',
            commit='c0ffee', tag_object='7a7a7a', archive_sha256='e' * 64)
        source = load_lock_source(updated, 'npu-compiler')
        self.assertEqual(source['kind'], 'git_annotated_tag')
        self.assertEqual(source['tag_object'], '7a7a7a')
        self.assertEqual(source['commit'], 'c0ffee')

    def test_noop_when_commit_unchanged(self):
        original = self.lock.read_text()
        source = load_lock_source(original, 'openvino')
        updated, changed = apply_pin(
            original, 'openvino', tag=source['tag'], commit=source['commit'],
            tag_object=source.get('tag_object'),
            archive_sha256=source['archive_sha256'])
        self.assertFalse(changed)
        self.assertEqual(updated, original)

    def test_stale_digest_self_heals_at_the_same_tag_and_commit(self):
        import tomllib
        original = self.lock.read_text()
        source = load_lock_source(original, 'openvino')
        updated, changed = apply_pin(
            original, 'openvino', tag=source['tag'], commit=source['commit'],
            tag_object=source.get('tag_object'), archive_sha256='0' * 64)
        self.assertTrue(changed)
        after = tomllib.loads(updated)
        record = next(s for s in after['sources'] if s['name'] == 'openvino')
        self.assertEqual(record['archive_sha256'], '0' * 64)

    def test_unknown_component_is_refused(self):
        with self.assertRaises(ValueError):
            load_lock_source(self.lock.read_text(), 'does-not-exist')


class GitlinkHandling(unittest.TestCase):
    lock = REPO_ROOT / 'packaging/fedora/44/provider-sources.toml'

    def test_component_gitlinks_parse_from_the_owning_block(self):
        links = component_gitlinks(self.lock.read_text(), 'linux-npu-driver')
        by_path = {link['path']: link for link in links}
        self.assertEqual(by_path['third_party/npu_compiler_elf']['commit'],
                         'd325f45f2cb405b5fa2ff17a30de9469f1641b73')
        self.assertEqual(by_path['third_party/npu_compiler_elf']['disposition'], 'bundled')
        self.assertEqual(by_path['third_party/npu_compiler_elf']['source'], 'npu-compiler-elf-driver')
        self.assertEqual(by_path['third_party/googletest']['disposition'], 'system')
        # Gitlinks belonging to other components are not exposed.
        self.assertNotIn('third_party/npu_compiler_elf_openvino', by_path)

    def test_component_without_gitlinks_returns_empty(self):
        self.assertEqual(component_gitlinks(self.lock.read_text(), 'level-zero'), [])

    def test_gitlink_stanza_update_rewrites_only_that_commit(self):
        import tomllib
        original = self.lock.read_text()
        updated = update_gitlink_stanza(
            original, 'linux-npu-driver', 'third_party/npu_compiler_elf', 'a' * 40)
        before = tomllib.loads(original)
        after = tomllib.loads(updated)
        def gitlinks(document, name):
            return next(s for s in document['sources'] if s['name'] == name)['gitlinks']
        self.assertEqual(
            [g for g in gitlinks(after, 'linux-npu-driver')
             if g['path'] == 'third_party/npu_compiler_elf'][0]['commit'], 'a' * 40)
        others = [g for g in gitlinks(after, 'linux-npu-driver')
                  if g['path'] != 'third_party/npu_compiler_elf']
        self.assertEqual(
            [g for g in gitlinks(before, 'linux-npu-driver')
             if g['path'] != 'third_party/npu_compiler_elf'], others)

    def test_tagless_record_pin_updates_commit_and_digest_only(self):
        import tomllib
        original = self.lock.read_text()
        updated, changed = apply_commit_pin(
            original, 'npu-compiler-elf-driver', 'b' * 40, 'c' * 64)
        self.assertTrue(changed)
        after = tomllib.loads(updated)
        record = next(s for s in after['sources'] if s['name'] == 'npu-compiler-elf-driver')
        self.assertEqual(record['commit'], 'b' * 40)
        self.assertEqual(record['archive_sha256'], 'c' * 64)
        self.assertNotIn('tag', record)
        # The tag-bearing linux-npu-driver record is untouched.
        driver = next(s for s in after['sources'] if s['name'] == 'linux-npu-driver')
        self.assertEqual(driver['tag'], 'v1.38.0')

    def test_tagless_pin_refuses_a_tagged_record(self):
        with self.assertRaises(ValueError):
            apply_commit_pin(self.lock.read_text(), 'linux-npu-driver', 'b' * 40, 'c' * 64)

    def test_noop_tagless_pin_when_commit_unchanged(self):
        original = self.lock.read_text()
        updated, changed = apply_commit_pin(
            original, 'npu-compiler-elf-driver',
            'd325f45f2cb405b5fa2ff17a30de9469f1641b73', 'c' * 64)
        self.assertFalse(changed)
        self.assertEqual(updated, original)


class CanonicalPreparation(unittest.TestCase):
    """The runner-driven flow: xtask hashing plus git ls-tree for gitlinks."""

    lock = REPO_ROOT / 'packaging/fedora/44/provider-sources.toml'

    def test_prepare_updates_gitlinks_and_bundled_records(self):
        import tempfile, tomllib
        original = self.lock.read_text()
        ls_tree = {'third_party/npu_compiler_elf': 'e' * 40,
                   'third_party/level-zero-npu-extensions': 'f9ad3bf89c2418d714aef2e6b96a5aafb12a1971',
                   'third_party/googletest': 'b514bdc898e2951020cbdca1304b75f5950d1f59',
                   'third_party/yaml-cpp': 'f7320141120f720aecc4c32be25586e7da9eb978'}
        calls = []
        def fake_xtask(clone, name, commit, scratch):
            calls.append((name, commit))
            return 'd' * 64 if name == 'linux-npu-driver' else '9' * 64
        def fake_ls_tree(clone, commit, path):
            return ls_tree[path]
        def fake_clone(url, commit, scratch):
            calls.append(('clone', url, commit))
            return '/ignored'
        with tempfile.TemporaryDirectory() as scratch:
            updated = prepare_update(
                original, issue_finding(tag='v1.39.0', commit='5' * 40),
                source_clone='/clone', xtask='/xtask', scratch=scratch,
                _hash=fake_xtask, _ls_tree=fake_ls_tree, _clone=fake_clone)
        after = tomllib.loads(updated)
        driver = next(s for s in after['sources'] if s['name'] == 'linux-npu-driver')
        self.assertEqual(driver['tag'], 'v1.39.0')
        self.assertEqual(driver['commit'], '5' * 40)
        self.assertEqual(driver['archive_sha256'], 'd' * 64)
        elf = next(g for g in driver['gitlinks']
                   if g['path'] == 'third_party/npu_compiler_elf')
        self.assertEqual(elf['commit'], 'e' * 40)
        record = next(s for s in after['sources'] if s['name'] == 'npu-compiler-elf-driver')
        self.assertEqual(record['commit'], 'e' * 40)
        self.assertEqual(record['archive_sha256'], '9' * 64)
        # Unchanged bundled and system gitlinks required no hashing or cloning.
        self.assertEqual(calls.count(('clone', 'https://github.com/openvinotoolkit/npu_compiler_elf.git', 'e' * 40)), 1)
        self.assertNotIn(('clone', 'https://github.com/oneapi-src/level-zero-npu-extensions.git', 'f9ad3bf89c2418d714aef2e6b96a5aafb12a1971'), calls)

    def test_prepare_refuses_structural_gitlink_changes(self):
        def fake_ls_tree(clone, commit, path):
            return None  # path vanished from the new tree
        with tempfile_dir() as scratch:
            with self.assertRaisesRegex(ValueError, 'manual completion'):
                prepare_update(
                    self.lock.read_text(), issue_finding(tag='v1.39.0', commit='5' * 40),
                    source_clone='/clone', xtask='/xtask', scratch=scratch,
                    _hash=lambda *a: 'd' * 64, _ls_tree=fake_ls_tree,
                    _clone=lambda *a: '/ignored')

    def test_prepare_refuses_changed_system_gitlinks(self):
        ls_tree = {'third_party/googletest': 'f' * 40,
                   'third_party/level-zero-npu-extensions': 'f9ad3bf89c2418d714aef2e6b96a5aafb12a1971',
                   'third_party/npu_compiler_elf': 'd325f45f2cb405b5fa2ff17a30de9469f1641b73',
                   'third_party/yaml-cpp': 'f7320141120f720aecc4c32be25586e7da9eb978'}
        with tempfile_dir() as scratch:
            with self.assertRaisesRegex(ValueError, 'manual completion'):
                prepare_update(
                    self.lock.read_text(), issue_finding(tag='v1.39.0', commit='5' * 40),
                    source_clone='/clone', xtask='/xtask', scratch=scratch,
                    _hash=lambda *a: 'd' * 64,
                    _ls_tree=lambda clone, commit, path: ls_tree[path],
                    _clone=lambda *a: '/ignored')


def tempfile_dir():
    import tempfile
    return tempfile.TemporaryDirectory()


def issue_finding(tag, commit):
    return {'component': 'linux-npu-driver', 'repository': 'intel/linux-npu-driver',
            'pinned_tag': 'v1.38.0', 'pinned_commit': 'a' * 40,
            'latest_tag': tag, 'latest_commit': commit}


class ArchiveAcquisition(unittest.TestCase):
    def test_archive_url_is_the_immutable_commit_form(self):
        self.assertEqual(
            archive_url('https://github.com/intel/linux-npu-driver.git', 'abc123'),
            'https://codeload.github.com/intel/linux-npu-driver/tar.gz/abc123')
        self.assertEqual(
            archive_url('https://github.com/oneapi-src/level-zero', 'def456'),
            'https://codeload.github.com/oneapi-src/level-zero/tar.gz/def456')

    def test_download_digest_verifies_bytes(self):
        payload = b'archive bytes'
        session = FakeSession(payload)
        digest = download_digest(session, 'https://codeload.invalid/x', limit=len(payload))
        self.assertEqual(digest, hashlib.sha256(payload).hexdigest())

    def test_download_over_limit_is_refused(self):
        with self.assertRaises(ValueError):
            download_digest(FakeSession(b'too big'), 'https://codeload.invalid/x', limit=3)


if __name__ == '__main__':
    unittest.main()
