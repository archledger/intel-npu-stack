#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Contract for publishing through immutable releases and composing the Pages site, against a fake GitHub."""
import hashlib
import http.server
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import threading
import unittest
from unittest import mock
import urllib.parse

import release_publish as publish
import release_site
import test_check_release as fixtures

API = 'https://api.example.test'
UPLOADS = 'https://uploads.example.test'
STORAGE = 'https://storage.example.test'
REPOSITORY = 'archledger/intel-npu-stack'
BASE_URL = 'https://archledger.github.io/intel-npu-stack/0.1.0/'
COMMIT = 'c' * 40
TOOLS = shutil.which('gpg') and shutil.which('gpgconf')


def sha(data):
    return hashlib.sha256(data).hexdigest()


class FakeGitHub:
    """The REST endpoints publication uses, with switches for the failures under test."""

    def __init__(self):
        self.pages = {'build_type': 'workflow', 'html_url': 'https://archledger.github.io/intel-npu-stack/'}
        self.releases, self.blobs, self.tags = [], {}, {}
        self.immutable_on_publish, self.tag_override, self.page_size = True, None, 2
        self.corrupt, self.fail, self.storage_auth, self.next_id = set(), {}, [], 1
        self.frozen_notes = False

    def new_id(self):
        self.next_id += 1
        return self.next_id

    def add_asset(self, release, name, data, digest=None):
        asset_id = self.new_id()
        self.blobs[asset_id] = data
        asset = {'id': asset_id, 'name': name, 'size': len(data), 'digest': digest or 'sha256:' + sha(data),
                 'url': f'{API}/repos/{REPOSITORY}/releases/assets/{asset_id}'}
        release['assets'].append(asset)
        return asset

    def add_release(self, tag, assets=None, draft=False, prerelease=False, immutable=True, commit=COMMIT):
        release_id = self.new_id()
        release = {'id': release_id, 'tag_name': tag, 'draft': draft, 'prerelease': prerelease,
                   'immutable': immutable, 'target_commitish': commit, 'assets': [],
                   'upload_url': f'{UPLOADS}/repos/{REPOSITORY}/releases/{release_id}/assets{{?name,label}}'}
        for name, data in (assets or {}).items():
            self.add_asset(release, name, data)
        if not draft:
            self.tags[tag] = commit
        self.releases.append(release)
        return release

    def reply(self, status, body=None, headers=None):
        return status, headers or {}, b'' if body is None else json.dumps(body).encode()

    def __call__(self, method, url, headers=None, data=None, timeout=None, sink=None):
        parts = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parts.query)
        if url.startswith(STORAGE):
            self.storage_auth.append((headers or {}).get('Authorization'))
            asset_id = int(parts.path.strip('/'))
            data = self.blobs[asset_id]
            name = next(a['name'] for r in self.releases for a in r['assets'] if a['id'] == asset_id)
            body = data + b'!' if name in self.corrupt else data
            if sink is not None:
                sink.write(body)
                return 200, {}, b''
            return 200, {}, body
        path = parts.path
        for (fail_method, prefix), status in self.fail.items():
            if method == fail_method and path.startswith(prefix):
                return self.reply(status, {'message': 'injected'})
        if url.startswith(UPLOADS):
            release = next(r for r in self.releases if r['id'] == int(path.split('/')[-2]))
            return self.reply(201, self.add_asset(release, query['name'][0], data))
        repo = f'/repos/{REPOSITORY}'
        rest = path[len(repo):] if path.startswith(repo) else None
        if rest == '/pages' and method == 'GET':
            return self.reply(200, self.pages) if self.pages else self.reply(404, {'message': 'Not Found'})
        if rest and rest.startswith('/git/matching-refs/tags/'):
            prefix = rest.split('/git/matching-refs/tags/')[1]
            return self.reply(200, [{'ref': 'refs/tags/' + tag} for tag in self.tags if tag.startswith(prefix)])
        if rest and rest.startswith('/git/ref/tags/'):
            tag = rest.split('/git/ref/tags/')[1]
            if tag not in self.tags:
                return self.reply(404, {'message': 'Not Found'})
            return self.reply(200, {'object': {'type': 'commit', 'sha': self.tags[tag]}})
        if rest == '/releases' and method == 'GET':
            page = int(query.get('page', ['1'])[0])
            chunk = self.releases[(page - 1) * self.page_size:page * self.page_size]
            more = page * self.page_size < len(self.releases)
            link = {'Link': f'<{API}{repo}/releases?per_page=100&page={page + 1}>; rel="next"'} if more else {}
            return self.reply(200, chunk, link)
        if rest == '/releases' and method == 'POST':
            body = json.loads(data)
            release = self.add_release(body['tag_name'], draft=True, immutable=False, commit=body['target_commitish'])
            release['name'], release['body'] = body['name'], body['body']
            return self.reply(201, release)
        if rest and rest.startswith('/releases/assets/'):
            asset_id = int(rest.split('/')[-1])
            if (headers or {}).get('Accept') == 'application/octet-stream':
                return self.reply(302, headers={'Location': f'{STORAGE}/{asset_id}'})
            return self.reply(200, next(a for r in self.releases for a in r['assets'] if a['id'] == asset_id))
        if rest and rest.startswith('/releases/'):
            release = next(r for r in self.releases if r['id'] == int(rest.split('/')[2]))
            if method == 'PATCH':
                body = json.loads(data)
                if release['draft'] and not self.frozen_notes:
                    release.update({key: body[key] for key in ('name', 'body') if key in body})
                if body.get('draft') is False and release['draft']:
                    release['draft'], release['immutable'] = False, self.immutable_on_publish
                    self.tags[release['tag_name']] = self.tag_override or release['target_commitish']
            return self.reply(200, release)
        return self.reply(404, {'message': 'Not Found ' + path})


def answer(status, body, sink, limit=None):
    """A live response as fetch_public gives it; bodies over the limit must be streamed into a sink."""
    if status == 200 and sink is not None:
        sink.write(body)
        return status, b''
    if limit is not None and len(body) > limit:
        raise publish.PublishRefused('response exceeds the size limit')
    return status, body


def make_release(root, key, version, **identity):
    """A tiny signed site and its four release assets.

    identity overrides what the signed manifest names: pinned (the version), base_url, primary_fingerprint or
    source_commit.
    """
    site = Path(root) / 'site' / version
    pinned = identity.pop('pinned', version)
    named = {'base_url': f'https://archledger.github.io/intel-npu-stack/{pinned}/',
             'primary_fingerprint': key.fingerprint, 'source_commit': COMMIT, **identity}
    manifest = {'installer': {'pinned': {'version': pinned, 'base_url': named['base_url'],
                                         'primary_fingerprint': named['primary_fingerprint']}},
                'source_commit': named['source_commit']}
    files = {'release.json': f'{{"stack_release": "{version}"}}\n'.encode(), 'release.json.sig': b'signature\n',
             'profile.toml': b'id = "fixture"\n', 'install.sh': b'#!/bin/sh\nexit 0\n',
             'intel-npu-stack-install': b'\x7fELF installer ' + version.encode() + bytes(200),
             'primary-command.txt': b'(true)\n', 'repodata/repomd.xml': b'<repomd/>\n',
             'publication-manifest.json': (json.dumps(manifest, sort_keys=True) + '\n').encode()}
    for name, data in files.items():
        (site / name).parent.mkdir(parents=True, exist_ok=True)
        (site / name).write_bytes(data)
    key.sign(site / 'install.sh', output=str(site / 'install.sh.asc'))
    (site / 'SHA256SUMS').write_bytes(release_site.render_sha256sums(site))
    key.sign(site / 'SHA256SUMS', output=str(site / 'SHA256SUMS.asc'))
    archive = Path(root) / f'intel-npu-stack-{version}.tar'
    with archive.open('xb') as stream:
        release_site.write_archive(site, stream)
    assets = {archive.name: archive.read_bytes(), 'SHA256SUMS': (site / 'SHA256SUMS').read_bytes(),
              'SHA256SUMS.asc': (site / 'SHA256SUMS.asc').read_bytes(),
              'publication-manifest.json': (site / 'publication-manifest.json').read_bytes()}
    return site, archive, assets


def noncanonical(archive):
    """The same members as a canonical archive, in reverse order with other metadata."""
    with tarfile.open(archive) as tar:
        members = [(member, tar.extractfile(member).read()) for member in tar.getmembers()]
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for member, data in reversed(members):
            member.mtime, member.mode = 1, 0o600
            tar.addfile(member, io.BytesIO(data))
    return stream.getvalue()


@unittest.skipUnless(TOOLS, 'gpg is required')
class Publication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='publish-')
        base = Path(cls.tmp.name)
        for name in ['key', 'other']:
            (base / name).mkdir(mode=0o700)
        cls.key, cls.other = fixtures.ThrowawayKey(base / 'key'), fixtures.ThrowawayKey(base / 'other')
        cls.site, cls.archive, cls.assets = make_release(base / 'r1', cls.key, '0.1.0')
        cls.site2, cls.archive2, cls.assets2 = make_release(base / 'r2', cls.key, '0.2.0')

    @classmethod
    def tearDownClass(cls):
        for key in [cls.key, cls.other]:
            subprocess.run(['gpgconf', '--homedir', str(key.home), '--kill', 'all'], capture_output=True)
        cls.tmp.cleanup()

    def setUp(self):
        self.fake = FakeGitHub()
        self.gh = publish.GitHub(API, REPOSITORY, 'token-value', transport=self.fake)
        self.values = {'version': '0.1.0', 'base_url': BASE_URL, 'primary_fingerprint': self.key.fingerprint}
        self.work = Path(tempfile.mkdtemp(prefix='case-', dir=self.tmp.name))
        self.addCleanup(shutil.rmtree, self.work, True)
        self.assets_dir = self.work / 'assets'
        self.assets_dir.mkdir()
        for name, data in self.assets.items():
            (self.assets_dir / name).write_bytes(data)
        self.notes = self.work / 'notes.md'
        self.notes.write_text('# Intel NPU Stack 0.1.0\n')
        self.live = {}

    def fetch(self, url, sink=None):
        path = urllib.parse.urlsplit(url).path
        return answer(200, self.live[path], sink) if path in self.live else (404, b'')

    def refused(self, message, function, *args, **kwargs):
        with self.assertRaises(publish.PublishRefused) as caught:
            function(*args, **kwargs)
        self.assertIn(message, str(caught.exception))

    # check-unpublished -------------------------------------------------------------------------------

    def test_preflight_accepts_a_clean_repository_and_a_404_site(self):
        self.assertEqual(publish.check_unpublished(self.gh, self.values, 'preflight', fetch=self.fetch), 'fresh')

    def test_preflight_refusals(self):
        def preflight():
            return publish.check_unpublished(self.gh, self.values, 'preflight', fetch=self.fetch)
        self.fake.pages['build_type'] = 'legacy'
        self.refused('GitHub Actions', preflight)
        self.fake.pages = {'build_type': 'workflow', 'html_url': 'https://archledger.github.io/other/'}
        self.refused('BASE_URL', preflight)
        self.fake.pages = None
        self.refused('GitHub Pages', preflight)
        self.fake.pages = {'build_type': 'workflow', 'html_url': 'https://archledger.github.io/intel-npu-stack/'}
        self.fake.tags['v0.1.0'] = COMMIT
        self.refused('tag v0.1.0 already exists', preflight)
        del self.fake.tags['v0.1.0']
        self.fake.add_release('v0.1.0', draft=True)
        self.refused('release or draft', preflight)
        self.fake.releases.clear()
        self.live['/intel-npu-stack/0.1.0/release.json'] = b'{}'
        self.refused('HTTP 200', preflight)
        del self.live['/intel-npu-stack/0.1.0/release.json']
        self.fake.fail[('GET', f'/repos/{REPOSITORY}/releases')] = 502
        self.refused('HTTP 502', preflight)

    def test_publish_phase_states(self):
        def state():
            return publish.check_unpublished(self.gh, self.values, 'publish', self.assets_dir, COMMIT, self.key.public)
        self.assertEqual(state(), 'fresh')
        draft = self.fake.add_release('v0.1.0', draft=True, immutable=False,
                                      assets={'SHA256SUMS': self.assets['SHA256SUMS']})
        self.assertEqual(state(), 'draft-resume')
        self.fake.add_asset(draft, 'publication-manifest.json', b'{"other": true}\n')
        self.refused('stale draft', state)
        self.fake.releases.clear()
        self.fake.add_release('v0.1.0', assets=self.assets)
        self.assertEqual(state(), 'published-resume')
        self.fake.tags['v0.1.0'] = 'd' * 40
        self.refused('not this immutable publication', state)
        self.fake.releases.clear()
        self.refused('exists without a release', state)
        del self.fake.tags['v0.1.0']
        self.fake.add_release('v0.1.0', draft=True, immutable=False, commit='d' * 40)
        self.refused('targets another commit', state)
        self.fake.releases.clear()
        self.fake.add_release('v0.1.0', draft=True, prerelease=True, immutable=False)
        self.refused('prerelease', state)
        self.fake.releases.clear()
        self.fake.add_release('v0.1.0', prerelease=True, assets=self.assets)
        self.refused('prerelease', state)

    # publish-release ---------------------------------------------------------------------------------

    def test_publishes_reads_back_and_resumes_idempotently(self):
        result = publish.publish_release(self.gh, self.values, self.assets_dir, self.notes, COMMIT, self.key.public)
        self.assertEqual(result['state'], 'fresh')
        release = self.fake.releases[0]
        self.assertEqual((release['draft'], release['immutable'], release['body']),
                         (False, True, '# Intel NPU Stack 0.1.0\n'))
        self.assertEqual(sorted(a['name'] for a in release['assets']), sorted(self.assets))
        self.assertEqual(self.fake.tags['v0.1.0'], COMMIT)
        self.assertTrue(self.fake.storage_auth and not any(self.fake.storage_auth),
                        'asset downloads must not send the token to the storage host')
        again = publish.publish_release(self.gh, self.values, self.assets_dir, self.notes, COMMIT, self.key.public)
        self.assertEqual(again['state'], 'published-resume')
        self.assertEqual(len(self.fake.releases), 1)

    def test_standalone_assets_must_be_the_archive_copies(self):
        for name in ['publication-manifest.json', 'SHA256SUMS']:
            with self.subTest(name):
                self.setUp()
                (self.assets_dir / name).write_bytes(b'{"stale": true}\n')
                self.refused(f'standalone {name} differs', publish.publish_release, self.gh, self.values,
                             self.assets_dir, self.notes, COMMIT, self.key.public)
                self.assertEqual(self.fake.releases, [], 'nothing may be created before the check')

    def test_an_interrupted_draft_is_completed(self):
        self.fake.add_release('v0.1.0', draft=True, immutable=False,
                              assets={'SHA256SUMS': self.assets['SHA256SUMS']})
        result = publish.publish_release(self.gh, self.values, self.assets_dir, self.notes, COMMIT, self.key.public)
        self.assertEqual(result['state'], 'draft-resume')
        self.assertEqual(sorted(a['name'] for a in self.fake.releases[0]['assets']), sorted(self.assets))

    def test_a_resumed_draft_gets_this_publications_title_and_notes(self):
        draft = self.fake.add_release('v0.1.0', draft=True, immutable=False,
                                      assets={'SHA256SUMS': self.assets['SHA256SUMS']})
        draft.update(name='Old title', body='stale qualification digests\n')
        publish.publish_release(self.gh, self.values, self.assets_dir, self.notes, COMMIT, self.key.public)
        self.assertEqual((draft['draft'], draft['name'], draft['body']),
                         (False, 'Intel NPU Stack 0.1.0', '# Intel NPU Stack 0.1.0\n'))

    def test_notes_are_checked_before_and_after_publication(self):
        draft = self.fake.add_release('v0.1.0', draft=True, immutable=False)
        draft.update(name='Old title', body='stale\n')
        self.fake.frozen_notes = True
        self.refused("draft does not carry this publication's title and notes", publish.publish_release, self.gh,
                     self.values, self.assets_dir, self.notes, COMMIT, self.key.public)
        self.assertTrue(draft['draft'], 'a draft with other notes must not be published')
        self.setUp()
        published = self.fake.add_release('v0.1.0', assets=self.assets)
        published.update(name='Intel NPU Stack 0.1.0', body='other notes\n')
        self.fake.tags['v0.1.0'] = COMMIT
        self.refused("published v0.1.0 release does not carry", publish.publish_release, self.gh, self.values,
                     self.assets_dir, self.notes, COMMIT, self.key.public)

    def test_publication_refusals(self):
        self.fake.corrupt = {'SHA256SUMS.asc'}
        self.refused('reads back differently', publish.publish_release, self.gh, self.values, self.assets_dir,
                     self.notes, COMMIT, self.key.public)
        self.setUp()
        self.fake.immutable_on_publish = False
        self.refused('not an immutable published release', publish.publish_release, self.gh, self.values,
                     self.assets_dir, self.notes, COMMIT, self.key.public)
        self.setUp()
        self.fake.tag_override = 'd' * 40
        self.refused('does not name the release commit', publish.publish_release, self.gh, self.values,
                     self.assets_dir, self.notes, COMMIT, self.key.public)

    def use_assets(self, assets):
        for name, data in assets.items():
            (self.assets_dir / name).write_bytes(data)

    def refused_before_publication(self, message):
        self.refused(message, publish.check_unpublished, self.gh, self.values, 'publish', self.assets_dir, COMMIT,
                     self.key.public)
        self.refused(message, publish.publish_release, self.gh, self.values, self.assets_dir, self.notes, COMMIT,
                     self.key.public)
        self.assertEqual(self.fake.releases, [], 'nothing may be created before the check')

    def test_the_publish_phase_needs_the_release_key(self):
        self.refused('committed release key is required', publish.check_unpublished, self.gh, self.values, 'publish',
                     self.assets_dir, COMMIT)

    def test_publication_is_bound_to_the_signed_release_identity(self):
        cases = [
            ('an older signed site repacked under this version', {'pinned': '0.0.9'}),
            ('another version', {'pinned': '0.0.9', 'base_url': BASE_URL}),
            ('another base URL', {'base_url': 'https://archledger.github.io/other/0.1.0/'}),
            ('another release key', {'primary_fingerprint': self.other.fingerprint}),
            ('another source commit', {'source_commit': 'd' * 40}),
        ]
        for index, (label, identity) in enumerate(cases):
            with self.subTest(label):
                self.setUp()
                self.use_assets(make_release(self.work / f'identity-{index}', self.key, '0.1.0', **identity)[2])
                self.refused_before_publication('names another release')

    def test_publication_requires_the_release_key_and_the_signed_files(self):
        self.use_assets(make_release(self.work / 'foreign', self.other, '0.1.0',
                                     primary_fingerprint=self.key.fingerprint)[2])
        self.refused_before_publication('release-key policy')
        self.setUp()
        site = self.work / 'edited/0.1.0'
        shutil.copytree(self.site, site)
        (site / 'publication-manifest.json').write_bytes(b'{"edited": true}\n')
        archive = self.assets_dir / 'intel-npu-stack-0.1.0.tar'
        archive.unlink()
        with archive.open('xb') as stream:
            release_site.write_archive(site, stream)
        (self.assets_dir / 'publication-manifest.json').write_bytes(b'{"edited": true}\n')
        self.refused_before_publication('publication-manifest.json differs from SHA256SUMS')

    def test_a_noncanonical_archive_is_refused_before_publication(self):
        (self.assets_dir / 'intel-npu-stack-0.1.0.tar').write_bytes(noncanonical(self.archive))
        self.refused_before_publication('not the canonical archive of its site')

    def test_a_site_over_the_pages_budget_is_refused_before_publication(self):
        size = sum(path.stat().st_size for path in self.site.rglob('*') if path.is_file())
        with mock.patch.object(publish, 'MAX_SITE', size - 1):
            self.refused_before_publication(f'the 0.1.0 site is {size} bytes, above the {size - 1}-byte Pages budget')
        with mock.patch.object(publish, 'MAX_SITE', size):
            self.assertEqual(publish.publish_release(self.gh, self.values, self.assets_dir, self.notes, COMMIT,
                                                     self.key.public)['state'], 'fresh')

    def flood(self, headers=500):
        """An archive of many empty duplicate members, cheap to write and costly to materialize."""
        path = self.work / 'flood.tar'
        path.unlink(missing_ok=True)
        with tarfile.open(path, 'w', format=tarfile.GNU_FORMAT) as tar:
            for _ in range(headers):
                tar.addfile(tarfile.TarInfo('0.1.0/SHA256SUMS'), io.BytesIO(b''))
        return path

    def headers_read(self, function, *args, **kwargs):
        """Refused for too many members after reading at most the limit plus two headers."""
        reads, original = [], tarfile.TarFile.next

        def counted(tar):
            reads.append(1)
            return original(tar)
        with mock.patch.object(publish, 'MAX_MEMBERS', 50), mock.patch.object(tarfile.TarFile, 'next', counted):
            self.refused('too many members', function, *args, **kwargs)
        self.assertLessEqual(len(reads), 52)

    def test_archive_headers_are_counted_while_they_are_read(self):
        (self.assets_dir / 'intel-npu-stack-0.1.0.tar').write_bytes(self.flood().read_bytes())
        self.headers_read(publish.publish_release, self.gh, self.values, self.assets_dir, self.notes, COMMIT,
                          self.key.public)
        self.assertEqual(self.fake.releases, [])
        self.headers_read(publish.unpack_release, self.flood(), '0.1.0', self.assets['SHA256SUMS'],
                          self.assets['SHA256SUMS.asc'], self.work / 'unpacked')
        self.headers_read(self.verify, lambda url, sink=None: (404, b''), archive=self.flood())

    def test_the_member_limit_admits_a_site_of_exactly_that_size(self):
        with tarfile.open(self.archive) as tar:
            count = len(tar.getmembers())
        with mock.patch.object(publish, 'MAX_MEMBERS', count - 1):
            self.refused_before_publication('too many members')
        with mock.patch.object(publish, 'MAX_MEMBERS', count):
            self.assertEqual(publish.publish_release(self.gh, self.values, self.assets_dir, self.notes, COMMIT,
                                                     self.key.public)['state'], 'fresh')

    # compose-pages -----------------------------------------------------------------------------------

    def registry(self, published=(), retired=()):
        path = self.work / 'published-versions.json'
        path.write_text(json.dumps({'schema_version': 1, 'published': list(published), 'retired': list(retired)}))
        return path

    def compose(self, registry=None, new_version='0.2.0', **kwargs):
        output, manifest = self.work / 'out/_site', self.work / 'out/pages-manifest.json'
        shutil.rmtree(self.work / 'out', ignore_errors=True)
        (self.work / 'out').mkdir()
        return publish.compose_pages(self.gh, self.values, self.key.public, self.key.fingerprint,
                                     registry or self.registry(), output, manifest, new_version, fetch=self.fetch,
                                     **kwargs), output

    def publish_both(self):
        self.fake.add_release('v0.1.0', assets=self.assets)
        self.fake.add_release('v0.2.0', assets=self.assets2)
        self.live['/intel-npu-stack/0.1.0/SHA256SUMS'] = self.assets['SHA256SUMS']

    def test_composes_every_immutable_release_and_skips_drafts_and_prereleases(self):
        self.publish_both()
        self.fake.add_release('v0.3.0', draft=True, immutable=False, assets=self.assets2)
        self.fake.add_release('v0.2.1', prerelease=True, assets=self.assets2)
        self.fake.add_release('release-inputs-0.1.0', prerelease=True, assets={'release-inputs.tar.gz': b'x'})
        registry = self.registry([{'version': '0.1.0', 'sha256sums_sha256': sha(self.assets['SHA256SUMS'])}])
        manifest, output = self.compose(registry)
        self.assertEqual(sorted(manifest['versions']), ['0.1.0', '0.2.0'])
        self.assertEqual(sorted(p.name for p in output.iterdir()), ['0.1.0', '0.2.0'])
        self.assertEqual((output / '0.2.0/SHA256SUMS').read_bytes(), self.assets2['SHA256SUMS'])
        self.assertFalse((output / 'index.html').exists())

    def test_retirement_must_name_the_release_it_retires(self):
        self.publish_both()
        registry = self.registry(retired=[{'version': '0.1.0', 'sha256sums_sha256': '0' * 64, 'reason': 'superseded'}])
        self.refused('retired entry for 0.1.0', self.compose, registry)

    def test_a_retired_release_must_be_immutable(self):
        self.publish_both()
        release = next(r for r in self.fake.releases if r['tag_name'] == 'v0.1.0')
        release['immutable'] = False
        registry = self.registry(retired=[{'version': '0.1.0', 'sha256sums_sha256': sha(self.assets['SHA256SUMS']),
                                           'reason': 'superseded'}])
        self.refused('release v0.1.0 is not immutable', self.compose, registry)
        release['immutable'] = True
        self.assertNotIn('0.1.0', self.compose(registry)[0]['versions'])

    def test_compose_refuses_a_release_whose_standalone_manifest_differs(self):
        self.publish_both()
        release = next(r for r in self.fake.releases if r['tag_name'] == 'v0.2.0')
        release['assets'] = [a for a in release['assets'] if a['name'] != 'publication-manifest.json']
        self.fake.add_asset(release, 'publication-manifest.json', b'{"stale": true}\n')
        self.refused('standalone publication-manifest.json differs', self.compose)

    def test_retired_versions_are_left_out(self):
        self.publish_both()
        registry = self.registry(retired=[{'version': '0.1.0', 'sha256sums_sha256': sha(self.assets['SHA256SUMS']),
                                           'reason': 'superseded'}])
        manifest, output = self.compose(registry)
        self.assertEqual(sorted(manifest['versions']), ['0.2.0'])

    def test_compose_binds_each_release_to_its_version(self):
        cases = [
            ('an older signed site repacked under a new version', {'pinned': '0.1.0'}),
            ('another version', {'pinned': '0.1.0', 'base_url': 'https://archledger.github.io/intel-npu-stack/0.2.0/'}),
            ('another base URL', {'base_url': 'https://archledger.github.io/other/0.2.0/'}),
            ('another release key', {'primary_fingerprint': self.other.fingerprint}),
        ]
        for index, (label, identity) in enumerate(cases):
            with self.subTest(label):
                self.setUp()
                assets = make_release(self.work / f'repacked-{index}', self.key, '0.2.0', **identity)[2]
                self.fake.add_release('v0.1.0', assets=self.assets)
                self.fake.add_release('v0.2.0', assets=assets)
                self.live['/intel-npu-stack/0.1.0/SHA256SUMS'] = self.assets['SHA256SUMS']
                self.refused('the signed publication manifest in the 0.2.0 archive names another release',
                             self.compose)
                self.assertFalse((self.work / 'out/_site').exists())

    def test_compose_binds_each_release_to_its_tag_commit(self):
        cases = [
            ('a tag at another commit', lambda: self.fake.tags.update({'v0.2.0': 'd' * 40}),
             'the signed publication manifest in the 0.2.0 archive names another release'),
            ('a missing tag', lambda: self.fake.tags.pop('v0.2.0'), 'release v0.2.0 has no tag'),
        ]
        for label, damage, message in cases:
            with self.subTest(label):
                self.setUp()
                self.publish_both()
                damage()
                self.refused(message, self.compose)
                self.assertFalse((self.work / 'out/_site').exists())

    def test_compose_refusals(self):
        def replace(version, name, data, digest=None):
            release = next(r for r in self.fake.releases if r['tag_name'] == 'v' + version)
            release['assets'] = [a for a in release['assets'] if a['name'] != name]
            self.fake.add_asset(release, name, data, digest)

        def retar(members):
            archive = self.work / 'retar.tar'
            archive.unlink(missing_ok=True)
            with tarfile.open(archive, 'w', format=tarfile.GNU_FORMAT) as tar:
                for info, data in members:
                    tar.addfile(info, None if data is None else io.BytesIO(data))
            return archive.read_bytes()

        def member(name, data=b'x', kind=tarfile.REGTYPE):
            info = tarfile.TarInfo(name)
            info.type, info.size = kind, (len(data) if kind == tarfile.REGTYPE else 0)
            if kind == tarfile.SYMTYPE:
                info.linkname = '/etc/passwd'
            return info, (data if kind == tarfile.REGTYPE else None)

        with tarfile.open(self.archive2) as tar:
            original = [(m, tar.extractfile(m).read()) for m in tar.getmembers()]
        tar_name, exact = 'intel-npu-stack-0.2.0.tar', 'does not hold exactly'
        cases = [
            ('mutable release', 'is not immutable',
             lambda: next(r for r in self.fake.releases if r['tag_name'] == 'v0.2.0').update(immutable=False)),
            ('foreign signature', 'release-key policy',
             lambda: replace('0.2.0', 'SHA256SUMS.asc', self.other_signature())),
            ('extra member', exact, lambda: replace('0.2.0', tar_name, retar(original + [member('0.2.0/extra.txt')]))),
            ('missing member', exact, lambda: replace('0.2.0', tar_name, retar(original[1:]))),
            ('symlink member', exact, lambda: replace('0.2.0', tar_name, retar(
                original[:-1] + [member(original[-1][0].name, kind=tarfile.SYMTYPE)]))),
            ('API digest', 'API digest',
             lambda: replace('0.2.0', 'SHA256SUMS', self.assets2['SHA256SUMS'], 'sha256:' + '0' * 64)),
            ('live drift', 'live 0.1.0/SHA256SUMS differs',
             lambda: self.live.update({'/intel-npu-stack/0.1.0/SHA256SUMS': b'changed'})),
            ('extra asset', 'exactly the release assets', lambda: replace('0.2.0', 'notes.txt', b'extra')),
            ('noncanonical archive', 'not the canonical archive of its site',
             lambda: replace('0.2.0', tar_name, noncanonical(self.archive2))),
            ('too many members', 'too many members',
             lambda: replace('0.2.0', tar_name, retar(original * 2000))),
        ]
        for label, message, damage in cases:
            with self.subTest(label):
                self.fake = FakeGitHub()
                self.gh = publish.GitHub(API, REPOSITORY, 'token-value', transport=self.fake)
                self.live = {}
                self.publish_both()
                damage()
                self.refused(message, self.compose)
                self.assertFalse((self.work / 'out/_site').exists())

    def other_signature(self):
        target = self.work / 'SHA256SUMS'
        target.write_bytes(self.assets2['SHA256SUMS'])
        self.other.sign(target, output=str(self.work / 'other.asc'))
        return (self.work / 'other.asc').read_bytes()

    def test_registry_and_budget_refusals(self):
        self.publish_both()
        self.refused('published version 0.0.9 is missing', self.compose,
                     self.registry([{'version': '0.0.9', 'sha256sums_sha256': '0' * 64}]))
        self.refused('another SHA256SUMS than recorded', self.compose,
                     self.registry([{'version': '0.1.0', 'sha256sums_sha256': '0' * 64}]))
        self.refused('byte budget', self.compose, limit=100)
        with self.assertRaises(publish.PublishRefused):
            self.compose(self.registry(retired=[{'version': '0.1.0', 'sha256sums_sha256': '0' * 64, 'reason': ''}]))

    # verify-live -------------------------------------------------------------------------------------

    def serve_live(self, site, version, stale=None):
        stale = dict(stale or {})

        def fetch(url, sink=None):
            # A 100-byte in-memory limit stands for MAX_BODY: every file of the version must be streamed.
            parts = urllib.parse.urlsplit(url)
            path = parts.path.removeprefix(f'/intel-npu-stack/{version}/')
            if path in stale and stale[path] > 0 and not parts.query:
                stale[path] -= 1
                return answer(200, b'old ' + path.encode(), sink, limit=100)
            target = site / path
            return answer(200, target.read_bytes(), sink, limit=100) if target.is_file() else (404, b'')
        return fetch

    def verify(self, fetch, archive=None, **kwargs):
        sleeps = []
        clock = iter(range(0, 100000, 30))
        result = publish.verify_live(self.values, self.key.public, self.key.fingerprint, archive or self.archive,
                                     fetch=fetch, sleep=sleeps.append, clock=lambda: next(clock), **kwargs)
        return result, sleeps

    def test_live_site_is_polled_until_fresh_then_compared_byte_for_byte(self):
        result, sleeps = self.verify(self.serve_live(self.site, '0.1.0', {'release.json': 2}))
        self.assertTrue(result['passed'])
        self.assertEqual(result['files'], len(release_site.site_files(self.site)))
        self.assertEqual(len(sleeps), 2)

    def test_live_refusals(self):
        broken = self.work / 'broken/0.1.0'
        shutil.copytree(self.site, broken)
        (broken / 'repodata/repomd.xml').write_bytes(b'<changed/>\n')
        self.refused('still serves stale', self.verify, self.serve_live(broken, '0.1.0'), timeout=90)
        shutil.rmtree(broken.parent)
        shutil.copytree(self.site, broken)
        (broken / 'install.sh.asc').unlink()
        self.refused('install.sh.asc differs', self.verify, self.serve_live(broken, '0.1.0'))
        shutil.rmtree(broken.parent)
        shutil.copytree(self.site, broken)
        (broken / 'publication-manifest.json').write_bytes(b'{"changed": true}\n')
        self.refused('live publication-manifest.json differs', self.verify, self.serve_live(broken, '0.1.0'))
        other = self.work / 'noncanonical.tar'
        with tarfile.open(other, 'w', format=tarfile.GNU_FORMAT) as tar:
            for relative in release_site.site_files(self.site):
                tar.add(self.site / relative, arcname='0.1.0/' + relative)
        self.refused('repack', self.verify, self.serve_live(self.site, '0.1.0'), archive=other)

    def test_live_installer_bootstrap_signature_must_pass_the_key_policy(self):
        # Every live byte equals the archive, but the archive's install.sh.asc is by another key.
        forged = self.work / 'forged/0.1.0'
        shutil.copytree(self.site, forged)
        self.other.sign(forged / 'install.sh', output=str(forged / 'install.sh.asc.new'))
        (forged / 'install.sh.asc.new').replace(forged / 'install.sh.asc')
        (forged / 'SHA256SUMS').write_bytes(release_site.render_sha256sums(forged))
        self.key.sign(forged / 'SHA256SUMS', output=str(forged / 'SHA256SUMS.asc.new'))
        (forged / 'SHA256SUMS.asc.new').replace(forged / 'SHA256SUMS.asc')
        archive = self.work / 'forged.tar'
        with archive.open('xb') as stream:
            release_site.write_archive(forged, stream)
        self.refused('install.sh.asc', self.verify, self.serve_live(forged, '0.1.0'), archive=archive)

    def test_archive_members_must_be_plain_paths(self):
        for name in ['0.1.0/../../escape', '0.1.0//tmp/escape', '0.1.0/./x', 'other/x']:
            with self.subTest(name):
                archive = self.work / 'unsafe.tar'
                archive.unlink(missing_ok=True)
                with tarfile.open(archive, 'w', format=tarfile.GNU_FORMAT) as tar:
                    info = tarfile.TarInfo(name)
                    info.size = 1
                    tar.addfile(info, io.BytesIO(b'x'))
                self.refused('unsafe or duplicate member', self.verify, self.serve_live(self.site, '0.1.0'),
                             archive=archive)

    def test_other_versions_must_keep_their_published_sums(self):
        manifest = self.work / 'pages-manifest.json'
        manifest.write_text(json.dumps({'versions': {'0.0.9': {'sha256sums_sha256': sha(b'old sums')}}}))
        fetch = self.serve_live(self.site, '0.1.0')

        def with_old(url, sink=None):
            if '/0.0.9/SHA256SUMS' in url:
                return answer(200, b'old sums', sink)
            return fetch(url, sink)
        result, _ = self.verify(with_old, pages_manifest=manifest)
        self.assertEqual(result['other_versions'], {'0.0.9': sha(b'old sums')})

        def drifted(url, sink=None):
            return answer(200, b'changed', sink) if '/0.0.9/SHA256SUMS' in url else fetch(url, sink)
        self.refused('0.0.9/SHA256SUMS changed', self.verify, drifted, pages_manifest=manifest)


class Transport(unittest.TestCase):
    def test_redirects_are_not_followed_with_credentials(self):
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get('Authorization')))
                self.send_response(302)
                self.send_header('Location', 'http://127.0.0.1:1/elsewhere')
                self.send_header('Content-Length', '0')
                self.end_headers()

            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        status, headers, _ = publish.http('GET', f'http://127.0.0.1:{server.server_address[1]}/asset',
                                          {'Authorization': 'Bearer secret'})
        self.assertEqual((status, headers.get('Location')), (302, 'http://127.0.0.1:1/elsewhere'))
        self.assertEqual(seen, [('/asset', 'Bearer secret')])

    def test_large_downloads_stream_to_disk_within_the_limit(self):
        body = b'x' * 3000

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f'http://127.0.0.1:{server.server_address[1]}/asset'
        sink = io.BytesIO()
        self.assertEqual(publish.http('GET', url, sink=sink)[2], b'')
        self.assertEqual(sink.getvalue(), body)
        body_limit, publish.MAX_BODY = publish.MAX_BODY, 1000
        self.addCleanup(setattr, publish, 'MAX_BODY', body_limit)
        with self.assertRaisesRegex(publish.PublishRefused, 'size limit'):
            publish.fetch_public(url)
        live = publish.Digest()
        self.assertEqual(publish.fetch_public(url, sink=live), (200, b''))
        self.assertEqual(live.sha256.hexdigest(), sha(body))
        limit, publish.MAX_ASSET = publish.MAX_ASSET, 1000
        self.addCleanup(setattr, publish, 'MAX_ASSET', limit)
        with self.assertRaisesRegex(publish.PublishRefused, 'size limit'):
            publish.http('GET', url, sink=io.BytesIO())

    def test_pagination_stays_on_the_api_host(self):
        def transport(method, url, headers=None, data=None):
            return 200, {'Link': '<https://evil.example/next>; rel="next"'}, b'[]'
        gh = publish.GitHub(API, REPOSITORY, 'token', transport=transport)
        with self.assertRaisesRegex(publish.PublishRefused, 'API host'):
            gh.releases()

    def test_network_errors_refuse_without_the_query(self):
        with self.assertRaises(publish.PublishRefused) as caught:
            publish.http('GET', 'http://127.0.0.1:1/x?token=secret', timeout=5)
        self.assertNotIn('secret', str(caught.exception))


class Sums(unittest.TestCase):
    def test_sums_paths_must_be_plain_relative_paths(self):
        digest = 'a' * 64
        self.assertEqual(publish.parse_sums(f'{digest}  repodata/repomd.xml\n'.encode()),
                         {'repodata/repomd.xml': digest})
        for path in ['../index.html', '/etc/passwd', 'a//b', './x', 'a/../b', '.hidden']:
            with self.subTest(path), self.assertRaisesRegex(publish.PublishRefused, 'unsafe path'):
                publish.parse_sums(f'{digest}  {path}\n'.encode())


class Registry(unittest.TestCase):
    def test_committed_registry_is_valid_and_empty_until_the_first_release(self):
        registry = publish.load_registry(Path(__file__).resolve().parents[2] / 'release/published-versions.json')
        self.assertEqual(registry, {'schema_version': 1, 'published': [], 'retired': []})


if __name__ == '__main__':
    unittest.main()
