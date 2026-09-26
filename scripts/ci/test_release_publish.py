#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Contract for publishing through immutable releases and composing the Pages site, against a fake GitHub."""
import contextlib
import errno
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import socket
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
        # A tag names a commit or one of the annotated tag objects, each of which names a commit.
        self.releases, self.blobs, self.tags, self.annotated = [], {}, {}, {}
        self.immutable_on_publish, self.tag_override, self.page_size = True, None, 2
        self.corrupt, self.fail, self.storage_auth, self.next_id = set(), {}, [], 1
        self.frozen_notes, self.upload_bodies, self.undrafts = False, [], []
        # Tokens that can only read, like the preflight job's: GitHub lists drafts only to a token that can push.
        self.readers = set()
        # 'upload', 'readback', 'undraft' (as the undraft request arrives, before it applies) or 'publish': called
        # once with the release when that first happens
        self.hooks = {}

    def new_id(self):
        self.next_id += 1
        return self.next_id

    def fire(self, event, release):
        hook = self.hooks.pop(event, None)
        if hook is not None:
            hook(release)

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

    def annotate(self, tag, tag_object, commit=COMMIT):
        """Point the tag at a new annotated tag object that names commit, as git tag -s -f does."""
        self.annotated[tag_object] = commit
        self.tags[tag] = tag_object

    def ref_object(self, tag):
        """What the tag's ref names: its annotated tag object or its commit."""
        target = self.tags[tag]
        return {'type': 'tag' if target in self.annotated else 'commit', 'sha': target}

    @staticmethod
    def require_length(headers, body):
        assert int((headers or {})['Content-Length']) == len(body), 'the upload must declare its length'

    def reply(self, status, body=None, headers=None):
        return status, headers or {}, b'' if body is None else json.dumps(body).encode()

    def listing(self, items, query, next_page):
        """One page of a listing and, while more follow, the link to the next page on the API host."""
        page = int(query.get('page', ['1'])[0])
        more = page * self.page_size < len(items)
        return self.reply(200, items[(page - 1) * self.page_size:page * self.page_size],
                          {'Link': f'<{next_page}{page + 1}>; rel="next"'} if more else {})

    def __call__(self, method, url, headers=None, data=None, timeout=None, sink=None):
        parts = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parts.query)
        if url.startswith(STORAGE):
            self.storage_auth.append((headers or {}).get('Authorization'))
            asset_id = int(parts.path.strip('/'))
            data = self.blobs[asset_id]
            release = next(r for r in self.releases if any(a['id'] == asset_id for a in r['assets']))
            self.fire('readback', release)
            name = next(a['name'] for r in self.releases for a in r['assets'] if a['id'] == asset_id)
            body = data + b'!' if name in self.corrupt else data
            if sink is not None:
                sink.write(body)
                return 200, {}, b''
            return 200, {}, body
        path = parts.path
        reader = (headers or {}).get('Authorization') in {'Bearer ' + token for token in self.readers}
        if reader and method != 'GET':
            return self.reply(403, {'message': 'Resource not accessible by integration'})
        for (fail_method, prefix), status in self.fail.items():
            if method == fail_method and path.startswith(prefix):
                return self.reply(status, {'message': 'injected'})
        if url.startswith(UPLOADS):
            release = next(r for r in self.releases if r['id'] == int(path.split('/')[-2]))
            self.upload_bodies.append(data)
            body = data.read() if hasattr(data, 'read') else data
            self.require_length(headers, body)
            asset = self.add_asset(release, query['name'][0], body)
            self.fire('upload', release)
            return self.reply(201, asset)
        repo = f'/repos/{REPOSITORY}'
        rest = path[len(repo):] if path.startswith(repo) else None
        if rest == '/pages' and method == 'GET':
            return self.reply(200, self.pages) if self.pages else self.reply(404, {'message': 'Not Found'})
        if rest and rest.startswith('/git/matching-refs/tags/'):
            prefix = rest.split('/git/matching-refs/tags/')[1]
            # Listed by name with the object each ref names, as git lists refs, and paged like the releases.
            return self.listing([{'ref': 'refs/tags/' + tag, 'object': self.ref_object(tag)}
                                 for tag in sorted(self.tags) if tag.startswith(prefix)], query, f'{API}{path}?page=')
        if rest and rest.startswith('/git/ref/tags/'):
            tag = rest.split('/git/ref/tags/')[1]
            if tag not in self.tags:
                return self.reply(404, {'message': 'Not Found'})
            return self.reply(200, {'object': self.ref_object(tag)})
        if rest and rest.startswith('/git/tags/'):
            tag_object = rest.split('/git/tags/')[1]
            if tag_object not in self.annotated:
                return self.reply(404, {'message': 'Not Found'})
            return self.reply(200, {'object': {'type': 'commit', 'sha': self.annotated[tag_object]}})
        if rest == '/releases' and method == 'GET':
            visible = [release for release in self.releases if not (reader and release['draft'])]
            return self.listing(visible, query, f'{API}{repo}/releases?per_page=100&page=')
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
            if reader and release['draft']:
                return self.reply(404, {'message': 'Not Found'})
            if method == 'PATCH':
                body = json.loads(data)
                if release['draft'] and 'tag_name' not in body:
                    # GitHub drops a draft's tag when an update omits it, as it did to the first 0.1.0 draft.
                    release['tag_name'] = f"untagged-{release['id']:020x}"
                if body.get('draft') is False:
                    self.fire('undraft', release)
                    self.undrafts.append(release['id'])
                if release['draft'] and not self.frozen_notes:
                    release.update({key: body[key] for key in ('name', 'body') if key in body})
                if release['draft']:
                    release.update({key: body[key] for key in ('tag_name', 'target_commitish', 'prerelease')
                                    if key in body})
                if body.get('draft') is False and release['draft']:
                    release['draft'], release['immutable'] = False, self.immutable_on_publish
                    self.fire('publish', release)
                    # GitHub publishes a draft on an existing tag without moving it.
                    self.tags.setdefault(release['tag_name'], self.tag_override or release['target_commitish'])
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


def make_release(root, key, version, installer_key=None, installer_bytes=None, extra=None, **identity):
    """A tiny signed site and its four release assets.

    identity overrides what the signed manifest names: pinned (the version), base_url, primary_fingerprint or
    source_commit. installer_key and installer_bytes sign install.sh.asc with another key or over other bytes, and
    extra adds files, such as packages, to the site.
    """
    site = Path(root) / 'site' / version
    pinned = identity.pop('pinned', version)
    named = {'base_url': f'https://archledger.github.io/intel-npu-stack/{pinned}/',
             'primary_fingerprint': key.fingerprint, 'source_commit': COMMIT, **identity}
    manifest = {'installer': {'pinned': {'version': pinned, 'base_url': named['base_url'],
                                         'primary_fingerprint': named['primary_fingerprint']}},
                'source_commit': named['source_commit']}
    matrix = {'repository': {'base_url': named['base_url'], 'key_fingerprint': named['primary_fingerprint']},
              'kernel': {'min': '7.2.5', 'max_exclusive': '7.3.0', 'module': 'intel_vpu', 'policy': 'Policy.',
                         'tested': [{'release': '7.2.6-200.fc44.x86_64', 'tests': ['probe']}]},
              'hardware': [{'vendor': '8086', 'device': '643e'}], 'not_supported': ['kernels from 7.3.0'],
              'platform': {'version_id': '44', 'arch': 'x86_64', 'id': 'fedora'},
              'profile': {'id': 'fixture', 'status': 'qualified'}, 'qualification': {'evidence_sha256': '0' * 64},
              'rollback': {'index': 'evidence/rollback/rollback-index.json', 'instructions': 'docs/install-fedora.md'}}
    files = {'release.json': f'{{"stack_release": "{version}"}}\n'.encode(), 'release.json.sig': b'signature\n',
             'profile.toml': b'id = "fixture"\n', 'install.sh': b'#!/bin/sh\nexit 0\n',
             'intel-npu-stack-install': b'\x7fELF installer ' + version.encode() + bytes(200),
             'primary-command.txt': b'(true)\n', 'repodata/repomd.xml': b'<repomd/>\n',
             'publication-manifest.json': (json.dumps(manifest, sort_keys=True) + '\n').encode(),
             'support-matrix.json': (json.dumps(matrix, sort_keys=True) + '\n').encode(), **(extra or {})}
    for name, data in files.items():
        (site / name).parent.mkdir(parents=True, exist_ok=True)
        (site / name).write_bytes(data)
    signed = site / 'install.sh'
    if installer_bytes is not None:
        signed = Path(root) / 'other-install.sh'
        signed.write_bytes(installer_bytes)
    (installer_key or key).sign(signed, output=str(site / 'install.sh.asc'))
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


def many_sums(count):
    """A SHA256SUMS that lists count files at plain relative paths."""
    return ''.join(f'{"0" * 64}  packages/{index}.rpm\n' for index in range(count)).encode()


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
        cls.site3, cls.archive3, cls.assets3 = make_release(base / 'r3', cls.key, '0.3.0')

    @classmethod
    def tearDownClass(cls):
        for key in [cls.key, cls.other]:
            subprocess.run(['gpgconf', '--homedir', str(key.home), '--kill', 'all'], capture_output=True)
        cls.tmp.cleanup()

    def setUp(self):
        self.fake = FakeGitHub()
        self.gh = publish.GitHub(API, REPOSITORY, 'token-value', transport=self.fake)
        # The preflight job's token can only read (contents: read); the publish job's can push.
        self.fake.readers.add('read-token')
        self.reader = publish.GitHub(API, REPOSITORY, 'read-token', transport=self.fake)
        self.values = {'version': '0.1.0', 'base_url': BASE_URL, 'primary_fingerprint': self.key.fingerprint}
        self.work = Path(tempfile.mkdtemp(prefix='case-', dir=self.tmp.name))
        self.addCleanup(shutil.rmtree, self.work, True)
        self.assets_dir = self.work / 'assets'
        self.assets_dir.mkdir()
        for name, data in self.assets.items():
            (self.assets_dir / name).write_bytes(data)
        self.notes = self.work / 'notes.md'
        self.notes.write_bytes(release_site.render_notes(self.site, self.archive))
        self.live = {}
        # What the committed registry records, and the bytes a preflight reserves for this version's site.
        self.recorded, self.retired, self.reserve = [], [], publish.site_bytes(self.site)

    def fetch(self, url, sink=None):
        path = urllib.parse.urlsplit(url).path
        return answer(200, self.live[path], sink) if path in self.live else (404, b'')

    def refused(self, message, function, *args, **kwargs):
        with self.assertRaises(publish.PublishRefused) as caught:
            function(*args, **kwargs)
        self.assertIn(message, str(caught.exception))

    def committed_registry(self):
        return self.registry(self.recorded, self.retired)

    def preflight(self, gh=None, **changes):
        """check-unpublished --phase preflight, by default under the preflight job's read-only token."""
        options = {'key': self.key.public, 'reserve': self.reserve, 'fetch': self.fetch, **changes}
        return publish.check_unpublished(gh or self.reader, self.values, 'preflight', self.committed_registry(),
                                         **options)

    def publish_phase(self, **changes):
        options = {'assets_dir': self.assets_dir, 'commit': COMMIT, 'key': self.key.public, 'fetch': self.fetch}
        return publish.check_unpublished(self.gh, self.values, 'publish', self.committed_registry(),
                                         **{**options, **changes})

    def publish(self, **hooks):
        """publish-release, with FakeGitHub hooks for what happens meanwhile."""
        self.fake.hooks.update(hooks)
        return publish.publish_release(self.gh, self.values, self.assets_dir, self.notes, COMMIT, self.key.public,
                                       self.committed_registry(), fetch=self.fetch)

    def pending(self):
        """A run that publishes 0.2.0 after 0.1.0 was published, recorded and served."""
        self.published('0.1.0', self.assets, self.site, self.archive)
        self.live['/intel-npu-stack/0.1.0/SHA256SUMS'] = self.assets['SHA256SUMS']
        self.recorded = [{'version': '0.1.0', 'sha256sums_sha256': sha(self.assets['SHA256SUMS'])}]
        self.values, self.reserve = self.version_values('0.2.0'), publish.site_bytes(self.site2)
        shutil.rmtree(self.assets_dir)
        self.assets_dir.mkdir()
        self.use_assets(self.assets2)
        self.notes.write_bytes(release_site.render_notes(self.site2, self.archive2))

    def retire_older_versions(self):
        """Retired releases of 0.0.1 to 0.0.3, whose tags come before v0.1.0 and fill the first page of tags."""
        for version in ['0.0.1', '0.0.2', '0.0.3']:
            sums = f'{sha(version.encode())}  release.json\n'.encode()
            self.fake.add_release('v' + version, assets={'SHA256SUMS': sums})
            self.retired.append({'version': version, 'sha256sums_sha256': sha(sums), 'reason': 'withdrawn'})

    # check-unpublished -------------------------------------------------------------------------------

    def test_preflight_accepts_a_clean_repository_and_a_404_site(self):
        self.assertEqual(self.preflight(), 'fresh')

    def test_preflight_refusals(self):
        preflight = self.preflight
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
        self.fake.add_release('v0.1.0')
        del self.fake.tags['v0.1.0']  # a published release whose tag was deleted
        self.refused('a release or draft for v0.1.0 already exists', preflight)
        self.fake.releases.clear()
        self.live['/intel-npu-stack/0.1.0/release.json'] = b'{}'
        self.refused('HTTP 200', preflight)
        del self.live['/intel-npu-stack/0.1.0/release.json']
        self.fake.fail[('GET', f'/repos/{REPOSITORY}/releases')] = 502
        self.refused('HTTP 502', preflight)

    def test_a_draft_the_preflight_cannot_see_is_resumed_or_refused_by_the_publish_phase(self):
        # GitHub lists drafts only to a token that can push. The preflight job's token can only read, so a draft an
        # aborted run left is first seen by the publish phase, after the signing and the attestation.
        stale = self.fake.add_release('v0.1.0', draft=True, immutable=False,
                                      assets={'publication-manifest.json': b'{"stale": true}\n'})
        self.assertEqual(self.preflight(), 'fresh')
        self.refused('a release or draft for v0.1.0 already exists', self.preflight, gh=self.gh)
        self.refused('a stale draft is deleted by hand', self.publish_phase)
        self.refused('a stale draft is deleted by hand', self.publish)
        self.assertEqual((stale['draft'], len(stale['assets']), self.fake.upload_bodies, self.fake.undrafts),
                         (True, 1, [], []))
        with self.subTest('a draft of another commit'):
            self.setUp()
            self.fake.add_release('v0.1.0', draft=True, immutable=False, commit='d' * 40,
                                  assets={'SHA256SUMS': self.assets['SHA256SUMS']})
            self.assertEqual(self.preflight(), 'fresh')
            self.refused('the v0.1.0 draft targets another commit than this publication', self.publish_phase)
            self.refused('the v0.1.0 draft targets another commit than this publication', self.publish)
        with self.subTest('a byte-identical subset of this publication at this commit'):
            self.setUp()
            draft = self.fake.add_release('v0.1.0', draft=True, immutable=False,
                                          assets={'SHA256SUMS': self.assets['SHA256SUMS']})
            self.assertEqual(self.preflight(), 'fresh')
            self.assertEqual(self.publish_phase(), 'draft-resume')
            self.assertEqual(self.publish()['state'], 'draft-resume')
            self.assertEqual((draft['draft'], draft['immutable'], self.fake.tags['v0.1.0']), (False, True, COMMIT))

    def test_the_preflight_token_cannot_write_or_see_drafts(self):
        draft = self.fake.add_release('v0.1.0', draft=True, immutable=False)
        self.assertEqual(self.reader.releases(), [])
        self.assertEqual([release['id'] for release in self.gh.releases()], [draft['id']])
        self.refused('returned HTTP 404', self.reader.call, 'GET', f"/releases/{draft['id']}")
        self.refused('returned HTTP 403', self.reader.call, 'PATCH', f"/releases/{draft['id']}", {'draft': False})
        self.assertTrue(draft['draft'])

    def test_preflight_requires_exactly_a_404_for_the_live_release_json(self):
        for code in (503, 403, 500, 301):
            with self.subTest(code=code):
                self.refused(f'the live release.json must not exist before publication (HTTP {code})', self.preflight,
                             fetch=lambda url, sink=None, code=code: (code, b''))
        with self.subTest('a network error'):
            def unreachable(url, sink=None):
                raise publish.NetworkRefused(f'GET {BASE_URL}release.json failed: timed out')
            self.refused('release.json failed: timed out', self.preflight, fetch=unreachable)

    def test_the_preflight_probe_bypasses_the_cdn_cache(self):
        def cdn(url, sink=None):  # the edge still serves a cached 404, but the version is already deployed
            return (200, b'{}') if urllib.parse.urlsplit(url).query else (404, b'')
        self.refused('the live release.json must not exist before publication (HTTP 200)', self.preflight, fetch=cdn)

    def test_publish_phase_states(self):
        state = self.publish_phase
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

    def test_a_draft_whose_tag_names_another_commit_is_refused_before_anything(self):
        draft = self.fake.add_release('v0.1.0', draft=True, immutable=False,
                                      assets={'SHA256SUMS': self.assets['SHA256SUMS']})
        draft.update(name='Old title', body='stale\n')
        self.fake.tags['v0.1.0'] = 'd' * 40  # pushed after the draft was made; publishing would keep it
        self.refused('the v0.1.0 draft targets another commit than this publication', self.publish_phase)
        self.refused('the v0.1.0 draft targets another commit than this publication', self.publish)
        self.assertEqual((draft['draft'], draft['name'], len(draft['assets']), self.fake.upload_bodies),
                         (True, 'Old title', 1, []), 'nothing may be patched, uploaded or published')
        self.assertEqual(self.fake.tags['v0.1.0'], 'd' * 40)

    # publish-release ---------------------------------------------------------------------------------

    def test_publishes_reads_back_and_resumes_idempotently(self):
        result = self.publish()
        self.assertEqual(result['state'], 'fresh')
        release = self.fake.releases[0]
        self.assertEqual((release['draft'], release['immutable'], release['body']),
                         (False, True, self.notes.read_text()))
        self.assertEqual(sorted(a['name'] for a in release['assets']), sorted(self.assets))
        self.assertEqual(self.fake.tags['v0.1.0'], COMMIT)
        self.assertTrue(self.fake.storage_auth and not any(self.fake.storage_auth),
                        'asset downloads must not send the token to the storage host')
        bodies = self.fake.upload_bodies
        self.assertTrue(bodies and not any(isinstance(body, bytes) for body in bodies),
                        'uploads must stream from the asset file')
        again = self.publish()
        self.assertEqual(again['state'], 'published-resume')
        self.assertEqual(len(self.fake.releases), 1)

    def test_standalone_assets_must_be_the_archive_copies(self):
        for name in ['publication-manifest.json', 'SHA256SUMS']:
            with self.subTest(name):
                self.setUp()
                (self.assets_dir / name).write_bytes(b'{"stale": true}\n')
                self.refused(f'standalone {name} differs', self.publish)
                self.assertEqual(self.fake.releases, [], 'nothing may be created before the check')

    def test_an_interrupted_draft_is_completed(self):
        self.fake.add_release('v0.1.0', draft=True, immutable=False,
                              assets={'SHA256SUMS': self.assets['SHA256SUMS']})
        result = self.publish()
        self.assertEqual(result['state'], 'draft-resume')
        self.assertEqual(sorted(a['name'] for a in self.fake.releases[0]['assets']), sorted(self.assets))

    def test_a_resumed_draft_gets_this_publications_title_and_notes(self):
        draft = self.fake.add_release('v0.1.0', draft=True, immutable=False,
                                      assets={'SHA256SUMS': self.assets['SHA256SUMS']})
        draft.update(name='Old title', body='stale qualification digests\n')
        self.publish()
        self.assertEqual((draft['draft'], draft['name'], draft['body']),
                         (False, 'Intel NPU Stack 0.1.0', self.notes.read_text()))

    def test_the_draft_keeps_its_tag_and_commit_while_its_title_and_notes_are_set(self):
        # The first 0.1.0 run set them without naming the tag; GitHub untagged the draft and the undraft check stopped it.
        for label, resumed in [('fresh', False), ('resumed', True)]:
            with self.subTest(label):
                self.setUp()
                if resumed:
                    self.fake.add_release('v0.1.0', draft=True, immutable=False,
                                          assets={'SHA256SUMS': self.assets['SHA256SUMS']})
                seen = []
                self.publish(upload=lambda release: seen.append((release['tag_name'], release['target_commitish'])))
                self.assertEqual(seen, [('v0.1.0', COMMIT)])

    def test_the_notes_must_be_the_rendering_of_this_release(self):
        for label, notes in [('stale', b'# Intel NPU Stack 0.1.0\n'),
                             ('edited digest', self.notes.read_bytes().replace(b'| SHA256SUMS | `', b'| SHA256SUMS | `0'))]:
            with self.subTest(label):
                self.setUp()
                self.notes.write_bytes(notes)
                self.refused('the release notes are not the rendering of this release', self.publish)
                self.assertEqual(self.fake.releases, [], 'nothing may be created before the check')

    def test_notes_are_checked_before_and_after_publication(self):
        draft = self.fake.add_release('v0.1.0', draft=True, immutable=False)
        draft.update(name='Old title', body='stale\n')
        self.fake.frozen_notes = True
        self.refused("draft does not carry this publication's title and notes", self.publish)
        self.assertTrue(draft['draft'], 'a draft with other notes must not be published')
        self.assertEqual(self.fake.storage_auth, [], 'nothing is read back before the notes are right')
        self.setUp()
        published = self.fake.add_release('v0.1.0', assets=self.assets)
        published.update(name='Intel NPU Stack 0.1.0', body='other notes\n')
        self.fake.tags['v0.1.0'] = COMMIT
        self.refused("published v0.1.0 release does not carry", self.publish)

    def test_the_draft_is_read_again_right_before_it_is_published(self):
        # Uploads and the readback take minutes; whatever changed meanwhile must stop the irreversible undraft.
        changed = 'the v0.1.0 draft changed before publication'
        cases = [
            ('flipped to prerelease during the readback', 'readback', lambda r: r.update(prerelease=True), changed),
            ('retargeted during the uploads', 'upload', lambda r: r.update(target_commitish='d' * 40), changed),
            ('moved to another tag during the readback', 'readback', lambda r: r.update(tag_name='v9.9.9'), changed),
            ('published by someone else during the readback', 'readback',
             lambda r: r.update(draft=False, immutable=True), changed),
            ('its tag pushed at another commit during the uploads', 'upload',
             lambda r: self.fake.tags.update({'v0.1.0': 'd' * 40}), 'tag v0.1.0 names another commit'),
            ('an asset added during the readback', 'readback', lambda r: self.fake.add_asset(r, 'extra.sh', b'x'),
             'the release does not carry exactly the publication assets'),
            ('its notes edited during the readback', 'readback', lambda r: r.update(body='edited\n'),
             "the v0.1.0 draft does not carry this publication's title and notes"),
            ('its title edited during the readback', 'readback', lambda r: r.update(name='Other title'),
             "the v0.1.0 draft does not carry this publication's title and notes"),
        ]
        for label, event, change, message in cases:
            with self.subTest(label):
                self.setUp()
                self.refused(message, self.publish, **{event: change})
                self.assertEqual(self.fake.undrafts, [], 'the draft must not be published')

    def test_the_undraft_request_sets_the_verified_title_and_notes_again(self):
        # An edit after the last read of the draft must not reach the immutable release.
        def edit(release):
            release.update(name='Other title', body='edited\n')
        self.publish(undraft=edit)
        release = next(r for r in self.fake.releases if r['tag_name'] == 'v0.1.0')
        self.assertEqual((release['draft'], release['name'], release['body']),
                         (False, publish.release_title('0.1.0'), self.notes.read_text()))

    def test_a_release_published_as_a_prerelease_or_under_another_tag_is_refused(self):
        message = 'the v0.1.0 release was published as a prerelease or under another tag'
        self.refused(message, self.publish, publish=lambda r: r.update(prerelease=True))
        self.setUp()
        # Its tag already names the release commit, so only the tag name tells.
        self.fake.add_release('v0.1.0', draft=True, immutable=False, assets={'SHA256SUMS': self.assets['SHA256SUMS']})
        self.fake.tags['v0.1.0'] = COMMIT
        self.refused(message, self.publish, publish=lambda r: r.update(tag_name='v9.9.9'))

    def test_the_undraft_request_names_this_tag_commit_and_full_release_again(self):
        # A change after the last read of the draft must not reach the immutable release: the request that publishes
        # it sets the tag, the commit and a full release again.
        for label, change in [('flipped to prerelease', lambda r: r.update(prerelease=True)),
                              ('retargeted', lambda r: r.update(target_commitish='d' * 40)),
                              ('moved to another tag', lambda r: r.update(tag_name='v9.9.9'))]:
            with self.subTest(label):
                self.setUp()
                self.assertEqual(self.publish(undraft=change)['state'], 'fresh')
                release = self.fake.releases[0]
                self.assertEqual((release['draft'], release['prerelease'], release['tag_name'],
                                  release['target_commitish'], self.fake.tags),
                                 (False, False, 'v0.1.0', COMMIT, {'v0.1.0': COMMIT}))
        with self.subTest('its tag pushed at another commit'):
            # GitHub keeps an existing tag whatever the request names, so only the check after publication tells.
            self.setUp()
            self.refused('tag v0.1.0 does not name the release commit', self.publish,
                         undraft=lambda r: self.fake.tags.update({'v0.1.0': 'd' * 40}))

    def test_publication_refusals(self):
        self.fake.corrupt = {'SHA256SUMS.asc'}
        self.refused('reads back differently', self.publish)
        self.setUp()
        self.fake.immutable_on_publish = False
        self.refused('not an immutable published release', self.publish)
        self.setUp()
        self.fake.tag_override = 'd' * 40
        self.refused('does not name the release commit', self.publish)

    def test_assets_added_or_misrecorded_after_classification_are_refused_while_a_draft(self):
        def extra(release):
            self.fake.add_asset(release, 'unsigned-extra.sh', b'#!/bin/sh\necho unsigned\n')

        def misrecorded(release):
            release['assets'][-1]['digest'] = 'sha256:' + '0' * 64
        for label, hook, message in [
                ('an extra asset', extra, 'the release does not carry exactly the publication assets'),
                ('a misrecorded API digest', misrecorded, 'the API digest of intel-npu-stack-0.1.0.tar differs')]:
            with self.subTest(label):
                self.setUp()
                self.refused(message, self.publish, upload=hook)
                self.assertEqual((len(self.fake.releases), self.fake.releases[0]['draft']), (1, True))
                self.assertNotIn('v0.1.0', self.fake.tags)
        with self.subTest('an extra asset once published'):
            self.setUp()
            self.refused('the release does not carry exactly the publication assets', self.publish, publish=extra)

    def use_assets(self, assets):
        for name, data in assets.items():
            (self.assets_dir / name).write_bytes(data)

    def refused_before_publication(self, message):
        self.refused(message, self.publish_phase)
        self.refused(message, self.publish)
        self.assertEqual(self.fake.releases, [], 'nothing may be created before the check')

    def test_the_publish_phase_needs_the_release_key(self):
        self.refused('committed release key is required', self.publish_phase, key=None)

    def test_the_preflight_needs_the_release_key_and_the_bytes_to_reserve(self):
        self.refused('committed release key is required', self.preflight, key=None)
        for reserve in [None, 0, -1, True]:
            with self.subTest(reserve=reserve):
                self.refused('the preflight needs a positive number of bytes to reserve', self.preflight,
                             reserve=reserve)
        self.assertEqual(self.fake.storage_auth, [])

    def test_nothing_is_created_that_compose_pages_would_refuse(self):
        # pages-build composes every served version with the new one; each of its gates must hold before anything
        # irreversible, or an immutable release could be published that Pages never serves.
        def older():
            return next(r for r in self.fake.releases if r['tag_name'] == 'v0.1.0')

        def retired_newer():  # a newer version still counts once it has left Pages
            self.published('0.3.0', self.assets3, self.site3, self.archive3)
            self.retired.append({'version': '0.3.0', 'sha256sums_sha256': sha(self.assets3['SHA256SUMS']),
                                 'reason': 'withdrawn'})

        def retire(sums):  # verify-live requires every file its SHA256SUMS lists gone
            self.fake.add_release('v0.0.5', assets={'SHA256SUMS': sums})
            self.retired.append({'version': '0.0.5', 'sha256sums_sha256': sha(sums), 'reason': 'withdrawn'})
        this = {'version': '0.2.0', 'sha256sums_sha256': sha(self.assets2['SHA256SUMS'])}
        room = publish.site_bytes(self.site2)
        unrecorded = 'tagged versions without an entry in published-versions.json: 0.1.0'
        cases = [
            ('an earlier version not recorded yet', lambda: self.recorded.clear(), None, unrecorded),
            ('an earlier version not recorded yet, its tag on a later page than the recorded ones',
             lambda: (self.recorded.clear(), self.retire_older_versions()), None, unrecorded),
            # GitHub keeps the tag of a deleted release, so the registry still has to account for the version.
            ('an earlier release deleted before it was recorded',
             lambda: (self.recorded.clear(), self.fake.releases.remove(older())), None, unrecorded),
            ('a mistyped registry digest', lambda: self.recorded[0].update(sha256sums_sha256='0' * 64), None,
             'published version 0.1.0 has another SHA256SUMS than recorded'),
            ('an older version that is not served', lambda: self.live.clear(), None,
             'the live 0.1.0/SHA256SUMS differs from its release (HTTP 404)'),
            ('older notes edited', lambda: older().update(body='edited\n'), None,
             'release v0.1.0 does not carry its title and rendered notes'),
            ('a stray mutable release', lambda: self.fake.add_release('v0.0.1', immutable=False), None,
             'release v0.0.1 is not immutable'),
            ('an older release flipped to prerelease', lambda: older().update(prerelease=True), None,
             'release v0.1.0 is marked a prerelease'),
            ('a newer release', lambda: self.fake.add_release('v0.3.0'), None,
             'versions are published in increasing order, and 0.2.0 is not newer than v0.3.0'),
            ('a newer release that is retired', retired_newer, None,
             'versions are published in increasing order, and 0.2.0 is not newer than v0.3.0'),
            ('this version already recorded', lambda: self.recorded.append(this), None,
             'published-versions.json already lists 0.2.0'),
            ('this version already retired', lambda: self.retired.append({**this, 'reason': 'withdrawn'}), None,
             'published-versions.json already lists 0.2.0'),
            ('no room for this version beside the served ones', lambda: None, room,
             f'the Pages site would be {publish.site_bytes(self.site) + room} bytes with 0.2.0, above the {room}-byte'),
        ]
        for label, damage, limit, message in cases:
            for phase in ['preflight', 'publish', 'publish-release']:
                with self.subTest(label, phase=phase):
                    self.setUp()
                    self.pending()
                    damage()
                    gate = {'preflight': self.preflight, 'publish': self.publish_phase, 'publish-release': self.publish}
                    with mock.patch.object(publish, 'MAX_SITE', limit or publish.MAX_SITE):
                        self.refused(message, gate[phase])
                    self.assertFalse(any(r['tag_name'] == 'v0.2.0' for r in self.fake.releases))
                    self.assertNotIn('v0.2.0', self.fake.tags)

    def test_what_the_room_check_composed_must_still_stand_at_the_undraft(self):
        # The uploads and the readback take minutes after the room check; a change to the versions already served in
        # that window must stop the irreversible undraft, not leave a release that Pages then refuses.
        def older():
            return next(r for r in self.fake.releases if r['tag_name'] == 'v0.1.0')
        cases = [
            ('an older release flipped to prerelease', lambda r: older().update(prerelease=True)),
            ('older notes edited', lambda r: older().update(body='edited\n')),
            ('an older release deleted, its tag kept', lambda r: self.fake.releases.remove(older())),
            ('a stray vX.Y.Z release', lambda r: self.fake.add_release('v0.0.9')),
            ('a stray vX.Y.Z tag', lambda r: self.fake.tags.update({'v0.1.5': COMMIT})),
            ('the older SHA256SUMS no longer served', lambda r: self.live.pop('/intel-npu-stack/0.1.0/SHA256SUMS')),
        ]
        for label, change in cases:
            with self.subTest(label):
                self.setUp()
                self.pending()
                with self.assertRaises(publish.PublishRefused):
                    self.publish(upload=change)
                new = next(r for r in self.fake.releases if r['tag_name'] == 'v0.2.0')
                self.assertEqual((new['draft'], self.fake.undrafts), (True, []))

    def test_a_change_during_the_room_check_stops_publication_before_a_draft_exists(self):
        # The room check downloads every served release; an edit meanwhile is refused before anything is created.
        self.pending()
        older = next(r for r in self.fake.releases if r['tag_name'] == 'v0.1.0')
        self.refused('the served releases or v tags changed during the room check', self.publish,
                     readback=lambda r: older.update(body='edited\n'))
        self.assertEqual([r['tag_name'] for r in self.fake.releases], ['v0.1.0'])

    def test_an_older_tag_moved_after_the_room_check_resolved_it_stops_publication(self):
        # The room check bound the older release to the commit its tag named. A force-moved tag makes the next
        # composition refuse that release, so the new one must not become immutable; the tag listing names each
        # tag's object, so no call per tag is needed to see the move.
        def move():
            self.fake.tags['v0.1.0'] = 'd' * 40
        with self.subTest('right after the room check resolved it'):
            self.pending()
            resolve = self.gh.tag_commit

            def resolve_then_move(tag):
                commit = resolve(tag)
                if tag == 'v0.1.0':
                    move()
                return commit
            with mock.patch.object(self.gh, 'tag_commit', resolve_then_move):
                self.refused('the served releases or v tags changed during the room check', self.publish)
            self.assertEqual([r['tag_name'] for r in self.fake.releases], ['v0.1.0'], 'no draft may be created')
        with self.subTest('during the uploads'):
            self.setUp()
            self.pending()
            self.refused('the served releases or v tags changed before publication', self.publish,
                         upload=lambda r: move())
            new = next(r for r in self.fake.releases if r['tag_name'] == 'v0.2.0')
            self.assertEqual((new['draft'], self.fake.undrafts), (True, []))
        with self.subTest('an annotated tag replaced by another tag object during the uploads'):
            # The listing names the tag object, not the commit behind it, and a signed tag moved by force gets a new
            # object.
            self.setUp()
            self.pending()
            self.fake.annotate('v0.1.0', 'a' * 40)
            self.refused('the served releases or v tags changed before publication', self.publish,
                         upload=lambda r: self.fake.annotate('v0.1.0', 'b' * 40, 'd' * 40))
            new = next(r for r in self.fake.releases if r['tag_name'] == 'v0.2.0')
            self.assertEqual((new['draft'], self.fake.undrafts), (True, []))

    def test_a_release_is_published_only_when_pages_can_serve_it_beside_every_older_version(self):
        self.pending()
        self.assertEqual(self.preflight(), 'fresh')
        self.assertEqual(self.publish_phase(), 'fresh')
        self.assertEqual(self.publish()['state'], 'fresh')
        # 0.2.0 is published but not served yet: a resumed run neither composes it nor looks for it live.
        self.assertEqual(self.publish_phase(), 'published-resume')
        self.assertEqual(self.publish()['state'], 'published-resume')
        manifest, output = self.compose(self.committed_registry())
        self.assertEqual(sorted(manifest['versions']), ['0.1.0', '0.2.0'])

    def test_resumed_publications_pass_the_same_dry_composition(self):
        # A resumed draft is still published, and a published release still needs pages-build to accept it.
        for state in ['draft-resume', 'published-resume']:
            with self.subTest(state):
                self.setUp()
                self.pending()
                if state == 'draft-resume':
                    release = self.fake.add_release('v0.2.0', draft=True, immutable=False,
                                                    assets={'SHA256SUMS': self.assets2['SHA256SUMS']})
                else:
                    release = self.published('0.2.0', self.assets2, self.site2, self.archive2)
                self.assertEqual(self.publish_phase(), state)
                self.live.clear()  # 0.1.0 is no longer served
                message = 'the live 0.1.0/SHA256SUMS differs from its release (HTTP 404)'
                self.refused(message, self.publish_phase)
                self.refused(message, self.publish)
                self.assertEqual((release['draft'], self.fake.undrafts, self.fake.upload_bodies),
                                 (state == 'draft-resume', [], []))

    def test_the_dry_composition_admits_a_site_that_fills_the_budget_exactly(self):
        self.pending()
        full = publish.site_bytes(self.site) + publish.site_bytes(self.site2)
        with mock.patch.object(publish, 'MAX_SITE', full):
            self.assertEqual(self.preflight(), 'fresh')
            self.assertEqual(self.publish_phase(), 'fresh')
        with mock.patch.object(publish, 'MAX_SITE', full - 1):
            self.refused(f'the Pages site would be {full} bytes with 0.2.0, above the {full - 1}-byte budget',
                         self.publish_phase)

    def test_the_room_check_leaves_out_a_retired_version_pages_still_serves(self):
        # The registry of this run retires 0.1.0, and the site this run deploys leaves it out, so its bytes are not
        # counted and whatever Pages still serves for it is not checked, neither by the room checks nor right before
        # publish-release publishes the release.
        for label, served in [('still served', self.assets['SHA256SUMS']), ('served with other bytes', b'other sums\n'),
                              ('no longer served', None)]:
            with self.subTest(label):
                self.setUp()
                self.pending()
                self.recorded = []
                self.retired = [{'version': '0.1.0', 'sha256sums_sha256': sha(self.assets['SHA256SUMS']),
                                 'reason': 'withdrawn'}]
                self.live = {} if served is None else {'/intel-npu-stack/0.1.0/SHA256SUMS': served}
                with mock.patch.object(publish, 'MAX_SITE', publish.site_bytes(self.site2)):
                    self.assertEqual(self.preflight(), 'fresh')
                    self.assertEqual(self.publish_phase(), 'fresh')
                    self.assertEqual(self.publish()['state'], 'fresh')

    def test_versions_are_ordered_by_number(self):
        for version in ['0.9.0', '0.10.0']:
            site, archive, assets = make_release(self.work / version, self.key, version)
            self.published(version, assets, site, archive)
            self.live[f'/intel-npu-stack/{version}/SHA256SUMS'] = assets['SHA256SUMS']
            if version == '0.9.0':  # recorded before 0.10.0 was published
                self.recorded = [{'version': version, 'sha256sums_sha256': sha(assets['SHA256SUMS'])}]
        self.assertEqual(list(self.compose(new_version='0.10.0')[0]['versions']), ['0.9.0', '0.10.0'])
        self.refused('the new version 0.9.0 is not the newest release 0.10.0', self.compose, new_version='0.9.0')
        self.values = self.version_values('0.9.1')
        self.refused('versions are published in increasing order, and 0.9.1 is not newer than v0.10.0',
                     self.preflight)

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
        self.use_assets(make_release(self.work / 'foreign', self.other, '0.1.0', installer_key=self.key,
                                     primary_fingerprint=self.key.fingerprint)[2])
        self.refused_before_publication('release-key policy: SHA256SUMS.asc')
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

    def test_the_installer_signature_is_verified_before_publication(self):
        for label, change in [('another key', {'installer_key': self.other}),
                              ('other bytes', {'installer_bytes': b'#!/bin/sh\nexit 1\n'})]:
            with self.subTest(label):
                self.setUp()
                self.use_assets(make_release(self.work / 'installer', self.key, '0.1.0', **change)[2])
                self.refused_before_publication('install.sh.asc')

    def test_a_noncanonical_archive_is_refused_before_publication(self):
        (self.assets_dir / 'intel-npu-stack-0.1.0.tar').write_bytes(noncanonical(self.archive))
        self.refused_before_publication('not the canonical archive of its site')

    def test_a_site_over_the_pages_budget_is_refused_before_publication(self):
        size = sum(path.stat().st_size for path in self.site.rglob('*') if path.is_file())
        with mock.patch.object(publish, 'MAX_SITE', size - 1):
            self.refused_before_publication(f'the 0.1.0 site is {size} bytes, above the {size - 1}-byte Pages budget')
        with mock.patch.object(publish, 'MAX_SITE', size):
            self.assertEqual(self.publish()['state'], 'fresh')

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
        self.headers_read(self.publish)
        self.assertEqual(self.fake.releases, [])
        self.headers_read(publish.unpack_release, self.flood(), '0.1.0', self.assets['SHA256SUMS'],
                          self.assets['SHA256SUMS.asc'], self.work / 'unpacked')
        self.headers_read(self.verify, lambda url, sink=None: (404, b''), archive=self.flood(),
                          pages_manifest=self.pages_record())

    def test_hidden_extension_headers_count_toward_the_member_limit(self):
        archive = self.work / 'long-names.tar'
        with tarfile.open(archive, 'w', format=tarfile.GNU_FORMAT) as tar:
            for index in range(30):  # each long name adds a GNU long-name header that tarfile never yields
                tar.addfile(tarfile.TarInfo(f'0.1.0/{"n" * 120}{index}'), io.BytesIO(b''))
        (self.assets_dir / 'intel-npu-stack-0.1.0.tar').write_bytes(archive.read_bytes())
        with mock.patch.object(publish, 'MAX_MEMBERS', 40):
            self.refused_before_publication('too many members: more than 40 tar headers')

    def test_a_release_archive_holds_only_regular_files_and_long_names(self):
        archive = self.work / 'pax.tar'
        with tarfile.open(archive, 'w', format=tarfile.PAX_FORMAT) as tar:
            info = tarfile.TarInfo('0.1.0/SHA256SUMS')
            info.mtime = 1.5
            tar.addfile(info, io.BytesIO(b''))
        (self.assets_dir / 'intel-npu-stack-0.1.0.tar').write_bytes(archive.read_bytes())
        self.refused_before_publication("tar header type b'x' is not allowed")

    def test_the_member_limit_admits_a_site_of_exactly_that_size(self):
        with tarfile.open(self.archive) as tar:
            count = len(tar.getmembers())
        with mock.patch.object(publish, 'MAX_MEMBERS', count - 1):
            self.refused_before_publication('too many members')
        with mock.patch.object(publish, 'MAX_MEMBERS', count):
            self.assertEqual(self.publish()['state'], 'fresh')

    # compose-pages -----------------------------------------------------------------------------------

    def registry(self, published=(), retired=()):
        path = self.work / 'published-versions.json'
        path.write_text(json.dumps({'schema_version': 1, 'published': list(published), 'retired': list(retired)}))
        return path

    def version_values(self, version):
        """The committed trust seam of a run that publishes this version."""
        return {**self.values, 'version': version, 'base_url': BASE_URL.replace('0.1.0', version)}

    def compose(self, registry=None, new_version='0.2.0', values=None, **kwargs):
        output, manifest = self.work / 'out/_site', self.work / 'out/pages-manifest.json'
        shutil.rmtree(self.work / 'out', ignore_errors=True)
        (self.work / 'out').mkdir()
        values = values or (self.values if new_version is None else self.version_values(new_version))
        return publish.compose_pages(self.gh, values, self.key.public, self.key.fingerprint,
                                     registry or self.committed_registry(), output, manifest, new_version,
                                     **{'fetch': self.fetch, **kwargs}), output

    def published(self, version, assets, site, archive):
        """An immutable release as publish-release leaves it: the assets, the title and the rendered notes."""
        release = self.fake.add_release('v' + version, assets=assets)
        release.update(name=f'Intel NPU Stack {version}', body=release_site.render_notes(site, archive).decode())
        return release

    def publish_both(self):
        """0.1.0 published, recorded and served, and 0.2.0 published by the run whose Pages are being built."""
        self.published('0.1.0', self.assets, self.site, self.archive)
        self.published('0.2.0', self.assets2, self.site2, self.archive2)
        self.live['/intel-npu-stack/0.1.0/SHA256SUMS'] = self.assets['SHA256SUMS']
        self.recorded = [{'version': '0.1.0', 'sha256sums_sha256': sha(self.assets['SHA256SUMS'])}]

    def test_composes_every_immutable_release_and_skips_drafts_and_other_tags(self):
        self.publish_both()
        self.fake.add_release('v0.3.0', draft=True, immutable=False, assets=self.assets2)
        self.fake.add_release('release-inputs-0.1.0', prerelease=True, assets={'release-inputs.tar.gz': b'x'})
        self.fake.tags['v0.3.0-rc1'] = COMMIT  # not a vX.Y.Z tag, so the registry need not record it
        registry = self.registry([{'version': '0.1.0', 'sha256sums_sha256': sha(self.assets['SHA256SUMS'])}])
        manifest, output = self.compose(registry)
        self.assertEqual((sorted(manifest['versions']), manifest['retired']), (['0.1.0', '0.2.0'], {}))
        self.assertEqual(sorted(p.name for p in output.iterdir()), ['0.1.0', '0.2.0'])
        self.assertEqual((output / '0.2.0/SHA256SUMS').read_bytes(), self.assets2['SHA256SUMS'])
        self.assertFalse((output / 'index.html').exists())

    def test_the_manifest_binds_each_release_to_its_id_and_the_commit_its_tag_names(self):
        # check-deploy compares both with the listings right before deploying. 0.1.0 was signed on another commit and
        # its tag is annotated, so the manifest must hold the commit the tag names, not the tag object.
        other = 'd' * 40
        site, archive, assets = make_release(self.work / 'elsewhere', self.key, '0.1.0', source_commit=other)
        older = self.fake.add_release('v0.1.0', assets=assets, commit=other)
        older.update(name=publish.release_title('0.1.0'), body=release_site.render_notes(site, archive).decode(),
                     target_commitish='main')  # GitHub keeps the branch a release was created from
        self.fake.annotate('v0.1.0', 'e' * 40, other)
        newer = self.published('0.2.0', self.assets2, self.site2, self.archive2)
        self.live['/intel-npu-stack/0.1.0/SHA256SUMS'] = assets['SHA256SUMS']
        self.recorded = [{'version': '0.1.0', 'sha256sums_sha256': sha(assets['SHA256SUMS'])}]
        manifest, _ = self.compose()
        bound = {version: (entry['release_id'], entry['commit']) for version, entry in manifest['versions'].items()}
        self.assertEqual(bound, {'0.1.0': (older['id'], other), '0.2.0': (newer['id'], COMMIT)})
        self.assertEqual(self.check_deploy(self.work / 'out/pages-manifest.json')['versions'], ['0.1.0', '0.2.0'])

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

    def test_a_retired_release_records_the_files_pages_could_have_served(self):
        # verify-live requires every file a retired SHA256SUMS lists gone from under that version's directory, one
        # fetch each. A SHA256SUMS that does not parse, lists an unsafe path or more files than a release archive may
        # hold belongs to a release compose-pages never served, so only its two sums files are recorded, and retiring
        # it stays possible.
        def retire(sums):
            self.setUp()
            self.publish_both()
            self.fake.add_release('v0.0.5', assets={'SHA256SUMS': sums})
            self.retired.append({'version': '0.0.5', 'sha256sums_sha256': sha(sums), 'reason': 'withdrawn'})
        for label, sums in [
                ('malformed', b'withdrawn\n'),
                ('an unsafe path', f'{"0" * 64}  ../0.1.0/release.json\n'.encode()),
                # With the two sums files, one file more than a release archive may hold.
                ('more files than a release archive may hold', many_sums(publish.MAX_MEMBERS - 1))]:
            with self.subTest(label):
                retire(sums)
                self.assertEqual(self.compose()[0]['retired']['0.0.5'], ['SHA256SUMS', 'SHA256SUMS.asc'])
        with self.subTest('as many files as a release archive may hold'):
            retire(many_sums(publish.MAX_MEMBERS - 2))
            self.assertEqual(len(self.compose()[0]['retired']['0.0.5']), publish.MAX_MEMBERS)

    def test_compose_refuses_a_release_whose_standalone_manifest_differs(self):
        self.publish_both()
        release = next(r for r in self.fake.releases if r['tag_name'] == 'v0.2.0')
        release['assets'] = [a for a in release['assets'] if a['name'] != 'publication-manifest.json']
        self.fake.add_asset(release, 'publication-manifest.json', b'{"stale": true}\n')
        self.refused('standalone publication-manifest.json differs', self.compose)

    def test_every_retired_entry_must_match_an_immutable_release(self):
        entry = {'version': '0.0.5', 'sha256sums_sha256': '0' * 64, 'reason': 'superseded'}
        missing = 'retired versions without an immutable release: 0.0.5'
        for label, damage, message in [
                ('no release', lambda: None, missing),
                ('only a draft', lambda: self.fake.add_release('v0.0.5', draft=True, immutable=False), missing),
                ('only a prerelease', lambda: self.fake.add_release('v0.0.5', prerelease=True),
                 'release v0.0.5 is marked a prerelease')]:
            with self.subTest(label):
                self.setUp()
                self.publish_both()
                damage()
                self.refused(message, self.compose, self.registry(retired=[entry]))
                self.assertFalse((self.work / 'out/_site').exists())

    def test_a_vXYZ_release_marked_prerelease_is_refused_rather_than_left_out(self):
        # publish-release never makes one; a release flipped to prerelease would silently leave Pages.
        recorded = [{'version': '0.1.0', 'sha256sums_sha256': sha(self.assets['SHA256SUMS'])}]
        for label, registry in [('not yet recorded', ()), ('recorded', recorded)]:
            with self.subTest(label):
                self.setUp()
                self.publish_both()
                next(r for r in self.fake.releases if r['tag_name'] == 'v0.1.0').update(prerelease=True)
                self.refused('release v0.1.0 is marked a prerelease', self.compose, self.registry(registry))
                self.assertFalse((self.work / 'out/_site').exists())

    def test_without_a_new_version_every_tagged_version_needs_an_entry(self):
        # Composing only what is already served exempts no version, the committed one included.
        self.publish_both()
        self.live['/intel-npu-stack/0.2.0/SHA256SUMS'] = self.assets2['SHA256SUMS']
        both = self.recorded + [{'version': '0.2.0', 'sha256sums_sha256': sha(self.assets2['SHA256SUMS'])}]
        manifest, output = self.compose(self.registry(both), new_version=None, values=self.version_values('0.2.0'))
        self.assertEqual(sorted(manifest['versions']), ['0.1.0', '0.2.0'])
        self.refused('tagged versions without an entry in published-versions.json: 0.2.0', self.compose,
                     self.registry(self.recorded), new_version=None, values=self.version_values('0.2.0'))
        self.assertFalse((self.work / 'out/_site').exists())

    def test_a_version_leaves_pages_only_through_a_reviewed_retired_entry(self):
        # A served version the registry does not record yet must not silently leave the site, even once its release
        # is deleted: GitHub keeps the tag, and every tagged version but the new one must be recorded.
        def delete():
            self.fake.releases.remove(next(r for r in self.fake.releases if r['tag_name'] == 'v0.1.0'))
        entry = {'version': '0.1.0', 'sha256sums_sha256': sha(self.assets['SHA256SUMS'])}
        unrecorded = 'tagged versions without an entry in published-versions.json: 0.1.0'
        # A retired entry must match an immutable release, so the refusal must not suggest retiring a deleted one.
        gone = ('published version 0.1.0 is missing; a deleted release can be neither served nor retired, so its '
                'entry and its tag are removed by hand after review')
        for label, damage, published, message in [
                ('served but not recorded yet', lambda: None, [], unrecorded),
                ('not recorded yet, its tag on a later page than the recorded ones', self.retire_older_versions, [],
                 unrecorded),
                ('deleted before it was recorded', delete, [], unrecorded),
                ('deleted once recorded', delete, [entry], gone)]:
            with self.subTest(label):
                self.setUp()
                self.publish_both()
                damage()
                self.refused(message, self.compose, self.registry(published, self.retired))
                self.assertFalse((self.work / 'out/_site').exists())

    def test_the_new_version_is_the_committed_version_and_the_newest(self):
        self.publish_both()
        self.refused('the new version 0.1.0 is not the committed version 0.2.0', self.compose, new_version='0.1.0',
                     values=self.version_values('0.2.0'))
        self.assertEqual(self.fake.storage_auth, [], 'nothing may be downloaded first')
        self.published('0.3.0', self.assets3, self.site3, self.archive3)
        self.refused('the new version 0.2.0 is not the newest release 0.3.0', self.compose)
        self.assertFalse((self.work / 'out/_site').exists())

    def test_a_rerun_of_an_older_pages_build_cannot_serve_a_retired_version_again(self):
        self.publish_both()
        retired = {'version': '0.1.0', 'sha256sums_sha256': sha(self.assets['SHA256SUMS']), 'reason': 'withdrawn'}
        self.assertEqual(sorted(self.compose(self.registry(retired=[retired]))[0]['versions']), ['0.2.0'])
        self.live = {'/intel-npu-stack/0.2.0/SHA256SUMS': self.assets2['SHA256SUMS']}  # 0.1.0 left Pages
        # The 0.1.0 run re-run: its commit names 0.1.0 and holds the registry from before the retirement.
        self.refused('the new version 0.1.0 is not the newest release 0.2.0', self.compose, self.registry(),
                     new_version='0.1.0')
        self.assertFalse((self.work / 'out/_site').exists())

    # check-deploy ------------------------------------------------------------------------------------

    def check_deploy(self, manifest, registry=None, version='0.2.0'):
        return publish.check_deploy(self.gh, self.version_values(version), registry or self.committed_registry(),
                                    manifest, fetch=self.fetch)

    def test_a_composition_is_deployed_only_while_it_is_still_current(self):
        # A job re-run reuses its run's artifacts, so a re-run of an older run's pages-deploy would put that run's
        # composition live again after a newer release changed what compose-pages serves.
        def older():
            return next(r for r in self.fake.releases if r['tag_name'] == 'v0.1.0')

        def newer_retired():  # a newer release counts once it has left Pages too
            self.published('0.3.0', self.assets3, self.site3, self.archive3)
            self.retired.append({'version': '0.3.0', 'sha256sums_sha256': sha(self.assets3['SHA256SUMS']),
                                 'reason': 'withdrawn'})

        def other_sums():
            next(a for a in older()['assets'] if a['name'] == 'SHA256SUMS').update(digest='sha256:' + '0' * 64)

        def no_sums():  # such as a release deleted and created again on its tag
            older()['assets'] = [asset for asset in older()['assets'] if asset['name'] != 'SHA256SUMS']

        def newer_deleted():  # GitHub keeps the tag of a deleted release, and compose-pages refuses it unrecorded
            self.fake.releases.remove(self.published('0.3.0', self.assets3, self.site3, self.archive3))
        stale = 'the composition of 0.2.0 is out of date: '
        unrecorded = 'tagged versions without an entry in published-versions.json: '
        cases = [
            ('a newer release', lambda: self.published('0.3.0', self.assets3, self.site3, self.archive3),
             stale + 'the newest release is 0.3.0'),
            ('a newer release that is retired', newer_retired, stale + 'the newest release is 0.3.0'),
            ('a newer release deleted, its tag kept', newer_deleted, unrecorded + '0.3.0'),
            ('an older tag without a registry entry', lambda: self.fake.tags.update({'v0.0.5': COMMIT}),
             unrecorded + '0.0.5'),
            ('a composed release deleted', lambda: self.fake.releases.remove(older()),
             stale + 'compose-pages would serve 0.2.0, not 0.1.0, 0.2.0'),
            ('an older release added', lambda: self.fake.add_release('v0.0.9', assets={'SHA256SUMS': b'sums\n'}),
             stale + 'compose-pages would serve 0.0.9, 0.1.0, 0.2.0, not 0.1.0, 0.2.0'),
            ('a composed release now with another SHA256SUMS', other_sums,
             stale + 'release v0.1.0 is not the release it composed'),
            ('a composed release now without its SHA256SUMS', no_sums,
             stale + 'release v0.1.0 is not the release it composed'),
            ('a composed older version no longer served', lambda: self.live.clear(),
             'the live 0.1.0/SHA256SUMS differs from its release (HTTP 404)'),
            ('a composed older version served with other bytes',
             lambda: self.live.update({'/intel-npu-stack/0.1.0/SHA256SUMS': b'other sums\n'}),
             'the live 0.1.0/SHA256SUMS differs from its release (HTTP 200)'),
        ]
        for label, change, message in cases:
            with self.subTest(label):
                self.setUp()
                self.publish_both()
                self.compose()
                manifest = self.work / 'out/pages-manifest.json'
                # The new version is not served before its first deployment, so only the older ones must be live.
                self.assertEqual(self.check_deploy(manifest), {'new_version': '0.2.0', 'versions': ['0.1.0', '0.2.0']})
                change()
                self.refused(message, self.check_deploy, manifest)

    def test_a_redeployment_cannot_serve_again_an_older_version_a_later_deployment_removed(self):
        # The run of 0.2.0 composed 0.1.0 and 0.2.0. The run of 0.3.0 retired 0.1.0 and deployed, so 0.1.0 left
        # Pages; then 0.3.0 was deleted, and its entry and its tag removed by hand. Every listing is again as the
        # 0.2.0 run composed it, so only the live site shows that its composition is no longer current.
        self.publish_both()
        self.compose()
        manifest = self.work / 'out/pages-manifest.json'
        newer = self.published('0.3.0', self.assets3, self.site3, self.archive3)
        self.live = {'/intel-npu-stack/0.2.0/SHA256SUMS': self.assets2['SHA256SUMS'],
                     '/intel-npu-stack/0.3.0/SHA256SUMS': self.assets3['SHA256SUMS']}
        self.fake.releases.remove(newer)
        del self.fake.tags['v0.3.0']
        self.refused('the live 0.1.0/SHA256SUMS differs from its release (HTTP 404)', self.check_deploy, manifest)
        # Had 0.1.0 stayed on Pages, the re-run would serve what is live without the deleted release.
        self.live['/intel-npu-stack/0.1.0/SHA256SUMS'] = self.assets['SHA256SUMS']
        self.assertEqual(self.check_deploy(manifest)['versions'], ['0.1.0', '0.2.0'])

    def test_a_composed_release_replaced_or_retargeted_on_its_tag_is_no_longer_current(self):
        # A release deleted and created again on its tag with a copy of its SHA256SUMS keeps every digest the
        # composition recorded, and its tag can then name another commit. compose-pages binds each release it composes
        # to the commit its tag names, so it would no longer compose that pair: the deployment must stop too.
        other = 'd' * 40

        def release(version):
            return next(r for r in self.fake.releases if r['tag_name'] == 'v' + version)

        def replaced(version, commit=COMMIT):
            def change():
                old = release(version)
                self.fake.releases.remove(old)
                again = self.fake.add_release('v' + version, commit=commit)
                again.update(name=old['name'], body=old['body'])
                for asset in old['assets']:
                    self.fake.add_asset(again, asset['name'], self.fake.blobs[asset['id']])
            return change

        def without_ids():  # GitHub always lists an id; a record without one must not match a release without one
            del release('0.1.0')['id']
            edit(lambda entry: entry.pop('release_id'))

        def without_commit():  # a missing tag must not match a record without a commit
            del self.fake.tags['v0.1.0']
            edit(lambda entry: entry.pop('commit'))

        def edit(change):
            record = json.loads(manifest.read_text())
            change(record['versions']['0.1.0'])
            manifest.write_text(json.dumps(record))
        stale = 'the composition of 0.2.0 is out of date: '
        older_release, newer_release = ('release v0.1.0 is not the release it composed',
                                        'release v0.2.0 is not the release it composed')
        older_tag, newer_tag = ('tag v0.1.0 no longer names the commit it composed',
                                'tag v0.2.0 no longer names the commit it composed')
        cases = [
            ('the older release replaced on its tag', replaced('0.1.0'), older_release),
            ('the new release replaced on its tag', replaced('0.2.0'), newer_release),
            ('the older release replaced on another commit', replaced('0.1.0', other), older_release),
            ('a record whose release id is text',
             lambda: edit(lambda entry: entry.update(release_id=str(entry['release_id']))), older_release),
            ('neither the release nor the record with an id', without_ids, older_release),
            ('the older tag moved to another commit', lambda: self.fake.tags.update({'v0.1.0': other}), older_tag),
            ('the new tag moved to another commit', lambda: self.fake.tags.update({'v0.2.0': other}), newer_tag),
            ('the older tag annotated on another commit', lambda: self.fake.annotate('v0.1.0', 'e' * 40, other),
             older_tag),
            ('the older tag deleted', lambda: self.fake.tags.pop('v0.1.0'), older_tag),
            ('neither the tag nor the record with a commit', without_commit, older_tag),
            ('a record of another commit', lambda: edit(lambda entry: entry.update(commit=other)), older_tag),
        ]
        for label, change, message in cases:
            with self.subTest(label):
                self.setUp()
                self.publish_both()
                self.compose()
                manifest = self.work / 'out/pages-manifest.json'
                self.assertEqual(self.check_deploy(manifest)['versions'], ['0.1.0', '0.2.0'])
                change()
                self.refused(stale + message, self.check_deploy, manifest)
        # The binding is to the commit, so a tag re-made as an annotated tag of the same commit still deploys.
        self.setUp()
        self.publish_both()
        self.compose()
        self.fake.annotate('v0.1.0', 'e' * 40, COMMIT)
        self.assertEqual(self.check_deploy(self.work / 'out/pages-manifest.json')['versions'], ['0.1.0', '0.2.0'])

    def test_the_deploy_check_orders_versions_by_number(self):
        composed = {}
        for version in ['0.9.0', '0.10.0']:
            release = self.fake.add_release('v' + version, assets={'SHA256SUMS': f'{version} sums\n'.encode()})
            composed[version] = {'sha256sums_sha256': sha(f'{version} sums\n'.encode()), 'release_id': release['id'],
                                 'commit': COMMIT}
        self.live['/intel-npu-stack/0.9.0/SHA256SUMS'] = b'0.9.0 sums\n'
        registry = self.registry([{'version': '0.9.0', 'sha256sums_sha256': composed['0.9.0']['sha256sums_sha256']}])
        manifest = self.pages_record(base_url=BASE_URL.replace('0.1.0', '0.10.0'), new_version='0.10.0',
                                     versions=composed)
        self.assertEqual(self.check_deploy(manifest, registry, '0.10.0'),
                         {'new_version': '0.10.0', 'versions': ['0.9.0', '0.10.0']})
        self.fake.add_release('v0.11.0', assets={'SHA256SUMS': b'0.11.0 sums\n'})
        self.refused('the composition of 0.10.0 is out of date: the newest release is 0.11.0', self.check_deploy,
                     manifest, registry, '0.10.0')

    def test_the_deployed_versions_are_the_releases_the_run_registry_does_not_retire(self):
        self.publish_both()
        retired = self.registry(retired=[{'version': '0.1.0', 'sha256sums_sha256': sha(self.assets['SHA256SUMS']),
                                          'reason': 'withdrawn'}])
        manifest = self.work / 'out/pages-manifest.json'
        self.compose(retired)
        self.assertEqual(self.check_deploy(manifest, retired), {'new_version': '0.2.0', 'versions': ['0.2.0']})
        # A retired version is not composed, so it is not checked live either: Pages may serve it, with any bytes,
        # until a deployment leaves it out, and a re-run after that finds it gone.
        for label, served in [('served with other bytes', b'other sums\n'), ('no longer served', None)]:
            with self.subTest(label):
                self.live = {} if served is None else {'/intel-npu-stack/0.1.0/SHA256SUMS': served}
                self.assertEqual(self.check_deploy(manifest, retired)['versions'], ['0.2.0'])
        # Drafts, releases of other tags and other tags are never composed, so they change nothing.
        self.fake.add_release('v0.3.0', draft=True, immutable=False, assets=self.assets3)
        self.fake.add_release('release-inputs-0.3.0', prerelease=True, assets={'release-inputs.tar.gz': b'x'})
        self.fake.tags['v0.3.0-rc1'] = COMMIT
        self.assertEqual(self.check_deploy(manifest, retired)['versions'], ['0.2.0'])
        self.refused('the composition of 0.2.0 is out of date: compose-pages would serve 0.1.0, 0.2.0, not 0.2.0',
                     self.check_deploy, manifest, self.registry(self.recorded))
        invalid = self.work / 'invalid-registry.json'
        invalid.write_text('{"schema_version": 1}')
        self.refused('published-versions.json must be schema 1', self.check_deploy, manifest, invalid)

    def test_the_deploy_check_first_requires_the_record_of_composing_this_version(self):
        release = self.published('0.1.0', self.assets, self.site, self.archive)
        self.fake.fail[('GET', f'/repos/{REPOSITORY}/releases')] = 500  # a listing before the record check fails
        malformed = self.work / 'pages-manifest-list.json'
        malformed.write_text('[]')
        unretired = self.pages_record()
        unretired.write_text(json.dumps({key: value for key, value in json.loads(unretired.read_text()).items()
                                         if key != 'retired'}))
        for label, record in [('not an object', malformed),
                              ('another schema', self.pages_record(schema_version=2)),
                              ('another base URL', self.pages_record(base_url=BASE_URL.replace('0.1.0', '0.0.9'))),
                              ('composed without a new version', self.pages_record(new_version=None)),
                              ('another new version', self.pages_record(new_version='0.0.9')),
                              ('versions that are not an object', self.pages_record(versions=[])),
                              # compose-pages records the retired versions it left out, if only as {}.
                              ('no retired versions', unretired),
                              ('retired versions in a list', self.pages_record(retired=['0.0.9']))]:
            with self.subTest(label):
                self.refused('the Pages manifest is not the record of composing 0.1.0', self.check_deploy, record,
                             self.registry(), '0.1.0')
        self.fake.fail.clear()
        composed = {'0.1.0': {**self.pages_entry(), 'release_id': release['id'], 'commit': COMMIT}}
        self.assertEqual(self.check_deploy(self.pages_record(versions=composed), self.registry(), '0.1.0'),
                         {'new_version': '0.1.0', 'versions': ['0.1.0']})

    def compose_into(self, output, manifest, fetch=None):
        return publish.compose_pages(self.gh, self.version_values('0.2.0'), self.key.public, self.key.fingerprint,
                                     self.committed_registry(), output, manifest, '0.2.0', fetch=fetch or self.fetch)

    def test_the_manifest_path_is_checked_before_anything_is_downloaded(self):
        self.publish_both()
        (self.work / 'out').mkdir()
        site, record = self.work / 'out/_site', self.work / 'out/record'
        for label, output, manifest in [('in a missing directory', site, self.work / 'out/missing/pages-manifest.json'),
                                        ('the site itself', site, site),
                                        ('inside the site', site, site / 'pages-manifest.json'),
                                        ('an ancestor of the site', record / '_site', record)]:
            with self.subTest(label):
                self.refused('the Pages manifest must be a new file in an existing directory, neither inside the site '
                             'nor containing it', self.compose_into, output, manifest)
                self.assertEqual((self.fake.storage_auth, output.exists(), manifest.exists()), ([], False, False))

    def test_a_failed_manifest_write_leaves_no_site_and_removes_only_its_own_manifest(self):
        self.publish_both()
        (self.work / 'out').mkdir()
        output, manifest = self.work / 'out/_site', self.work / 'out/pages-manifest.json'

        def racing(url, sink=None):  # another writer creates the manifest after the up-front check
            if not manifest.exists():
                manifest.write_text('theirs\n')
            return self.fetch(url, sink)
        with self.assertRaises(FileExistsError):
            self.compose_into(output, manifest, racing)
        self.assertEqual((output.exists(), manifest.read_text()), (False, 'theirs\n'))
        manifest.unlink()

        class FullDisk:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *failure):
                self.stream.close()

            def write(self, data):
                raise OSError(errno.ENOSPC, 'No space left on device')

        def full_disk(path, *args, **kwargs):
            stream = open(path, *args, **kwargs)
            return FullDisk(stream) if Path(path) == manifest else stream
        with mock.patch.object(publish, 'open', full_disk, create=True), self.assertRaises(OSError):
            self.compose_into(output, manifest)
        self.assertEqual((output.exists(), manifest.exists()), (False, False))

    def test_retired_versions_are_left_out_and_recorded_for_verify_live(self):
        # verify-live requires every file of a retired version gone: each one its SHA256SUMS lists and the two sums
        # files.
        self.publish_both()
        registry = self.registry(retired=[{'version': '0.1.0', 'sha256sums_sha256': sha(self.assets['SHA256SUMS']),
                                           'reason': 'superseded'}])
        manifest, output = self.compose(registry)
        gone = {'0.1.0': sorted(release_site.site_files(self.site))}
        self.assertEqual((sorted(manifest['versions']), manifest['retired']), (['0.2.0'], gone))
        self.assertEqual(json.loads((self.work / 'out/pages-manifest.json').read_text())['retired'], gone)
        self.assertFalse((output / '0.1.0').exists())

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
                self.published('0.1.0', self.assets, self.site, self.archive)
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

    def test_compose_verifies_each_release_installer_signature(self):
        site, archive, assets = make_release(self.work / 'installer', self.key, '0.2.0', installer_key=self.other)
        self.published('0.1.0', self.assets, self.site, self.archive)
        self.published('0.2.0', assets, site, archive)
        self.live['/intel-npu-stack/0.1.0/SHA256SUMS'] = self.assets['SHA256SUMS']
        self.refused('install.sh.asc', self.compose)
        self.assertFalse((self.work / 'out/_site').exists())

    def test_compose_requires_each_release_to_carry_its_title_and_rendered_notes(self):
        for label, change in [('another title', {'name': 'Intel NPU Stack'}),
                              ('stale notes', {'body': '# Intel NPU Stack 0.2.0\n'}),
                              ('edited notes', None)]:
            with self.subTest(label):
                self.setUp()
                self.publish_both()
                release = next(r for r in self.fake.releases if r['tag_name'] == 'v0.2.0')
                release.update(change or {'body': release['body'].replace('| SHA256SUMS | `', '| SHA256SUMS | `0')})
                self.refused('release v0.2.0 does not carry its title and rendered notes', self.compose)
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
            ('symlink member', "tar header type b'2' is not allowed", lambda: replace('0.2.0', tar_name, retar(
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

    def test_a_retired_entry_needs_a_reason(self):
        for reason in ['', '   ', None]:
            with self.subTest(reason=reason):
                self.setUp()
                self.publish_both()
                registry = self.registry(retired=[{'version': '0.1.0', 'reason': reason,
                                                   'sha256sums_sha256': sha(self.assets['SHA256SUMS'])}])
                self.refused('a retired version needs a reason', self.compose, registry)
                self.assertFalse((self.work / 'out/_site').exists())

    def test_the_new_version_must_be_composed(self):
        for label, damage in [('missing from the listing', lambda: None),
                              ('left as a draft', lambda: self.fake.add_release('v0.2.0', draft=True, immutable=False,
                                                                                 assets=self.assets2))]:
            with self.subTest(label):
                self.setUp()
                self.published('0.1.0', self.assets, self.site, self.archive)
                self.live['/intel-npu-stack/0.1.0/SHA256SUMS'] = self.assets['SHA256SUMS']
                damage()
                self.refused('the new version 0.2.0 is not composed', self.compose)
                self.assertFalse((self.work / 'out/_site').exists())

    def test_compose_compares_older_versions_past_the_cdn_cache(self):
        self.publish_both()

        def cdn(url, sink=None):  # the edge still serves the old 0.1.0/SHA256SUMS, origin serves other bytes
            parts = urllib.parse.urlsplit(url)
            if parts.path == '/intel-npu-stack/0.1.0/SHA256SUMS' and parts.query:
                return answer(200, b'changed at origin\n', sink)
            return self.fetch(url, sink)
        self.refused('the live 0.1.0/SHA256SUMS differs from its release (HTTP 200)', self.compose, fetch=cdn)

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

    def pages_entry(self, archive=None):
        """What compose-pages records for 0.1.0: the digests of its archive and of the archive's SHA256SUMS."""
        archive = Path(archive or self.archive)
        with tarfile.open(archive) as tar:
            sums = [tar.extractfile(member).read() for member in tar.getmembers()
                    if member.name == '0.1.0/SHA256SUMS' and member.isreg()]
        return {'archive_sha256': sha(archive.read_bytes()), 'sha256sums_sha256': sha(sums[-1] if sums else b'')}

    def pages_record(self, archive=None, **changes):
        """The pages-manifest.json compose-pages wrote with 0.1.0 as the new version and this archive, with changes."""
        record = {'schema_version': 1, 'base_url': BASE_URL, 'new_version': '0.1.0', 'total_bytes': 1,
                  'versions': {'0.1.0': self.pages_entry(archive)}, 'retired': {}, **changes}
        path = self.work / f'pages-manifest-{len(list(self.work.glob("pages-manifest-*.json")))}.json'
        path.write_text(json.dumps(record))
        return path

    def verify(self, fetch, archive=None, pages_manifest=None, commit=COMMIT, sleeps=None, **kwargs):
        """verify-live against this fetch; the Pages record is by default the one composed with this archive."""
        sleeps = [] if sleeps is None else sleeps
        clock = iter(range(0, 100000, 30))
        result = publish.verify_live(self.values, self.key.public, self.key.fingerprint, archive or self.archive,
                                     pages_manifest=pages_manifest or self.pages_record(archive), commit=commit,
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
        self.refused('the live repodata/repomd.xml is still stale or missing at its plain URL (HTTP 200)', self.verify,
                     self.serve_live(broken, '0.1.0'), timeout=90)
        shutil.rmtree(broken.parent)
        shutil.copytree(self.site, broken)
        (broken / 'install.sh.asc').unlink()
        self.refused('the live install.sh.asc is still stale or missing at its plain URL (HTTP 404)', self.verify,
                     self.serve_live(broken, '0.1.0'), timeout=90)
        shutil.rmtree(broken.parent)
        shutil.copytree(self.site, broken)
        (broken / 'publication-manifest.json').write_bytes(b'{"changed": true}\n')
        self.refused('the live publication-manifest.json is still stale or missing at its plain URL (HTTP 200)',
                     self.verify, self.serve_live(broken, '0.1.0'), timeout=90)
        other = self.work / 'noncanonical.tar'
        with tarfile.open(other, 'w', format=tarfile.GNU_FORMAT) as tar:
            for relative in release_site.site_files(self.site):
                tar.add(self.site / relative, arcname='0.1.0/' + relative)
        self.refused('repack', self.verify, self.serve_live(self.site, '0.1.0'), archive=other)

    def test_live_files_must_be_exactly_the_signed_sums(self):
        for label, change, message in [
                ('edited after signing', lambda site: (site / 'release.json').write_bytes(b'{"edited": true}\n'),
                 'the live release.json differs from the signed SHA256SUMS'),
                ('unlisted file', lambda site: (site / 'extra.txt').write_bytes(b'extra\n'),
                 'the live files are not exactly the files the signed SHA256SUMS lists')]:
            with self.subTest(label):
                self.setUp()
                site = self.work / 'edited/0.1.0'
                shutil.copytree(self.site, site)
                change(site)
                archive = self.work / 'intel-npu-stack-0.1.0.tar'
                with archive.open('xb') as stream:
                    release_site.write_archive(site, stream)
                self.refused(message, self.verify, self.serve_live(site, '0.1.0'), archive=archive)

    def test_live_verification_is_bound_to_the_signed_release_identity(self):
        for label, identity in [('an older signed site repacked under this version', {'pinned': '0.0.9'}),
                                ('another base URL', {'base_url': 'https://archledger.github.io/other/0.1.0/'}),
                                ('another release key', {'primary_fingerprint': self.other.fingerprint})]:
            with self.subTest(label):
                self.setUp()
                site, archive, _ = make_release(self.work / 'old', self.key, '0.1.0', **identity)
                self.refused('the signed publication manifest in the 0.1.0 archive names another release',
                             self.verify, self.serve_live(site, '0.1.0'), archive=archive)
        with self.subTest('another commit'):
            self.setUp()
            self.refused('names another release', self.verify, self.serve_live(self.site, '0.1.0'), commit='d' * 40)
            self.assertTrue(self.verify(self.serve_live(self.site, '0.1.0'), commit=COMMIT)[0]['passed'])

    def test_the_wait_counts_network_errors_as_not_converged_until_the_timeout(self):
        live = self.serve_live(self.site, '0.1.0')
        outages = [2]

        def flaky(url, sink=None):
            if outages[0] and not urllib.parse.urlsplit(url).query:
                outages[0] -= 1
                raise publish.NetworkRefused(f'GET {url} failed: [Errno 104] Connection reset by peer')
            return live(url, sink)
        result, sleeps = self.verify(flaky)
        self.assertEqual((result['passed'], len(sleeps)), (True, 2))

        def down(url, sink=None):
            raise publish.NetworkRefused(f'GET {url} failed: [Errno 111] Connection refused')
        sleeps = []
        self.refused(f'the live site could not be read before the timeout: GET {BASE_URL}release.json failed: '
                     '[Errno 111] Connection refused', self.verify, down, timeout=90, sleeps=sleeps)
        self.assertEqual(len(sleeps), 2)

    def test_every_file_is_polled_at_its_plain_url_until_it_serves_the_release(self):
        # Users fetch every file at its plain URL, so an RPM the CDN still serves stale once the paths the installer
        # reads first have converged keeps the wait going. A file is fetched there until it serves the release and
        # never again, and a round stops at its first stale response, so the wait stays bounded on a large site.
        rpm = 'packages/fixture-1.0-1.fc44.x86_64.rpm'
        site, archive, _ = make_release(self.work / 'packages', self.key, '0.1.0', extra={rpm: b'\xed\xab\xee\xdb\n'})
        live, events, stale = self.serve_live(site, '0.1.0'), [], {rpm: 3, 'support-matrix.json': 1}

        def edge(url, sink=None):  # events records (path, stale) for each plain fetch and 30 for each pause
            parts = urllib.parse.urlsplit(url)
            path = parts.path.removeprefix('/intel-npu-stack/0.1.0/')
            if parts.query:
                return live(url, sink)
            events.append((path, bool(stale.get(path))))
            if stale.get(path):
                stale[path] -= 1
                return answer(200, b'old\n', sink)
            return live(url, sink)
        self.assertTrue(self.verify(edge, archive=archive, sleeps=events)[0]['passed'])
        rounds = [[]]
        for event in events:
            if event == 30:
                rounds.append([])
            else:
                rounds[-1].append(event)
        self.assertEqual([[path for path, old in fetches if old] for fetches in rounds],
                         [[rpm], [rpm], [rpm], ['support-matrix.json'], []])
        self.assertEqual(sorted(path for fetches in rounds for path, old in fetches if not old),
                         release_site.site_files(site))
        outages = [2]

        def unreachable(url, sink=None):  # right after a deployment, a network error only means not converged yet
            if url == BASE_URL + rpm and outages[0]:
                outages[0] -= 1
                raise publish.NetworkRefused(f'GET {url} failed: [Errno 104] Connection reset by peer')
            return live(url, sink)
        result, sleeps = self.verify(unreachable, archive=archive)
        self.assertEqual((result['passed'], len(sleeps)), (True, 2))
        for label, fetch, status in [
                ('stale until the timeout', self.serve_live(site, '0.1.0', {rpm: 1000}), 200),
                ('missing until the timeout', lambda url, sink=None: (404, b'') if url == BASE_URL + rpm
                 else live(url, sink), 404)]:
            with self.subTest(label):
                sleeps = []
                self.refused(f'the live {rpm} is still stale or missing at its plain URL (HTTP {status})',
                             self.verify, fetch, archive=archive, timeout=90, sleeps=sleeps)
                self.assertEqual(len(sleeps), 2)

    def test_other_errors_and_errors_after_the_wait_fail_at_once(self):
        live = self.serve_live(self.site, '0.1.0')

        def oversized(url, sink=None):
            raise publish.PublishRefused('response exceeds the size limit')

        def reset_during_the_download(url, sink=None):
            if urllib.parse.urlsplit(url).query:
                raise publish.NetworkRefused(f'GET {url} failed: [Errno 104] Connection reset by peer')
            return live(url, sink)
        for label, fetch, message in [('a size limit during the wait', oversized, 'response exceeds the size limit'),
                                      ('a network error after the wait', reset_during_the_download, 'reset by peer')]:
            with self.subTest(label):
                sleeps = []
                self.refused(message, self.verify, fetch, sleeps=sleeps)
                self.assertEqual(sleeps, [])

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

    def test_verify_live_needs_the_release_commit(self):
        fetched = []
        for commit in [None, 'D' * 40, 'd' * 39]:
            with self.subTest(commit=commit):
                self.refused('verify-live needs the 40-hex release commit', self.verify,
                             lambda url, sink=None: fetched.append(url), commit=commit)
        self.assertEqual(fetched, [])

    def test_the_pages_manifest_must_be_the_record_of_composing_this_version(self):
        fetched, files = [], ['SHA256SUMS', 'SHA256SUMS.asc', 'release.json']
        malformed = self.work / 'pages-manifest-list.json'
        malformed.write_text('[]')
        unretired = self.pages_record()
        unretired.write_text(json.dumps({key: value for key, value in json.loads(unretired.read_text()).items()
                                         if key != 'retired'}))
        for label, record in [('not an object', malformed),
                              ('another schema', self.pages_record(schema_version=2)),
                              ('another base URL', self.pages_record(base_url='https://archledger.github.io/o/0.1.0/')),
                              ('composed without a new version', self.pages_record(new_version=None)),
                              ('another new version', self.pages_record(new_version='0.0.9')),
                              ('versions that are not an object', self.pages_record(versions=[])),
                              ('no retired versions', unretired),
                              # A list or a string names no files to require gone; an empty one would check nothing.
                              ('retired versions in a list', self.pages_record(retired=['0.0.9'])),
                              ('retired versions in an empty string', self.pages_record(retired='')),
                              ('a retired entry that is not a version',
                               self.pages_record(retired={'0.0.9': files, '../0': files})),
                              ('a retired entry that only starts with a version',
                               self.pages_record(retired={'0.0.9': files, '0.0.9-x': files})),
                              # Each character of this name alone would pass as a plain path.
                              ('retired files that are not a list',
                               self.pages_record(retired={'0.0.9': 'SHA256SUMS'})),
                              ('a retired file that is not a string',
                               self.pages_record(retired={'0.0.9': [*files, 1]})),
                              ('a retired file that is not a plain path',
                               self.pages_record(retired={'0.0.9': [*files, '../0.1.0/release.json']}))]:
            with self.subTest(label):
                self.refused('the Pages manifest is not the record of composing 0.1.0', self.verify,
                             lambda url, sink=None: fetched.append(url), pages_manifest=record)
        self.assertEqual(fetched, [], 'nothing is fetched before the record is checked')

    def test_the_pages_manifest_must_record_this_archive_and_its_sums(self):
        # verify-live qualifies the archive compose-pages recorded for this version, and no other.
        fetched, entry = [], self.pages_entry()
        unrecorded = 'the Pages manifest does not record this 0.1.0 archive and its SHA256SUMS'
        for label, record, message in [
                ('no entry for this version', self.pages_record(versions={}), unrecorded),
                ('an entry that is not an object', self.pages_record(versions={'0.1.0': entry['archive_sha256']}),
                 unrecorded),
                # Neither digest may be missing: a record written before archive digests were recorded has only one.
                ('an entry without the archive digest',
                 self.pages_record(versions={'0.1.0': {'sha256sums_sha256': entry['sha256sums_sha256']}}), unrecorded),
                ('an entry without the SHA256SUMS digest',
                 self.pages_record(versions={'0.1.0': {'archive_sha256': entry['archive_sha256']}}), unrecorded),
                ('another archive', self.pages_record(versions={'0.1.0': {**entry, 'archive_sha256': '0' * 64}}),
                 unrecorded),
                ('other sums', self.pages_record(versions={'0.1.0': {**entry, 'sha256sums_sha256': '0' * 64}}),
                 unrecorded),
                ('this archive recorded by the run of another version', self.pages_record(new_version='0.2.0'),
                 'the Pages manifest is not the record of composing 0.1.0')]:
            with self.subTest(label):
                self.refused(message, self.verify, lambda url, sink=None: fetched.append(url), pages_manifest=record)
        self.assertEqual(fetched, [], 'nothing is fetched before the record is checked')
        result, _ = self.verify(self.serve_live(self.site, '0.1.0'), pages_manifest=self.pages_record())
        self.assertEqual((result['passed'], result['archive_sha256']), (True, entry['archive_sha256']))

    def test_retired_versions_must_be_gone_at_every_plain_url_and_past_the_cdn_cache(self):
        # compose-pages left them out and recorded their files. The CDN caches each URL on its own, so every file
        # must return 404 where users fetch it, the installer and the packages as much as release.json, and
        # release.json and SHA256SUMS past the CDN cache too, where the version's directory leaves as a whole. Every
        # retired version is checked, the older of two as much as the newer.
        gone = {old: sorted([*release_site.site_files(self.site), f'packages/fixture-{old}-1.fc44.x86_64.rpm'])
                for old in ['0.0.8', '0.0.9']}
        live, record = self.serve_live(self.site, '0.1.0'), self.pages_record(retired=gone)

        def lingering(name=None, busted=False, times=0, status=200, fetched=None):
            """Every retired file returns 404 but name, a version/path that first answers times with status, or with a
            network error when status is None, at its plain URL or past the CDN cache."""
            served = [times]

            def fetch(url, sink=None):
                parts = urllib.parse.urlsplit(url)
                path = parts.path.removeprefix('/intel-npu-stack/')
                if path.startswith('0.1.0/'):
                    return live(url, sink)
                if fetched is not None:
                    fetched.append((path, bool(parts.query)))
                if path == name and bool(parts.query) == busted and served[0]:
                    served[0] -= 1
                    if status is None:
                        raise publish.NetworkRefused(f'GET {parts._replace(query="").geturl()} failed: '
                                                     '[Errno 104] Connection reset by peer')
                    return answer(status, b'retired\n', sink)
                return 404, b''
            return fetch
        fetched = []
        result, sleeps = self.verify(lingering(fetched=fetched), pages_manifest=record)
        self.assertEqual((result['passed'], result['retired_versions'], sleeps), (True, ['0.0.8', '0.0.9'], []))
        self.assertEqual(sorted(fetched), sorted([(f'{old}/{path}', False) for old in gone for path in gone[old]]
                                                 + [(f'{old}/{name}', True) for old in gone
                                                    for name in ['release.json', 'SHA256SUMS']]))
        rpm = 'packages/fixture-0.0.9-1.fc44.x86_64.rpm'
        for name, busted, where in [*((f'0.0.9/{name}', False, 'at its plain URL') for name in
                                      ['release.json', 'SHA256SUMS', 'install.sh', 'repodata/repomd.xml', rpm]),
                                    ('0.0.9/release.json', True, 'past the CDN cache'),
                                    ('0.0.9/SHA256SUMS', True, 'past the CDN cache'),
                                    ('0.0.8/install.sh', False, 'at its plain URL'),
                                    ('0.0.8/SHA256SUMS', True, 'past the CDN cache')]:
            with self.subTest(name=name, where=where):
                result, sleeps = self.verify(lingering(name, busted, 2), pages_manifest=record)
                self.assertEqual((result['passed'], len(sleeps)), (True, 2))
                self.refused(f'the retired {name} still does not return 404 {where} (HTTP 200)',
                             self.verify, lingering(name, busted, 1000), pages_manifest=record, timeout=90)
        for name, busted, where in [('0.0.9/install.sh', False, 'at its plain URL'),
                                    ('0.0.9/release.json', True, 'past the CDN cache')]:
            for status in [503, 403, 429]:
                with self.subTest('only exactly 404 means gone', name=name, where=where, status=status):
                    self.refused(f'the retired {name} still does not return 404 {where} (HTTP {status})',
                                 self.verify, lingering(name, busted, 1000, status), pages_manifest=record, timeout=90)
            with self.subTest('a network error only means not converged yet', name=name, where=where):
                result, sleeps = self.verify(lingering(name, busted, 2, None), pages_manifest=record)
                self.assertEqual((result['passed'], len(sleeps)), (True, 2))
                self.refused('the live site could not be read before the timeout: '
                             f'GET https://archledger.github.io/intel-npu-stack/{name} failed', self.verify,
                             lingering(name, busted, 1000, None), pages_manifest=record, timeout=90)

    def test_one_timeout_bounds_the_whole_wait(self):
        # Every check waits within the same deadline, so checks that each converge within the timeout but not
        # together are refused once it has passed, whichever check is still waiting then.
        stale = {'release.json': 2, 'install.sh': 2}
        result, sleeps = self.verify(self.serve_live(self.site, '0.1.0', stale), timeout=150)
        self.assertEqual((result['passed'], len(sleeps)), (True, 4))
        sleeps = []
        self.refused('the live install.sh is still stale or missing at its plain URL (HTTP 200)', self.verify,
                     self.serve_live(self.site, '0.1.0', stale), timeout=90, sleeps=sleeps)
        self.assertEqual(len(sleeps), 2)
        live, lingering = self.serve_live(self.site, '0.1.0', {'release.json': 2}), [2]

        def retired_after_a_slow_file(url, sink=None):
            if url == 'https://archledger.github.io/intel-npu-stack/0.0.9/install.sh' and lingering[0]:
                lingering[0] -= 1
                return answer(200, b'retired\n', sink)
            return live(url, sink) if '/0.1.0/' in url else (404, b'')
        sleeps = []
        self.refused('the retired 0.0.9/install.sh still does not return 404 at its plain URL (HTTP 200)',
                     self.verify, retired_after_a_slow_file, timeout=90, sleeps=sleeps,
                     pages_manifest=self.pages_record(retired={'0.0.9': ['install.sh']}))
        self.assertEqual(len(sleeps), 2)

    def test_live_sums_signature_must_pass_the_key_policy(self):
        # Every live byte equals the archive and install.sh.asc is valid, but SHA256SUMS.asc is not a signature of
        # SHA256SUMS by the release key.
        for label, signer, signed in [('another key', self.other, None),
                                      ('the release key over other bytes', self.key, b'other sums\n')]:
            with self.subTest(label):
                self.setUp()
                forged = self.work / 'forged/0.1.0'
                shutil.copytree(self.site, forged)
                target = forged / 'SHA256SUMS'
                if signed is not None:
                    target = self.work / 'other-sums'
                    target.write_bytes(signed)
                signer.sign(target, output=str(forged / 'SHA256SUMS.asc.new'))
                (forged / 'SHA256SUMS.asc.new').replace(forged / 'SHA256SUMS.asc')
                archive = self.work / 'forged.tar'
                with archive.open('xb') as stream:
                    release_site.write_archive(forged, stream)
                self.refused('live signature does not satisfy the pinned release-key policy: SHA256SUMS.asc',
                             self.verify, self.serve_live(forged, '0.1.0'), archive=archive)

    def test_new_version_files_are_compared_past_the_cdn_cache(self):
        deployed = self.work / 'origin/0.1.0'
        shutil.copytree(self.site, deployed)
        (deployed / 'support-matrix.json').write_bytes(b'{"changed": true}\n')  # at origin; the edge serves the release
        edge, origin = self.serve_live(self.site, '0.1.0'), self.serve_live(deployed, '0.1.0')

        def cdn(url, sink=None):
            return (origin if urllib.parse.urlsplit(url).query else edge)(url, sink)
        self.refused('the live support-matrix.json differs from the release', self.verify, cdn)

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
        manifest = self.pages_record(versions={'0.0.9': {'sha256sums_sha256': sha(b'old sums')},
                                               '0.1.0': self.pages_entry()})
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

        def cdn(url, sink=None):  # the edge still serves the recorded bytes, origin serves other bytes
            if '/0.0.9/SHA256SUMS' in url:
                return answer(200, b'changed' if urllib.parse.urlsplit(url).query else b'old sums', sink)
            return fetch(url, sink)
        self.refused('0.0.9/SHA256SUMS changed', self.verify, cdn, pages_manifest=manifest)


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

    def test_uploads_stream_the_file_with_its_length(self):
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers['Content-Length'])
                received.append((length, self.headers.get('Transfer-Encoding'), self.rfile.read(length)))
                answer = json.dumps({'id': 7, 'name': 'asset'}).encode()
                self.send_response(201)
                self.send_header('Content-Length', str(len(answer)))
                self.end_headers()
                self.wfile.write(answer)

            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'asset'
            path.write_bytes(bytes(range(256)) * 400)
            gh = publish.GitHub(API, REPOSITORY, 'token-value')
            release = {'upload_url': f'http://127.0.0.1:{server.server_address[1]}/assets{{?name,label}}'}
            self.assertEqual(gh.upload(release, 'asset', path), {'id': 7, 'name': 'asset'})
        self.assertEqual(received, [(102400, None, bytes(range(256)) * 400)])

    def test_pagination_stays_on_the_api_host(self):
        def transport(method, url, headers=None, data=None):
            return 200, {'Link': '<https://evil.example/next>; rel="next"'}, b'[]'
        gh = publish.GitHub(API, REPOSITORY, 'token', transport=transport)
        with self.assertRaisesRegex(publish.PublishRefused, 'API host'):
            gh.releases()

    def test_the_tag_listing_must_name_the_object_of_every_tag(self):
        # The served-state snapshots compare each v tag's object; one the listing leaves out would never differ.
        listed = {'ref': 'refs/tags/v0.1.0', 'object': {'type': 'commit', 'sha': COMMIT}}
        for label, ref in [('no object', {'ref': 'refs/tags/v0.2.0'}),
                           ('an object without a sha', {'ref': 'refs/tags/v0.2.0', 'object': {'type': 'commit'}}),
                           ('an abbreviated sha', {'ref': 'refs/tags/v0.2.0',
                                                   'object': {'type': 'commit', 'sha': COMMIT[:12]}})]:
            with self.subTest(label):
                gh = publish.GitHub(API, REPOSITORY, 'token', transport=lambda *args, ref=ref: (
                    200, {}, json.dumps([listed, ref]).encode()))
                with self.assertRaisesRegex(publish.PublishRefused, 'the tag listing names no object for v0.2.0'):
                    gh.tags()
        # An annotated tag's ref names its tag object, which moving the tag replaces; the commit behind it is not
        # listed.
        annotated = {'ref': 'refs/tags/v0.2.0', 'object': {'type': 'tag', 'sha': 'a' * 40}}
        gh = publish.GitHub(API, REPOSITORY, 'token', transport=lambda *args: (
            200, {}, json.dumps([listed, annotated]).encode()))
        self.assertEqual(gh.tags(), [('v0.1.0', COMMIT), ('v0.2.0', 'a' * 40)])

    def test_network_errors_refuse_without_the_query(self):
        with self.assertRaises(publish.NetworkRefused) as caught:
            publish.http('GET', 'http://127.0.0.1:1/x?token=secret', timeout=5)
        self.assertNotIn('secret', str(caught.exception))

    def raw_server(self, response):
        """A server that answers each connection with these bytes and closes it."""
        server = socket.create_server(('127.0.0.1', 0))

        def serve():
            while True:
                try:
                    connection, _ = server.accept()
                except OSError:
                    return
                with connection:
                    connection.recv(65536)
                    connection.sendall(response)
        threading.Thread(target=serve, daemon=True).start()
        self.addCleanup(server.close)
        return f'http://127.0.0.1:{server.getsockname()[1]}/asset?token=secret'

    def test_protocol_errors_refuse_as_network_errors(self):
        truncated = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n400\r\n' + b'x' * 100
        for label, response, options in [('a truncated chunked body streamed', truncated, {'sink': publish.Digest()}),
                                         ('a truncated chunked body', truncated, {}),
                                         ('a malformed status line', b'FOO 200 OK\r\n\r\n', {})]:
            with self.subTest(label):
                with self.assertRaises(publish.NetworkRefused) as caught:
                    publish.http('GET', self.raw_server(response), timeout=5, **options)
                self.assertNotIn('secret', str(caught.exception))

    def test_a_truncated_error_body_keeps_its_status(self):
        url = self.raw_server(b'HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n'
                              b'400\r\n' + b'x' * 100)
        status, _, body = publish.http('GET', url, timeout=5)
        self.assertEqual((status, body), (404, b''))


class Wiring(unittest.TestCase):
    def main(self, argv, environment=None, unset=()):
        """The exit status and error output of the command line in this environment."""
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, environment or {}), contextlib.redirect_stderr(stderr), \
                contextlib.redirect_stdout(io.StringIO()):
            for name in unset:
                os.environ.pop(name, None)
            try:
                return publish.main(argv), stderr.getvalue()
            except SystemExit as exit:
                return exit.code, stderr.getvalue()

    def test_verify_live_is_given_the_pages_manifest_and_the_release_commit(self):
        with mock.patch.object(publish, 'verify_live', return_value={'passed': True}) as verify:
            self.assertEqual(self.main(['verify-live', '--archive', 'release.tar', '--pages-manifest', 'pages.json',
                                        '--sha', 'd' * 40])[0], 0)
            self.assertEqual(verify.call_args.args[3:6], (Path('release.tar'), Path('pages.json'), 'd' * 40))
            self.assertEqual(self.main(['verify-live', '--archive', 'release.tar', '--pages-manifest', 'pages.json'],
                                       {'GITHUB_SHA': 'e' * 40})[0], 0)
            self.assertEqual(verify.call_args.args[5], 'e' * 40)

    ENVIRONMENT = {'GH_TOKEN': 'token-value', 'GITHUB_REPOSITORY': REPOSITORY}

    def test_check_unpublished_takes_the_registry_and_for_the_preflight_the_bytes_to_reserve(self):
        with mock.patch.object(publish, 'check_unpublished', return_value='fresh') as check:
            self.assertEqual(self.main(['check-unpublished', '--phase', 'preflight', '--registry', 'r.json',
                                        '--reserve-bytes', '1000'], self.ENVIRONMENT)[0], 0)
            self.assertEqual((check.call_args.args[2:4], check.call_args.kwargs['reserve']),
                             (('preflight', Path('r.json')), 1000))
            self.assertEqual(self.main(['check-unpublished', '--phase', 'publish', '--registry', 'r.json', '--assets',
                                        'assets', '--sha', 'c' * 40], self.ENVIRONMENT)[0], 0)
            self.assertEqual((check.call_args.args[2:4], check.call_args.kwargs['assets_dir']),
                             (('publish', Path('r.json')), Path('assets')))
            publish_options = ['--phase', 'publish', '--registry', 'r.json', '--sha', 'c' * 40]
            refusals = [
                (['--phase', 'preflight', '--reserve-bytes', '1000'], 'requires --phase and --registry'),
                (['--registry', 'r.json', '--assets', 'assets', '--sha', 'c' * 40], 'requires --phase and --registry'),
                (['--phase', 'preflight', '--registry', 'r.json'], '--phase preflight requires --reserve-bytes'),
                (publish_options, '--phase publish requires --assets'),
                (publish_options + ['--assets', 'assets', '--reserve-bytes', '1000'],
                 'only check-unpublished --phase preflight takes --reserve-bytes'),
            ]
            for options, message in refusals:
                with self.subTest(options):
                    code, stderr = self.main(['check-unpublished', *options], self.ENVIRONMENT)
                    self.assertEqual(code, 1)
                    self.assertIn(message, stderr)
            self.assertEqual(check.call_count, 2)

    def test_publish_release_takes_the_registry(self):
        options = ['publish-release', '--assets', 'assets', '--notes', 'notes.md', '--sha', 'c' * 40]
        with mock.patch.object(publish, 'publish_release', return_value={'state': 'fresh'}) as release:
            code, stderr = self.main(options, self.ENVIRONMENT)
            self.assertEqual(code, 1)
            self.assertIn('publish-release needs --assets, --notes, --sha and --registry', stderr)
            self.assertEqual(self.main(options + ['--registry', 'r.json'], self.ENVIRONMENT)[0], 0)
        self.assertEqual(release.call_count, 1)
        self.assertEqual(release.call_args.args[6], Path('r.json'))

    def test_check_deploy_takes_the_registry_and_the_pages_manifest(self):
        with mock.patch.object(publish, 'check_deploy', return_value={'new_version': '0.1.0'}) as check:
            self.assertEqual(self.main(['check-deploy', '--registry', 'r.json', '--pages-manifest', 'pages.json'],
                                       self.ENVIRONMENT)[0], 0)
            self.assertEqual(check.call_args.args[2:], (Path('r.json'), Path('pages.json')))
            for options in [['--registry', 'r.json'], ['--pages-manifest', 'pages.json']]:
                with self.subTest(options):
                    code, stderr = self.main(['check-deploy', *options], self.ENVIRONMENT)
                    self.assertEqual(code, 1)
                    self.assertIn('check-deploy needs --registry and --pages-manifest', stderr)
        self.assertEqual(check.call_count, 1)

    def test_options_are_spelled_in_full(self):
        with mock.patch.object(publish, 'check_unpublished', return_value='fresh') as check:
            for options in [['--regis', 'r.json', '--reserve-bytes', '1'], ['--registry', 'r.json', '--reserve', '1']]:
                with self.subTest(options):
                    code, stderr = self.main(['check-unpublished', '--phase', 'preflight', *options], self.ENVIRONMENT)
                    self.assertEqual(code, 2)
                    self.assertIn('unrecognized arguments', stderr)
        check.assert_not_called()

    def test_verify_live_refuses_to_run_without_the_pages_manifest_or_the_commit(self):
        hex_commit = 'the 40-hex release commit'
        cases = [('no Pages manifest', ['--sha', 'd' * 40], 'verify-live requires --pages-manifest'),
                 ('no commit', ['--pages-manifest', 'pages.json'], 'verify-live requires --sha (or GITHUB_SHA)'),
                 ('an abbreviated commit', ['--pages-manifest', 'pages.json', '--sha', 'd' * 39], hex_commit),
                 ('an uppercase commit', ['--pages-manifest', 'pages.json', '--sha', 'D' * 40], hex_commit)]
        with mock.patch.object(publish, 'verify_live') as verify:
            for label, options, message in cases:
                with self.subTest(label):
                    code, stderr = self.main(['verify-live', '--archive', 'release.tar', *options],
                                             unset=['GITHUB_SHA'])
                    self.assertEqual(code, 1)
                    self.assertIn(message, stderr)
        verify.assert_not_called()


class Sums(unittest.TestCase):
    def test_sums_paths_must_be_plain_relative_paths(self):
        digest = 'a' * 64
        self.assertEqual(publish.parse_sums(f'{digest}  repodata/repomd.xml\n'.encode()),
                         {'repodata/repomd.xml': digest})
        for path in ['../index.html', '/etc/passwd', 'a//b', './x', 'a/../b', '.hidden']:
            with self.subTest(path), self.assertRaisesRegex(publish.PublishRefused, 'unsafe path'):
                publish.parse_sums(f'{digest}  {path}\n'.encode())


class Registry(unittest.TestCase):
    def test_committed_registry_is_valid_and_records_the_published_releases(self):
        # Each entry names the SHA-256 of the SHA256SUMS asset of its immutable release. 0.1.0 is retired: its
        # installer fails on Fedora 44 with SELinux enforcing (#53).
        registry = publish.load_registry(Path(__file__).resolve().parents[2] / 'release/published-versions.json')
        self.assertEqual(registry['published'], [
            {'version': '0.1.1', 'sha256sums_sha256': '0e1f9479fed5c7636e8e4642d58971f7872539d159112e4155bfc18e75732291'}])
        self.assertEqual([(entry['version'], entry['sha256sums_sha256']) for entry in registry['retired']],
                         [('0.1.0', 'c0d4192964a6020627006fc95a517800bbca96fb80292f06b320c03d4f929417')])

    def load(self, text):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / 'published-versions.json'
            path.write_text(text)
            return publish.load_registry(path)

    def test_repeated_keys_and_a_schema_that_is_not_the_integer_1_are_refused(self):
        entry = '{"version": "0.1.0", "sha256sums_sha256": "' + 'a' * 64 + '"}'
        self.assertEqual(self.load('{"schema_version": 1, "published": [' + entry + '], "retired": []}')['published'],
                         [{'version': '0.1.0', 'sha256sums_sha256': 'a' * 64}])
        cases = [
            # A reviewer reads the recorded versions, but the last key would win and disable their checks.
            ('a repeated top-level key', '{"schema_version": 1, "published": [' + entry + '], "retired": [], '
                                         '"published": []}', 'published-versions.json repeats a key'),
            ('a repeated entry key', '{"schema_version": 1, "published": [{"version": "0.1.0", "version": "0.2.0", '
                                     '"sha256sums_sha256": "' + 'a' * 64 + '"}], "retired": []}',
             'published-versions.json repeats a key'),
            ('a boolean schema', '{"schema_version": true, "published": [], "retired": []}', 'schema 1'),
            ('a float schema', '{"schema_version": 1.0, "published": [], "retired": []}', 'schema 1'),
        ]
        for label, text, message in cases:
            with self.subTest(label), self.assertRaisesRegex(publish.PublishRefused, message):
                self.load(text)


class Token(unittest.TestCase):
    MESSAGE = 'GH_TOKEN must be 1 to 4096 visible ASCII characters (no spaces or line breaks)'
    MALFORMED = [('a trailing newline', 'ghp_SECRETVALUE\n'), ('CRLF', 'ghp_SECRETVALUE\r\n'),
                 ('a character outside ASCII', 'ghp_SECRETVALUE’'), ('a space', 'ghp_SECRET VALUE'),
                 ('4097 characters', 'ghp_SECRETVALUE' + 'x' * 4082)]

    def test_a_token_that_is_not_1_to_4096_visible_ascii_characters_is_refused_without_echoing_it(self):
        for token in ['ghs_' + 'A1b2' * 9 + '_.-', 'ghp_' + 'x' * 4092]:
            self.assertEqual(publish.GitHub(API, REPOSITORY, token).token, token)
        for label, token in self.MALFORMED:
            with self.subTest(label):
                with self.assertRaises(publish.PublishRefused) as caught:
                    publish.GitHub(API, REPOSITORY, token)
                self.assertEqual(str(caught.exception), self.MESSAGE)

    def test_the_command_line_never_prints_the_token(self):
        # http.client would refuse such a header with the whole Authorization value in the error.
        work = Path(tempfile.mkdtemp(prefix='token-'))
        self.addCleanup(shutil.rmtree, work, True)
        (work / 'published-versions.json').write_text('{"schema_version": 1, "published": [], "retired": []}')
        for label, token in self.MALFORMED[:3]:
            with self.subTest(label):
                stderr = io.StringIO()
                environment = {'GITHUB_API_URL': 'http://127.0.0.1:1', 'GITHUB_REPOSITORY': REPOSITORY,
                               'GH_TOKEN': token}
                with mock.patch.dict(os.environ, environment), contextlib.redirect_stderr(stderr), \
                        contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as caught:
                    publish.main(['compose-pages', '--registry', str(work / 'published-versions.json'),
                                  '--output', str(work / 'site'), '--manifest', str(work / 'pages-manifest.json')])
                self.assertEqual(caught.exception.code, 1)
                self.assertIn(self.MESSAGE, stderr.getvalue())
                self.assertNotIn('SECRET', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
