#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Publish a verified release as an immutable GitHub release and compose the Pages site from releases.

  release_publish.py check-unpublished --phase preflight
  release_publish.py check-unpublished --phase publish --assets DIR --sha COMMIT
  release_publish.py publish-release --assets DIR --notes FILE --sha COMMIT
  release_publish.py compose-pages --registry FILE --output _site --manifest FILE [--new-version V]
  release_publish.py verify-live --archive FILE [--pages-manifest FILE] [--fetched DIR] [--timeout SECONDS]

Standard library only. The REST API base comes from GITHUB_API_URL, the
repository from GITHUB_REPOSITORY and the token from GH_TOKEN. The version, base
URL and release key come from the committed trust seam of --repo.

check-unpublished preflight refuses unless GitHub Pages is served by GitHub
Actions at the committed base URL, no tag or release (draft or published)
exists for the version, and the live release.json returns 404. The publish
phase first checks the publication itself: SHA256SUMS.asc must pass the
release-key policy, the archive must hold exactly the files SHA256SUMS lists,
its signed publication-manifest.json must name this version, base URL, release
key and commit, the archive must be the canonical archive of its site, and the
site must fit the Pages budget. It then classifies the state as fresh,
draft-resume (a draft whose assets are a byte-identical subset of this
publication) or published-resume (an immutable release with exactly these
assets whose tag is the release commit), and refuses anything else.

publish-release runs the same publication checks, requires the notes to be the
release_site rendering of this site and archive, creates or resumes the draft,
sets its title and notes, uploads the missing assets, reads every asset back,
publishes it as the latest release and requires the release to be immutable
with the same title, notes and assets and its tag at the release commit.

compose-pages builds _site/<version>/ from every non-draft, non-prerelease
vX.Y.Z release. Every such release must be immutable. A release retired in
release/published-versions.json is left out, and its retired entry must have
the digest of its SHA256SUMS. Every other release must carry exactly the four
release assets with matching API digests and a SHA256SUMS.asc that passes the
release-key policy, and its archive must hold exactly the files SHA256SUMS
lists plus the two sums files, packed canonically. Its signed
publication-manifest.json must name its own version, the base URL of that
version, the release key and the commit its tag names. Every published version
in the registry must be present with the same SHA256SUMS. The live SHA256SUMS
of every version other than --new-version must equal its release's, and the
site must fit the size budget.

verify-live waits until the plain URLs of the version serve the archive's
bytes, then streams every file to disk cache-busted and compares its digest,
repacks the fetched files into the canonical archive, verifies SHA256SUMS.asc
and install.sh.asc, and compares the live SHA256SUMS of the other versions with
the Pages manifest.

Every release archive is first scanned by its raw tar headers (release_tar):
at most MAX_MEMBERS headers, extension headers included, and only regular
files and GNU long names.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import release_site
import release_tar
import release_trust

REPO = Path(__file__).resolve().parents[2]
TAG = re.compile(r'v((?:0|[1-9][0-9]{0,9})\.(?:0|[1-9][0-9]{0,9})\.(?:0|[1-9][0-9]{0,9}))')
DIGEST = re.compile(r'[0-9a-f]{64}')
MAX_BODY = 512 << 20
MAX_SITE = 950 << 20
MAX_ASSET = 1 << 30  # streamed to disk: a release archive may be as large as the whole site budget
MAX_MEMBERS = 20000  # raw tar headers; a site holds tens of files
STANDALONE = ['SHA256SUMS', 'SHA256SUMS.asc', 'publication-manifest.json']
MAX_PAGES = 20
PLAIN = ['release.json', 'release.json.sig', 'profile.toml', 'install.sh', 'intel-npu-stack-install',
         'primary-command.txt', 'repodata/repomd.xml']


class PublishRefused(Exception):
    """A publication gate failed."""


def require(condition, message):
    if not condition:
        raise PublishRefused(message)


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def release_assets(version):
    return [f'intel-npu-stack-{version}.tar', 'SHA256SUMS', 'SHA256SUMS.asc', 'publication-manifest.json']


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def http(method, url, headers=None, data=None, timeout=120, sink=None):
    """(status, headers, body) without following redirects; network failures refuse.

    With a sink, a successful body is streamed into it up to MAX_ASSET bytes and the returned body is empty.
    """
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with OPENER.open(request, timeout=timeout) as response:
            status, response_headers = response.status, dict(response.headers)
            if sink is not None:
                written = 0
                while chunk := response.read(1 << 20):
                    written += len(chunk)
                    require(written <= MAX_ASSET, 'download exceeds the size limit')
                    sink.write(chunk)
                return status, response_headers, b''
            body = response.read(MAX_BODY + 1)
    except urllib.error.HTTPError as error:
        status, response_headers = error.code, dict(error.headers or {})
        try:
            body = error.read(MAX_BODY + 1)
        except OSError:
            body = b''
    except (urllib.error.URLError, OSError) as error:
        raise PublishRefused(f'{method} {urllib.parse.urlsplit(url)._replace(query="").geturl()} failed: '
                             f'{getattr(error, "reason", error)}') from None
    require(len(body) <= MAX_BODY, 'response exceeds the size limit')
    return status, response_headers, body


def fetch_public(url, sink=None):
    """GET without credentials, following at most five redirects to HTTPS URLs; returns (status, body).

    With a sink, a successful body is streamed into it as http() does, and the returned body is empty.
    """
    for _ in range(6):
        status, headers, body = http('GET', url, {'User-Agent': 'intel-npu-stack-release'}, sink=sink)
        if status not in {301, 302, 303, 307, 308}:
            return status, body
        location = urllib.parse.urljoin(url, headers.get('Location') or headers.get('location') or '')
        require(location.startswith('https://'), 'a live site redirect left HTTPS')
        url = location
    raise PublishRefused('too many redirects from the live site')


def cache_busted(url):
    return url + '?nocache=' + secrets.token_hex(8)


class Digest:
    """A sink that keeps only the SHA-256 of what is written to it."""

    def __init__(self):
        self.sha256 = hashlib.sha256()

    def write(self, chunk):
        self.sha256.update(chunk)


def live_sha(fetch, url):
    """(status, SHA-256 of a 200 body or None), streamed so no live file is held in memory."""
    sink = Digest()
    status, _ = fetch(url, sink=sink)
    return status, (sink.sha256.hexdigest() if status == 200 else None)


class GitHub:
    """The REST calls publication needs; asset downloads follow the storage redirect without the token."""

    def __init__(self, api_url, repository, token, transport=http):
        require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository or '') is not None,
                'GITHUB_REPOSITORY must be owner/name')
        require(bool(token), 'GH_TOKEN is required')
        self.api, self.repository, self.token, self.transport = api_url.rstrip('/'), repository, token, transport

    def headers(self, accept='application/vnd.github+json', extra=None):
        return {'Accept': accept, 'Authorization': 'Bearer ' + self.token, 'X-GitHub-Api-Version': '2022-11-28',
                'User-Agent': 'intel-npu-stack-release', **(extra or {})}

    def call(self, method, path, body=None, expect=(200,)):
        url = path if path.startswith(('https://', 'http://')) else f'{self.api}/repos/{self.repository}{path}'
        data = None if body is None else json.dumps(body).encode()
        extra = {'Content-Type': 'application/json'} if data is not None else None
        status, headers, content = self.transport(method, url, self.headers(extra=extra), data)
        require(status in expect, f'{method} {path} returned HTTP {status}')
        return status, headers, (json.loads(content) if content.strip() else None)

    def paged(self, path):
        items, url = [], f'{self.api}/repos/{self.repository}{path}'
        for _ in range(MAX_PAGES):
            _, headers, page = self.call('GET', url)
            require(isinstance(page, list), f'GET {path} did not return a list')
            items.extend(page)
            match = re.search(r'<([^>]+)>;\s*rel="next"', headers.get('Link') or headers.get('link') or '')
            if match is None:
                return items
            url = match.group(1)
            require(url.startswith(self.api + '/'), 'a pagination link left the API host')
        raise PublishRefused(f'GET {path} has more than {MAX_PAGES} pages')

    def releases(self):
        return self.paged('/releases?per_page=100')

    def pages(self):
        status, _, info = self.call('GET', '/pages', expect=(200, 404))
        return info if status == 200 else None

    def tag_commit(self, tag):
        """The commit a tag names, or None when the tag does not exist."""
        status, _, ref = self.call('GET', f'/git/ref/tags/{tag}', expect=(200, 404))
        if status == 404:
            return None
        target = ref.get('object', {})
        for _ in range(3):
            if target.get('type') == 'commit':
                return target.get('sha')
            require(target.get('type') == 'tag', f'tag {tag} does not name a commit')
            _, _, annotated = self.call('GET', f"/git/tags/{target.get('sha')}")
            target = annotated.get('object', {})
        raise PublishRefused(f'tag {tag} nests too deeply')

    def tag_exists(self, tag):
        _, _, refs = self.call('GET', f'/git/matching-refs/tags/{tag}')
        return any(ref.get('ref') == 'refs/tags/' + tag for ref in refs or [])

    def download_asset(self, asset, path):
        """Stream an asset to a new file and return its SHA-256; the storage redirect gets no token."""
        with open(path, 'xb') as sink:
            status, headers, _ = self.transport('GET', asset['url'], self.headers('application/octet-stream'),
                                                None, sink=sink)
            if status in {302, 307}:
                location = headers.get('Location') or headers.get('location') or ''
                require(location.startswith('https://'), 'an asset redirect left HTTPS')
                sink.seek(0)
                sink.truncate()
                storage_headers = {'Accept': 'application/octet-stream', 'User-Agent': 'intel-npu-stack-release'}
                status, _, _ = self.transport('GET', location, storage_headers, None, sink=sink)
        require(status == 200, f"asset {asset.get('name')} could not be read back (HTTP {status})")
        return release_site.sha(path)

    def upload(self, release, name, path):
        base = release['upload_url'].split('{', 1)[0]
        url = base + '?' + urllib.parse.urlencode({'name': name})
        data = Path(path).read_bytes()
        status, _, content = self.transport('POST', url, self.headers(extra={
            'Content-Type': 'application/octet-stream', 'Content-Length': str(len(data))}), data)
        require(status == 201, f'uploading {name} returned HTTP {status}')
        return json.loads(content)


@contextlib.contextmanager
def open_archive(archive):
    """A release archive opened for reading once its raw headers are within the bounds, so tarfile reads no more."""
    with open(archive, 'rb') as stream:
        try:
            release_tar.scan(stream, MAX_MEMBERS, release_tar.RELEASE_TYPES)
        except release_tar.TarRefused as error:
            raise PublishRefused(f'the release archive {Path(archive).name}: {error}') from None
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode='r:') as tar:
            yield tar


def check_standalone(archive, version, files):
    """The separate SHA256SUMS, SHA256SUMS.asc and publication-manifest.json assets are the archive's own copies."""
    with open_archive(archive) as tar:
        members = {member.name: member for member in tar.getmembers()}
        for name in STANDALONE:
            member = members.get(f'{version}/{name}')
            require(member is not None, f'the {version} archive has no {name}')
            require(member.isreg() and tar.extractfile(member).read() == Path(files[name]).read_bytes(),
                    f'the standalone {name} differs from the copy in the signed archive')


def check_identity(root, version, base_url, fingerprint, commit=None):
    """The signed publication manifest names this version, base URL and release key, and the release commit."""
    manifest = json.loads((Path(root) / 'publication-manifest.json').read_text())
    installer = manifest.get('installer') if isinstance(manifest, dict) else None
    pinned = installer.get('pinned') if isinstance(installer, dict) else None
    require(isinstance(pinned, dict) and pinned.get('version') == version and pinned.get('base_url') == base_url
            and pinned.get('primary_fingerprint') == fingerprint
            and (commit is None or manifest.get('source_commit') == commit),
            f'the signed publication manifest in the {version} archive names another release')


def site_bytes(root):
    return sum(path.stat().st_size for path in Path(root).rglob('*') if path.is_file())


def canonical_sha(root):
    """The SHA-256 of the canonical archive of a site directory."""
    with tempfile.TemporaryFile() as rendered:
        release_site.write_archive(root, rendered)
        rendered.seek(0)
        return hashlib.file_digest(rendered, 'sha256').hexdigest()


def local_assets(assets_dir, values, commit, key, notes=None):
    """Digests of the publication assets, once the signed archive is proven to be this release within budget.

    With notes, they must also be the release_site rendering of this site and archive.
    """
    version, assets = values['version'], Path(assets_dir)
    digests = {}
    for name in release_assets(version):
        path = assets / name
        require(path.is_file() and not path.is_symlink(), 'publication asset is missing: ' + name)
        digests[name] = release_site.sha(path)
    archive = assets / release_assets(version)[0]
    check_standalone(archive, version, {name: assets / name for name in STANDALONE})
    try:
        release_site.verify_signature(assets / 'SHA256SUMS.asc', assets / 'SHA256SUMS', key,
                                      values['primary_fingerprint'])
    except release_site.SiteRefused as error:
        raise PublishRefused(f'{version}: {error}') from None
    with tempfile.TemporaryDirectory(prefix='publication-') as work:
        unpack_release(archive, version, (assets / 'SHA256SUMS').read_bytes(),
                       (assets / 'SHA256SUMS.asc').read_bytes(), work)
        root = Path(work) / version
        check_identity(root, version, values['base_url'], values['primary_fingerprint'], commit)
        # verify-live repacks the live files canonically, so any other packing could never be verified.
        require(canonical_sha(root) == digests[archive.name],
                f'the {version} archive is not the canonical archive of its site')
        total = site_bytes(root)
        if notes is not None:
            try:
                rendered = release_site.render_notes(root, archive)
            except release_site.SiteRefused as error:
                raise PublishRefused(f'{version}: {error}') from None
            require(rendered == Path(notes).read_bytes(), 'the release notes are not the rendering of this release')
    require(total <= MAX_SITE, f'the {version} site is {total} bytes, above the {MAX_SITE}-byte Pages budget')
    return digests


def publish_state(gh, values, local, commit):
    """fresh, draft-resume or published-resume, with the matching release; anything else refuses."""
    tag = 'v' + values['version']
    matches = [release for release in gh.releases() if release.get('tag_name') == tag]
    require(len(matches) <= 1, f'more than one release uses tag {tag}')
    tag_sha = gh.tag_commit(tag)
    if not matches:
        require(tag_sha is None, f'tag {tag} exists without a release; delete it by hand after review')
        return 'fresh', None
    release = matches[0]
    assets = {asset.get('name'): asset.get('digest') for asset in release.get('assets', [])}
    require(set(assets) <= set(local) and all(assets[name] == 'sha256:' + local[name] for name in assets),
            f'the existing {tag} release or draft differs from this publication; a stale draft is deleted by hand')
    require(release.get('prerelease') is False, f'the existing {tag} release is a prerelease')
    if release.get('draft'):
        # Publishing a draft creates its tag at target_commitish, so the draft must already name this commit.
        require(release.get('target_commitish') == commit and tag_sha in {None, commit},
                f'the {tag} draft targets another commit than this publication')
        return 'draft-resume', release
    require(set(assets) == set(local) and release.get('immutable') is True and tag_sha == commit,
            f'a published {tag} release exists and is not this immutable publication')
    return 'published-resume', release


def check_unpublished(gh, values, phase, assets_dir=None, commit=None, key=None, fetch=fetch_public):
    version, tag = values['version'], 'v' + values['version']
    if phase == 'publish':
        require(commit is not None and re.fullmatch(r'[0-9a-f]{40}', commit), 'the release commit is required')
        require(key is not None, 'the committed release key is required')
        return publish_state(gh, values, local_assets(assets_dir, values, commit, key), commit)[0]
    pages = gh.pages()
    require(pages is not None and pages.get('build_type') == 'workflow'
            and str(pages.get('html_url', '')).rstrip('/') + '/' + version + '/' == values['base_url'],
            'GitHub Pages must be served by GitHub Actions at the committed BASE_URL')
    require(not gh.tag_exists(tag), f'tag {tag} already exists')
    require(not any(release.get('tag_name') == tag for release in gh.releases()),
            f'a release or draft for {tag} already exists')
    status, _ = fetch(cache_busted(values['base_url'] + 'release.json'))
    require(status == 404, f'the live release.json must not exist before publication (HTTP {status})')
    return 'fresh'


def check_release_assets(gh, release, local, readback):
    assets = {asset.get('name'): asset for asset in release.get('assets', [])}
    require(set(assets) == set(local), 'the release does not carry exactly the publication assets')
    for name, digest in local.items():
        require(assets[name].get('digest') == 'sha256:' + digest, f'the API digest of {name} differs')
        if readback:
            with tempfile.TemporaryDirectory(prefix='readback-') as work:
                require(gh.download_asset(assets[name], Path(work) / name) == digest,
                        f'the uploaded {name} reads back differently')


def publish_release(gh, values, assets_dir, notes, commit, key):
    version, tag = values['version'], 'v' + values['version']
    local = local_assets(assets_dir, values, commit, key, notes)
    body = Path(notes).read_text()
    require(0 < len(body) <= 120000, 'release notes must be non-empty and within the GitHub limit')
    title = f'Intel NPU Stack {version}'
    state, release = publish_state(gh, values, local, commit)
    if state == 'fresh':
        _, _, release = gh.call('POST', '/releases', expect=(201,), body={
            'tag_name': tag, 'target_commitish': commit, 'name': title, 'body': body,
            'draft': True, 'prerelease': False})
    if state in {'fresh', 'draft-resume'}:
        # A resumed draft may carry another title or stale notes; they are set while the release is still a draft.
        gh.call('PATCH', f"/releases/{release['id']}", body={'name': title, 'body': body})
        present = {asset.get('name') for asset in release.get('assets', [])}
        for name in release_assets(version):
            if name not in present:
                gh.upload(release, name, Path(assets_dir) / name)
        _, _, release = gh.call('GET', f"/releases/{release['id']}")
        require(release.get('draft') is True and release.get('name') == title and release.get('body') == body,
                f'the {tag} draft does not carry this publication\'s title and notes')
        check_release_assets(gh, release, local, readback=True)
        gh.call('PATCH', f"/releases/{release['id']}", body={'draft': False, 'make_latest': 'true'})
    _, _, final = gh.call('GET', f"/releases/{release['id']}")
    require(final.get('draft') is False and final.get('immutable') is True,
            f'the {tag} release is not an immutable published release')
    require(final.get('name') == title and final.get('body') == body,
            f'the published {tag} release does not carry this publication\'s title and notes')
    check_release_assets(gh, final, local, readback=False)
    require(gh.tag_commit(tag) == commit, f'tag {tag} does not name the release commit')
    return {'state': state, 'release_id': final['id'], 'tag': tag, 'commit': commit, 'assets': local}


def load_registry(path):
    registry = json.loads(Path(path).read_text())
    require(isinstance(registry, dict) and set(registry) == {'schema_version', 'published', 'retired'}
            and registry['schema_version'] == 1, 'published-versions.json must be schema 1 with published and retired')
    seen = set()
    for kind, fields in (('published', {'version', 'sha256sums_sha256'}),
                         ('retired', {'version', 'sha256sums_sha256', 'reason'})):
        require(isinstance(registry[kind], list), f'{kind} must be a list')
        for entry in registry[kind]:
            require(isinstance(entry, dict) and set(entry) == fields
                    and TAG.fullmatch('v' + str(entry['version'])) is not None
                    and isinstance(entry['sha256sums_sha256'], str) and DIGEST.fullmatch(entry['sha256sums_sha256'])
                    and entry['version'] not in seen, f'invalid {kind} entry: {entry!r}')
            require(kind == 'published' or (isinstance(entry['reason'], str) and entry['reason'].strip()),
                    'a retired version needs a reason')
            seen.add(entry['version'])
    return registry


def plain_path(path):
    return all(release_site.SEGMENT.fullmatch(part) for part in path.split('/'))


def parse_sums(data):
    listed = {}
    for line in data.decode().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (\S+)', line)
        require(match is not None and match.group(2) not in listed, 'malformed SHA256SUMS')
        require(plain_path(match.group(2)), 'unsafe path in SHA256SUMS: ' + repr(match.group(2)))
        listed[match.group(2)] = match.group(1)
    return listed


def unpack_release(archive, version, sums, signature, destination):
    """Extract a release archive that holds exactly the SHA256SUMS files and the two sums files."""
    listed = parse_sums(sums)
    wanted = {version + '/' + path for path in listed} | {version + '/SHA256SUMS', version + '/SHA256SUMS.asc'}
    with open_archive(archive) as tar:
        members = tar.getmembers()
        names = [member.name for member in members]
        require(len(names) == len(set(names)) and set(names) == wanted and all(m.isreg() for m in members),
                f'the {version} archive does not hold exactly the files SHA256SUMS lists')
        tar.extractall(destination, members=members, filter='data')
    root = Path(destination) / version
    require((root / 'SHA256SUMS').read_bytes() == sums and (root / 'SHA256SUMS.asc').read_bytes() == signature,
            f'the {version} archive carries other sums files than the release assets')
    for path, digest in listed.items():
        require(release_site.sha(root / path) == digest, f'{version}/{path} differs from SHA256SUMS')
    return len(names)


def compose_pages(gh, values, key, fingerprint, registry_path, output, manifest_path, new_version=None,
                  fetch=fetch_public, limit=MAX_SITE):
    output, manifest_path = Path(output), Path(manifest_path)
    require(not output.exists() and not manifest_path.exists(), 'outputs are never overwritten')
    registry = load_registry(registry_path)
    retired = {entry['version']: entry['sha256sums_sha256'] for entry in registry['retired']}
    host, prefix, _ = site_location(values['base_url'])
    root_url = f'https://{host}{prefix}'
    candidates = sorted((release for release in gh.releases()
                         if not release.get('draft') and not release.get('prerelease')
                         and TAG.fullmatch(release.get('tag_name') or '')),
                        key=lambda release: tuple(int(p) for p in release['tag_name'][1:].split('.')))
    versions = {}
    output.mkdir(parents=True)
    try:
        with tempfile.TemporaryDirectory(prefix='compose-pages-') as work:
            for release in candidates:
                version = release['tag_name'][1:]
                assets = {asset.get('name'): asset for asset in release.get('assets', [])}
                folder = Path(work) / version
                folder.mkdir()
                require(release.get('immutable') is True, f"release {release['tag_name']} is not immutable")
                if version in retired:
                    # A retirement record must name the release it retires.
                    require('SHA256SUMS' in assets, f"retired release {release['tag_name']} has no SHA256SUMS")
                    digest = gh.download_asset(assets['SHA256SUMS'], folder / 'SHA256SUMS')
                    require(assets['SHA256SUMS'].get('digest') == 'sha256:' + digest and digest == retired[version],
                            f'the retired entry for {version} does not match its release SHA256SUMS')
                    continue
                require(set(assets) == set(release_assets(version)),
                        f"release {release['tag_name']} does not carry exactly the release assets")
                data = {}
                for name, asset in assets.items():
                    digest = gh.download_asset(asset, folder / name)
                    require(asset.get('digest') == 'sha256:' + digest,
                            f"the API digest of {release['tag_name']} {name} differs from its bytes")
                    data[name] = folder / name
                try:
                    release_site.verify_signature(folder / 'SHA256SUMS.asc', folder / 'SHA256SUMS', key, fingerprint)
                except release_site.SiteRefused as error:
                    raise PublishRefused(f'{version}: {error}') from None
                files = unpack_release(data[release_assets(version)[0]], version, data['SHA256SUMS'].read_bytes(),
                                       data['SHA256SUMS.asc'].read_bytes(), output)
                tag_commit = gh.tag_commit(release['tag_name'])
                require(tag_commit is not None, f"release {release['tag_name']} has no tag")
                check_identity(output / version, version, f'{root_url}{version}/', fingerprint, tag_commit)
                require(canonical_sha(output / version) == release_site.sha(data[release_assets(version)[0]]),
                        f'the {version} archive is not the canonical archive of its site')
                check_standalone(data[release_assets(version)[0]], version, data)
                versions[version] = {'sha256sums_sha256': release_site.sha(data['SHA256SUMS']),
                                     'archive_sha256': release_site.sha(data[release_assets(version)[0]]),
                                     'files': files, 'release_id': release.get('id')}
        for entry in registry['published']:
            require(entry['version'] in versions, f"published version {entry['version']} is missing; retiring "
                    'a version needs a reviewed retired entry')
            require(versions[entry['version']]['sha256sums_sha256'] == entry['sha256sums_sha256'],
                    f"published version {entry['version']} has another SHA256SUMS than recorded")
        require(new_version is None or new_version in versions, f'the new version {new_version} is not composed')
        for version, record in versions.items():
            if version == new_version:
                continue
            status, body = fetch(cache_busted(f'{root_url}{version}/SHA256SUMS'))
            require(status == 200 and sha_bytes(body) == record['sha256sums_sha256'],
                    f'the live {version}/SHA256SUMS differs from its release (HTTP {status})')
        total = site_bytes(output)
        require(total <= limit, f'the Pages site is {total} bytes, above the {limit}-byte budget')
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise
    manifest = {'schema_version': 1, 'base_url': values['base_url'], 'versions': versions, 'total_bytes': total,
                'new_version': new_version}
    with open(manifest_path, 'x') as stream:
        stream.write(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    return manifest


def site_location(base_url):
    parts = urllib.parse.urlsplit(base_url)
    segments = parts.path.strip('/').split('/')
    require(parts.scheme == 'https' and parts.hostname and len(segments) >= 2, 'the base URL must be versioned HTTPS')
    return parts.hostname, '/' + '/'.join(segments[:-1]) + '/', segments[-1]


def verify_live(values, key, fingerprint, archive, pages_manifest=None, fetched=None, timeout=1200,
                fetch=fetch_public, sleep=time.sleep, clock=time.monotonic):
    version, base = values['version'], values['base_url']
    expected = {}
    with open_archive(archive) as tar:
        for member in tar.getmembers():
            path = member.name[len(version) + 1:] if member.name.startswith(version + '/') else ''
            require(member.isreg() and plain_path(path) and path not in expected,
                    'unsafe or duplicate member in the release archive: ' + repr(member.name))
            expected[path] = hashlib.file_digest(tar.extractfile(member), 'sha256').hexdigest()
    deadline = clock() + timeout
    while True:
        stale = [path for path in PLAIN if live_sha(fetch, base + path) != (200, expected.get(path))]
        if not stale:
            break
        require(clock() < deadline, 'the live site still serves stale or missing files: ' + ', '.join(stale))
        sleep(30)
    with tempfile.TemporaryDirectory(prefix='verify-live-') as work:
        root = Path(fetched or work) / version
        require(not root.exists(), f'{root} exists; outputs are never overwritten')
        for path, digest in sorted(expected.items()):
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, 'xb') as sink:
                status, _ = fetch(cache_busted(base + path), sink=sink)
            require(status == 200 and release_site.sha(target) == digest,
                    f'the live {path} differs from the release (HTTP {status})')
        require(canonical_sha(root) == release_site.sha(archive),
                'the live files do not repack into the release archive')
        try:
            release_site.verify_signature(root / 'SHA256SUMS.asc', root / 'SHA256SUMS', key, fingerprint)
            release_site.verify_signature(root / 'install.sh.asc', root / 'install.sh', key, fingerprint)
        except release_site.SiteRefused as error:
            raise PublishRefused('live ' + str(error)) from None
    others = {}
    if pages_manifest is not None:
        host, prefix, _ = site_location(base)
        for other, record in json.loads(Path(pages_manifest).read_text())['versions'].items():
            if other == version:
                continue
            status, body = fetch(cache_busted(f'https://{host}{prefix}{other}/SHA256SUMS'))
            require(status == 200 and sha_bytes(body) == record['sha256sums_sha256'],
                    f'the live {other}/SHA256SUMS changed (HTTP {status})')
            others[other] = record['sha256sums_sha256']
    return {'version': version, 'files': len(expected), 'archive_sha256': release_site.sha(archive),
            'other_versions': others, 'passed': True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=['check-unpublished', 'publish-release', 'compose-pages', 'verify-live'])
    parser.add_argument('--repo', type=Path, default=REPO)
    parser.add_argument('--phase', choices=['preflight', 'publish'])
    parser.add_argument('--assets', type=Path)
    parser.add_argument('--notes', type=Path)
    parser.add_argument('--sha', default=os.environ.get('GITHUB_SHA'))
    parser.add_argument('--registry', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--new-version')
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--pages-manifest', type=Path)
    parser.add_argument('--fetched', type=Path)
    parser.add_argument('--timeout', type=int, default=1200)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(argv)
    try:
        values = release_trust.check_committed(args.repo)
        key = args.repo / release_trust.KEY_PATH
        if args.report is not None:
            require(not args.report.exists() and args.report.parent.is_dir(),
                    'the report must be a new file in an existing directory')
        if args.command == 'verify-live':
            require(args.archive is not None, 'verify-live requires --archive')
            result = verify_live(values, key, values['primary_fingerprint'], args.archive, args.pages_manifest,
                                 args.fetched, args.timeout)
        else:
            gh = GitHub(os.environ.get('GITHUB_API_URL', 'https://api.github.com'),
                        os.environ.get('GITHUB_REPOSITORY'), os.environ.get('GH_TOKEN'))
            if args.command == 'check-unpublished':
                require(args.phase is not None, 'check-unpublished requires --phase')
                result = {'phase': args.phase,
                          'state': check_unpublished(gh, values, args.phase, args.assets, args.sha, key)}
            elif args.command == 'publish-release':
                require(None not in (args.assets, args.notes, args.sha),
                        'publish-release needs --assets, --notes and --sha')
                result = publish_release(gh, values, args.assets, args.notes, args.sha, key)
            else:
                require(None not in (args.registry, args.output, args.manifest),
                        'compose-pages needs --registry, --output and --manifest')
                result = compose_pages(gh, values, key, values['primary_fingerprint'], args.registry, args.output,
                                       args.manifest, args.new_version)
        text = json.dumps(result, indent=2, sort_keys=True) + '\n'
        if args.report is not None:
            with open(args.report, 'x') as stream:
                stream.write(text)
    except (PublishRefused, release_trust.TrustRefused, release_site.SiteRefused) as error:
        parser.exit(1, f'release {args.command} refused: {error}\n')
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        parser.exit(1, f'release {args.command} refused: {error!r}\n')
    sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
