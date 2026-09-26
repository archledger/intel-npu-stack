#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Publish a verified release as an immutable GitHub release and compose the Pages site from releases.

  release_publish.py check-unpublished --phase preflight --registry FILE --reserve-bytes N
  release_publish.py check-unpublished --phase publish --registry FILE --assets DIR --sha COMMIT
  release_publish.py publish-release --registry FILE --assets DIR --notes FILE --sha COMMIT
  release_publish.py compose-pages --registry FILE --output _site --manifest FILE [--new-version V]
  release_publish.py check-deploy --registry FILE --pages-manifest FILE
  release_publish.py verify-live --archive FILE --pages-manifest FILE --sha COMMIT [--fetched DIR]
                                 [--timeout SECONDS]

Standard library only. The REST API base comes from GITHUB_API_URL, the
repository from GITHUB_REPOSITORY and the token from GH_TOKEN, which must be 1
to 4096 visible ASCII characters, without spaces or line breaks. --sha defaults
to GITHUB_SHA, and options must be spelled in full. The version, base URL and
release key come from the committed trust seam of --repo.

Versions are published in increasing order, and the gates compose-pages applies
to the other versions run before anything irreversible. Both
check-unpublished phases and publish-release also run compose-pages dry into a
temporary directory over every non-draft vX.Y.Z release but this version (the
room check) before they classify or create anything: the preflight after its
Pages, tag, release and live checks, the publish phase and publish-release
after the publication checks. Every gate of compose-pages below must pass,
including the live SHA256SUMS of each composed version and a registry entry for
every other tagged version, so the change that records a release lands before
the next release. This version must be newer than every such release, retired
ones included, and not yet listed in --registry, and the composed site plus
this version's bytes must fit the Pages budget. The preflight reserves
--reserve-bytes, since the site is not built yet; the publish phase and
publish-release reserve the size of the new site.

check-unpublished preflight refuses unless GitHub Pages is served by GitHub
Actions at the committed base URL, no tag or release exists for the version,
the live release.json returns 404 and the room check passes. GitHub lists
drafts only to a token that can push, and the release workflow's preflight
token can only read, so a draft an aborted run left is not seen there: the
publish phase finds it and refuses one it cannot resume. The publish phase
first checks the publication itself: SHA256SUMS.asc must pass the release-key
policy, the archive must hold exactly the files SHA256SUMS lists, its signed
publication-manifest.json must name this version, base URL, release key and
commit, install.sh.asc must pass the release-key policy, the archive must be
the canonical archive of its site, and the site must fit the Pages budget.
After the room check it classifies the state as fresh, draft-resume (a draft
whose assets are a byte-identical subset of this publication, targeting the
release commit, with no tag at another commit) or published-resume (an
immutable release with exactly these assets whose tag is the release commit),
and refuses anything else.

publish-release runs the same publication checks and the room check, requires
the notes to be the release_site rendering of this site and archive, creates or
resumes the draft, sets its title and notes, uploads the missing assets and
reads every asset back. Right before publishing it reads the draft again: it
must still be a draft, not a prerelease, of this tag and commit, with this
title, notes and exactly these assets, and the tag must be absent or name the
release commit. The other non-draft vX.Y.Z releases and the v tags, with the
object each tag names in the tag listing, must be as the room check found
them, both when it ends and at that point, so an older tag force-moved after
the room check bound its release to a commit refuses too. The live SHA256SUMS
of every version it composed must still be served. It then publishes the draft
as the latest release, naming this tag, the commit, the title, the notes and a
full release again in that request so no later change to them takes effect,
and requires the release to be immutable, not a prerelease, under this tag,
with the same title, notes and assets and its tag at the release commit. GitHub
keeps a tag pushed after that last read, so only this final check can refuse
one.

compose-pages builds _site/<version>/ from every non-draft vX.Y.Z release.
Every such release must be immutable and not a prerelease. A release retired in
release/published-versions.json is left out, and its retired entry must have
the digest of its SHA256SUMS; every retired entry must match such a release.
Every other release must carry exactly the four release assets with matching
API digests and a SHA256SUMS.asc that passes the release-key policy, and its
archive must hold exactly the files SHA256SUMS lists plus the two sums files,
packed canonically. The release must carry its title and the release_site notes
rendered from its site and archive, and its install.sh.asc must pass the
release-key policy. Its signed publication-manifest.json must name its own
version, the base URL of that version, the release key and the commit its tag
names. The registry must be schema 1 (the integer) without repeated keys, and
a retired entry needs a reason. Every published version in the registry must
be present with the same SHA256SUMS, and every vX.Y.Z tag but that of
--new-version must have a registry entry, published or retired. Composing needs
each release's tag, and GitHub keeps the tag of a deleted release, so a release
deleted before or after it was recorded stops the next run; only deleting both
a release and its tag before the version is recorded goes unseen. --new-version
must be the committed version and the newest composed version, so a re-run of
an older run cannot serve again what a later registry retired. The live
SHA256SUMS of every version other than --new-version must equal its release's,
and the site must fit the size budget. The manifest records each composed
version with the digests of its archive and SHA256SUMS, and each retired
version left out with the files it could have served: those its SHA256SUMS
lists and the two sums files, or only the sums files when its SHA256SUMS does
not parse, lists an unsafe path or more than MAX_MEMBERS files, since such a
release never passed compose-pages. It must be a new file in an existing
directory, neither inside the site nor containing it; this is checked before
anything is downloaded, and a refusal leaves neither the site nor the manifest.

check-deploy runs right before a Pages deployment, because a re-run of an older
run's pages-deploy would put that run's composition live again. The Pages
manifest must be the record of composing the committed version, that version
must be the newest non-draft vX.Y.Z release, retired ones included, and the
composed versions must be exactly the non-draft vX.Y.Z releases --registry does
not retire, each with the SHA256SUMS digest it was composed with. As in
compose-pages, every other vX.Y.Z tag must have an entry in --registry, so a
newer release deleted with its tag kept still stops it, and the live SHA256SUMS
of every composed version but the committed one must be the composed one, so a
version a later deployment removed is not served again even once that release
and its tag are deleted. Only the committed version is not checked live, since
it is not served before its first deployment; such a re-run can therefore serve
it again although the deleted release's registry retired it.

verify-live requires the Pages manifest compose-pages wrote with this version as
--new-version, recording this archive and the archive's SHA256SUMS, and the
40-hex release commit, before it fetches anything. It waits until every file of
the archive serves the archive's bytes at its plain URL, as users fetch it, and
every file the manifest records for a retired version returns 404 at its plain
URL, with that version's release.json and SHA256SUMS also past the CDN cache.
A check that passed is not repeated and each round stops at the first that has
not, so a round downloads at most the files that converged in it and one stale
response. Network and protocol errors count as not converged yet until the
timeout. It then streams every file to disk cache-busted and compares its
digest, repacks the fetched files into the canonical archive, verifies
SHA256SUMS.asc and install.sh.asc, requires the fetched files to be exactly
those the signed SHA256SUMS lists with its digests and the signed
publication-manifest.json to name this version, base URL, release key and
commit, and compares the live SHA256SUMS of the other versions with the Pages
manifest. Every other network or protocol error refuses at once.

Every release archive is first scanned by its raw tar headers (release_tar):
at most MAX_MEMBERS headers, extension headers included, and only regular
files and GNU long names.
"""
import argparse
import contextlib
import hashlib
from http.client import HTTPException  # not `import http.client`: the module's http() would shadow the package
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


class NetworkRefused(PublishRefused):
    """A network or HTTP protocol failure; only verify-live's wait for the deployment to converge retries it."""


def require(condition, message):
    if not condition:
        raise PublishRefused(message)


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def release_title(version):
    return f'Intel NPU Stack {version}'


def rendered_notes(site, archive, version):
    """The release_site notes of a verified site and its canonical archive."""
    try:
        return release_site.render_notes(site, archive)
    except release_site.SiteRefused as error:
        raise PublishRefused(f'{version}: {error}') from None


def release_assets(version):
    return [f'intel-npu-stack-{version}.tar', 'SHA256SUMS', 'SHA256SUMS.asc', 'publication-manifest.json']


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def http(method, url, headers=None, data=None, timeout=120, sink=None):
    """(status, headers, body) without following redirects; network and protocol failures refuse.

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
        except (OSError, HTTPException):
            body = b''
    except (urllib.error.URLError, OSError, HTTPException) as error:
        raise NetworkRefused(f'{method} {urllib.parse.urlsplit(url)._replace(query="").geturl()} failed: '
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
        # http.client would refuse any other header value with the whole Authorization value in its error.
        require(re.fullmatch(r'[\x21-\x7e]{1,4096}', token) is not None,
                'GH_TOKEN must be 1 to 4096 visible ASCII characters (no spaces or line breaks)')
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

    def tags(self):
        """(name, object) of each tag that starts with v, from the listing alone; the object is the commit or the
        annotated tag the ref names, so a moved tag changes it."""
        tags = []
        for ref in self.paged('/git/matching-refs/tags/v'):
            name, target = ref.get('ref', '').removeprefix('refs/tags/'), (ref.get('object') or {}).get('sha')
            require(isinstance(target, str) and re.fullmatch(r'[0-9a-f]{40}', target) is not None,
                    f'the tag listing names no object for {name}')
            tags.append((name, target))
        return tags

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
        # The open file is the body: http.client sends it in blocks, so no asset is held in memory.
        with Path(path).open('rb') as data:
            status, _, content = self.transport('POST', url, self.headers(extra={
                'Content-Type': 'application/octet-stream', 'Content-Length': str(os.fstat(data.fileno()).st_size)}),
                data)
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


def check_identity(root, version, base_url, fingerprint, commit):
    """The signed publication manifest names this version, base URL and release key, and the release commit."""
    manifest = json.loads((Path(root) / 'publication-manifest.json').read_text())
    installer = manifest.get('installer') if isinstance(manifest, dict) else None
    pinned = installer.get('pinned') if isinstance(installer, dict) else None
    require(isinstance(pinned, dict) and pinned.get('version') == version and pinned.get('base_url') == base_url
            and pinned.get('primary_fingerprint') == fingerprint and manifest.get('source_commit') == commit,
            f'the signed publication manifest in the {version} archive names another release')


def check_installer_signature(root, key, fingerprint, version):
    """install.sh.asc passes the release-key policy over install.sh, as verify-live requires after deployment."""
    try:
        release_site.verify_signature(Path(root) / 'install.sh.asc', Path(root) / 'install.sh', key, fingerprint)
    except release_site.SiteRefused as error:
        raise PublishRefused(f'{version}: {error}') from None


def site_bytes(root):
    return sum(path.stat().st_size for path in Path(root).rglob('*') if path.is_file())


def canonical_sha(root):
    """The SHA-256 of the canonical archive of a site directory."""
    with tempfile.TemporaryFile() as rendered:
        release_site.write_archive(root, rendered)
        rendered.seek(0)
        return hashlib.file_digest(rendered, 'sha256').hexdigest()


def local_assets(assets_dir, values, commit, key, notes=None):
    """Digests of the publication assets and the site's bytes, once the signed archive is proven to be this release.

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
        check_installer_signature(root, key, values['primary_fingerprint'], version)
        # verify-live repacks the live files canonically, so any other packing could never be verified.
        require(canonical_sha(root) == digests[archive.name],
                f'the {version} archive is not the canonical archive of its site')
        total = site_bytes(root)
        if notes is not None:
            require(rendered_notes(root, archive, version) == Path(notes).read_bytes(),
                    'the release notes are not the rendering of this release')
    require(total <= MAX_SITE, f'the {version} site is {total} bytes, above the {MAX_SITE}-byte Pages budget')
    return digests, total


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


def check_unpublished(gh, values, phase, registry, assets_dir=None, commit=None, key=None, reserve=None,
                      fetch=fetch_public):
    version, tag = values['version'], 'v' + values['version']
    require(key is not None, 'the committed release key is required')
    if phase == 'publish':
        require(commit is not None and re.fullmatch(r'[0-9a-f]{40}', commit), 'the release commit is required')
        local, size = local_assets(assets_dir, values, commit, key)
        check_pages_room(gh, values, key, registry, size, fetch)
        return publish_state(gh, values, local, commit)[0]
    # The site is not built yet, so the preflight reserves the most bytes it may take.
    require(type(reserve) is int and reserve > 0, 'the preflight needs a positive number of bytes to reserve')
    pages = gh.pages()
    require(pages is not None and pages.get('build_type') == 'workflow'
            and str(pages.get('html_url', '')).rstrip('/') + '/' + version + '/' == values['base_url'],
            'GitHub Pages must be served by GitHub Actions at the committed BASE_URL')
    require(not gh.tag_exists(tag), f'tag {tag} already exists')
    require(not any(release.get('tag_name') == tag for release in gh.releases()),
            f'a release or draft for {tag} already exists')
    status, _ = fetch(cache_busted(values['base_url'] + 'release.json'))
    require(status == 404, f'the live release.json must not exist before publication (HTTP {status})')
    check_pages_room(gh, values, key, registry, reserve, fetch)
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


def check_draft(gh, release_id, tag, commit, title, body, local):
    """Right before the irreversible undraft: still a draft of a full release of this tag, commit, notes and assets."""
    _, _, release = gh.call('GET', f'/releases/{release_id}')
    require(release.get('draft') is True and release.get('prerelease') is False and release.get('tag_name') == tag
            and release.get('target_commitish') == commit, f'the {tag} draft changed before publication')
    require(release.get('name') == title and release.get('body') == body,
            f'the {tag} draft does not carry this publication\'s title and notes')
    check_release_assets(gh, release, local, readback=False)
    # An existing tag is kept on publication, whatever the draft targets.
    require(gh.tag_commit(tag) in {None, commit}, f'tag {tag} names another commit than this publication')


def publish_release(gh, values, assets_dir, notes, commit, key, registry, fetch=fetch_public):
    version, tag = values['version'], 'v' + values['version']
    local, size = local_assets(assets_dir, values, commit, key, notes)
    body = Path(notes).read_text()
    require(0 < len(body) <= 120000, 'release notes must be non-empty and within the GitHub limit')
    title = release_title(version)
    # The room check downloads every served release and the uploads and readback below take minutes more; what it
    # composed must still stand when it ends and again right before the undraft.
    served = served_state(gh, version)
    _, room = check_pages_room(gh, values, key, registry, size, fetch)
    require(served_state(gh, version) == served, 'the served releases or v tags changed during the room check')
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
        # The readback takes minutes: the draft is read again right before it is published, and the request that
        # publishes it names the tag, the commit, the title, the notes and a full release again, so no later change
        # to those takes effect.
        check_draft(gh, release['id'], tag, commit, title, body, local)
        require(served_state(gh, version) == served, 'the served releases or v tags changed before publication')
        check_live_sums(fetch, site_root(values['base_url']), room)
        gh.call('PATCH', f"/releases/{release['id']}", body={
            'draft': False, 'make_latest': 'true', 'tag_name': tag, 'target_commitish': commit, 'prerelease': False,
            'name': title, 'body': body})
    _, _, final = gh.call('GET', f"/releases/{release['id']}")
    require(final.get('draft') is False and final.get('immutable') is True,
            f'the {tag} release is not an immutable published release')
    require(final.get('prerelease') is False and final.get('tag_name') == tag,
            f'the {tag} release was published as a prerelease or under another tag')
    require(final.get('name') == title and final.get('body') == body,
            f'the published {tag} release does not carry this publication\'s title and notes')
    check_release_assets(gh, final, local, readback=False)
    require(gh.tag_commit(tag) == commit, f'tag {tag} does not name the release commit')
    return {'state': state, 'release_id': final['id'], 'tag': tag, 'commit': commit, 'assets': local}


def unique_keys(pairs):
    """A JSON object whose keys are unique, so no later key silently replaces what a reviewer read."""
    require(len({key for key, _ in pairs}) == len(pairs), 'published-versions.json repeats a key')
    return dict(pairs)


def load_registry(path):
    registry = json.loads(Path(path).read_text(), object_pairs_hook=unique_keys)
    require(isinstance(registry, dict) and set(registry) == {'schema_version', 'published', 'retired'}
            and type(registry['schema_version']) is int and registry['schema_version'] == 1,
            'published-versions.json must be schema 1 with published and retired')
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


def version_key(version):
    return tuple(int(part) for part in version.split('.'))


def compose_releases(gh, key, fingerprint, registry, root_url, output, pending=None):
    """Unpack every non-draft vX.Y.Z release but the pending version into output once it passes every gate.

    Returns the composed versions, and each retired version with the files verify-live requires gone: those its
    SHA256SUMS lists and the two sums files, or only the sums files when its SHA256SUMS does not parse, lists an
    unsafe path or more than MAX_MEMBERS files, since compose-pages never served such a release. A retired release
    is otherwise only matched with its entry. Every published entry must match a
    composed release and every retired entry an immutable one; check_recorded requires the other direction, an entry
    for every tagged version. The pending version is neither composed nor looked for, and every other release,
    retired ones included, must be older: versions are published in increasing order.
    """
    retired = {entry['version']: entry['sha256sums_sha256'] for entry in registry['retired']}
    candidates = sorted((release for release in gh.releases()
                         if not release.get('draft') and TAG.fullmatch(release.get('tag_name') or '')
                         and release['tag_name'] != f'v{pending}'),
                        key=lambda release: version_key(release['tag_name'][1:]))
    newer = [release['tag_name'] for release in candidates
             if pending is not None and version_key(release['tag_name'][1:]) >= version_key(pending)]
    require(not newer, f'versions are published in increasing order, and {pending} is not newer than '
            + ', '.join(newer))
    versions, gone = {}, {}
    with tempfile.TemporaryDirectory(prefix='compose-pages-') as work:
        for release in candidates:
            version = release['tag_name'][1:]
            assets = {asset.get('name'): asset for asset in release.get('assets', [])}
            folder = Path(work) / version
            folder.mkdir()
            require(release.get('immutable') is True, f"release {release['tag_name']} is not immutable")
            # publish-release never makes one, so a release flipped to prerelease must not silently leave Pages.
            require(release.get('prerelease') is False, f"release {release['tag_name']} is marked a prerelease")
            if version in retired:
                # A retirement record must name the release it retires.
                require('SHA256SUMS' in assets, f"retired release {release['tag_name']} has no SHA256SUMS")
                digest = gh.download_asset(assets['SHA256SUMS'], folder / 'SHA256SUMS')
                require(assets['SHA256SUMS'].get('digest') == 'sha256:' + digest and digest == retired[version],
                        f'the retired entry for {version} does not match its release SHA256SUMS')
                # verify-live fetches each file this version could have served. compose-pages refuses a release whose
                # SHA256SUMS does not parse, lists an unsafe path or more files than an archive may hold, so Pages
                # never served one: only its two sums files are recorded, and retiring it stays possible.
                try:
                    paths = sorted({*parse_sums((folder / 'SHA256SUMS').read_bytes()), 'SHA256SUMS', 'SHA256SUMS.asc'})
                except PublishRefused:
                    paths = []
                gone[version] = paths if 0 < len(paths) <= MAX_MEMBERS else ['SHA256SUMS', 'SHA256SUMS.asc']
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
            check_installer_signature(output / version, key, fingerprint, version)
            require(canonical_sha(output / version) == release_site.sha(data[release_assets(version)[0]]),
                    f'the {version} archive is not the canonical archive of its site')
            # A release made or edited outside publish-release must still carry exactly what it would have set.
            notes = rendered_notes(output / version, data[release_assets(version)[0]], version).decode()
            require(release.get('name') == release_title(version) and release.get('body') == notes,
                    f"release {release['tag_name']} does not carry its title and rendered notes")
            check_standalone(data[release_assets(version)[0]], version, data)
            versions[version] = {'sha256sums_sha256': release_site.sha(data['SHA256SUMS']),
                                 'archive_sha256': release_site.sha(data[release_assets(version)[0]]),
                                 'files': files, 'release_id': release.get('id')}
    for entry in registry['published']:
        require(entry['version'] in versions, f"published version {entry['version']} is missing; a deleted "
                'release can be neither served nor retired, so its entry and its tag are removed by hand after review')
        require(versions[entry['version']]['sha256sums_sha256'] == entry['sha256sums_sha256'],
                f"published version {entry['version']} has another SHA256SUMS than recorded")
    missing = sorted(set(retired) - set(gone))
    require(not missing, 'retired versions without an immutable release: ' + ', '.join(missing))
    return versions, gone


def check_recorded(gh, registry, version):
    """Every vX.Y.Z tag but this run's version has a registry entry, so no version leaves Pages unnoticed.

    Composing needs each release's tag, and GitHub keeps the tag of a deleted release, so a release that is not
    recorded yet, or was deleted before it was recorded, is refused: the change that records a release lands before
    the next one. Deleting both a release and its tag before it is recorded is the one removal this cannot see.
    """
    recorded = {entry['version'] for entry in registry['published'] + registry['retired']}
    tagged = {name[1:] for name, _ in gh.tags() if TAG.fullmatch(name)}
    missing = sorted(tagged - recorded - {version}, key=version_key)
    require(not missing, 'tagged versions without an entry in published-versions.json: ' + ', '.join(missing))


def check_live_sums(fetch, root_url, versions, undeployed=None):
    """The live SHA256SUMS of every composed version but the undeployed one is its release's, past the CDN cache."""
    for version, record in versions.items():
        if version == undeployed:
            continue
        status, body = fetch(cache_busted(f'{root_url}{version}/SHA256SUMS'))
        require(status == 200 and sha_bytes(body) == record['sha256sums_sha256'],
                f'the live {version}/SHA256SUMS differs from its release (HTTP {status})')


def served_state(gh, version):
    """What the room check composed from, read from the listings alone: every other non-draft vX.Y.Z release and
    the v tags with the objects they name. Equal snapshots mean no release it verified or skipped, and no tag it
    counted or bound a release to, changed since; a force-moved tag names another object."""
    tag = 'v' + version
    releases = {release.get('id'): (release.get('tag_name'), release.get('immutable'), release.get('prerelease'),
                                    release.get('name'), release.get('body'),
                                    sorted((str(asset.get('name')), str(asset.get('digest')))
                                           for asset in release.get('assets', [])))
                for release in gh.releases()
                if not release.get('draft') and TAG.fullmatch(release.get('tag_name') or '') and release.get('tag_name') != tag}
    return releases, sorted((name, target) for name, target in gh.tags() if name != tag)


def check_pages_room(gh, values, key, registry_path, reserve, fetch=fetch_public):
    """compose-pages without this version, run dry before anything irreversible; the bytes and versions it serves.

    Every non-draft vX.Y.Z release but this version is composed into a temporary directory with every compose-pages
    gate, including the live SHA256SUMS of each composed version and a registry entry for every other tagged
    version. This version must be newer than every such release and not yet in the registry, and the composed site
    plus the reserved bytes must fit the Pages budget.
    """
    version = values['version']
    registry = load_registry(registry_path)
    require(version not in {entry['version'] for entry in registry['published'] + registry['retired']},
            f'published-versions.json already lists {version}')
    root_url = site_root(values['base_url'])
    with tempfile.TemporaryDirectory(prefix='pages-room-') as work:
        site = Path(work) / '_site'
        site.mkdir()
        versions, _ = compose_releases(gh, key, values['primary_fingerprint'], registry, root_url, site,
                                       pending=version)
        check_recorded(gh, registry, version)
        check_live_sums(fetch, root_url, versions)
        total = site_bytes(site)
    require(total + reserve <= MAX_SITE,
            f'the Pages site would be {total + reserve} bytes with {version}, above the {MAX_SITE}-byte budget')
    return total, versions


def compose_pages(gh, values, key, fingerprint, registry_path, output, manifest_path, new_version=None,
                  fetch=fetch_public, limit=MAX_SITE):
    output, manifest_path = Path(output), Path(manifest_path)
    require(not output.exists() and not manifest_path.exists(), 'outputs are never overwritten')
    # With the site not existing yet, a manifest inside it has no directory; one containing it is refused here.
    require(manifest_path.parent.is_dir() and not output.resolve().is_relative_to(manifest_path.resolve()),
            'the Pages manifest must be a new file in an existing directory, neither inside the site nor containing it')
    require(new_version in {None, values['version']},
            f"the new version {new_version} is not the committed version {values['version']}")
    registry = load_registry(registry_path)
    root_url = site_root(values['base_url'])
    output.mkdir(parents=True)
    written = False
    try:
        versions, gone = compose_releases(gh, key, fingerprint, registry, root_url, output)
        require(new_version is None or new_version in versions, f'the new version {new_version} is not composed')
        newest = max(versions, key=version_key, default=None)
        # A re-run of an older run's pages-build must not serve what a later registry retired.
        require(new_version in {None, newest}, f'the new version {new_version} is not the newest release {newest}')
        check_recorded(gh, registry, new_version)
        check_live_sums(fetch, root_url, versions, new_version)
        total = site_bytes(output)
        require(total <= limit, f'the Pages site is {total} bytes, above the {limit}-byte budget')
        # Each retired version it left out, with every file that version served; verify-live requires them gone.
        manifest = {'schema_version': 1, 'base_url': values['base_url'], 'versions': versions, 'total_bytes': total,
                    'new_version': new_version, 'retired': gone}
        with open(manifest_path, 'x') as stream:
            written = True
            stream.write(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        if written:
            manifest_path.unlink(missing_ok=True)
        raise
    return manifest


def pages_record(path, values):
    """The Pages manifest compose-pages wrote with the committed version as --new-version."""
    version = values['version']
    record = json.loads(Path(path).read_text())
    retired = record.get('retired') if isinstance(record, dict) else None
    require(isinstance(record, dict) and record.get('schema_version') == 1
            and record.get('base_url') == values['base_url'] and record.get('new_version') == version
            and isinstance(record.get('versions'), dict) and isinstance(retired, dict)
            and all(TAG.fullmatch('v' + old) and isinstance(paths, list)
                    and all(isinstance(path, str) and plain_path(path) for path in paths)
                    for old, paths in retired.items()),
            f'the Pages manifest is not the record of composing {version}')
    return record


def check_deploy(gh, values, registry_path, pages_manifest, fetch=fetch_public):
    """Right before a deployment: the recorded composition is still the one compose-pages would serve.

    A job re-run reuses its run's artifacts, so a re-run of an older run's pages-deploy could otherwise put that
    run's composition live again after a newer release. The committed version must be the newest non-draft vX.Y.Z
    release, retired ones included, and the composed versions exactly the non-draft vX.Y.Z releases the run's
    registry does not retire, each with the SHA256SUMS digest it was composed with. Every other vX.Y.Z tag must have
    an entry in that registry, as compose-pages requires: GitHub keeps the tag of a deleted release, so a newer
    release deleted after this composition still stops it. As in compose-pages, the live SHA256SUMS of every
    composed version but the committed one must be the composed one, so a version a later deployment removed is not
    served again even once that release and its tag are deleted. Only the committed version is not checked live,
    since it is not served before its first deployment; such a re-run can therefore serve it again although the
    deleted release's registry retired it. It reads the release and tag listings and those live files.
    """
    version = values['version']
    record = pages_record(pages_manifest, values)
    registry = load_registry(registry_path)
    retired = {entry['version'] for entry in registry['retired']}
    releases = sorted((release for release in gh.releases()
                       if not release.get('draft') and TAG.fullmatch(release.get('tag_name') or '')),
                      key=lambda release: version_key(release['tag_name'][1:]))
    stale = f'the composition of {version} is out of date: '
    newest = releases[-1]['tag_name'][1:] if releases else None
    require(newest == version, stale + f'the newest release is {newest}')
    served = [release for release in releases if release['tag_name'][1:] not in retired]
    composed = sorted(record['versions'], key=version_key)
    names = [release['tag_name'][1:] for release in served]
    require(names == composed, stale + f"compose-pages would serve {', '.join(names)}, not {', '.join(composed)}")
    for release in served:
        entry = record['versions'][release['tag_name'][1:]]
        digests = [asset.get('digest') for asset in release.get('assets', []) if asset.get('name') == 'SHA256SUMS']
        require(isinstance(entry, dict) and digests == ['sha256:' + str(entry.get('sha256sums_sha256'))],
                stale + f"release {release['tag_name']} is not the release it composed")
    check_recorded(gh, registry, version)
    check_live_sums(fetch, site_root(values['base_url']), record['versions'], version)
    return {'new_version': version, 'versions': names}


def site_location(base_url):
    parts = urllib.parse.urlsplit(base_url)
    segments = parts.path.strip('/').split('/')
    require(parts.scheme == 'https' and parts.hostname and len(segments) >= 2, 'the base URL must be versioned HTTPS')
    return parts.hostname, '/' + '/'.join(segments[:-1]) + '/', segments[-1]


def site_root(base_url):
    """The Pages URL the version directories are served under."""
    host, prefix, _ = site_location(base_url)
    return f'https://{host}{prefix}'


def verify_live(values, key, fingerprint, archive, pages_manifest, commit, fetched=None, timeout=1200,
                fetch=fetch_public, sleep=time.sleep, clock=time.monotonic):
    version, base = values['version'], values['base_url']
    require(isinstance(commit, str) and re.fullmatch(r'[0-9a-f]{40}', commit) is not None,
            'verify-live needs the 40-hex release commit')
    # The record pages-build wrote for this version names every other version the deployed site serves, and each
    # retired version it left out with the files that version could have served.
    record = pages_record(pages_manifest, values)
    retired = record['retired']
    expected = {}
    with open_archive(archive) as tar:
        for member in tar.getmembers():
            path = member.name[len(version) + 1:] if member.name.startswith(version + '/') else ''
            require(member.isreg() and plain_path(path) and path not in expected,
                    'unsafe or duplicate member in the release archive: ' + repr(member.name))
            expected[path] = hashlib.file_digest(tar.extractfile(member), 'sha256').hexdigest()
    archive_sha, recorded, root_url = release_site.sha(archive), record['versions'].get(version), site_root(base)
    require(isinstance(recorded, dict) and recorded.get('archive_sha256') == archive_sha
            and recorded.get('sha256sums_sha256') == expected.get('SHA256SUMS'),
            f'the Pages manifest does not record this {version} archive and its SHA256SUMS')
    # Users fetch every file at its plain URL, where the CDN caches each one on its own: every file of this version
    # must serve the archive's bytes there, and every file of a retired version must be gone. Past the CDN cache, the
    # Pages origin drops a version's directory as a whole, so a retired release.json and SHA256SUMS stand for it.
    # A check that passed is not repeated and a round stops at the first that has not, so a round downloads at most
    # the files that converged in it and one stale response, however large the site.
    checks = [(base + path, False, (200, expected.get(path)), f'the live {path} is still stale or missing')
              for path in [*PLAIN, *sorted(set(expected) - set(PLAIN))]]
    checks += [(f'{root_url}{old}/{path}', busted, (404, None), f'the retired {old}/{path} still does not return 404')
               for old in sorted(retired, key=version_key)
               for path, busted in [*((path, False) for path in retired[old]), ('release.json', True),
                                    ('SHA256SUMS', True)]]
    deadline = clock() + timeout
    for url, busted, wanted, what in checks:
        while True:
            try:
                served = live_sha(fetch, cache_busted(url) if busted else url)
                problem = f"{what} {'past the CDN cache' if busted else 'at its plain URL'} (HTTP {served[0]})"
            except NetworkRefused as error:  # right after a deployment, a network error only means not converged yet
                served, problem = None, f'the live site could not be read before the timeout: {error}'
            if served == wanted:
                break
            require(clock() < deadline, problem)
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
        require(canonical_sha(root) == archive_sha, 'the live files do not repack into the release archive')
        try:
            release_site.verify_signature(root / 'SHA256SUMS.asc', root / 'SHA256SUMS', key, fingerprint)
            release_site.verify_signature(root / 'install.sh.asc', root / 'install.sh', key, fingerprint)
        except release_site.SiteRefused as error:
            raise PublishRefused('live ' + str(error)) from None
        listed = parse_sums((root / 'SHA256SUMS').read_bytes())
        require(set(listed) | {'SHA256SUMS', 'SHA256SUMS.asc'} == set(expected),
                'the live files are not exactly the files the signed SHA256SUMS lists')
        for path, digest in sorted(listed.items()):
            require(release_site.sha(root / path) == digest, f'the live {path} differs from the signed SHA256SUMS')
        check_identity(root, version, base, fingerprint, commit)
    others = {}
    for other, entry in record['versions'].items():
        if other == version:
            continue
        status, body = fetch(cache_busted(f'{root_url}{other}/SHA256SUMS'))
        require(status == 200 and sha_bytes(body) == entry['sha256sums_sha256'],
                f'the live {other}/SHA256SUMS changed (HTTP {status})')
        others[other] = entry['sha256sums_sha256']
    return {'version': version, 'files': len(expected), 'archive_sha256': archive_sha, 'other_versions': others,
            'retired_versions': sorted(retired, key=version_key), 'passed': True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     allow_abbrev=False)
    parser.add_argument('command', choices=['check-unpublished', 'publish-release', 'compose-pages', 'check-deploy',
                                            'verify-live'])
    parser.add_argument('--repo', type=Path, default=REPO)
    parser.add_argument('--phase', choices=['preflight', 'publish'])
    parser.add_argument('--assets', type=Path)
    parser.add_argument('--notes', type=Path)
    parser.add_argument('--sha', default=os.environ.get('GITHUB_SHA'))
    parser.add_argument('--registry', type=Path)
    parser.add_argument('--reserve-bytes', type=int)
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
        preflight = args.command == 'check-unpublished' and args.phase == 'preflight'
        require(preflight or args.reserve_bytes is None,
                'only check-unpublished --phase preflight takes --reserve-bytes')
        if args.command == 'verify-live':
            require(args.archive is not None, 'verify-live requires --archive')
            require(args.pages_manifest is not None, 'verify-live requires --pages-manifest')
            require(args.sha is not None, 'verify-live requires --sha (or GITHUB_SHA)')
            require(re.fullmatch(r'[0-9a-f]{40}', args.sha) is not None, '--sha must name the 40-hex release commit')
            result = verify_live(values, key, values['primary_fingerprint'], args.archive, args.pages_manifest,
                                 args.sha, args.fetched, args.timeout)
        else:
            gh = GitHub(os.environ.get('GITHUB_API_URL', 'https://api.github.com'),
                        os.environ.get('GITHUB_REPOSITORY'), os.environ.get('GH_TOKEN'))
            if args.command == 'check-unpublished':
                require(None not in (args.phase, args.registry), 'check-unpublished requires --phase and --registry')
                require(not preflight or args.reserve_bytes is not None, '--phase preflight requires --reserve-bytes')
                require(preflight or args.assets is not None, '--phase publish requires --assets')
                result = {'phase': args.phase,
                          'state': check_unpublished(gh, values, args.phase, args.registry, assets_dir=args.assets,
                                                     commit=args.sha, key=key, reserve=args.reserve_bytes)}
            elif args.command == 'publish-release':
                require(None not in (args.assets, args.notes, args.sha, args.registry),
                        'publish-release needs --assets, --notes, --sha and --registry')
                result = publish_release(gh, values, args.assets, args.notes, args.sha, key, args.registry)
            elif args.command == 'check-deploy':
                require(None not in (args.registry, args.pages_manifest),
                        'check-deploy needs --registry and --pages-manifest')
                result = check_deploy(gh, values, args.registry, args.pages_manifest)
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
