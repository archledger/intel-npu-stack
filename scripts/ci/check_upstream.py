#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Issue-only upstream release watcher for the pinned primary components.

Remote tags, release names, URLs and asset metadata are untrusted data: they
are parsed with bounded output, never interpolated into shell source, and only
rendered into issue titles/bodies as data. This module performs no writes;
the workflow turns its JSON findings into deduplicated GitHub issues.
"""
import argparse
import json
from pathlib import Path
import re
import sys
import tomllib
import urllib.error
import urllib.request

API_ROOT = 'https://api.github.com'
TAG_LIMIT = 10
MAX_BODY = 1 << 20
TIMEOUT = 30

WATCHED = {
    'linux-npu-driver': 'intel/linux-npu-driver',
    'openvino': 'openvinotoolkit/openvino',
    'level-zero': 'oneapi-src/level-zero',
    'npu-compiler': 'openvinotoolkit/npu_compiler',
}

SEMVER = re.compile(r'^v?(\d+)\.(\d+)\.(\d+)$')
MANUAL_NOTE = 'non-semver tags: manual review required before any candidate work'


class WatchedComponent:
    """One pinned primary component and the newest upstream observation."""

    def __init__(self, name, repository, pinned_tag, pinned_commit):
        self.name = name
        self.repository = repository
        self.pinned_tag = pinned_tag
        self.pinned_commit = pinned_commit


def load_pinned(manifest_path):
    """Read the watched components from the trusted in-repo source manifest."""
    document = tomllib.loads(Path(manifest_path).read_text())
    pinned = {}
    for source in document.get('sources', []):
        name = source.get('name')
        if name not in WATCHED:
            continue
        repository = source['url'].removeprefix('https://github.com/').removesuffix('.git')
        if repository != WATCHED[name]:
            raise ValueError(f'{name} moved from {WATCHED[name]} to {repository}')
        pinned[name] = {'tag': source['tag'], 'commit': source['commit'], 'repository': repository}
    missing = set(WATCHED) - set(pinned)
    if missing:
        raise ValueError('manifest lacks watched sources: ' + ', '.join(sorted(missing)))
    return pinned


def _semver(tag):
    match = SEMVER.fullmatch(tag or '')
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


def compare_tags(pinned, latest):
    """Classify the latest upstream tag relative to the pinned tag."""
    pinned_version = _semver(pinned)
    latest_version = _semver(latest)
    if pinned_version is not None and latest_version is not None:
        if latest_version > pinned_version:
            return 'newer'
        if latest_version == pinned_version:
            return 'same'
        return 'older'
    return 'same' if pinned == latest else 'different'


class _NotFound(Exception):
    """The requested upstream resource does not exist."""


class _Response:
    def __init__(self, raw):
        self._raw = raw

    def read_bytes(self):
        return self._raw


class HttpSession:
    """Minimal adapter matching the test session interface over urllib."""

    USER_AGENT = 'intel-npu-stack-upstream-watch'

    def get(self, url, timeout):
        request = urllib.request.Request(url, headers={'User-Agent': self.USER_AGENT})
        try:
            response = urllib.request.urlopen(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise _NotFound(url) from error
            raise
        return _Response(response.read())


def _get_json(session, url):
    response = session.get(url, timeout=TIMEOUT)
    body = response.read_bytes()
    if len(body) > MAX_BODY:
        raise ValueError('upstream response exceeds byte limit')
    document = json.loads(body)
    if isinstance(document, dict) and document.get('message') == 'Not Found':
        raise _NotFound(url)
    return document


def _resolve_commit(session, repository, tag):
    """Resolve a tag name to its commit SHA, following annotated tag objects."""
    reference = _get_json(session, f'{API_ROOT}/repos/{repository}/git/ref/tags/{tag}')
    target = reference['object']
    commit = target['sha']
    if target.get('type') == 'tag':
        annotated = _get_json(session, f'{API_ROOT}/repos/{repository}/git/tags/{commit}')
        commit = annotated['object']['sha']
    return commit


def fetch_latest(session, repository):
    """Return the newest non-draft upstream {tag, commit, url, source}."""
    try:
        release = _get_json(session, f'{API_ROOT}/repos/{repository}/releases/latest')
    except _NotFound:
        release = None
    if release is not None:
        if release.get('draft') or release.get('prerelease'):
            raise ValueError('latest release endpoint returned a draft or prerelease')
        tag = release['tag_name']
        try:
            commit = _resolve_commit(session, repository, tag)
        except _NotFound:
            commit = ''
        return {'tag': tag,
                'commit': commit,
                'url': release.get('html_url') or '',
                'source': 'release'}
    tags = _get_json(session, f'{API_ROOT}/repos/{repository}/tags?per_page={TAG_LIMIT}')
    if not tags:
        raise ValueError(f'{repository} exposes no tags')
    newest = tags[0]
    target = newest['object']
    commit = target['sha']
    if target.get('type') == 'tag':
        annotated = _get_json(session, f'{API_ROOT}/repos/{repository}/git/tags/{commit}')
        commit = annotated['object']['sha']
    return {'tag': newest['name'], 'commit': commit,
            'url': f'https://github.com/{repository}/releases/tag/{newest["name"]}',
            'source': 'tags'}


def dedup_key(repository, tag):
    return f'upstream:{repository}:{tag}'


def existing_keys(open_issues):
    """Extract dedup keys from open issue titles; titles are data, not commands."""
    keys = set()
    for issue in open_issues:
        title = issue.get('title') or ''
        for token in title.replace(']', ' ').split():
            if token.startswith('upstream:') and token.count(':') >= 2:
                keys.add(token)
    return keys


def scan(session, pinned, open_keys):
    """Produce one finding per genuinely new upstream release."""
    findings = []
    for name in sorted(pinned):
        component = pinned[name]
        try:
            latest = fetch_latest(session, component['repository'])
        except (ValueError, KeyError, json.JSONDecodeError, OSError):
            findings.append({'component': name, 'repository': component['repository'],
                             'observation': 'check-failed',
                             'note': 'upstream query failed; scheduled runs are advisory'})
            continue
        relation = compare_tags(component['tag'], latest['tag'])
        if relation in {'same', 'older'}:
            continue
        key = dedup_key(component['repository'], latest['tag'])
        if key in open_keys:
            continue
        finding = {'component': name, 'repository': component['repository'],
                   'observation': 'update-available', 'dedup_key': key,
                   'pinned_tag': component['tag'], 'pinned_commit': component['commit'],
                   'latest_tag': latest['tag'], 'latest_commit': latest['commit'],
                   'latest_url': latest['url'], 'source': latest['source']}
        if relation == 'different':
            finding['note'] = MANUAL_NOTE
        findings.append(finding)
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path,
                        default=Path(__file__).resolve().parents[2] / 'packaging/fedora/44/provider-sources.toml')
    parser.add_argument('--report', type=Path, help='write findings JSON to this path')
    parser.add_argument('--open-issues', type=Path,
                        help='JSON array of open issue objects used for deduplication')
    args = parser.parse_args(argv)
    pinned = load_pinned(args.manifest)
    raw = args.open_issues.read_text().strip() if args.open_issues else ''
    open_keys = existing_keys(json.loads(raw) if raw else [])
    session = HttpSession()
    findings = scan(session, pinned, open_keys)
    report = {'schema_version': 1, 'findings': findings}
    text = json.dumps(report, indent=2) + '\n'
    if args.report:
        args.report.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
