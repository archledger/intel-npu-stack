#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare an unqualified candidate pin update from a validated watcher finding.

Reads one open `upstream-update` issue, re-resolves the upstream tag to its
commit, downloads the immutable source archive to hash it, and rewrites only
the matching provider source lock entry. It refuses when any production
profile is already qualified. Upstream strings are untrusted data throughout.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
import urllib.error
import urllib.request

MAX_DOWNLOAD = 256 * 1024 * 1024
MAX_PROFILE_BYTES = 1 << 20
TIMEOUT = 60
TAGS = ('linux-npu-driver', 'openvino', 'level-zero', 'npu-compiler')

KEY = re.compile(r'^upstream:(?P<repository>[^:\s]+):(?P<tag>[^:\s]+)$')
BODY_FIELD = re.compile(r'^- (?P<name>[A-Za-z ]+): (?P<value>\S.*)$')


class _Response:
    def __init__(self, raw):
        self._raw = raw

    def read_bytes(self):
        return self._raw


class HttpSession:
    USER_AGENT = 'intel-npu-stack-prepare-candidate'

    def get(self, url, timeout):
        request = urllib.request.Request(url, headers={'User-Agent': self.USER_AGENT})
        return _Response(urllib.request.urlopen(request, timeout=timeout).read())


def finding_from_issue(title, body):
    """Parse and cross-check one watcher issue into a finding dictionary."""
    match = None
    for token in (title or '').replace(']', ' ').split():
        if KEY.fullmatch(token):
            match = KEY.fullmatch(token)
    if match is None:
        raise ValueError('issue title carries no upstream dedup key')
    fields = {}
    for line in body.splitlines():
        line_match = BODY_FIELD.match(line)
        if line_match:
            fields[line_match.group('name').lower().replace(' ', '_')] = \
                line_match.group('value').strip()
    for required in ('component', 'repository', 'pinned_tag', 'pinned_commit',
                     'latest_tag', 'latest_commit'):
        if not fields.get(required):
            raise ValueError(f'issue body lacks the {required} field')
    if fields['repository'] != match.group('repository'):
        raise ValueError('issue title and body disagree about the repository')
    if fields['latest_tag'] != match.group('tag'):
        raise ValueError('issue title and body disagree about the release tag')
    if fields['component'] not in TAGS:
        raise ValueError(f"{fields['component']} is not a watched primary component")
    return fields


def qualified_profiles(profiles_dir):
    """Every production profile already marked qualified; any entry blocks work."""
    blocked = []
    for path in sorted(Path(profiles_dir).glob('*.toml')):
        text = path.read_text()
        if len(text) > MAX_PROFILE_BYTES:
            raise ValueError(f'{path.name} exceeds the profile size bound')
        if tomllib.loads(text).get('status') == 'qualified':
            blocked.append(path)
    return blocked


def _blocks(text):
    return text.split('[[sources]]')


def _own_scalars(block):
    """A block's own scalar lines, excluding its [[sources.gitlinks]] stanzas."""
    lines = []
    for line in block.splitlines():
        if line.startswith('[['):
            break
        lines.append(line)
    return lines


def load_lock_source(text, component):
    for block in _blocks(text)[1:]:
        if f'name = "{component}"' in _own_scalars(block) or \
                any(line == f'name = "{component}"' for line in _own_scalars(block)):
            record = {}
            for line in _own_scalars(block):
                if ' = ' in line and not line.startswith('#'):
                    key, value = line.split(' = ', 1)
                    record[key.strip()] = value.strip()
            source = {'kind': record.get('kind', '').strip('"'),
                      'tag': record.get('tag', '').strip('"') or None,
                      'commit': record.get('commit', '').strip('"'),
                      'tag_object': record.get('tag_object', '').strip('"') or None}
            if not source['commit']:
                raise ValueError(f'{component} entry has no pinned commit')
            return source
    raise ValueError(f'unknown provider source: {component}')


def _replace_or_remove(lines, index, key, value):
    """Rewrite one `key = "value"` line in place, or drop it when value is None."""
    if value is None:
        del lines[index]
    else:
        lines[index] = f'{key} = "{value}"'


def apply_pin(text, component, tag, commit, tag_object, archive_sha256):
    """Return (updated_text, changed) with only the component's pin lines edited."""
    blocks = _blocks(text)
    for position, block in enumerate(blocks[1:], start=1):
        if f'name = "{component}"' not in block:
            continue
        lines = block.splitlines()
        current = load_lock_source(text, component)
        if current['commit'] == commit and current['tag'] == tag:
            return text, False
        scalars = _own_scalars(block)
        indexes = {}
        for index, line in enumerate(scalars):
            for key in ('kind', 'tag', 'commit', 'archive_sha256', 'tag_object'):
                if line.startswith(key + ' = '):
                    indexes[key] = index
        for key in ('tag', 'commit', 'archive_sha256'):
            if key not in indexes:
                raise ValueError(f'{component} entry lacks a {key} line')
        scalars[indexes['tag']] = f'tag = "{tag}"'
        scalars[indexes['commit']] = f'commit = "{commit}"'
        scalars[indexes['archive_sha256']] = f'archive_sha256 = "{archive_sha256}"'
        kind = 'git_annotated_tag' if tag_object else 'git_tag'
        if 'kind' in indexes:
            scalars[indexes['kind']] = f'kind = "{kind}"'
        else:
            raise ValueError(f'{component} entry lacks a kind line')
        if tag_object:
            if 'tag_object' in indexes:
                scalars[indexes['tag_object']] = f'tag_object = "{tag_object}"'
            else:
                scalars.insert(indexes['commit'] + 1, f'tag_object = "{tag_object}"')
        elif 'tag_object' in indexes:
            del scalars[indexes['tag_object']]
        rebuilt = '\n'.join(scalars) + block[len('\n'.join(_own_scalars(block))):]
        blocks[position] = rebuilt if rebuilt.endswith('\n') else rebuilt + '\n'
        return '[[sources]]'.join(blocks), True
    raise ValueError(f'unknown provider source: {component}')


def archive_url(source_url, commit):
    """The immutable commit-addressed tarball URL for one GitHub source."""
    repository = source_url.removeprefix('https://github.com/').removesuffix('.git')
    if '/' not in repository:
        raise ValueError('only github.com sources are supported')
    return f'https://codeload.github.com/{repository}/tar.gz/{commit}'


def download_digest(session, url, limit=MAX_DOWNLOAD):
    """Stream one bounded download and return its SHA256 hex digest."""
    import io
    response = session.get(url, timeout=TIMEOUT)
    digest = hashlib.sha256()
    total = 0
    reader = io.BytesIO(response.read_bytes())
    while block := reader.read(1024 * 1024):
        total += len(block)
        if total > limit:
            raise ValueError('archive exceeds the download byte limit')
        digest.update(block)
    if total == 0:
        raise ValueError('archive download returned no bytes')
    return digest.hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--issue-title', required=True)
    parser.add_argument('--issue-body', required=True)
    parser.add_argument('--lock', type=Path,
                        default=Path(__file__).resolve().parents[2] /
                        'packaging/fedora/44/provider-sources.toml')
    parser.add_argument('--profiles', type=Path,
                        default=Path(__file__).resolve().parents[2] / 'profiles')
    parser.add_argument('--resolved-tag', help='JSON from live tag re-resolution '
                        '{"commit": .., "tag_object": ..} guarding against retagging')
    parser.add_argument('--archive-digest', help='pre-computed archive digest; '
                        'the download is skipped when given and matching')
    parser.add_argument('--output', type=Path, help='write the updated lock here')
    args = parser.parse_args(argv)
    finding = finding_from_issue(args.issue_title, args.issue_body)
    blocked = qualified_profiles(args.profiles)
    if blocked:
        print('refusing: qualified profiles would be affected: ' +
              ', '.join(path.name for path in blocked), file=sys.stderr)
        return 3
    text = args.lock.read_text()
    session = HttpSession()
    resolution = json.loads(Path(args.resolved_tag).read_text()) if args.resolved_tag else None
    if resolution is not None and resolution.get('commit') != finding['latest_commit']:
        print('refusing: upstream tag no longer resolves to the recorded commit',
              file=sys.stderr)
        return 4
    tag_object = resolution.get('tag_object') if resolution else None
    digest = args.archive_digest
    if not digest:
        digest = download_digest(session, archive_url(
            _source_url(text, finding['component']), finding['latest_commit']))
    updated, changed = apply_pin(text, finding['component'], finding['latest_tag'],
                                 finding['latest_commit'], tag_object, digest)
    if not changed:
        print(json.dumps({'status': 'already-current', 'component': finding['component']}))
        return 0
    if args.output:
        args.output.write_text(updated)
    else:
        sys.stdout.write(updated)
    return 0


def _source_url(text, component):
    for block in _blocks(text)[1:]:
        if f'name = "{component}"' in block:
            for line in block.splitlines():
                if line.startswith('url = '):
                    return line.split(' = ', 1)[1].strip().strip('"')
    raise ValueError(f'unknown provider source: {component}')


if __name__ == '__main__':
    raise SystemExit(main())
