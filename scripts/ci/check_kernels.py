#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Issue-only watcher for Fedora 44 kernel updates against the qualified kernel window.

A qualified profile admits a kernel series (for example [7.2.5, 7.3.0)); newer
kernels inside that window are admitted by policy but need a recorded
per-kernel probe (release/kernel-probes.json, docs/kernel-probes.md); the
kernels the qualification evidence covers are recorded there too. A kernel at
or above a profile's window needs a new qualification of that profile. Each
qualified profile is classified separately, and records apply only to the
profile's current component set and evidence. Bodhi data is
untrusted: only regex-validated kernel NVRs reach the findings. This module
performs no writes; the workflow turns findings into deduplicated issues.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
import unicodedata
import urllib.parse
import urllib.request

BODHI = 'https://bodhi.fedoraproject.org/updates/'
QUERY = [('packages', 'kernel'), ('releases', 'F44'), ('status', 'stable'), ('status', 'testing'),
         ('status', 'obsolete'), ('rows_per_page', '100')]
MAX_PAGES = 20
MAX_BODY = 4 << 20
TIMEOUT = 30
KERNEL_NVR = re.compile(r'kernel-(\d{1,3})\.(\d{1,3})\.(\d{1,4})-(\d{1,4}(?:\.[0-9A-Za-z]{1,40}){0,6})\.fc44')
MAX_SCALAR_BYTES = 4096  # the profile schema's scalar limit
U64_MAX = 2 ** 64 - 1
ALIAS = re.compile(r'FEDORA-\d{4}-[0-9a-f]{10}')
DIGEST = re.compile(r'[0-9a-f]{64}')
DATE = re.compile(r'\d{4}-\d{2}-\d{2}')
PROBE_FIELDS = {'kernel', 'profile', 'components_sha256', 'result', 'source', 'evidence_sha256', 'recorded'}
KEY_PREFIX = 'kernel:fedora-44:'
# Rank of a build's most published state; obsolete builds count only if they reached updates-testing.
OBSERVED = {'stable': 3, 'testing': 2, 'obsolete': 1}


def fetch_json(url, timeout=TIMEOUT):
    request = urllib.request.Request(url, headers={'Accept': 'application/json',
                                                   'User-Agent': 'intel-npu-stack-kernel-watch'})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (fixed https URL)
        body = response.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise ValueError('Bodhi response exceeds the size limit')
    return json.loads(body)


def fetch_updates(fetch):
    """Every stable, testing and obsolete Fedora 44 kernel update, following Bodhi's pagination."""
    updates, page, pages = [], 1, 1
    while page <= pages:
        document = fetch(BODHI + '?' + urllib.parse.urlencode(QUERY + [('page', str(page))]), TIMEOUT)
        if not isinstance(document, dict) or not isinstance(document.get('updates'), list):
            raise ValueError('unexpected Bodhi response')
        pages = document.get('pages')
        if type(pages) is not int or not 0 <= pages <= MAX_PAGES:
            raise ValueError('Bodhi page count is missing or above the limit')
        updates.extend(document['updates'])
        page += 1
    return {'updates': updates}


def parse_kernel_nvr(nvr):
    """(major, minor, patch) and the 'version-release' string for a Fedora 44 kernel build."""
    if not isinstance(nvr, str) or len(nvr) > 64:
        return None
    match = KERNEL_NVR.fullmatch(nvr)
    if not match:
        return None
    version = tuple(int(part) for part in match.groups()[:3])
    return version, nvr.removeprefix('kernel-')


def parse_version(value):
    """Numeric triple of a profile kernel release, by the schema's rules (crates/stack-schema/src/kernel.rs)."""
    invalid = ValueError('invalid kernel version in profile: ' + repr(value))
    if not isinstance(value, str) or not value or value.strip() != value:
        raise invalid
    numeric, dash, suffix = value.partition('-')
    if dash and (not suffix or any(character.isspace() for character in suffix)):
        raise invalid
    parts = numeric.split('.')
    if len(parts) != 3 or not all(part and part.isascii() and part.isdigit() for part in parts):
        raise invalid
    version = tuple(int(part) for part in parts)
    if max(version) > U64_MAX:
        raise invalid
    return version


def kernels_from_bodhi(document):
    """Kernel builds that reached a repository, newest first, one entry per build at its most published state."""
    updates = document.get('updates') if isinstance(document, dict) else None
    if not isinstance(updates, list):
        return []
    found = {}
    for entry in updates:
        if not isinstance(entry, dict) or entry.get('status') not in OBSERVED:
            continue
        if entry['status'] == 'obsolete' and not (isinstance(entry.get('date_testing'), str) and entry['date_testing']):
            continue
        release = entry.get('release')
        if not isinstance(release, dict) or release.get('name') != 'F44':
            continue
        builds = entry.get('builds')
        if not isinstance(builds, list):
            continue
        alias = entry.get('alias') if isinstance(entry.get('alias'), str) and ALIAS.fullmatch(entry['alias']) else ''
        for build in builds:
            parsed = parse_kernel_nvr(build.get('nvr') if isinstance(build, dict) else None)
            if parsed is None:
                continue
            version, kernel = parsed
            current = found.get(kernel)
            if current is None or OBSERVED[entry['status']] > OBSERVED[current['status']]:
                found[kernel] = {'kernel': kernel, 'version': version, 'status': entry['status'], 'update': alias}
    return [dict(item, version='.'.join(map(str, item['version'])))
            for item in sorted(found.values(), key=lambda item: item['version'], reverse=True)]


def valid_profile_id(value):
    """The schema's rule for profile text: non-empty, trimmed, no control characters, within the scalar limit."""
    return (isinstance(value, str) and bool(value) and value.strip() == value
            and not any(unicodedata.category(character) == 'Cc' for character in value)
            and len(value.encode()) <= MAX_SCALAR_BYTES)


def components_digest(document):
    """SHA-256 of a profile's component set as canonical JSON; a probe covers only the stack it ran on."""
    components = document.get('components')
    if not isinstance(components, dict) or not components:
        raise ValueError('profile has no component set')
    canonical = json.dumps(components, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def qualified_windows(profiles_dir):
    """Kernel windows of qualified Fedora 44 profiles."""
    windows = []
    for path in sorted(Path(profiles_dir).rglob('*.toml')):
        document = tomllib.loads(path.read_text())
        platform = document.get('platform', {})
        if (document.get('status') != 'qualified' or platform.get('id') != 'fedora'
                or platform.get('version_id') != '44'):
            continue
        kernel = document.get('kernel', {})
        low, high = parse_version(kernel.get('min')), parse_version(kernel.get('max_exclusive'))
        if not low < high:
            raise ValueError('qualified profile has an empty kernel window: ' + path.name)
        evidence = document.get('qualification', {}).get('evidence_sha256')
        if not isinstance(evidence, str) or not DIGEST.fullmatch(evidence):
            raise ValueError('qualified profile lacks a qualification evidence digest: ' + path.name)
        profile = document.get('id')
        if not valid_profile_id(profile):
            raise ValueError('qualified profile has an invalid id: ' + path.name)
        if profile in {window['id'] for window in windows}:
            raise ValueError('duplicate qualified profile id: ' + profile)
        windows.append({'id': profile, 'min': kernel['min'], 'max_exclusive': kernel['max_exclusive'],
                        'evidence_sha256': evidence, 'components_sha256': components_digest(document)})
    return windows


def valid_date(value):
    if not isinstance(value, str) or not DATE.fullmatch(value):
        return False
    try:
        datetime.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def load_probes(path, windows):
    """Recorded outcomes that apply to the current qualified profiles, and the records that no longer apply.

    Every record has exactly the documented fields, and a profile, kernel, component
    set and evidence digest appear at most once. A record applies to a qualified
    profile with its id only while its component-set digest (and, for a
    qualification record, its evidence digest) equals the profile's current one;
    otherwise it is stale and never covers a kernel. Records that apply to the same
    profile and kernel must agree. Records for profiles that are
    not qualified are history and are only shape-checked. Returns
    ({(profile id, kernel): 'pass' | 'fail'}, [stale record summaries]).
    """
    document = json.loads(Path(path).read_text())
    if not isinstance(document, dict) or document.get('schema_version') != 1 \
            or not isinstance(document.get('probes'), list):
        raise ValueError('kernel probe registry must be schema_version 1 with a probes list')
    current = {window['id']: window for window in windows}
    outcomes, stale, seen = {}, [], set()
    for probe in document['probes']:
        invalid = 'invalid kernel probe record: ' + repr(probe)
        if not isinstance(probe, dict) or set(probe) != PROBE_FIELDS:
            raise ValueError(invalid)
        parsed = parse_kernel_nvr('kernel-' + probe['kernel']) if isinstance(probe['kernel'], str) else None
        identity = (probe['profile'], probe['kernel'], probe['components_sha256'], probe['evidence_sha256'])
        if (parsed is None or not valid_profile_id(probe['profile']) or identity in seen
                or probe['result'] not in {'pass', 'fail'} or probe['source'] not in {'probe', 'qualification'}
                or any(not isinstance(probe[field], str) or not DIGEST.fullmatch(probe[field])
                       for field in ['components_sha256', 'evidence_sha256'])
                or not valid_date(probe['recorded'])
                or (probe['source'] == 'qualification' and probe['result'] != 'pass')):
            raise ValueError(invalid)
        seen.add(identity)
        window = current.get(probe['profile'])
        if window is None:
            continue
        reason = None
        if probe['components_sha256'] != window['components_sha256']:
            reason = 'component set changed'
        elif probe['source'] == 'qualification' and probe['evidence_sha256'] != window['evidence_sha256']:
            reason = 'qualification evidence changed'
        if reason:
            stale.append({'kernel': probe['kernel'], 'profile': probe['profile'], 'reason': reason})
            continue
        pair = (probe['profile'], probe['kernel'])
        if outcomes.setdefault(pair, probe['result']) != probe['result']:
            raise ValueError('conflicting records for the current component set: ' + repr(pair))
    return outcomes, stale


def dedup_key(kernel):
    return KEY_PREFIX + kernel


def open_issues(issues):
    """Dedup key to the oldest open issue number carrying it; titles are data, not commands."""
    found = {}
    for issue in issues:
        if (not isinstance(issue, dict) or type(issue.get('number')) is not int
                or not isinstance(issue.get('title'), str)):
            continue
        for token in issue['title'].replace(']', ' ').split():
            if token.startswith(KEY_PREFIX) and parse_kernel_nvr('kernel-' + token[len(KEY_PREFIX):]):
                found[token] = min(found.get(token, issue['number']), issue['number'])
    return found


def scan(kernels, windows, outcomes, issues):
    """One finding per kernel that needs action for at least one qualified profile, classified per profile.

    A finding whose kernel already has an open issue carries that issue's number so the
    workflow refreshes it instead of opening another.
    """
    findings = []
    for item in kernels:
        version = tuple(int(part) for part in item['version'].split('.'))
        key = dedup_key(item['kernel'])
        actions = []
        for window in windows:
            if version < parse_version(window['min']):
                continue
            if version >= parse_version(window['max_exclusive']):
                action = 'requalification-required'
            else:
                outcome = outcomes.get((window['id'], item['kernel']))
                if outcome == 'pass':
                    continue
                action = 'probe-failed' if outcome == 'fail' else 'probe-required'
            actions.append({'profile': window['id'], 'window': f"[{window['min']}, {window['max_exclusive']})",
                            'action': action})
        if actions:
            findings.append({'observation': ', '.join(sorted({a['action'] for a in actions})), 'dedup_key': key,
                             'kernel': item['kernel'], 'version': item['version'], 'bodhi_status': item['status'],
                             'update': item['update'], 'actions': sorted(actions, key=lambda a: a['profile']),
                             'issue': issues.get(key)})
    return findings


def build_report(fetch, profiles_dir, probes_path, issues):
    windows = qualified_windows(profiles_dir)
    outcomes, stale = load_probes(probes_path, windows)
    report = {'schema_version': 1, 'qualified_windows': windows,
              'recorded_outcomes': [{'profile': profile, 'kernel': kernel, 'result': result}
                                    for (profile, kernel), result in sorted(outcomes.items())],
              'stale_records': stale, 'observed_kernels': [], 'findings': []}
    try:
        document = fetch_updates(fetch)
    except (OSError, ValueError, json.JSONDecodeError):
        report['findings'] = [{'observation': 'check-failed',
                               'note': 'Bodhi query failed; scheduled runs are advisory'}]
        return report
    report['observed_kernels'] = kernels_from_bodhi(document)
    report['findings'] = scan(report['observed_kernels'], windows, outcomes, issues)
    return report


def main(argv=None):
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profiles', type=Path, default=root / 'profiles')
    parser.add_argument('--probes', type=Path, default=root / 'release/kernel-probes.json')
    parser.add_argument('--open-issues', type=Path,
                        help='JSON array of open kernel-watch issues ({number, title}) to refresh instead of duplicate')
    parser.add_argument('--report', type=Path, help='write the report JSON to this path')
    parser.add_argument('--components-digest', type=Path, metavar='PROFILE',
                        help='print the component-set digest of a profile TOML (for probe records) and exit')
    args = parser.parse_args(argv)
    if args.components_digest:
        print(components_digest(tomllib.loads(args.components_digest.read_text())))
        return 0
    raw = args.open_issues.read_text().strip() if args.open_issues else ''
    report = build_report(fetch_json, args.profiles, args.probes, open_issues(json.loads(raw) if raw else []))
    text = json.dumps(report, indent=2) + '\n'
    if args.report:
        args.report.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
