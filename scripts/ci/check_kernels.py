#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Issue-only watcher for Fedora 44 kernel updates against the qualified kernel window.

A qualified profile admits a kernel series (for example [7.2.5, 7.3.0)); newer
kernels inside that window are admitted by policy but need a recorded
per-kernel probe (release/kernel-probes.json, docs/kernel-probes.md). A kernel
at or above every qualified window needs a new qualification. Bodhi data is
untrusted: only regex-validated kernel NVRs reach the findings. This module
performs no writes; the workflow turns findings into deduplicated issues.
"""
import argparse
import json
from pathlib import Path
import re
import sys
import tomllib
import urllib.parse
import urllib.request

BODHI = 'https://bodhi.fedoraproject.org/updates/'
QUERY = {'packages': 'kernel', 'releases': 'F44', 'rows_per_page': '30'}
MAX_BODY = 4 << 20
TIMEOUT = 30
KERNEL_NVR = re.compile(r'kernel-(\d{1,3})\.(\d{1,3})\.(\d{1,4})-(\d{1,4})\.fc44')
KERNEL_VERSION = re.compile(r'(\d{1,3})\.(\d{1,3})\.(\d{1,4})(?:-[A-Za-z0-9._+~]+)?')
ALIAS = re.compile(r'FEDORA-\d{4}-[0-9a-f]{10}')
KEY_PREFIX = 'kernel:fedora-44:'
OBSERVED = {'stable', 'testing'}


def fetch_json(url, timeout=TIMEOUT):
    request = urllib.request.Request(url, headers={'Accept': 'application/json',
                                                   'User-Agent': 'intel-npu-stack-kernel-watch'})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (fixed https URL)
        body = response.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise ValueError('Bodhi response exceeds the size limit')
    return json.loads(body)


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
    match = KERNEL_VERSION.fullmatch(value) if isinstance(value, str) else None
    if not match:
        raise ValueError('invalid kernel version in profile: ' + repr(value))
    return tuple(int(part) for part in match.groups())


def kernels_from_bodhi(document):
    """Stable and testing kernel builds, newest first, one entry per build."""
    updates = document.get('updates') if isinstance(document, dict) else None
    if not isinstance(updates, list):
        return []
    found = {}
    for entry in updates:
        if not isinstance(entry, dict) or entry.get('status') not in OBSERVED:
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
            if current is None or (current['status'] == 'testing' and entry['status'] == 'stable'):
                found[kernel] = {'kernel': kernel, 'version': version, 'status': entry['status'], 'update': alias}
    return [dict(item, version='.'.join(map(str, item['version'])))
            for item in sorted(found.values(), key=lambda item: item['version'], reverse=True)]


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
        windows.append({'id': document.get('id'), 'min': kernel['min'], 'max_exclusive': kernel['max_exclusive']})
    return windows


def load_probes(path):
    """Kernels (version-release) with a recorded passing probe."""
    document = json.loads(Path(path).read_text())
    if not isinstance(document, dict) or document.get('schema_version') != 1 \
            or not isinstance(document.get('probes'), list):
        raise ValueError('kernel probe registry must be schema_version 1 with a probes list')
    passed = set()
    for probe in document['probes']:
        if not isinstance(probe, dict) or parse_kernel_nvr('kernel-' + str(probe.get('kernel'))) is None:
            raise ValueError('invalid kernel probe record: ' + repr(probe))
        if probe.get('result') == 'pass':
            passed.add(probe['kernel'])
    return passed


def dedup_key(kernel):
    return KEY_PREFIX + kernel


def existing_keys(open_issues):
    """Dedup keys from open issue titles; titles are data, not commands."""
    keys = set()
    for issue in open_issues:
        title = issue.get('title') if isinstance(issue, dict) else None
        for token in (title or '').replace(']', ' ').split():
            if token.startswith(KEY_PREFIX) and parse_kernel_nvr('kernel-' + token[len(KEY_PREFIX):]):
                keys.add(token)
    return keys


def scan(kernels, windows, probed, open_keys):
    if not windows:
        return []
    ranges = [(parse_version(w['min']), parse_version(w['max_exclusive']), w) for w in windows]
    findings = []
    for item in kernels:
        version = tuple(int(part) for part in item['version'].split('.'))
        key = dedup_key(item['kernel'])
        if key in open_keys:
            continue
        inside = [w for low, high, w in ranges if low <= version < high]
        if inside:
            if item['kernel'] in probed:
                continue
            observation = 'probe-required'
        elif all(version >= high for _, high, _ in ranges):
            observation = 'requalification-required'
        else:
            continue
        findings.append({'observation': observation, 'dedup_key': key, 'kernel': item['kernel'],
                         'version': item['version'], 'bodhi_status': item['status'], 'update': item['update'],
                         'windows': [f"{w['id']} [{w['min']}, {w['max_exclusive']})" for w in (inside or windows)]})
    return findings


def build_report(fetch, profiles_dir, probes_path, open_keys):
    windows = qualified_windows(profiles_dir)
    probed = load_probes(probes_path)
    report = {'schema_version': 1, 'qualified_windows': windows, 'probed_kernels': sorted(probed),
              'observed_kernels': [], 'findings': []}
    try:
        document = fetch(BODHI + '?' + urllib.parse.urlencode(QUERY), TIMEOUT)
    except (OSError, ValueError, json.JSONDecodeError):
        report['findings'] = [{'observation': 'check-failed', 'note': 'Bodhi query failed; scheduled runs are advisory'}]
        return report
    report['observed_kernels'] = kernels_from_bodhi(document)
    report['findings'] = scan(report['observed_kernels'], windows, probed, open_keys)
    return report


def main(argv=None):
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profiles', type=Path, default=root / 'profiles')
    parser.add_argument('--probes', type=Path, default=root / 'release/kernel-probes.json')
    parser.add_argument('--open-issues', type=Path, help='JSON array of open issue objects used for deduplication')
    parser.add_argument('--report', type=Path, help='write the report JSON to this path')
    args = parser.parse_args(argv)
    raw = args.open_issues.read_text().strip() if args.open_issues else ''
    open_keys = existing_keys(json.loads(raw) if raw else [])
    report = build_report(fetch_json, args.profiles, args.probes, open_keys)
    text = json.dumps(report, indent=2) + '\n'
    if args.report:
        args.report.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
