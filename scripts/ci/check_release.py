#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify a signed production release tree for publication.

Refuses publication unless every gate passes: a qualified profile with a
complete qualification record, a production (non-test) assembly manifest,
matching profile and package digests, a complete checksums file, a valid
detached release-metadata signature and repomd signature from the pinned
production key, valid RPM signatures for every package, and the required
SPDX/notices/rollback evidence. Emits publication-manifest.json on success.

Runs gpg and rpmkeys as subprocesses in a throwaway keyring; performs no
build, signing or publication.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

FINGERPRINT_RE = re.compile(r'^[0-9A-F]{40}$')
DIGEST_RE = re.compile(r'^[0-9a-f]{64}$')
EVIDENCE_DIRS = ['evidence/spdx', 'evidence/notices', 'evidence/rollback']
QUALIFICATION_FIELDS = ['evidence_id', 'evidence_sha256', 'qualified_at',
                        'hardware_class', 'test_suite_version']


class ReleaseRefused(Exception):
    """A publication gate failed; nothing was published."""


def require(condition, message):
    if not condition:
        raise ReleaseRefused(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_json(path):
    value = json.loads(Path(path).read_text())
    require(isinstance(value, dict), 'unexpected JSON shape in ' + str(path))
    return value


def verify_profile(profile_path, release):
    document = tomllib.loads(Path(profile_path).read_text())
    require(document.get('status') == 'qualified',
            'publication requires a qualified profile, found: '
            + str(document.get('status')))
    evidence = document.get('qualification')
    if not isinstance(evidence, dict):
        raise ReleaseRefused('qualified profile lacks qualification evidence')
    for field in QUALIFICATION_FIELDS:
        value = evidence.get(field)
        require(isinstance(value, str) and value.strip(),
                'qualification evidence field is empty: ' + field)
    require(DIGEST_RE.fullmatch(evidence['evidence_sha256']),
            'qualification evidence SHA-256 is invalid')
    require(document.get('stack_release') == release['stack_release'],
            'profile release does not match the release metadata')
    require(sha(profile_path) == release.get('profile_sha256'),
            'release metadata does not bind the profile bytes')
    return document, evidence


def verify_assembly(manifest_path, release):
    manifest = load_json(manifest_path)
    require(manifest.get('passed') is True, 'assembly did not pass')
    require(manifest.get('test_only') is False,
            'publication requires a production assembly, not a test-only assembly')
    require(manifest.get('release_ready') is False,
            'assembly must not claim release readiness by itself')
    require(manifest.get('package_count') == len(release.get('packages', [])),
            'assembly package count does not match the release metadata')
    return manifest


def verify_tree_digests(tree, manifest):
    recorded = manifest.get('output_digests')
    require(isinstance(recorded, dict) and recorded, 'assembly records no output digests')
    for relative, expected in recorded.items():
        path = tree / relative
        require(path.is_file() and not path.is_symlink(),
                'assembly output is missing: ' + relative)
        require(sha(path) == expected, 'assembly output digest drift: ' + relative)


def verify_release_metadata(tree):
    release_path = tree / 'release.json'
    require(release_path.is_file(), 'release metadata is missing')
    release = load_json(release_path)
    require(release.get('schema_version') == 1, 'unsupported release schema version')
    packages = release.get('packages')
    require(isinstance(packages, list) and packages, 'release metadata lists no packages')
    for entry in packages:
        require(isinstance(entry, dict), 'release package entries must be objects')
        for field in ['name', 'nevr', 'arch', 'filename', 'sha256', 'role']:
            require(isinstance(entry.get(field), str) and entry[field],
                    'incomplete release package entry')
        require(DIGEST_RE.fullmatch(entry['sha256']),
                'invalid release package digest for ' + entry['name'])
        package = tree / 'packages' / entry['filename']
        require(package.is_file() and not package.is_symlink(),
                'release package is missing: ' + entry['filename'])
        require(sha(package) == entry['sha256'],
                'release package digest drift: ' + entry['filename'])
    repository = release.get('repository')
    require(isinstance(repository, dict), 'release metadata lacks the repository record')
    base_url = repository.get('base_url', '')
    require(base_url.startswith('https://') and base_url.endswith('/')
            and '?' not in base_url and '#' not in base_url,
            'release base URL must be an immutable HTTPS location')
    return release


def verify_checksums(tree):
    checksums = tree / 'checksums.sha256'
    require(checksums.is_file(), 'checksums file is missing')
    recorded = {}
    for line in checksums.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if match is None:
            raise ReleaseRefused('malformed checksums line')
        digest, relative = match.group(1), match.group(2)
        require(relative not in recorded, 'duplicate checksums entry: ' + relative)
        recorded[relative] = digest
    for path in sorted(tree.rglob('*')):
        if not path.is_file():
            continue
        relative = path.relative_to(tree).as_posix()
        if relative in {'checksums.sha256', 'assembly-manifest.json'}:
            continue
        require(relative in recorded, 'file missing from checksums: ' + relative)
        require(sha(path) == recorded[relative], 'checksums drift: ' + relative)
    return recorded


def verify_evidence(tree):
    counts = {}
    for relative in EVIDENCE_DIRS:
        directory = tree / relative
        require(directory.is_dir(), 'required evidence is missing: ' + relative)
        files = [p for p in sorted(directory.rglob('*')) if p.is_file()]
        require(files, 'required evidence is empty: ' + relative)
        counts[relative] = len(files)
    return counts


def gpg_verify(keyring, public_key, signature, signed, expected_fingerprint):
    subprocess.run(['gpg', '--batch', '--import', str(public_key)],
                   env=keyring, check=True, capture_output=True)
    result = subprocess.run(['gpg', '--batch', '--status-fd', '1', '--verify',
                             str(signature), str(signed)],
                            env=keyring, capture_output=True, text=True)
    if result.returncode != 0:
        if 'NO_PUBKEY' in result.stdout or 'ERRSIG' in result.stdout \
                or 'NO_PUBKEY' in result.stderr:
            raise ReleaseRefused('signature is not from the pinned release key: '
                                 + str(signature))
        raise ReleaseRefused('signature verification failed: ' + str(signature))
    require('[GNUPG:] VALIDSIG ' + expected_fingerprint + ' ' in result.stdout,
            'signature is not from the pinned release key: ' + str(signature))


def verify_signatures(tree, production_key, fingerprint):
    with tempfile.TemporaryDirectory() as home:
        keyring = {'GNUPGHOME': home, 'PATH': '/usr/bin:/bin'}
        release_signature = tree / 'release.json.sig'
        require(release_signature.is_file(), 'detached release metadata signature is missing')
        gpg_verify(keyring, production_key, release_signature,
                   tree / 'release.json', fingerprint)
        repomd = tree / 'repodata' / 'repomd.xml'
        repomd_signature = tree / 'repodata' / 'repomd.xml.asc'
        require(repomd.is_file() and repomd_signature.is_file(),
                'signed repomd is missing')
        gpg_verify(keyring, production_key, repomd_signature, repomd, fingerprint)


def verify_rpm_signatures(tree, production_key, fingerprint):
    packages = sorted((tree / 'packages').glob('*.rpm'))
    require(packages, 'no release packages found')
    with tempfile.TemporaryDirectory() as dbpath:
        subprocess.run(['rpm', '--dbpath', dbpath, '--import', str(production_key)],
                       check=True, capture_output=True)
        for package in packages:
            result = subprocess.run(
                ['rpmkeys', '--dbpath', dbpath, '--checksig', '--verbose', str(package)],
                capture_output=True, text=True)
            lines = {line.strip() for line in result.stdout.splitlines()}
            signature = re.compile(
                r'Header OpenPGP V4 EdDSA(?:/SHA\d+)? signature, key fingerprint: '
                + fingerprint.lower() + r': OK')
            require(result.returncode == 0
                    and any(signature.fullmatch(line) for line in lines)
                    and {'Header SHA256 digest: OK', 'Payload SHA256 digest: OK'} <= lines,
                    'RPM signature verification failed: ' + package.name)
    return len(packages)


def check_release(tree, profile, output, production_key=None):
    tree = Path(tree).resolve(strict=True)
    require(not Path(output).exists(), 'publication manifest already exists')
    release = verify_release_metadata(tree)
    _, evidence = verify_profile(profile, release)
    manifest = verify_assembly(tree / 'assembly-manifest.json', release)
    verify_tree_digests(tree, manifest)
    verify_checksums(tree)
    evidence_counts = verify_evidence(tree)
    if production_key is None:
        production_key = Path(__file__).resolve().parents[2] / \
            'crates/stack-install/src/trust/release-public.asc'
    production_key = Path(production_key)
    require(production_key.is_file(), 'pinned production trust key is missing')
    fingerprint = None
    listing = subprocess.run(['gpg', '--with-colons', '--import-options', 'show-only',
                              '--import', str(production_key)],
                             capture_output=True, text=True)
    for line in listing.stdout.splitlines():
        if line.startswith('fpr:'):
            fingerprint = line.split(':')[9]
            break
    require(fingerprint is not None and FINGERPRINT_RE.fullmatch(fingerprint),
            'cannot read the pinned production fingerprint')
    verify_signatures(tree, production_key, fingerprint)
    rpm_count = verify_rpm_signatures(tree, production_key, fingerprint)
    result = {
        'passed': True,
        'publication_ready': True,
        'scope': 'verified signed production release tree; publication requires the '
                 'protected environment approval in the release workflow',
        'release_version': release['stack_release'],
        'repository_id': release['repository']['id'],
        'base_url': release['repository']['base_url'],
        'profile_sha256': release['profile_sha256'],
        'qualification_evidence_sha256': evidence['evidence_sha256'],
        'release_key_fingerprint': fingerprint,
        'package_count': len(release['packages']),
        'rpm_signatures_verified': rpm_count,
        'evidence_files': evidence_counts,
        'tree_digests': {relative: sha(tree / relative)
                         for relative in sorted(manifest['output_digests'])},
    }
    Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-tree', required=True, type=Path)
    parser.add_argument('--profile', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = check_release(args.release_tree, args.profile, args.output)
    except ReleaseRefused as error:
        parser.exit(1, 'Publication refused: ' + str(error) + '\n')
    print(json.dumps({'passed': True, 'publication_ready': True,
                      'release_version': result['release_version'],
                      'package_count': result['package_count'],
                      'release_key_fingerprint': result['release_key_fingerprint']},
                     indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
