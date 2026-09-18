#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Rewrite an accepted candidate profile into the release profile.

Every component must bind its provider exactly as accepted: the candidate
digest equals the provider's unsigned build digest and the provider version
equals the full signed-inventory NEVR. The output replaces only those
component digests with the signed digests; the document is otherwise
byte-identical and stays a candidate. Qualification is recorded by hardware
gates elsewhere and can never be produced here. No subprocess, no build,
no signing, no publication.
"""
import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

COMPONENT_HEADER = re.compile(r'^\[components\.([A-Za-z0-9_-]+)\]$')
DIGEST_LINE = re.compile(r'^sha256 = "([0-9a-f]{64})"$')
RELEASE_VERSION = re.compile(r'^[0-9]+\.[0-9]+\.[0-9]+$')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return bool(re.fullmatch(r'[0-9a-f]{64}', value or ''))


def load_json(path):
    value = json.loads(path.read_text())
    require(isinstance(value, dict), 'unexpected JSON shape in '+str(path))
    return value


def load_identity(path):
    identity = load_json(path)
    test_only = identity.get('test_only')
    require(identity.get('passed') is True and
            (test_only is True or
             (test_only is False and identity.get('production_ready') is True)),
            'signed identity must be a passed test-only or production-ready record')
    packages = identity.get('packages')
    require(isinstance(packages, list) and packages, 'signed identity lists no packages')
    by_name = {}
    for entry in packages:
        require(isinstance(entry, dict), 'signed identity package entries must be objects')
        for field in ['name', 'nevr', 'role', 'unsigned_sha256', 'signed_sha256']:
            require(isinstance(entry.get(field), str) and entry[field],
                    'incomplete signed identity entry')
        require(digest(entry['unsigned_sha256']) and digest(entry['signed_sha256']),
                'invalid signed identity digest for '+entry['name'])
        require(entry['unsigned_sha256'] != entry['signed_sha256'],
                'signed digest equals the unsigned digest for '+entry['name'])
        require(entry['name'] not in by_name, 'duplicate signed identity package')
        by_name[entry['name']] = entry
    return identity, by_name


def rewrite(candidate_bytes, by_name):
    text = candidate_bytes.decode('utf-8')
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ValueError('candidate profile is not valid TOML: '+str(error)) from error
    require(document.get('schema_version') == 1, 'unsupported candidate schema version')
    require(document.get('status') == 'candidate', 'only a candidate profile may be rewritten')
    require(document.get('package_manager') == 'rpm', 'candidate is not an rpm profile')
    release = document.get('stack_release')
    require(isinstance(release, str) and RELEASE_VERSION.fullmatch(release),
            'candidate stack_release must be a numeric triple')
    profile_id = document.get('id')
    require(isinstance(profile_id, str) and profile_id, 'candidate has no profile id')
    components = document.get('components')
    if not isinstance(components, dict) or not components:
        raise ValueError('candidate has no components')

    rewrites = {}
    for capability, component in sorted(components.items()):
        if not isinstance(component, dict):
            raise ValueError('component is not a table: '+capability)
        provider = component.get('provider')
        if not isinstance(provider, dict):
            raise ValueError('component lacks a provider: '+capability)
        name = provider.get('package')
        entry = by_name.get(name) if isinstance(name, str) else None
        if entry is None:
            raise ValueError('component provider is absent from the signed inventory: '+str(name))
        require(entry['role'] == 'runtime', 'component provider is not a runtime package: '+str(name))
        require(provider.get('version') == entry['nevr'],
                'component provider NEVR does not match the signed inventory: '+capability)
        candidate_digest = component.get('sha256')
        require(digest(candidate_digest), 'component lacks a valid digest: '+capability)
        require(candidate_digest == entry['unsigned_sha256'],
                'component digest does not bind the accepted unsigned provider build: '+capability)
        rewrites[capability] = (candidate_digest, entry['signed_sha256'])

    lines, seen = [], set()
    current, consumed = None, False
    for line in text.split('\n'):
        if line.startswith('['):
            header = COMPONENT_HEADER.match(line)
            if header is not None and header.group(1) in rewrites:
                current, consumed = header.group(1), False
            else:
                current, consumed = None, False
        elif current is not None:
            match = DIGEST_LINE.fullmatch(line)
            if match is not None:
                require(not consumed, 'multiple top-level digest lines for component: '+current)
                require(match.group(1) == rewrites[current][0],
                        'component digest line does not match the parsed document: '+current)
                lines.append('sha256 = "'+rewrites[current][1]+'"')
                seen.add(current)
                consumed = True
                continue
        lines.append(line)
    missing = sorted(set(rewrites)-seen)
    require(not missing,
            'component digest line not found or unexpectedly formatted for: '+','.join(missing))

    output = '\n'.join(lines)
    try:
        rewritten = tomllib.loads(output)
    except tomllib.TOMLDecodeError as error:
        raise ValueError('rewritten profile is not valid TOML: '+str(error)) from error
    require(rewritten.get('status') == 'candidate', 'rewrite changed the profile status')
    rewritten_components = rewritten.get('components')
    if not isinstance(rewritten_components, dict) or not rewritten_components:
        raise ValueError('rewritten profile lost its components')
    for capability, component in rewritten_components.items():
        provider = component.get('provider')
        require(isinstance(provider, dict), 'rewritten component lacks a provider: '+capability)
        entry = by_name.get(provider.get('package'))
        require(entry is not None, 'rewritten provider left the inventory: '+capability)
        require(component.get('sha256') == entry['signed_sha256'],
                'internal error: component digest rewrite failed for '+capability)
    return output.encode('utf-8'), document, rewrites


def component_records(document, by_name, rewrites):
    records = {}
    for capability in sorted(rewrites):
        provider = document['components'][capability]['provider']
        entry = by_name[provider['package']]
        records[capability] = {'package': entry['name'], 'nevr': entry['nevr'],
                               'unsigned_sha256': entry['unsigned_sha256'],
                               'signed_sha256': entry['signed_sha256']}
    return records


def generate(candidate, identity_path, output, record):
    identity, by_name = load_identity(identity_path)
    candidate_bytes = candidate.read_bytes()
    output_bytes, document, rewrites = rewrite(candidate_bytes, by_name)
    require(not output.exists(), 'output already exists: '+str(output))
    require(record is None or not record.exists(), 'record already exists: '+str(record))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(output_bytes)
    if record is not None:
        record.parent.mkdir(parents=True, exist_ok=True)
        record.write_text(json.dumps({
            'passed': True,
            'test_only': identity.get('test_only') is True,
            'scope': 'candidate-to-release profile digest rewrite from the passed '
                     'signed-identity inventory; no build, signing or qualification',
            'schema_version': 1,
            'stack_release': document['stack_release'],
            'profile_id': document['id'],
            'candidate_sha256': hashlib.sha256(candidate_bytes).hexdigest(),
            'signed_identity_sha256': hashlib.sha256(identity_path.read_bytes()).hexdigest(),
            'output_sha256': hashlib.sha256(output_bytes).hexdigest(),
            'primary_fingerprint': identity.get('primary_fingerprint', ''),
            'components': component_records(document, by_name, rewrites),
        }, indent=2, sort_keys=True)+'\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--identity', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--record')
    args = parser.parse_args(argv)
    try:
        generate(Path(args.candidate).resolve(strict=True),
                 Path(args.identity).resolve(strict=True),
                 Path(args.output), Path(args.record) if args.record else None)
    except (OSError, ValueError, KeyError, TypeError, UnicodeDecodeError) as error:
        parser.exit(1, 'Release profile generation: '+str(error)+'\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
