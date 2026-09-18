#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Compose the immutable Fedora release from exact accepted inputs.

The assembler verifies every byte against the accepted inventories, copies
the signed repository, profile, evidence and rollback assets, and writes the
installer release manifest. It runs no subprocess and performs no publication,
signing or build; providers are reused by digest only. The profile RPM is a
separately built and signed small artifact whose build evidence is bound here.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
import shutil
import sys
import tomllib

REQUIRED_RUNTIME = ['intel-npu-stack', 'intel-npu-stack-tools']
ROLES = {'runtime', 'python', 'devel', 'profile'}
ALIAS_SEGMENTS = {'latest', 'current', 'stable', 'experimental'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_json(path):
    value = json.loads(path.read_text())
    require(isinstance(value, (dict, list)), 'unexpected JSON shape in '+str(path))
    return value


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


def repository_url(url, version):
    if len(url) > 2048 or not url.startswith('https://'):
        return False
    host, _, path = url.removeprefix('https://').partition('/')
    labels = host.split('.')
    if (not host or len(host) > 253 or len(labels) < 2
            or not all(0 < len(label) <= 63 and label[0].isalnum() and label[-1].isalnum()
                       and re.fullmatch(r'[A-Za-z0-9-]+', label) for label in labels)):
        return False
    segments = path.rstrip('/').split('/')
    if not path.endswith('/') or not segments or segments[-1] == '':
        return False
    if version not in segments and 'v'+version not in segments:
        return False
    return all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]*', segment)
               and segment not in {'.', '..'} and segment not in ALIAS_SEGMENTS
               for segment in segments)


def release_version(version):
    parts = version.split('.')
    return (len(parts) == 3
            and all(re.fullmatch(r'0|[1-9][0-9]*', part) and len(part) <= 10 for part in parts))


def identifier(value):
    return bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,127}', value))


def digest(value):
    return bool(re.fullmatch(r'[0-9a-f]{64}', value or ''))


def copy_tree(source, target):
    for entry in sorted(source.rglob('*')):
        relative = entry.relative_to(source)
        require(relative.as_posix() == relative.as_posix().strip('/'), 'unsafe evidence path')
        destination = target/relative
        if entry.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            continue
        require(entry.is_file() and not entry.is_symlink(), 'evidence entries must be regular files')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(entry, destination)


def assemble(input_root, output, base_url, repository_id, release, production=False):
    require(release_version(release), 'release version must be a numeric triple')
    require(identifier(repository_id), 'invalid repository identity')
    require(repository_url(base_url, release), 'base URL must be an immutable versioned HTTPS location')

    repository = input_root/'repository'
    packages = sorted((repository/'packages').glob('*.rpm'))
    repodata = sorted((repository/'repodata').iterdir())
    require(all(entry.is_file() and not entry.is_symlink() for entry in packages+repodata),
            'repository payload must be regular files')
    identity = load_json(input_root/'signed-identity.json')
    if production:
        require(identity.get('passed') is True and identity.get('test_only') is False
                and identity.get('production_ready') is True,
                'production assembly requires a passed production-ready signed identity')
    else:
        require(identity.get('passed') is True and identity.get('test_only') is True,
                'signed repository evidence must be the passed test-only record')
    require(digest(identity.get('primary_fingerprint', '')) is False
            or re.fullmatch(r'[0-9A-F]{40}', identity.get('primary_fingerprint', '')),
            'invalid release key fingerprint record')
    repomd = repository/'repodata/repomd.xml'
    require(repomd.is_file(), 'signed repomd is missing')
    require(sha(repomd) == identity['repomd_sha256'], 'signed repomd digest drift')

    entries = identity['packages']
    require(1 < len(entries) <= 128, 'release package count is out of range')
    by_name, by_filename = {}, {}
    for entry in entries:
        for field in ['name', 'nevr', 'arch', 'filename', 'role', 'unsigned_sha256',
                      'signed_sha256', 'unchanged_cpio_sha256']:
            require(isinstance(entry.get(field), str) and entry[field], 'incomplete package identity')
        require(entry['role'] in ROLES, 'unknown package role')
        require(identifier(entry['name']), 'invalid package name')
        require(digest(entry['unsigned_sha256']) and digest(entry['signed_sha256'])
                and digest(entry['unchanged_cpio_sha256']), 'invalid package digests')
        require(entry['name'] not in by_name and entry['filename'] not in by_filename,
                'duplicate package identity')
        if entry['role'] == 'profile':
            require(entry['name'] == 'intel-npu-stack-profile', 'unexpected profile package name')
        by_name[entry['name']] = entry
        by_filename[entry['filename']] = entry
    profile_entries = [entry for entry in entries if entry['role'] == 'profile']
    require(len(profile_entries) == 1, 'exactly one profile package is required')
    profile_entry = profile_entries[0]
    for name in REQUIRED_RUNTIME:
        require(by_name.get(name, {}).get('role') == 'runtime',
                'required runtime package is absent: '+name)
    require({entry['filename'] for entry in entries} == {path.name for path in packages},
            'repository payload does not match the signed inventory exactly')
    for path in packages:
        require(sha(path) == by_filename[path.name]['signed_sha256'],
                'signed RPM digest drift: '+path.name)

    package_index = load_json(input_root/'aggregate/package-index.json')
    owned = {}
    for name, record in sorted(package_index.items()):
        require(by_name.get(name, {}).get('role') == 'runtime',
                'payload inventory names a non-release provider: '+name)
        for path in record['regular_files']:
            require(str(PurePosixPath(path)) == path and path.startswith('/'),
                    'noncanonical payload path')
            require(path not in owned, 'conflicting payload ownership: '+path)
            owned[path] = name

    spdx_index = load_json(input_root/'aggregate/spdx-index.json')
    for document, record in sorted(spdx_index.items()):
        require(digest(record.get('sha256', '')), 'invalid SPDX digest record')
        relative = PurePosixPath(document)
        require(isinstance(document, str) and document == str(relative)
                and not relative.is_absolute() and '..' not in relative.parts
                and all(part not in {'', '.'} for part in relative.parts),
                'unsafe SPDX document key: '+str(document))
        source = input_root/'evidence/spdx'/relative
        require(source.is_file() and sha(source) == record['sha256'],
                'missing or drifted SPDX document: '+document)

    policy = load_json(input_root/'aggregate/source-policy.json')
    for source in policy:
        for license_file in source.get('license_files', []):
            notice = input_root/'evidence/notices'/license_file
            require(notice.is_file(), 'missing license notice: '+license_file)

    profile_path = input_root/'profile.toml'
    profile_bytes = profile_path.read_bytes()
    profile_sha = hashlib.sha256(profile_bytes).hexdigest()
    build = load_json(input_root/'profile-rpm-build.json')
    require(build.get('reproducible') is True and build.get('builds')
            and len(set(build['builds'])) == 1, 'profile build is not a reproducible pair')
    require(digest(build.get('source_profile_sha256', ''))
            and build['source_profile_sha256'] == profile_sha, 'wrong profile hash')
    require(build['profile_filename'] == profile_entry['filename']
            and build['unsigned_sha256'] == profile_entry['unsigned_sha256']
            and build['signed_sha256'] == profile_entry['signed_sha256'],
            'profile build evidence does not match the signed repository entry')
    installed = build.get('installed_profile_path', '')
    require(str(PurePosixPath(installed)) == installed
            and installed.startswith('/usr/share/intel-npu-stack/profiles/')
            and installed.endswith('.toml'), 'invalid installed profile path')

    text = profile_path.read_text()
    if production:
        require('status = "qualified"' in text,
                'production assembly requires a qualified profile')
    else:
        require('status = "candidate"' in text,
                'only an evidence-backed candidate may be assembled')
    require(f'stack_release = "{release}"' in text, 'profile release does not match the assembly')
    try:
        profile_document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise ValueError('profile is not valid TOML: '+str(error)) from error
    components = profile_document.get('components')
    if not isinstance(components, dict) or not components:
        raise ValueError('profile has no components')
    runtime = {entry['name']: entry for entry in entries if entry['role'] == 'runtime'}
    self_hashes = {profile_entry['signed_sha256'], profile_entry['unsigned_sha256'],
                   profile_entry['unchanged_cpio_sha256']}
    require(not any(value in text for value in self_hashes),
            'profile references its own RPM digest (self-hash cycle)')
    for capability, component in sorted(components.items()):
        if not isinstance(component, dict):
            raise ValueError('component is not a table: '+capability)
        provider = component.get('provider')
        if not isinstance(provider, dict):
            raise ValueError('component lacks a provider: '+capability)
        name = provider.get('package')
        entry = runtime.get(name)
        if entry is None:
            raise ValueError('component provider is absent from the release: '+str(name))
        require(provider.get('version') == entry['nevr'],
                'component provider version does not match the signed inventory')
        require(component.get('sha256') == entry['signed_sha256'],
                'component digest does not bind its signed provider: '+capability)

    release_signature = input_root/'release-metadata.sig'
    require(release_signature.is_file() and not release_signature.is_symlink(),
            'detached release metadata signature is missing')
    signature_bytes = release_signature.read_bytes()
    require(0 < len(signature_bytes) <= 65_536,
            'detached release metadata signature must be 1..65536 bytes')
    require(signature_bytes.startswith(b'-----BEGIN PGP SIGNATURE-----'),
            'detached release metadata signature is not ASCII-armored OpenPGP')

    require(not output.exists() or (output.is_dir() and not any(output.iterdir())),
            'output must be absent or empty')

    (output/'packages').mkdir(parents=True)
    for path in packages:
        shutil.copyfile(path, output/'packages'/path.name)
    (output/'repodata').mkdir()
    for path in repodata:
        shutil.copyfile(path, output/'repodata'/path.name)
    shutil.copyfile(profile_path, output/'profile.toml')
    shutil.copyfile(release_signature, output/'release.json.sig')
    copy_tree(input_root/'evidence/spdx', output/'evidence/spdx')
    copy_tree(input_root/'evidence/notices', output/'evidence/notices')
    copy_tree(input_root/'evidence/rollback', output/'evidence/rollback')

    release_manifest = {
        'schema_version': 1,
        'stack_release': release,
        'profile_sha256': profile_sha,
        'repository': {'id': repository_id, 'base_url': base_url,
                       'repomd_sha256': identity['repomd_sha256']},
        'packages': [{'name': entry['name'], 'nevr': entry['nevr'], 'arch': entry['arch'],
                      'filename': entry['filename'], 'sha256': entry['signed_sha256'],
                      'role': entry['role']} for entry in sorted(entries,
                                                                 key=lambda entry: entry['name'])],
    }
    write_json(output/'release.json', release_manifest)

    checksums = []
    for path in sorted(output.rglob('*')):
        if path.is_file():
            checksums.append(f'{sha(path)}  {path.relative_to(output).as_posix()}')
    (output/'checksums.sha256').write_text('\n'.join(checksums)+'\n')

    inputs = {str(path.relative_to(input_root)): sha(path)
              for path in sorted(input_root.rglob('*')) if path.is_file()}
    manifest = {
        'passed': True,
        'test_only': not production,
        'release_ready': False,
        'scope': ('deterministic offline production release composition from accepted '
                  'production-signed inputs; qualification, publication and hardware '
                  'gates remain separate' if production else
                  'deterministic offline release composition from accepted signed inputs; '
                  'no build, signing, publication, VM or hardware qualification'),
        'release_version': release,
        'repository_id': repository_id,
        'base_url': base_url,
        'primary_fingerprint': identity['primary_fingerprint'],
        'package_count': len(entries),
        'payload_paths_verified': len(owned),
        'spdx_documents': len(spdx_index),
        'notices': len(policy),
        'input_digests': inputs,
        'output_digests': {str(path.relative_to(output)): sha(path)
                           for path in sorted(output.rglob('*')) if path.is_file()},
    }
    write_json(output/'assembly-manifest.json', manifest)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['input-root', 'output', 'base-url', 'repository-id', 'release-version']:
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--production', action='store_true',
                        help='compose a production release from production-signed inputs')
    args = parser.parse_args(argv)
    try:
        assemble(Path(args.input_root).resolve(strict=True), Path(args.output),
                 args.base_url, args.repository_id, args.release_version,
                 production=args.production)
    except (OSError, ValueError, KeyError, StopIteration) as error:
        parser.exit(1, 'Fedora release assembly: '+str(error)+'\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
