#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compose, check, sign, archive and describe the versioned release site.

  release_site.py compose --source-commit SHA --tree DIR --records DIR --leg-a DIR --leg-b DIR
                          --profile FILE [--support-notes FILE] --output site/<version>
  release_site.py check   --source-commit SHA --site DIR --profile FILE [--support-notes FILE]
                          --stage unsigned|signed [--expected-files REPORT] [--max-bytes N] [--report FILE]
  release_site.py sign    --source-commit SHA --site DIR --profile FILE [--support-notes FILE]
                          --expected-files REPORT --gpg-home DIR --fingerprint FPR [--passphrase-file FILE]
                          [--require-passphrase]
  release_site.py archive --source-commit SHA --site DIR --profile FILE [--support-notes FILE]
                          --expected-files REPORT --output intel-npu-stack-<version>.tar
  release_site.py notes   --site DIR --archive FILE --output FILE

The site is the signed release tree unchanged, the pinned installer set built
by two independent legs, the build and signing records, a support matrix and a
publication manifest. Everything except the tree, the installer binary and the
signatures is a pure function of its inputs and is re-rendered by `check`.
`check` records the bytes of the site's regular files as total_bytes in its
result and --report, and with --max-bytes N it refuses a site larger than N
bytes. At the unsigned stage it also records signed_bytes_at_most, the site
plus what `sign` adds at most (SHA256SUMS exactly and three signatures of
MAX_SIGNATURE_BYTES), and that must fit N instead: the release workflow's
verify and finalize pass SITE_BUDGET_BYTES, the bytes its preflight reserves
for the new version on Pages.
`sign` adds exactly four files: the installer and install.sh signatures,
SHA256SUMS over every other file, and its signature. It and the signed stage
refuse a signature larger than MAX_SIGNATURE_BYTES. `--repo` (default: this
checkout) must be at --source-commit with unmodified tracked files; its
committed trust seam and release key are the only trust anchors. Outputs are
never overwritten.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib

import check_release
import release_installer
import release_sign
import release_trust

BINARY = release_installer.BINARY
REPO = Path(__file__).resolve().parents[2]
EPOCH = release_sign.EPOCH
SEGMENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]*')
VERSION = re.compile(r'(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})')
DIGEST = re.compile(r'[0-9a-f]{64}')
TREE_EXTRA = ['checksums.sha256', 'checksums.sha256.sig', 'assembly-manifest.json']
INSTALLER_SET = [BINARY, 'install.sh', 'primary-command.txt']
EXECUTABLES = {BINARY, 'install.sh'}
SIGN_RECORDS = ['provider-identity.json', 'signed-identity.json', 'profile-generation.json', 'profile-rpm-build.json']
DERIVED = ['support-matrix.json', 'publication-manifest.json', 'records/installer-build.json',
           'records/installer-trust.rs']
FINALIZE_FILES = ['SHA256SUMS', 'SHA256SUMS.asc', BINARY + '.asc', 'install.sh.asc']
# An armored detached signature by the committed Ed25519 release key is a few hundred bytes; sign and the signed stage
# refuse a larger one, so the size budget can count the signatures before they exist.
MAX_SIGNATURE_BYTES = 4096
LEG_FILES = {*INSTALLER_SET, 'installer-trust.rs', 'installer-build.json'}
LEG_BINDINGS = [('binary_sha256', BINARY), ('install_sh_sha256', 'install.sh'),
                ('primary_command_sha256', 'primary-command.txt'), ('pinned_trust_sha256', 'installer-trust.rs')]
LEG_RECORD_FIELDS = {'leg', 'source_commit', 'version', 'base_url', 'primary_fingerprint', 'release_json_sha256',
                     'pinned_trust_sha256', 'binary_sha256', 'install_sh_sha256', 'primary_command_sha256',
                     'src_root', 'target_dir', 'toolchain', 'image', 'build_environment', 'caller_environment',
                     'umask'}
ASSEMBLY_RECORDS = ['signed-identity.json', 'profile-rpm-build.json']
IDENTITY_ENTRY_FIELDS = {'name', 'nevr', 'arch', 'filename', 'role', 'unsigned_sha256', 'signed_sha256',
                         'header_sha256', 'payload_sha256', 'unchanged_cpio_sha256'}
GENERATION_FIELDS = {'passed', 'test_only', 'profile_status', 'scope', 'schema_version', 'stack_release', 'profile_id',
                     'candidate_sha256', 'signed_identity_sha256', 'output_sha256', 'primary_fingerprint', 'components'}
LEG_AGREE = ['source_commit', 'version', 'base_url', 'primary_fingerprint', 'release_json_sha256',
             'pinned_trust_sha256', 'binary_sha256', 'install_sh_sha256', 'primary_command_sha256', 'src_root',
             'target_dir', 'toolchain', 'image']
FORBIDDEN_TEXT = re.compile(r'claude|anthropic|openai|chatgpt|codex|copilot|gemini|opencode|hermes|'
                            r'co-authored-by|claude-session', re.I)


class SiteRefused(Exception):
    """A site gate failed; nothing further was produced."""


REFUSALS = (SiteRefused, check_release.ReleaseRefused, release_trust.TrustRefused,
            release_installer.InstallerRefused, release_sign.SigningRefused)


def require(condition, message):
    if not condition:
        raise SiteRefused(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(document):
    return (json.dumps(document, indent=2, sort_keys=True) + '\n').encode()


def load_json(path):
    try:
        document = json.loads(Path(path).read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SiteRefused(f'{Path(path).name} is not readable JSON: {error}') from None
    require(isinstance(document, dict), f'{Path(path).name} must hold a JSON object')
    return document


def load_toml(path):
    try:
        return tomllib.loads(Path(path).read_text())
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise SiteRefused(f'{Path(path).name} is not readable TOML: {error}') from None


def write_new(path, data, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'xb') as stream:
        stream.write(data)
    os.chmod(path, mode)


def site_files(root):
    """Regular files under root, bytewise sorted; refuses symlinks, dotfiles, special files and odd names."""
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), f'{root} is not a directory')
    files = []
    def unreadable(error):
        raise SiteRefused(f'site directory cannot be read: {error.filename}')
    for directory, dirnames, filenames in os.walk(root, onerror=unreadable):
        for name in sorted(dirnames + filenames):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            require(SEGMENT.fullmatch(name) is not None, 'unsafe site path: ' + relative)
            mode = os.lstat(path).st_mode
            require(not stat.S_ISLNK(mode), 'symlink in the site: ' + relative)
            if name in filenames:
                require(stat.S_ISREG(mode), 'not a regular file: ' + relative)
                files.append(relative)
    return sorted(files, key=str.encode)


def digests(root, files):
    return {relative: sha(Path(root) / relative) for relative in files}


def committed(repo, commit):
    """The committed trust values of a checkout at the release commit with unmodified tracked files."""
    head = release_installer.git(repo, 'rev-parse', 'HEAD').decode().strip()
    require(head == commit, f'repository HEAD {head} is not the release source commit')
    require(release_installer.git(repo, 'status', '--porcelain', '--untracked-files=no') == b'',
            'tracked files of the release checkout must be unmodified')
    return release_trust.check_committed(repo)


def tracked(repo, path, label):
    """A release input that is a tracked file of the release checkout, so its bytes are the commit's."""
    repo, path = Path(repo).resolve(), Path(path).resolve()
    require(path.is_relative_to(repo) and path.is_file(), f'the {label} must be a tracked file of the release checkout')
    listed = subprocess.run(['git', '-C', str(repo), 'ls-files', '--error-unmatch', '--',
                             path.relative_to(repo).as_posix()], capture_output=True, check=False,
                            env=release_installer.minimal_env({'GIT_CONFIG_NOSYSTEM': '1'}))
    require(listed.returncode == 0, f'the {label} must be a tracked file of the release checkout')
    return path


def tree_subset(root):
    """The signed tree's own files: every checksums entry plus the three files it cannot list."""
    listed = set()
    for line in (Path(root) / 'checksums.sha256').read_text().splitlines():
        match = re.fullmatch(r'[0-9a-f]{64}  (.+)', line)
        require(match is not None, 'malformed checksums line')
        listed.add(check_release.safe_relative(match.group(1)))
    require(not listed & set(TREE_EXTRA), 'checksums.sha256 lists a file it cannot cover: '
            + ', '.join(sorted(listed & set(TREE_EXTRA))))
    return listed | set(TREE_EXTRA)


def check_tree(root, subset, profile, key):
    """check_release on an exact copy of the tree subset."""
    with tempfile.TemporaryDirectory(prefix='site-tree-') as work:
        copy = Path(work) / 'tree'
        for relative in sorted(subset):
            source = Path(root) / relative
            require(source.is_file() and not source.is_symlink(), 'release tree file is missing: ' + relative)
            target = copy / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        return check_release.check_release(copy, profile, Path(work) / 'publication-manifest.json',
                                           production_key=key)


def verify_signature(signature, data, key, fingerprint):
    """The strict release-key policy of the installer, against the committed public key."""
    with tempfile.TemporaryDirectory(prefix='site-gnupg-') as home:
        env = release_sign.child_env(home)
        try:
            imported = subprocess.run(['gpg', '--batch', '--import', str(key)], env=env, capture_output=True,
                                      stdin=subprocess.DEVNULL, timeout=120, check=False)
            require(imported.returncode == 0, 'the committed release key could not be imported')
            result = subprocess.run(['gpg', '--batch', '--status-fd', '1', '--verify', str(signature), str(data)],
                                    env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                                    timeout=120, check=False)
        finally:
            subprocess.run(['gpgconf', '--homedir', home, '--kill', 'all'], env=env, capture_output=True,
                           check=False)
    try:
        require(result.returncode == 0, 'bad signature')
        release_sign.check_signature_status(result.stdout, fingerprint)
    except (SiteRefused, release_sign.SigningRefused):
        raise SiteRefused('signature does not satisfy the pinned release-key policy: '
                          + Path(signature).name) from None


def kernel_version(value, pattern):
    match = re.fullmatch(pattern, value) if isinstance(value, str) else None
    require(match is not None, 'invalid kernel version: ' + repr(value))
    return tuple(int(part) for part in match.groups()[:3])


def requalification_line(maximum):
    major, minor, patch = kernel_version(maximum, r'(\d{1,3})\.(\d{1,3})\.(\d{1,4})')
    if patch == 0:
        return f'kernel {major}.{minor} series and later: requires requalification'
    return f'kernel {maximum} and later: requires requalification'


def short_text(value):
    return isinstance(value, str) and 0 < len(value) <= 120 and value.isprintable()


def support_notes(notes, profile, release):
    """Validated tested kernels and extra not-supported lines from release/<version>/support-notes.toml."""
    require(set(notes) == {'schema_version', 'stack_release', 'profile_id', 'tested_kernels', 'not_supported'},
            'support notes must have exactly schema_version, stack_release, profile_id, tested_kernels and '
            'not_supported')
    require(notes['schema_version'] == 1, 'support notes must be schema_version 1')
    require(notes['stack_release'] == release['stack_release'], 'support notes name another release')
    require(notes['profile_id'] == profile.get('id'), 'support notes name another profile')
    window = profile.get('kernel', {})
    low = kernel_version(window.get('min'), r'(\d{1,3})\.(\d{1,3})\.(\d{1,4})')
    high = kernel_version(window.get('max_exclusive'), r'(\d{1,3})\.(\d{1,3})\.(\d{1,4})')
    suffix = re.escape('fc' + str(profile.get('platform', {}).get('version_id')))
    tested = notes['tested_kernels']
    require(isinstance(tested, list) and tested, 'support notes must list the tested kernels')
    releases = []
    for entry in tested:
        require(isinstance(entry, dict) and set(entry) == {'release', 'tests'}, 'invalid tested kernel entry')
        version = kernel_version(entry['release'], r'(\d{1,3})\.(\d{1,3})\.(\d{1,4})-\d{1,4}\.' + suffix)
        require(low <= version < high, f'tested kernel {entry["release"]} lies outside the profile kernel window')
        require(entry['release'] not in releases, 'duplicate tested kernel: ' + entry['release'])
        require(isinstance(entry['tests'], list) and entry['tests'] and all(map(short_text, entry['tests'])),
                'tested kernel entries need short printable test names')
        releases.append(entry['release'])
    require(isinstance(notes['not_supported'], list) and all(map(short_text, notes['not_supported'])),
            'not_supported must be a list of short printable lines')
    return tested, notes['not_supported']


def render_support_matrix(profile, release, notes, values, fingerprint, metadata):
    tested, extra = support_notes(notes, profile, release)
    window = profile['kernel']
    components = {
        name: {'upstream_version': component.get('version'), 'package': component['provider']['package'],
               'package_version': component['provider']['version'],
               'activation': component['provider']['activation']}
        for name, component in sorted(profile.get('components', {}).items())}
    optional = [{'name': entry['name'], 'nevr': entry['nevr'], 'role': entry['role']}
                for entry in release['packages'] if entry['role'] in {'python', 'devel'}]
    matrix = {
        'schema_version': 1,
        'stack_release': release['stack_release'],
        'profile': {'id': profile['id'], 'status': profile['status']},
        'platform': profile['platform'],
        'hardware': profile.get('hardware', []),
        'kernel': {'min': window['min'], 'max_exclusive': window['max_exclusive'], 'module': window['module'],
                   'tested': tested,
                   'policy': 'Other kernels inside the window are admitted by policy, observed by the kernel '
                             'watcher and need a recorded per-kernel probe.'},
        'channels': ['stable'],
        'components': components,
        'optional_packages': optional,
        'qualification': profile['qualification'],
        'repository': {'id': release['repository']['id'], 'base_url': values['base_url'],
                       'release_json_sha256': metadata, 'key_fingerprint': fingerprint},
        'rollback': {'index': 'evidence/rollback/rollback-index.json',
                     'instructions': 'docs/install-fedora.md, section "Removal and rollback"'},
        'not_supported': [requalification_line(window['max_exclusive']), *extra],
    }
    return canonical(matrix)


def render_installer_set(repo, values, binary_sha):
    render = release_installer.renderer(repo)
    bootstrap = render.render_bootstrap(values['version'], values['base_url'] + BINARY, binary_sha).encode()
    primary = render.render_install_command(values['version'], values['base_url'] + 'install.sh',
                                            hashlib.sha256(bootstrap).hexdigest()).encode()
    return {'install.sh': bootstrap, 'primary-command.txt': primary}


def render_publication_manifest(result, site, legs, values, metadata, commit, files):
    manifest = dict(result)
    manifest['installer'] = {
        'pinned': {'version': values['version'], 'base_url': values['base_url'],
                   'primary_fingerprint': values['primary_fingerprint'], 'release_json_sha256': metadata,
                   'pinned_trust_sha256': sha(site / 'records/installer-trust.rs')},
        'digests': {name: sha(site / name) for name in [*INSTALLER_SET, 'records/installer-trust.rs']},
        'legs': {name: record['binary_sha256'] for name, record in sorted(legs.items())},
    }
    manifest['site_files'] = digests(site, [f for f in files if f != 'publication-manifest.json'])
    manifest['source_commit'] = commit
    return canonical(manifest)


def render_sha256sums(site):
    files = [f for f in site_files(site) if f not in {'SHA256SUMS', 'SHA256SUMS.asc'}]
    return ''.join(f'{sha(Path(site) / f)}  {f}\n' for f in files).encode()


def signing_bytes(files):
    """The most bytes sign adds to an unsigned site of these files: SHA256SUMS exactly, with a line for each file and
    for the two signatures it lists, and three signatures of at most MAX_SIGNATURE_BYTES each."""
    listed = [*files, BINARY + '.asc', 'install.sh.asc']
    return sum(len(f'{"0" * 64}  {name}\n'.encode()) for name in listed) + 3 * MAX_SIGNATURE_BYTES


def check_signature_size(path):
    require(path.stat().st_size <= MAX_SIGNATURE_BYTES, f'{path.name} is larger than {MAX_SIGNATURE_BYTES} bytes')


def check_leg_record(record, name):
    """An installer build record with every provenance field present and well formed."""
    invalid = f'installer leg {name} record '
    require(isinstance(record, dict) and set(record) == LEG_RECORD_FIELDS,
            invalid + 'must have exactly the build record fields: ' + ', '.join(sorted(LEG_RECORD_FIELDS)))
    require(record['leg'] == name, invalid + 'names another leg')
    require(isinstance(record['source_commit'], str) and re.fullmatch(r'[0-9a-f]{40}', record['source_commit']),
            invalid + 'has an invalid source_commit')
    for field in ['release_json_sha256', 'pinned_trust_sha256', 'binary_sha256', 'install_sh_sha256',
                  'primary_command_sha256']:
        require(isinstance(record[field], str) and DIGEST.fullmatch(record[field]), invalid + 'has an invalid ' + field)
    require(isinstance(record['image'], str) and release_installer.IMAGE_DIGEST.fullmatch(record['image']),
            invalid + 'lacks a builder image digest')
    toolchain = record['toolchain']
    require(isinstance(toolchain, dict) and set(toolchain) == {'rustc', 'cargo'}
            and all(isinstance(value, str) and value.strip() for value in toolchain.values()),
            invalid + 'lacks the rustc and cargo versions')
    for field in ['src_root', 'target_dir']:
        require(isinstance(record[field], str) and Path(record[field]).is_absolute(),
                invalid + 'has a non-absolute ' + field)
    environment = record['build_environment']
    require(isinstance(environment, dict) and all(isinstance(k, str) and isinstance(v, str)
                                                 for k, v in environment.items())
            and {'PATH', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS'} <= set(environment),
            invalid + 'lacks its build environment')
    caller = record['caller_environment']
    require(isinstance(caller, dict) and set(caller) == {'TZ', 'LANG', 'IMAGE_DIGEST'}
            and caller['IMAGE_DIGEST'] == record['image'], invalid + 'has an invalid caller environment')
    require(isinstance(record['umask'], str) and re.fullmatch(r'0o[0-7]{1,4}', record['umask']),
            invalid + 'has an invalid umask')
    return record


def load_legs(leg_a, leg_b):
    """Both leg outputs, byte-equal, with records that bind their bytes and agree on everything but perturbation."""
    legs = {}
    for name, directory in (('a', Path(leg_a)), ('b', Path(leg_b))):
        require(set(site_files(directory)) == LEG_FILES, f'installer leg {name} has an unexpected file set')
        record = check_leg_record(load_json(directory / 'installer-build.json'), name)
        for field, file in LEG_BINDINGS:
            require(record.get(field) == sha(directory / file), f'installer leg {name} record does not bind {file}')
        legs[name] = record
    for file in sorted(LEG_FILES - {'installer-build.json'}):
        require((Path(leg_a) / file).read_bytes() == (Path(leg_b) / file).read_bytes(),
                'tool drift between legs: ' + file + ' differs')
    check_legs_agree(legs['a'], legs['b'])
    return legs


def check_legs_agree(first, second):
    """Two well-formed leg records that differ only in the perturbed job count, TZ, LANG and umask."""
    for field in LEG_AGREE:
        require(first[field] == second[field], 'tool drift between legs: ' + field)

    def unperturbed(record):
        return {key: value for key, value in record['build_environment'].items() if key != 'CARGO_BUILD_JOBS'}
    require(unperturbed(first) == unperturbed(second), 'tool drift between legs: build_environment')
    # Leg b must carry every prescribed perturbation; a copied leg repeats leg a's values.
    repeated = [name for name, one, other in (
        ('CARGO_BUILD_JOBS', first['build_environment']['CARGO_BUILD_JOBS'],
         second['build_environment']['CARGO_BUILD_JOBS']),
        ('TZ', first['caller_environment']['TZ'], second['caller_environment']['TZ']),
        ('LANG', first['caller_environment']['LANG'], second['caller_environment']['LANG']),
        ('umask', first['umask'], second['umask'])) if one == other]
    require(not repeated, "the installer legs are not independent builds: leg b repeats leg a's "
            + ', '.join(repeated))


def production_identity(record, fingerprint):
    return (isinstance(record, dict) and record.get('passed') is True and record.get('test_only') is False
            and record.get('production_ready') is True and record.get('private_key_exported') is False
            and record.get('primary_fingerprint') == fingerprint and isinstance(record.get('packages'), list)
            and all(isinstance(entry, dict) for entry in record['packages']))


def check_identity_entries(site, release, signed, candidate):
    """Each signed-identity entry: release.json fields, the RPM's own digests and the candidate's unsigned digest."""
    published = {entry['filename']: entry for entry in release['packages']}
    # generate-release-profile.py requires a component's candidate digest to be its provider's unsigned digest.
    unsigned = {component.get('provider', {}).get('package'): component.get('sha256')
                for component in candidate.get('components', {}).values()}
    for entry in signed['packages']:
        invalid = f"records/signed-identity.json does not describe {entry.get('filename')!r}"
        require(set(entry) == IDENTITY_ENTRY_FIELDS, invalid + ': it must have exactly the identity entry fields')
        release_entry = published[entry['filename']]
        require(all(entry[field] == release_entry[field] for field in ['name', 'nevr', 'arch', 'role']),
                invalid + ': name, nevr, arch or role differs from release.json')
        require(all(isinstance(entry[field], str) and DIGEST.fullmatch(entry[field])
                    for field in ['unsigned_sha256', 'header_sha256', 'payload_sha256', 'unchanged_cpio_sha256']),
                invalid + ': malformed digest')
        digests = release_sign.payload_digests(site / 'packages' / entry['filename'])
        require(digests == {field: entry[field] for field in digests},
                invalid + ': header or payload digests differ from the RPM')
        require(entry['name'] not in unsigned or entry['unsigned_sha256'] == unsigned[entry['name']],
                invalid + ': unsigned digest differs from the selected profile')


def check_signing_records(site, release, values, profile, candidate):
    """The signing job's records describe this release: key, packages, repository, profile and each other."""
    provider = load_json(site / 'records/provider-identity.json')
    signed = load_json(site / 'records/signed-identity.json')
    generation = load_json(site / 'records/profile-generation.json')
    fingerprint = values['primary_fingerprint']
    for label, record in (('provider-identity', provider), ('signed-identity', signed)):
        require(production_identity(record, fingerprint),
                f'records/{label}.json is not a passed production identity for the release key')
    require(signed.get('repomd_sha256') == release['repository']['repomd_sha256'],
            'records/signed-identity.json does not bind the signed repository metadata')
    require(sorted((entry.get('filename'), entry.get('signed_sha256')) for entry in signed['packages'])
            == sorted((entry['filename'], entry['sha256']) for entry in release['packages']),
            'records/signed-identity.json does not list the release packages')
    check_identity_entries(site, release, signed, load_toml(candidate))

    def by_name(entries):
        return sorted(entries, key=lambda entry: str(entry.get('name')))
    # The signed identity is the provider identity plus the profile package and the repository digest.
    require(set(provider) == set(signed) - {'repomd_sha256'}
            and all(provider[key] == signed[key] for key in provider if key != 'packages')
            and by_name(provider['packages'])
            == by_name([entry for entry in signed['packages'] if entry.get('role') != 'profile']),
            'records/provider-identity.json is not the identity the signed identity extends')
    check_profile_build(site, release, signed, profile)
    # The generator rewrote each component digest from the identity; candidate.toml is the selected profile.
    by_name = {entry.get('name'): entry for entry in signed['packages']}
    components = {}
    for capability, component in sorted(profile.get('components', {}).items()):
        package = component.get('provider', {}).get('package')
        entry = by_name.get(package, {})
        require(entry.get('signed_sha256') == component.get('sha256'),
                'records/profile-generation.json does not describe this release profile')
        components[capability] = {'package': package, 'nevr': entry.get('nevr'),
                                   'unsigned_sha256': entry.get('unsigned_sha256'),
                                   'signed_sha256': entry.get('signed_sha256')}
    expected = {'passed': True, 'test_only': False, 'profile_status': 'qualified', 'schema_version': 1,
                'stack_release': values['version'], 'profile_id': profile.get('id'), 'primary_fingerprint': fingerprint,
                'candidate_sha256': sha(candidate),
                'signed_identity_sha256': sha(site / 'records/provider-identity.json'),
                'output_sha256': sha(site / 'profile.toml'), 'components': components}
    require(set(generation) == GENERATION_FIELDS
            and isinstance(generation['scope'], str) and generation['scope'].strip()
            and all(generation[key] == value for key, value in expected.items()),
            'records/profile-generation.json does not describe this release profile')


def check_profile_build(site, release, signed, profile):
    """records/profile-rpm-build.json, checked against the signed release rather than the unsigned manifest."""
    record = load_json(site / 'records/profile-rpm-build.json')
    invalid = 'records/profile-rpm-build.json does not describe the release profile package'
    profiles = [entry for entry in release['packages'] if entry['role'] == 'profile']
    require(set(record) == {'profile_filename', 'source_profile_sha256', 'unsigned_sha256', 'signed_sha256',
                            'installed_profile_path', 'builds', 'reproducible'} and len(profiles) == 1, invalid)
    identity = [entry for entry in signed['packages'] if entry.get('filename') == profiles[0]['filename']]
    require(record['profile_filename'] == profiles[0]['filename'] and record['signed_sha256'] == profiles[0]['sha256']
            and record['source_profile_sha256'] == sha(site / 'profile.toml')
            and isinstance(record['unsigned_sha256'], str) and DIGEST.fullmatch(record['unsigned_sha256'])
            and record['builds'] == [record['unsigned_sha256']] * 2 and record['reproducible'] is True
            and len(identity) == 1 and identity[0].get('role') == 'profile'
            and identity[0].get('unsigned_sha256') == record['unsigned_sha256']
            and record['installed_profile_path'] == f"/usr/share/intel-npu-stack/profiles/{profile.get('id')}.toml",
            invalid)


def check_installer_records(site, values, metadata, commit):
    document = load_json(site / 'records/installer-build.json')
    require(set(document) == {'schema_version', 'legs'} and document['schema_version'] == 1
            and isinstance(document['legs'], dict) and set(document['legs']) == {'a', 'b'},
            'records/installer-build.json must hold schema_version 1 and exactly legs a and b')
    expected = {'source_commit': commit, 'version': values['version'], 'base_url': values['base_url'],
                'primary_fingerprint': values['primary_fingerprint'], 'release_json_sha256': metadata,
                'binary_sha256': sha(site / BINARY), 'install_sh_sha256': sha(site / 'install.sh'),
                'primary_command_sha256': sha(site / 'primary-command.txt'),
                'pinned_trust_sha256': sha(site / 'records/installer-trust.rs')}
    for name, record in document['legs'].items():
        check_leg_record(record, name)
        for field, value in expected.items():
            require(record.get(field) == value, f'installer leg {name} record does not match the site: {field}')
    check_legs_agree(document['legs']['a'], document['legs']['b'])
    return document['legs']


def verify_site(site, repo, commit, profile, notes_path, stage, expected_files=None):
    """Every rule of the site at one stage; returns the verification report."""
    site, repo = Path(site), Path(repo)
    values = committed(repo, commit)
    profile, notes_path = tracked(repo, profile, 'profile'), tracked(repo, notes_path, 'support notes')
    key = repo / release_trust.KEY_PATH
    files = site_files(site)
    subset = tree_subset(site)
    unsigned = sorted(subset | set(INSTALLER_SET) | {'records/' + name for name in SIGN_RECORDS} | set(DERIVED),
                      key=str.encode)
    expected = unsigned if stage == 'unsigned' else sorted([*unsigned, *FINALIZE_FILES], key=str.encode)
    missing, extra = sorted(set(expected) - set(files)), sorted(set(files) - set(expected))
    require(not missing and not extra, f'site file set differs; missing {missing}, unexpected {extra}')

    result = check_tree(site, subset, profile, key)
    release = load_json(site / 'release.json')
    metadata = sha(site / 'release.json')
    committed_trust = (repo / release_trust.TRUST_PATH).read_text()
    require((site / 'records/installer-trust.rs').read_text() == release_trust.pin_metadata(committed_trust, metadata),
            'records/installer-trust.rs is not the committed trust seam pinned to this release.json')
    require(release['repository']['base_url'] == values['base_url'] == result['base_url'],
            'release base_url does not equal the committed BASE_URL')
    require(result['release_key_fingerprint'] == values['primary_fingerprint'],
            'the release key fingerprint does not equal the committed PRIMARY_FINGERPRINT')
    binary = (site / BINARY).read_bytes()
    release_installer.check_elf(binary)
    for literal in (metadata, values['base_url'], values['primary_fingerprint']):
        require(literal.encode() in binary, 'the installer lacks a pinned trust value: ' + literal)
    legs = check_installer_records(site, values, metadata, commit)
    assembled = load_json(site / 'assembly-manifest.json').get('input_digests')
    require(isinstance(assembled, dict), 'assembly-manifest.json records no input digests')
    for name in ASSEMBLY_RECORDS:
        require(assembled.get(name) == sha(site / 'records' / name),
                f'records/{name} is not the signing record the assembly was built from')
    check_signing_records(site, release, values, load_toml(site / 'profile.toml'), profile)

    for name, data in render_installer_set(repo, values, sha(site / BINARY)).items():
        require((site / name).read_bytes() == data, name + ' differs from its rendering')
    matrix = render_support_matrix(load_toml(site / 'profile.toml'), release, load_toml(notes_path), values,
                                   values['primary_fingerprint'], metadata)
    require((site / 'support-matrix.json').read_bytes() == matrix, 'support-matrix.json differs from its rendering')
    manifest = render_publication_manifest(result, site, legs, values, metadata, commit, unsigned)
    require((site / 'publication-manifest.json').read_bytes() == manifest,
            'publication-manifest.json differs from its rendering')

    if stage == 'signed':
        require(expected_files is not None, 'the signed stage needs the unsigned verification report')
        require(digests(site, unsigned) == expected_files, 'unsigned files changed after verification')
        for signature in (BINARY + '.asc', 'install.sh.asc', 'SHA256SUMS.asc'):
            check_signature_size(site / signature)
        require((site / 'SHA256SUMS').read_bytes() == render_sha256sums(site), 'SHA256SUMS differs from the site')
        for signature, data in ((BINARY + '.asc', BINARY), ('install.sh.asc', 'install.sh'),
                                ('SHA256SUMS.asc', 'SHA256SUMS')):
            verify_signature(site / signature, site / data, key, values['primary_fingerprint'])
    return {'schema_version': 1, 'stage': stage, 'passed': True, 'source_commit': commit,
            'release_version': values['version'], 'release_json_sha256': metadata,
            'binary_sha256': sha(site / BINARY), 'files': digests(site, expected)}


def compose(repo, commit, tree, records, leg_a, leg_b, profile, notes_path, output):
    repo, tree, records, output = Path(repo), Path(tree), Path(records), Path(output)
    require(not output.exists(), f'{output} already exists; outputs are never overwritten')
    values = committed(repo, commit)
    profile, notes_path = tracked(repo, profile, 'profile'), tracked(repo, notes_path, 'support notes')
    require(output.name == values['version'], 'the site directory must be named after the release version')
    legs = load_legs(leg_a, leg_b)
    tree_files = site_files(tree)
    subset = tree_subset(tree)
    require(set(tree_files) == subset, 'the release tree holds files outside its checksums')
    require(set(site_files(records)) == set(SIGN_RECORDS),
            'the signing records must be exactly ' + ', '.join(SIGN_RECORDS))
    added = set(INSTALLER_SET) | {'records/' + name for name in SIGN_RECORDS} | set(DERIVED) | set(FINALIZE_FILES)
    collisions = sorted(subset & added)
    require(not collisions, 'release tree names collide with site files: ' + ', '.join(collisions))
    for name in SIGN_RECORDS:
        load_json(records / name)
    result = check_tree(tree, subset, profile, repo / release_trust.KEY_PATH)
    release = load_json(tree / 'release.json')
    metadata = sha(tree / 'release.json')
    require(legs['a']['release_json_sha256'] == metadata and legs['a']['source_commit'] == commit,
            'the installer legs were built for another release.json or commit')

    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o755)
    try:
        for relative in tree_files:
            write_new(output / relative, (tree / relative).read_bytes())
        for name in INSTALLER_SET:
            write_new(output / name, (Path(leg_a) / name).read_bytes(), 0o755 if name in EXECUTABLES else 0o644)
        for name in SIGN_RECORDS:
            write_new(output / 'records' / name, (records / name).read_bytes())
        write_new(output / 'records/installer-trust.rs', (Path(leg_a) / 'installer-trust.rs').read_bytes())
        write_new(output / 'records/installer-build.json', canonical({'schema_version': 1, 'legs': legs}))
        write_new(output / 'support-matrix.json',
                  render_support_matrix(load_toml(tree / 'profile.toml'), release, load_toml(notes_path), values,
                                        values['primary_fingerprint'], metadata))
        unsigned = sorted([*tree_files, *INSTALLER_SET, *('records/' + n for n in SIGN_RECORDS), *DERIVED],
                          key=str.encode)
        write_new(output / 'publication-manifest.json',
                  render_publication_manifest(result, output, legs, values, metadata, commit, unsigned))
        for directory, _, _ in os.walk(output):
            os.chmod(directory, 0o755)
        return verify_site(output, repo, commit, profile, notes_path, 'unsigned')
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise


def sign(site, gnupghome, fingerprint, repo, commit, profile, notes_path, expected_files, passphrase_file=None):
    """Sign a site only after it passes the unsigned stage with exactly the verified unsigned bytes."""
    site = Path(site)
    require(not any((site / name).exists() for name in FINALIZE_FILES), 'the site is already signed')
    require(fingerprint == release_trust.check_committed(repo)['primary_fingerprint'],
            'the signing fingerprint is not the committed PRIMARY_FINGERPRINT')
    report = verify_site(site, repo, commit, profile, notes_path, 'unsigned')
    require(report['files'] == expected_files, 'the site is not the verified unsigned site')
    written = []
    try:
        for name in [BINARY, 'install.sh']:
            signature = site / (name + '.asc')
            written.append(signature)
            release_sign.detach_sign(site / name, signature, gnupghome, fingerprint, passphrase_file)
            check_signature_size(signature)
            release_sign.verify_detached(signature, site / name, gnupghome, fingerprint)
        sums = site / 'SHA256SUMS'
        written.append(sums)
        write_new(sums, render_sha256sums(site))
        written.append(site / 'SHA256SUMS.asc')
        release_sign.detach_sign(sums, site / 'SHA256SUMS.asc', gnupghome, fingerprint, passphrase_file)
        check_signature_size(site / 'SHA256SUMS.asc')
        release_sign.verify_detached(site / 'SHA256SUMS.asc', sums, gnupghome, fingerprint)
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        raise
    for name in FINALIZE_FILES:
        os.chmod(site / name, 0o644)
    return {name: sha(site / name) for name in FINALIZE_FILES}


def archive(site, output, repo, commit, profile, notes_path, expected_files):
    """Deterministic uncompressed GNU tar of a signed site; members <version>/<path>, bytewise sorted.

    The site passes every signed-stage check first, so only a verified site becomes the archive.
    """
    site, output = Path(site), Path(output)
    version = site.name
    require(VERSION.fullmatch(version) is not None, 'the site directory must be named after the release version')
    require(output.name == f'intel-npu-stack-{version}.tar', f'the archive must be named intel-npu-stack-{version}.tar')
    require(not output.exists(), f'{output} already exists; outputs are never overwritten')
    require(not Path(os.path.abspath(output)).parent.resolve().is_relative_to(site.resolve()),
            'the archive must be written outside the site')
    verify_site(site, repo, commit, profile, notes_path, 'signed', expected_files)
    require(load_json(site / 'release.json').get('stack_release') == version, 'release.json names another version')
    try:
        with open(output, 'xb') as stream:
            write_archive(site, stream)
    except FileExistsError:
        raise SiteRefused(f'{output} already exists; outputs are never overwritten') from None
    except BaseException:  # never leave a partial archive
        output.unlink(missing_ok=True)
        raise
    return sha(output)


def write_archive(site, stream):
    """The canonical archive of a site: GNU tar, members <version>/<path> bytewise sorted, normalized metadata."""
    site = Path(site)
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.GNU_FORMAT) as tar:
        for relative in site_files(site):
            path = site / relative
            info = tarfile.TarInfo(site.name + '/' + relative)
            info.size = path.stat().st_size
            info.mode = 0o755 if relative in EXECUTABLES else 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mtime = EPOCH
            info.type = tarfile.REGTYPE
            with path.open('rb') as data:
                tar.addfile(info, data)


def repository_slug(base_url, version):
    match = re.fullmatch(r'https://([a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?)\.github\.io/([A-Za-z0-9._-]+)/'
                         + re.escape(version) + '/', base_url)
    require(match is not None, 'release notes need a versioned GitHub Pages base URL')
    return match.group(1) + '/' + match.group(2)


def lint_public_text(text):
    found = FORBIDDEN_TEXT.search(text)
    require(found is None, 'public release text names a tool or product it must not: ' + repr(found and found.group(0)))
    require('\r' not in text and all(ch.isprintable() or ch == '\n' for ch in text),
            'public release text holds control characters')
    return text


def check_archive_holds(archive_path, site):
    """The archive is byte for byte the canonical archive of this site, trailing bytes included."""
    with tempfile.TemporaryFile() as rendered:
        write_archive(site, rendered)
        rendered.seek(0)
        canonical_sha = hashlib.file_digest(rendered, 'sha256').hexdigest()
    require(sha(archive_path) == canonical_sha, 'the archive is not the canonical archive of this site')


def render_notes(site, archive_path):
    site, archive_path = Path(site), Path(archive_path)
    version = site.name
    require(archive_path.name == f'intel-npu-stack-{version}.tar', 'the archive does not belong to this version')
    check_archive_holds(archive_path, site)
    matrix = load_json(site / 'support-matrix.json')
    repository = matrix['repository']
    base = repository['base_url']
    slug = repository_slug(base, version)
    kernel = matrix['kernel']
    tested = '; '.join(f'{entry["release"]} ({", ".join(entry["tests"])})' for entry in kernel['tested'])
    hardware = ', '.join(f'{entry["vendor"]}:{entry["device"]}' for entry in matrix['hardware'])
    platform = matrix['platform']
    command = (site / 'primary-command.txt').read_text().rstrip('\n')
    rows = [('release.json', sha(site / 'release.json')), (archive_path.name, sha(archive_path)),
            ('SHA256SUMS', sha(site / 'SHA256SUMS')),
            ('Qualification evidence', matrix['qualification']['evidence_sha256'])]
    lines = [
        f'# Intel NPU Stack {version}', '',
        # The version directory has no index page, so the notes link its files and never the bare directory.
        f'Signed Fedora {platform["version_id"]} {platform["arch"]} packages for the Intel NPU on PCI {hardware}, '
        f'served from `{base}`. That directory has no index page; [`SHA256SUMS`]({base}SHA256SUMS) lists every '
        f'other file in it, and [`SHA256SUMS.asc`]({base}SHA256SUMS.asc) is its signature.', '',
        '## Install', '',
        'Run as a normal user; the installer asks for privileges only when it applies the plan:', '',
        '```sh', command, '```', '',
        'The command downloads `install.sh`, checks its SHA-256 and runs it. `install.sh` checks the installer '
        'binary the same way, and the installer verifies `release.json` against the release key it carries.', '',
        '### Verify before running', '',
        f'1. Download [`install.sh`]({base}install.sh) and [`install.sh.asc`]({base}install.sh.asc).',
        '2. Run `gpg --status-fd 1 --verify install.sh.asc install.sh` with the release public key and check that '
        f'`VALIDSIG` names the primary key `{repository["key_fingerprint"]}`.',
        '3. Read `install.sh`.',
        '4. Run `sh install.sh --dry-run`, then `sh install.sh`.', '',
        '## Support', '',
        f'- Platform: Fedora {platform["version_id"]} {platform["arch"]} (`{platform["id"]}`), profile '
        f'`{matrix["profile"]["id"]}` ({matrix["profile"]["status"]}).',
        f'- Hardware: PCI {hardware}.',
        f'- Kernel: {kernel["min"]} up to, not including, {kernel["max_exclusive"]} (`{kernel["module"]}`). '
        f'Tested: {tested}. {kernel["policy"]}',
        '- Not supported: ' + '; '.join(matrix['not_supported']) + '.',
        f'- The full matrix is [`support-matrix.json`]({base}support-matrix.json).', '',
        '## Digests', '',
        '| File | SHA-256 |', '|---|---|',
        *[f'| {name} | `{digest}` |' for name, digest in rows], '',
        '## Rollback', '',
        'The Fedora packages this release replaces are kept in `evidence/rollback` '
        f'(index `{matrix["rollback"]["index"]}`). '
        f'See {matrix["rollback"]["instructions"]} for removal and rollback.', '',
        '## Verify the release', '',
        '```sh',
        f'gh release verify v{version} -R {slug}',
        f'gh release verify-asset v{version} {archive_path.name} -R {slug}',
        f'gh attestation verify {archive_path.name} -R {slug}',
        'gpg --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS',
        'sha256sum --check --strict SHA256SUMS',
        '```', '',
    ]
    return lint_public_text('\n'.join(lines)).encode()


def require_outside(path, roots, label):
    """Auxiliary outputs (reports, notes) never land inside a site, which must keep its exact file set."""
    parent = Path(os.path.abspath(path)).parent.resolve()
    for root in roots:
        require(root is None or not parent.is_relative_to(Path(root).resolve()),
                f'the {label} must be written outside the site')


def require_new_file(path, label):
    """An output that does not exist yet in an existing directory, checked before anything changes."""
    path = Path(path)
    require(not path.exists() and not path.is_symlink(), f'the {label} {path} already exists')
    require(path.parent.is_dir(), f'the {label} directory {path.parent} does not exist')


def unsigned_report(path):
    """The file digests of an unsigned-stage verification report."""
    report = load_json(path)
    require(report.get('stage') == 'unsigned' and isinstance(report.get('files'), dict),
            '--expected-files must be an unsigned-stage report')
    return report['files']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=['compose', 'check', 'sign', 'archive', 'notes'])
    parser.add_argument('--repo', type=Path, default=REPO)
    parser.add_argument('--source-commit')
    parser.add_argument('--tree', type=Path)
    parser.add_argument('--records', type=Path)
    parser.add_argument('--leg-a', type=Path)
    parser.add_argument('--leg-b', type=Path)
    parser.add_argument('--profile', type=Path)
    parser.add_argument('--support-notes', type=Path)
    parser.add_argument('--site', type=Path)
    parser.add_argument('--stage', choices=['unsigned', 'signed'])
    parser.add_argument('--expected-files', type=Path, help='the unsigned-stage report of the verified site')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--max-bytes', type=int, help='check: refuse a site larger than this many bytes')
    parser.add_argument('--gpg-home', type=Path)
    parser.add_argument('--fingerprint')
    parser.add_argument('--passphrase-file')
    parser.add_argument('--require-passphrase', action='store_true')
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    needed = {'compose': ['source_commit', 'tree', 'records', 'leg_a', 'leg_b', 'profile', 'output'],
              'check': ['source_commit', 'site', 'profile', 'stage'],
              'sign': ['source_commit', 'site', 'profile', 'expected_files', 'gpg_home', 'fingerprint'],
              'archive': ['source_commit', 'site', 'profile', 'expected_files', 'output'],
              'notes': ['site', 'archive', 'output']}[args.command]
    missing = [name for name in needed if getattr(args, name) is None]
    if missing:
        parser.error(args.command + ' requires ' + ', '.join('--' + name.replace('_', '-') for name in missing))
    try:
        sites = [args.site, args.output if args.command == 'compose' else None]
        if args.report is not None:
            require_outside(args.report, sites, 'report')
            require_new_file(args.report, 'report')
        if args.command == 'notes':
            require_outside(args.output, [args.site], 'release notes')
            require_new_file(args.output, 'release notes')
        notes_path = args.support_notes
        if args.command in {'compose', 'check', 'sign', 'archive'} and notes_path is None:
            version = release_trust.check_committed(args.repo)['version']
            notes_path = args.repo / 'release' / version / 'support-notes.toml'
        if args.command == 'compose':
            result = compose(args.repo, args.source_commit, args.tree, args.records, args.leg_a, args.leg_b,
                             args.profile, notes_path, args.output)
        elif args.command == 'check':
            expected = None
            if args.stage == 'signed':
                require(args.expected_files is not None, 'the signed stage needs --expected-files')
                expected = unsigned_report(args.expected_files)
            result = verify_site(args.site, args.repo, args.source_commit, args.profile, notes_path, args.stage,
                                 expected)
            files = site_files(args.site)
            result['total_bytes'] = budgeted = sum((args.site / name).stat().st_size for name in files)
            size = f'the site is {budgeted} bytes'
            if args.stage == 'unsigned':
                # The budget is the preflight's reserve for the site as Pages serves it, so what sign adds counts.
                budgeted = result['signed_bytes_at_most'] = budgeted + signing_bytes(files)
                size += f' and at most {budgeted} once signed'
            require(args.max_bytes is None or budgeted <= args.max_bytes,
                    f'{size}, above the {args.max_bytes}-byte size budget')
        elif args.command == 'sign':
            passphrase = (release_sign.check_passphrase_file(args.passphrase_file)
                          if args.passphrase_file else None)
            require(passphrase or not args.require_passphrase, '--require-passphrase needs --passphrase-file')
            result = sign(args.site, args.gpg_home, args.fingerprint, args.repo, args.source_commit, args.profile,
                          notes_path, unsigned_report(args.expected_files), passphrase)
        elif args.command == 'archive':
            result = {'archive': str(args.output),
                      'sha256': archive(args.site, args.output, args.repo, args.source_commit, args.profile,
                                        notes_path, unsigned_report(args.expected_files))}
        else:
            write_new(args.output, render_notes(args.site, args.archive))
            result = {'notes': str(args.output), 'sha256': sha(args.output)}
        if args.report is not None:
            write_new(args.report, canonical(result))
    except REFUSALS as error:
        parser.exit(1, f'release site {args.command} refused: {error}\n')
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'release site {args.command} refused: {error!r}\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'files'}, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
