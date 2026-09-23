#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Sign and assemble a production release tree from prepared release inputs.

Runs in the protected release environment only. Consumes previously built
unsigned RPMs, the aggregate evidence inputs and the retained rollback RPMs,
signs every RPM and the profile RPM with the production key from the
isolated keyring, signs the repository and detached release metadata,
composes the release twice with --production and emits the signed release
tree. Performs no publication, no installer build and no build of the
provider packages.

The key passphrase reaches gpg and rpmsign only as a file path
(--passphrase-file); it is never placed on a command line or in a child
environment, and a passphrase in RELEASE_SIGNING_PASSPHRASE is refused.
Signing must leave every package header and payload digest unchanged.

--check-inputs validates the inputs directory against the selected profile
without any key material.

Inputs directory contract:
  index.json, unsigned-rpms/, candidate.toml, package-index.json,
  spdx-index.json, source-policy.json, notices/, evidence/spdx/,
  rollback-index.json, rollback-rpms/
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib

EPOCH = 1789084800
PROFILE_ID = 'fedora-44-lunar-lake-x86_64'
# Fedora providers replaced by the coupled stack, including the loader takeover.
ROLLBACK_PACKAGES = {
    'intel-npu-compiler', 'intel-npu-driver', 'libopenvino-ir-frontend',
    'libopenvino-onnx-frontend', 'libopenvino-paddle-frontend',
    'libopenvino-pytorch-frontend', 'libopenvino-tensorflow-frontend',
    'libopenvino-tensorflow-lite-frontend', 'oneapi-level-zero',
    'openvino', 'openvino-devel', 'openvino-plugins',
}
# The fourteen runtime packages of the matched stack; every one must be staged as runtime.
RUNTIME_PACKAGES = {
    'intel-npu-compiler', 'intel-npu-driver', 'intel-npu-stack', 'intel-npu-stack-firmware',
    'intel-npu-stack-tools', 'libopenvino-ir-frontend', 'libopenvino-onnx-frontend',
    'libopenvino-paddle-frontend', 'libopenvino-pytorch-frontend',
    'libopenvino-tensorflow-frontend', 'libopenvino-tensorflow-lite-frontend',
    'oneapi-level-zero', 'openvino', 'openvino-plugins',
}
INPUT_ROLES = {'runtime', 'python', 'devel'}
DIGEST = re.compile(r'[0-9a-f]{64}')
SAFE_FILENAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]*')
# popt parses the rpmsign extra-args macro without quoting, so the path is restricted.
PASSPHRASE_PATH = re.compile(r'/[A-Za-z0-9._/-]+')
SIGN_TIMEOUT = 300
CHILD_HOME = None
FINGERPRINT = re.compile(r'[0-9A-F]{40}')
QUALIFICATION_FIELDS = ['evidence_id', 'evidence_sha256', 'qualified_at', 'hardware_class', 'test_suite_version']
# GnuPG records that carry no trust decision; anything else is refused (mirrors
# crates/stack-install/src/signature.rs verify_signature_status).
NEUTRAL_STATUS = {'KEY_CONSIDERED', 'SIG_ID', 'TRUST_UNDEFINED', 'TRUST_NEVER', 'TRUST_MARGINAL',
                  'TRUST_FULLY', 'TRUST_ULTIMATE'}


class SigningRefused(Exception):
    """A precondition failed; nothing was signed or composed."""


def require(condition, message):
    if not condition:
        raise SigningRefused(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def child_env(gnupghome=None):
    """Minimal child environment: nothing from the caller's environment is inherited."""
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC',
           'HOME': str(CHILD_HOME or tempfile.gettempdir())}
    if gnupghome is not None:
        env['GNUPGHOME'] = str(gnupghome)
    return env


def run(argv, env=None, timeout=900, **kwargs):
    argv = list(map(str, argv))
    try:
        result = subprocess.run(argv, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                                env=child_env() if env is None else env, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired:
        raise SigningRefused('command timed out: ' + ' '.join(argv)) from None
    require(result.returncode == 0,
            'command failed: ' + ' '.join(argv) + '\n' + result.stderr[-2000:])
    return result


def query(rpm, fmt):
    return run(['rpm', '--noplugins', '-qp', '--qf', fmt, str(rpm)]).stdout


def check_passphrase_file(path):
    """Accept only an absolute, safely spelled, owner-only regular file."""
    require(PASSPHRASE_PATH.fullmatch(path) is not None and '..' not in path.split('/'),
            'unsafe passphrase file path: use an absolute path of [A-Za-z0-9._/-]')
    try:
        info = os.lstat(path)
    except OSError:
        raise SigningRefused('passphrase file is missing') from None
    require(stat.S_ISREG(info.st_mode), 'passphrase file must be a regular file')
    require(stat.S_IMODE(info.st_mode) & 0o077 == 0,
            'passphrase file must not be readable by group or others')
    require(info.st_uid == os.geteuid(), 'passphrase file must be owned by the signing user')
    return path


def gpg_batch_args(passphrase_file):
    args = ['--batch', '--no-tty', '--pinentry-mode', 'loopback']
    if passphrase_file:
        args += ['--passphrase-file', passphrase_file]
    return args


def load_key(gpg_home, fingerprint):
    listing = run(['gpg', '--batch', '--with-colons', '--list-secret-keys'],
                  env=child_env(gpg_home)).stdout
    fingerprints = [line.split(':')[9] for line in listing.splitlines()
                    if line.startswith('fpr:')]
    require(fingerprint in fingerprints,
            'the production signing key is not present in the isolated keyring')


def rpmsign_command(path, gnupghome, fingerprint, passphrase_file):
    return ['rpmsign', '--define', '_gpg_path ' + str(gnupghome),
            '--define', '_openpgp_sign_id ' + fingerprint,
            '--define', '_gpg_sign_cmd_extra_args ' + ' '.join(gpg_batch_args(passphrase_file)),
            '--addsign', str(path)]


def payload_digests(rpm):
    """Header and payload digests recorded in the package header.

    unchanged_cpio_sha256 is PAYLOADSHA256ALT, the digest of the uncompressed
    payload as stored in the header; it is not `rpm2cpio | sha256sum`.
    """
    fields = query(rpm, '%{SHA256HEADER} %{PAYLOADSHA256} %{PAYLOADSHA256ALT}').split()
    require(len(fields) == 3 and all(DIGEST.fullmatch(field) for field in fields),
            'package lacks header or payload digests: ' + Path(rpm).name)
    return {'header_sha256': fields[0], 'payload_sha256': fields[1],
            'unchanged_cpio_sha256': fields[2]}


def sign_rpm(path, gnupghome, fingerprint, passphrase_file, dbpath):
    """Sign in place, verify the signature, and prove header and payload are unchanged."""
    before = payload_digests(path)
    run(rpmsign_command(path, gnupghome, fingerprint, passphrase_file),
        env=child_env(gnupghome), timeout=SIGN_TIMEOUT)
    check = run(['rpmkeys', '--dbpath', str(dbpath), '--checksig', '--verbose',
                 str(path)]).stdout
    require(fingerprint.lower() in check.lower()
            and 'Header SHA256 digest: OK' in check
            and 'Payload SHA256 digest: OK' in check,
            'signed RPM failed verification: ' + Path(path).name)
    after = payload_digests(path)
    require(after == before, 'signing changed the package header or payload: ' + Path(path).name)
    return after


def detach_sign(data, output, gnupghome, fingerprint, passphrase_file):
    run(['gpg', *gpg_batch_args(passphrase_file), '--armor', '--detach-sign',
         '--local-user', fingerprint, '--output', str(output), str(data)],
        env=child_env(gnupghome), timeout=SIGN_TIMEOUT)


def check_signature_status(status, expected_primary):
    """Accept exactly one binary detached signature from the pinned primary key.

    Same policy as the installer: one NEWSIG, one GOODSIG whose key id ends the
    VALIDSIG fingerprint, VALIDSIG naming the expected primary key with a v4
    binary-document signature and SHA256/384/512; expiry, revocation, errors
    and unknown records are refused even when VALIDSIG is also present.
    """
    invalid = 'signature does not satisfy the pinned release-key policy'
    require(FINGERPRINT.fullmatch(expected_primary or '') is not None and len(status) <= 65536, invalid)
    starts, good, valid = 0, None, None
    for line in status.splitlines():
        require(line.startswith('[GNUPG:] '), invalid)
        fields = line[len('[GNUPG:] '):].split()
        kind = fields[0] if fields else ''
        if kind == 'NEWSIG':
            starts += 1
        elif kind == 'GOODSIG' and len(fields) >= 3 and good is None:
            require(re.fullmatch(r'[0-9A-F]{16}', fields[1]) is not None, invalid)
            good = fields[1]
        elif kind == 'VALIDSIG' and len(fields) == 11 and valid is None:
            require(FINGERPRINT.fullmatch(fields[1]) is not None and fields[10] == expected_primary
                    and fields[5] == '4' and fields[6] == '0' and fields[8] in {'8', '9', '10'}
                    and fields[9] == '00', invalid)
            valid = fields[1]
        elif kind not in NEUTRAL_STATUS:
            raise SigningRefused(invalid)
    require(starts == 1 and good is not None and valid is not None and valid.endswith(good), invalid)


def verify_detached(signature, data, gnupghome, fingerprint):
    try:
        status = run(['gpg', '--batch', '--status-fd', '1', '--verify', str(signature), str(data)],
                     env=child_env(gnupghome)).stdout
        check_signature_status(status, fingerprint)
    except SigningRefused:
        raise SigningRefused('detached signature did not verify under the release-key policy: '
                             + Path(signature).name) from None


def build_profile_rpm(source, work, profile_bytes):
    spec = source / 'packaging/fedora/44/rpm/intel-npu-stack-profile/' \
        'intel-npu-stack-profile.spec'
    tar_files = {'intel-npu-stack-profile-0.1.0/LICENSE':
                 (source / 'LICENSE').read_bytes(),
                 f'intel-npu-stack-profile-0.1.0/profiles/{PROFILE_ID}.toml': profile_bytes}
    pair = []
    for build in ['build1', 'build2']:
        top = work / ('profile-' + build)
        for leaf in ['BUILD', 'SOURCES', 'SPECS', 'RPMS', 'SRPMS', 'tmp']:
            (top / leaf).mkdir(parents=True, exist_ok=True)
        with tarfile.open(top / 'SOURCES/intel-npu-stack-profile-0.1.0.tar',
                          'w', format=tarfile.GNU_FORMAT) as archive:
            for relative in sorted(tar_files):
                data = tar_files[relative]
                info = tarfile.TarInfo(relative)
                info.size = len(data)
                info.mtime = EPOCH
                info.mode = 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = 'root'
                archive.addfile(info, io.BytesIO(data))
        shutil.copyfile(spec, top / 'SPECS/intel-npu-stack-profile.spec')
        run(['rpmbuild', '-bb', '--nodeps', '--define', '_topdir ' + str(top),
             '--define', '_tmppath ' + str(top / 'tmp'),
             '--define', '_source_date_epoch ' + str(EPOCH),
             '--define', 'use_source_date_epoch_as_buildtime 1',
             '--define', 'clamp_mtime_to_source_date_epoch 1',
             str(top / 'SPECS/intel-npu-stack-profile.spec')])
        produced = sorted((top / 'RPMS').rglob('*.rpm'))
        require(len(produced) == 1, 'profile RPM pair did not produce one artifact')
        pair.append(produced[0])
    builds = [sha(pair[0]), sha(pair[1])]
    require(builds[0] == builds[1], 'profile RPM pair is not reproducible')
    return pair[0], builds


def regular_file(path, root):
    """A regular, non-symlink file whose resolved location stays inside root."""
    path, root = Path(path), Path(root)
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return (stat.S_ISREG(info.st_mode)
            and path.resolve().is_relative_to(root.resolve()))


def safe_relative(value):
    """Canonical relative POSIX path without empty, '.' or '..' parts."""
    if not isinstance(value, str) or not value:
        return False
    relative = PurePosixPath(value)
    return (str(relative) == value and not relative.is_absolute()
            and all(part not in {'', '.', '..'} for part in relative.parts))


def check_rollback(inputs):
    rows = json.loads((inputs / 'rollback-index.json').read_text())
    require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows)
            and len(rows) == len(ROLLBACK_PACKAGES)
            and {row.get('name') for row in rows} == ROLLBACK_PACKAGES
            and len({row.get('filename') for row in rows}) == len(rows),
            'rollback package set is incomplete or duplicated (names and filenames must be unique)')
    for row in rows:
        require(isinstance(row.get('filename'), str) and SAFE_FILENAME.fullmatch(row['filename']) is not None,
                'unsafe rollback filename: ' + str(row.get('filename')))
        origin = inputs / 'rollback-rpms' / row['filename']
        require(regular_file(origin, inputs), 'rollback RPM is not a regular file inside the inputs: '
                + row['filename'])
        require(sha(origin) == row.get('sha256'), 'rollback RPM digest drift: ' + row['filename'])
    return rows


def check_profile(profile, allow_candidate):
    """Production signing requires a qualified profile carrying its qualification record."""
    document = tomllib.loads(Path(profile).read_text())
    status = document.get('status')
    if allow_candidate and status == 'candidate':
        return status
    require(status == 'qualified', 'the selected profile is not qualified; refusing before any key use')
    record = document.get('qualification')
    require(isinstance(record, dict), 'the qualified profile lacks its qualification record')
    for field in QUALIFICATION_FIELDS:
        require(isinstance(record.get(field), str) and record[field].strip(),
                'the qualification record lacks ' + field)
    require(DIGEST.fullmatch(record['evidence_sha256']) is not None,
            'the qualification evidence digest is not a lowercase SHA-256')
    return status


def copy_rollback(inputs, output):
    rows = check_rollback(inputs)
    output.mkdir(parents=True)
    for row in rows:
        shutil.copyfile(inputs / 'rollback-rpms' / row['filename'], output / row['filename'])
    shutil.copyfile(inputs / 'rollback-index.json', output / 'rollback-index.json')


def validate_inputs(inputs, profile, allow_candidate=False):
    """Keyless check of the release inputs contract against the selected profile.

    Everything the signing and assembly steps later consume is checked here, so
    malformed inputs are refused before the production key is imported.
    """
    inputs = Path(inputs)
    for name in ['index.json', 'unsigned-rpms', 'candidate.toml', 'package-index.json',
                 'spdx-index.json', 'source-policy.json', 'notices', 'evidence/spdx',
                 'rollback-index.json', 'rollback-rpms']:
        require((inputs / name).exists(), 'release inputs lack ' + name)
    profile_status = check_profile(profile, allow_candidate)
    require(regular_file(inputs / 'candidate.toml', inputs), 'candidate.toml must be a regular file')
    require((inputs / 'candidate.toml').read_bytes() == Path(profile).read_bytes(),
            'candidate.toml differs from the selected profile')

    rows = json.loads((inputs / 'index.json').read_text())
    require(isinstance(rows, list) and 1 < len(rows) <= 128,
            'unexpected release input package count')
    names, filenames, roles = set(), set(), {}
    for number, row in enumerate(rows):
        require(isinstance(row, dict), f'index.json row {number} is not an object')
        label = f'index.json row {number} ({row.get("name", "unnamed")})'
        for field in ['name', 'filename', 'sha256', 'role']:
            require(isinstance(row.get(field), str) and row[field],
                    f'{label} lacks {field}; every input needs a role in '
                    + ', '.join(sorted(INPUT_ROLES)) if field == 'role' else f'{label} lacks {field}')
        require(row['role'] in INPUT_ROLES, f'{label} has unknown role {row["role"]!r}')
        require(DIGEST.fullmatch(row['sha256']) is not None, f'{label} has an invalid digest')
        require(SAFE_FILENAME.fullmatch(row['filename']) is not None, f'{label} has an unsafe filename')
        require(row['name'] not in names, 'duplicate package name in index.json: ' + row['name'])
        require(row['filename'] not in filenames, 'duplicate filename in index.json: ' + row['filename'])
        names.add(row['name'])
        filenames.add(row['filename'])
        roles[row['role']] = roles.get(row['role'], 0) + 1
        origin = inputs / 'unsigned-rpms' / row['filename']
        require(regular_file(origin, inputs), 'unsigned input is not a regular file inside the inputs: '
                + row['filename'])
        require(sha(origin) == row['sha256'], 'unsigned input digest mismatch: ' + row['filename'])
    runtime = {row['name'] for row in rows if row['role'] == 'runtime'}
    missing = RUNTIME_PACKAGES - runtime
    require(not missing, 'required runtime packages missing or not staged as runtime: '
            + ', '.join(sorted(missing)))
    rollback = check_rollback(inputs)

    spdx = json.loads((inputs / 'spdx-index.json').read_text())
    require(isinstance(spdx, dict) and spdx, 'SPDX index is empty or malformed')
    for key, record in sorted(spdx.items()):
        require(safe_relative(key), 'unsafe SPDX document path: ' + str(key))
        require(isinstance(record, dict) and isinstance(record.get('sha256'), str)
                and DIGEST.fullmatch(record['sha256']) is not None, 'malformed SPDX record: ' + key)
        origin = inputs / 'evidence/spdx' / key
        require(regular_file(origin, inputs) and sha(origin) == record['sha256'],
                'SPDX document digest drift or not a regular file: ' + key)

    package_index = json.loads((inputs / 'package-index.json').read_text())
    require(isinstance(package_index, dict) and package_index, 'package index must be a non-empty object')
    owned = {}
    for name, record in sorted(package_index.items()):
        require(name in runtime, 'package index names a package that is not a runtime input: ' + name)
        require(isinstance(record, dict) and isinstance(record.get('regular_files'), list),
                'package index record lacks regular_files: ' + name)
        for path in record['regular_files']:
            require(isinstance(path, str) and path.startswith('/') and str(PurePosixPath(path)) == path,
                    'noncanonical payload path in the package index: ' + str(path))
            require(path not in owned, 'conflicting payload ownership in the package index: ' + path)
            owned[path] = name

    policy = json.loads((inputs / 'source-policy.json').read_text())
    require(isinstance(policy, list) and all(isinstance(source, dict) for source in policy),
            'source policy must be a list of objects')
    notices = 0
    for source in policy:
        files = source.get('license_files', [])
        require(isinstance(files, list), 'source policy license_files must be a list')
        for license_file in files:
            require(safe_relative(license_file), 'unsafe license notice path: ' + str(license_file))
            require(regular_file(inputs / 'notices' / license_file, inputs),
                    'missing license notice: ' + license_file)
            notices += 1
    return {'passed': True, 'packages': len(rows), 'roles': dict(sorted(roles.items())),
            'runtime_packages': len(runtime), 'rollback_packages': len(rollback),
            'spdx_documents': len(spdx), 'payload_files': len(owned), 'license_notices': notices,
            'profile_status': profile_status, 'candidate_sha256': sha(inputs / 'candidate.toml')}


def main(argv=None):
    global CHILD_HOME
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--profile', type=Path,
                        help='selected profile; candidate.toml must equal it byte for byte')
    parser.add_argument('--check-inputs', action='store_true',
                        help='validate the inputs against --profile without any key and exit')
    parser.add_argument('--allow-candidate', action='store_true',
                        help='with --check-inputs only: accept a candidate profile (staging checks)')
    parser.add_argument('--source', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--work', type=Path)
    parser.add_argument('--fingerprint')
    parser.add_argument('--gpg-home', type=Path)
    parser.add_argument('--passphrase-file',
                        help='owner-only file holding the key passphrase (path only)')
    parser.add_argument('--require-passphrase', action='store_true',
                        help='refuse to sign without --passphrase-file')
    parser.add_argument('--base-url')
    parser.add_argument('--release-version')
    args = parser.parse_args(argv)
    # Never hold the passphrase: a value in the environment is removed and refused.
    passphrase_in_environment = bool(os.environ.pop('RELEASE_SIGNING_PASSPHRASE', ''))
    dbpath = None
    try:
        require(not passphrase_in_environment,
                'RELEASE_SIGNING_PASSPHRASE is set in the environment; pass --passphrase-file')
        if args.check_inputs:
            require(args.profile is not None, '--check-inputs requires --profile')
            print(json.dumps(validate_inputs(args.inputs, args.profile, args.allow_candidate),
                             indent=2, sort_keys=True))
            return 0
        require(not args.allow_candidate, '--allow-candidate is only valid with --check-inputs')
        for name in ['profile', 'source', 'output', 'work', 'fingerprint', 'gpg_home', 'base_url',
                     'release_version']:
            require(getattr(args, name), '--' + name.replace('_', '-') + ' is required for signing')
        passphrase_file = (check_passphrase_file(args.passphrase_file)
                           if args.passphrase_file else None)
        require(passphrase_file or not args.require_passphrase,
                '--require-passphrase needs --passphrase-file')
        inputs = args.inputs.resolve(strict=True)
        source = args.source.resolve(strict=True)
        validate_inputs(inputs, args.profile)
        require(not args.output.exists() or not any(args.output.iterdir()),
                'output must be absent or empty')
        args.output.mkdir(parents=True, exist_ok=True)
        args.work.mkdir(parents=True, exist_ok=True)
        CHILD_HOME = args.work / 'home'
        CHILD_HOME.mkdir(mode=0o700, exist_ok=True)
        gnupghome = args.gpg_home.resolve(strict=True)
        load_key(gnupghome, args.fingerprint)
        dbpath = Path(tempfile.mkdtemp(prefix='release-sign-rpmdb-'))
        public = args.work / 'signing-public.asc'
        with public.open('w') as stream:
            stream.write(run(['gpg', '--batch', '--armor', '--export', args.fingerprint],
                             env=child_env(gnupghome)).stdout)
        run(['rpm', '--dbpath', str(dbpath), '--import', str(public)])

        rows = json.loads((inputs / 'index.json').read_text())
        require(1 < len(rows) <= 128, 'unexpected release input package count')
        repository = args.output / 'repository/packages'
        repository.mkdir(parents=True)
        signed = []
        for row in sorted(rows, key=lambda entry: entry['filename']):
            source_rpm = inputs / 'unsigned-rpms' / row['filename']
            require(regular_file(source_rpm, inputs) and sha(source_rpm) == row['sha256'],
                    'unsigned input digest mismatch: ' + row['filename'])
            require(row.get('role') in INPUT_ROLES, 'input package lacks a valid role: ' + row['filename'])
            target = repository / source_rpm.name
            shutil.copyfile(source_rpm, target)
            digests = sign_rpm(target, gnupghome, args.fingerprint, passphrase_file, dbpath)
            name, nevr, arch = (query(target, '%{NAME}'),
                                query(target, '%{EPOCHNUM}:%{VERSION}-%{RELEASE}'),
                                query(target, '%{ARCH}'))
            require(name == row['name'], 'signed RPM identity changed: ' + row['filename'])
            signed.append({'name': name, 'nevr': nevr, 'arch': arch,
                           'filename': target.name, 'role': row['role'],
                           'unsigned_sha256': row['sha256'], 'signed_sha256': sha(target),
                           **digests})

        identity_path = args.output / 'provider-identity.json'
        identity = {'passed': True, 'test_only': False, 'production_ready': True,
                    'private_key_exported': False,
                    'primary_fingerprint': args.fingerprint, 'packages': signed}
        identity_path.write_text(json.dumps(identity, indent=2, sort_keys=True) + '\n')

        run(['python3', str(source / 'packaging/fedora/44/repository/'
                            'generate-release-profile.py'),
             '--candidate', str(inputs / 'candidate.toml'),
             '--identity', str(identity_path),
             '--output', str(args.output / 'release-profile.toml'),
             '--record', str(args.output / 'profile-generation.json')])
        profile_bytes = (args.output / 'release-profile.toml').read_bytes()

        profile_rpm, profile_builds = build_profile_rpm(source, args.work, profile_bytes)
        target = repository / profile_rpm.name
        shutil.copyfile(profile_rpm, target)
        digests = sign_rpm(target, gnupghome, args.fingerprint, passphrase_file, dbpath)
        signed.append({'name': query(target, '%{NAME}'),
                       'nevr': query(target, '%{EPOCHNUM}:%{VERSION}-%{RELEASE}'),
                       'arch': query(target, '%{ARCH}'),
                       'filename': target.name, 'role': 'profile',
                       'unsigned_sha256': sha(profile_rpm),
                       'signed_sha256': sha(target), **digests})
        identity['packages'] = sorted(signed, key=lambda entry: entry['name'])

        run(['createrepo_c', str(repository.parent)])
        repomd = repository.parent / 'repodata/repomd.xml'
        detach_sign(repomd, str(repomd) + '.asc', gnupghome, args.fingerprint, passphrase_file)
        verify_detached(str(repomd) + '.asc', repomd, gnupghome, args.fingerprint)
        identity['repomd_sha256'] = sha(repomd)
        (args.output / 'signed-identity.json').write_text(
            json.dumps(identity, indent=2, sort_keys=True) + '\n')
        (args.output / 'profile-rpm-build.json').write_text(json.dumps({
            'profile_filename': target.name,
            'source_profile_sha256': hashlib.sha256(profile_bytes).hexdigest(),
            'unsigned_sha256': sha(profile_rpm),
            'signed_sha256': sha(target),
            'installed_profile_path':
                f'/usr/share/intel-npu-stack/profiles/{PROFILE_ID}.toml',
            'builds': profile_builds,
            'reproducible': True}, indent=2, sort_keys=True) + '\n')

        assembly = args.work / 'assembly-input'
        (assembly / 'repository/packages').mkdir(parents=True)
        (assembly / 'repository/repodata').mkdir(parents=True)
        for path in sorted(repository.iterdir()):
            shutil.copyfile(path, assembly / 'repository/packages' / path.name)
        for path in sorted((repository.parent / 'repodata').iterdir()):
            shutil.copyfile(path, assembly / 'repository/repodata' / path.name)
        shutil.copyfile(args.output / 'release-profile.toml', assembly / 'profile.toml')
        shutil.copyfile(args.output / 'signed-identity.json', assembly / 'signed-identity.json')
        shutil.copyfile(args.output / 'profile-rpm-build.json',
                        assembly / 'profile-rpm-build.json')
        (assembly / 'aggregate').mkdir(parents=True)
        for name in ['package-index.json', 'spdx-index.json', 'source-policy.json']:
            shutil.copyfile(inputs / name, assembly / 'aggregate' / name)
        spdx_index = json.loads((inputs / 'spdx-index.json').read_text())
        for key, record in sorted(spdx_index.items()):
            origin = inputs / 'evidence/spdx' / key
            require(regular_file(origin, inputs) and sha(origin) == record['sha256'],
                    'SPDX document digest drift: ' + key)
            destination = assembly / 'evidence/spdx' / key
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(origin, destination)
        shutil.copytree(inputs / 'notices', assembly / 'evidence/notices')
        copy_rollback(inputs, assembly / 'evidence/rollback')

        assemble = source / 'packaging/fedora/44/repository/assemble.py'
        (assembly / 'release-metadata.sig').write_bytes(
            b'-----BEGIN PGP SIGNATURE-----\nplaceholder\n')
        first = args.output / 'release-tree-pass1'
        run(['python3', str(assemble), '--input-root', str(assembly),
             '--output', str(first), '--base-url', args.base_url,
             '--repository-id', 'intel-npu-stack-' + args.release_version,
             '--release-version', args.release_version, '--production'])
        signature = args.output / 'release-metadata.sig'
        detach_sign(first / 'release.json', signature, gnupghome, args.fingerprint, passphrase_file)
        verify_detached(signature, first / 'release.json', gnupghome, args.fingerprint)
        shutil.copyfile(signature, assembly / 'release-metadata.sig')
        final_tree = args.output / 'release-tree'
        run(['python3', str(assemble), '--input-root', str(assembly),
             '--output', str(final_tree), '--base-url', args.base_url,
             '--repository-id', 'intel-npu-stack-' + args.release_version,
             '--release-version', args.release_version, '--production'])
        require((final_tree / 'release.json').read_bytes()
                == (first / 'release.json').read_bytes(),
                'release metadata changed between assembly passes')
        verify_detached(final_tree / 'release.json.sig', final_tree / 'release.json',
                        gnupghome, args.fingerprint)

        detach_sign(final_tree / 'checksums.sha256', final_tree / 'checksums.sha256.sig',
                    gnupghome, args.fingerprint, passphrase_file)
        verify_detached(final_tree / 'checksums.sha256.sig', final_tree / 'checksums.sha256',
                        gnupghome, args.fingerprint)
        result = {
            'passed': True, 'test_only': False, 'release_ready': False,
            'scope': 'production release signing and deterministic composition from '
                     'accepted inputs; publication, VM and hardware gates remain separate',
            'primary_fingerprint': args.fingerprint,
            'repomd_sha256': identity['repomd_sha256'],
            'release_tree': str(final_tree),
            'package_count': len(identity['packages']),
            'release_json_sha256': sha(final_tree / 'release.json'),
            'release_signature_sha256': sha(final_tree / 'release.json.sig'),
        }
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
    except (SigningRefused, KeyError, OSError, ValueError, TypeError, AttributeError,
            tomllib.TOMLDecodeError) as error:
        parser.exit(1, 'Release signing refused: ' + str(error) + '\n')
    finally:
        if dbpath is not None:
            shutil.rmtree(dbpath, ignore_errors=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
