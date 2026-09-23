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
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

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


def verify_detached(signature, data, gnupghome, fingerprint):
    try:
        status = run(['gpg', '--batch', '--status-fd', '1', '--verify', str(signature), str(data)],
                     env=child_env(gnupghome)).stdout
    except SigningRefused:
        status = ''
    require('[GNUPG:] VALIDSIG ' + fingerprint + ' ' in status,
            'detached signature did not verify: ' + Path(signature).name)


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


def check_rollback(inputs):
    rows = json.loads((inputs / 'rollback-index.json').read_text())
    require(isinstance(rows, list) and len(rows) == len(ROLLBACK_PACKAGES)
            and {row['name'] for row in rows} == ROLLBACK_PACKAGES,
            'rollback package set is incomplete or duplicated')
    for row in rows:
        require(SAFE_FILENAME.fullmatch(row['filename']) is not None,
                'unsafe rollback filename: ' + row['filename'])
        origin = inputs / 'rollback-rpms' / row['filename']
        require(origin.is_file() and sha(origin) == row['sha256'],
                'rollback RPM digest drift: ' + row['filename'])
    return rows


def copy_rollback(inputs, output):
    rows = check_rollback(inputs)
    output.mkdir(parents=True)
    for row in rows:
        shutil.copyfile(inputs / 'rollback-rpms' / row['filename'], output / row['filename'])
    shutil.copyfile(inputs / 'rollback-index.json', output / 'rollback-index.json')


def validate_inputs(inputs, profile):
    """Keyless check of the release inputs contract against the selected profile."""
    inputs = Path(inputs)
    for name in ['index.json', 'unsigned-rpms', 'candidate.toml', 'package-index.json',
                 'spdx-index.json', 'source-policy.json', 'notices', 'evidence/spdx',
                 'rollback-index.json', 'rollback-rpms']:
        require((inputs / name).exists(), 'release inputs lack ' + name)
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
        require(origin.is_file() and sha(origin) == row['sha256'],
                'unsigned input digest mismatch: ' + row['filename'])
    runtime = {row['name'] for row in rows if row['role'] == 'runtime'}
    missing = RUNTIME_PACKAGES - runtime
    require(not missing, 'required runtime packages missing or not staged as runtime: '
            + ', '.join(sorted(missing)))
    require((inputs / 'candidate.toml').read_bytes() == Path(profile).read_bytes(),
            'candidate.toml differs from the selected profile')
    rollback = check_rollback(inputs)
    spdx = json.loads((inputs / 'spdx-index.json').read_text())
    require(isinstance(spdx, dict) and spdx, 'SPDX index is empty or malformed')
    for key, record in sorted(spdx.items()):
        parts = Path(key).parts
        require(not Path(key).is_absolute() and '..' not in parts and parts,
                'unsafe SPDX document path: ' + key)
        origin = inputs / 'evidence/spdx' / key
        require(origin.is_file() and sha(origin) == record.get('sha256'),
                'SPDX document digest drift: ' + key)
    require(isinstance(json.loads((inputs / 'package-index.json').read_text()), dict),
            'package index is malformed')
    json.loads((inputs / 'source-policy.json').read_text())
    return {'passed': True, 'packages': len(rows), 'roles': dict(sorted(roles.items())),
            'runtime_packages': len(runtime), 'rollback_packages': len(rollback),
            'spdx_documents': len(spdx), 'candidate_sha256': sha(inputs / 'candidate.toml')}


def main(argv=None):
    global CHILD_HOME
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--profile', type=Path,
                        help='selected profile; candidate.toml must equal it byte for byte')
    parser.add_argument('--check-inputs', action='store_true',
                        help='validate the inputs against --profile without any key and exit')
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
            print(json.dumps(validate_inputs(args.inputs, args.profile), indent=2, sort_keys=True))
            return 0
        for name in ['source', 'output', 'work', 'fingerprint', 'gpg_home', 'base_url',
                     'release_version']:
            require(getattr(args, name), '--' + name.replace('_', '-') + ' is required for signing')
        passphrase_file = (check_passphrase_file(args.passphrase_file)
                           if args.passphrase_file else None)
        require(passphrase_file or not args.require_passphrase,
                '--require-passphrase needs --passphrase-file')
        inputs = args.inputs.resolve(strict=True)
        source = args.source.resolve(strict=True)
        if args.profile is not None:
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
            require(source_rpm.is_file() and sha(source_rpm) == row['sha256'],
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
            require(origin.is_file() and sha(origin) == record['sha256'],
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
    except (SigningRefused, KeyError, OSError, ValueError) as error:
        parser.exit(1, 'Release signing refused: ' + str(error) + '\n')
    finally:
        if dbpath is not None:
            shutil.rmtree(dbpath, ignore_errors=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
