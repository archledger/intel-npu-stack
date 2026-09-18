#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Sign and assemble a production release tree from prepared release inputs.

Runs in the protected release environment only. Consumes previously built
unsigned RPMs, the aggregate evidence inputs and the retained rollback RPMs,
signs every RPM and the profile RPM with the production key from the
environment, signs the repository and detached release metadata, composes
the release twice with --production, builds the pinned-trust installer pair,
and emits the signed release tree. Performs no publication and no build of
the provider packages.

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
import shutil
import subprocess
import sys
import tarfile

EPOCH = 1789084800
PROFILE_ID = 'fedora-44-lunar-lake-x86_64'


class SigningRefused(Exception):
    """A precondition failed; nothing was signed or composed."""


def require(condition, message):
    if not condition:
        raise SigningRefused(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(argv, **kwargs):
    result = subprocess.run(list(map(str, argv)), capture_output=True, text=True, **kwargs)
    require(result.returncode == 0,
            'command failed: ' + ' '.join(map(str, argv)) + '\n' + result.stderr[-2000:])
    return result


def query(rpm, fmt):
    return run(['rpm', '--noplugins', '-qp', '--qf', fmt, str(rpm)]).stdout


def load_key(gpg_home, fingerprint):
    env = {**os.environ, 'GNUPGHOME': str(gpg_home)}
    listing = run(['gpg', '--batch', '--with-colons', '--list-secret-keys'], env=env).stdout
    fingerprints = [line.split(':')[9] for line in listing.splitlines()
                    if line.startswith('fpr:')]
    require(fingerprint in fingerprints,
            'the production signing key is not present in the isolated keyring')
    return env


def sign_rpm(path, env, fingerprint, passphrase, dbpath):
    command = ['rpmsign', '--define', '_gpg_path ' + str(env['GNUPGHOME']),
               '--define', '_openpgp_sign_id ' + fingerprint]
    if passphrase:
        command += ['--define', '_gpg_passphrase ' + passphrase]
    command += ['--addsign', str(path)]
    run(command, env=env)
    check = run(['rpmkeys', '--dbpath', str(dbpath), '--checksig', '--verbose',
                 str(path)]).stdout
    require(fingerprint.lower() in check.lower()
            and 'Header SHA256 digest: OK' in check
            and 'Payload SHA256 digest: OK' in check,
            'signed RPM failed verification: ' + path.name)


def build_profile_rpm(source, inputs, work, env, fingerprint, passphrase, profile_bytes):
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
    require(sha(pair[0]) == sha(pair[1]), 'profile RPM pair is not reproducible')
    return pair[0]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--fingerprint', required=True)
    parser.add_argument('--gpg-home', required=True, type=Path)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--release-version', required=True)
    args = parser.parse_args(argv)
    try:
        passphrase = os.environ.get('RELEASE_SIGNING_PASSPHRASE', '')
        env = load_key(args.gpg_home, args.fingerprint)
        import tempfile
        dbpath = Path(tempfile.mkdtemp(prefix='release-sign-rpmdb-'))
        public = args.work / 'signing-public.asc'
        with public.open('w') as stream:
            stream.write(run(['gpg', '--batch', '--armor', '--export', args.fingerprint],
                             env=env).stdout)
        run(['rpm', '--dbpath', str(dbpath), '--import', str(public)])
        inputs = args.inputs.resolve(strict=True)
        source = args.source.resolve(strict=True)
        require(not args.output.exists() or not any(args.output.iterdir()),
                'output must be absent or empty')
        args.output.mkdir(parents=True, exist_ok=True)
        args.work.mkdir(parents=True, exist_ok=True)

        rows = json.loads((inputs / 'index.json').read_text())
        require(1 < len(rows) <= 128, 'unexpected release input package count')
        repository = args.output / 'repository/packages'
        repository.mkdir(parents=True)
        signed = []
        for row in sorted(rows, key=lambda entry: entry['filename']):
            source_rpm = inputs / 'unsigned-rpms' / row['filename']
            require(source_rpm.is_file() and sha(source_rpm) == row['sha256'],
                    'unsigned input digest mismatch: ' + row['filename'])
            target = repository / source_rpm.name
            shutil.copyfile(source_rpm, target)
            sign_rpm(target, env, args.fingerprint, passphrase, dbpath)
            name, nevr, arch = (query(target, '%{NAME}'),
                                query(target, '%{EPOCHNUM}:%{VERSION}-%{RELEASE}'),
                                query(target, '%{ARCH}'))
            require(name == row['name'], 'signed RPM identity changed: ' + row['filename'])
            signed.append({'name': name, 'nevr': nevr, 'arch': arch,
                           'filename': target.name, 'role': row['role'],
                           'unsigned_sha256': row['sha256'], 'signed_sha256': sha(target),
                           'unchanged_cpio_sha256': row['sha256']})

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

        profile_rpm = build_profile_rpm(source, inputs, args.work, env,
                                        args.fingerprint, passphrase, profile_bytes)
        target = repository / profile_rpm.name
        shutil.copyfile(profile_rpm, target)
        sign_rpm(target, env, args.fingerprint, passphrase, dbpath)
        signed.append({'name': query(target, '%{NAME}'),
                       'nevr': query(target, '%{EPOCHNUM}:%{VERSION}-%{RELEASE}'),
                       'arch': query(target, '%{ARCH}'),
                       'filename': target.name, 'role': 'profile',
                       'unsigned_sha256': sha(profile_rpm),
                       'signed_sha256': sha(target),
                       'unchanged_cpio_sha256': sha(profile_rpm)})
        identity['packages'] = sorted(signed, key=lambda entry: entry['name'])

        run(['createrepo_c', str(repository.parent)])
        repomd = repository.parent / 'repodata/repomd.xml'
        run(['gpg', '--batch', '--pinentry-mode', 'loopback',
             '--passphrase', passphrase, '--armor', '--detach-sign',
             '--local-user', args.fingerprint,
             '--output', str(repomd) + '.asc', str(repomd)], env=env)
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
            'builds': [sha(profile_rpm), sha(profile_rpm)],
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
        rollback = assembly / 'evidence/rollback'
        rollback.mkdir(parents=True)
        rollback_index = json.loads((inputs / 'rollback-index.json').read_text())
        require(len(rollback_index) == 11, 'rollback index is incomplete')
        for row in rollback_index:
            origin = inputs / 'rollback-rpms' / row['filename']
            require(origin.is_file() and sha(origin) == row['sha256'],
                    'rollback RPM digest drift: ' + row['filename'])
            shutil.copyfile(origin, rollback / row['filename'])
        shutil.copyfile(inputs / 'rollback-index.json', rollback / 'rollback-index.json')

        assemble = source / 'packaging/fedora/44/repository/assemble.py'
        (assembly / 'release-metadata.sig').write_bytes(
            b'-----BEGIN PGP SIGNATURE-----\nplaceholder\n')
        first = args.output / 'release-tree-pass1'
        run(['python3', str(assemble), '--input-root', str(assembly),
             '--output', str(first), '--base-url', args.base_url,
             '--repository-id', 'intel-npu-stack-' + args.release_version,
             '--release-version', args.release_version, '--production'])
        signature = args.output / 'release-metadata.sig'
        run(['gpg', '--batch', '--pinentry-mode', 'loopback',
             '--passphrase', passphrase, '--armor', '--detach-sign',
             '--local-user', args.fingerprint,
             '--output', str(signature), str(first / 'release.json')], env=env)
        verify = run(['gpg', '--batch', '--status-fd', '1', '--verify',
                      str(signature), str(first / 'release.json')], env=env).stdout
        require('[GNUPG:] VALIDSIG ' + args.fingerprint + ' ' in verify,
                'release metadata signature did not verify')
        shutil.copyfile(signature, assembly / 'release-metadata.sig')
        final_tree = args.output / 'release-tree'
        run(['python3', str(assemble), '--input-root', str(assembly),
             '--output', str(final_tree), '--base-url', args.base_url,
             '--repository-id', 'intel-npu-stack-' + args.release_version,
             '--release-version', args.release_version, '--production'])
        require((final_tree / 'release.json').read_bytes()
                == (first / 'release.json').read_bytes(),
                'release metadata changed between assembly passes')
        verify = run(['gpg', '--batch', '--status-fd', '1', '--verify',
                      str(final_tree / 'release.json.sig'),
                      str(final_tree / 'release.json')], env=env).stdout
        require('[GNUPG:] VALIDSIG ' + args.fingerprint + ' ' in verify,
                'final release metadata signature did not verify')

        run(['gpg', '--batch', '--pinentry-mode', 'loopback',
             '--passphrase', passphrase, '--armor', '--detach-sign',
             '--local-user', args.fingerprint,
             '--output', str(final_tree / 'checksums.sha256.sig'),
             str(final_tree / 'checksums.sha256')], env=env)
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
    except (SigningRefused, KeyError, OSError) as error:
        parser.exit(1, 'Release signing refused: ' + str(error) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
