#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the pinned installer and render the bootstrap pair for a signed release.

  release_installer.py build --repo DIR --source-commit SHA --release-tree DIR --leg a|b --output DIR
                             [--src-root DIR] [--target-dir DIR]
  release_installer.py pin-source --repo DIR --source-commit SHA --release-tree DIR --src-root DIR

The repository must be clean at --source-commit. release.json.sig must verify
under the committed release key, and release.json must name this version and
base URL in production mode. The source is exported with `git archive` into a
fixed path, trust.rs is pinned with the SHA-256 of release.json (and nothing
else changes), and the installer is built with the locked, offline toolchain.
Two legs built on separate runners must produce identical bytes; the caller
compares them. pin-source only writes the pinned tree (used by the rehearsal
to build test harnesses against identical trust). Outputs are never
overwritten.
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
import tempfile

import release_sign
import release_trust

BINARY = 'intel-npu-stack-install'
DEFAULT_SRC = Path('/opt/intel-npu-stack-src')
DEFAULT_TARGET = Path('/opt/intel-npu-stack-target')
MAX_BUILD_JOBS = 4  # the project's local build budget (AGENTS.md)


class InstallerRefused(Exception):
    """A precondition failed; no installer output was produced."""


def require(condition, message):
    if not condition:
        raise InstallerRefused(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def minimal_env(extra=None):
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'HOME': tempfile.gettempdir()}
    env.update(extra or {})
    return env


def build_jobs(environ):
    """Cargo job count: the caller's value when it is 1 to MAX_BUILD_JOBS, otherwise refused; 4 when unset."""
    jobs = environ.get('CARGO_BUILD_JOBS', str(MAX_BUILD_JOBS))
    require(jobs in {str(count) for count in range(1, MAX_BUILD_JOBS + 1)},
            f'CARGO_BUILD_JOBS must be 1 to {MAX_BUILD_JOBS}, found {jobs!r}')
    return jobs


def current_umask():
    mask = os.umask(0)
    os.umask(mask)
    return mask


def toolchain_env(target_dir, src_root, environ=None):
    """Minimal build environment using the real cargo/rustc of the repository's pinned toolchain.

    rustup proxies need the caller's HOME and read rust-toolchain.toml from the working
    directory, so the sysroot is resolved once inside the exported source and its bin
    directory (the real tools) leads a minimal PATH. CARGO_HOME stays fixed and absolute
    because registry paths reach the binary; both legs must use the same one.
    """
    environ = dict(os.environ if environ is None else environ)
    rustc = shutil.which('rustc', path=environ.get('PATH', ''))
    require(rustc is not None, 'rustc is not on PATH')
    query = subprocess.run([rustc, '--print', 'sysroot'], cwd=src_root, env=environ, capture_output=True,
                           text=True, check=False, timeout=600)
    sysroot = Path(query.stdout.strip())
    require(query.returncode == 0 and sysroot.is_absolute() and (sysroot / 'bin/cargo').is_file()
            and (sysroot / 'bin/rustc').is_file(), 'cannot resolve the pinned Rust toolchain sysroot')
    cargo_home = environ.get('CARGO_HOME') or str(Path(environ.get('HOME', '/nonexistent')) / '.cargo')
    require(Path(cargo_home).is_absolute(), 'CARGO_HOME must be absolute')
    return minimal_env({'CARGO_TARGET_DIR': str(target_dir), 'CARGO_HOME': cargo_home,
                        'CARGO_BUILD_JOBS': build_jobs(environ), 'PATH': str(sysroot / 'bin') + ':/usr/bin:/bin'})


def run_cargo(argv, cwd, env):
    """Default runner: the real toolchain, inheriting only PATH/CARGO_HOME/RUSTUP_HOME style settings."""
    return subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, check=False,
                          stdin=subprocess.DEVNULL, timeout=3600)


def git(repo, *args):
    result = subprocess.run(['git', '-C', str(repo), *args], capture_output=True, check=False,
                            env=minimal_env({'GIT_CONFIG_NOSYSTEM': '1'}))
    require(result.returncode == 0, 'git ' + ' '.join(args) + ' failed')
    return result.stdout


def signature_accepted(returncode, status, primary):
    """The installer's strict GnuPG status policy (release_sign.check_signature_status)."""
    try:
        release_sign.check_signature_status(status, primary)
    except release_sign.SigningRefused:
        return False
    return returncode == 0


def verify_release(repo, release_tree, values):
    """VALIDSIG under the committed key, then the release fields must match the trust seam."""
    data, signature = Path(release_tree) / 'release.json', Path(release_tree) / 'release.json.sig'
    require(data.is_file() and signature.is_file(), 'release tree lacks release.json or its signature')
    with tempfile.TemporaryDirectory(prefix='installer-gnupg-') as home:
        env = minimal_env({'GNUPGHOME': home})
        imported = subprocess.run(['gpg', '--batch', '--import', str(Path(repo) / release_trust.KEY_PATH)],
                                  env=env, capture_output=True, check=False)
        require(imported.returncode == 0, 'the committed release key could not be imported')
        verified = subprocess.run(['gpg', '--batch', '--status-fd', '1', '--verify', str(signature), str(data)],
                                  env=env, capture_output=True, text=True, check=False)
    require(signature_accepted(verified.returncode, verified.stdout, values['primary_fingerprint']),
            'release.json signature does not satisfy the pinned release-key policy')
    document = json.loads(data.read_text())
    require(document.get('stack_release') == values['version'], 'release.json stack_release mismatch')
    require(document.get('repository', {}).get('base_url') == values['base_url'],
            'release.json base_url does not equal the committed BASE_URL')
    require(document.get('test_only') is False, 'release.json is test_only; refusing to pin it')
    return sha(data)


def export_pinned_source(repo, commit, metadata_digest, src_root):
    src_root = Path(src_root)
    require(not src_root.exists(), f'{src_root} already exists')
    archive = git(repo, 'archive', '--format=tar', commit)
    src_root.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as tar:
        tar.extractall(src_root, filter='data')
    trust_file = src_root / release_trust.TRUST_PATH
    trust_file.write_text(release_trust.pin_metadata(trust_file.read_text(), metadata_digest))
    return trust_file


def prepare(repo, commit, release_tree):
    repo = Path(repo)
    head = git(repo, 'rev-parse', 'HEAD').decode().strip()
    require(head == commit, f'repository HEAD {head} is not the requested source commit')
    require(git(repo, 'status', '--porcelain', '--untracked-files=all') == b'',
            'the repository working tree must be clean')
    values = release_trust.check_committed(repo)
    return values, verify_release(repo, release_tree, values)


def pin_source(repo, commit, release_tree, src_root):
    _, metadata_digest = prepare(repo, commit, release_tree)
    return export_pinned_source(repo, commit, metadata_digest, src_root)


def renderer(repo):
    return release_trust.load_module('release_renderer', Path(repo) / 'install/render-bootstrap.py')


def write_new(path, data, mode=0o644):
    with open(path, 'xb') as stream:
        stream.write(data if isinstance(data, bytes) else data.encode())
    os.chmod(path, mode)


def build(repo, commit, release_tree, output, leg, src_root=DEFAULT_SRC, target_dir=DEFAULT_TARGET,
          runner=run_cargo, environ=None):
    require(leg in {'a', 'b'}, 'leg must be a or b')
    environ = dict(os.environ if environ is None else environ)
    jobs = build_jobs(environ)
    output, target_dir = Path(output), Path(target_dir)
    require(not output.exists(), f'{output} already exists; outputs are never overwritten')
    require(not target_dir.exists(), f'{target_dir} already exists')
    values, metadata_digest = prepare(repo, commit, release_tree)
    trust_file = export_pinned_source(repo, commit, metadata_digest, src_root)
    if runner is run_cargo:
        env = toolchain_env(target_dir, src_root, environ)
    else:  # injected runners (tests) do not execute a real toolchain
        env = minimal_env({'CARGO_TARGET_DIR': str(target_dir), 'CARGO_BUILD_JOBS': jobs})
    for argv in (['cargo', 'fetch', '--locked'],
                 ['cargo', 'build', '--release', '--locked', '--offline', '-p', 'stack-install', '--bin', BINARY]):
        result = runner(argv, Path(src_root), env)
        require(result.returncode == 0, ' '.join(argv) + ' failed:\n' + (result.stderr or '')[-2000:])
    binary = target_dir / 'release' / BINARY
    require(binary.is_file(), 'the build produced no installer binary')
    content = binary.read_bytes()
    require(content[:4] == b'\x7fELF', 'the installer is not an ELF executable')
    for literal in (metadata_digest, values['base_url'], values['primary_fingerprint']):
        require(literal.encode() in content, 'the installer lacks a pinned trust value: ' + literal)
    version = runner([str(binary), '--version'], Path(src_root), env)
    require(version.returncode == 0 and version.stdout.strip() == f'{BINARY} {values["version"]}',
            'unexpected installer version output: ' + (version.stdout or '').strip())
    toolchain = {name: runner([name, *flag], Path(src_root), env).stdout.strip()
                 for name, flag in [('rustc', ['-vV']), ('cargo', ['-V'])]}

    render = renderer(repo)
    binary_sha = hashlib.sha256(content).hexdigest()
    bootstrap = render.render_bootstrap(values['version'], values['base_url'] + BINARY, binary_sha)
    bootstrap_sha = hashlib.sha256(bootstrap.encode()).hexdigest()
    primary = render.render_install_command(values['version'], values['base_url'] + 'install.sh', bootstrap_sha)

    output.mkdir(parents=True)
    write_new(output / BINARY, content, 0o755)
    write_new(output / 'install.sh', bootstrap, 0o755)
    write_new(output / 'primary-command.txt', primary)
    write_new(output / 'installer-trust.rs', trust_file.read_bytes())
    for script in ['install.sh', 'primary-command.txt']:
        checked = subprocess.run(['sh', '-n', str(output / script)], capture_output=True, check=False)
        require(checked.returncode == 0, script + ' is not valid shell')
    record = {
        'leg': leg, 'source_commit': commit, 'version': values['version'], 'base_url': values['base_url'],
        'primary_fingerprint': values['primary_fingerprint'], 'release_json_sha256': metadata_digest,
        'pinned_trust_sha256': sha(trust_file), 'binary_sha256': binary_sha, 'install_sh_sha256': bootstrap_sha,
        'primary_command_sha256': sha(output / 'primary-command.txt'), 'src_root': str(src_root),
        'target_dir': str(target_dir), 'toolchain': toolchain,
        # Every variable the toolchain saw; the caller's TZ and LANG never reach it.
        'build_environment': dict(sorted(env.items())),
        'caller_environment': {name: environ.get(name) for name in ['TZ', 'LANG', 'IMAGE_DIGEST']},
        'umask': oct(current_umask()),
    }
    write_new(output / 'installer-build.json', json.dumps(record, indent=2, sort_keys=True) + '\n')
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=['build', 'pin-source'])
    parser.add_argument('--repo', type=Path, default=Path('.'))
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--release-tree', type=Path, required=True)
    parser.add_argument('--leg', choices=['a', 'b'])
    parser.add_argument('--output', type=Path)
    parser.add_argument('--src-root', type=Path, default=DEFAULT_SRC)
    parser.add_argument('--target-dir', type=Path, default=DEFAULT_TARGET)
    args = parser.parse_args(argv)
    try:
        if args.command == 'pin-source':
            print(pin_source(args.repo, args.source_commit, args.release_tree, args.src_root))
            return 0
        if args.leg is None or args.output is None:
            parser.error('build requires --leg and --output')
        print(json.dumps(build(args.repo, args.source_commit, args.release_tree, args.output, args.leg,
                               args.src_root, args.target_dir), indent=2, sort_keys=True))
    except (InstallerRefused, release_trust.TrustRefused, OSError, ValueError, KeyError) as error:
        parser.exit(1, 'installer build refused: ' + str(error) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
