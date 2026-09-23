#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Contract for building the pinned installer and rendering the bootstrap pair."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import release_installer as installer
import release_trust as trust

REPO = Path(__file__).resolve().parents[2]
BASE_URL = 'https://archledger.github.io/intel-npu-stack/0.1.0/'
TOOLS = shutil.which('gpg') and shutil.which('gpgconf') and shutil.which('git')


def git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True, text=True,
                          env={'PATH': '/usr/bin:/bin', 'HOME': str(repo), 'GIT_AUTHOR_NAME': 't',
                               'GIT_AUTHOR_EMAIL': 't@example.invalid', 'GIT_COMMITTER_NAME': 't',
                               'GIT_COMMITTER_EMAIL': 't@example.invalid'}).stdout.strip()


def elf_header(machine=62):
    """A 64-bit little-endian ELF executable header for the given e_machine (62 is x86_64)."""
    return (b'\x7fELF\x02\x01\x01' + b'\0' * 9 + (2).to_bytes(2, 'little') + machine.to_bytes(2, 'little')
            + b'\0' * 44)


class FakeCargo:
    """Stands in for cargo/rustc: "builds" a binary from the pinned trust.rs it finds."""

    def __init__(self, embed=True, version='intel-npu-stack-install 0.1.0', machine=62, toolchain_exit=0):
        self.embed, self.version, self.machine, self.calls = embed, version, machine, []
        self.toolchain_exit = toolchain_exit

    def __call__(self, argv, cwd, env):
        self.calls.append((list(argv), str(cwd), dict(env)))
        if argv[0] == 'cargo' and argv[1] == 'build':
            values = trust.parse_trust((Path(cwd) / 'crates/stack-install/src/trust.rs').read_text())
            body = elf_header(self.machine)
            if self.embed:
                body += '\n'.join([values['metadata_sha256'], values['base_url'],
                                   values['primary_fingerprint']]).encode()
            target = argv[argv.index('--target') + 1] if '--target' in argv else None
            # Like cargo, a relative CARGO_TARGET_DIR is taken from the build's working directory.
            binary = Path(cwd) / env['CARGO_TARGET_DIR'] / (target or '') / 'release/intel-npu-stack-install'
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(body)
            return subprocess.CompletedProcess(argv, 0, '', '')
        if argv[:2] == ['cargo', 'fetch']:
            return subprocess.CompletedProcess(argv, 0, '', '')
        if argv[-1] == '--version':
            return subprocess.CompletedProcess(argv, 0, self.version + '\n', '')
        return subprocess.CompletedProcess(argv, self.toolchain_exit,
                                           '' if self.toolchain_exit else argv[0] + ' 1.85.0 (fake)\n', '')


class ToolchainEnvironment(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='rt-', dir='/tmp'))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.sysroot = self.root / 'toolchains/1.85.0'
        (self.sysroot / 'bin').mkdir(parents=True)
        (self.sysroot / 'bin/cargo').write_text('#!/bin/sh\n')
        self.fake_rustc(self.sysroot, '1.85.0')
        proxies = self.root / 'proxies'
        proxies.mkdir()
        # A rustup-like proxy that reports the pinned toolchain only inside the source tree.
        (proxies / 'rustc').write_text('#!/bin/sh\n[ -f rust-toolchain.toml ] || exit 3\nprintf "%s\\n" "' + str(self.sysroot) + '"\n')
        (proxies / 'rustc').chmod(0o755)
        self.src = self.root / 'src'
        self.src.mkdir()
        (self.src / 'rust-toolchain.toml').write_text('[toolchain]\nchannel = "1.85.0"\n')
        self.environ = {'PATH': str(proxies) + ':/usr/bin:/bin', 'HOME': str(self.root / 'home'),
                        'CARGO_BUILD_JOBS': '1', 'SECRET_FROM_CALLER': 'x'}

    @staticmethod
    def fake_rustc(sysroot, version):
        rustc = sysroot / 'bin/rustc'
        rustc.write_text('#!/bin/sh\n[ "$1" = -V ] && printf "rustc ' + version + ' (0000000 2025-02-17)\\n"\n')
        rustc.chmod(0o755)

    def test_real_toolchain_bin_leads_a_minimal_path(self):
        env = installer.toolchain_env(self.root / 'target', self.src, self.environ)
        self.assertEqual(env['PATH'], str(self.sysroot / 'bin') + ':/usr/bin:/bin')
        self.assertEqual(env['CARGO_HOME'], str(self.root / 'home/.cargo'))
        self.assertEqual(env['CARGO_BUILD_JOBS'], '1')
        self.assertEqual(env['CARGO_TARGET_DIR'], str(self.root / 'target'))
        self.assertNotIn('SECRET_FROM_CALLER', env)

    def test_explicit_cargo_home_is_kept_and_must_be_absolute(self):
        env = installer.toolchain_env(self.root / 't', self.src, {**self.environ, 'CARGO_HOME': '/opt/ci-cargo'})
        self.assertEqual(env['CARGO_HOME'], '/opt/ci-cargo')
        with self.assertRaisesRegex(installer.InstallerRefused, 'absolute'):
            installer.toolchain_env(self.root / 't', self.src, {**self.environ, 'CARGO_HOME': 'relative'})

    def test_build_jobs_default_to_four_and_never_exceed_it(self):
        environ = {name: value for name, value in self.environ.items() if name != 'CARGO_BUILD_JOBS'}
        self.assertEqual(installer.toolchain_env(self.root / 't', self.src, environ)['CARGO_BUILD_JOBS'], '4')
        for bad in ['5', '64', '0', '-1', '04', 'x', '']:
            with self.subTest(bad), self.assertRaisesRegex(installer.InstallerRefused, 'CARGO_BUILD_JOBS'):
                installer.toolchain_env(self.root / 't', self.src, {**environ, 'CARGO_BUILD_JOBS': bad})

    def test_resolved_compiler_must_be_the_pinned_channel(self):
        # A host rustc or a RUSTUP_TOOLCHAIN override resolves another toolchain.
        self.fake_rustc(self.sysroot, '1.90.0')
        with self.assertRaisesRegex(installer.InstallerRefused, 'channel 1.85.0'):
            installer.toolchain_env(self.root / 't', self.src, self.environ)
        self.fake_rustc(self.sysroot, '1.85.0')
        (self.src / 'rust-toolchain.toml').write_text('[toolchain]\nchannel = "stable"\n')
        with self.assertRaisesRegex(installer.InstallerRefused, 'exact version'):
            installer.toolchain_env(self.root / 't', self.src, self.environ)

    def test_cargo_configuration_outside_the_exported_tree_is_refused(self):
        for config in [self.root / 'home/.cargo/config.toml', self.root / 'home/.cargo/config',
                       self.root / '.cargo/config.toml']:
            with self.subTest(str(config.relative_to(self.root))):
                config.parent.mkdir(parents=True, exist_ok=True)
                config.write_text('[build]\nrustflags = ["-C", "target-cpu=native"]\n')
                with self.assertRaisesRegex(installer.InstallerRefused, 'Cargo configuration'):
                    installer.toolchain_env(self.root / 't', self.src, self.environ)
                config.unlink()
        # The exported tree's own configuration is tracked source and stays allowed.
        (self.src / '.cargo').mkdir()
        (self.src / '.cargo/config.toml').write_text('[net]\noffline = true\n')
        installer.toolchain_env(self.root / 't', self.src, self.environ)

    def test_missing_or_unresolvable_toolchain_is_refused(self):
        with self.assertRaisesRegex(installer.InstallerRefused, 'rustc'):
            installer.toolchain_env(self.root / 't', self.src, {**self.environ, 'PATH': str(self.root / 'none')})
        (self.sysroot / 'bin/cargo').unlink()
        with self.assertRaisesRegex(installer.InstallerRefused, 'sysroot'):
            installer.toolchain_env(self.root / 't', self.src, self.environ)


class SignaturePolicy(unittest.TestCase):
    PRIMARY = 'A' * 24 + '0123456789ABCDEF'
    GOOD = ('[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 0123456789ABCDEF release\n'
            '[GNUPG:] VALIDSIG ' + PRIMARY + ' 2026-09-23 1790000000 0 4 0 22 10 00 ' + PRIMARY + '\n')

    def test_strict_policy_applies_to_release_metadata(self):
        self.assertTrue(installer.signature_accepted(0, self.GOOD, self.PRIMARY))
        self.assertFalse(installer.signature_accepted(1, self.GOOD, self.PRIMARY))
        self.assertFalse(installer.signature_accepted(
            0, self.GOOD + '[GNUPG:] EXPKEYSIG 0123456789ABCDEF release\n', self.PRIMARY))
        self.assertFalse(installer.signature_accepted(0, self.GOOD, 'B' * 40))


@unittest.skipUnless(TOOLS, 'gpg, gpgconf and git are required')
class InstallerBuild(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='ri-', dir='/tmp'))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.fingerprint, self.home = self.key('release')
        self.repo = self.root / 'repo'
        for relative in ['Cargo.toml', 'crates/stack-install/src/trust.rs',
                         'packaging/fedora/44/repository/assemble.py', 'install/render-bootstrap.py']:
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / relative, target)
        # Scratch trust root: the throwaway key replaces the committed key, as in the rehearsal.
        key = self.repo / 'crates/stack-install/src/trust/release-public.asc'
        key.parent.mkdir(parents=True)
        key.write_text(self.export(self.home, self.fingerprint))
        source = self.repo / 'crates/stack-install/src/trust.rs'
        source.write_text(source.read_text().replace('1085FBE578732D1CF0C50417A8FE2F718B8763D8', self.fingerprint))
        git(self.repo, 'init', '-q')
        git(self.repo, 'add', '-A')
        git(self.repo, 'commit', '-q', '-m', 'scratch')
        self.commit = git(self.repo, 'rev-parse', 'HEAD')
        self.release = self.root / 'release-tree'
        self.write_release({'schema_version': 1, 'stack_release': '0.1.0', 'test_only': False,
                            'repository': {'id': 'intel-npu-stack-0.1.0', 'base_url': BASE_URL}})

    def key(self, name):
        home = self.root / ('g-' + name)
        home.mkdir(mode=0o700)
        self.addCleanup(subprocess.run, ['gpgconf', '--homedir', str(home), '--kill', 'all'], capture_output=True)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'GNUPGHOME': str(home)}
        subprocess.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
                        name + ' <' + name + '@example.invalid>', 'ed25519', 'sign', '1d'], env=env, check=True,
                       capture_output=True)
        listing = subprocess.run(['gpg', '--batch', '--with-colons', '--list-secret-keys'], env=env, check=True,
                                 capture_output=True, text=True).stdout
        return [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')][0], home

    def export(self, home, fingerprint):
        return subprocess.run(['gpg', '--batch', '--armor', '--export', fingerprint], check=True, capture_output=True,
                              text=True, env={'PATH': '/usr/bin:/bin', 'GNUPGHOME': str(home)}).stdout

    def write_release(self, document, signer=None):
        self.release.mkdir(exist_ok=True)
        data = self.release / 'release.json'
        data.write_text(json.dumps(document, indent=2) + '\n')
        home, fingerprint = signer or (self.home, self.fingerprint)
        signature = self.release / 'release.json.sig'
        signature.unlink(missing_ok=True)
        subprocess.run(['gpg', '--batch', '--armor', '--detach-sign', '--local-user', fingerprint, '--output',
                        str(signature), str(data)], check=True, capture_output=True,
                       env={'PATH': '/usr/bin:/bin', 'GNUPGHOME': str(home)})

    def build(self, runner=None, name='out', leg='a', environ=None):
        runner = runner or FakeCargo()
        output = self.root / name
        result = installer.build(self.repo, self.commit, self.release, output, leg,
                                 self.root / (name + '-src'), self.root / (name + '-target'), runner=runner,
                                 environ=environ or {'PATH': '/usr/bin:/bin'})
        return result, output, runner

    def test_build_pins_only_the_metadata_digest_and_renders_the_pair(self):
        result, output, runner = self.build()
        release_sha = hashlib.sha256((self.release / 'release.json').read_bytes()).hexdigest()
        binary = output / 'intel-npu-stack-install'
        self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
        pinned = (output / 'installer-trust.rs').read_text()
        self.assertEqual(trust.parse_trust(pinned)['metadata_sha256'], release_sha)
        committed = (self.repo / 'crates/stack-install/src/trust.rs').read_text()
        self.assertEqual(pinned, trust.pin_metadata(committed, release_sha))
        bootstrap = (output / 'install.sh').read_text()
        self.assertIn(BASE_URL + 'intel-npu-stack-install', bootstrap)
        self.assertIn(hashlib.sha256(binary.read_bytes()).hexdigest(), bootstrap)
        primary = (output / 'primary-command.txt').read_text()
        # Regression: the primary command fetches install.sh, never the installer binary.
        self.assertIn(BASE_URL + 'install.sh', primary)
        self.assertNotIn('intel-npu-stack-install', primary)
        self.assertIn(hashlib.sha256((output / 'install.sh').read_bytes()).hexdigest(), primary)
        for script in ['install.sh', 'primary-command.txt']:
            subprocess.run(['sh', '-n', str(output / script)], check=True)
        record = json.loads((output / 'installer-build.json').read_text())
        self.assertEqual(record['leg'], 'a')
        self.assertEqual(record['source_commit'], self.commit)
        self.assertEqual(record['release_json_sha256'], release_sha)
        self.assertEqual(record['binary_sha256'], hashlib.sha256(binary.read_bytes()).hexdigest())
        build = [call for call in runner.calls if call[0][:2] == ['cargo', 'build']][0]
        self.assertEqual(build[0], ['cargo', 'build', '--release', '--locked', '--offline', '--target',
                                    'x86_64-unknown-linux-gnu', '-p', 'stack-install', '--bin',
                                    'intel-npu-stack-install'])
        self.assertEqual(result['binary_sha256'], record['binary_sha256'])

    def test_record_holds_the_environment_and_umask_the_build_used(self):
        previous = os.umask(0o027)
        try:
            _, output, runner = self.build(environ={'PATH': '/usr/bin:/bin', 'TZ': 'Pacific/Chatham',
                                                    'LANG': 'de_DE.UTF-8', 'CARGO_BUILD_JOBS': '1'})
        finally:
            os.umask(previous)
        record = json.loads((output / 'installer-build.json').read_text())
        build_env = [call for call in runner.calls if call[0][:2] == ['cargo', 'build']][0][2]
        self.assertEqual(record['build_environment'], build_env)
        self.assertEqual(build_env['CARGO_BUILD_JOBS'], '1')
        self.assertEqual(build_env['TZ'], 'UTC')
        self.assertEqual(record['caller_environment'], {'TZ': 'Pacific/Chatham', 'LANG': 'de_DE.UTF-8',
                                                        'IMAGE_DIGEST': None})
        self.assertEqual(record['umask'], '0o27')

    def test_oversized_job_count_is_refused_before_any_output(self):
        with self.assertRaisesRegex(installer.InstallerRefused, 'CARGO_BUILD_JOBS'):
            self.build(environ={'PATH': '/usr/bin:/bin', 'CARGO_BUILD_JOBS': '16'})
        self.assertFalse((self.root / 'out-src').exists())
        self.assertFalse((self.root / 'out').exists())

    def test_signature_under_another_key_is_refused(self):
        other = self.key('other')
        self.write_release(json.loads((self.release / 'release.json').read_text()), signer=(other[1], other[0]))
        with self.assertRaisesRegex(installer.InstallerRefused, 'signature'):
            self.build()

    def test_release_fields_must_match_the_trust_seam(self):
        base = {'schema_version': 1, 'stack_release': '0.1.0', 'test_only': False,
                'repository': {'id': 'intel-npu-stack-0.1.0', 'base_url': BASE_URL}}
        for label, change in {'base_url': {'repository': {'id': 'x', 'base_url': BASE_URL + 'other/'}},
                              'stack_release': {'stack_release': '0.2.0'},
                              'test_only': {'test_only': True}}.items():
            with self.subTest(label):
                self.write_release({**base, **change})
                with self.assertRaisesRegex(installer.InstallerRefused, label):
                    self.build(name='out-' + label)

    def test_dirty_tree_or_wrong_commit_is_refused(self):
        with self.assertRaisesRegex(installer.InstallerRefused, 'commit'):
            installer.build(self.repo, 'f' * 40, self.release, self.root / 'o1', 'a', self.root / 's1',
                            self.root / 't1', runner=FakeCargo(), environ={'PATH': '/usr/bin:/bin'})
        (self.repo / 'Cargo.toml').write_text((self.repo / 'Cargo.toml').read_text() + '\n')
        with self.assertRaisesRegex(installer.InstallerRefused, 'clean'):
            self.build()

    def test_binary_without_the_pinned_literals_is_refused(self):
        with self.assertRaisesRegex(installer.InstallerRefused, 'pinned'):
            self.build(runner=FakeCargo(embed=False))

    def test_failed_toolchain_probe_is_refused(self):
        with self.assertRaisesRegex(installer.InstallerRefused, 'toolchain probe'):
            self.build(runner=FakeCargo(toolchain_exit=1))

    def test_relative_paths_are_made_absolute(self):
        previous = os.getcwd()
        os.chdir(self.root)
        try:
            result = installer.build(self.repo, self.commit, self.release, Path('rel-out'), 'a', Path('rel-src'),
                                     Path('rel-target'), runner=FakeCargo(), environ={'PATH': '/usr/bin:/bin'})
        finally:
            os.chdir(previous)
        self.assertEqual(result['src_root'], str(self.root / 'rel-src'))
        self.assertEqual(result['target_dir'], str(self.root / 'rel-target'))
        self.assertTrue((self.root / 'rel-out/intel-npu-stack-install').is_file())

    def test_installer_for_another_architecture_is_refused(self):
        for machine in [183, 3]:  # aarch64, i386
            with self.subTest(machine), self.assertRaisesRegex(installer.InstallerRefused, 'x86_64'):
                self.build(runner=FakeCargo(machine=machine), name=f'out-{machine}')

    def test_unexpected_version_output_is_refused(self):
        with self.assertRaisesRegex(installer.InstallerRefused, 'version'):
            self.build(runner=FakeCargo(version='intel-npu-stack-install 0.2.0'))

    def test_outputs_are_never_overwritten(self):
        self.build()
        with self.assertRaisesRegex(installer.InstallerRefused, 'exist'):
            self.build()

    def test_pin_source_writes_only_the_pinned_tree(self):
        src = self.root / 'pinned-src'
        installer.pin_source(self.repo, self.commit, self.release, src)
        release_sha = hashlib.sha256((self.release / 'release.json').read_bytes()).hexdigest()
        self.assertEqual(trust.parse_trust((src / 'crates/stack-install/src/trust.rs').read_text())['metadata_sha256'],
                         release_sha)
        self.assertTrue((src / 'Cargo.toml').is_file())
        self.assertFalse((self.root / 'out').exists())


if __name__ == '__main__':
    unittest.main()
