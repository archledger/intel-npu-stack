# SPDX-License-Identifier: Apache-2.0
"""Execute generated bootstraps with isolated transport and UID fixtures."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('renderer', Path(__file__).with_name('render-bootstrap.py'))
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)

URL = 'https://downloads.example.invalid/releases/0.1.0/intel-npu-stack-install'
PAYLOAD = b'#!/bin/sh\nprintf "%s\\n" "$@" > "$TEST_ARGS"\nexit "${TEST_EXIT:-0}"\n'


class BootstrapContract(unittest.TestCase):
    def run_bootstrap(self, *, download=PAYLOAD, expected=None, curl_exit=0, uid='1000', args=(), child_exit=0, primary=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_dir = root / 'bin'
            bin_dir.mkdir()
            work = root / 'tmp'
            work.mkdir()
            (root / 'payload').write_bytes(download)
            (bin_dir / 'id').write_text('#!/bin/sh\nprintf "%s\\n" "$TEST_UID"\n')
            (bin_dir / 'curl').write_text('''#!/usr/bin/python3
import json,os,pathlib,sys
args=sys.argv[1:]
pathlib.Path(os.environ['TEST_CURL_ARGS']).write_text(json.dumps(args))
pathlib.Path(args[args.index('--output')+1]).write_bytes(pathlib.Path(os.environ['TEST_PAYLOAD']).read_bytes())
sys.exit(int(os.environ['TEST_CURL_EXIT']))
''')
            for tool in bin_dir.iterdir():
                tool.chmod(0o700)
            script = root / 'bootstrap.sh'
            render = renderer.render_install_command if primary else renderer.render_bootstrap
            script.write_text(render('0.1.0', URL, expected or hashlib.sha256(PAYLOAD).hexdigest()))
            env = dict(os.environ, PATH=str(bin_dir) + ':/usr/bin:/bin', TMPDIR=str(work),
                       TEST_ARGS=str(root / 'args'), TEST_CURL_ARGS=str(root / 'curl-args'),
                       TEST_PAYLOAD=str(root / 'payload'), TEST_UID=uid,
                       TEST_CURL_EXIT=str(curl_exit), TEST_EXIT=str(child_exit))
            result = subprocess.run(['/bin/sh', str(script), *args], env=env, capture_output=True, text=True)
            calls = {'executed': (root / 'args').exists(), 'downloaded': (root / 'curl-args').exists(),
                     'remaining': list(work.iterdir())}
            if calls['executed']:
                calls['args'] = (root / 'args').read_text().splitlines()
            if calls['downloaded']:
                calls['curl_args'] = json.loads((root / 'curl-args').read_text())
            return result, calls

    def test_complete_verified_download_executes_and_cleans_up(self):
        args = ['--dry-run', '--yes', '--channel', 'experimental', '--accept-experimental-risk']
        result, calls = self.run_bootstrap(args=args)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls['args'], args)
        self.assertEqual(calls['remaining'], [])
        curl = calls['curl_args']
        self.assertEqual(curl[0], '--disable')
        self.assertEqual(curl[curl.index('--proto') + 1], '=https')
        self.assertEqual(curl[curl.index('--proto-redir') + 1], '=https')
        self.assertIn('--max-filesize', curl)
        self.assertEqual(curl[-2:], ['--', URL])

    def test_a_download_cut_short_and_piped_into_sh_runs_nothing(self):
        # `curl -fsSL .../install.sh | sh` hands sh whatever arrived. Every prefix of the script, however it is cut,
        # must neither download nor execute; the whole script must pass the caller's arguments through unchanged.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bin_dir = root / 'bin'
            bin_dir.mkdir()
            (root / 'tmp').mkdir()
            (root / 'payload').write_bytes(PAYLOAD)
            (bin_dir / 'id').write_text('#!/bin/sh\nprintf "%s\\n" 1000\n')
            (bin_dir / 'curl').write_text('#!/bin/sh\n: > "$TEST_CURL_ARGS"\n'
                                          'while [ "$#" -gt 0 ]; do [ "$1" = --output ] && cp "$TEST_PAYLOAD" "$2"; '
                                          'shift; done\n')
            for tool in bin_dir.iterdir():
                tool.chmod(0o700)
            script = renderer.render_bootstrap('0.1.0', URL, hashlib.sha256(PAYLOAD).hexdigest()).encode()
            env = dict(os.environ, PATH=str(bin_dir) + ':/usr/bin:/bin', TMPDIR=str(root / 'tmp'),
                       TEST_ARGS=str(root / 'args'), TEST_CURL_ARGS=str(root / 'curl-args'),
                       TEST_PAYLOAD=str(root / 'payload'))
            for cut in range(len(script) - 1):  # the last prefix is the script without its final newline
                subprocess.run(['/bin/sh', '-s', '--', '--dry-run'], input=script[:cut], env=env,
                               capture_output=True)
                self.assertFalse((root / 'curl-args').exists() or (root / 'args').exists(), cut)
            for args in [['--yes'], ['--dry-run', '--channel', 'experimental', '--accept-experimental-risk']]:
                result = subprocess.run(['/bin/sh', '-s', '--', *args], input=script, env=env, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((root / 'args').read_text().splitlines(), args)

    def test_wrong_digest_never_executes(self):
        result, calls = self.run_bootstrap(expected='0' * 64)
        self.assertEqual(result.returncode, 20)
        self.assertFalse(calls['executed'])
        self.assertEqual(calls['remaining'], [])

    def test_partial_or_failed_transfer_never_executes(self):
        for payload in [b'#!/bin/sh\n', PAYLOAD]:
            with self.subTest(payload=payload):
                result, calls = self.run_bootstrap(download=payload, curl_exit=18)
                self.assertEqual(result.returncode, 20)
                self.assertFalse(calls['executed'])
                self.assertEqual(calls['remaining'], [])

    def test_root_and_invalid_uid_are_refused_before_download(self):
        for uid in ['0', '', 'invalid']:
            with self.subTest(uid=uid):
                result, calls = self.run_bootstrap(uid=uid)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(calls['downloaded'])
                self.assertFalse(calls['executed'])

    def test_help_and_version_do_not_download_or_require_nonroot(self):
        for flag in ['--help', '--version']:
            result, calls = self.run_bootstrap(uid='0', args=[flag])
            self.assertEqual(result.returncode, 0)
            self.assertTrue(result.stdout)
            self.assertFalse(calls['downloaded'])

    def test_misuse_and_risk_mismatch_do_not_download(self):
        for args in [['--force'], ['--channel', 'candidate'], ['--channel'],
                     ['--channel', 'experimental', '--yes'], ['--accept-experimental-risk'],
                     ['--yes;id'], ['--root', '/tmp']]:
            with self.subTest(args=args):
                result, calls = self.run_bootstrap(args=args)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(calls['downloaded'])

    def test_installer_exit_class_is_preserved_and_files_removed(self):
        for code in [10, 20, 30, 40]:
            result, calls = self.run_bootstrap(child_exit=code)
            self.assertEqual(result.returncode, code)
            self.assertTrue(calls['executed'])
            self.assertEqual(calls['remaining'], [])

    def test_unsafe_unversioned_or_malformed_render_inputs_are_rejected(self):
        for url in ['http://example.invalid/0.1.0/a', 'https://u:p@example.invalid/0.1.0/a',
                    'https://example.invalid/latest/a', 'https://example.invalid/0.1.0/../a',
                    'https://example.invalid/0.1.0/a?cmd=id', 'https://example.invalid/0.1.0/a\n',
                    'https://example.invalid/0.1.0/%2e%2e/a']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                renderer.render_bootstrap('0.1.0', url, 'a' * 64)
        for digest in ['a' * 63, 'A' * 64, 'z' * 64]:
            with self.assertRaises(ValueError):
                renderer.render_bootstrap('0.1.0', URL, digest)
        with self.assertRaises(ValueError):
            renderer.render_bootstrap('latest', URL, 'a' * 64)

    def test_primary_command_verifies_complete_bootstrap_before_shell_execution(self):
        result, calls = self.run_bootstrap(primary=True, args=['--dry-run'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls['args'], ['--dry-run'])
        self.assertEqual(calls['remaining'], [])
        for kwargs in [dict(expected='0' * 64), dict(curl_exit=18)]:
            result, calls = self.run_bootstrap(primary=True, **kwargs)
            self.assertEqual(result.returncode, 20)
            self.assertFalse(calls['executed'])
            self.assertEqual(calls['remaining'], [])

    def test_versioned_github_release_path_and_shell_syntax(self):
        script = renderer.render_bootstrap('0.1.0', 'https://github.com/example/project/releases/download/v0.1.0/installer', 'a' * 64)
        result = subprocess.run(['/bin/sh', '-n'], input=script, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)



class PagesLocation(unittest.TestCase):
    """The published pair renders for the versioned GitHub Pages base."""

    BASE = 'https://archledger.github.io/intel-npu-stack/0.1.0/'

    def test_bootstrap_and_primary_command_render_for_pages(self):
        digest = hashlib.sha256(b'installer').hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            for name, text in [
                    ('install.sh', renderer.render_bootstrap('0.1.0', self.BASE + 'intel-npu-stack-install', digest)),
                    ('primary', renderer.render_install_command('0.1.0', self.BASE + 'install.sh', digest))]:
                script = Path(temporary) / name
                script.write_text(text)
                self.assertEqual(subprocess.run(['sh', '-n', str(script)]).returncode, 0, name)
                self.assertIn(self.BASE, text)

    def test_unversioned_pages_urls_are_refused(self):
        digest = hashlib.sha256(b'installer').hexdigest()
        for url in ['https://archledger.github.io/intel-npu-stack/install.sh',
                    'https://archledger.github.io/intel-npu-stack/latest/install.sh']:
            with self.subTest(url), self.assertRaises(ValueError):
                renderer.render_install_command('0.1.0', url, digest)

if __name__ == '__main__':
    unittest.main()
