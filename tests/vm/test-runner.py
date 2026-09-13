#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the isolated Fedora VM scenario runner.

These run anywhere with a fake toolchain: no QEMU, no image, no boot. The
runner must refuse everything unverified or unsafe, keep every privileged
virtualization property bounded, and clean up on timeout.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('runner', HERE/'run-fedora.py')
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

IMAGE_SHA = hashlib.sha256(b'cloud image bytes').hexdigest()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fake_tool(directory, name, behavior):
    path = directory/name
    path.write_text('#!/bin/sh\n'+behavior+'\n')
    path.chmod(0o700)
    return path


def make_fixture(root):
    """A miniature release4-shaped fixture tree with a truthful result.json."""
    fixture = root/'fixture'
    release_tree = fixture/'release-tree'
    release_tree.mkdir(parents=True, exist_ok=True)
    (release_tree/'release.json').write_bytes(b'{"stack_release": "0.1.0"}\n')
    (release_tree/'profile.toml').write_bytes(b'schema_version = 1\n')
    (fixture/'binaries/build1/guest-harness').parent.mkdir(parents=True, exist_ok=True)
    (fixture/'binaries/build1/guest-harness').write_bytes(b'ELF harness\n')
    (fixture/'binaries/build1/intel-npu-stack-install').write_bytes(b'ELF installer\n')
    (fixture/'install.sh').write_bytes(b'#!/bin/sh\nbootstrap\n')
    (fixture/'test-public.asc').write_bytes(b'-----BEGIN TEST KEY-----\n')
    result = {'passed': True, 'test_only': True,
              'metadata_sha256': sha((release_tree/'release.json').read_bytes()),
              'guest_harness_sha256': sha((fixture/'binaries/build1/guest-harness').read_bytes()),
              'installer_sha256': sha((fixture/'binaries/build1/intel-npu-stack-install').read_bytes()),
              'primary_fingerprint': '5B2F5071D178BBD14860F2D5C1EF013B8E20F2CE'}
    (fixture/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    return fixture, result


class RunnerContract(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.base = Path(self.workspace.name)
        self.tools = self.base/'bin'
        self.tools.mkdir()
        self.image = self.base/'image.qcow2'
        self.image.write_bytes(b'cloud image bytes')
        self.calls = self.base/'calls'
        self.calls.mkdir()
        fake_tool(self.tools, 'qemu-img',
                  f'printf "%s\\n" "$@" >> {self.calls}/qemu-img.argv; '
                  'for last; do :; done; : > "$last"; exit 0')
        fake_tool(self.tools, 'xorriso',
                  f'printf "%s\\n" "$@" >> {self.calls}/xorriso.argv; exit 0')
        fake_tool(self.tools, 'openssl',
                  f'printf "%s\\n" "$@" >> {self.calls}/openssl.argv; '
                  'exec /usr/bin/openssl "$@"')
        self.fake_qemu(post_result=True)
        self.kvm = self.base/'kvm'
        self.kvm.write_bytes(b'')

    def fake_qemu(self, post_result):
        post = ''
        if post_result:
            post = (
                'python3 -c \'import json,ssl,urllib.request;'
                'ctx=ssl._create_unverified_context();'
                'data=json.dumps({"scenario":"install","passed":True}).encode();'
                'req=urllib.request.Request('
                '"https://127.0.0.1:8443/scenario-result",data=data,method="POST");'
                'urllib.request.urlopen(req,context=ctx)\' >/dev/null 2>&1; ')
        behavior = (f'printf "%s\\n" "$@" >> {self.calls}/qemu.argv; '
                    f'{post}sleep 5')
        fake_tool(self.tools, 'qemu-system-x86_64', behavior)

    def tearDown(self):
        self.workspace.cleanup()

    def environment(self, scenario='install'):
        fixture, _ = make_fixture(self.base)
        return runner.RunnerEnvironment(
            scenario=scenario, image=self.image, image_sha256=IMAGE_SHA,
            fixture=fixture, output=self.base/'run', kvm=self.kvm,
            cpus=4, memory_megabytes=3072, timeout_seconds=30,
            tool_path=self.tools, port=8443, server_hostname='127.0.0.1')

    def refusal(self, error_fragment, environment=None):
        with self.assertRaises(runner.RunnerRefused) as raised:
            runner.run_scenario(environment or self.environment())
        self.assertIn(error_fragment, str(raised.exception))

    def test_unknown_scenario_is_refused(self):
        self.refusal('unknown scenario', self.environment(scenario='boot-and-pray'))

    def test_image_digest_drift_is_refused(self):
        self.image.write_bytes(b'tampered image bytes')
        self.refusal('image digest')

    def test_fixture_digest_drift_is_refused(self):
        fixture, _ = make_fixture(self.base)
        (fixture/'release-tree/release.json').write_bytes(b'{"stack_release": "0.0.9"}\n')
        environment = runner.RunnerEnvironment(
            scenario='install', image=self.image, image_sha256=IMAGE_SHA, fixture=fixture,
            output=self.base/'run', kvm=self.kvm, cpus=4, memory_megabytes=3072,
            timeout_seconds=30, tool_path=self.tools, port=8443, server_hostname='127.0.0.1')
        self.refusal('fixture digest drift', environment)

    def test_occupied_output_is_refused(self):
        (self.base/'run').mkdir()
        (self.base/'run/earlier.txt').write_text('kept')
        self.refusal('output path already exists')

    def test_missing_kvm_is_refused(self):
        self.kvm.unlink()
        self.refusal('KVM device')

    def test_held_run_lock_is_refused(self):
        (self.base/'run.lock').mkdir()
        environment = self.environment()
        environment = environment._replace(lock=self.base/'run.lock')
        self.refusal('another scenario run holds the lock')

    def test_unsafe_cpu_or_memory_request_is_refused(self):
        self.refusal('CPU', self.environment()._replace(cpus=11))
        self.refusal('memory', self.environment()._replace(memory_megabytes=16384))

    def test_seed_iso_uses_cidata_volume_with_exact_files(self):
        environment = self.environment()
        seed_files = runner.seed_files(environment)
        self.assertEqual(sorted(seed_files), ['meta-data', 'user-data'])
        runner.build_seed_iso(environment, seed_files)
        argv = (self.calls/'xorriso.argv').read_text().splitlines()
        self.assertIn('-volid', argv)
        self.assertEqual(argv[argv.index('-volid')+1], 'cidata')
        self.assertIn('-graft-points', argv)

    def test_user_data_pins_the_test_endpoints_and_harness_only(self):
        environment = self.environment()
        user_data = runner.seed_files(environment)['user-data'].decode()
        self.assertIn('10.0.2.2 downloads.example.invalid', user_data)
        self.assertIn('update-ca-trust', user_data)
        self.assertIn('dnf5 --assumeyes install gnupg2', user_data)
        self.assertIn('--scenario, install', user_data)
        self.assertIn('poweroff', user_data)
        self.assertNotIn('experimental', user_data)
        self.assertNotIn('ACCEPT_EXPERIMENTAL_RISK', user_data)

    def test_overlay_backing_is_the_verified_image(self):
        environment = self.environment()
        runner.create_overlay(environment)
        argv = (self.calls/'qemu-img.argv').read_text().splitlines()
        self.assertIn('create', argv)
        self.assertIn(str(self.image), argv)
        self.assertIn('-F', argv)
        self.assertEqual(argv[argv.index('-F')+1], 'qcow2')

    def test_larger_disk_resizes_only_disposable_overlay(self):
        environment = self.environment()._replace(disk_gigabytes=20)
        fake_tool(self.tools, 'qemu-img',
                  f'printf "%s\\n" "$@" >> {self.calls}/qemu-img.argv; '
                  'if [ "$1" = create ]; then for last; do :; done; : > "$last"; fi')
        overlay = runner.create_overlay(environment)
        argv = (self.calls/'qemu-img.argv').read_text().splitlines()
        self.assertEqual(argv[argv.index('resize'):], ['resize', str(overlay), '20G'])
        self.assertEqual(self.image.read_bytes(), b'cloud image bytes')
        self.refusal('disk', environment._replace(disk_gigabytes=100, output=self.base/'invalid-run'))

    def test_qemu_command_is_bounded_and_isolated(self):
        environment = self.environment()
        command = runner.qemu_command(environment, overlay=self.base/'overlay.qcow2',
                                      seed=self.base/'seed.iso')
        joined = ' '.join(command)
        self.assertIn('--enable-kvm', joined)
        self.assertIn('-smp', joined)
        self.assertLessEqual(int(joined.split('-smp ')[1].split()[0]), 4)
        self.assertIn('-m 3072', joined)
        self.assertIn('-netdev user', joined)
        forwarder = ' '.join(runner.forwarder_unit(self.environment()))
        self.assertIn('TCP-LISTEN:443,bind=127.0.0.1', forwarder)
        self.assertIn('TCP:127.0.0.1:8443', forwarder)
        self.assertIn('sudo', forwarder.split())
        for forbidden in ['vfio', 'usb-host', '-bridge', 'virtfs', 'fsdev', 'hostfwd',
                          'pci-assign', '-usb ']:
            self.assertNotIn(forbidden, joined, forbidden)

    def test_run_collects_scenario_result_and_cleans_up(self):
        result = runner.run_scenario(self.environment())
        self.assertTrue(result['passed'])
        self.assertEqual(result['scenario'], 'install')
        self.assertIn('inputs', result)
        self.assertEqual(result['inputs']['image_sha256'], IMAGE_SHA)
        self.assertTrue(result['cleanup']['overlay_removed'])
        self.assertTrue(result['cleanup']['lock_released'])
        self.assertTrue((self.base/'run/run.json').is_file())

    def test_timeout_kills_qemu_and_records_cleanup(self):
        environment = self.environment()._replace(timeout_seconds=0)
        result = runner.run_scenario(environment)
        self.assertFalse(result['passed'])
        self.assertTrue(result['timeout'])
        self.assertTrue(result['cleanup']['qemu_killed'])
        self.assertTrue(result['cleanup']['overlay_removed'])
        self.assertTrue(result['cleanup']['lock_released'])

    def test_reboot_restarts_same_overlay_before_accepting_final_result(self):
        marker = self.base/'first-boot'
        behavior = (
            f'printf "%s\\n" "$@" >> {self.calls}/qemu.argv; '
            'python3 -c \'import json,ssl,urllib.request; from pathlib import Path; '
            f'p=Path("{marker}"); first=not p.exists(); p.touch(); '
            'data={"scenario":"reboot","passed":not first}; '
            'data.update({"stage":"reboot-requested"} if first else {}); '
            'req=urllib.request.Request("https://127.0.0.1:8443/scenario-result", '
            'data=json.dumps(data).encode(),method="POST"); '
            'urllib.request.urlopen(req,context=ssl._create_unverified_context())\''
        )
        fake_tool(self.tools, 'qemu-system-x86_64', behavior)
        result = runner.run_scenario(self.environment('reboot'))
        self.assertTrue(result['passed'])
        self.assertEqual(result['reboots'], 1)
        self.assertEqual((self.calls/'qemu.argv').read_text().count('--enable-kvm'), 2)
        self.assertTrue(result['cleanup']['overlay_removed'])

    def test_http_server_serves_release_and_control_plane(self):
        import threading
        import urllib.request
        import ssl
        environment = self.environment()
        certificate, key = runner.generate_certificate(environment)
        server = runner.FixtureServer(environment, hostname='127.0.0.1', port=0)
        server.enable_tls(certificate, key)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        base = f'https://127.0.0.1:{server.port}'

        def request(path, method='GET', body=None):
            request = urllib.request.Request(base+path, data=body, method=method)
            with urllib.request.urlopen(request, context=context, timeout=10) as response:
                return response.status, response.read()

        status, body = request('/intel-npu-stack/0.1.0/fedora/44/x86_64/release.json')
        self.assertEqual((status, body), (200, b'{"stack_release": "0.1.0"}\n'))
        self.assertEqual(request('/intel-npu-stack/0.1.0/fedora/44/x86_64/'
                                 'intel-npu-stack-install')[1], b'ELF installer\n')
        self.assertEqual(request('/guest/guest-harness')[1], b'ELF harness\n')
        self.assertEqual(request('/guest/install.sh')[1], b'#!/bin/sh\nbootstrap\n')
        self.assertEqual(request('/guest/public.asc')[1], b'-----BEGIN TEST KEY-----\n')
        request('/corrupt', method='POST', body=json.dumps(
            {'target': 'release.json'}).encode())
        status, corrupted = request('/intel-npu-stack/0.1.0/fedora/44/x86_64/release.json')
        self.assertNotEqual(corrupted, b'{"stack_release": "0.1.0"}\n')
        self.assertEqual(len(corrupted), len(b'{"stack_release": "0.1.0"}\n'))
        request('/restore', method='POST', body=b'{}')
        self.assertEqual(request('/intel-npu-stack/0.1.0/fedora/44/x86_64/release.json')[1],
                         b'{"stack_release": "0.1.0"}\n')
        status, _ = request('/scenario-result', method='POST',
                            body=json.dumps({'scenario': 'install', 'passed': True}).encode())
        self.assertEqual(status, 200)
        self.assertEqual(server.scenario_result['passed'], True)
        server.shutdown()
        server.server_close()

    def test_fixture_paths_refuse_unlisted_and_absolute_paths(self):
        server = runner.FixtureServer(self.environment(), hostname='127.0.0.1', port=0)
        handler = runner.FixtureHandler.__new__(runner.FixtureHandler)
        handler.server = server
        try:
            for path in ['/guest/../../result.json', '/guest/arbitrary-file',
                         runner.RELEASE_PATH+'/etc/passwd', '/fedora-inputs/../result.json']:
                self.assertIsNone(handler.fixture_path(path), path)
        finally:
            server.server_close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
