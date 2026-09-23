#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Contract for the local HTTPS Pages fixture and the serve-test classifiers.

The real curl, installer and DNF run needs root in a disposable container; the
release workflow's verify job and the rehearsal cover it.
"""
import os
from pathlib import Path
import shutil
import socket
import ssl
import tempfile
import unittest

import release_serve as serve

BASE_URL = 'https://archledger.github.io/intel-npu-stack/0.1.0/'
HOST = 'archledger.github.io'


def fetch(port, path, cafile):
    """One HTTPS GET to 127.0.0.1:port presenting the Pages host name; returns (status, body)."""
    context = ssl.create_default_context(cafile=str(cafile))
    with socket.create_connection(('127.0.0.1', port), timeout=10) as raw, \
            context.wrap_socket(raw, server_hostname=HOST) as tls:
        tls.sendall(f'GET {path} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n'.encode())
        data = b''
        while chunk := tls.recv(65536):
            data += chunk
    head, _, body = data.partition(b'\r\n\r\n')
    return int(head.split()[1]), body


class Classifiers(unittest.TestCase):
    def test_location_of_the_versioned_base(self):
        self.assertEqual(serve.location(BASE_URL), (HOST, '/intel-npu-stack/', '0.1.0'))
        for bad in ['http://archledger.github.io/intel-npu-stack/0.1.0/', 'https://archledger.github.io/0.1.0/',
                    'https://archledger.github.io/intel-npu-stack/0.1.0', BASE_URL + '?x=1',
                    'https://archledger.github.io/intel-npu-stack/../0.1.0/']:
            with self.subTest(bad), self.assertRaises(serve.ServeRefused):
                serve.location(bad)

    def test_served_path_mapping(self):
        prefix = '/intel-npu-stack/'
        self.assertEqual(serve.served_path(prefix, '/intel-npu-stack/0.1.0/release.json'), '0.1.0/release.json')
        self.assertEqual(serve.served_path(prefix, '/intel-npu-stack/0.1.0/repodata/repomd.xml'),
                         '0.1.0/repodata/repomd.xml')
        for raw in ['/other/0.1.0/release.json', '/intel-npu-stack/', '/intel-npu-stack/0.1.0/',
                    '/intel-npu-stack/0.1.0/../x', '/intel-npu-stack/0.1.0/%2e%2e/x', '/intel-npu-stack/0.1.0//x',
                    '/intel-npu-stack/0.1.0/.hidden', '/intel-npu-stack/0.1.0/release.json?cache=1',
                    '/intel-npu-stack/0.1.0/release.json#x']:
            with self.subTest(raw):
                self.assertIsNone(serve.served_path(prefix, raw))

    def test_corruption_changes_exactly_one_byte(self):
        body = b'{"schema_version": 1}\n'
        changed = serve.corrupted(body)
        self.assertEqual(len(changed), len(body))
        self.assertEqual(sum(a != b for a, b in zip(body, changed)), 1)
        self.assertEqual(serve.corrupted(b''), b'\0')

    def test_exit_classes(self):
        line = 'intel-npu-stack-install: {} [{}]'
        cases = [
            (10, line.format('exactly one compatible profile admitted by this channel is required',
                             'INSTALL_PROFILE_UNSUPPORTED'), 'verified'),
            (30, line.format('native platform facts could not be discovered', 'INSTALL_PLATFORM_DISCOVERY_FAILED'),
             'verified'),
            (20, line.format('release metadata digest mismatch', 'INSTALL_INTEGRITY_FAILED'), 'integrity-refused'),
            (20, '', 'integrity-refused'),
            (0, 'Dry run complete; nothing was installed.', 'unexpected'),
            (30, line.format('Fedora sources could not be verified', 'INSTALL_FEDORA_SOURCES_INVALID'), 'unexpected'),
            (10, line.format('x', 'INSTALL_CAPABILITY_UNAVAILABLE'), 'unexpected'),
            (10, '\n'.join([line.format('x', 'INSTALL_PROFILE_UNSUPPORTED'),
                            line.format('y', 'INSTALL_PROFILE_UNSUPPORTED')]), 'unexpected'),
            (2, 'usage', 'unexpected'),
        ]
        for code, stderr, wanted in cases:
            with self.subTest(code=code, stderr=stderr):
                self.assertEqual(serve.classify(code, stderr), wanted)

    def test_pages_host_must_map_only_to_loopback(self):
        def resolver(addresses):
            return lambda host, port, proto: [(socket.AF_INET, socket.SOCK_STREAM, proto, '', (a, port))
                                              for a in addresses]
        serve.check_local(HOST, resolver(['127.0.0.1']))
        for addresses in [['185.199.108.153'], ['127.0.0.1', '185.199.108.153'], []]:
            with self.subTest(addresses), self.assertRaisesRegex(serve.ServeRefused, '127.0.0.1'):
                serve.check_local(HOST, resolver(addresses))

    def test_dnf_commands_check_package_and_repository_signatures(self):
        makecache, download = serve.dnf_commands(BASE_URL, '/src/key.asc', '/w/cache', '/w/out', ['a', 'b'])
        common = ['dnf5', '--assumeyes', '--setopt=reposdir=/nonexistent', '--setopt=cachedir=/w/cache',
                  '--repofrompath=npu,' + BASE_URL, '--setopt=npu.gpgcheck=1', '--setopt=npu.repo_gpgcheck=1',
                  '--setopt=npu.gpgkey=file:///src/key.asc', '--repo=npu']
        self.assertEqual(makecache, common + ['makecache'])
        self.assertEqual(download, common + ['download', '--destdir=/w/out', 'a', 'b'])

    def test_primary_command_never_runs_as_root(self):
        with self.assertRaisesRegex(serve.ServeRefused, 'unprivileged'):
            serve.run_primary('/nonexistent', 'root')

    @unittest.skipIf(os.geteuid() == 0, 'checks the refusal for unprivileged callers')
    def test_trust_anchor_needs_root(self):
        with self.assertRaisesRegex(serve.ServeRefused, 'root'):
            serve.install_anchor('/nonexistent')


@unittest.skipUnless(shutil.which('openssl'), 'openssl is required')
class LocalPages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='serve-')
        root = Path(cls.tmp.name)
        cls.site = root / 'site'
        (cls.site / '0.1.0/repodata').mkdir(parents=True)
        (cls.site / '0.1.0/release.json').write_bytes(b'{"stack_release": "0.1.0"}\n')
        (cls.site / '0.1.0/repodata/repomd.xml').write_bytes(b'<repomd/>\n')
        (cls.site / '0.1.0/link').symlink_to(cls.site / '0.1.0/release.json')
        (root / 'outside').mkdir()
        (root / 'outside/secret').write_bytes(b'outside the site\n')
        (cls.site / '0.1.0/escape').symlink_to(root / 'outside')
        cls.ca, cls.leaf, cls.key = serve.make_certificates(root / 'tls', HOST)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_serves_logs_and_corrupts_on_request(self):
        with serve.SiteServer(self.site, '/intel-npu-stack/', self.leaf, self.key, ('127.0.0.1', 0)) as server:
            original = (self.site / '0.1.0/release.json').read_bytes()
            self.assertEqual(fetch(server.port, '/intel-npu-stack/0.1.0/release.json', self.ca), (200, original))
            self.assertEqual(fetch(server.port, '/intel-npu-stack/0.1.0/repodata/repomd.xml', self.ca)[0], 200)
            self.assertEqual(fetch(server.port, '/intel-npu-stack/0.1.0/missing', self.ca)[0], 404)
            self.assertEqual(fetch(server.port, '/intel-npu-stack/0.1.0/link', self.ca)[0], 404)
            self.assertEqual(fetch(server.port, '/intel-npu-stack/', self.ca)[0], 404)
            self.assertEqual(fetch(server.port, '/intel-npu-stack/0.1.0/escape/secret', self.ca)[0], 404)
            server.corrupt = {'0.1.0/release.json'}
            status, body = fetch(server.port, '/intel-npu-stack/0.1.0/release.json', self.ca)
            self.assertEqual((status, body), (200, serve.corrupted(original)))
            self.assertEqual(server.take_log(), [
                ('/intel-npu-stack/0.1.0/release.json', 200), ('/intel-npu-stack/0.1.0/repodata/repomd.xml', 200),
                ('/intel-npu-stack/0.1.0/missing', 404), ('/intel-npu-stack/0.1.0/link', 404),
                ('/intel-npu-stack/', 404), ('/intel-npu-stack/0.1.0/escape/secret', 404),
                ('/intel-npu-stack/0.1.0/release.json', 200)])
            self.assertEqual(server.take_log(), [])

    def test_certificate_names_only_the_pages_host(self):
        with serve.SiteServer(self.site, '/intel-npu-stack/', self.leaf, self.key, ('127.0.0.1', 0)) as server:
            context = ssl.create_default_context(cafile=str(self.ca))
            with socket.create_connection(('127.0.0.1', server.port), timeout=10) as raw:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    context.wrap_socket(raw, server_hostname='example.org')
            with socket.create_connection(('127.0.0.1', server.port), timeout=10) as raw:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    ssl.create_default_context().wrap_socket(raw, server_hostname=HOST)


if __name__ == '__main__':
    unittest.main()
