#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Contract for fetching and extracting the prepared release inputs before any key exists."""
import contextlib
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

import release_inputs as inputs_tool
import test_release_sign

URL = 'https://github.com/archledger/intel-npu-stack/releases/download/release-inputs-0.1.0/release-inputs.tar.gz'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Inputs(unittest.TestCase):
    def setUp(self):
        fixture = test_release_sign.InputsContract('test_complete_inputs_pass_and_report_counts')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.source, self.profile = fixture.inputs, fixture.profile
        self.work = Path(tempfile.mkdtemp(prefix='inputs-'))
        self.addCleanup(shutil.rmtree, self.work, True)
        self.archive = self.work / 'release-inputs.tar.gz'
        self.pack(self.archive)

    def pack(self, archive, extra=None):
        with tarfile.open(archive, 'w:gz') as tar:
            for path in sorted(self.source.rglob('*')):
                tar.add(path, arcname='./' + path.relative_to(self.source).as_posix(), recursive=False)
            for info, data in extra or []:
                tar.addfile(info, io.BytesIO(data) if data is not None else None)
        return sha(archive)

    def extract(self, archive=None, digest=None, expected=None, output=None):
        archive = archive or self.archive
        digest = digest or sha(archive)
        return inputs_tool.extract_check(archive, digest, expected or digest, self.profile,
                                         output or self.work / 'out')

    def test_extracted_inputs_pass_the_keyless_check(self):
        result = self.extract()
        self.assertTrue(result['inputs']['passed'])
        self.assertEqual(result['archive_sha256'], sha(self.archive))
        self.assertEqual((self.work / 'out/index.json').read_bytes(), (self.source / 'index.json').read_bytes())

    def test_digest_must_match_the_dispatch_input_and_the_preflight_output(self):
        digest = sha(self.archive)
        with self.assertRaisesRegex(inputs_tool.InputsRefused, 'SHA-256'):
            inputs_tool.extract_check(self.archive, 'a' * 64, digest, self.profile, self.work / 'o1')
        with self.assertRaisesRegex(inputs_tool.InputsRefused, 'preflight'):
            inputs_tool.extract_check(self.archive, digest, 'a' * 64, self.profile, self.work / 'o2')
        with self.assertRaisesRegex(inputs_tool.InputsRefused, 'SHA-256'):
            inputs_tool.extract_check(self.archive, 'A' * 64, 'A' * 64, self.profile, self.work / 'o3')
        self.assertFalse((self.work / 'o1').exists())

    def test_unsafe_members_are_refused_before_extraction(self):
        def member(name, kind=tarfile.REGTYPE, data=b'x', link=''):
            info = tarfile.TarInfo(name)
            info.type, info.linkname = kind, link
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            return info, data if kind == tarfile.REGTYPE else None
        cases = {
            'absolute': [member('/etc/passwd')],
            'parent': [member('../outside')],
            'nested parent': [member('notices/../../outside')],
            'symlink': [member('link', tarfile.SYMTYPE, link='/etc/passwd')],
            'hard link': [member('hard', tarfile.LNKTYPE, link='index.json')],
            'device': [member('device', tarfile.CHRTYPE)],
            'duplicate': [member('./index.json', data=b'[]')],
            'backslash': [member('notices\\evil')],
        }
        for label, extra in cases.items():
            with self.subTest(label):
                archive = self.work / (label.replace(' ', '-') + '.tar.gz')
                self.pack(archive, extra)
                output = self.work / ('out-' + label.replace(' ', '-'))
                with self.assertRaises(inputs_tool.InputsRefused):
                    self.extract(archive, output=output)
                self.assertFalse(output.exists())

    def test_the_member_limit_counts_every_header_while_streaming(self):
        limit, inputs_tool.MAX_MEMBERS = inputs_tool.MAX_MEMBERS, 50
        self.addCleanup(setattr, inputs_tool, 'MAX_MEMBERS', limit)
        entries = []
        for _ in range(60):  # '.' entries are skipped, but still count
            info = tarfile.TarInfo('./')
            info.type = tarfile.DIRTYPE
            entries.append((info, None))
        archive = self.work / 'many.tar.gz'
        self.pack(archive, entries)
        with self.assertRaisesRegex(inputs_tool.InputsRefused, 'too many members'):
            self.extract(archive, output=self.work / 'many')

    def test_hidden_pax_headers_count_toward_the_member_limit(self):
        limit, inputs_tool.MAX_MEMBERS = inputs_tool.MAX_MEMBERS, 50
        self.addCleanup(setattr, inputs_tool, 'MAX_MEMBERS', limit)
        count = len(list(self.source.rglob('*')))
        self.assertLess(count + 1, 50)
        entries = []
        for index in range(50 - count):  # a fractional mtime gives each member a pax header tarfile never yields
            info = tarfile.TarInfo(f'extra/{index}')
            info.mtime = 1.5
            entries.append((info, b''))
        archive = self.work / 'hidden.tar.gz'
        self.pack(archive, entries)
        with tarfile.open(archive) as tar:
            self.assertLessEqual(len(tar.getmembers()), 50)
        with self.assertRaisesRegex(inputs_tool.InputsRefused, 'too many members'):
            self.extract(archive, output=self.work / 'hidden')

    def test_inputs_are_scanned_before_tarfile_reads_them(self):
        info = tarfile.TarInfo('././@LongLink')
        info.type, info.size = tarfile.GNUTYPE_LONGNAME, 900 << 20
        archive = self.work / 'huge-name.tar.gz'
        with gzip.open(archive, 'wb') as stream:
            stream.write(info.tobuf(tarfile.GNU_FORMAT, 'utf-8', 'surrogateescape') + bytes(1024))
        with self.assertRaisesRegex(inputs_tool.InputsRefused, 'extension header'):
            self.extract(archive, output=self.work / 'huge-name')

    def test_inputs_that_fail_the_keyless_check_are_refused(self):
        (self.source / 'candidate.toml').write_text('status = "candidate"\n')
        archive = self.work / 'bad.tar.gz'
        self.pack(archive)
        with self.assertRaisesRegex(Exception, 'candidate.toml'):
            self.extract(archive, output=self.work / 'bad')

    def test_existing_output_is_never_overwritten(self):
        (self.work / 'out').mkdir()
        with self.assertRaisesRegex(inputs_tool.InputsRefused, 'exists'):
            self.extract()

    def test_fetch_uses_https_only_and_then_extract_checks(self):
        argv = inputs_tool.curl_command(URL, self.work / 'x.tar.gz')
        for option, value in [('--proto', '=https'), ('--proto-redir', '=https')]:
            self.assertEqual(argv[argv.index(option) + 1], value)
        self.assertIn('--fail', argv)
        self.assertEqual(argv[-2:], ['--', URL])
        fetched = []

        def download(url, output):
            fetched.append(url)
            shutil.copyfile(self.archive, output)
        result = inputs_tool.fetch_check(URL, sha(self.archive), self.profile, self.work / 'fetched.tar.gz',
                                         self.work / 'fetched', download=download)
        self.assertEqual(fetched, [URL])
        self.assertTrue(result['inputs']['passed'])
        for url in ['http://example.org/x.tar.gz', 'file:///tmp/x.tar.gz', 'https://user@example.org/x',
                    'https://example.org/x?token=1', 'ftp://example.org/x']:
            with self.subTest(url), self.assertRaisesRegex(inputs_tool.InputsRefused, 'HTTPS'):
                inputs_tool.fetch_check(url, sha(self.archive), self.profile, self.work / 'y.tar.gz',
                                        self.work / 'y', download=download)

    def test_command_line_reports_the_result(self):
        report = self.work / 'report.json'
        with contextlib.redirect_stdout(io.StringIO()):
            code = inputs_tool.main(['extract-check', '--archive', str(self.archive), '--sha256', sha(self.archive),
                                     '--expected', sha(self.archive), '--profile', str(self.profile),
                                     '--output', str(self.work / 'cli'), '--report', str(report)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(report.read_text())['archive_sha256'], sha(self.archive))


if __name__ == '__main__':
    unittest.main()
