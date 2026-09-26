#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Contract for sealing and checking the artifacts passed between release jobs."""
import contextlib
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import release_artifact as artifact


class Handoff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='artifact-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'signed-release'
        (self.root / 'release-tree/packages').mkdir(parents=True)
        (self.root / 'release-tree/release.json').write_text('{}\n')
        (self.root / 'release-tree/packages/a.rpm').write_bytes(b'rpm')
        (self.root / 'records').mkdir()
        (self.root / 'records/signed-identity.json').write_text('{}\n')

    def test_seal_lists_every_file_and_check_accepts_the_same_bytes(self):
        digest = artifact.seal(self.root)
        sums = (self.root / artifact.SUMS).read_text().splitlines()
        self.assertEqual([line.split('  ')[1] for line in sums],
                         ['records/signed-identity.json', 'release-tree/packages/a.rpm', 'release-tree/release.json'])
        self.assertEqual(digest, hashlib.sha256((self.root / artifact.SUMS).read_bytes()).hexdigest())
        self.assertEqual(artifact.check(self.root, digest), 3)

    def test_check_refuses_any_difference(self):
        digest = artifact.seal(self.root)
        cases = {
            'digest of the sums file': lambda: None,
            'changed file': lambda: (self.root / 'release-tree/release.json').write_text('{"changed": 1}\n'),
            'extra file': lambda: (self.root / 'records/extra.json').write_text('{}\n'),
            'missing file': lambda: (self.root / 'records/signed-identity.json').unlink(),
            'symlink': lambda: (self.root / 'link').symlink_to(self.root / 'release-tree/release.json'),
        }
        for label, damage in cases.items():
            with self.subTest(label):
                work = Path(self.tmp.name) / label.replace(' ', '-')
                shutil.copytree(self.root, work, symlinks=True)
                self.root, original = work, self.root
                try:
                    damage()
                    expected = '0' * 64 if label == 'digest of the sums file' else digest
                    with self.assertRaises(artifact.ArtifactRefused):
                        artifact.check(work, expected)
                finally:
                    self.root = original

    def test_seal_refuses_a_sealed_directory_or_a_symlink(self):
        artifact.seal(self.root)
        with self.assertRaisesRegex(artifact.ArtifactRefused, 'already sealed'):
            artifact.seal(self.root)
        other = Path(self.tmp.name) / 'other'
        other.mkdir()
        (other / 'link').symlink_to(self.root)
        with self.assertRaisesRegex(artifact.ArtifactRefused, 'symlink'):
            artifact.seal(other)

    def test_seal_and_check_refuse_a_special_file_without_reading_it(self):
        # Opening a pipe to read it waits for a writer, so a producing step that hashed one would hang until its job
        # times out. The seal runs as the workflow runs it, in a process of its own with a time limit.
        digest = artifact.seal(self.root)
        os.mkfifo(self.root / 'records/pipe')
        with self.assertRaisesRegex(artifact.ArtifactRefused, '^special file in the artifact: records/pipe$'):
            artifact.check(self.root, digest)
        (self.root / artifact.SUMS).unlink()
        result = subprocess.run(['python3', str(Path(artifact.__file__)), 'seal', str(self.root)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (1, '', 'artifact seal refused: special file in the artifact: records/pipe\n'))
        self.assertFalse((self.root / artifact.SUMS).exists())

    def test_seal_refuses_a_directory_without_files(self):
        # Its empty sums file would pass the consuming job's check as well.
        empty = Path(self.tmp.name) / 'empty'
        (empty / 'records').mkdir(parents=True)
        with self.assertRaisesRegex(artifact.ArtifactRefused, 'holds no files'):
            artifact.seal(empty)
        self.assertFalse((empty / artifact.SUMS).exists())

    def test_command_line_prints_a_github_output_line(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(artifact.main(['seal', str(self.root)]), 0)
        line = out.getvalue().strip()
        self.assertRegex(line, r'^digest=[0-9a-f]{64}$')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(artifact.main(['check', str(self.root), '--digest', line.split('=')[1]]), 0)


if __name__ == '__main__':
    unittest.main()
