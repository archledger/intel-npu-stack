# SPDX-License-Identifier: Apache-2.0
import subprocess
import tempfile
import unittest
from pathlib import Path

from check_contributions import check_range


class ContributionChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git('init', '-q')
        self.base = self.commit('Initial\n\nSigned-off-by: Fixture Author <fixture@example.invalid>')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], text=True).strip()

    def commit(self, message):
        path = self.repo / 'file'
        path.write_text(path.read_text() + 'x' if path.exists() else 'x')
        self.git('add', 'file')
        self.git('-c', 'user.name=Fixture Author', '-c', 'user.email=fixture@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', message)
        return self.git('rev-parse', 'HEAD')

    def test_signed_off_author_passes(self):
        head = self.commit('Change\n\nSigned-off-by: Fixture Author <fixture@example.invalid>')
        self.assertEqual(check_range(self.repo, self.base, head), [])

    def test_missing_or_foreign_signoff_fails(self):
        for message in ['Missing', 'Foreign\n\nSigned-off-by: Someone Else <other@example.invalid>']:
            head = self.commit(message)
            self.assertTrue(check_range(self.repo, self.base, head))

    def test_quoted_body_is_not_a_trailer(self):
        head = self.commit('Example\n\nSigned-off-by: Fixture Author <fixture@example.invalid>\n\nThis is only a quotation.')
        self.assertTrue(check_range(self.repo, self.base, head))

    def test_only_requested_range_is_checked(self):
        bad = self.commit('Unsigned earlier contribution')
        head = self.commit('Corrected scope\n\nSigned-off-by: Fixture Author <fixture@example.invalid>')
        self.assertEqual(check_range(self.repo, bad, head), [])

    def test_initial_push_checks_all_history(self):
        head = self.commit('Missing')
        self.assertTrue(check_range(self.repo, '0' * 40, head))

    def test_revision_options_are_refused(self):
        with self.assertRaises(ValueError):
            check_range(self.repo, '--all', self.base)


if __name__ == '__main__':
    unittest.main()
