# SPDX-License-Identifier: Apache-2.0
import unittest

from check_gate import evaluate


class GateChecks(unittest.TestCase):
    def results(self):
        return {name: {'result': 'success'} for name in ['quality', 'native', 'dco', 'dependencies', 'codeql']}

    def test_all_success_passes(self):
        self.assertEqual(evaluate(self.results(), 'pull_request'), [])

    def test_failed_cancelled_or_skipped_required_job_fails(self):
        for status in ['failure', 'cancelled', 'skipped']:
            results = self.results()
            results['quality']['result'] = status
            self.assertTrue(evaluate(results, 'pull_request'))

    def test_dependency_skip_only_allowed_without_pull_request(self):
        results = self.results()
        results['dependencies']['result'] = 'skipped'
        self.assertEqual(evaluate(results, 'push'), [])
        self.assertTrue(evaluate(results, 'pull_request'))

    def test_missing_job_cannot_pass(self):
        results = self.results()
        del results['native']
        self.assertTrue(evaluate(results, 'pull_request'))

    def test_unknown_event_cannot_pass(self):
        self.assertTrue(evaluate(self.results(), 'pull_request_target'))


if __name__ == '__main__':
    unittest.main()
