#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Guest orchestration regressions without booting a machine."""
import importlib.util
from pathlib import Path
import subprocess
import io
import json
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('guest', Path(__file__).with_name('guest-lifecycle.py'))
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class GuestContract(unittest.TestCase):
    def test_bootstrap_refusal_exercises_generated_primary_command(self):
        with patch.object(guest, 'fetch') as fetch, patch.object(guest, 'run', side_effect=[
                {'exit': 2, 'stderr': 'root refused'},
                {'exit': 10, 'stderr': 'INSTALL_PROFILE_UNSUPPORTED'}]) as run:
            guest.scenario_bootstrap_refusal('server', Path('/tmp'))
        self.assertIn('/guest/primary-command.txt', [call.args[1] for call in fetch.call_args_list])
        self.assertIn('/tmp/primary-command.txt', run.call_args.args[1])

    def test_corrupted_rpm_success_cannot_pass(self):
        metadata = {'packages': [{'name': 'intel-npu-stack-tools', 'filename': 'tools.rpm'}]}
        with patch.object(guest.urllib.request, 'urlopen', return_value=io.BytesIO(json.dumps(metadata).encode())), \
             patch.object(guest, 'fetch'), patch.object(guest, 'control'), \
             patch.object(guest, 'inventory', return_value=['unchanged']), \
             patch.object(guest, 'run', return_value={'exit': 0, 'stdout': ''}):
            with self.assertRaises(AssertionError):
                guest.scenario_package_corruption('https://example.invalid', Path('/tmp'))

    def test_exact_rollback_inventory_refuses_missing_wrong_or_duplicate_provider(self):
        expected = [{'name': 'openvino', 'nevr': '0:2025.1.0-14.fc44', 'arch': 'x86_64'}]
        valid = ['openvino|0:2025.1.0-14.fc44|x86_64|100', 'unrelated|0:1-1|noarch|1']
        guest.verify_expected_packages(expected, valid)
        for actual in [[], ['openvino|0:2026.2.0-1|x86_64|100'], valid+[valid[0]]]:
            with self.assertRaises(AssertionError):
                guest.verify_expected_packages(expected, actual)

    def test_reboot_requires_changed_boot_and_identical_packages(self):
        record = {'boot_id_before': 'old', 'after': ['pkg|1|x86_64|10']}
        for boot, packages in [('old', record['after']), ('new', [])]:
            with self.assertRaises(AssertionError):
                guest.resume_reboot_record(record, boot, packages)
        self.assertTrue(guest.resume_reboot_record(record, 'new', record['after'])['reboot_verified'])

    def test_removal_leftovers_fail_the_scenario(self):
        records = []
        with patch.dict(guest.SCENARIOS, {'removal': lambda *_: {'remaining_stack': ['leftover']}}), \
             patch.object(guest.Path, 'mkdir'), \
             patch.object(guest, 'control', side_effect=lambda server, path, record: records.append(record.copy())):
            result = guest.main(['--scenario', 'removal', '--server', 'https://example.invalid', '--fingerprint', 'test'])
        self.assertEqual(result, 1)
        self.assertFalse(records[0]['passed'])

    def test_dry_run_refuses_inventory_changes(self):
        with patch.object(guest, 'fetch'), patch.object(guest, 'run', return_value={'exit': 0}), \
             patch.object(guest, 'inventory', side_effect=[['before'], ['after']]):
            with self.assertRaises(AssertionError):
                guest.scenario_dry_run('server', Path('/tmp'))

    def test_repeat_refuses_inventory_changes(self):
        baseline = {'steps': [], 'after': ['unchanged']}
        with patch.object(guest, 'scenario_install', return_value=baseline), \
             patch.object(guest, 'run', return_value={'exit': 0, 'stdout': 'Nothing to install'}), \
             patch.object(guest, 'inventory', return_value=['different']):
            with self.assertRaises(AssertionError):
                guest.scenario_repeat('server', Path('/tmp'))

    def test_harness_runs_as_normal_user(self):
        with patch.object(guest.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'ok', '')) as run:
            result = guest.run('dry-run', ['/var/tmp/guest-harness', '--dry-run'], expect=0)
        expected = ['sudo', '-u', 'runner', '--', '/var/tmp/guest-harness', '--dry-run']
        self.assertEqual(run.call_args.args[0], expected)
        self.assertEqual(result['argv'], expected)

    def test_failure_records_reason_before_result_is_posted(self):
        records = []
        with patch.dict(guest.SCENARIOS, {'install': lambda *_: (_ for _ in ()).throw(AssertionError('native exit20'))}), \
             patch.object(guest.Path, 'mkdir'), \
             patch.object(guest, 'control', side_effect=lambda server, path, record: records.append(record.copy())):
            result = guest.main(['--scenario', 'install', '--server', 'https://example.invalid', '--fingerprint', 'test'])
        self.assertEqual(result, 1)
        self.assertFalse(records[0]['passed'])
        self.assertIn('native exit20', records[0]['error'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
