#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Guest-side lifecycle scenario engine for the disposable Fedora 44 VMs.

Runs INSIDE the virtual machine from the cloud-init seed. It executes one
scenario against the pinned test release served by the loopback fixture
server, records exact command exits and before/after RPM inventories, and
POSTs the result back. The public installer binary is only used for the
bootstrap-refusal scenario: a VM has no NPU, so the real installer must
refuse. Successful orchestration scenarios use the test-only guest harness
with synthetic allowlisted facts; that harness authorizes nothing outside
these throwaway machines.
"""
from pathlib import Path
import argparse
import json
import os
import shlex
import hashlib
import shutil
import subprocess
import sys
import urllib.request

GUEST_USER = 'runner'
# The profile stays a candidate; only the experimental channel with explicit
# risk acknowledgement may select it, exactly like any real machine.
EXPERIMENTAL = ['--channel', 'experimental', '--accept-experimental-risk']
EXPECTED_INSTALL_COUNT = 15  # runtime + profile packages of the default selection
STACK_PACKAGES = ['intel-npu-stack', 'intel-npu-stack-profile', 'intel-npu-stack-tools']


def inventory():
    result = subprocess.run(
        ['rpm', '-qa', '--qf', '%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}|%{INSTALLTIME}\\n'],
        capture_output=True, text=True, check=True)
    return sorted(result.stdout.splitlines())


def fetch(server, path, target):
    request = urllib.request.Request(server+path)
    with urllib.request.urlopen(request, timeout=60) as response, open(target, 'wb') as stream:
        shutil.copyfileobj(response, stream, length=1024*1024)
    target.chmod(0o755)


def control(server, path, payload=None):
    request = urllib.request.Request(
        server+path, data=json.dumps(payload or {}).encode(), method='POST')
    with urllib.request.urlopen(request, timeout=60) as response:
        response.read()


def run(name, argv, expect=None):
    if Path(argv[0]).name == 'guest-harness':
        argv = ['sudo', '-u', GUEST_USER, '--', *argv]
    result = subprocess.run(argv, capture_output=True, text=True)
    record = {'argv': [str(argument) for argument in argv], 'exit': result.returncode,
              'stdout': result.stdout[-8000:], 'stderr': result.stderr[-8000:]}
    if expect is not None and result.returncode != expect:
        subprocess.run(['sh', '-c',
                        'for d in /tmp/intel-npu-prepare-*; do [ -d "$d" ] || continue; '
                        'echo "== DIAG $d"; find "$d" -maxdepth 2 -type f | head -10; done'],
                       timeout=60)
        assert result.returncode == expect, (name, record)
    return record


def scenario_bootstrap_refusal(server, work):
    fetch(server, '/guest/install.sh', work/'install.sh')
    fetch(server, '/guest/primary-command.txt', work/'primary-command.txt')
    # The public bootstrap runs as a normal user; cloud-init executes as root,
    # and the installer correctly refuses root before anything else. Running
    # via the unprivileged VM user reaches the intended platform refusal.
    steps = [run('bootstrap-as-root', ['sh', str(work/'install.sh'), '--dry-run']),
             run('bootstrap-as-user',
                 ['sudo', '-u', GUEST_USER, '--', 'sh', str(work/'primary-command.txt'), '--dry-run'])]
    user_refusal = steps[-1]
    assert user_refusal['exit'] != 0, user_refusal
    assert 'INSTALL_PLATFORM' in user_refusal['stderr'] or \
        'INSTALL_PROFILE_UNSUPPORTED' in user_refusal['stderr'], user_refusal['stderr']
    return {'steps': steps, 'refused': True}




def scenario_dry_run(server, work):
    fetch(server, '/guest/guest-harness', work/'guest-harness')
    before = inventory()
    steps = [run('dry-run', [str(work/'guest-harness'), '--dry-run', '--yes',
                          *EXPERIMENTAL], expect=0)]
    after = inventory()
    assert before == after, 'dry run changed installed inventory'
    return {'steps': steps, 'before': before, 'after': after}


def scenario_install(server, work, repeat=False, with_devel=False):
    fetch(server, '/guest/guest-harness', work/'guest-harness')
    before = inventory()
    steps = [run('install', [str(work/'guest-harness'), '--yes', *EXPERIMENTAL,
                            *(['--with-devel'] if with_devel else [])], expect=0)]
    after = inventory()
    added = sorted(set(after)-set(before))
    count = 16 if with_devel else 15
    assert f'verified {count} release package(s)' in steps[0]['stdout']
    return {'steps': steps, 'before': before, 'after': after, 'added': added,
            'verified_install_count': count}


def scenario_repeat(server, work):
    record = scenario_install(server, work)
    record['steps'].append(run('repeat', [str(work/'guest-harness'), '--yes', *EXPERIMENTAL], expect=0))
    record['added_after_repeat'] = sorted(
        set(inventory())-set(record['after'])) == []
    record['after_repeat'] = inventory()
    assert record['after_repeat'] == record['after'], 'repeat changed installed inventory'
    assert 'Nothing to install' in record['steps'][-1]['stdout']
    return record


def scenario_corruption(server, work, target):
    fetch(server, '/guest/guest-harness', work/'guest-harness')
    steps = []
    steps.append(run('baseline', [str(work/'guest-harness'), '--yes', *EXPERIMENTAL], expect=0))
    control(server, '/corrupt', {'target': target})
    try:
        steps.append(run('corrupted', [str(work/'guest-harness'), '--yes', *EXPERIMENTAL]))
    finally:
        control(server, '/restore')
    return {'steps': steps}


def scenario_package_corruption(server, work):
    with urllib.request.urlopen(server+'/intel-npu-stack/0.1.0/fedora/44/x86_64/release.json', timeout=60) as response:
        manifest = json.load(response)
    package = next(row for row in manifest['packages'] if row['name'] == 'intel-npu-stack-tools')
    target = 'packages/'+package['filename']
    fetch(server, '/guest/guest-harness', work/'guest-harness')
    before = inventory()
    steps = [run('baseline-dry-run', [str(work/'guest-harness'), '--dry-run', '--yes', *EXPERIMENTAL], expect=0)]
    control(server, '/corrupt', {'target': target})
    try:
        steps.append(run('corrupted-rpm', [str(work/'guest-harness'), '--yes', *EXPERIMENTAL]))
        assert steps[-1]['exit'] != 0, 'corrupted RPM was accepted'
        after_refusal = inventory()
        assert before == after_refusal, 'corrupted RPM attempt changed installed inventory'
    finally:
        control(server, '/restore')
    steps.append(run('restored-install', [str(work/'guest-harness'), '--yes', *EXPERIMENTAL], expect=0))
    assert 'verified 15 release package(s)' in steps[-1]['stdout']
    return {'steps': steps, 'corrupted_target': target, 'before': before,
            'after_refusal': after_refusal, 'after_recovery': inventory()}


def scenario_reboot(server, work):
    record = scenario_install(server, work)
    assert 'Reboot required before npu_firmware becomes active.' in record['steps'][0]['stdout']
    record['boot_id_before'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    (work/'reboot-state.json').write_text(json.dumps(record))
    command = shlex.join(['python3', '/usr/local/bin/guest-lifecycle.py', *sys.argv[1:], '--resume-reboot'])
    unit = Path('/etc/systemd/system/intel-npu-vm-resume.service')
    unit.write_text('[Unit]\nDescription=Disposable NPU lifecycle reboot evidence\n'
                    'Wants=network-online.target\nAfter=network-online.target\n'
                    '[Service]\nType=oneshot\nExecStart='+command+'\n'
                    '[Install]\nWantedBy=multi-user.target\n')
    run('enable-reboot-evidence', ['systemctl', 'enable', 'intel-npu-vm-resume.service'], expect=0)
    record['stage'] = 'reboot-requested'
    return record


def resume_reboot_record(record, boot_id, packages):
    assert boot_id != record['boot_id_before'], 'guest did not reboot'
    assert packages == record['after'], 'installed inventory changed across reboot'
    return {**record, 'boot_id_after': boot_id, 'after_reboot': packages, 'reboot_verified': True}


def scenario_removal(server, work):
    record = scenario_install(server, work)
    steps = record['steps']
    with urllib.request.urlopen(server+'/intel-npu-stack/0.1.0/fedora/44/x86_64/release.json', timeout=60) as response:
        manifest = json.load(response)
    names = [row['name'] for row in manifest['packages'] if row['role'] in {'runtime', 'profile'}]
    steps.append(run('remove', ['sudo', 'dnf5', '--assumeyes', 'remove',
                                *names], expect=0))
    after = inventory()
    remaining = [line for line in after
                 if line.split('|')[0] in names]
    return {'steps': steps, 'after': after, 'remaining_stack': remaining,
            'remaining_assertion': not remaining}


def verify_expected_packages(expected, actual):
    for row in expected:
        identities = [line.split('|')[1:3] for line in actual
                      if line.split('|')[0] == row['name']]
        assert identities == [[row['nevr'], row.get('arch', 'x86_64')]], (row['name'], identities)


def scenario_rollback(server, work):
    # Establish the actual old Fedora baseline first. A fresh Cloud image is
    # not a rollback baseline for these providers and their dependency set.
    with urllib.request.urlopen(server+'/guest/fedora-inputs.json', timeout=60) as response:
        fedora = json.load(response)
    assert fedora['passed'] and fedora['count'] == len(fedora['packages'])
    rollback_index = json.loads(urllib.request.urlopen(
        server+'/intel-npu-stack/0.1.0/fedora/44/x86_64/'
        'evidence/rollback/rollback-index.json', timeout=60).read())
    for rows, prefix in [(fedora['packages'], '/fedora-inputs/'),
                         (rollback_index, '/intel-npu-stack/0.1.0/fedora/44/x86_64/evidence/rollback/')]:
        for row in rows:
            filename = row['filename']
            assert '/' not in filename and '..' not in filename and filename.endswith('.rpm')
            target = work/filename
            fetch(server, prefix+filename, target)
            with target.open('rb') as stream:
                assert hashlib.file_digest(stream, 'sha256').hexdigest() == row['sha256'], filename
    baseline_argv = ['dnf5', '--assumeyes', '--setopt=localpkg_gpgcheck=True',
                     '--setopt=install_weak_deps=False', '--disable-repo=*', 'install',
                     *[str(work/row['filename']) for row in fedora['packages']+rollback_index]]
    baseline_step = run('old-fedora-baseline', baseline_argv, expect=0)
    old = inventory()
    verify_expected_packages(rollback_index, old)
    record = scenario_install(server, work, with_devel=True)
    steps = [baseline_step, *record['steps']]
    steps.append(run('remove-version-pins', ['dnf5', '--assumeyes',
                     '--setopt=clean_requirements_on_remove=False', 'remove',
                     'intel-npu-stack', 'intel-npu-stack-profile', 'intel-npu-stack-tools',
                     'intel-npu-stack-firmware'], expect=0))
    argv = ['sudo', 'dnf5', '--assumeyes', '--disablerepo=*',
            '--setopt=localpkg_gpgcheck=True', 'downgrade',
            *[str(work/row['filename']) for row in rollback_index]]
    steps.append(run('rollback', argv, expect=0))
    after = inventory()
    verify_expected_packages(rollback_index, after)
    # RPM import adds one public-key record; payload identities must otherwise
    # exactly match the old baseline. Record installtimes separately as evidence.
    identities = lambda rows: sorted('|'.join(line.split('|')[:3]) for line in rows
                                     if line.split('|')[0] != 'gpg-pubkey')
    assert identities(old) == identities(after), 'rollback changed the baseline package set'
    restored = {row['name']: row['nevr'] for row in rollback_index}
    return {'steps': steps, 'old_baseline': old, 'after_install': record['after'],
            'after': after, 'restored_expected': restored, 'verified_install_count': 16}


def scenario_upgrade(server, work):
    record = scenario_rollback(server, work)
    fetch(server, '/guest/guest-harness', work/'guest-harness')
    record['steps'].append(run('upgrade', [str(work/'guest-harness'), '--yes', *EXPERIMENTAL,
                                         '--with-devel'], expect=0))
    record['after_upgrade'] = inventory()
    with urllib.request.urlopen(server+'/intel-npu-stack/0.1.0/fedora/44/x86_64/release.json', timeout=60) as response:
        manifest = json.load(response)
    verify_expected_packages(manifest['packages'], record['after_upgrade'])
    assert 'verified 16 release package(s)' in record['steps'][-1]['stdout']
    return record


SCENARIOS = {
    'bootstrap-refusal': scenario_bootstrap_refusal,
    'dry-run': scenario_dry_run,
    'install': scenario_install,
    'repeat': scenario_repeat,
    'corruption': lambda server, work: scenario_corruption(server, work, 'release.json'),
    'repomd-corruption': lambda server, work: scenario_corruption(server, work,
                                                                  'repodata/repomd.xml'),
    'package-corruption': scenario_package_corruption,
    'reboot': scenario_reboot,
    'removal': scenario_removal,
    'rollback': scenario_rollback,
    'upgrade': scenario_upgrade,
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', required=True)
    parser.add_argument('--server', required=True)
    parser.add_argument('--fingerprint', required=True)
    parser.add_argument('--resume-reboot', action='store_true')
    args = parser.parse_args(argv)
    work = Path('/var/tmp/intel-npu-scenario')
    work.mkdir(parents=True, exist_ok=True)
    record = {'schema_version': 1, 'scenario': args.scenario, 'passed': False,
              'fingerprint': args.fingerprint}
    try:
        if args.resume_reboot:
            outcome = resume_reboot_record(
                json.loads((work/'reboot-state.json').read_text()),
                Path('/proc/sys/kernel/random/boot_id').read_text().strip(), inventory())
        else:
            outcome = SCENARIOS[args.scenario](args.server, work)
        record.update(outcome)
        if outcome.get('stage') == 'reboot-requested':
            control(args.server, '/scenario-result', record)
            run('reboot', ['systemctl', 'reboot'], expect=0)
            return 0
        install_steps = [step for step in outcome.get('steps', [])
                         if any(Path(arg).name == 'guest-harness' for arg in step['argv'])
                         and '--yes' in step['argv'] and '--dry-run' not in step['argv']]
        if args.scenario in {'install', 'repeat', 'reboot', 'upgrade'}:
            assert f"verified {outcome.get('verified_install_count', 15)} release package(s)" in install_steps[0]['stdout'], \
                install_steps[0]['stdout']
        if args.scenario in {'bootstrap-refusal'}:
            assert outcome['steps'][0]['exit'] not in (0,), 'refusal scenario succeeded'
        if args.scenario in {'corruption', 'repomd-corruption'}:
            assert outcome['steps'][-1]['exit'] != 0, 'corrupted release was accepted'
        if args.scenario == 'removal':
            assert not outcome['remaining_stack'], 'stack packages remain installed'
        record['passed'] = True
    except Exception as error:
        record['error'] = str(error)
    finally:
        try:
            control(args.server, '/scenario-result', record)
        except OSError:
            pass
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
