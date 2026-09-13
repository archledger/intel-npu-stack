#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Run unfiltered rpmlint and verify two reviewed, unchanged notice findings.

No rpmlint configuration is added or changed. The original output and exit code
are retained, separately from the policy decision. Notice verification always
reads the supplied RPM; callers cannot supply a cached verification report.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
# Explicitly approved exceptions: immutable original upstream notice copies.
# A different package, architecture, path, diagnostic or digest needs review.
EXCEPTIONS = (
    ('openvino', 'x86_64', 'incorrect-fsf-address',
     '/usr/share/licenses/openvino/src/plugins/intel_cpu/thirdparty/onednn/third_party/ittnotify/ittptmark64.S',
     '15e6b25d6e6ef3f4f5866423d71d22d7026e4ed0a6a707e7d6777abcf4b620ad'),
    ('intel-npu-driver', 'x86_64', 'incorrect-fsf-address',
     '/usr/share/licenses/intel-npu-driver/linux-uapi/GPL-2.0',
     'f6b78c087c3ebdf0f3c13415070dd480a3f35d8fc76f3d02180a407c1c812f79'),
)
SUMMARY = re.compile(r'[= ]*(\d+) packages and (\d+) specfiles checked; (\d+) errors, '
                     r'(\d+) warnings, (\d+) filtered, (\d+) badness; has taken \d+\.\d+ s[= ]*')


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def assess(stdout, stderr, returncode, inventory, notices):
    """Assess a completed run using freshly verified internal notice evidence."""
    require(returncode in (0, 64), 'rpmlint failed for a reason outside the reviewed errors')
    require(not stderr, 'unexpected rpmlint stderr; review the preserved raw output')
    lines = stdout.decode('utf-8').splitlines()
    require(lines and 'rpmlint: 2.8.0' in lines, 'unrecognized rpmlint version/output')
    summaries = [SUMMARY.fullmatch(line) for line in lines if SUMMARY.fullmatch(line)]
    require(len(summaries) == 1 and SUMMARY.fullmatch(lines[-1]), 'missing or incomplete rpmlint summary')
    packages, specs, errors, warnings, filtered, badness = map(int, summaries[0].groups())
    require(packages == len(inventory) > 0 and specs == 0, 'rpmlint package count differs')
    error_lines = [line for line in lines if ': E:' in line]
    require(errors == len(error_lines), 'rpmlint error count differs')
    require(warnings == sum(': W:' in line for line in lines), 'rpmlint warning count differs')
    require(returncode == (64 if errors else 0), 'rpmlint status contradicts its findings')
    identities = {r['package']+'.'+r['architecture']: r for r in inventory}
    require(len(identities) == len(inventory), 'duplicate RPM identity')
    reviewed = []
    for line in error_lines:
        matches = [entry for entry in EXCEPTIONS
                   if line == entry[0]+'.'+entry[1]+': E: '+entry[2]+' '+entry[3]]
        require(len(matches) == 1, 'unreviewed lint error: '+line)
        package, arch, diagnostic, path, digest = matches[0]
        record = identities.get(package+'.'+arch)
        verified = notices.get(package)
        require(record and verified and verified.get('package') == package,
                'complete notice verification is missing')
        require(verified['rpm_sha256'] == record['sha256'], 'notice verification belongs to a different RPM')
        require(verified['verified_notices'] == len(verified['notice_sha256']) > 0,
                'incomplete notice verification inventory')
        relative = path.removeprefix('/usr/share/licenses/'+package+'/')
        require(verified['notice_sha256'].get(relative) == digest, 'reviewed notice bytes differ')
        entry = dict(package=package, architecture=arch, diagnostic=diagnostic, path=path, sha256=digest,
                     rpm_sha256=record['sha256'])
        require(entry not in reviewed, 'duplicate reviewed lint finding')
        reviewed.append(entry)
    # rpmlint 2.8.0's observed notice error contributes one point. Threshold
    # failures (66), promoted warnings (65) and unexplained scores stay blocked.
    require(not errors or badness == len(reviewed), 'unexplained lint badness')
    return dict(lint_policy_passed=True, raw_exit_code=returncode, errors=errors, warnings=warnings,
                filtered=filtered, badness=badness, reviewed_exceptions=reviewed)


def audit(rpms, manifest, output):
    output.mkdir()  # Keep every run separate; never overwrite prior evidence.
    report = {'lint_policy_passed': False, 'raw_exit_code': None, 'reviewed_exceptions': []}
    try:
        require(rpms and len(set(rpms)) == len(rpms), 'nonempty unique RPM paths required')
        inventory = []
        for rpm in rpms:
            require(rpm.is_file() and rpm.suffix == '.rpm', 'RPM file required')
            result = subprocess.run(['rpm', '--noplugins', '-qp', '--queryformat',
                                     '%{NAME}\n%{ARCH}\n%{SOURCEPACKAGE}', str(rpm)],
                                    capture_output=True, text=True, check=True, timeout=120)
            package, architecture, source_package = result.stdout.splitlines()
            require(source_package in ('1', '(none)'), 'unrecognized RPM source-package marker')
            # A source RPM retains its target ARCH header. rpmlint identifies it
            # as .src, and its archived inputs are not an installed notice tree.
            if source_package == '1':
                architecture = 'src'
            inventory.append(dict(path=str(rpm), package=package, architecture=architecture, sha256=sha(rpm)))
        report['rpms'] = inventory
        command = ['rpmlint', *map(str, rpms)]
        report['command'] = command
        with (output/'stdout.log').open('xb') as stdout, (output/'stderr.log').open('xb') as stderr:
            result = subprocess.run(command, stdout=stdout, stderr=stderr,
                                    env=dict(os.environ, LC_ALL='C', LANG='C'))
        report['raw_exit_code'] = result.returncode
        report['stdout_sha256'] = sha(output/'stdout.log')
        report['stderr_sha256'] = sha(output/'stderr.log')
        require((output/'stdout.log').stat().st_size <= 16_777_216, 'lint output exceeds review bound')
        require((output/'stderr.log').stat().st_size <= 1_048_576, 'lint stderr exceeds review bound')
        raw = (output/'stdout.log').read_bytes()
        sys.stdout.buffer.write(raw)
        sys.stdout.flush()
        notices = {}
        if result.returncode == 64:
            spec = importlib.util.spec_from_file_location('notice_rpm', HERE/'rpm/verify-provider-notice-rpm.py')
            verifier = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(verifier)
            report['notice_manifest_sha256'] = sha(manifest)
            for row, rpm in zip(inventory, rpms):
                if any((row['package'], row['architecture']) == entry[:2] for entry in EXCEPTIONS):
                    notices[row['package']] = verifier.verify(rpm, manifest)
            report['notice_verification'] = notices
        decision = assess(raw, (output/'stderr.log').read_bytes(), result.returncode, inventory, notices)
        require(all(row['sha256'] == sha(rpm) for row, rpm in zip(inventory, rpms)), 'RPM changed during lint')
        if notices:
            require(report['notice_manifest_sha256'] == sha(manifest), 'notice manifest changed during lint')
        report.update(decision)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report['failure'] = str(error)
    finally:
        (output/'result.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('rpms', nargs='+', type=Path)
    args = parser.parse_args()
    result = audit(args.rpms, args.manifest, args.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    sys.exit(0 if result['lint_policy_passed'] else 1)
