#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One fail-closed required status over every CI job, including matrix results."""
import json
import os

REQUIRED = {'quality', 'native', 'dco', 'dependencies', 'codeql'}


def evaluate(needs, event):
    if event not in {'push', 'pull_request', 'workflow_dispatch'}:
        return ['unsupported workflow event']
    if set(needs) != REQUIRED:
        return ['CI job set is incomplete or unexpected']
    failures = []
    for name, job in sorted(needs.items()):
        status = job.get('result')
        allowed = {'success'}
        if name == 'dependencies' and event != 'pull_request':
            allowed.add('skipped')
        if status not in allowed:
            failures.append(f'{name}: {status}')
    return failures


if __name__ == '__main__':
    failures = evaluate(json.loads(os.environ['NEEDS_JSON']), os.environ['GITHUB_EVENT_NAME'])
    print('\n'.join(failures) if failures else 'All required CI jobs passed')
    raise SystemExit(int(bool(failures)))
