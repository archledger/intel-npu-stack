#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check actual Git trailers for each commit in the supplied immutable range."""
import argparse
from pathlib import Path
import re
import subprocess


def git(repo, *args, input_text=None):
    result = subprocess.run(['git', '-C', str(repo), *args], input=input_text,
                            capture_output=True, text=True, check=True, timeout=30)
    return result.stdout


def check_range(repo, base, head):
    if not all(re.fullmatch(r'[0-9a-f]{40}', value) for value in [base, head]):
        raise ValueError('base and head must be full hexadecimal commit IDs')
    revision = head if base == '0' * 40 else base + '..' + head
    commits = git(repo, 'rev-list', revision).splitlines()
    if len(commits) > 500:
        raise ValueError('commit range exceeds the 500-commit review bound')
    failures = []
    for commit in commits:
        name, email, body = git(repo, 'show', '--no-patch', '--format=%an%x00%ae%x00%B', commit).split('\0', 2)
        trailers = git(repo, 'interpret-trailers', '--parse', input_text=body)
        expected = f'{name.strip()} <{email.strip()}>'.casefold()
        signoffs = [value.strip().casefold() for line in trailers.splitlines()
                    if ':' in line for key, value in [line.split(':', 1)]
                    if key.casefold() == 'signed-off-by']
        if expected not in signoffs:
            failures.append(f'{commit}: missing author-matching Signed-off-by trailer')
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True)
    parser.add_argument('--head', required=True)
    parser.add_argument('--repo', type=Path, default=Path.cwd())
    args = parser.parse_args()
    failures = check_range(args.repo, args.base, args.head)
    for failure in failures:
        print(failure)
    if not failures:
        print('DCO sign-off: PASS')
    return int(bool(failures))


if __name__ == '__main__':
    raise SystemExit(main())
