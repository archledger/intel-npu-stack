#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fetch or extract the prepared release inputs and check them before any key exists.

  release_inputs.py fetch-check --url URL --sha256 SHA --profile FILE --archive FILE --output DIR [--report FILE]
  release_inputs.py extract-check --archive FILE --sha256 SHA --expected SHA --profile FILE --output DIR
                                  [--report FILE]

fetch-check downloads the tarball over HTTPS only (redirects included), requires
its SHA-256 to equal the dispatch input, extracts it safely and runs the keyless
inputs check of release_sign.py against the selected profile. extract-check
repeats the same for the archive handed between jobs, whose digest must equal
both the dispatch input and the preflight job's output. Safe extraction accepts
only regular files and directories with plain relative names, each at most once,
within size and count limits, and extracts with the tarfile data filter.
Outputs are never overwritten.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import urllib.parse

import release_sign

MAX_ARCHIVE = 4 << 30
MAX_UNPACKED = 8 << 30
MAX_MEMBERS = 20000
DIGEST = re.compile(r'[0-9a-f]{64}')
SEGMENT = re.compile(r'[A-Za-z0-9_+][A-Za-z0-9._+~@-]*')


class InputsRefused(Exception):
    """A release-inputs gate failed; nothing was signed."""


def require(condition, message):
    if not condition:
        raise InputsRefused(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def curl_command(url, output):
    return ['curl', '--disable', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https',
            '--connect-timeout', '30', '--max-time', '600', '--max-filesize', str(MAX_ARCHIVE),
            '--output', str(output), '--', url]


def curl_download(url, output):
    result = subprocess.run(curl_command(url, output), capture_output=True, text=True, check=False,
                            stdin=subprocess.DEVNULL, timeout=900)
    require(result.returncode == 0, 'the release inputs could not be downloaded: ' + result.stderr.strip()[-300:])


def check_url(url):
    parts = urllib.parse.urlsplit(url)
    require(parts.scheme == 'https' and parts.hostname and not parts.username and not parts.password
            and not parts.query and not parts.fragment and len(url) <= 2048,
            'the release inputs URL must be a plain HTTPS URL without credentials or query')


def member_name(member):
    name = member.name[2:] if member.name.startswith('./') else member.name
    return name.rstrip('/') if member.isdir() else name


def safe_members(tar):
    """Regular files and directories with plain relative names, each once, within the limits."""
    members, seen, total = [], set(), 0
    for member in tar.getmembers():
        require(len(members) < MAX_MEMBERS, 'the release inputs archive has too many members')
        name = member_name(member)
        if member.isdir() and name in {'', '.'}:
            continue
        require(member.isreg() or member.isdir(), 'the release inputs may only hold files and directories: '
                + repr(member.name))
        require('\\' not in name and not name.startswith('/')
                and all(SEGMENT.fullmatch(part) for part in name.split('/')),
                'unsafe path in the release inputs: ' + repr(member.name))
        require(name not in seen, 'duplicate path in the release inputs: ' + name)
        seen.add(name)
        total += member.size
        require(total <= MAX_UNPACKED, 'the release inputs unpack beyond the size limit')
        members.append(member)
    return members


def extract(archive, output):
    output = Path(output)
    require(not output.exists(), f'{output} exists; outputs are never overwritten')
    try:
        with tarfile.open(archive, 'r:*') as tar:
            members = safe_members(tar)
            output.mkdir(parents=True)
            tar.extractall(output, members=members, filter='data')
    except tarfile.TarError as error:
        raise InputsRefused('the release inputs archive is not a readable tar: ' + str(error)) from None
    return len(members)


def extract_check(archive, digest, expected, profile, output):
    require(isinstance(digest, str) and DIGEST.fullmatch(digest), 'the inputs SHA-256 must be 64 lowercase hex')
    actual = sha(archive)
    require(actual == digest, 'the release inputs archive does not have the dispatched SHA-256')
    require(actual == expected, 'the release inputs archive differs from the one the preflight job checked')
    members = extract(archive, output)
    try:
        result = release_sign.validate_inputs(output, profile)
    except release_sign.SigningRefused as error:
        raise InputsRefused('the release inputs fail the keyless check: ' + str(error)) from None
    return {'archive_sha256': actual, 'members': members, 'inputs': result}


def fetch_check(url, digest, profile, archive, output, download=curl_download):
    check_url(url)
    require(isinstance(digest, str) and DIGEST.fullmatch(digest), 'the inputs SHA-256 must be 64 lowercase hex')
    archive = Path(archive)
    require(not archive.exists(), f'{archive} exists; outputs are never overwritten')
    download(url, archive)
    require(archive.is_file() and not archive.is_symlink(), 'the release inputs download produced no file')
    return extract_check(archive, digest, digest, profile, output)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=['fetch-check', 'extract-check'])
    parser.add_argument('--url')
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--expected')
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(argv)
    if args.command == 'fetch-check' and args.url is None:
        parser.error('fetch-check requires --url')
    if args.command == 'extract-check' and args.expected is None:
        parser.error('extract-check requires --expected')
    try:
        if args.report is not None:
            require(not args.report.exists() and args.report.parent.is_dir(),
                    'the report must be a new file in an existing directory')
        if args.command == 'fetch-check':
            result = fetch_check(args.url, args.sha256, args.profile, args.archive, args.output)
        else:
            result = extract_check(args.archive, args.sha256, args.expected, args.profile, args.output)
        text = json.dumps(result, indent=2, sort_keys=True) + '\n'
        if args.report is not None:
            with open(args.report, 'x') as stream:
                stream.write(text)
    except (InputsRefused, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f'release inputs {args.command} refused: {error}\n')
    sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
