#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fetch or extract the prepared release inputs and check them before any key exists.

  release_inputs.py dispatch-check --ref REF --version V --url URL --sha256 SHA --profile PATH [--repo DIR]
  release_inputs.py fetch-check --url URL --sha256 SHA --profile FILE --archive FILE --output DIR [--report FILE]
  release_inputs.py extract-check --archive FILE --sha256 SHA --expected SHA --profile FILE --output DIR
                                  [--report FILE]

dispatch-check refuses a dispatch that is not from main, names another version
than the committed trust seam, gives a non-HTTPS inputs URL or a malformed
SHA-256, or selects a profile that is not a tracked .toml file under profiles/
named without '..'. It also validates release/<version>/support-notes.toml as
release_site.py compose does, which runs only after the first signing: a
tracked file of this release and profile whose tested kernels lie inside the
profile's kernel window. Both files are read from the --repo checkout.
fetch-check downloads the tarball over HTTPS only (redirects included), requires
its SHA-256 to equal the dispatch input, extracts it safely and runs the keyless
inputs check of release_sign.py against the selected profile. extract-check
repeats the same for the archive handed between jobs, whose digest must equal
both the dispatch input and the preflight job's output. Before tarfile reads the
(decompressed) tarball, release_tar scans its raw headers: at most MAX_MEMBERS
headers, extension headers included, and only files, directories, GNU long
names and pax headers, whose declared sizes fit MAX_UNPACKED. Safe extraction
then accepts only regular files and directories with plain relative names, each
at most once, with times from 1970 up to MAX_MTIME, within the size limit, and
extracts with the tarfile data filter.
Outputs are never overwritten.
"""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import urllib.parse
import zlib

import release_sign
import release_site
import release_tar
import release_trust

REPO = Path(__file__).resolve().parents[2]

MAX_ARCHIVE = 4 << 30
MAX_UNPACKED = 8 << 30
MAX_MEMBERS = 20000
MAX_MTIME = 1 << 33  # extraction sets member times; this is the year 2242, well inside a 64-bit time_t
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
    """Regular files and directories with plain relative names, each once, within the size limit.

    release_tar.scan has already bounded the raw headers and refused the forms tarfile reads differently, such as a
    regular file named like a directory, so iterating the members reads no more than those headers.
    """
    members, seen, total = [], set(), 0
    for member in tar:
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
        require(0 <= member.mtime < MAX_MTIME,
                'a member of the release inputs has a time outside the supported range: ' + repr(member.name))
        total += member.size
        require(total <= MAX_UNPACKED, 'the release inputs unpack beyond the size limit')
        members.append(member)
    return members


def extract(archive, output):
    output = Path(output)
    require(not output.exists(), f'{output} exists; outputs are never overwritten')
    try:
        with release_tar.open_stream(archive) as stream:
            # The raw headers are bounded first; tarfile then reads the same decompressed bytes.
            release_tar.scan(stream, MAX_MEMBERS, release_tar.INPUT_TYPES, MAX_UNPACKED)
            stream.seek(0)
            with tarfile.open(fileobj=stream, mode='r:') as tar:
                members = safe_members(tar)
                output.mkdir(parents=True)
                tar.extractall(output, members=members, filter='data')
    except release_tar.TarRefused as error:
        raise InputsRefused('the release inputs archive: ' + str(error)) from None
    except (tarfile.TarError, EOFError, zlib.error, lzma.LZMAError) as error:
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


def dispatch_check(repo, ref, version, url, digest, profile):
    """The workflow_dispatch inputs, checked against the committed trust seam before anything is fetched.

    The support notes get the validation release_site compose applies, which runs only after the first signing.
    """
    require(ref == 'refs/heads/main', 'releases are dispatched from refs/heads/main only')
    values = release_trust.check_committed(repo)
    require(version == values['version'], f"release_version must equal the committed VERSION {values['version']}")
    check_url(url)
    require(isinstance(digest, str) and DIGEST.fullmatch(digest), 'the inputs SHA-256 must be 64 lowercase hex')
    relative = Path(profile)
    # An absolute path starts with '/', not 'profiles'.
    require(relative.parts[:1] == ('profiles',) and '..' not in relative.parts and relative.suffix == '.toml',
            'the profile must be a TOML file under profiles/')
    notes = Path('release') / values['version'] / 'support-notes.toml'
    try:
        release_site.tracked(repo, Path(repo) / relative, 'profile')
        tested, _ = release_site.support_notes(
            release_site.load_toml(release_site.tracked(repo, Path(repo) / notes, 'support notes')),
            release_site.load_toml(Path(repo) / relative), {'stack_release': values['version']})
    except release_site.SiteRefused as error:
        raise InputsRefused(str(error)) from None
    return {'version': version, 'base_url': values['base_url'], 'profile': relative.as_posix(),
            'support_notes': notes.as_posix(), 'tested_kernels': [entry['release'] for entry in tested],
            'inputs_url': url, 'inputs_sha256': digest}


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
    parser.add_argument('command', choices=['dispatch-check', 'fetch-check', 'extract-check'])
    parser.add_argument('--repo', type=Path, default=REPO)
    parser.add_argument('--ref')
    parser.add_argument('--version')
    parser.add_argument('--url')
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--expected')
    parser.add_argument('--profile', required=True)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(argv)
    needed = {'dispatch-check': ['ref', 'version', 'url'], 'fetch-check': ['url', 'archive', 'output'],
              'extract-check': ['expected', 'archive', 'output']}[args.command]
    missing = [name for name in needed if getattr(args, name) is None]
    if missing:
        parser.error(args.command + ' requires ' + ', '.join('--' + name for name in missing))
    try:
        if args.report is not None:
            require(not args.report.exists() and args.report.parent.is_dir(),
                    'the report must be a new file in an existing directory')
        if args.command == 'dispatch-check':
            result = dispatch_check(args.repo, args.ref, args.version, args.url, args.sha256, args.profile)
        elif args.command == 'fetch-check':
            result = fetch_check(args.url, args.sha256, args.profile, args.archive, args.output)
        else:
            result = extract_check(args.archive, args.sha256, args.expected, args.profile, args.output)
        text = json.dumps(result, indent=2, sort_keys=True) + '\n'
        if args.report is not None:
            with open(args.report, 'x') as stream:
                stream.write(text)
    except (InputsRefused, release_trust.TrustRefused, OSError, ValueError, KeyError,
            subprocess.SubprocessError) as error:
        parser.exit(1, f'release inputs {args.command} refused: {error}\n')
    sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
