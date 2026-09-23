#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read and pin the installer trust seam (crates/stack-install/src/trust.rs).

The committed seam pins the version, the versioned base URL and the primary
fingerprint; only METADATA_SHA256 stays all zeros. At release time
pin_metadata() replaces exactly that one literal with the SHA-256 of the
signed release.json and proves nothing else changed.

  release_trust.py check [--repo DIR]
  release_trust.py read --field version|base-url|primary-fingerprint [--repo DIR]
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

TRUST_PATH = 'crates/stack-install/src/trust.rs'
KEY_PATH = 'crates/stack-install/src/trust/release-public.asc'
ZEROS = '0' * 64
DIGEST = re.compile(r'[0-9a-f]{64}')

# name -> (pattern, key); each item must occur exactly once. rustfmt may wrap a
# long string literal onto the next line, so whitespace around '=' is flexible.
ITEMS = {
    'VERSION': (r'pub\(crate\) const VERSION: &str =\s*"([0-9]+\.[0-9]+\.[0-9]+)";', 'version'),
    'BASE_URL': (r'pub\(crate\) const BASE_URL: &str =\s*"(https://[A-Za-z0-9./_+-]+/)";', 'base_url'),
    'METADATA_SHA256': (r'pub\(crate\) const METADATA_SHA256: &str =\s*"([0-9a-f]{64})";', 'metadata_sha256'),
    'PRIMARY_FINGERPRINT': (r'pub\(crate\) const PRIMARY_FINGERPRINT: &str =\s*"([0-9A-F]{40})";',
                            'primary_fingerprint'),
    'KEYRING': (r'pub\(crate\) const KEYRING: &\[u8\] = include_bytes!\("(trust/[A-Za-z0-9._-]+)"\);', 'keyring'),
}


class TrustRefused(Exception):
    """The trust seam or a requested change is not acceptable."""


def require(condition, message):
    if not condition:
        raise TrustRefused(message)


def parse_trust(text):
    values = {}
    for name, (pattern, key) in ITEMS.items():
        found = re.findall(pattern, text)
        require(len(found) == 1, f'{name} must be defined exactly once in the trust seam')
        values[key] = found[0]
        require(len(re.findall(r'\bconst ' + name + r'\b', text)) == 1,
                f'{name} must be defined exactly once in the trust seam')
    return values


def pin_metadata(text, digest):
    """Replace the single all-zero METADATA_SHA256 literal; nothing else may change."""
    require(isinstance(digest, str) and DIGEST.fullmatch(digest) is not None and digest != ZEROS,
            'metadata digest must be a lowercase, non-zero SHA-256')
    before = parse_trust(text)
    require(before['metadata_sha256'] == ZEROS, 'the source metadata digest is already pinned')
    literal = '"' + ZEROS + '"'
    require(text.count(literal) == 1, 'expected exactly one all-zero metadata literal')
    pinned = text.replace(literal, '"' + digest + '"')
    after = parse_trust(pinned)
    require(after == {**before, 'metadata_sha256': digest}, 'pinning changed more than the metadata digest')
    changed = [pair for pair in zip(text.splitlines(), pinned.splitlines()) if pair[0] != pair[1]]
    require(len(changed) == 1 and len(text.splitlines()) == len(pinned.splitlines()),
            'pinning must change exactly one line')
    return pinned


def pinned_fingerprint(key_path):
    """Fingerprint of the single primary key in an armored public key file."""
    with tempfile.TemporaryDirectory(prefix='trust-gnupg-') as home:
        listing = subprocess.run(['gpg', '--homedir', home, '--batch', '--with-colons', '--show-keys',
                                  str(key_path)], capture_output=True, text=True, check=False,
                                 env={'PATH': '/usr/bin:/bin', 'HOME': home})
    # A partially readable key file still prints records; only a clean parse counts.
    require(listing.returncode == 0, 'gpg could not inspect the committed release key')
    fingerprints, want = [], False
    for line in listing.stdout.splitlines():
        fields = line.split(':')
        if fields[0] == 'pub':
            want = True
        elif fields[0] == 'fpr' and want:
            fingerprints.append(fields[9])
            want = False
    require(len(fingerprints) == 1, 'the committed release key must contain exactly one primary key')
    return fingerprints[0]


def load_module(name, path):
    """Import a repository script without writing bytecode into the checkout."""
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def repository_url_check(repo):
    return load_module('release_assemble',
                       Path(repo) / 'packaging/fedora/44/repository/assemble.py').repository_url


def check_committed(repo):
    repo = Path(repo)
    values = parse_trust((repo / TRUST_PATH).read_text())
    workspace = tomllib.loads((repo / 'Cargo.toml').read_text())['workspace']['package']['version']
    require(values['version'] == workspace, 'VERSION must equal the workspace package version')
    require(repository_url_check(repo)(values['base_url'], values['version'])
            and values['base_url'].endswith('/' + values['version'] + '/'),
            'BASE_URL must be an immutable HTTPS release URL ending in /<VERSION>/')
    require(values['primary_fingerprint'] == pinned_fingerprint(repo / KEY_PATH),
            'PRIMARY_FINGERPRINT must name the committed release public key')
    require(values['keyring'] == 'trust/release-public.asc', 'KEYRING must be the committed release key')
    require(values['metadata_sha256'] == ZEROS,
            'METADATA_SHA256 must stay all zeros in source; the release build pins the metadata digest')
    return values


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=['check', 'read'])
    parser.add_argument('--repo', type=Path, default=Path('.'))
    parser.add_argument('--field', choices=['version', 'base-url', 'primary-fingerprint'])
    args = parser.parse_args(argv)
    try:
        values = check_committed(args.repo)
    except (TrustRefused, OSError, KeyError, tomllib.TOMLDecodeError) as error:
        parser.exit(1, 'trust seam refused: ' + str(error) + '\n')
    if args.command == 'check':
        print(json.dumps(values, indent=2, sort_keys=True))
    else:
        if args.field is None:
            parser.error('read requires --field')
        print(values[args.field.replace('-', '_')])
    return 0


if __name__ == '__main__':
    sys.exit(main())
