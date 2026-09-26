#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Seal and check the artifacts that release jobs hand to each other.

  release_artifact.py seal DIR                 # writes DIR/ARTIFACT-SHA256SUMS, prints digest=<sha256>
  release_artifact.py check DIR --digest SHA   # the sums file has SHA and lists exactly DIR's files

The producing job seals its artifact directory, which must hold at least one
file, and publishes the SHA-256 of ARTIFACT-SHA256SUMS as a job output. The
consuming job checks the downloaded directory against that output: the sums
file must have the digest, and it must list exactly the regular files present,
each with its digest. Symlinks and special files are refused.
download-artifact's own digest check is a second, independent layer.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

SUMS = 'ARTIFACT-SHA256SUMS'


class ArtifactRefused(Exception):
    """A handoff check failed."""


def require(condition, message):
    if not condition:
        raise ArtifactRefused(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inventory(root):
    """Regular files under root (except the sums file), bytewise sorted; refuses symlinks and special files."""
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), f'{root} is not a directory')
    files = []

    def unreadable(error):
        raise ArtifactRefused(f'artifact directory cannot be read: {error.filename}')
    for directory, dirnames, filenames in os.walk(root, onerror=unreadable):
        for name in dirnames + filenames:
            path = Path(directory) / name
            mode = os.lstat(path).st_mode
            require(not stat.S_ISLNK(mode), 'symlink in the artifact: ' + str(path.relative_to(root)))
            if name in filenames:
                require(stat.S_ISREG(mode), 'special file in the artifact: ' + str(path.relative_to(root)))
                relative = path.relative_to(root).as_posix()
                require('\n' not in relative, 'newline in an artifact path')
                if relative != SUMS:
                    files.append(relative)
    return sorted(files, key=str.encode)


def seal(root):
    root = Path(root)
    require(not (root / SUMS).exists(), f'{root} is already sealed')
    files = inventory(root)
    require(files, f'{root} holds no files')
    with open(root / SUMS, 'x') as stream:
        stream.write(''.join(f'{sha(root / relative)}  {relative}\n' for relative in files))
    return sha(root / SUMS)


def check(root, digest):
    root = Path(root)
    require(re.fullmatch(r'[0-9a-f]{64}', digest or '') is not None, 'the expected digest must be 64 lowercase hex')
    require((root / SUMS).is_file() and sha(root / SUMS) == digest,
            f'{SUMS} is not the one the producing job sealed')
    listed = {}
    for line in (root / SUMS).read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        require(match is not None and match.group(2) not in listed, f'malformed {SUMS}')
        listed[match.group(2)] = match.group(1)
    files = inventory(root)
    require(set(files) == set(listed), f'the artifact files differ from {SUMS}: missing '
            f'{sorted(set(listed) - set(files))}, unexpected {sorted(set(files) - set(listed))}')
    for relative in files:
        require(sha(root / relative) == listed[relative], 'artifact file changed in transit: ' + relative)
    return len(files)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=['seal', 'check'])
    parser.add_argument('directory', type=Path)
    parser.add_argument('--digest')
    args = parser.parse_args(argv)
    try:
        if args.command == 'seal':
            print('digest=' + seal(args.directory))
        else:
            require(args.digest is not None, 'check requires --digest')
            print(f'{check(args.directory, args.digest)} files match {SUMS}')
    except (ArtifactRefused, OSError) as error:
        parser.exit(1, f'artifact {args.command} refused: {error}\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
