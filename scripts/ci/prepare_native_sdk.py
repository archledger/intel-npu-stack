#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Assemble a private CI SDK from hash-pinned public assets, without hardware use."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
from urllib.parse import urlsplit
import zipfile

MAX_DOWNLOAD = 128 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def download(asset, cache):
    expected = asset['sha256']
    url = urlsplit(asset['url'])
    if not re.fullmatch(r'[0-9a-f]{64}', expected) or url.scheme != 'https' or url.username or url.password:
        raise ValueError('SDK asset must have an HTTPS URL and exact SHA256')
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / expected
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise ValueError('cached SDK asset digest/type mismatch')
        return path
    with tempfile.NamedTemporaryFile(dir=cache, delete=False) as output:
        temporary = Path(output.name)
        try:
            size = 0
            with urllib.request.urlopen(asset['url'], timeout=60) as response:
                while block := response.read(1024 * 1024):
                    size += len(block)
                    if size > MAX_DOWNLOAD:
                        raise ValueError('SDK download exceeds byte limit')
                    output.write(block)
            output.flush()
            if digest(temporary) != expected:
                raise ValueError('downloaded SDK digest mismatch')
            temporary.rename(path)
        finally:
            temporary.unlink(missing_ok=True)
    return path


def safe_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name:
        raise ValueError('SDK archive path escapes its extraction root')
    return path


def extract_wheel(archive, destination):
    with zipfile.ZipFile(archive) as wheel:
        total = 0
        for member in wheel.infolist():
            path = safe_name(member.filename)
            if stat.S_ISLNK(member.external_attr >> 16):
                raise ValueError('SDK wheel symlinks are not accepted')
            total += member.file_size
            if total > MAX_EXPANDED:
                raise ValueError('SDK wheel exceeds expanded byte limit')
            selected = member.filename.startswith(('openvino/cmake/', 'openvino/include/', 'openvino/libs/'))
            selected |= '.dist-info/' in member.filename and any(x in member.filename for x in ['LICENSE', 'METADATA'])
            if not selected or member.is_dir():
                continue
            target = destination / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with wheel.open(member) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output)


def extract_source(archive, destination):
    with tarfile.open(archive) as source:
        members = source.getmembers()
        if sum(m.size for m in members) > MAX_EXPANDED:
            raise ValueError('SDK source exceeds expanded byte limit')
        for member in members:
            safe_name(member.name)
            if not (member.isfile() or member.isdir()):
                raise ValueError('SDK source accepts only regular files/directories')
        source.extractall(destination, members=members, filter='data')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if args.output.exists() or not 1 <= args.jobs <= 4:
        raise ValueError('SDK output must be absent and jobs must be within1..4')
    lock = json.loads(Path(__file__).with_name('native-sdk-lock.json').read_text())
    if lock['schema_version'] != 1:
        raise ValueError('unknown SDK lock schema')
    args.output.mkdir(parents=True)
    extract_wheel(download(lock['openvino'], args.cache), args.output)
    source_root = args.output / 'level-zero-source'
    extract_source(download(lock['level_zero'], args.cache), source_root)
    source = source_root / ('level-zero-' + lock['level_zero']['commit'])
    build = args.output / 'level-zero-build'
    subprocess.run(['cmake', '-S', str(source), '-B', str(build), '-G', 'Ninja',
                    '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_INSTALL_PREFIX=' + str(args.output.resolve()),
                    '-DCMAKE_INSTALL_LIBDIR=lib', '-DBUILD_L0_LOADER_TESTS=OFF'], check=True)
    subprocess.run(['cmake', '--build', str(build), '--parallel', str(args.jobs)], check=True)
    subprocess.run(['cmake', '--install', str(build)], check=True)
    record = {'scope': lock['scope'], 'inputs': lock, 'hardware_executed': False,
              'openvino_runtime_sha256': digest(args.output / 'openvino/libs/libopenvino.so.2620'),
              'level_zero_loader_sha256': digest((args.output / 'lib/libze_loader.so').resolve())}
    (args.output / 'sdk-record.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
