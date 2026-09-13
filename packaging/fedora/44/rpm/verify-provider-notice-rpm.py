#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Verify one RPM's exact prepared notice bytes, modes and license ownership.

This checks notice transport only. Package closure and source-license review
remain separate gates. Payload links are resolved in memory, never extracted.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def query(rpm, format):
    result = subprocess.run(['rpm', '--noplugins', '-qp', '--queryformat', format, str(rpm)],
                            capture_output=True, text=True, timeout=120, check=True)
    require(len(result.stdout) <= 16_777_216, 'RPM metadata exceeds limit')
    return result.stdout


def path_name(name):
    if name.startswith('./'):
        name = name[2:]
    if not name.startswith('/'):
        name = '/'+name
    path = PurePosixPath(name)
    require(str(path) == name and '..' not in path.parts, 'noncanonical payload path')
    return name


def verify(rpm, manifest):
    report = json.loads(manifest.read_text())
    require(report['schema_version'] == 1, 'unsupported notice manifest')
    package = query(rpm, '%{NAME}')
    expected = report['packages'][package]
    require(0 < len(expected) <= 128, 'bounded notice inventory required')
    for name, digest in expected.items():
        require(path_name(name) == '/'+name and name != 'SHA256.json', 'invalid notice path')
        require(re.fullmatch('[a-f0-9]{64}', digest), 'invalid notice digest')
    require(query(rpm, '%{FILEDIGESTALGO}') == '8', 'SHA256 RPM file digests required')
    prefix = '/usr/share/licenses/'+package+'/'
    format = '[%{FILENAMES:json}\t%{FILEMODES:octal}\t%{FILEFLAGS:fflags}\t%{FILEDIGESTS:json}\n]'
    header = {}
    for row in query(rpm, format).splitlines():
        name, mode, flags, digest = row.split('\t')
        name, mode, digest = json.loads(name), int(mode, 8), json.loads(digest)
        if not name.startswith(prefix) or stat.S_ISDIR(mode):
            continue
        relative = name[len(prefix):]
        require(relative not in header, 'duplicate notice header')
        require(stat.S_ISREG(mode) and mode & 0o7777 == 0o644 and 'l' in flags,
                'notice must be regular mode 0644 and flagged as license: '+name)
        header[relative] = digest
    require(header.keys() == expected.keys() | {'SHA256.json'}, 'notice header inventory differs')
    for name, digest in expected.items():
        require(header[name] == digest, 'notice header digest differs: '+name)
    content, links = {}, {}
    with rpm.open('rb') as stream:
        process = subprocess.Popen(['rpm2archive', '-n', '-f', 'pax', '-'], stdin=stream, stdout=subprocess.PIPE)
        try:
            with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
                for member in archive:
                    name = path_name(member.name)
                    if not name.startswith(prefix) or member.isdir():
                        continue
                    relative = name[len(prefix):]
                    require(relative in header and relative not in content and relative not in links,
                            'unexpected or duplicate notice payload: '+name)
                    if member.islnk():
                        target = path_name(member.linkname)
                        require(target.startswith(prefix), 'notice hardlink leaves package license directory')
                        links[relative] = target[len(prefix):]
                    else:
                        require(member.isfile() and 0 < member.size <= 1_048_576,
                                'notice payload must be a bounded regular file')
                        with archive.extractfile(member) as value:
                            content[relative] = value.read()
            require(process.wait(timeout=120) == 0, 'rpm2archive failed')
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.kill()
                process.wait()
    hardlink_count = len(links)
    while links:
        ready = [name for name, target in links.items() if target in content]
        require(ready, 'unresolved or cyclic notice hardlinks')
        for name in ready:
            content[name] = content[links.pop(name)]
    actual = {name: hashlib.sha256(data).hexdigest() for name, data in content.items()}
    require(actual == header, 'notice payload digests differ from RPM header')
    require(json.loads(content['SHA256.json']) == expected, 'installed notice manifest differs')
    with rpm.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'package': package, 'rpm_sha256': digest, 'verified_notices': len(expected),
            'notice_sha256': expected, 'verified_hardlinks': hardlink_count}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rpm', required=True, type=Path)
    parser.add_argument('--manifest', required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.rpm, args.manifest), indent=2, sort_keys=True))
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, 'provider notice RPM check: '+str(error)+'\n')
