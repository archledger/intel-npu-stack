#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Validate uninstalled tools/metapackage RPMs against their expected manifest."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import stat
import subprocess
import sys
import tomllib


def require(condition, message):
    if not condition:
        raise SystemExit('FAIL: ' + message)


def query(rpm, *args):
    result = subprocess.run(['/usr/bin/rpm', '--noplugins', '-qp', *args, str(rpm)],
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                            capture_output=True, timeout=15, check=True)
    require(len(result.stdout) <= 4 * 1024 * 1024, 'RPM query output limit')
    return result.stdout.decode('utf-8')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


require(len(sys.argv) == 5, 'usage: check-packages.py MANIFEST PAYLOAD META_RPM TOOLS_RPM')
manifest_path = Path(sys.argv[1]).resolve(strict=True)
payload = Path(sys.argv[2]).resolve(strict=True)
manifest = tomllib.loads(manifest_path.read_text())
require(manifest.get('schema_version') == 1 and manifest.get('status') == 'candidate'
        and manifest.get('reboot_required') is True, 'manifest candidate/activation policy')
required = {
    'intel-npu-stack': {
        ('intel-npu-stack-tools(x86-64)', '=', '0.1.0-3.intelnpu.fc44'),
        ('intel-npu-driver(x86-64)', '=', '1.38.0-1.intelnpu.fc44'),
        ('intel-npu-stack-firmware', '=', '1.38.0-1.intelnpu.fc44'),
        ('oneapi-level-zero(x86-64)', '=', '1.32.0-1.intelnpu.fc44'),
        ('openvino(x86-64)', '=', '2026.2.0-2.intelnpu.fc44'),
        ('openvino-plugins(x86-64)', '=', '2026.2.0-2.intelnpu.fc44'),
        ('intel-npu-compiler(x86-64)', '=', '2026.2.0-2.intelnpu.fc44'),
    },
    'intel-npu-stack-tools': {
        ('openvino(x86-64)', '=', '2026.2.0-2.intelnpu.fc44'),
        ('oneapi-level-zero(x86-64)', '=', '1.32.0-1.intelnpu.fc44'),
    },
}
executables = {'/usr/bin/intel-npu-stack',
               '/usr/libexec/intel-npu-stack/intel-npu-level-zero-probe',
               '/usr/libexec/intel-npu-stack/intel-npu-openvino-probe'}
manifest_name = '/usr/share/intel-npu-stack/installed-manifest.toml'
allowed = executables | {manifest_name}
prefixes = ('/usr/share/doc/intel-npu-stack-tools/',
            '/usr/share/licenses/intel-npu-stack-tools/', '/usr/lib/.build-id/')
packages = set()
seen = set()
licensed = False
for argument in sys.argv[3:]:
    rpm = Path(argument)
    require(rpm.is_absolute() and rpm.is_file() and not rpm.is_symlink(), 'regular absolute RPM input')
    identity = query(rpm, '--queryformat', '%{NAME}\n%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n%{ARCH}\n%{FILEDIGESTALGO}\n').splitlines()
    require(len(identity) == 4, 'RPM identity response')
    name, nevr, arch, algorithm = identity
    require(name in required and name not in packages, 'exact two distinct package identities')
    packages.add(name)
    expected_arch = 'noarch' if name == 'intel-npu-stack' else 'x86_64'
    require(nevr == '0:0.1.0-3.intelnpu.fc44' and arch == expected_arch and algorithm == '8', 'RPM version/arch/SHA256')
    for option in ['--scripts', '--triggers', '--filetriggers']:
        require(not query(rpm, option).strip(), 'script-free package: ' + name)
    relations = set()
    for line in query(rpm, '--queryformat', '[%{REQUIRENAME:json}\t%{REQUIREFLAGS:depflags}\t%{REQUIREVERSION:json}\n]').splitlines():
        dep, op, version = line.split('\t')
        dep = json.loads(dep)
        version = None if version == '(none)' else json.loads(version)
        relations.add((dep, op, version))
        require(dep != 'rpmlib(ShortCircuited)', 'normal RPM build required')
    require(required[name] <= relations, 'exact provider requirements: ' + name)
    rows = query(rpm, '--queryformat', '[%{FILENAMES:json}\t%{FILEMODES:octal}\t%{FILEDIGESTS:json}\t%{FILEFLAGS:fflags}\t%{LONGFILESIZES}\n]').splitlines()
    require(name != 'intel-npu-stack' or not rows, 'metapackage must own no files')
    for row in rows:
        relative, mode, digest, flags, size = row.split('\t')
        relative = json.loads(relative)
        path = PurePosixPath(relative)
        require(relative.startswith('/usr/') and str(path) == relative
                and '..' not in path.parts, 'normalized Fedora-owned path')
        mode = int(mode, 8)
        if stat.S_ISDIR(mode):
            continue
        require(relative in allowed or relative.startswith(prefixes), 'unexpected packaged file: ' + relative)
        require(relative not in seen, 'overlapping packaged file')
        seen.add(relative)
        file = payload / relative.lstrip('/')
        require(file.resolve(strict=True).is_relative_to(payload), 'contained extracted file')
        if stat.S_ISREG(mode):
            require(not file.is_symlink() and file.is_file(), 'regular payload type')
            require(file.stat().st_size == int(size) and sha(file) == json.loads(digest), 'payload size/digest: ' + relative)
        else:
            require(stat.S_ISLNK(mode) and file.is_symlink(), 'supported payload type')
            require(not os.readlink(file).startswith('/'), 'relative payload symlink')
        if relative in executables:
            require(stat.S_ISREG(mode) and stat.S_IMODE(mode) == 0o755
                    and stat.S_IMODE(file.stat().st_mode) == 0o755,
                    f'executable path/mode: {relative} rpm={oct(mode)} extracted={oct(file.stat().st_mode)}')
        if relative.startswith('/usr/share/licenses/intel-npu-stack-tools/') and 'l' in flags:
            licensed = True
require(packages == set(required), 'complete two-package set')
require(allowed <= seen and licensed, 'required tools, manifest and license ownership')
require((payload / manifest_name.lstrip('/')).read_bytes() == manifest_path.read_bytes(), 'exact installed manifest binding')
print('PASS: tools/metapackage ownership, modes, dependencies, scripts and manifest binding')
