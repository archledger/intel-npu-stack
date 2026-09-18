#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the production checker with real isolated, uninstalled RPMs."""
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
MANIFEST = 'schema_version = 1\nstatus = "candidate"\nreboot_required = true\n'


def case(mutation):
    with tempfile.TemporaryDirectory(prefix='stack-rpm-contract-') as directory:
        root = Path(directory)
        for name in ['BUILD', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS', 'tmp', 'payload']:
            (root / name).mkdir()
        manifest = root / 'manifest.toml'
        manifest.write_text(MANIFEST)
        requirement = '1.35.0' if mutation == 'requirement' else '1.38.0'
        helpers = ['intel-npu-level-zero-probe', 'intel-npu-openvino-probe']
        if mutation == 'missing':
            helpers.pop()
        install = ['mkdir -p %{buildroot}/usr/bin %{buildroot}/usr/libexec/intel-npu-stack %{buildroot}/usr/share/intel-npu-stack',
                   'echo fixture > LICENSE', 'echo fixture > README.md',
                   "printf '#!/bin/sh\\nexit 0\\n' > %{buildroot}/usr/bin/intel-npu-stack",
                   'chmod 755 %{buildroot}/usr/bin/intel-npu-stack',
                   f'cp {manifest} %{{buildroot}}/usr/share/intel-npu-stack/installed-manifest.toml']
        for helper in helpers:
            install += [f"printf '#!/bin/sh\\nexit 0\\n' > %{{buildroot}}/usr/libexec/intel-npu-stack/{helper}",
                        f'chmod {"644" if mutation == "mode" else "755"} %{{buildroot}}/usr/libexec/intel-npu-stack/{helper}']
        extra = ''
        if mutation == 'extra':
            install.append('echo fixture > %{buildroot}/usr/bin/unexpected')
            extra = '/usr/bin/unexpected\n'
        spec = root / 'SPECS/fixture.spec'
        spec.write_text('''%global debug_package %{nil}
Name: intel-npu-stack-tools
Version: 0.1.0
Release: 2.intelnpu.fc44
Summary: Contract fixture
License: Apache-2.0
Requires: openvino(x86-64) = 2026.2.0-2.intelnpu.fc44
Requires: oneapi-level-zero(x86-64) = 1.32.0-1.intelnpu.fc44
%description
Tool fixture.
%package -n intel-npu-stack
Summary: Metadata fixture
BuildArch: noarch
Requires: intel-npu-stack-tools(x86-64) = 0.1.0-2.intelnpu.fc44
Requires: intel-npu-driver(x86-64) = ''' + requirement + '''-1.intelnpu.fc44
Requires: intel-npu-stack-firmware = 1.38.0-1.intelnpu.fc44
Requires: oneapi-level-zero(x86-64) = 1.32.0-1.intelnpu.fc44
Requires: openvino(x86-64) = 2026.2.0-2.intelnpu.fc44
Requires: openvino-plugins(x86-64) = 2026.2.0-2.intelnpu.fc44
Requires: intel-npu-compiler(x86-64) = 2026.2.0-2.intelnpu.fc44
%description -n intel-npu-stack
Metadata fixture.
%install
''' + '\n'.join(install) + '\n' + ('%post\necho forbidden\n' if mutation == 'script' else '') + '''%files -n intel-npu-stack
%files
%license LICENSE
%doc README.md
/usr/bin/intel-npu-stack
/usr/libexec/intel-npu-stack
/usr/share/intel-npu-stack
''' + extra)
        result = subprocess.run(['rpmbuild', '-bb', '--define', '_topdir ' + str(root),
                                 '--define', '_tmppath ' + str(root / 'tmp'), str(spec)], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        rpms = sorted((root / 'RPMS').rglob('*.rpm'))
        assert len(rpms) == 2
        for rpm in rpms:
            with rpm.open('rb') as stream:
                unpack = subprocess.Popen(['rpm2cpio'], stdin=stream, stdout=subprocess.PIPE)
                extract = subprocess.run(['cpio', '-idm', '--quiet', '--no-absolute-filenames'],
                                         stdin=unpack.stdout, cwd=root / 'payload', capture_output=True)
                unpack.stdout.close()
                assert unpack.wait() == 0 and extract.returncode == 0
        if mutation == 'manifest':
            (root / 'payload/usr/share/intel-npu-stack/installed-manifest.toml').write_text('status="qualified"\n')
        result = subprocess.run(['python3', str(HERE / 'check-packages.py'), str(manifest),
                                 str(root / 'payload'), *map(str, rpms)], capture_output=True, text=True)
        assert (result.returncode == 0) == (mutation == 'valid'), (mutation, result.stdout, result.stderr)


for mutation in ['valid', 'requirement', 'missing', 'mode', 'extra', 'script', 'manifest']:
    case(mutation)
    print('PASS:', mutation, flush=True)
