#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise candidate generation against actual, uninstalled temporary RPMs."""
from pathlib import Path
import hashlib,json,shutil,subprocess,sys,tempfile,tomllib

binary=Path(sys.argv[1]).resolve()
manifest=tomllib.loads(Path('packaging/fedora/44/installed-manifest.toml').read_text())
packages={p['name']:p for p in manifest['providers']}
packages['intel-npu-driver']['license'] = 'MIT AND Apache-2.0 AND (GPL-2.0-only WITH Linux-syscall-note)'
packages['intel-npu-stack-tools']={'nevr':'0:0.1.0-1.intelnpu.fc44','arch':'x86_64','license':'Apache-2.0 AND Artistic-2.0 AND BSD-3-Clause AND ISC AND MIT AND MPL-2.0 AND Unicode-3.0 AND (Apache-2.0 WITH LLVM-exception)',
    'files':[{'path':'/usr/bin/intel-npu-stack'}, {'path':'/usr/libexec/intel-npu-stack/intel-npu-level-zero-probe'},
             {'path':'/usr/libexec/intel-npu-stack/intel-npu-openvino-probe'}, {'path':'/usr/share/intel-npu-stack/installed-manifest.toml'}]}
packages['intel-npu-stack']={'nevr':'0:0.1.0-1.intelnpu.fc44','arch':'noarch','license':'Apache-2.0','files':[]}
packages['intel-npu-compiler']['license'] = 'Apache-2.0 AND MIT AND BSL-1.0 AND HPND AND BSD-3-Clause AND (GPL-2.0-only OR BSD-3-Clause) AND (Apache-2.0 WITH LLVM-exception) AND NCSA AND BSD-2-Clause AND ISC AND Spencer-94 AND Unicode-DFS-2015 AND LicenseRef-LLVM-MD5'
license_owners={'intel-npu-stack-tools','intel-npu-driver','intel-npu-stack-firmware','oneapi-level-zero','openvino','intel-npu-compiler'}

with tempfile.TemporaryDirectory(prefix='profile-rpm-contract-') as temporary:
    root=Path(temporary)
    for name in ['BUILD','SOURCES','SPECS','RPMS','SRPMS','tmp']:(root/name).mkdir()
    spec=['%global debug_package %{nil}', 'Name: intel-npu-stack-tools', 'Version: 0.1.0', 'Release: 1.intelnpu.fc44',
          'Summary: Profile generation fixture','License: '+packages['intel-npu-stack-tools']['license'],
          'Requires: oneapi-level-zero(x86-64) = 1.28.6-1.fc44',
          'Requires: openvino(x86-64) = 2026.2.0-1.intelnpu.fc44','%description','Fixture.']
    for name,p in sorted(packages.items()):
        if name=='intel-npu-stack-tools':continue
        version,release=p['nevr'].split(':')[1].split('-',1)
        spec += ['%package -n '+name,'Summary: Profile generation fixture','Version: '+version,
                 'Release: '+release,'License: '+p['license']]
        if p['arch']=='noarch':spec.append('BuildArch: noarch')
        if name.startswith('libopenvino-') or name in ['intel-npu-compiler','openvino-plugins']:
            spec.append('Requires: openvino(x86-64) = 2026.2.0-1.intelnpu.fc44')
        if name=='intel-npu-stack':
            for dependency in ['intel-npu-stack-tools','intel-npu-driver','intel-npu-stack-firmware',
                               'oneapi-level-zero','openvino','openvino-plugins','intel-npu-compiler']:
                dep=packages[dependency]
                spec.append('Requires: '+dependency+('(x86-64)' if dep['arch']=='x86_64' else '')+' = '+dep['nevr'].removeprefix('0:'))
        spec+=['%description -n '+name,'Fixture.']
    spec+=['%install']
    for name,p in sorted(packages.items()):
        for f in p['files']:
            path=f['path'];spec+=['mkdir -p %{buildroot}'+str(Path(path).parent), "printf '#!/bin/sh\\nexit 0\\n' > %{buildroot}"+path]
            spec.append('chmod 755 %{buildroot}'+path)
        if name in license_owners:
            spec+=['mkdir -p %{buildroot}/usr/share/licenses/'+name,
                   'printf "fixture notice\\n" > %{buildroot}/usr/share/licenses/'+name+'/LICENSE']
    for name,p in sorted(packages.items()):
        spec+=['%files'+('' if name=='intel-npu-stack-tools' else ' -n '+name)]
        spec += [f['path'] for f in p['files']]
        if name in license_owners:spec+=['%license /usr/share/licenses/'+name+'/LICENSE']
    spec_path=root/'SPECS/intel-npu-stack-tools.spec';spec_path.write_text('\n'.join(spec)+'\n')
    result=subprocess.run(['rpmbuild','-bb','--define','_topdir '+str(root),'--define','_tmppath '+str(root/'tmp'),str(spec_path)],capture_output=True,text=True)
    assert result.returncode==0,result.stdout+result.stderr
    rpms=root/'flat';rpms.mkdir()
    for p in (root/'RPMS').rglob('*.rpm'):shutil.copyfile(p,rpms/p.name)
    assert len(list(rpms.iterdir()))==14
    def generate(output,*extra):
        return subprocess.run([str(binary),'generate-fedora-profile','--rpms',str(rpms),'--output',str(output),*extra],capture_output=True,text=True)
    first=root/'first.toml';result=generate(first)
    assert result.returncode==0,result.stdout+result.stderr
    second=root/'second.toml';result=generate(second)
    assert result.returncode==0,result.stdout+result.stderr
    assert first.read_bytes()==second.read_bytes()
    profile=tomllib.loads(first.read_text())
    assert profile['status']=='candidate' and 'qualification' not in profile
    assert profile['platform']=={'id':'fedora','version_id':'44','arch':'x86_64'}
    assert profile['hardware']==[{'vendor':'8086','device':'643e'}] and profile['kernel']['module']=='intel_vpu'
    assert profile['components']['level_zero_loader']['provider']['version']=='0:1.28.6-1.fc44'
    assert profile['components']['npu_userspace_driver']['provider']['version']=='0:1.35.0-1.intelnpu.fc44'
    assert profile['components']['npu_firmware']['provider']['activation']=='reboot'
    for component in profile['components'].values():
        rpm=next(p for p in rpms.iterdir() if p.name.startswith(component['provider']['package']+'-'+component['provider']['version'].split(':')[1]+'.'))
        assert component['sha256']==hashlib.sha256(rpm.read_bytes()).hexdigest()
        assert component['provider']['files']
    mutation_cases=['wrong-release','wrong-driver','wrong-openvino','wrong-arch','script','overlap','conflicting-requirement','missing-frontend-file','unreviewed-license','missing-shared-license','missing-compiler-license','legacy-compiler-license','legacy-driver-license','legacy-tools-license']
    accepted_invalid=[]
    for case in ['overwrite','qualified','missing-firmware','duplicate',*mutation_cases]:
        output=root/(case+'.toml');restore=None
        if case=='overwrite':output=first;before=first.read_bytes()
        elif case=='missing-firmware':
            path=next(p for p in rpms.iterdir() if p.name.startswith('intel-npu-stack-firmware-'));backup=root/'removed.rpm';path.rename(backup);restore=lambda:backup.rename(path)
        elif case=='duplicate':
            path=rpms/'duplicate.rpm';shutil.copyfile(next(rpms.iterdir()),path);restore=lambda:path.unlink()
        elif case!='qualified':
            # Rebuild the same real package set with exactly one policy violation.
            changed='\n'.join(spec)+'\n'
            if case=='wrong-release':changed=changed.replace('1.intelnpu.fc44','1.intelnpu.fc43')
            if case=='wrong-driver':changed=changed.replace('%package -n intel-npu-driver\nSummary: Profile generation fixture\nVersion: 1.35.0','%package -n intel-npu-driver\nSummary: Profile generation fixture\nVersion: 1.32.0')
            if case=='wrong-openvino':changed=changed.replace('Version: 2026.2.0','Version: 2025.1.0')
            if case=='wrong-arch':changed=changed.replace('%package -n oneapi-level-zero\n','%package -n oneapi-level-zero\nBuildArch: noarch\n')
            if case=='script':changed+='\n%post\necho forbidden\n'
            if case=='overlap':changed=changed.replace('%files -n intel-npu-driver\n','%files -n intel-npu-driver\n/usr/bin/intel-npu-stack\n')
            if case=='conflicting-requirement':changed=changed.replace('%description -n intel-npu-stack\n','Requires: intel-npu-driver(x86-64) = 1.32.0-1.intelnpu.fc44\n%description -n intel-npu-stack\n')
            if case=='missing-frontend-file':changed=changed.replace('/usr/lib64/libopenvino_ir_frontend.so.2026.2.0','/usr/share/fixture-missing-frontend')
            if case=='unreviewed-license':changed=changed.replace('License: MIT AND Apache-2.0','License: LicenseRef-Unreviewed')
            if case=='missing-compiler-license':changed=changed.replace('%license /usr/share/licenses/intel-npu-compiler/LICENSE','/usr/share/licenses/intel-npu-compiler/LICENSE')
            if case=='legacy-compiler-license':changed=changed.replace('License: '+packages['intel-npu-compiler']['license'], 'License: '+packages['openvino']['license'])
            if case=='legacy-driver-license':changed=changed.replace('License: '+packages['intel-npu-driver']['license'], 'License: MIT AND Apache-2.0')
            if case=='legacy-tools-license':changed=changed.replace('License: '+packages['intel-npu-stack-tools']['license'], 'License: '+packages['intel-npu-stack-tools']['license'].removesuffix(' AND (Apache-2.0 WITH LLVM-exception)'))
            if case=='missing-shared-license':changed=changed.replace('%license /usr/share/licenses/openvino/LICENSE','/usr/share/licenses/openvino/LICENSE')
            alternate=root/('alternate-'+case)
            for name in ['BUILD','SOURCES','SPECS','RPMS','SRPMS','tmp']:(alternate/name).mkdir(parents=True)
            sp=alternate/'SPECS/intel-npu-stack-tools.spec';sp.write_text(changed)
            result=subprocess.run(['rpmbuild','-bb','--define','_topdir '+str(alternate),'--define','_tmppath '+str(alternate/'tmp'),str(sp)],capture_output=True,text=True)
            assert result.returncode==0,result.stdout+result.stderr
            original=rpms;rpms=alternate/'flat';rpms.mkdir()
            for p in (alternate/'RPMS').rglob('*.rpm'):shutil.copyfile(p,rpms/p.name)
            restore=lambda:None
        result=generate(output,*(['--status','qualified'] if case=='qualified' else []))
        if result.returncode==0:accepted_invalid.append(case)
        elif case=='overwrite':assert first.read_bytes()==before
        else:assert not output.exists(),case
        if restore:restore()
        if case in mutation_cases:rpms=original
        print('FAIL:' if result.returncode==0 else 'PASS:',case)
    assert not accepted_invalid,('accepted invalid RPM sets',accepted_invalid)
    if len(sys.argv)>2:Path(sys.argv[2]).write_bytes(first.read_bytes())
    print('PASS: deterministic candidate and exact provider/file hashes')
