#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Copy source-bound Rust notices only for the reviewed Fedora toolchain."""
from pathlib import Path,PurePosixPath
import hashlib,json,re,shutil,subprocess,sys,tomllib


def require(value,message):
    if not value:raise ValueError(message)


def digest(path):
    require(path.is_file() and not path.is_symlink(),'regular non-symlink file required: '+str(path))
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def relative(value):
    path=PurePosixPath(value)
    require(not path.is_absolute() and str(path)==value and '..' not in path.parts,'unsafe notice path')
    return value


def install(bundle,sysroot,output):
    require(bundle.is_dir() and not bundle.is_symlink(),'notice bundle directory required')
    require(not output.exists() and not output.is_symlink(),'output must not exist')
    require(not output.resolve().is_relative_to(bundle.resolve()) and not bundle.resolve().is_relative_to(output.resolve()),'notice input/output overlap')
    digest(bundle/'manifest.json')
    policy=json.loads((bundle/'manifest.json').read_text())
    require(policy['schema_version']==1 and policy['source_rpm']=='rust-1.98.0-1.fc44.src.rpm','reviewed Rust source required')
    require(policy['source_rpm_sha256']=='56475c3c3d550f89e6ec95de90fc5186199b843a059e3f64d1c21a00717ff308','Rust source digest differs')
    installed=subprocess.check_output(['rpm','--noplugins','-q','--queryformat','%{NAME} %{VERSION}-%{RELEASE} %{SOURCERPM}\n','rust','rust-std-static'],text=True)
    require(installed.splitlines()==['rust 1.98.0-1.fc44 rust-1.98.0-1.fc44.src.rpm','rust-std-static 1.98.0-1.fc44 rust-1.98.0-1.fc44.src.rpm'],'installed Rust toolchain differs')
    expected=policy['files']
    actual=set()
    for path in bundle.rglob('*'):
        require(not path.is_symlink(),'symlink in notice bundle')
        if path.is_file():actual.add(str(path.relative_to(bundle)))
        else:require(path.is_dir(),'unsupported notice member')
    require(actual==set(expected)|{'manifest.json'},'notice inventory differs')
    for name,sha in expected.items():require(digest(bundle/relative(name))==sha,'notice digest differs: '+name)
    installed_paths={'usr/share/doc/rust/COPYRIGHT-library.html','usr/share/licenses/rust-std-static/cargo-vendor.txt','usr/share/licenses/rust/LICENSE-APACHE','usr/share/licenses/rust/LICENSE-MIT'}
    require(set(policy['installed_files'])==installed_paths,'installed notice evidence incomplete')
    for name,record in policy['installed_files'].items():
        require(record['sha256']==expected[relative(record['path'])] and digest(sysroot/relative(name))==record['sha256'],'installed notice differs: '+name)
    inventory=set()
    for line in (sysroot/'usr/share/licenses/rust-std-static/cargo-vendor.txt').read_text().splitlines():
        if not line.strip():continue
        fields=line.split();require(len(fields)==2 and fields[1].startswith('v'),'invalid Fedora vendor inventory')
        identity=(fields[0],fields[1][1:]);require(identity not in inventory,'duplicate Fedora dependency');inventory.add(identity)
    seen=set()
    for component in policy['components']:
        identity=(component['name'],component['version']);require(identity not in seen,'duplicate source dependency');seen.add(identity)
        prefix='source/library/vendor/'+identity[0]+'-'+identity[1]+'/'
        metadata=tomllib.loads((bundle/(prefix+'Cargo.toml')).read_text())['package']
        require((metadata['name'],metadata['version'])==identity and metadata['license']==component['declared_license'],'source dependency metadata differs')
        require(component['selected_license']=='MIT' and 'MIT' in metadata['license'],'unreviewed license selection')
        require(set(component['files'])=={p for p in expected if p.startswith(prefix)},'dependency notice inventory differs')
        require(any(re.search(r'LICENSE-MIT(?:\.md)?$',p) for p in component['files']),'MIT notice absent')
    require(seen==inventory and len(seen)==14,'complete pinned stdlib dependency inventory required')
    required={'source/library/compiler-builtins/LICENSE.txt','source/library/compiler-builtins/libm/LICENSE.txt','source/LICENSES/Unicode-3.0.txt','source/LICENSES/LLVM-exception.txt','source/library/backtrace/LICENSE-MIT','source/library/stdarch/LICENSE-MIT','source/library/portable-simd/LICENSE-MIT'}
    require(required<=set(expected),'in-tree stdlib notices incomplete')
    shutil.copytree(bundle,output)
    for path in output.rglob('*'):
        if path.is_file():path.chmod(0o644)
    print('PASS: 14 pinned Rust stdlib dependencies and source notice digests')


if __name__=='__main__':
    try:
        require(len(sys.argv)==4,'usage: install-stdlib-notices.py BUNDLE SYSROOT OUTPUT')
        install(*map(Path,sys.argv[1:]))
    except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
        raise SystemExit('Rust stdlib notices: '+str(error))
