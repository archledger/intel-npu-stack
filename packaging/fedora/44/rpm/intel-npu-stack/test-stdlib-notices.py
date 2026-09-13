#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the pinned source notice set against installed toolchain evidence."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,tempfile,unittest
HERE=Path(__file__).resolve().parent
BUNDLE=HERE.parents[1]/'licenses/rust-stdlib-1.98.0'
class StdlibNotices(unittest.TestCase):
 def test_source_notices_and_refusals(self):
  for mutation in ['valid','missing','changed','extra','symlink','toolchain','installed','inventory','in-tree-policy','output']:
   with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp);bundle=root/'bundle';shutil.copytree(BUNDLE,bundle)
    policy=json.loads((bundle/'manifest.json').read_text());sysroot=root/'sysroot';sysroot.mkdir()
    for rel,record in policy['installed_files'].items():
     p=sysroot/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(bundle/record['path'],p)
    binary=root/'bin';binary.mkdir();rpm=binary/'rpm'
    rpm.write_text('#!/usr/bin/python3\nimport sys\nassert sys.argv[1:]==["--noplugins","-q","--queryformat","%{NAME} %{VERSION}-%{RELEASE} %{SOURCERPM}\\n","rust","rust-std-static"]\nprint("rust 1.98.0-1.fc44 rust-1.98.0-1.fc44.src.rpm")\nprint("rust-std-static '+('1.97.0' if mutation=='toolchain' else '1.98.0')+'-1.fc44 rust-1.98.0-1.fc44.src.rpm")\n');rpm.chmod(0o755)
    victim=bundle/'source/library/compiler-builtins/LICENSE.txt';output=root/'output'
    if mutation=='missing':victim.unlink()
    if mutation=='changed':victim.write_text('changed')
    if mutation=='extra':(bundle/'unexpected').write_text('extra')
    if mutation=='symlink':
     saved=root/'saved';victim.rename(saved);victim.symlink_to(saved)
    if mutation=='installed':(sysroot/'usr/share/licenses/rust-std-static/cargo-vendor.txt').write_text('changed')
    if mutation=='inventory':
     policy['components'].pop();(bundle/'manifest.json').write_text(json.dumps(policy))
    if mutation=='in-tree-policy':
     victim.unlink();policy['files'].pop(str(victim.relative_to(bundle)));(bundle/'manifest.json').write_text(json.dumps(policy))
    if mutation=='output':output.mkdir();(output/'keep').write_text('preserve')
    result=subprocess.run(['python3',str(HERE/'install-stdlib-notices.py'),str(bundle),str(sysroot),str(output)],env=dict(os.environ,PATH=str(binary)+':'+os.environ['PATH']),capture_output=True,text=True)
    self.assertEqual(result.returncode==0,mutation=='valid',result.stdout+result.stderr)
    if mutation=='valid':
     self.assertEqual({str(p.relative_to(output)) for p in output.rglob('*') if p.is_file()},set(policy['files'])|{'manifest.json'})
     for rel,digest in policy['files'].items():self.assertEqual(hashlib.sha256((output/rel).read_bytes()).hexdigest(),digest)
    elif mutation=='output':self.assertEqual((output/'keep').read_text(),'preserve')
    else:self.assertFalse(output.exists())
if __name__=='__main__':unittest.main()
