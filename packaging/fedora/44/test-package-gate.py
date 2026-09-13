#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Observe orchestration with real lightweight firmware RPMs and boundary doubles."""
from pathlib import Path
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[3]
FAKE = r'''#!/usr/bin/python3
from pathlib import Path
import hashlib,json,os,re,shutil,subprocess,sys
name=Path(sys.argv[0]).name;args=sys.argv[1:]
with open(os.environ['CALLS'],'a') as f:f.write(json.dumps({'tool':name,'args':args})+'\n')
if os.environ.get('FAIL_TOOL')==name and args not in [['version'],['--version']]:sys.exit(19)
if name=='podman':
 assert args[0]=='run'
 index=next(i for i,v in enumerate(args) if re.fullmatch('sha256:[a-f0-9]{64}',v))
 env=dict(os.environ)
 for i,v in enumerate(args[:index]):
  if v=='--env':k,value=args[i+1].split('=',1);env[k]=value
 command=args[index+1:]
 mount=next((v for v in args if v.startswith('type=bind,src=') and v.endswith(',dst=/work')),None)
 if mount:
  source=Path(mount.split(',src=',1)[1].split(',dst=',1)[0]);virtual=source.parent/'virtual-work'
  assert not virtual.exists();shutil.copytree(source,virtual)
  position=command.index('--build-root')+1
  assert command[position]=='/work/rpmbuild'
  command[position]=str(virtual/'rpmbuild')
  if source.name=='build2':env['SECOND_BUILD']='1'
  code=subprocess.call(command,env=env)
  shutil.rmtree(source);shutil.move(virtual,source);sys.exit(code)
 sys.exit(subprocess.call(command,env=env))
if name=='xtask':
 if args[0]=='validate-source-lock':sys.exit(0)
 assert args[0]=='bundle-sources'
 cache=Path(args[args.index('--cache')+1]);out=Path(args[args.index('--output')+1])
 assert out.is_dir() and not out.is_symlink() and not any(out.iterdir()), 'bundle-sources requires existing empty output'
 shutil.copyfile(cache/'linux-npu-driver.tar',out/'linux-npu-driver.tar');sys.exit(0)
if name in ['rpmbuild','rpm']:
 code=subprocess.call(['/usr/bin/'+name,*args])
 if name=='rpmbuild' and code==0 and os.environ.get('MUTATE_SECOND') and '-ba' in args:
  top=next(v.split(' ',1)[1] for v in args if v.startswith('_topdir '))
  if os.environ.get('SECOND_BUILD'):
   with next((Path(top)/'RPMS').rglob('*.rpm')).open('ab') as f:f.write(b'changed')
 sys.exit(code)
if name=='rpmlint':
 print('rpmlint: 2.8.0')
 print(str(len(args))+' packages and 0 specfiles checked; 0 errors, 0 warnings, 0 filtered, 0 badness; has taken 0.1 s')
 sys.exit(0)
if name=='syft':
 if args==['version']:print('Version: 1.51.10' if os.environ.get('BAD_VERSION') else 'Version: 1.51.1');sys.exit(0)
 assert args[:2]==['scan',args[1]] and args[1].startswith('file:')
 rpm=Path(args[1][5:]);out=Path(next(v[10:] for v in args if v.startswith('spdx-json=')))
 identity=subprocess.check_output(['/usr/bin/rpm','-qp','--qf','%{NAME}\n%{EPOCHNUM}:%{VERSION}-%{RELEASE}',str(rpm)],text=True).splitlines()
 if os.environ.get('BAD_SBOM'):identity[0]='wrong-package'
 out.write_text(json.dumps({'spdxVersion':'SPDX-2.3','packages':[{'name':identity[0],'versionInfo':identity[1],'checksums':[{'algorithm':'SHA256','checksumValue':hashlib.sha256(rpm.read_bytes()).hexdigest()}]}]}));sys.exit(0)
if name=='diffoscope':
 if args==['--version']:print('diffoscope 324');sys.exit(0)
 assert '--json' in args and '--output-empty' in args
 Path(args[args.index('--json')+1]).write_text('{}')
 sys.exit(0 if os.environ.get('LIE_DIFF') or Path(args[-2]).read_bytes()==Path(args[-1]).read_bytes() else 1)
raise AssertionError(name)
'''

class PackageGate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root/'repo'
        self.cache = self.root/'cache'
        self.output = self.root/'output'
        self.bin = self.root/'bin'
        for p in [self.repo,self.cache,self.output,self.bin]:p.mkdir()
        self.calls = self.root/'calls.jsonl'
        self.env = dict(os.environ, PATH=str(self.bin)+':'+os.environ['PATH'], CALLS=str(self.calls))
        for name in ['podman','rpmbuild','rpm','rpmlint','xtask','syft','diffoscope']:
            p=self.bin/name;p.write_text(FAKE);p.chmod(0o755)
        required = ['scripts/check-fedora-packages.sh','packaging/fedora/44/package-gate.py',
                    'packaging/fedora/44/lint-provider-rpms.py',
                    'packaging/fedora/44/sbom-policy.toml','packaging/fedora/44/rpm/install-provider-notices.py',
                    'packaging/fedora/44/rpm/verify-provider-notice-rpm.py',
                    'packaging/fedora/44/rpm/intel-npu-stack-firmware/intel-npu-stack-firmware.spec']
        for relative in required:
            p=REPO/relative
            if p.exists():
                target=self.repo/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,target)
        data=b'Firmware transport fixture copyright and permissions\n'
        with tarfile.open(self.cache/'linux-npu-driver.tar','w') as tar:
            for name,value in [('firmware/bin/COPYRIGHT',data),('firmware/bin/vpu_40xx_v1.bin',b'firmware-fixture')]:
                info=tarfile.TarInfo('linux-npu-driver/'+name);info.size=len(value);info.mode=0o644;info.mtime=1000;tar.addfile(info,io.BytesIO(value))
        notice=self.repo/'packaging/fedora/44/licenses/firmware.txt';notice.parent.mkdir(parents=True);notice.write_bytes(data)
        lock=self.repo/'packaging/fedora/44/provider-sources.toml'
        lock.write_text('schema_version = 1\nstatus = "sealed"\n[[sources]]\nname = "linux-npu-driver"\nredistribution = "allowed"\narchive_sha256 = "'+hashlib.sha256((self.cache/'linux-npu-driver.tar').read_bytes()).hexdigest()+'"\nlicense_files = ["packaging/fedora/44/licenses/firmware.txt"]\nlicense_evidence_sha256 = "'+hashlib.sha256(data).hexdigest()+'"\n')

    def run_gate(self, **extra):
        env=dict(self.env,**extra)
        result = subprocess.run(['bash',str(self.repo/'scripts/check-fedora-packages.sh'),
            '--recipe','firmware','--source-cache',str(self.cache),'--output',str(self.output),
            '--builder-image','sha256:'+'1'*64,'--audit-image','sha256:'+'2'*64,
            '--xtask',str(self.bin/'xtask'),'--epoch','1788996950','--jobs','4','--cpuset','0-3'],
            env=env,text=True,capture_output=True)
        if result.returncode and (self.output/'logs').is_dir():
            result.stderr += ''.join('\n'+p.name+':\n'+p.read_text()[-6000:] for p in sorted((self.output/'logs').iterdir()))
        return result

    def events(self):
        return [json.loads(row) for row in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_two_clean_builds_every_binary_sbom_and_strict_comparison(self):
        result=self.run_gate();self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        report=json.loads((self.output/'result.json').read_text())
        self.assertTrue(report['provider_pair_passed']);self.assertFalse(report['release_ready'])
        events=self.events();containers=[e['args'] for e in events if e['tool']=='podman']
        self.assertEqual(len(containers),4)
        self.assertIn('sha256:'+'2'*64,containers[0])
        for args in containers:
            self.assertIn('--network=none',args);self.assertIn('--pull=never',args)
            self.assertIn('--cpus=4',args);self.assertIn('--cpuset-cpus=0-3',args)
            self.assertNotIn('--privileged',args)
        builds=[e['args'] for e in events if e['tool']=='rpmbuild' and '-ba' in e['args']]
        self.assertEqual(len(builds),2)
        roots=[next(a for a in row if a.startswith('_topdir ')) for row in builds]
        self.assertEqual(roots[0],roots[1])
        mounts=[next(v for v in row if v.startswith('type=bind,src=') and v.endswith(',dst=/work')) for row in containers if '--build-root' in row]
        self.assertEqual(len(mounts),2);self.assertNotEqual(mounts[0],mounts[1])
        for row in containers:
            if '--build-root' in row:
                for folder in ['SOURCES','SPECS']:
                    self.assertTrue(any(v.endswith(',dst=/work/rpmbuild/'+folder+',readonly') for v in row))
        self.assertTrue((self.output/'build1/rpmbuild/RPMS').is_dir())
        self.assertTrue((self.output/'build2/rpmbuild/RPMS').is_dir())
        self.assertEqual(sum(e['tool']=='syft' and e['args'][0]=='scan' for e in events),2)
        self.assertEqual(sum(e['tool']=='diffoscope' and '--json' in e['args'] for e in events),2)
        self.assertEqual([e['args'][0] for e in events if e['tool']=='xtask'],['validate-source-lock','bundle-sources'])
        for label in ['build1', 'build2']:
            lint = self.output/label/'rpmlint/result.json'
            self.assertTrue(lint.is_file(), 'raw lint evidence and policy decision are missing')
            decision = json.loads(lint.read_text())
            self.assertEqual(decision['raw_exit_code'], 0)
            self.assertTrue(decision['lint_policy_passed'])
            self.assertEqual(decision['reviewed_exceptions'], [])
            # Source and native dependency audits run after RPM acceptance.
            # A successful build must not erase their actual build inputs.
            sources = list((self.output/label/'rpmbuild/BUILD').glob(
                '*/linux-npu-driver/firmware/bin/vpu_40xx_v1.bin'))
            self.assertEqual(len(sources), 1, label+' discarded its source tree')
            self.assertEqual(sources[0].read_bytes(), b'firmware-fixture')

    def test_input_and_output_refusals_happen_before_any_container(self):
        sentinel=self.output/'keep';sentinel.write_text('keep')
        self.assertNotEqual(self.run_gate().returncode,0);self.assertEqual(sentinel.read_text(),'keep')
        sentinel.unlink();original=self.output
        for bad in [self.cache,self.cache/'nested',self.repo/'nested']:
            if not bad.exists():bad.mkdir()
            self.output=bad;self.assertNotEqual(self.run_gate().returncode,0)
        self.output=self.root/'alias';self.output.symlink_to(original,target_is_directory=True)
        self.assertNotEqual(self.run_gate().returncode,0)
        self.assertEqual(self.events(),[])

    def test_mutable_image_and_relative_cache_are_rejected(self):
        script=self.repo/'scripts/check-fedora-packages.sh'
        args=['bash',str(script),'--recipe','firmware','--source-cache',str(self.cache),
              '--output',str(self.output),'--builder-image','fedora:latest','--audit-image','sha256:'+'2'*64,
              '--xtask',str(self.bin/'xtask'),'--epoch','1788996950','--jobs','4','--cpuset','0-3']
        self.assertNotEqual(subprocess.run(args,env=self.env,capture_output=True).returncode,0)
        args[args.index('fedora:latest')]='sha256:'+'1'*64
        args[args.index(str(self.cache))]='relative-cache'
        self.assertNotEqual(subprocess.run(args,env=self.env,capture_output=True).returncode,0)
        self.assertEqual(self.events(),[])

    def test_changed_source_archive_is_rejected_before_prep(self):
        with (self.cache/'linux-npu-driver.tar').open('ab') as f:f.write(b'changed')
        self.assertNotEqual(self.run_gate().returncode,0)
        self.assertFalse(any(e['tool']=='rpmbuild' for e in self.events()))

    def test_version_prefix_match_cannot_accept_a_different_syft_release(self):
        self.assertNotEqual(self.run_gate(BAD_VERSION='1').returncode,0)
        self.assertFalse(any(e['tool']=='rpmbuild' for e in self.events()))

    def test_sbom_with_wrong_package_identity_is_rejected(self):
        self.assertNotEqual(self.run_gate(BAD_SBOM='1').returncode,0)
        self.assertTrue(any(e['tool']=='syft' and e['args'][0]=='scan' for e in self.events()))
        self.assertFalse((self.output/'result.json').exists())

    def test_source_validation_failure_never_starts_a_build(self):
        result=self.run_gate(FAIL_TOOL='xtask');self.assertNotEqual(result.returncode,0)
        self.assertFalse(any(e['tool']=='rpmbuild' for e in self.events()))
        self.assertFalse((self.output/'result.json').exists())

    def test_build_metadata_sbom_and_comparison_errors_fail_the_gate(self):
        for tool in ['rpmbuild','rpm','rpmlint','syft','diffoscope']:
            with self.subTest(tool=tool):
                self.output=self.root/('failure-'+tool);self.output.mkdir()
                self.assertNotEqual(self.run_gate(FAIL_TOOL=tool).returncode,0)
                self.assertTrue(any(e['tool']==tool and e['args'] not in [['version'],['--version']] for e in self.events()))
                self.assertFalse((self.output/'result.json').exists())
                if tool == 'rpmlint':
                    lint = json.loads((self.output/'build1/rpmlint/result.json').read_text())
                    self.assertFalse(lint['lint_policy_passed'])
                    self.assertEqual(lint['raw_exit_code'], 19)

    def test_different_bytes_fail_even_if_diffoscope_claims_equal(self):
        result=self.run_gate(MUTATE_SECOND='1',LIE_DIFF='1')
        self.assertNotEqual(result.returncode,0)
        self.assertTrue(any(e['tool']=='diffoscope' and '--json' in e['args'] for e in self.events()),result.stderr)
        self.assertFalse((self.output/'result.json').exists())

if __name__=='__main__':unittest.main()
