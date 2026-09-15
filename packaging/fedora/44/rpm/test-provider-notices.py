#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Observe source/archive binding and complete package notice preparation."""
from pathlib import Path
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
# Independently enumerated source locations and installed ownership contract.
LLVM = ['llvm/LICENSE.TXT', 'mlir/LICENSE.TXT', 'llvm/lib/Support/COPYRIGHT.regex',
        'llvm/lib/Support/BLAKE3/LICENSE', 'llvm/lib/Support/ConvertUTF.cpp',
        'llvm/lib/Support/MD5.cpp', 'llvm/lib/Support/xxhash.cpp',
        'llvm/lib/Support/regstrlcpy.c', 'llvm/include/llvm/Support/ConvertUTF.h',
        'llvm/include/llvm/Support/MD5.h', 'llvm/include/llvm/Support/xxhash.h']
DRIVER = ['LICENSE.md', 'compiler/include/npu_driver_compiler.h',
          'linux/include/uapi/drm/drm.h', 'linux/include/uapi/drm/ivpu_accel.h',
          'umd/level_zero_driver/source/ext/cityhash/city.cc',
          'umd/level_zero_driver/source/ext/cityhash/city.h',
          'umd/level_zero_driver/source/ext/cityhash/citycrc.h',
          'firmware/include/api/vpu_cmx_info_37xx.h',
          'firmware/include/api/vpu_cmx_info_40xx.h',
          'firmware/include/api/vpu_dma_hw.h',
          'firmware/include/api/vpu_dma_hw_37xx.h',
          'firmware/include/api/vpu_dma_hw_40xx.h',
          'firmware/include/api/vpu_jsm_api.h',
          'firmware/include/api/vpu_jsm_job_cmd_api.h',
          'firmware/include/api/vpu_media_hw.h',
          'firmware/include/api/vpu_nce_hw_37xx.h',
          'firmware/include/api/vpu_nce_hw_40xx.h',
          'firmware/include/api/vpu_nnrt_api.h',
          'firmware/include/api/vpu_nnrt_api_37xx.h',
          'firmware/include/api/vpu_nnrt_api_40xx.h',
          'firmware/include/api/vpu_nnrt_api_ver.h',
          'firmware/include/api/vpu_nnrt_common.h',
          'firmware/include/api/vpu_nnrt_shavert.h',
          'firmware/include/api/vpu_nnrt_wlm.h',
          'firmware/include/api/vpu_pwrmgr_api.h']
GROUPS = {
    'openvino': {
        'openvino': [('openvino', '', ['LICENSE', 'licensing/third-party-programs.txt']),
                     ('openvino-flatbuffers', 'thirdparty/flatbuffers/flatbuffers/', ['LICENSE']),
                     ('openvino-onnx', 'thirdparty/onnx/onnx/', ['LICENSE']),
                     ('openvino-protobuf', 'thirdparty/protobuf/protobuf/', ['LICENSE', 'third_party/utf8_range/LICENSE']),
                     ('openvino-mlas', 'src/plugins/intel_cpu/thirdparty/mlas/', ['LICENSE']),
                     ('openvino-onednn-cpu', 'src/plugins/intel_cpu/thirdparty/onednn/', ['LICENSE', 'THIRD-PARTY-PROGRAMS']),
                     ('openvino-onednn-gpu', 'src/plugins/intel_gpu/thirdparty/onednn_gpu/', ['LICENSE', 'THIRD-PARTY-PROGRAMS']),
                     ('level-zero-npu-extensions', 'src/plugins/intel_npu/thirdparty/level-zero-ext/', ['LICENSE.txt'])],
        'intel-npu-compiler': [('npu-compiler', '', ['LICENSE']),
                               ('npu-compiler-elf-openvino', 'thirdparty/elf/', ['LICENCE']),
                               ('intel-npu-nn-cost-model', 'thirdparty/vpucostmodel/', ['LICENSE']),
                               ('intel-npu-compiler-llvm', 'thirdparty/llvm-project/', LLVM)],
    },
    'driver': {'intel-npu-driver': [('linux-npu-driver', '', DRIVER),
                                  ('level-zero', 'third_party/level-zero/', ['LICENSE']),
                                  ('level-zero-npu-extensions', 'third_party/level-zero-npu-extensions/', ['LICENSE.txt']),
                                  ('npu-compiler-elf-driver', 'third_party/npu_compiler_elf/', ['LICENCE'])]},
    'firmware': {'intel-npu-stack-firmware': [('linux-npu-driver', '', ['firmware/bin/COPYRIGHT'])]},
    'loader': {'oneapi-level-zero': [('level-zero', '', ['LICENSE'])]},
}

# Reviewed source-file attributions, independent of the production collector.
EXTRA_NOTICES = {'intel-npu-compiler-llvm': ['llvm/lib/Support/regcomp.c',
                             'llvm/lib/Support/regengine.inc',
                             'llvm/lib/Support/regerror.c',
                             'llvm/lib/Support/regex2.h',
                             'llvm/lib/Support/regex_impl.h',
                             'llvm/lib/Support/regexec.c',
                             'llvm/lib/Support/regfree.c',
                             'llvm/lib/Support/regutils.h'],
 'npu-compiler': ['src/vpux_compiler/include/vpux/compiler/NPU37XX/dialect/NPUReg37XX/firmware_headers/details/api/vpu_cmx_info_37xx.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU37XX/dialect/NPUReg37XX/firmware_headers/details/api/vpu_dma_hw_37xx.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU37XX/dialect/NPUReg37XX/firmware_headers/details/api/vpu_nce_hw_37xx.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU37XX/dialect/NPUReg37XX/firmware_headers/details/api/vpu_nnrt_api_37xx.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU37XX/dialect/NPUReg37XX/firmware_headers/details/api/vpu_pwrmgr_api.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU40XX/dialect/NPUReg40XX/firmware_headers/details/api/vpu_cmx_info_40xx.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU40XX/dialect/NPUReg40XX/firmware_headers/details/api/vpu_dma_hw_40xx.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU40XX/dialect/NPUReg40XX/firmware_headers/details/api/vpu_media_hw.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU40XX/dialect/NPUReg40XX/firmware_headers/details/api/vpu_nce_hw_40xx.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU40XX/dialect/NPUReg40XX/firmware_headers/details/api/vpu_nnrt_api.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU40XX/dialect/NPUReg40XX/firmware_headers/details/api/vpu_nnrt_api_40xx.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU40XX/dialect/NPUReg40XX/firmware_headers/details/api/vpu_nnrt_api_ver.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU40XX/dialect/NPUReg40XX/firmware_headers/details/api/vpu_nnrt_common.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU40XX/dialect/NPUReg40XX/firmware_headers/details/api/vpu_nnrt_shavert.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU40XX/dialect/NPUReg40XX/firmware_headers/details/api/vpu_nnrt_wlm.h',
                  'src/vpux_compiler/include/vpux/compiler/NPU40XX/dialect/NPUReg40XX/firmware_headers/details/api/vpu_pwrmgr_api.h',
                  'src/vpux_compiler/src/pipelines/compilation_options.cpp'],
 'openvino': ['licensing/onednn_third-party-programs.txt',
              'licensing/onetbb_third-party-programs.txt',
              'licensing/runtime-third-party-programs.txt',
              'src/plugins/intel_gpu/thirdparty/rapidjson/allocators.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/document.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/encodedstream.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/encodings.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/error/error.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/internal/biginteger.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/internal/diyfp.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/internal/dtoa.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/internal/ieee754.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/internal/itoa.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/internal/meta.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/internal/pow10.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/internal/stack.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/internal/strfunc.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/internal/strtod.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/internal/swap.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/istreamwrapper.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/memorystream.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/prettywriter.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/rapidjson.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/reader.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/stream.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/stringbuffer.h',
              'src/plugins/intel_gpu/thirdparty/rapidjson/writer.h'],
 'openvino-mlas': ['inc/mlas.h',
                   'lib/qdwconv_kernelsize.cpp',
                   'lib/reorder.cpp',
                   'lib/x86_64/AssembleAvxVnni.h'],
 'openvino-onednn-cpu': ['third_party/ittnotify/disable_warnings.h',
                         'third_party/ittnotify/ittnotify.h',
                         'third_party/ittnotify/ittnotify_config.h',
                         'third_party/ittnotify/ittnotify_static.c',
                         'third_party/ittnotify/ittnotify_static.h',
                         'third_party/ittnotify/ittnotify_types.h',
                         'third_party/ittnotify/ittptmark64.S',
                         'third_party/ittnotify/jitprofiling.c',
                         'third_party/ittnotify/jitprofiling.h',
                         'third_party/ittnotify/legacy/ittnotify.h'],
 'openvino-protobuf': ['src/google/protobuf/stubs/casts.h',
                       'src/google/protobuf/stubs/mutex.h',
                       'src/google/protobuf/stubs/platform_macros.h']}

class ProviderNotices(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root/'source'
        self.archives = self.root/'archives'
        self.source.mkdir(); self.archives.mkdir()
        self.spec = self.root/'fixture.spec'
        self.lock = self.root/'lock.toml'
        self.evidence = self.root/'provider-license-evidence.tar'
        self.output = self.root/'prepared'

    def fixture(self, kind):
        self.kind = kind
        self.expected = {}
        archive_entries = {}
        for package, groups in GROUPS[kind].items():
            records = {}
            for archive, prefix, names in groups:
                for name in [*names, *EXTRA_NOTICES.get(archive, [])]:
                    relative = prefix+name
                    src = ('thirdparty/npu-compiler/' if package=='intel-npu-compiler' else '')+relative
                    dest = 'COPYRIGHT' if kind=='firmware' else relative
                    data = ('Copyright '+archive+' '+name+'\r\nPermission and terms\r\n').encode()
                    (self.source/src).parent.mkdir(parents=True, exist_ok=True)
                    (self.source/src).write_bytes(data)
                    archive_entries.setdefault(archive, {})[archive+'/'+name] = data
                    records[dest] = data
            self.expected[package] = records
        # Identical notices must retain both paths without duplicate RPM payload.
        if kind=='openvino':
            data = self.expected['openvino']['LICENSE']
            relative = 'src/plugins/intel_cpu/thirdparty/mlas/LICENSE'
            self.expected['openvino'][relative] = data
            (self.source/relative).write_bytes(data)
            archive_entries['openvino-mlas']['openvino-mlas/LICENSE'] = data
        lock=['schema_version = 1', 'status = "sealed"']
        evidence = {}
        for archive, entries in sorted(archive_entries.items()):
            path=self.archives/(archive+'.tar')
            self.tar(path, entries)
            notice=next(iter(entries.values()))
            relative='packaging/fedora/44/licenses/'+archive+'.txt'
            evidence[relative]=notice
            lock += ['[[sources]]', 'name = "'+archive+'"', 'redistribution = "allowed"',
                     'archive_sha256 = "'+hashlib.sha256(path.read_bytes()).hexdigest()+'"',
                     'license_files = ["'+relative+'"]',
                     'license_evidence_sha256 = "'+hashlib.sha256(notice).hexdigest()+'"']
            if archive == 'openvino':
                lock += ['[[sources.gitlinks]]', 'path = "thirdparty/json/nlohmann_json"',
                         'commit = "9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03"',
                         'disposition = "system"',
                         'packages = [{ name = "json-devel", nevr = "0:3.12.0-2.fc44" }]']
        self.tar(self.evidence, evidence)
        self.lock.write_text('\n'.join(lock)+'\n')
        self.spec.write_text('\n'.join('Source'+str(i)+': '+name+'.tar' for i,name in enumerate(sorted(archive_entries)))+'\nSource99: provider-license-evidence.tar\n')

        if kind == 'openvino':
            data = (HERE/'openvino/json-3.12.0-LICENSE.MIT').read_bytes()
            (self.archives/'json-3.12.0-LICENSE.MIT').write_bytes(data)
            self.expected['openvino']['system/json/LICENSE.MIT'] = data
            self.spec.write_text(self.spec.read_text()+'Source100: json-3.12.0-LICENSE.MIT\n')
        if kind == 'driver':
            for number, name in enumerate(['GPL-2.0', 'Linux-syscall-note'], 100):
                filename = 'linux-uapi-'+name
                data = (HERE/'intel-npu-driver'/filename).read_bytes()
                (self.archives/filename).write_bytes(data)
                self.expected['intel-npu-driver']['linux-uapi/'+name] = data
                self.spec.write_text(self.spec.read_text()+f'Source{number}: {filename}\n')

    @staticmethod
    def tar(path, entries):
        with tarfile.open(path, 'w') as tar:
            for name,data in sorted(entries.items()):
                info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644
                tar.addfile(info,io.BytesIO(data))

    def run_prepare(self):
        return subprocess.run([sys.executable,str(HERE/'install-provider-notices.py'),
            '--kind',self.kind,'--source',str(self.source),'--archives',str(self.archives),
            '--spec',str(self.spec),'--source-lock',str(self.lock),'--license-evidence',str(self.evidence),
            '--output',str(self.output)],capture_output=True,text=True)

    def test_all_families_have_exact_notice_bytes_and_ownership(self):
        self.fixture('openvino')
        for kind in GROUPS:
            if kind!='openvino':
                self.source=self.root/(kind+'-source');self.source.mkdir()
                self.archives=self.root/(kind+'-archives');self.archives.mkdir()
                self.output=self.root/(kind+'-output');self.fixture(kind)
            result=self.run_prepare();self.assertEqual(result.returncode,0,result.stderr)
            for package,files in self.expected.items():
                folder=self.output/package
                hashes=json.loads((folder/'SHA256.json').read_text())
                self.assertEqual(set(hashes),set(files))
                for name,data in files.items():
                    file=folder/name
                    self.assertEqual(file.read_bytes(),data)
                    self.assertEqual(file.stat().st_mode & 0o777,0o644)
                    self.assertEqual(hashes[name],hashlib.sha256(data).hexdigest())
            first = {str(p.relative_to(self.output)): p.read_bytes() for p in self.output.rglob('*') if p.is_file()}
            self.output = self.root/(kind+'-second-output')
            self.assertEqual(self.run_prepare().returncode, 0)
            second = {str(p.relative_to(self.output)): p.read_bytes() for p in self.output.rglob('*') if p.is_file()}
            self.assertEqual(first, second)
            if kind=='openvino':
                self.assertTrue((self.output/'openvino/LICENSE').samefile(self.output/'openvino/src/plugins/intel_cpu/thirdparty/mlas/LICENSE'))

    def test_compiler_declares_its_bundled_license_terms(self):
        result = subprocess.run(['rpmspec', '-q', '--qf', '%{NAME}\t%{LICENSE}\n',
                                 str(HERE / 'openvino/openvino.spec')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        packages = dict(line.split('\t', 1) for line in result.stdout.splitlines())
        expression = packages['intel-npu-compiler']
        for term in ['Apache-2.0 WITH LLVM-exception', 'NCSA', 'BSD-2-Clause',
                     'Spencer-94', 'Unicode-DFS-2015', 'ISC', 'LicenseRef-LLVM-MD5']:
            self.assertIn(term, expression)
        self.assertNotIn('LLVM-exception', packages['openvino'])

    def test_system_notice_requires_exact_bytes_without_partial_output(self):
        self.fixture('openvino')
        path = self.archives/'json-3.12.0-LICENSE.MIT'
        path.write_bytes(path.read_bytes().replace(b'2013-2025', b'2013-2022'))
        self.assertNotEqual(self.run_prepare().returncode, 0)
        self.assertFalse(self.output.exists())
        path.unlink()
        self.assertNotEqual(self.run_prepare().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_driver_declares_the_distributed_uapi_header_exception(self):
        result = subprocess.run(['rpmspec', '-q', '--qf', '%{NAME}\t%{LICENSE}\n',
                                 str(HERE/'intel-npu-driver/intel-npu-driver.spec')],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        packages = dict(line.split('\t', 1) for line in result.stdout.splitlines())
        self.assertIn('GPL-2.0-only WITH Linux-syscall-note', packages['intel-npu-driver'])

    def test_system_notice_requires_matching_locked_provider(self):
        self.fixture('openvino')
        self.lock.write_text(self.lock.read_text().replace('0:3.12.0-2.fc44', '0:3.11.3-2.fc44'))
        self.assertNotEqual(self.run_prepare().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_system_notice_must_be_declared_in_srpm(self):
        self.fixture('openvino')
        self.spec.write_text(self.spec.read_text().replace('Source100: json-3.12.0-LICENSE.MIT\n', ''))
        self.assertNotEqual(self.run_prepare().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_changed_embedded_attribution_has_no_partial_output(self):
        self.fixture('openvino')
        path = self.source/'src/plugins/intel_cpu/thirdparty/mlas/lib/qdwconv_kernelsize.cpp'
        path.write_bytes(b'changed embedded notice')
        self.assertNotEqual(self.run_prepare().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_changed_driver_embedded_notice_has_no_partial_output(self):
        self.fixture('driver')
        path = self.source/'umd/level_zero_driver/source/ext/cityhash/city.cc'
        path.write_bytes(b'Google attribution removed')
        self.assertNotEqual(self.run_prepare().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_driver_uapi_terms_require_exact_bytes(self):
        self.fixture('driver')
        (self.archives/'linux-uapi-Linux-syscall-note').write_bytes(b'exception missing')
        self.assertNotEqual(self.run_prepare().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_driver_uapi_terms_must_be_srpm_sources(self):
        self.fixture('driver')
        self.spec.write_text(self.spec.read_text().replace('Source101: linux-uapi-Linux-syscall-note\n', ''))
        self.assertNotEqual(self.run_prepare().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_missing_notice_has_no_partial_output(self):
        self.fixture('openvino');(self.source/'thirdparty/npu-compiler/LICENSE').unlink()
        self.assertNotEqual(self.run_prepare().returncode,0);self.assertFalse(self.output.exists())

    def test_source_bytes_must_match_the_locked_archive(self):
        self.fixture('driver');(self.source/'LICENSE.md').write_text('changed')
        self.assertNotEqual(self.run_prepare().returncode,0);self.assertFalse(self.output.exists())

    def test_changed_archive_is_rejected(self):
        self.fixture('driver')
        with next(self.archives.glob('*.tar')).open('ab') as stream:stream.write(b'changed')
        self.assertNotEqual(self.run_prepare().returncode,0);self.assertFalse(self.output.exists())

    def test_unreviewed_source_archive_cannot_enter_the_spec(self):
        self.fixture('openvino');self.spec.write_text(self.spec.read_text()+'Source100: another-library.tar\n')
        self.assertNotEqual(self.run_prepare().returncode,0);self.assertFalse(self.output.exists())

    def test_missing_declared_archive_is_rejected(self):
        self.fixture('driver');self.spec.write_text(self.spec.read_text().replace('Source1: level-zero-npu-extensions.tar\n',''))
        self.assertNotEqual(self.run_prepare().returncode,0);self.assertFalse(self.output.exists())

    def test_license_evidence_hash_must_match_the_lock(self):
        self.fixture('driver');self.tar(self.evidence,{'wrong':'bytes'.encode()})
        self.assertNotEqual(self.run_prepare().returncode,0);self.assertFalse(self.output.exists())

    def test_symlinked_source_file_or_parent_is_rejected(self):
        self.fixture('driver');path=self.source/'LICENSE.md';copy=self.root/'copy';path.rename(copy);path.symlink_to(copy)
        self.assertNotEqual(self.run_prepare().returncode,0);self.assertFalse(self.output.exists())
        path.unlink();copy.rename(path)
        path=self.source/'third_party';copy=self.root/'third_party';path.rename(copy);path.symlink_to(copy,target_is_directory=True)
        self.assertNotEqual(self.run_prepare().returncode,0);self.assertFalse(self.output.exists())

    def test_symlinked_output_is_rejected_without_following_it(self):
        self.fixture('driver')
        target=self.root/'uncreated-target'
        self.output.symlink_to(target,target_is_directory=True)
        self.assertNotEqual(self.run_prepare().returncode,0)
        self.assertFalse(target.exists())
        self.assertTrue(self.output.is_symlink())

    def test_existing_output_and_source_overlap_are_rejected(self):
        self.fixture('driver');self.output.mkdir();sentinel=self.output/'sentinel';sentinel.write_bytes(b'keep')
        self.assertNotEqual(self.run_prepare().returncode,0);self.assertEqual(list(self.output.iterdir()),[sentinel]);self.assertEqual(sentinel.read_bytes(),b'keep')
        self.output=self.source/'notices'
        self.assertNotEqual(self.run_prepare().returncode,0);self.assertFalse(self.output.exists())

if __name__=='__main__':unittest.main()
