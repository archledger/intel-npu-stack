#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Bind reviewed notices to every bundled source archive before compilation.

This verifies explicit notice coverage and bytes, not a legal conclusion about
all source files. A source graph change requires updating and reviewing this map.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import tomllib

LLVM_NOTICES = (
    'llvm/LICENSE.TXT', 'mlir/LICENSE.TXT', 'llvm/lib/Support/COPYRIGHT.regex',
    'llvm/lib/Support/BLAKE3/LICENSE', 'llvm/lib/Support/ConvertUTF.cpp',
    'llvm/lib/Support/MD5.cpp', 'llvm/lib/Support/xxhash.cpp',
    'llvm/lib/Support/regstrlcpy.c', 'llvm/include/llvm/Support/ConvertUTF.h',
    'llvm/include/llvm/Support/MD5.h', 'llvm/include/llvm/Support/xxhash.h',
)
DRIVER_NOTICES = (
    'LICENSE.md', 'compiler/include/npu_driver_compiler.h',
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
    'firmware/include/api/vpu_pwrmgr_api.h',
)
# archive name, source-tree prefix, installed-notice prefix, members in archive
POLICY = {
    'openvino': {
        'openvino': (
            ('openvino', '', '', ('LICENSE', 'licensing/third-party-programs.txt')),
            ('openvino-flatbuffers', 'thirdparty/flatbuffers/flatbuffers/', 'thirdparty/flatbuffers/flatbuffers/', ('LICENSE',)),
            ('openvino-onnx', 'thirdparty/onnx/onnx/', 'thirdparty/onnx/onnx/', ('LICENSE',)),
            ('openvino-protobuf', 'thirdparty/protobuf/protobuf/', 'thirdparty/protobuf/protobuf/', ('LICENSE', 'third_party/utf8_range/LICENSE')),
            ('openvino-mlas', 'src/plugins/intel_cpu/thirdparty/mlas/', 'src/plugins/intel_cpu/thirdparty/mlas/', ('LICENSE',)),
            ('openvino-onednn-cpu', 'src/plugins/intel_cpu/thirdparty/onednn/', 'src/plugins/intel_cpu/thirdparty/onednn/', ('LICENSE', 'THIRD-PARTY-PROGRAMS')),
            ('openvino-onednn-gpu', 'src/plugins/intel_gpu/thirdparty/onednn_gpu/', 'src/plugins/intel_gpu/thirdparty/onednn_gpu/', ('LICENSE', 'THIRD-PARTY-PROGRAMS')),
            ('level-zero-npu-extensions', 'src/plugins/intel_npu/thirdparty/level-zero-ext/', 'src/plugins/intel_npu/thirdparty/level-zero-ext/', ('LICENSE.txt',)),
        ),
        'intel-npu-compiler': (
            ('npu-compiler', 'thirdparty/npu-compiler/', '', ('LICENSE',)),
            ('npu-compiler-elf-openvino', 'thirdparty/npu-compiler/thirdparty/elf/', 'thirdparty/elf/', ('LICENCE',)),
            ('intel-npu-nn-cost-model', 'thirdparty/npu-compiler/thirdparty/vpucostmodel/', 'thirdparty/vpucostmodel/', ('LICENSE',)),
            ('intel-npu-compiler-llvm', 'thirdparty/npu-compiler/thirdparty/llvm-project/', 'thirdparty/llvm-project/', LLVM_NOTICES),
        ),
    },
    'driver': {'intel-npu-driver': (
        ('linux-npu-driver', '', '', DRIVER_NOTICES),
        ('level-zero-npu-extensions', 'third_party/level-zero-npu-extensions/', 'third_party/level-zero-npu-extensions/', ('LICENSE.txt',)),
        ('npu-compiler-elf-driver', 'third_party/npu_compiler_elf/', 'third_party/npu_compiler_elf/', ('LICENCE',)),
    )},
    'firmware': {'intel-npu-stack-firmware': (
        ('linux-npu-driver', '', '', ('firmware/bin/COPYRIGHT',)),
    )},
}


# Explicitly reviewed notice-bearing files observed in the native input graph.
# Preserve the complete source bytes, including embedded third-party notices.
SOURCE_NOTICE_ADDITIONS = {'intel-npu-compiler-llvm': ('llvm/lib/Support/regcomp.c',
                             'llvm/lib/Support/regengine.inc',
                             'llvm/lib/Support/regerror.c',
                             'llvm/lib/Support/regex2.h',
                             'llvm/lib/Support/regex_impl.h',
                             'llvm/lib/Support/regexec.c',
                             'llvm/lib/Support/regfree.c',
                             'llvm/lib/Support/regutils.h'),
 'npu-compiler': ('src/vpux_compiler/include/vpux/compiler/NPU37XX/dialect/NPUReg37XX/firmware_headers/details/api/vpu_cmx_info_37xx.h',
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
                  'src/vpux_compiler/src/pipelines/compilation_options.cpp'),
 'openvino': ('licensing/onednn_third-party-programs.txt',
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
              'src/plugins/intel_gpu/thirdparty/rapidjson/writer.h'),
 'openvino-mlas': ('inc/mlas.h',
                   'lib/qdwconv_kernelsize.cpp',
                   'lib/reorder.cpp',
                   'lib/x86_64/AssembleAvxVnni.h'),
 'openvino-onednn-cpu': ('third_party/ittnotify/disable_warnings.h',
                         'third_party/ittnotify/ittnotify.h',
                         'third_party/ittnotify/ittnotify_config.h',
                         'third_party/ittnotify/ittnotify_static.c',
                         'third_party/ittnotify/ittnotify_static.h',
                         'third_party/ittnotify/ittnotify_types.h',
                         'third_party/ittnotify/ittptmark64.S',
                         'third_party/ittnotify/jitprofiling.c',
                         'third_party/ittnotify/jitprofiling.h',
                         'third_party/ittnotify/legacy/ittnotify.h'),
 'openvino-protobuf': ('src/google/protobuf/stubs/casts.h',
                       'src/google/protobuf/stubs/mutex.h',
                       'src/google/protobuf/stubs/platform_macros.h')}

def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular(path):
    require(path.absolute() == path.resolve(strict=True) and path.is_file(),
            'expected a canonical regular file: '+str(path))
    return path


def member_bytes(tar, name):
    member = tar.getmember(name)
    require(member.isfile() and 0 < member.size <= 1_048_576,
            'notice must be a nonempty bounded regular member: '+name)
    with tar.extractfile(member) as stream:
        return stream.read()


def inspect_inputs(kind, spec, source_lock, license_evidence, archives):
    groups = POLICY[kind]
    expected_archives = {row[0] for rows in groups.values() for row in rows}
    source_lines = re.findall(r'^Source\d+:\s*(\S+)\s*$', regular(spec).read_text(), re.MULTILINE)
    archive_names = [n for n in source_lines if n.endswith(('.tar', '.tar.gz', '.tgz', '.tar.xz', '.tar.zst', '.zip'))]
    require(len(archive_names) == len(set(archive_names)), 'duplicate source archive declaration')
    require(set(archive_names) == {n+'.tar' for n in expected_archives} | {'provider-license-evidence.tar'},
            'source archives differ from the reviewed notice coverage map')
    document = tomllib.loads(regular(source_lock).read_text())
    require(document['schema_version'] == 1 and document['status'] == 'sealed', 'sealed source lock required')
    records = document['sources']
    require(0 < len(records) <= 128, 'bounded source lock required')
    sources = {r['name']: r for r in records}
    require(len(sources) == len(records) and expected_archives <= sources.keys(), 'source identities must be unique and present')
    system_notices = {}
    if kind == 'openvino':
        # The pinned Fedora header-only JSON dependency is newer than the
        # attribution in OpenVINO's upstream third-party-programs.txt.
        filename = 'json-3.12.0-LICENSE.MIT'
        require(source_lines.count(filename) == 1, 'JSON notice must be an explicit SRPM source')
        links = [link for link in sources['openvino'].get('gitlinks', [])
                 if link['path'] == 'thirdparty/json/nlohmann_json']
        require(len(links) == 1 and links[0]['disposition'] == 'system'
                and links[0]['packages'] == [{'name': 'json-devel', 'nevr': '0:3.12.0-2.fc44'}],
                'JSON notice requires the reviewed system provider')
        data = regular(archives/filename).read_bytes()
        require(hashlib.sha256(data).hexdigest()
                == '46a65cffd1ea955132d95a8dd921640714a8d6b537d2e4e482d31145ae95b603',
                'system JSON notice digest mismatch')
        system_notices['system/json/LICENSE.MIT'] = (None, data)
    if kind == 'driver':
        # Preserve the complete terms for the redistributed Linux UAPI header.
        # These are explicit, hash-bound sources, not inferred from host files.
        for name, digest in (
            ('GPL-2.0', 'f6b78c087c3ebdf0f3c13415070dd480a3f35d8fc76f3d02180a407c1c812f79'),
            ('Linux-syscall-note', '8e378ab93586eb55135d3bc119cce787f7324f48394777d00c34fa3d0be3303f'),
        ):
            filename = 'linux-uapi-'+name
            require(source_lines.count(filename) == 1, 'UAPI terms must be explicit SRPM sources')
            data = regular(archives/filename).read_bytes()
            require(hashlib.sha256(data).hexdigest() == digest, 'UAPI license or exception digest mismatch')
            system_notices['linux-uapi/'+name] = (None, data)
    with tarfile.open(regular(license_evidence), 'r:') as evidence:
        for record in records:
            paths = record['license_files']
            require(0 < len(paths) <= 64 and paths == sorted(set(paths)), 'sorted, unique license evidence paths required')
            digest = hashlib.sha256()
            for relative in paths:
                path = PurePosixPath(relative)
                require(not path.is_absolute() and '..' not in path.parts
                        and str(path) == relative and relative.startswith('packaging/fedora/44/licenses/'),
                        'unsafe license evidence path')
                digest.update(member_bytes(evidence, relative))
            require(digest.hexdigest() == record['license_evidence_sha256'], 'source-lock license evidence mismatch: '+record['name'])
    packages = {}
    with ExitStack() as stack:
        opened = {}
        for name in sorted(expected_archives):
            record = sources[name]
            require(record['redistribution'] == 'allowed', 'source is not redistributable: '+name)
            path = regular(archives/(name+'.tar'))
            require(sha(path) == record['archive_sha256'], 'source archive digest mismatch: '+name)
            opened[name] = stack.enter_context(tarfile.open(path, 'r:'))
        for package, rows in groups.items():
            files = {}
            for archive, source_prefix, output_prefix, names in rows:
                for name in (*names, *SOURCE_NOTICE_ADDITIONS.get(archive, ())):
                    destination = 'COPYRIGHT' if kind == 'firmware' else output_prefix+name
                    require(destination not in files, 'duplicate notice destination')
                    files[destination] = (source_prefix+name, member_bytes(opened[archive], archive+'/'+name))
            packages[package] = files
    if system_notices:
        package = 'openvino' if kind == 'openvino' else 'intel-npu-driver'
        require(not (packages[package].keys() & system_notices.keys()), 'duplicate system notice destination')
        packages[package].update(system_notices)
    return packages, {name: sources[name]['archive_sha256'] for name in sorted(expected_archives)}


def prepare(kind, source, archives, spec, source_lock, license_evidence, output):
    source = Path(source).absolute()
    archives = Path(archives).absolute()
    output = Path(os.path.abspath(output))
    require(output == output.resolve() and not output.is_symlink(), 'canonical output path required')
    for root in [source, archives]:
        require(root == root.resolve(strict=True) and root.is_dir(), 'canonical input directory required')
        require(output != root and root not in output.parents, 'output must be outside input directories')
    require(not output.exists(), 'output must not exist')
    packages, archive_hashes = inspect_inputs(kind, Path(spec), Path(source_lock), Path(license_evidence), archives)
    # Complete all checks before publishing any output or beginning compilation.
    for files in packages.values():
        for relative, data in files.values():
            # None denotes a separately hash-bound SRPM source, not an archive member.
            if relative is not None:
                require(regular(source/relative).read_bytes() == data, 'source notice differs from archive: '+relative)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    hashes = {}
    for package, files in sorted(packages.items()):
        folder = output/package
        folder.mkdir()
        seen = {}
        hashes[package] = {}
        for name, (_, data) in sorted(files.items()):
            target = folder/name
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256(data).hexdigest()
            if digest in seen:
                require(seen[digest].read_bytes() == data, 'notice digest collision')
                target.hardlink_to(seen[digest])
            else:
                with target.open('xb') as stream:
                    stream.write(data)
                target.chmod(0o644)
                seen[digest] = target
            hashes[package][name] = digest
        (folder/'SHA256.json').write_text(json.dumps(hashes[package], indent=2, sort_keys=True)+'\n')
        (folder/'SHA256.json').chmod(0o644)
    report = {'schema_version': 1, 'kind': kind, 'source_lock_sha256': sha(Path(source_lock)),
              'spec_sha256': sha(Path(spec)), 'archives': archive_hashes, 'packages': hashes}
    (output/'manifest.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', choices=sorted(POLICY), required=True)
    for option in ['source', 'archives', 'spec', 'source-lock', 'license-evidence', 'output']:
        parser.add_argument('--'+option, type=Path, required=True)
    try:
        print(json.dumps(prepare(**vars(parser.parse_args())), indent=2, sort_keys=True))
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(1, 'provider notice preflight: '+str(error)+'\n')
