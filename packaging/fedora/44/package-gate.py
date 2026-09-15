#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Build and compare a source-locked Fedora provider recipe in two clean roots.

This provider-pair gate does not confer full-stack release readiness. The tools
recipe consumes the later regenerated provider manifest and is audited after
these native provider outputs exist.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tomllib

REPO = Path(__file__).resolve().parents[3]
FEDORA = REPO/'packaging/fedora/44'
RECIPES = {'firmware': ('intel-npu-stack-firmware', '1.38.0', 'noarch'),
           'driver': ('intel-npu-driver', '1.38.0', 'x86_64'),
           'level-zero': ('oneapi-level-zero', '1.32.0', 'x86_64'),
           'openvino': ('openvino', '2026.2.0', 'x86_64')}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    with path.open('x') as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True)+'\n')


def run(args, **kwargs):
    print('+ '+repr([str(a) for a in args]), flush=True)
    return subprocess.run(list(map(str, args)), check=True, **kwargs)


def query(rpm, format):
    value = run(['rpm', '--noplugins', '-qp', '--queryformat', format, rpm], capture_output=True, text=True).stdout
    require(len(value) <= 16_777_216, 'RPM metadata is too large')
    return value


def canonical(path, directory=True):
    require(path.is_absolute() and path == path.resolve(strict=True), 'canonical absolute path required: '+str(path))
    require(path.is_dir() if directory else path.is_file(), 'wrong input type: '+str(path))
    return path


def safe_name(name):
    name = name.removeprefix('./')
    require(str(PurePosixPath(name)) == name and '..' not in PurePosixPath(name).parts,
            'noncanonical archive path')
    return name


def payload(rpm):
    """Hash payload regular files and resolve hardlinks without extracting paths."""
    files, links, symlinks = {}, {}, {}
    with rpm.open('rb') as stream:
        process = subprocess.Popen(['rpm2archive', '-n', '-f', 'pax', '-'], stdin=stream, stdout=subprocess.PIPE)
        try:
            with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
                for member in archive:
                    name = safe_name(member.name).lstrip('/')
                    require(name not in files and name not in links and name not in symlinks, 'duplicate payload member')
                    if member.isdir():
                        continue
                    if member.islnk():
                        links[name] = safe_name(member.linkname).lstrip('/')
                    elif member.issym():
                        symlinks[name] = member.linkname
                    else:
                        require(member.isfile(), 'unsupported payload member')
                        with archive.extractfile(member) as source:
                            files[name] = (hashlib.file_digest(source, 'sha256').hexdigest(), member.size)
            require(process.wait(timeout=120) == 0, 'rpm2archive failed')
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.kill(); process.wait()
    while links:
        ready = [name for name, target in links.items() if target in files]
        require(ready, 'unresolved payload hardlink')
        for name in ready:
            files[name] = files[links.pop(name)]
    return files, symlinks


def recipe_names(kind):
    name, _, _ = RECIPES[kind]
    if kind == 'firmware':
        return {name}
    if kind in ('driver', 'level-zero'):
        return {name, name+'-debuginfo', name+'-debugsource'}
    runtime = {'openvino', 'openvino-plugins', 'intel-npu-compiler'} | {
        'libopenvino-'+frontend+'-frontend' for frontend in ['ir', 'onnx', 'paddle', 'pytorch', 'tensorflow', 'tensorflow-lite']}
    return runtime | {n+'-debuginfo' for n in runtime} | {'openvino-devel', 'openvino-debugsource'}


def inputs_manifest(top):
    return {str(p.relative_to(top)): sha(p) for folder in ['SOURCES', 'SPECS'] for p in sorted((top/folder).iterdir())}


def rpm_command(top, stage, jobs):
    spec = next((top/'SPECS').glob('*.spec'))
    # Keep actual source/object dependency evidence for the post-build audit.
    # --noclean preserves it without skipping prep, build, install or check.
    retention = ['--noclean'] if stage == '-ba' else []
    return ['rpmbuild', stage, *retention, '--define', '_topdir '+str(top), '--define', '_tmppath '+str(top/'tmp'),
            '--define', '_smp_build_ncpus '+str(jobs), '--define', '_buildhost intel-npu-builder',
            '--define', 'use_source_date_epoch_as_buildtime 1', '--define', 'clamp_mtime_to_source_date_epoch 1', spec]


def audit_tools():
    policy = tomllib.loads((FEDORA/'sbom-policy.toml').read_text())
    require(policy['schema_version'] == 1, 'unsupported SBOM policy')
    for field in ['require_every_binary_rpm', 'require_rpm_identity', 'require_rpm_sha256', 'require_byte_identical_rebuilds']:
        require(policy[field] is True, 'required audit check cannot be disabled: '+field)
    require(re.search(r'(?m)^Version:\s*'+re.escape(policy['syft_version'])+r'\s*$',
                      run(['syft', 'version'], capture_output=True, text=True).stdout), 'Syft version differs')
    require(run(['diffoscope', '--version'], capture_output=True, text=True).stdout.strip() == 'diffoscope '+policy['diffoscope_version'], 'diffoscope version differs')
    return policy


def prepare(args):
    audit_tools()
    run([args.xtask, 'validate-source-lock', '--path', FEDORA/'provider-sources.toml'], cwd=REPO)
    (args.output/'sources').mkdir()
    run([args.xtask, 'bundle-sources', '--lock', FEDORA/'provider-sources.toml', '--cache', args.source_cache,
         '--output', args.output/'sources'], cwd=REPO)
    lock = tomllib.loads((FEDORA/'provider-sources.toml').read_text())
    for record in lock['sources']:
        if record['redistribution'] == 'allowed':
            require(sha(args.output/'sources'/(record['name']+'.tar')) == record['archive_sha256'], 'source archive digest mismatch')
    evidence = args.output/'provider-license-evidence.tar'
    paths = sorted({p for record in lock['sources'] for p in record['license_files']})
    with tarfile.open(evidence, 'w', format=tarfile.USTAR_FORMAT) as archive:
        for relative in paths:
            source = canonical(REPO/relative, False)
            require(REPO in source.parents, 'license evidence leaves repository')
            data = source.read_bytes(); info = tarfile.TarInfo(relative)
            info.size = len(data); info.mode = 0o644; info.mtime = args.epoch
            archive.addfile(info, io.BytesIO(data))
    name, _, _ = RECIPES[args.recipe]
    package = FEDORA/'rpm'/name; spec = package/(name+'.spec')
    inputs = re.findall(r'^(?:Source|Patch)\d+:\s*(\S+)\s*$', spec.read_text(), re.MULTILINE)
    require(len(inputs) == len(set(inputs)), 'duplicate RPM input')
    selected = {}
    for filename in inputs:
        require(Path(filename).name == filename, 'plain RPM input filename required')
        candidates = [p for p in [args.output/'sources'/filename, package/filename, package/'patches'/filename,
                                  FEDORA/'rpm'/filename, FEDORA/filename, args.output/filename] if p.is_file()]
        require(len(candidates) == 1, 'ambiguous or absent RPM source: '+filename)
        selected[filename] = canonical(candidates[0], False)
    manifests = []
    for label in ['preflight', 'build1', 'build2']:
        top = args.output/label/'rpmbuild'; top.mkdir(parents=True)
        for folder in ['SOURCES', 'SPECS', 'BUILD', 'BUILDROOT', 'RPMS', 'SRPMS', 'tmp']:
            (top/folder).mkdir()
        for filename, source in selected.items():
            shutil.copyfile(source, top/'SOURCES'/filename)
        shutil.copyfile(spec, top/'SPECS'/spec.name)
        for folder in ['SOURCES', 'SPECS']:
            for source in (top/folder).iterdir():
                source.chmod(0o644)
                os.utime(source, (args.epoch, args.epoch))
        manifest = inputs_manifest(top); manifests.append(manifest)
        write_json(top.parent/'input-sha256.json', manifest)
    require(manifests[0] == manifests[1] == manifests[2], 'independent source inputs differ')
    run(rpm_command(args.output/'preflight/rpmbuild', '-bp', args.jobs))
    notices = list((args.output/'preflight/rpmbuild/BUILD').glob('*/provider-notices/manifest.json'))
    require(len(notices) == 1, 'pre-compilation notice evidence missing')
    write_json(args.output/'prepared.json', {'source_lock_sha256': sha(FEDORA/'provider-sources.toml'),
                                           'inputs': manifests[0], 'notice_manifest': json.loads(notices[0].read_text())})


def inspect_binary(rpm, args):
    name, version, arch, digest_algo = query(rpm, '%{NAME}\n%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n%{ARCH}\n%{FILEDIGESTALGO}').splitlines()
    require(name in recipe_names(args.recipe), 'unexpected binary RPM')
    require(version == '0:'+RECIPES[args.recipe][1]+'-1.intelnpu.fc44', 'RPM version differs')
    require(arch == RECIPES[args.recipe][2] and digest_algo == '8', 'RPM architecture/digest algorithm differs')
    for option in ['--scripts', '--triggers', '--filetriggers']:
        require(not run(['rpm', '--noplugins', '-qp', option, rpm], capture_output=True, text=True).stdout.strip(), 'RPM scripts are forbidden')
    format = '[%{FILENAMES:json}\t%{FILEMODES:octal}\t%{FILEDIGESTS:json}\t%{LONGFILESIZES}\t%{FILELINKTOS:json}\n]'
    files, links = {}, {}
    for row in query(rpm, format).splitlines():
        path, mode, digest, size, target = row.split('\t')
        path, mode, digest, target = json.loads(path), int(mode, 8), json.loads(digest), json.loads(target)
        require(safe_name(path) == path and path.startswith('/usr/'), 'RPM owns a path outside /usr')
        if stat.S_ISREG(mode):
            require(not mode & 0o6000, 'set-id RPM file forbidden')
            files[path.lstrip('/')] = (digest, int(size))
        elif stat.S_ISLNK(mode):
            links[path.lstrip('/')] = target
        else:
            require(stat.S_ISDIR(mode), 'unsupported RPM file type')
    actual, actual_links = payload(rpm)
    require(actual == files and actual_links == links, 'RPM payload differs from header')
    return {'name': name, 'version': version, 'sha256': sha(rpm), 'regular_files': len(files)}


def build(args):
    top = args.build_root
    require(inputs_manifest(top) == json.loads((top.parent/'input-sha256.json').read_text()), 'sealed build inputs changed')
    for folder in ['BUILD', 'BUILDROOT', 'RPMS', 'SRPMS', 'tmp']:
        require(not any((top/folder).iterdir()), 'build root is not clean')
    run(rpm_command(top, '-ba', args.jobs))
    rpms = sorted((top/'RPMS').rglob('*.rpm')); srpms = list((top/'SRPMS').glob('*.rpm'))
    records = [inspect_binary(p, args) for p in rpms]
    require({r['name'] for r in records} == recipe_names(args.recipe) and len(records) == len(recipe_names(args.recipe)), 'binary RPM set incomplete')
    require(len(srpms) == 1, 'one SRPM required')
    inputs = json.loads((top.parent/'input-sha256.json').read_text())
    sources, links = payload(srpms[0])
    require(not links and {name: value[0] for name, value in sources.items()} == {Path(name).name: digest for name, digest in inputs.items()}, 'SRPM source closure differs')
    # The preflight manifest is independent of successful build cleanup.
    manifest = args.output/'prepared-notices.json'
    expected = json.loads((args.output/'prepared.json').read_text())['notice_manifest']
    if not manifest.exists():
        write_json(manifest, expected)
    require(json.loads(manifest.read_text()) == expected, 'prepared notice evidence changed')
    for rpm, record in zip(rpms, records):
        if record['name'] in expected['packages']:
            result = run([sys.executable, FEDORA/'rpm/verify-provider-notice-rpm.py', '--rpm', rpm, '--manifest', manifest], capture_output=True, text=True)
            write_json(top.parent/(record['name']+'-notice-rpm.json'), json.loads(result.stdout))
    run([sys.executable, FEDORA/'lint-provider-rpms.py', '--manifest', manifest,
         '--output', top.parent/'rpmlint', *rpms, *srpms])
    require(inputs_manifest(top) == inputs, 'build mutated sealed source inputs')
    write_json(top.parent/'build-result.json', {'binary_rpms': records, 'srpm_sha256': sha(srpms[0])})


def compare(args):
    policy = audit_tools()
    sboms = args.output/'sbom'; sboms.mkdir()
    diffs = args.output/'diffoscope'; diffs.mkdir()
    sets, evidence = [], []
    for label in ['build1', 'build2']:
        top = args.output/label/'rpmbuild'
        records = json.loads((top.parent/'build-result.json').read_text())['binary_rpms']
        expected = {row['name']: row for row in records}
        files = {str(p.relative_to(top)): p for folder in ['RPMS', 'SRPMS'] for p in sorted((top/folder).rglob('*.rpm'))}
        require(len(files) == len(recipe_names(args.recipe))+1, 'artifact set changed before comparison')
        sets.append(files)
        for relative, rpm in files.items():
            record = {'build': label, 'path': relative, 'sha256': sha(rpm)}
            if relative.startswith('RPMS/'):
                name = query(rpm, '%{NAME}'); require(expected[name]['sha256'] == record['sha256'], 'RPM changed after build acceptance')
                output = sboms/(label+'-'+rpm.name+'.spdx.json')
                run(['syft', 'scan', 'file:'+str(rpm), '--parallelism', '1', '-o', 'spdx-json='+str(output)])
                document = json.loads(output.read_text())
                require(document['spdxVersion'] == policy['spdx_version'], 'SPDX version differs')
                require(any(p.get('name') == name and p.get('versionInfo') == expected[name]['version'] for p in document['packages']), 'SBOM package identity missing')
                require(any(c.get('algorithm') == 'SHA256' and c.get('checksumValue') == record['sha256'] for p in document['packages'] for c in p.get('checksums', [])), 'SBOM RPM digest missing')
                record['sbom_sha256'] = sha(output)
            else:
                require(record['sha256'] == json.loads((top.parent/'build-result.json').read_text())['srpm_sha256'], 'SRPM changed after acceptance')
            evidence.append(record)
    require(sets[0].keys() == sets[1].keys(), 'build artifact names differ')
    comparisons = []
    for relative in sorted(sets[0]):
        left, right = sets[0][relative], sets[1][relative]
        report = diffs/(left.name+'.json')
        result = subprocess.run(['diffoscope', '--output-empty', '--json', str(report), '--text', str(report.with_suffix('.txt')),
                                 '--max-report-size', '10485760', '--max-text-report-size', '10485760', str(left), str(right)])
        comparisons.append({'path': relative, 'exit_code': result.returncode, 'sha256_equal': sha(left) == sha(right)})
        (args.output/'comparison-progress.json').write_text(json.dumps(comparisons, indent=2)+'\n')
    write_json(args.output/'comparison.json', {'artifacts': evidence, 'comparisons': comparisons})
    require(all(row['exit_code'] == 0 and row['sha256_equal'] for row in comparisons), 'independent artifacts differ or diffoscope failed')


def orchestrate(args):
    canonical(args.source_cache); canonical(args.output); canonical(args.xtask, False)
    require(os.access(args.xtask, os.X_OK), 'executable xtask required')
    for first, second in [(args.source_cache, args.output), (REPO, args.output)]:
        require(first != second and first not in second.parents and second not in first.parents, 'input and output roots overlap')
    require(not any(args.output.iterdir()), 'output must be empty')
    for image in [args.builder_image, args.audit_image]:
        require(re.fullmatch('sha256:[a-f0-9]{64}', image), 'immutable image digest required')
    require(1 <= args.jobs <= 10 and re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*', args.cpuset), 'bounded jobs and explicit CPU set required')
    require(args.epoch > 0, 'positive source epoch required')
    write_json(args.output/'invocation.json', {**{k: str(v) for k, v in vars(args).items()},
                                              'started_at': datetime.now(timezone.utc).isoformat(),
                                              'source_lock_sha256': sha(FEDORA/'provider-sources.toml')})
    logs = args.output/'logs'; logs.mkdir()
    (args.output/'tmp').mkdir()
    for phase, build_name in [('prepare', ''), ('build', 'build1'), ('build', 'build2'), ('compare', '')]:
        image = args.builder_image if phase == 'build' else args.audit_image
        command = [args.runtime, 'run', '--pull=never', '--restart=no', '--network=none', '--cpus='+str(args.jobs),
                   '--cpuset-cpus='+args.cpuset, '--memory=22g', '--memory-swap=30g', '--user='+str(os.getuid())+':'+str(os.getgid()),
                   '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev,size=1g,mode=1777']
        if args.runtime == 'podman':
            command += ['--userns=keep-id']
        for path, readonly in [(REPO, True), (args.source_cache, True), (args.xtask, True), (args.output, False)]:
            require(',' not in str(path), 'container mount path cannot contain commas')
            command += ['--mount', 'type=bind,src='+str(path)+',dst='+str(path)+(',readonly' if readonly else '')]
        if build_name:
            command += ['--mount', 'type=bind,src='+str(args.output/build_name)+',dst=/work']
            for folder in ['SOURCES', 'SPECS']:
                command += ['--mount', 'type=bind,src='+str(args.output/build_name/'rpmbuild'/folder)+',dst=/work/rpmbuild/'+folder+',readonly']
        command += ['--env', 'HOME=/tmp', '--env', 'TMPDIR='+str(args.output/'tmp'), '--env', 'SOURCE_DATE_EPOCH='+str(args.epoch), '--env', 'CMAKE_BUILD_PARALLEL_LEVEL='+str(args.jobs),
                    '--env', 'CARGO_NET_OFFLINE=true', '--env', 'SYFT_CHECK_FOR_APP_UPDATE=false',
                    '--workdir', str(REPO), image, 'python3', str(Path(__file__).resolve()),
                    '--worker', phase, '--recipe', args.recipe, '--source-cache', str(args.source_cache), '--output', str(args.output),
                    '--xtask', str(args.xtask), '--epoch', str(args.epoch), '--jobs', str(args.jobs)]
        if build_name:
            command += ['--build', build_name, '--build-root', '/work/rpmbuild']
        with (logs/(build_name or phase)).open('x') as log:
            run(command, stdout=log, stderr=subprocess.STDOUT)
    comparison = json.loads((args.output/'comparison.json').read_text())
    require(comparison['comparisons'] and all(r['exit_code'] == 0 and r['sha256_equal'] for r in comparison['comparisons']), 'comparison evidence does not pass')
    write_json(args.output/'result.json', {'provider_pair_passed': True, 'recipe': args.recipe, 'release_ready': False,
                                         'scope': 'provider artifact reproduction and raw RPM SPDX; full package/static/source closure is separate',
                                         'comparison_sha256': sha(args.output/'comparison.json'),
                                         'source_lock_sha256': sha(FEDORA/'provider-sources.toml')})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', required=True, choices=sorted(RECIPES))
    for name in ['source-cache', 'output', 'xtask']:
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--builder-image'); parser.add_argument('--audit-image')
    parser.add_argument('--epoch', required=True, type=int)
    parser.add_argument('--jobs', required=True, type=int)
    parser.add_argument('--cpuset', default='')
    parser.add_argument('--runtime', choices=['podman', 'docker'], default='podman')
    parser.add_argument('--worker', choices=['prepare', 'build', 'compare'])
    parser.add_argument('--build', choices=['build1', 'build2'])
    parser.add_argument('--build-root', type=Path)
    args = parser.parse_args()
    try:
        if args.worker:
            {'prepare': prepare, 'build': build, 'compare': compare}[args.worker](args)
        else:
            require(args.builder_image and args.audit_image, 'explicit build and audit image digests required')
            orchestrate(args)
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Fedora provider pair gate: '+str(error)+'\n')
