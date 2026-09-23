#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Contract for composing, checking, signing, archiving and describing the versioned release site."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import unittest

import release_installer as installer
import release_site as site_tool
import release_trust as trust
import test_check_release as fixtures
from test_release_installer import BUILD_ENV, FakeCargo, elf_header, git

REPO = Path(__file__).resolve().parents[2]
BASE_URL = 'https://archledger.github.io/intel-npu-stack/0.1.0/'
TOOLS = all(shutil.which(tool) for tool in ['gpg', 'gpgconf', 'git', 'rpmbuild', 'rpmsign', 'rpmkeys'])
BINARY = 'intel-npu-stack-install'
PLATFORM = '''
[platform]
id = "fedora"
version_id = "44"
arch = "x86_64"

[[hardware]]
vendor = "8086"
device = "643e"

[kernel]
min = "7.2.5"
max_exclusive = "7.3.0"
module = "intel_vpu"
'''
NOTES = '''schema_version = 1
stack_release = "0.1.0"
profile_id = "fedora-44-verifier-fixture"
not_supported = ["Meteor Lake and Arrow Lake NPUs"]

[[tested_kernels]]
release = "7.2.5-200.fc44"
tests = ["install lifecycle", "doctor"]

[[tested_kernels]]
release = "7.2.6-200.fc44"
tests = ["suspend and resume", "cold boot"]
'''


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def build_site_tree(root, key):
    """The verifier's signed fixture tree with a platform, hardware and kernel window and the Pages base URL."""
    tree = fixtures.build_tree(root, key)
    for path in [tree / 'profile.toml', tree.parent / 'repo-profile.toml']:
        path.write_text(path.read_text() + PLATFORM)
    release = json.loads((tree / 'release.json').read_text())
    release['profile_sha256'] = fixtures.sha(tree / 'profile.toml')
    release['repository']['base_url'] = BASE_URL
    (tree / 'release.json').write_text(json.dumps(release, indent=2, sort_keys=True) + '\n')
    key.sign(tree / 'release.json')
    fixtures.reseal(tree, key=key)
    return tree


def scratch_repo(root, key, profile):
    """A committed checkout whose trust root is the throwaway key, as in the rehearsal."""
    for relative in ['Cargo.toml', 'crates/stack-install/src/trust.rs', 'packaging/fedora/44/repository/assemble.py',
                     'install/render-bootstrap.py']:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / relative, target)
    (root / trust.KEY_PATH).parent.mkdir(parents=True)
    shutil.copyfile(key.public, root / trust.KEY_PATH)
    source = root / trust.TRUST_PATH
    source.write_text(source.read_text().replace('1085FBE578732D1CF0C50417A8FE2F718B8763D8', key.fingerprint))
    notes = root / 'release/0.1.0/support-notes.toml'
    notes.parent.mkdir(parents=True)
    notes.write_text(NOTES)
    (root / 'profiles/fedora/44').mkdir(parents=True)
    shutil.copyfile(profile, root / 'profiles/fedora/44/fixture.toml')
    git(root, 'init', '-q')
    git(root, 'add', '-A')
    git(root, 'commit', '-q', '-m', 'scratch')
    return git(root, 'rev-parse', 'HEAD')


class Fixture:
    def __init__(self, base):
        self.base = base
        for home in ['keyring', 'other-keyring']:
            (base / home).mkdir(mode=0o700)
        self.key = fixtures.ThrowawayKey(base / 'keyring')
        self.other = fixtures.ThrowawayKey(base / 'other-keyring')
        self.tree = build_site_tree(base / 'tree', self.key)
        self.repo = base / 'repo'
        self.commit = scratch_repo(self.repo, self.key, base / 'repo-profile.toml')
        self.profile = self.repo / 'profiles/fedora/44/fixture.toml'
        self.notes = self.repo / 'release/0.1.0/support-notes.toml'
        self.legs = {}
        for leg, environ in (('a', BUILD_ENV),
                             ('b', {**BUILD_ENV, 'CARGO_BUILD_JOBS': '1', 'TZ': 'Pacific/Chatham',
                                    'LANG': 'de_DE.UTF-8'})):
            self.legs[leg] = base / ('leg-' + leg)
            installer.build(self.repo, self.commit, self.tree, self.legs[leg], leg, base / 'src', base / 'target',
                            runner=FakeCargo(), environ=environ)
            shutil.rmtree(base / 'src')
            shutil.rmtree(base / 'target')
        self.records = base / 'records'
        self.records.mkdir()
        for name in site_tool.SIGN_RECORDS:
            (self.records / name).write_text('{}\n')
        (self.records / 'signed-identity.json').write_text(json.dumps(
            {'repomd_sha256': fixtures.sha(self.tree / 'repodata/repomd.xml'),
             'primary_fingerprint': self.key.fingerprint}) + '\n')
        (self.records / 'profile-rpm-build.json').write_text('{"reproducible": true}\n')
        # The assembler records the digests of the signing records it was built from.
        manifest = json.loads((self.tree / 'assembly-manifest.json').read_text())
        manifest['input_digests'] = {name: fixtures.sha(self.records / name)
                                     for name in ['signed-identity.json', 'profile-rpm-build.json']}
        (self.tree / 'assembly-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        self.site = base / 'site/0.1.0'
        self.report = site_tool.compose(self.repo, self.commit, self.tree, self.records, self.legs['a'],
                                        self.legs['b'], self.profile, self.notes, self.site)
        self.signed = base / 'signed/0.1.0'
        shutil.copytree(self.site, self.signed)
        self.sign(self.signed)

    def sign(self, site, expected=None):
        return site_tool.sign(site, self.key.home, self.key.fingerprint, self.repo, self.commit, self.profile,
                              self.notes, self.report['files'] if expected is None else expected)

    def archive(self, site, output):
        return site_tool.archive(site, output, self.repo, self.commit, self.profile, self.notes, self.report['files'])

    def verify(self, site, stage='unsigned', expected=None, notes=None, commit=None):
        return site_tool.verify_site(site, self.repo, commit or self.commit, self.profile, notes or self.notes, stage,
                                     expected if expected is not None or stage == 'unsigned'
                                     else self.report['files'])


FIXTURE = None


def setUpModule():
    global FIXTURE, WORKSPACE
    if TOOLS:
        WORKSPACE = tempfile.TemporaryDirectory(prefix='release-site-')
        FIXTURE = Fixture(Path(WORKSPACE.name))


def tearDownModule():
    if FIXTURE is not None:
        for home in [FIXTURE.key.home, FIXTURE.other.home]:
            subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'all'], capture_output=True, check=False)
        WORKSPACE.cleanup()


class Case(unittest.TestCase):
    def setUp(self):
        if FIXTURE is None:
            self.skipTest('gpg, git and RPM tooling are required')
        self.f = FIXTURE
        self.work = Path(tempfile.mkdtemp(prefix='case-', dir=self.f.base))
        self.addCleanup(shutil.rmtree, self.work, True)

    def copy(self, source):
        target = self.work / 'copy' / source.name
        shutil.copytree(source, target)
        return target

    def refused(self, message, function, *args):
        with self.assertRaises(site_tool.REFUSALS) as caught:
            function(*args)
        self.assertIn(message, str(caught.exception))

    def reseal_tree(self, site):
        """Re-list and re-sign the tree subset of a site after an intended change to it."""
        subset = site_tool.tree_subset(site)
        lines = [f'{fixtures.sha(site / p)}  {p}' for p in sorted(subset - set(site_tool.TREE_EXTRA))]
        (site / 'checksums.sha256').write_text('\n'.join(lines) + '\n')
        self.f.key.sign(site / 'checksums.sha256')
        manifest = json.loads((site / 'assembly-manifest.json').read_text())
        manifest['output_digests'] = {p: fixtures.sha(site / p) for p in manifest['output_digests']}
        (site / 'assembly-manifest.json').write_text(json.dumps(manifest))

    def set_leg_field(self, site, field, value):
        path = site / 'records/installer-build.json'
        document = json.loads(path.read_text())
        for record in document['legs'].values():
            record[field] = value
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')


class Lifecycle(Case):
    def test_composed_site_holds_the_tree_installer_records_and_derived_files(self):
        files = set(site_tool.site_files(self.f.site))
        tree = set(site_tool.site_files(self.f.tree))
        self.assertTrue(tree <= files)
        self.assertEqual(files - tree, {BINARY, 'install.sh', 'primary-command.txt', 'support-matrix.json',
                                        'publication-manifest.json', 'records/installer-build.json',
                                        'records/installer-trust.rs',
                                        *('records/' + name for name in site_tool.SIGN_RECORDS)})
        for name in tree:
            self.assertEqual((self.f.site / name).read_bytes(), (self.f.tree / name).read_bytes(), name)
        self.assertEqual((self.f.site / BINARY).stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.f.site / 'release.json').stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.f.report['stage'], 'unsigned')
        self.assertEqual(set(self.f.report['files']), files)

    def test_manifest_binds_tree_installer_legs_and_site(self):
        manifest = json.loads((self.f.site / 'publication-manifest.json').read_text())
        self.assertTrue(manifest['passed'])
        self.assertEqual(manifest['source_commit'], self.f.commit)
        self.assertEqual(manifest['release_key_fingerprint'], self.f.key.fingerprint)
        metadata = fixtures.sha(self.f.site / 'release.json')
        self.assertEqual(manifest['installer']['pinned']['release_json_sha256'], metadata)
        self.assertEqual(manifest['installer']['pinned']['base_url'], BASE_URL)
        binary = fixtures.sha(self.f.site / BINARY)
        self.assertEqual(manifest['installer']['legs'], {'a': binary, 'b': binary})
        self.assertEqual(manifest['installer']['digests'][BINARY], binary)
        self.assertNotIn('publication-manifest.json', manifest['site_files'])
        self.assertEqual(manifest['site_files']['support-matrix.json'],
                         fixtures.sha(self.f.site / 'support-matrix.json'))
        pinned = (self.f.site / 'records/installer-trust.rs').read_text()
        self.assertEqual(trust.parse_trust(pinned)['metadata_sha256'], metadata)
        legs = json.loads((self.f.site / 'records/installer-build.json').read_text())['legs']
        self.assertEqual(legs['b']['build_environment']['CARGO_BUILD_JOBS'], '1')

    def test_support_matrix_states_the_window_tested_kernels_and_requalification(self):
        matrix = json.loads((self.f.site / 'support-matrix.json').read_text())
        self.assertEqual(matrix['kernel']['min'], '7.2.5')
        self.assertEqual([entry['release'] for entry in matrix['kernel']['tested']],
                         ['7.2.5-200.fc44', '7.2.6-200.fc44'])
        self.assertEqual(matrix['not_supported'], ['kernel 7.3 series and later: requires requalification',
                                                   'Meteor Lake and Arrow Lake NPUs'])
        self.assertEqual(matrix['hardware'], [{'vendor': '8086', 'device': '643e'}])
        self.assertEqual(matrix['qualification']['evidence_id'], 'verifier-fixture-evidence')
        self.assertEqual(matrix['components']['fixture']['package'], 'verifier-fixture')
        self.assertEqual(matrix['repository']['key_fingerprint'], self.f.key.fingerprint)
        self.assertEqual(matrix['channels'], ['stable'])

    def test_signing_adds_exactly_four_files_and_the_signed_stage_passes(self):
        added = set(site_tool.site_files(self.f.signed)) - set(site_tool.site_files(self.f.site))
        self.assertEqual(added, set(site_tool.FINALIZE_FILES))
        lines = (self.f.signed / 'SHA256SUMS').read_text().splitlines()
        listed = [line.split('  ', 1)[1] for line in lines]
        self.assertEqual(listed, sorted(listed, key=str.encode))
        self.assertEqual(set(listed), set(site_tool.site_files(self.f.signed)) - {'SHA256SUMS', 'SHA256SUMS.asc'})
        report = self.f.verify(self.f.signed, 'signed')
        self.assertEqual(report['stage'], 'signed')

    def test_archive_is_byte_identical_and_normalized(self):
        first, second = self.work / 'one/intel-npu-stack-0.1.0.tar', self.work / 'two/intel-npu-stack-0.1.0.tar'
        first.parent.mkdir()
        second.parent.mkdir()
        digest = self.f.archive(self.f.signed, first)
        os.chmod(self.f.signed / 'profile.toml', 0o600)
        try:
            self.assertEqual(self.f.archive(self.f.signed, second), digest)
        finally:
            os.chmod(self.f.signed / 'profile.toml', 0o644)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with tarfile.open(first) as tar:
            members = tar.getmembers()
        names = [member.name for member in members]
        self.assertEqual(names, sorted(names, key=str.encode))
        self.assertEqual(names, ['0.1.0/' + f for f in site_tool.site_files(self.f.signed)])
        for member in members:
            self.assertTrue(member.isreg())
            self.assertEqual((member.uid, member.gid, member.uname, member.gname, member.mtime),
                             (0, 0, '', '', site_tool.EPOCH))
            expected = 0o755 if member.name in {'0.1.0/' + BINARY, '0.1.0/install.sh'} else 0o644
            self.assertEqual(member.mode, expected, member.name)

    def test_notes_carry_the_command_verification_and_digests(self):
        tar = self.work / 'intel-npu-stack-0.1.0.tar'
        self.f.archive(self.f.signed, tar)
        notes = site_tool.render_notes(self.f.signed, tar).decode()
        self.assertIn((self.f.signed / 'primary-command.txt').read_text().rstrip('\n'), notes)
        self.assertIn(self.f.key.fingerprint, notes)
        self.assertIn('kernel 7.3 series and later: requires requalification', notes)
        self.assertIn(fixtures.sha(tar), notes)
        self.assertIn(fixtures.sha(self.f.signed / 'SHA256SUMS'), notes)
        self.assertIn('gh attestation verify intel-npu-stack-0.1.0.tar -R archledger/intel-npu-stack', notes)
        self.assertIn('evidence/rollback/rollback-index.json', notes)

    def test_command_line_checks_the_signed_stage_against_the_report(self):
        report = self.work / 'unsigned-report.json'
        report.write_text(json.dumps(self.f.report))
        out = self.work / 'signed-report.json'
        with contextlib.redirect_stdout(io.StringIO()):
            code = site_tool.main(['check', '--repo', str(self.f.repo), '--source-commit', self.f.commit,
                                   '--site', str(self.f.signed), '--profile', str(self.f.profile), '--stage',
                                   'signed', '--expected-files', str(report), '--report', str(out)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.read_text())['stage'], 'signed')


class Refusals(Case):
    def test_missing_or_extra_files(self):
        site = self.copy(self.f.site)
        (site / 'extra.txt').write_text('x\n')
        self.refused('unexpected', self.f.verify, site)
        (site / 'extra.txt').unlink()
        (site / 'support-matrix.json').unlink()
        self.refused('missing', self.f.verify, site)

    def test_dotfiles_symlinks_and_special_names(self):
        for label, make in {'unsafe site path': lambda s: (s / '.hidden').write_text('x'),
                            'symlink in the site': lambda s: (s / 'link').symlink_to(s / 'release.json')}.items():
            with self.subTest(label):
                site = self.copy(self.f.site)
                make(site)
                self.refused(label, self.f.verify, site)
                shutil.rmtree(site.parent)

    def test_tree_names_may_not_collide_with_site_files(self):
        tree = self.copy(self.f.tree)
        (tree / 'install.sh').write_text('#!/bin/sh\n')
        fixtures.reseal(tree, key=self.f.key)
        self.refused('collide', site_tool.compose, self.f.repo, self.f.commit, tree, self.f.records,
                     self.f.legs['a'], self.f.legs['b'], self.f.profile, self.f.notes, self.work / 'out/0.1.0')
        self.assertFalse((self.work / 'out/0.1.0').exists())

    def test_leg_drift_is_refused(self):
        def compose(leg_b):
            site_tool.compose(self.f.repo, self.f.commit, self.f.tree, self.f.records, self.f.legs['a'], leg_b,
                              self.f.profile, self.f.notes, self.work / 'out/0.1.0')
        leg = self.copy(self.f.legs['b'])
        with (leg / BINARY).open('ab') as stream:
            stream.write(b'drift')
        self.refused('does not bind', compose, leg)
        record = json.loads((leg / 'installer-build.json').read_text())
        record['binary_sha256'] = fixtures.sha(leg / BINARY)
        (leg / 'installer-build.json').write_text(json.dumps(record))
        self.refused('tool drift between legs: intel-npu-stack-install', compose, leg)
        shutil.copyfile(self.f.legs['b'] / BINARY, leg / BINARY)
        record = json.loads((self.f.legs['b'] / 'installer-build.json').read_text())
        record['toolchain']['rustc'] = 'rustc 1.86.0'
        (leg / 'installer-build.json').write_text(json.dumps(record))
        self.refused('tool drift between legs: toolchain', compose, leg)
        record = json.loads((self.f.legs['b'] / 'installer-build.json').read_text())
        record['build_environment']['CARGO_HOME'] = '/elsewhere'
        (leg / 'installer-build.json').write_text(json.dumps(record))
        self.refused('tool drift between legs: build_environment', compose, leg)
        record = json.loads((self.f.legs['b'] / 'installer-build.json').read_text())
        record['image'] = record['caller_environment']['IMAGE_DIGEST'] = 'registry.example/other@sha256:' + 'ab' * 32
        (leg / 'installer-build.json').write_text(json.dumps(record))
        self.refused('tool drift between legs: image', compose, leg)

    def test_leg_records_need_every_provenance_field(self):
        def compose(leg_b):
            site_tool.compose(self.f.repo, self.f.commit, self.f.tree, self.f.records, self.f.legs['a'], leg_b,
                              self.f.profile, self.f.notes, self.work / 'out/0.1.0')
        original = json.loads((self.f.legs['b'] / 'installer-build.json').read_text())
        for field, value in [('image', None), ('toolchain', None), ('src_root', None),
                             ('image', 'fedora:44'), ('toolchain', {'rustc': ''}), ('src_root', 'relative'),
                             ('source_commit', 'abc'), ('umask', '18')]:
            with self.subTest(field=field, value=value):
                leg = self.work / ('leg-' + field)
                shutil.rmtree(leg, ignore_errors=True)
                shutil.copytree(self.f.legs['b'], leg)
                record = dict(original)
                if value is None:
                    del record[field]
                else:
                    record[field] = value
                (leg / 'installer-build.json').write_text(json.dumps(record))
                self.refused('installer leg b record', compose, leg)

    def test_persisted_legs_must_still_agree(self):
        other = 'registry.example/other@sha256:' + 'ab' * 32

        def new_image(legs):
            legs['b']['image'] = legs['b']['caller_environment']['IMAGE_DIGEST'] = other
        for label, change in {
                'toolchain': lambda legs: legs['b']['toolchain'].update(rustc='rustc 1.86.0 (other)'),
                'image': new_image,
                'build_environment': lambda legs: legs['b']['build_environment'].update(PATH='/elsewhere')}.items():
            with self.subTest(label):
                site = self.copy(self.f.site)
                path = site / 'records/installer-build.json'
                document = json.loads(path.read_text())
                change(document['legs'])
                path.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')
                self.refused('tool drift between legs: ' + label, self.f.verify, site)
                shutil.rmtree(site.parent)

    def test_signing_needs_the_verified_unsigned_site(self):
        site = self.copy(self.f.site)
        document = json.loads((site / 'support-matrix.json').read_text())
        document['channels'] = ['stable', 'experimental']
        (site / 'support-matrix.json').write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')
        self.refused('support-matrix.json differs', self.f.sign, site)
        shutil.rmtree(site.parent)
        site = self.copy(self.f.site)
        expected = dict(self.f.report['files'])
        expected['release.json'] = '0' * 64
        self.refused('verified unsigned site', self.f.sign, site, expected)
        self.assertFalse(any((site / name).exists() for name in site_tool.FINALIZE_FILES))

    def test_notes_need_the_archive_of_this_site(self):
        tar = self.work / 'intel-npu-stack-0.1.0.tar'
        self.f.archive(self.f.signed, tar)
        site = self.copy(self.f.signed)
        (site / 'SHA256SUMS').write_text((site / 'SHA256SUMS').read_text() + '\n')
        self.refused('archive', site_tool.render_notes, site, tar)
        other = self.work / 'other/intel-npu-stack-0.1.0.tar'
        other.parent.mkdir()
        with tarfile.open(other, 'w', format=tarfile.GNU_FORMAT) as handle:
            handle.add(self.f.signed / 'release.json', arcname='0.1.0/release.json')
        self.refused('archive', site_tool.render_notes, self.f.signed, other)

    def test_archive_output_must_be_outside_the_site(self):
        site = self.copy(self.f.signed)
        self.refused('outside the site', self.f.archive, site, site / 'intel-npu-stack-0.1.0.tar')
        link = self.work / 'link'
        link.symlink_to(site / 'records')
        self.refused('outside the site', self.f.archive, site, link / 'intel-npu-stack-0.1.0.tar')
        self.assertEqual(set(site_tool.site_files(site)), set(site_tool.site_files(self.f.signed)))

    def test_signing_records_must_be_the_assembly_inputs(self):
        for name in ['signed-identity.json', 'profile-rpm-build.json']:
            with self.subTest(name):
                site = self.copy(self.f.site)
                (site / 'records' / name).write_text('{}\n')
                self.refused('assembly', self.f.verify, site)
                shutil.rmtree(site.parent)

    def test_pinned_trust_must_be_the_committed_seam_pinned_to_release_json(self):
        site = self.copy(self.f.site)
        committed = (self.f.repo / trust.TRUST_PATH).read_text()
        (site / 'records/installer-trust.rs').write_text(trust.pin_metadata(committed, 'ab' * 32))
        self.refused('installer-trust.rs', self.f.verify, site)

    def test_base_url_must_match_the_committed_seam(self):
        site = self.copy(self.f.site)
        release = json.loads((site / 'release.json').read_text())
        release['repository']['base_url'] = BASE_URL + 'mirror/'
        (site / 'release.json').write_text(json.dumps(release, indent=2, sort_keys=True) + '\n')
        self.f.key.sign(site / 'release.json')
        self.reseal_tree(site)
        committed = (self.f.repo / trust.TRUST_PATH).read_text()
        (site / 'records/installer-trust.rs').write_text(
            trust.pin_metadata(committed, fixtures.sha(site / 'release.json')))
        self.refused('base_url', self.f.verify, site)

    def test_release_signed_by_another_key_is_refused(self):
        site = self.copy(self.f.site)
        self.f.other.sign(site / 'release.json')
        self.reseal_tree(site)
        self.refused('pinned release key', self.f.verify, site)

    def test_installer_must_embed_the_pinned_values_and_match_its_records(self):
        site = self.copy(self.f.site)
        (site / BINARY).write_bytes(elf_header())
        self.refused('lacks a pinned trust value', self.f.verify, site)
        (site / BINARY).write_bytes(elf_header(183) + (self.f.site / BINARY).read_bytes()[len(elf_header()):])
        self.refused('x86_64', self.f.verify, site)
        (site / BINARY).write_bytes((self.f.site / BINARY).read_bytes() + b'\0')
        self.refused('binary_sha256', self.f.verify, site)

    def test_tampered_install_sh_is_refused_even_with_matching_records(self):
        site = self.copy(self.f.site)
        tampered = (site / 'install.sh').read_bytes() + b'echo tampered\n'
        (site / 'install.sh').write_bytes(tampered)
        self.set_leg_field(site, 'install_sh_sha256', sha_bytes(tampered))
        self.refused('install.sh differs from its rendering', self.f.verify, site)

    def test_primary_command_must_fetch_install_sh(self):
        site = self.copy(self.f.site)
        render = installer.renderer(self.f.repo)
        wrong = render.render_install_command('0.1.0', BASE_URL + BINARY, fixtures.sha(site / BINARY)).encode()
        (site / 'primary-command.txt').write_bytes(wrong)
        self.set_leg_field(site, 'primary_command_sha256', sha_bytes(wrong))
        self.refused('primary-command.txt differs from its rendering', self.f.verify, site)

    def test_derived_files_must_equal_their_rendering(self):
        for name in ['support-matrix.json', 'publication-manifest.json']:
            with self.subTest(name):
                site = self.copy(self.f.site)
                document = json.loads((site / name).read_text())
                document['schema_version'] = 2
                (site / name).write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')
                self.refused(name + ' differs', self.f.verify, site)
                shutil.rmtree(site.parent)

    def test_support_notes_are_validated(self):
        cases = {
            'outside the profile kernel window': NOTES.replace('7.2.6-200.fc44', '7.3.1-200.fc44'),
            'duplicate tested kernel': NOTES.replace('7.2.6-200.fc44', '7.2.5-200.fc44'),
            'another profile': NOTES.replace('fedora-44-verifier-fixture', 'fedora-44-other'),
            'invalid kernel version': NOTES.replace('7.2.6-200.fc44', '7.2.6-200.fc43'),
            'exactly schema_version': 'extra = 1\n' + NOTES,
        }
        profile = site_tool.load_toml(self.f.site / 'profile.toml')
        release = site_tool.load_json(self.f.site / 'release.json')
        for message, text in cases.items():
            with self.subTest(message):
                self.refused(message, site_tool.support_notes, tomllib.loads(text), profile, release)

    def test_signed_stage_refusals(self):
        site = self.copy(self.f.signed)
        (site / 'SHA256SUMS').write_text((site / 'SHA256SUMS').read_text().replace('  ', '  ./', 1))
        self.refused('SHA256SUMS differs', self.f.verify, site, 'signed')
        shutil.rmtree(site.parent)
        site = self.copy(self.f.signed)
        self.f.other.sign(site / 'install.sh', output=str(site / 'install.sh.asc'))
        (site / 'SHA256SUMS').write_bytes(site_tool.render_sha256sums(site))
        self.f.key.sign(site / 'SHA256SUMS', output=str(site / 'SHA256SUMS.asc'))
        self.refused('signature does not satisfy the pinned release-key policy: install.sh.asc',
                     self.f.verify, site, 'signed')
        (site / 'install.sh.asc').unlink()
        self.refused('missing', self.f.verify, site, 'signed')

    def test_unsigned_files_may_not_change_between_stages(self):
        expected = dict(self.f.report['files'])
        expected['profile.toml'] = '0' * 64
        self.refused('unsigned files changed', self.f.verify, self.f.signed, 'signed', expected)

    def test_release_checkout_must_be_the_source_commit(self):
        self.refused('source commit', self.f.verify, self.f.site, 'unsigned', None, None, 'f' * 40)

    def test_profile_and_support_notes_must_be_tracked_release_files(self):
        outside = self.work / 'profile.toml'
        shutil.copyfile(self.f.profile, outside)
        with self.assertRaises(site_tool.REFUSALS) as caught:
            site_tool.verify_site(self.f.site, self.f.repo, self.f.commit, outside, self.f.notes, 'unsigned')
        self.assertIn('tracked file', str(caught.exception))
        untracked = self.f.repo / 'release/0.1.0/other-notes.toml'
        shutil.copyfile(self.f.notes, untracked)
        self.addCleanup(untracked.unlink)
        self.refused('tracked file', self.f.verify, self.f.site, 'unsigned', None, untracked)

    def test_outputs_are_never_overwritten(self):
        self.refused('already exists', site_tool.compose, self.f.repo, self.f.commit, self.f.tree, self.f.records,
                     self.f.legs['a'], self.f.legs['b'], self.f.profile, self.f.notes, self.f.site)
        self.refused('already signed', self.f.sign, self.f.signed)
        tar = self.work / 'intel-npu-stack-0.1.0.tar'
        tar.write_bytes(b'')
        self.refused('already exists', self.f.archive, self.f.signed, tar)
        (self.work / 'x').mkdir()
        self.refused('missing', self.f.archive, self.f.site, self.work / 'x/intel-npu-stack-0.1.0.tar')

    def test_archive_verifies_the_signed_site_first(self):
        site = self.copy(self.f.signed)
        (site / 'install.sh.asc').write_text('-----BEGIN PGP SIGNATURE-----\nplaceholder\n')
        (site / 'SHA256SUMS').write_bytes(site_tool.render_sha256sums(site))
        self.f.key.sign(site / 'SHA256SUMS', output=str(site / 'SHA256SUMS.asc'))
        output = self.work / 'out/intel-npu-stack-0.1.0.tar'
        output.parent.mkdir()
        self.refused('install.sh.asc', self.f.archive, site, output)
        self.assertFalse(output.exists())

    def test_public_text_lint(self):
        for text in ['Built with Claude', 'see https://chatgpt.com/x', 'Co-Authored-By: someone', 'bell\x07']:
            with self.subTest(text), self.assertRaises(site_tool.SiteRefused):
                site_tool.lint_public_text(text)
        self.assertEqual(site_tool.lint_public_text('Intel NPU Stack 0.1.0\n'), 'Intel NPU Stack 0.1.0\n')


if __name__ == '__main__':
    unittest.main()
