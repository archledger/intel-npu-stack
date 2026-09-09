#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the locked vendor tree and preserve each dependency's license notices."""
from pathlib import Path
import hashlib
import json
import shutil
import sys
import tomllib


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


vendor, lock, output = map(Path, sys.argv[1:])
locked = {(p['name'], p['version']): p['checksum']
          for p in tomllib.loads(lock.read_text())['package'] if 'source' in p}
seen = set()
evidence = []
notices = []
for crate in sorted(vendor.iterdir()):
    package = tomllib.loads((crate / 'Cargo.toml').read_text())['package']
    identity = package['name'], package['version']
    assert identity in locked and identity not in seen, identity
    seen.add(identity)
    checksums = json.loads((crate / '.cargo-checksum.json').read_text())
    assert checksums['package'] == locked[identity], identity
    actual = {str(p.relative_to(crate)) for p in crate.rglob('*') if p.is_file()}
    assert actual == set(checksums['files']) | {'.cargo-checksum.json'}, identity
    for relative, sha in checksums['files'].items():
        path = crate / relative
        assert not path.is_symlink() and path.resolve().is_relative_to(crate.resolve()), path
        assert digest(path) == sha, path
    license_expression = package['license']
    # Every current locked dependency offers MIT, with a Unicode notice in
    # unicode-ident. Reject new expressions until their actual terms are reviewed.
    approved = {
        'MIT', 'MIT OR Apache-2.0', 'Apache-2.0 OR MIT', 'MIT/Apache-2.0',
        'Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT', 'Unlicense OR MIT',
        'MIT OR Apache-2.0 OR LGPL-2.1-or-later', '(MIT OR Apache-2.0) AND Unicode-3.0',
    }
    assert license_expression in approved, (identity, license_expression)
    paths = {p for p in crate.iterdir() if p.is_file()
             and p.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE'))}
    if package.get('license-file'):
        paths.add(crate / package['license-file'])
    if identity == ('r-efi', '6.0.0'):
        authors = crate / 'AUTHORS'
        assert 'AUTHORS-MIT:' in authors.read_text()
        assert 'Permission is hereby granted, free of charge' in authors.read_text()
        paths.add(authors)
    assert paths, (identity, 'missing license evidence')
    files = []
    for path in sorted(paths):
        assert path.is_file() and str(path.relative_to(crate)) in checksums['files'], path
        relative = path.relative_to(vendor)
        files.append({'path': str(relative), 'sha256': digest(path)})
        notices.append((path, relative))
    selected = 'MIT AND Unicode-3.0' if 'Unicode-3.0' in license_expression else 'MIT'
    evidence.append({'crate': identity[0], 'version': identity[1],
                     'declared_license': license_expression, 'selected_license': selected,
                     'registry_checksum': locked[identity], 'files': files})
assert seen == set(locked), 'complete locked registry dependency set required'
output.mkdir()
for source, relative in notices:
    target = output / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
(output / 'cargo-license-evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
print(f'PASS: {len(seen)} locked crates, source checksums and license notices')
