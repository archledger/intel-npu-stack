#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise source integrity, completeness and reviewed license-layout handling."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile

CHECKER = Path(__file__).with_name('check-vendor-licenses.py')
for case in ['lowercase', 'authors', 'tampered', 'missing-notice', 'unreviewed', 'extra-file', 'missing-crate']:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        vendor = root / 'vendor'
        crate = vendor / 'fixture'
        crate.mkdir(parents=True)
        name, version = ('r-efi', '6.0.0') if case == 'authors' else ('fixture', '1.0.0')
        license_expression = 'unreviewed' if case == 'unreviewed' else 'MIT'
        (crate / 'Cargo.toml').write_text(f'[package]\nname="{name}"\nversion="{version}"\nlicense="{license_expression}"\n')
        (crate / 'lib.rs').write_text('// fixture\n')
        if case == 'authors':
            (crate / 'AUTHORS').write_text('AUTHORS-MIT:\nPermission is hereby granted, free of charge\n')
        elif case != 'missing-notice':
            (crate / 'license-mit').write_text('fixture license notice\n')
        checksum = 'a' * 64
        files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in crate.iterdir()}
        (crate / '.cargo-checksum.json').write_text(json.dumps({'package': checksum, 'files': files}))
        lock = root / 'Cargo.lock'
        lock.write_text(f'[[package]]\nname="{name}"\nversion="{version}"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="{checksum}"\n')
        if case == 'tampered':
            (crate / 'lib.rs').write_text('// changed\n')
        if case == 'extra-file':
            (crate / 'extra.rs').write_text('// unbound\n')
        if case == 'missing-crate':
            with lock.open('a') as stream:
                stream.write(f'[[package]]\nname="missing"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="{checksum}"\n')
        output = root / 'notices'
        result = subprocess.run(['python3', str(CHECKER), str(vendor), str(lock), str(output)], capture_output=True, text=True)
        expected = case in ['lowercase', 'authors']
        assert (result.returncode == 0) == expected, (case, result.stdout, result.stderr)
        if expected:
            evidence = json.loads((output / 'cargo-license-evidence.json').read_text())
            assert len(evidence) == 1 and evidence[0]['registry_checksum'] == checksum
            for notice in evidence[0]['files']:
                assert hashlib.sha256((output / notice['path']).read_bytes()).hexdigest() == notice['sha256']
        else:
            assert not output.exists(), 'reject before writing partial notice evidence'
        print('PASS:', case)
