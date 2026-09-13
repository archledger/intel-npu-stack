# Native DNF fixtures

Captured using DNF5 5.4.2.1 in disposable Fedora 44 containers. These are structural test fixtures, not a production release or host inventory.

- install.json: exact local tools/metapackage/firmware Install plan; aliases tools.rpm/meta.rpm/firmware.rpm reflect its local input filenames.
- upgrade.json and installed-before-upgrade.txt: full signed native lifecycle harness, eleven provider upgrades plus three project installs from an isolated Fedora baseline. Public test-key records are included; no private key or hardware identity is present.
- dependencies.json: real cache-only createrepo_c plan with two dependencies from Fedora metadata. The package database was unchanged.
- dependency-inputs.json: exact three Fedora RPM identities and digests independently verified against the pinned Fedora 44 signing key.
- full-dependency-install.json: the 434 Install records from the captured native rollback dependency transaction; the separate eleven Downgrade and eleven Replaced rows are excluded from this install-only fixture.
- fedora-dependency-identities.json: those 434 independently verified RPM identities and digests, including six packages with older distribution tags. The unit test substitutes tiny bytes and captured-format process responses to test the verifier boundary; separate offline integration exercises the real RPMs through the same library.

Upgrade parsing tests use the accepted unsigned package identities to exercise structural binding and version checks. The captured native plan records NEVRAs and paths, not RPM digests. Actual signed-file digests, identical unsigned/signed payload checks, native signatures and completed lifecycle evidence are retained separately under the shared ledger's 2026-09-11-phase3b-signed-native-lifecycle and related exports. Passing these parser tests does not authenticate release metadata or authorize execution.
