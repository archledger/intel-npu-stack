# Versioned release site

A release is published as one immutable directory per version under the
committed `BASE_URL` in `crates/stack-install/src/trust.rs`, for example
`https://archledger.github.io/intel-npu-stack/0.1.0/`. The site root has no
index and no `latest` alias. `scripts/ci/release_site.py` composes, checks,
signs and archives that directory. `scripts/ci/release_serve.py` serves it
locally as the Pages host and runs the published install path against it. The
release workflow does not call either tool yet.

## Layout

| Paths under `<version>/` | Source |
|---|---|
| `release.json`, `release.json.sig`, `profile.toml`, `checksums.sha256`, `checksums.sha256.sig`, `assembly-manifest.json`, `repodata/`, `packages/`, `evidence/{spdx,notices,rollback}/` | The signed release tree from `release_sign.py`, byte for byte |
| `intel-npu-stack-install`, `install.sh`, `primary-command.txt` | The pinned installer build; legs a and b must be byte-equal |
| `records/provider-identity.json`, `records/signed-identity.json`, `records/profile-generation.json`, `records/profile-rpm-build.json` | The signing job's records |
| `records/installer-build.json`, `records/installer-trust.rs` | Both leg records and the pinned trust seam |
| `support-matrix.json`, `publication-manifest.json` | Rendered by `compose`, re-rendered by `check` |
| `intel-npu-stack-install.asc`, `install.sh.asc`, `SHA256SUMS`, `SHA256SUMS.asc` | Added by `sign` |

Names must be plain segments of `[A-Za-z0-9][A-Za-z0-9._+-]*`, so dotfiles,
symlinks and special files are refused. `SHA256SUMS` lists every other file,
sorted bytewise, as `<sha256>  <path>`. The archive
`intel-npu-stack-<version>.tar` is an uncompressed GNU tar of the signed site.
Its members are named `<version>/<path>` and sorted bytewise, with uid and gid
0, empty owner names and mtime 1789084800. Every member has mode 0644 except
the installer and `install.sh`, which have 0755.

## Support notes

The kernels a release was tested on are not part of the profile schema. They
are committed as `release/<version>/support-notes.toml`, reviewed with the
promotion change and rendered into `support-matrix.json` and the release notes:

```toml
schema_version = 1
stack_release = "0.1.0"
profile_id = "fedora-44-lunar-lake-x86_64"
not_supported = []

[[tested_kernels]]
release = "7.2.5-200.fc44"
tests = ["install lifecycle", "doctor"]
```

Every tested kernel must lie inside the profile's kernel window and appear
once. The support matrix always adds the requalification line for the window's
upper bound, for example `kernel 7.3 series and later: requires
requalification`.

## Commands

```sh
release_site.py compose --source-commit SHA --tree release-tree --records records \
    --leg-a installer-a --leg-b installer-b --profile PROFILE --output site/0.1.0
release_site.py check --source-commit SHA --site site/0.1.0 --profile PROFILE --stage unsigned --report verification.json
release_site.py sign --source-commit SHA --site site/0.1.0 --profile PROFILE --expected-files verification.json \
    --gpg-home DIR --fingerprint FPR --passphrase-file FILE --require-passphrase
release_site.py check --source-commit SHA --site site/0.1.0 --profile PROFILE --stage signed --expected-files verification.json
release_site.py archive --source-commit SHA --site site/0.1.0 --profile PROFILE --expected-files verification.json \
    --output intel-npu-stack-0.1.0.tar
release_site.py notes --site site/0.1.0 --archive intel-npu-stack-0.1.0.tar --output notes.md
release_serve.py serve-test --site-root site --expected-files verification.json --report serve.json
release_serve.py serve-test --live --site-root site --report live.json
```

The checkout must be at `--source-commit` with unmodified tracked files, and
`--profile` and the support notes must be tracked files of it. Its committed
trust seam and release key are the only trust anchors.

`check` does the following:

- It runs `check_release.py` on an exact copy of the tree's own files.
- It re-pins the committed `trust.rs` with the SHA-256 of `release.json` and
  requires `records/installer-trust.rs` to equal the result.
- It requires the base URL and key fingerprint to match the committed seam.
- It requires the installer to be an x86_64 ELF that embeds the pinned values
  and to match both leg records. The leg records must have every build record
  field: the builder image digest, both toolchain versions, absolute source and
  target directories, the build environment and the umask. They must also
  still agree with each other apart from the perturbed job count, TZ, LANG and
  umask. Leg b must differ from leg a in all four, so a copied leg is refused.
- It requires `records/signed-identity.json` and `records/profile-rpm-build.json`
  to be the records the assembly was built from, as listed in
  `assembly-manifest.json`. Both identity records must be passed production
  identities for the release key. The signed identity must list the release
  packages and the signed repository digest. The provider identity must be the
  signed identity without the profile package and the repository digest.
  `records/profile-generation.json` must be exactly the generator's record for
  this release: the candidate (the selected profile), the provider identity, the
  shipped `profile.toml` and every rewritten component digest. `records/profile-rpm-build.json` must
  describe the one `profile` package of the signed `release.json`, the shipped
  profile, the signed identity's unsigned digest and a reproducible build pair.
  `assembly-manifest.json` is not signed, so its input digests are only a
  consistency check. Every record is validated against signed data.
- It re-renders `install.sh`, `primary-command.txt`, `support-matrix.json` and
  `publication-manifest.json` and requires byte equality, and it requires the
  exact file set.

The signed stage additionally requires:

- the unsigned files to equal the unsigned-stage report;
- `SHA256SUMS` to be exact;
- all three signatures to satisfy the installer's strict release-key policy.

`sign` refuses any fingerprint other than the committed `PRIMARY_FINGERPRINT`.
It runs the unsigned stage again and requires exactly the bytes of the
verification report before it uses the key. Reports and release notes must be
written outside the site, and so must the `serve-test` report. `archive` runs every signed-stage
check before writing, and it refuses an output path inside the site. `notes`
requires the archive to hold exactly the site's files, byte for byte, with the
normalized member metadata. Report and notes paths must not exist yet and are
checked before anything runs. The
release notes are linted against tool and product names that public release
text must not carry.

`serve-test` runs as root in a disposable container in which the Pages host
resolves only to 127.0.0.1. It performs these checks:

- It refuses to run anything unless the site equals its verification report
  and `install.sh` and `primary-command.txt` are exactly the committed
  renderings for the site's installer.
- It adds a throwaway CA to the trust anchors and serves the site on port 443.
  A failure to remove the CA again fails the run.
- It runs the primary command with `--dry-run` as an unprivileged user. The
  command must pass release verification and stop at the platform: exit 10
  `INSTALL_PROFILE_UNSUPPORTED` or exit 30 `INSTALL_PLATFORM_*`. It must fetch
  exactly `install.sh`, the installer, `release.json`, `release.json.sig` and
  `profile.toml`.
- A one-byte change to `release.json` must make the installer fetch it and
  refuse it with `INSTALL_INTEGRITY_FAILED` before fetching its signature. A
  one-byte change to `install.sh` must make the command exit 20 before
  anything else is fetched.
- DNF runs without any proxy and with package and repository signature checks
  against the committed key. It must download every package with the bytes and
  signatures that `release.json` records, and the server log must show the
  signed metadata and every package served by the local fixture.

The server indexes the site's regular files when it starts and serves only
those. `--live` runs the positive checks against the real host. It runs the
published primary command only after the command matches the signed
`SHA256SUMS`. It takes the package inventory from the published `release.json`
after verifying it under the committed key. With `--site-root`, both files
must equal the expected site's. The throwaway CA is removed again even if setup fails. The
exact DNF5 option syntax is proven in the release rehearsal.
