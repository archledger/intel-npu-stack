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
release_site.py sign --site site/0.1.0 --gpg-home DIR --fingerprint FPR --passphrase-file FILE --require-passphrase
release_site.py check --source-commit SHA --site site/0.1.0 --profile PROFILE --stage signed --expected-files verification.json
release_site.py archive --site site/0.1.0 --output intel-npu-stack-0.1.0.tar
release_site.py notes --site site/0.1.0 --archive intel-npu-stack-0.1.0.tar --output notes.md
release_serve.py serve-test --site-root site --report serve.json
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
  and to match both leg records.
- It re-renders `install.sh`, `primary-command.txt`, `support-matrix.json` and
  `publication-manifest.json` and requires byte equality, and it requires the
  exact file set.

The signed stage additionally requires:

- the unsigned files to equal the unsigned-stage report;
- `SHA256SUMS` to be exact;
- all three signatures to satisfy the installer's strict release-key policy.

The release notes are linted against tool and product names that public
release text must not carry.

`serve-test` runs as root in a disposable container in which the Pages host
resolves only to 127.0.0.1. It performs these checks:

- It adds a throwaway CA to the trust anchors and serves the site on port 443.
- It runs the primary command with `--dry-run` as an unprivileged user. The
  command must pass release verification and stop at the platform: exit 10
  `INSTALL_PROFILE_UNSUPPORTED` or exit 30 `INSTALL_PLATFORM_*`. It must fetch
  exactly `install.sh`, the installer, `release.json`, `release.json.sig` and
  `profile.toml`.
- A one-byte change to `release.json` must make it exit 20, and so must a
  one-byte change to `install.sh`, before anything else is fetched.
- DNF, with package and repository signature checks against the committed
  key, must download every package with the bytes and signatures that
  `release.json` records.

The exact DNF5 option syntax is proven in the release rehearsal.
