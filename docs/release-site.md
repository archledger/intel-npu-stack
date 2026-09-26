# Versioned release site

A release is published as one immutable directory per version under the
committed `BASE_URL` in `crates/stack-install/src/trust.rs`, for example
`https://archledger.github.io/intel-npu-stack/0.1.0/`. The site root has no
index and no `latest` alias. `scripts/ci/release_site.py` composes, checks,
signs and archives that directory. `scripts/ci/release_serve.py` serves it
locally as the Pages host and runs the published install path against it. The
release workflow runs them as described in [release-process.md](release-process.md).

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
symlinks and special files are refused, and a directory that cannot be read
fails the inventory. `checksums.sha256` may not list itself, its signature or
`assembly-manifest.json`. `SHA256SUMS` lists every other file,
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
requalification`. The release workflow's preflight applies the same checks to
the notes with `release_inputs.py dispatch-check`, before any key is used.

## Commands

```sh
release_site.py compose --source-commit SHA --tree release-tree --records records \
    --leg-a installer-a --leg-b installer-b --profile PROFILE --output site/0.1.0
release_site.py check --source-commit SHA --site site/0.1.0 --profile PROFILE --stage unsigned \
    --max-bytes 314572800 --report verification.json
release_serve.py serve-test --site-root site --expected-files verification.json --report serve.json
release_site.py sign --source-commit SHA --site site/0.1.0 --profile PROFILE --expected-files verification.json \
    --gpg-home DIR --fingerprint FPR --passphrase-file FILE --require-passphrase
release_site.py check --source-commit SHA --site site/0.1.0 --profile PROFILE --stage signed --expected-files verification.json
release_site.py archive --source-commit SHA --site site/0.1.0 --profile PROFILE --expected-files verification.json \
    --output intel-npu-stack-0.1.0.tar
release_site.py notes --site site/0.1.0 --archive intel-npu-stack-0.1.0.tar --output notes.md
release_serve.py serve-test --live --site-root site --report live.json   # after publication
```

The local serve test runs on the unsigned site with its unsigned-stage report,
before the key is used. To serve a signed site, pass the report of `check
--stage signed`, because the report must describe the site's current files.

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
  packages and the signed repository digest. Each entry must have exactly the
  identity fields: name, version, architecture and role from `release.json`,
  header and payload digests read from the RPM itself, and for component
  providers the selected profile's unsigned digest. The provider identity must be the
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
- It records the bytes of the site's regular files as `total_bytes` in its
  result and `--report`. With `--max-bytes N` it refuses a site larger than N
  bytes. The release workflow's `verify` passes `SITE_BUDGET_BYTES`, the bytes
  its preflight reserves for the new version on Pages.

The signed stage additionally requires:

- the unsigned files to equal the unsigned-stage report;
- `SHA256SUMS` to be exact;
- all three signatures to satisfy the installer's strict release-key policy.

`sign` refuses any fingerprint other than the committed `PRIMARY_FINGERPRINT`.
It runs the unsigned stage again and requires exactly the bytes of the
verification report before it uses the key. Reports and release notes must be
written outside the site, and so must the `serve-test` report. `archive` runs every signed-stage
check before writing, and it refuses an output path inside the site. `notes`
requires the archive to be byte for byte the canonical archive of the site. Report and notes paths must not exist yet and are
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

## Publication

`scripts/ci/release_inputs.py dispatch-check` checks the dispatch against the
committed trust seam and validates the support notes of the selected profile.
`fetch-check` then fetches the prepared release inputs tarball and checks it
before any key exists. The download is HTTPS only, including redirects, and the
tarball must have the dispatched SHA-256. Extraction accepts only regular files
and directories with plain relative names, each once, and uses the tarfile data
filter. `release_sign.py --check-inputs` then validates the result.
`extract-check` repeats this for the copy passed between jobs, which must also
match the preflight job's digest.

`scripts/ci/release_publish.py` publishes through the GitHub REST API, using
only the standard library. Its options must be spelled in full, and `GH_TOKEN`
must be 1 to 4096 visible ASCII characters, without spaces or line breaks, so a
malformed token is refused without being echoed.

Versions are published in increasing order, and the gates `compose-pages`
applies to the other versions run before anything irreversible. Both
`check-unpublished` phases and `publish-release` also run `compose-pages` dry
into a temporary directory over every non-draft `vX.Y.Z` release but this one,
before they classify or create anything: the preflight after its Pages, tag,
release and live checks, the publish phase and `publish-release` after the
publication checks. Every `compose-pages` gate below applies, including the
live `SHA256SUMS` of each composed version and an entry in the committed
registry `release/published-versions.json` (`--registry`) for every other
tagged version, so the change that records a release must land before the next
release. This version must be newer than all of those releases, retired ones
included, and not yet listed in the registry, and the composed site plus this
version's bytes must stay within 950 MiB. The preflight reserves
`--reserve-bytes` for this version, since its site is not built yet; the
publish phase and `publish-release` reserve the new site's size.

- `check-unpublished --phase preflight` refuses unless Pages is served by
  GitHub Actions at the committed base URL, no tag or release exists for the
  version, the live `release.json` returns exactly 404 and the dry composition
  passes. GitHub lists drafts only to a token that can push, and the release
  workflow's preflight token can only read, so a draft left by an aborted run
  is not seen there. The publish phase finds it and refuses it unless it can
  resume it.
- `check-unpublished --phase publish` first checks the publication itself. The
  three separate files must be the archive's own copies, and `SHA256SUMS.asc`
  must pass the release-key policy. The archive must hold exactly the files
  `SHA256SUMS` lists. Its signed `publication-manifest.json` must name this
  version, the committed base URL and release key, and the release commit, and
  `install.sh.asc` must pass the release-key policy. The archive must be the
  canonical archive of its site, and the site must fit the 950 MiB Pages
  budget. After the dry composition it classifies the state as fresh, a draft
  to resume (its assets a byte-identical subset of this publication, targeting
  the release commit, and no tag at another commit) or a published release to
  resume (immutable, exactly these assets, tag at the release commit).
  Prereleases and anything else are refused, and a stale draft is deleted by
  hand.
- `publish-release` runs the same publication checks and the dry composition
  before it creates or resumes anything, and the notes must be the
  `release_site.py notes` rendering of this site and archive. It streams the
  archive, `SHA256SUMS`, `SHA256SUMS.asc` and `publication-manifest.json` to a
  draft. It sets the draft's title and notes to this publication's and streams
  every asset back to disk without sending the token to the storage host. Right
  before publishing it reads the draft again: it must still be a draft, not a
  prerelease, of this tag and commit, with this title, notes and exactly these
  assets, and the tag must be absent or name the release commit. The other
  non-draft `vX.Y.Z` releases and the `v` tags, with the object each tag names
  in the tag listing, must still be as the dry composition found them, both
  when it ends and at that point, so an older tag force-moved after the dry
  composition bound its release to a commit stops the publication too. The
  live `SHA256SUMS` of every version it composed must still be served. It then
  publishes the release as the latest, naming this tag, the release commit, the
  title, the notes and a full release again in the same request so that no
  later change to them takes effect, and requires it to be immutable, not a
  prerelease and under this tag, with the same title and notes and its tag at
  the release commit. GitHub keeps a tag pushed after the last read, so only
  that final check can refuse one.
- `compose-pages` builds the Pages tree from immutable, non-draft `vX.Y.Z`
  releases only. A `vX.Y.Z` release marked prerelease is refused rather than
  left out, since `publish-release` never makes one. Each archive must hold
  exactly the files its signed `SHA256SUMS` lists, each at a plain relative
  path, and the separate asset files must be its own copies. The archive must
  be packed canonically, the release must carry its title and the notes
  rendered from its site and archive, `install.sh.asc` must pass the
  release-key policy, and its signed `publication-manifest.json` must name that
  version, its base URL, the release key and the commit its tag names. Every
  version listed in `release/published-versions.json` must be present with the
  recorded `SHA256SUMS`, and every `vX.Y.Z` tag other than the new version's
  must have an entry there, published or retired. The file must be schema 1
  without repeated keys. Composing needs each release's tag, and GitHub keeps
  the tag of a deleted release, so no version leaves Pages unnoticed: a release
  deleted before or after it was recorded stops the next run. A release leaves
  Pages through a reviewed `retired` entry with a reason, whose digest is that
  of the release's `SHA256SUMS`; a retired release must be immutable too, and
  every retired entry must match such a release. A deleted release can
  therefore be neither served nor retired, and its entry and its tag have to be
  removed by hand after review. The one removal this cannot see is a release
  deleted together with its tag before its version is recorded; a ruleset that
  blocks deleting `v*` tags closes that. `--new-version` must be the committed
  version and the newest composed version, so re-running an older run's
  `pages-build` cannot serve again what a later registry retired. Every run
  composes from its own commit's registry, so a `retired` entry takes effect
  only when the next release's `pages-build` and `pages-deploy` run. The live
  `SHA256SUMS` of the other versions must be unchanged, and the site must stay
  within 950 MiB. The manifest records each composed version with the digests
  of its archive and `SHA256SUMS`, its release id and the commit its tag names,
  and each retired version left out with the files it could have served: those
  its `SHA256SUMS` lists and the two sums files, or only the sums files when its
  `SHA256SUMS` does not parse, lists an unsafe path or more than 20000 files,
  since such a release never passed `compose-pages`. `--manifest` must be a new
  file in an existing directory, neither inside the site nor containing it. This
  is checked before anything is downloaded, and a refusal leaves neither the
  site nor the manifest behind.
- `check-deploy` runs in `pages-deploy` right before the deployment, because a
  re-run of an older run's `pages-deploy` would put that run's composition live
  again. `--pages-manifest` must be the record of composing the committed
  version, that version must be the newest non-draft `vX.Y.Z` release, retired
  ones included, and the composed versions must be exactly the non-draft
  `vX.Y.Z` releases that `--registry` does not retire, each with the
  `SHA256SUMS` digest and release id it was composed with and its tag still
  naming the commit it named then. A release deleted and created again on its
  tag, even with a copy of its `SHA256SUMS`, or a moved tag therefore stops it,
  as it would stop `compose-pages`. As in `compose-pages`, every other
  `vX.Y.Z` tag must have an entry in `--registry`, so a newer release deleted
  while its tag remains still stops it, and the live `SHA256SUMS` of every
  composed version but the committed one must be the composed one, so a
  version a later deployment removed is not served again even once that
  release and its tag are deleted. Only the committed version is not checked
  live, since it is not served before its first deployment; such a re-run can
  therefore serve it again although the deleted release's registry retired it.
- `verify-live` requires `--pages-manifest`, the record `compose-pages` wrote
  with this version as `--new-version`, and the 40-hex release commit from
  `--sha` or `GITHUB_SHA`. Before it fetches anything, the record's entry for
  this version must name the archive's digest and the digest of the archive's
  `SHA256SUMS`. It waits until every file of the archive serves the archive's
  bytes at its plain URL, as users fetch it, and every file the record lists
  for a retired version returns 404 at its plain URL, since the CDN caches each
  URL on its own; that version's `release.json` and `SHA256SUMS` must return
  404 past the CDN cache too, where the Pages origin drops a version's
  directory as a whole. A check that passed is not repeated, and each round
  stops at the first one that has not, so a round downloads at most the files
  that converged in it and one stale response. Network and protocol errors
  count as not converged yet until the 20-minute timeout. It then streams every
  file to disk past the CDN cache and compares it with the archive, repacks the
  live files into the canonical archive, verifies `SHA256SUMS.asc` and
  `install.sh.asc` under the committed key, and requires the files to be
  exactly those the signed `SHA256SUMS` lists, with its digests. The signed
  `publication-manifest.json` must name this version, base URL, release key and
  commit, and the live `SHA256SUMS` of every other version the Pages manifest
  lists must be unchanged. Any other network or protocol error refuses at once.

Before `tarfile` reads a release archive or the inputs tarball,
`scripts/ci/release_tar.py` scans its raw headers. At most 20000 headers are
allowed, extension headers included, and a negative declared size is refused.
Only the header types each archive needs are admitted: regular files and GNU
long names in a release archive, and also directories and pax headers in the
inputs. A regular file named like a directory, the old v7 directory form, is
refused: `tarfile` reads it as a directory, but after an extension header as a
file whose data it skips, so the scan and `tarfile` would read different
headers. Extension data is capped at 64 KiB per header and 1 MiB per archive, and
global pax data, which `tarfile` copies into every later member, at 1 KiB. Each
cap is checked from the declared size before any data is read, and at most four
extension headers may come in a row. pax records that change a size or describe
a sparse file are refused, and so is pax padding that is not zero, since
`tarfile` would parse records there. Member data is skipped, not read. For
the inputs, the declared member sizes must also fit the 8 GiB unpacked budget
before any data is decompressed. `release.yml` uses these tools; see
[release-process.md](release-process.md).
