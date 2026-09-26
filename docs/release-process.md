<!-- SPDX-License-Identifier: Apache-2.0 -->
# Release process

`.github/workflows/release.yml` publishes one version as an immutable GitHub
release and serves it from GitHub Pages at the `BASE_URL` committed in
`crates/stack-install/src/trust.rs`, for example
`https://archledger.github.io/intel-npu-stack/0.1.0/`. The layout of the
published directory is described in [release-site.md](release-site.md).

## Before the first release

The repository settings are changed by a maintainer, once:

1. Pages source: GitHub Actions (Settings → Pages). `GET
   repos/archledger/intel-npu-stack/pages` must show `build_type: workflow` and
   `html_url: https://archledger.github.io/intel-npu-stack/`.
2. `github-pages` environment: protected branches only, no secrets, and
   administrator bypass turned off.
3. Immutable releases on (Settings → General → Releases). This setting is not
   retroactive, so it must be on before any release or tag is created.
   `gh api repos/archledger/intel-npu-stack/immutable-releases` must show
   `"enabled": true`. The workflow token cannot read this setting, so it is
   checked by hand, here and again at every dispatch, every approval and every
   re-run of `publish-release`.
4. `release` environment: keep the required reviewer and the protected-branch
   rule, and turn administrator bypass off. The same maintainer approves both
   gates, which is a recorded deviation from separate reviewers.

Every release also needs these on `main`:

- a qualified profile;
- `release/<version>/support-notes.toml` with the kernels the qualification
  evidence covers;
- an entry in `release/published-versions.json` for every earlier release (see
  [After publication](#after-publication));
- the prepared release inputs tarball at an HTTPS URL, with its SHA-256.

The kernel watcher should run before the first dispatch.

## Dispatch

Right before every dispatch, confirm that
`gh api repos/archledger/intel-npu-stack/immutable-releases` still shows
`"enabled": true`. A release published while the setting is off is public and
mutable, and `publish-release` refuses it only after it is public.

```sh
gh workflow run release.yml --ref main \
  -f inputs_url=<https URL> -f inputs_sha256=<sha256> \
  -f release_version=0.1.0 -f profile=profiles/fedora/44/lunar-lake-x86_64.toml
```

`release_version` must equal `VERSION` in `trust.rs`. `preflight` refuses a
dispatch from any other ref than `main`. It validates
`release/<version>/support-notes.toml` as `verify` does after the first
signing: a tracked file naming this release and profile, whose tested kernels
lie inside the profile's kernel window. It also refuses unless the inputs pass
the keyless checks, Pages is served by GitHub Actions at the committed base URL,
nothing is published yet for the version (no tag, no published release, and a
live `release.json` that returns 404), and the room check below passes.

The preflight token can only read, and GitHub lists draft releases only to a
token that can push, so the preflight cannot see a draft. `publish-release`
finds a draft left by an aborted run after both approvals. It resumes the draft
only when its assets are a byte-identical subset of this publication at this
commit, and refuses any other. A new dispatch signs again, so a draft that
already holds assets from an earlier dispatch is always refused: delete it by
hand before dispatching again.

### The room check

Pages serves every published version from one site of at most 950 MiB. Before
anything is created, `preflight` composes the site that the registry
`release/published-versions.json` of the dispatch commit serves: every
non-draft `vX.Y.Z` release it does not retire. It composes in a temporary
directory, with every gate `pages-build` applies: every non-draft `vX.Y.Z`
release must be immutable, not a prerelease and match its entry in the
registry, every `vX.Y.Z` tag needs an entry there, and every version that
stays served must carry its signed assets, title and notes, with a live
`SHA256SUMS` equal to its release's. The new version must be newer than every
existing release, retired ones included, and must not be in the registry yet.

That site plus a reserve for the new version must fit the 950 MiB budget. The
new site is not built yet, so the preflight reserves `SITE_BUDGET_BYTES`
(300 MiB), the per-version limit that `verify` then enforces on the unsigned
site it composes together with the files signing will add: `SHA256SUMS`,
counted exactly, and three signatures of at most 4096 bytes each. `finalize`
holds the signed site to the same limit. A dispatch therefore needs the
versions that stay served to take at most 650 MiB. A retired version that Pages
still serves is neither counted nor checked live, since the site this run
deploys leaves it out. The `Classify the release state` step and
`publish-release` repeat the room check with the real size of the signed site
before anything is created. Right before publishing, `publish-release` also
requires the other published `vX.Y.Z` releases and the `v` tags to be
unchanged, and the versions that stay served to be still live.

## Approvals

Two jobs use the `release` environment and wait for approval. Before approving
either, confirm again that
`gh api repos/archledger/intel-npu-stack/immutable-releases` shows
`"enabled": true`.

- **sign (approval 1).** Before approving, review the preflight log: the
  dispatch check with the support notes and tested kernels, the profile
  validation, the inputs report and the room check. The job then imports the
  key into a tmpfs keyring, signs the RPMs and assembles the tree, and destroys
  the keyring.
- **finalize (approval 2, go-live).** Before approving, review the `verify` job
  and its `unsigned-site` artifact:
  - `verification/verification-report.json`: the unsigned site's file digests
    and size;
  - `verification/serve-report.json`: the published install path against a
    local copy (exit class and fetched files), the two corruption controls and
    the DNF package check;
  - the two installer legs: byte-equal, with records that agree except for the
    perturbation.

  The job signs the installer, `install.sh` and `SHA256SUMS`, then writes the
  archive and the release notes. Approval 2 is the last point before the
  public attestation, so check the immutable-releases setting right before
  approving it.

After approval 2, these jobs run without further approval: `attest`,
`publish-release`, `pages-build`, `pages-deploy` and `verify-live`. The release
is public, and immutable, before Pages serves it. For those minutes the primary
command fails closed with exit 20.

## Resuming and aborting

Re-run only the failed job. Nothing is signed again after `attest`. A re-run of
`attest` or `publish-release` runs `publish-release` without any approval, so
right before it confirm again that
`gh api repos/archledger/intel-npu-stack/immutable-releases` shows
`"enabled": true`: `publish-release` refuses a release published while the
setting is off only after it is public.

- `publish-release` resumes a draft whose assets are a byte-identical subset of
  this publication. It also accepts an already published immutable release with
  exactly these assets and its tag at this commit. Any other state is refused.
  A resume repeats the room check, so every version that stays served must
  still be live.
- `pages-build` composes the site from the published releases and the registry
  of the run's commit. It serves the run's version only while that version is
  the newest release, so re-running an older run's `pages-build` is refused
  once a newer release exists.
- `pages-deploy` deploys the Pages artifact of its own run. Right before it
  deploys, it requires that composition to be still current: the run's version
  is the newest release, the composed versions are exactly the releases the
  run's registry does not retire, every other `vX.Y.Z` tag has an entry in
  that registry, and every composed version but the run's own is live with the
  `SHA256SUMS` it was composed with. Re-running an older run's `pages-deploy`
  is therefore refused once a newer release exists, and still refused after
  that release is deleted, because GitHub keeps its tag. Once the tag is
  removed as well, the re-run is refused if a later deployment removed any
  other version it composed. The run's own version is not checked live, since
  it may never have been served, so such a re-run can serve it again even if
  the deleted release's registry retired it.
- `verify-live` polls for up to 20 minutes before failing. Re-run it once the
  Pages CDN serves the new files.

If a run's `pages-deploy` never succeeds, its version is published but not
served, and the next dispatch refuses in the room check because that version's
live `SHA256SUMS` is missing. Re-run that run's `pages-build` within GitHub's
30-day re-run limit; `pages-deploy` and `verify-live` run again after it, and
`verify-live` also needs the run's `publication` artifact, kept for 7 days.
GitHub keeps the artifacts of the earlier attempt and refuses a second artifact
of the same name in a run, so `pages-build` names its Pages artifact and
`pages-record` after the run attempt, and the later jobs take both names from
its outputs.

A release published while immutable releases were off is refused by every
re-run of `publish-release` and by every later composition, and retiring it
does not help. Turn the setting back on, delete that release and its tag by
hand after review, and re-run `publish-release`.

An aborted run can leave signed artifacts, kept for 7 days, and a draft
release. Delete each artifact of the run:

```sh
gh api repos/archledger/intel-npu-stack/actions/runs/<run>/artifacts --jq '.artifacts[].id'
gh api -X DELETE repos/archledger/intel-npu-stack/actions/artifacts/<id>
```

Delete a stale draft by hand in the Releases page before the next dispatch.
The workflow never deletes anything public and refuses a stale draft.

## After publication

- `gh release verify v0.1.0` and
  `gh release verify-asset v0.1.0 intel-npu-stack-0.1.0.tar`.
- `gh attestation verify intel-npu-stack-0.1.0.tar --repo archledger/intel-npu-stack`.
- `gpg --verify SHA256SUMS.asc SHA256SUMS` with the release key, then
  `sha256sum --check --strict SHA256SUMS` in an extracted archive.
- An independent rebuild of the installer from tag `v0.1.0`: pin
  `METADATA_SHA256` to the SHA-256 of the live `release.json` and build with
  the image and toolchain recorded in `records/installer-build.json`. The
  result must be the published installer.
- A reviewed pull request adds the version and the SHA-256 of its `SHA256SUMS`
  to `release/published-versions.json`. It must merge before the next release:
  the room check and `pages-build` refuse any `vX.Y.Z` tag without an entry.
  From then on, `pages-build` keeps serving the version. Removing a version
  needs a `retired` entry with a reason and the SHA-256 of that release's
  `SHA256SUMS`, and the release must stay published and immutable. A
  retirement takes effect only when the next release's `pages-build` and
  `pages-deploy` run. Re-running an earlier run cannot remove a version,
  because it composes from its own commit's registry. A deleted release can be
  neither served nor retired, so its entry and its tag are removed by hand
  after review.
