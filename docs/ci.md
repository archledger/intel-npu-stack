<!-- SPDX-License-Identifier: Apache-2.0 -->
# Continuous integration and repository controls

The `CI` workflow runs on pull requests targeting `main`, pushes to `main`,
and manual dispatch. It uses GitHub-hosted runners, not the maintainer's NPU
machines. No hardware qualification, package publication, production signing,
or device power transition is part of this workflow.

## Checks

| Check | Scope |
|---|---|
| Fedora quality | Digest-pinned Fedora 44 x86_64 container, pinned Rust1.85.0 with rustfmt/Clippy, the unchanged locked project quality gate, and Python packaging/bootstrap/VM-runner/CI contract suites. Test execution is unprivileged, with four build jobs and two Rust test threads. |
| Native SDK and C++ CodeQL | Hash-pinned OpenVINO2026.2.0 C++ wheel assets and LevelZero1.28.6 source, native helper build/CTest/ELF hardening checks, the issue #20 reproducer's CPU cases, and manually traced C++ analysis. No NPU is accessed. |
| CodeQL (actions/python/rust) | Default CodeQL queries with no-build analysis. Copied third-party licensing/source excerpts are excluded from project-source analysis; maintained code and tests remain in scope. |
| DCO sign-off | Author-matching `Signed-off-by` trailers from actual Git trailer parsing, checked across the immutable contribution range. Also runs hash-pinned actionlint for workflow syntax. |
| Dependency review | Pull-request dependency changes are checked for high/critical known vulnerabilities. It does not comment on PRs or publish packages. |
| CI gate | Always runs after the other jobs and fails for any failed, cancelled, missing, or unexpectedly skipped required job. Dependency review may be skipped only for non-PR events. |

The DCO check uses the actual PR head rather than GitHub's synthetic merge
commit. Initial pushes/manual dispatches check the available history when no
base commit exists. GitHub's signed-commit protection is a separate control
from DCO certification.

## Trust and reproducibility boundaries

- Every third-party action is pinned to a full commit ID. The Fedora base
  image is pinned by OCI digest; Rust has an explicit version.
- Native SDK URLs and SHA256 digests are in
  [`native-sdk-lock.json`](../scripts/ci/native-sdk-lock.json). Downloads are
  bounded and verified before extraction. The OpenVINO Python binding is not
  installed; only the wheel's C++ SDK files and notices are used.
- Native CI builds against a public test SDK. It does not rebuild or certify
  the project's Fedora provider RPMs, and its binaries are not release assets.
- Fedora's signed repositories supply ordinary test-tool dependencies; their
  package versions can receive Fedora updates. This CI environment is not a
  byte-reproducible release builder.
- Cargo acquisition is explicit (`cargo fetch --locked`); `scripts/check.sh`
  then retains its offline contract. No private source cache is required.
- Checkout credentials are not persisted. Default permissions are
  `contents: read`; only CodeQL jobs receive `security-events: write` and
  `actions: read` for analysis upload/context. There is no
  `pull_request_target`, self-hosted job, release secret, package-write or
  OIDC permission.
- Uploads contain bounded job logs/SDK identities and expire after14days.
  They are CI diagnostics, not hardware or release qualification receipts.

## Main-branch policy

Configure protection only after the real workflow has established its check
names. Require pull requests, up-to-date successful CI checks, signed commits,
and resolved conversations; disallow force pushes and branch deletion, with
the policy applying to administrators as well. The initial single-maintainer
policy need not require a second person's approval to merge the maintainer's
own PR, but code review remains required by the contribution workflow.

Enable dependency alerts and code-scanning merge protection for newly introduced
high/critical security findings where supported. Do not treat a successful
scanner execution as proof that its findings were reviewed or resolved.

## Local verification

```sh
python3 -m unittest discover -s scripts/ci -p 'test_*.py'
```

The full Fedora job requires the tools listed in
[`install-fedora-tools.sh`](../scripts/ci/install-fedora-tools.sh), an installed
Rust1.85.0 toolchain, and an unprivileged workspace. Run provisioning only in
a disposable build environment. The native check also requires its pinned
SDK and an empty build directory as documented by `scripts/check-native.sh`.

CI success does not replace the hardware cases, promote a candidate, or
establish production trust.

## Upstream watcher

The `Upstream watch` workflow runs daily at a non-round UTC minute and on
manual dispatch. It compares the primary pinned components
(Intel Linux NPU driver, OpenVINO, Level Zero and the NPU compiler) in
`packaging/fedora/44/provider-sources.toml` against their newest non-draft
upstream GitHub release or tag, resolves release tags to commit SHAs, and
opens one deduplicated `upstream-update` issue per genuinely new release
(`upstream:<repository>:<tag>` in the title is the dedup key).

Boundaries:

- Scheduled runs are advisory. GitHub may delay, drop, or disable them; a
  quiet watcher is not proof that no update exists.
- Upstream tags, names, URLs and asset metadata are parsed as untrusted data
  with bounded output. Nothing upstream is executed or interpolated into
  shell source; issue titles/bodies are passed as data only.
- A finding is the `update-available` observation: a newer official release
  exists but is not qualified. A feature release alone is not `outdated`.
  Failed upstream queries are logged for the next run instead of opening
  noisy issues.
- The workflow holds only `contents: read` and `issues: write`. It never
  creates branches or pull requests, and candidate preparation remains a
  separately permissioned manual operation.

## Candidate preparation

The `Prepare candidate` workflow is a separately permissioned
`workflow_dispatch` operation (design §9). A maintainer supplies one open
`upstream-update` issue number; the workflow re-resolves the upstream tag
against retagging, downloads the immutable commit archive to hash it, rewrites
only that component's entry in the provider source lock, validates the whole
lock with the offline `xtask validate-source-lock` gate, and opens one DRAFT
pull request from a `candidate/<component>-<tag>` branch.

Boundaries:

- It refuses to run when any production profile is already `qualified`, when
  the upstream tag no longer resolves to the commit the watcher recorded, when
  the target branch or an open PR already exists, and when the lock is already
  current.
- The generated commit is authored and signed off by `github-actions[bot]`;
  it changes source pin metadata only. It never rebuilds provider RPMs, binds
  or alters profiles, approves workflows, merges, signs, or publishes.
- The draft PR carries the maintainer checklist: upstream license review,
  offline provider rebuild with reproducibility evidence, profile regeneration
  from new RPM evidence, and the unchanged qualification gates. Merging the
  draft remains an explicit maintainer decision under the standard protected
  pipeline.

## Release workflow

`release.yml` runs only on manual dispatch from `main`. The top level grants
no permissions, and every job asks for its own:

| Job | Permissions | Environment | Secrets |
|---|---|---|---|
| preflight | contents: read, pages: read | none | none |
| sign | contents: read | `release` (approval 1) | Import step only |
| installer-a, installer-b | contents: read | none | none |
| verify | contents: read | none | none |
| finalize | contents: read | `release` (approval 2) | Import step only |
| attest | contents: read, id-token: write, attestations: write | none | none |
| publish-release | contents: write | none | none |
| pages-build | contents: read | none | none |
| pages-deploy | contents: read, pages: write, id-token: write | `github-pages` | none |
| verify-live | contents: read | none | none |

The signing key reaches only the two Import steps. They receive it as step
environment and write it into a tmpfs keyring. A Destroy step that always runs
removes the keyring right after the signing step, before the job's remaining
checks and uploads. Jobs that hold the key have no write token, and they build
nothing. They run no action but checkout and the two artifact actions and no
service container, and only the signing step runs while the key is present.
That step is one command, the signing tool with the reads it substitutes and no
other program, and its tool calls are pinned, so every check of the job runs
before the import or after the Destroy step. Every artifact passed between jobs
with `upload-artifact` is sealed with `ARTIFACT-SHA256SUMS` and checked against
the producing job's output. The Pages artifact is the exception: `deploy-pages`
takes it straight from `upload-pages-artifact`, and `check-deploy` checks the
sealed `pages-record` that describes it, not the tree. `pages-deploy` reads its
checkout, the release and tag listings, the tag of each version it composed and
the live `SHA256SUMS` of the other versions it composed, and deploys only while
its run's composition is still current.

`scripts/ci/test_release_workflow.py` enforces these rules, the action pins,
the container image and the equality of the two installer legs. Every job runs
once, without a matrix, on a GitHub-hosted `ubuntu-24.04` runner, never on a
self-hosted one. Secrets may appear only in the two Import steps, never in the
workflow or a job environment, a container, a service or another step. It pins
the environment of the workflow, of every job and of every step, and every job
container, and no job may run a service. It pins the actions each job runs with
their inputs, so every checkout takes the run's commit and keeps no token, and
`attest` covers every served file and every release asset. Every use of an
action, in any workflow, must name the same full commit, so no single pin, such
as that of a checkout in a job that holds the key, can change on its own. Each
downloaded artifact is checked by the first step after its download that
downloads nothing, before any other step or action reads it. It pins every
`scripts/ci` tool call of each job, in order and with its arguments, because a
tool refuses a missing required option only after parsing; the preflight's
reserve must be the site budget `verify` enforces. No job or step may tolerate
an error or choose its own shell, and none may carry a condition except the
Destroy step right after each signing step, which always runs. A step has only
the keys of a run block or of an action. Every step runs in the workspace,
where each tool and script path names the checkout's file, except the profile
validation, which runs `cargo` in the checkout. A Destroy step run from the
fetched inputs, for example, would run their keyring script while the key is
present. Step names are unique within a job. Jobs that can run at the same time
share four build jobs, so installer leg a builds with three and leg b with one.
`pages-build` is the only job with a step after an upload, and the recovery
path re-runs it after it succeeded. Its two artifacts are named after the run
attempt, and the jobs that read them take the names from its outputs.

Each run block is one line of commands joined by `&&`, so it stops at the
first command that fails. The shell does not check a tool whose output
`$(...)` substitutes into an argument; the tool that receives the value refuses
an empty one. The committed version is first assigned to a shell variable,
which takes the status of its read, so a failed read stops the block and only
that version is ever written to `$GITHUB_ENV`. Each command is a pinned tool
call, a seal that writes its digest to `$GITHUB_OUTPUT`, or one of a fixed list
of other commands. A seal names its work directory as a plain path, so no other
program can follow it. A command substitution in a tool call may only run
another `scripts/ci` tool, whose call is pinned too, so no other program can
hide inside a tool call. No run block has a single quote, backslash or
backquote, and every expansion is inside double quotes, so bash passes exactly
the arguments the test pins. The test also parses every tool call with that
tool's own arguments, options spelled in full. See
[release-process.md](release-process.md).
