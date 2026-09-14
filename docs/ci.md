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
| Native SDK and C++ CodeQL | Hash-pinned OpenVINO2026.2.0 C++ wheel assets and LevelZero1.28.6 source, native helper build/CTest/ELF hardening checks, and manually traced C++ analysis. No NPU is accessed. |
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

CI success does not complete the deferred hardware suspend/resume or
removal/restoration cases, promote a candidate, or establish production trust.
