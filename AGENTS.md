# Repository Instructions

These instructions apply to any coding agent working in this repository.

## Project record

Use `docs/release-readiness.md`, `docs/hardware-validation.md`, the rest of the repository documentation and verified Git state as the project's record. Do not assume access to the maintainer's machines or private test artifacts.

## Project boundaries

- Subagents and multi-agent workflows may be used. Each agent follows these same boundaries.
- Obtain explicit authorization before external network, privileged, publishing, GitHub, package-installation, hardware-mutation, signing-infrastructure, or out-of-plan Git actions.
- Preserve exact qualification evidence and component digests. Never promote a profile without the required independent evidence and approval.
- Keep this project application-neutral. Do not add downstream application code, models, configuration, activation, dependencies, services, or branding.
- Follow test-driven development for behavior changes, as `CONTRIBUTING.md` describes, and run the locked quality gate (`./scripts/check.sh`) before claiming completion.
- Build with at most four jobs (`CARGO_BUILD_JOBS=4`), as `scripts/ci/quality.sh` and CI do; the release installer build refuses more.
