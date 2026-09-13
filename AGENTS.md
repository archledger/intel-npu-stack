# Repository Instructions

## Shared memory

In a maintainer checkout with the shared ledger mounted, read its `index.md`, then `project-intel-npu-stack.md` before every project task. The live roots are `/mnt/archledger-gp` on the laptop and `/srv/archledger-gp` on the server; the laptop's `/home/wisbfime/archledger-gp` Markdown aliases also resolve there. Use the live ledger rather than a copied snapshot.

After every material design, code, system, or test change in that environment, refresh the handoff's mutable current state, append a factual checkpoint and update the corresponding index row under `archledger-edit`. Keep completed history append-only. Do not record secrets, recovery material, or host-identifying diagnostic data.

For public clones without that private ledger, use `docs/release-readiness.md`, `docs/hardware-validation.md`, the repository documentation and verified Git state. Do not assume access to the maintainer's hosts or private test artifacts.

## Project boundaries

- Do not use subagents for this project.
- Obtain explicit authorization before external network, privileged, publishing, GitHub, package-installation, hardware-mutation, signing-infrastructure, or out-of-plan Git actions.
- Preserve exact qualification evidence and component digests. Never promote a profile without the required independent evidence and approval.
- Keep this project application-neutral. Do not add downstream application code, models, configuration, activation, dependencies, services, or branding.
- Follow test-driven development for behavior changes and run the locked project quality gate before claiming completion.
- Keep local CPU-heavy project work within the user's four-CPU budget. Run build/check containers with `--cpus=4`, use at most four build jobs, and avoid concurrent CPU-heavy project containers unless they share that total budget. Preserve this limit on every restart unless the user changes it.
- Archhost remote builds have separate user authorization for ten logical CPUs and ten jobs, leaving six logical CPUs outside the build's CPU set. On the verified 16-thread topology, use `--cpus=10 --cpuset-cpus=3-7,11-15`; recheck topology before reusing that set on another host. Keep laptop compilation stopped while building remotely.
