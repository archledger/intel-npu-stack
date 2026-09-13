<!-- SPDX-License-Identifier: Apache-2.0 -->
# Fedora VM lifecycle gate (disposable, test-only)

Status (2026-09-12): **Gate 3 VM lifecycle acceptance passed: the ten planned
scenarios plus an additional corrupted-RPM refusal/recovery scenario.** VM
execution and removal of stale build outputs to make room were explicitly
approved. The source recovery workspace and exact run records are linked
in the shared project handoff.

The latest fixture rebuild fixes preparation of Fedora's 36,915,318-byte
primary metadata (formerly rejected by an 8 MiB limit), and retains the
verified Fedora key symlink through replay. Bootstrap refusal, dry-run,
install, repeat, release-metadata corruption, repository-metadata corruption,
reboot, removal, exact rollback and upgrade passed against those rebuilt binaries. This is test-only
installer lifecycle evidence, not NPU qualification or a public release.

The original rollback attempt exposed an incomplete test baseline. The fixed
rollback and upgrade scenarios use a 20 GiB disposable overlay (the verified
5 GiB base image remains unchanged), the retained 434 digest-verified Fedora
dependency RPMs and eleven signed rollback RPMs, and official Fedora DNF
repositories for additional Cloud-guest dependencies. They establish a real
old-provider baseline including `openvino-devel`, install through the
unprivileged harness with `--with-devel` (16 selected release packages), remove
the four project version-pinning packages without dependency autoremove, and
downgrade all eleven providers to their exact original NEVRs. The ordinary
payload identities return to the recorded baseline; the imported release
public-key record remains explicit. Upgrade then reinstalls the exact stack.

The primary command is also exercised end-to-end: it pins and downloads
`install.sh`, which separately pins and downloads the installer binary. An
earlier assembly caller incorrectly supplied the binary URL/digest to the
primary-command renderer; the failing VM evidence is retained, and the
corrected chain reaches the intended unsupported-platform refusal.

## What runs and where

- Host side: `tests/vm/run-fedora.py` on archhost, one scenario per
  invocation. Every input is digest-verified first: the acquired Fedora
  Cloud Base 44 image against its recorded SHA256, and the VM fixture
  release against its own `result.json` digests (release
  metadata, installer, guest harness, fingerprint).
- Guest side: `tests/vm/guest-lifecycle.py`, embedded in a NoCloud seed
  ISO built per run with `xorriso`.

## Isolation properties (enforced by tests/vm/test-runner.py)

- A fresh qcow2 overlay per run over the verified image; removed after
  every run, success or timeout.
- KVM required; at most 4 vCPUs and 8192 MiB per VM so the archhost build
  set keeps six logical CPUs free; a per-run lock refuses concurrent runs.
- Networking is QEMU **user-mode NAT only**. No bridged adapter, no host
  port forwards, no USB/PCI passthrough, no host filesystem shares. The
  guest reaches two things: official Fedora mirrors (signature-verified by
  the guest's own dnf against built-in Fedora keys) and the loopback-bound
  HTTPS fixture server via the slirp gateway address 10.0.2.2.
- The fixture server (started by the runner, 127.0.0.1 only, disposable
  self-signed test CA covering `downloads.example.invalid` and 10.0.2.2)
  serves the test release at the exact pinned URL path, the guest
  binaries, and a control plane (`/corrupt`, `/restore`,
  `/scenario-result`). Nothing else listens.
- On timeout the VM process is killed, the overlay is deleted, the lock is
  released, and all of it is recorded in `run.json`.
- The pinned HTTPS endpoint is served through a transient loopback-only
  privileged 443-to-8443 forwarder. It is stopped after each run. No host
  keyring or package installation is involved.
- Reboot uses two QEMU invocations with the same disposable overlay and a
  single overall deadline. A guest-only resume unit verifies a changed boot
  ID and byte-equal package inventory (including install times); first-boot
  serial evidence is retained separately. A reboot request alone never passes.

## Test-only trust

The VM fixture release is signed by a disposable test key whose private
half was destroyed with its build container. The pinned installer and
guest harness verify that key only. The guest harness (`examples/`
`guest-harness.rs`) shares the production trust seam and the real
fetch/validate/prepare/review/replay pipeline, but replaces platform
DISCOVERY with synthetic allowlisted facts, because a virtual machine has
no NPU. The real installer binary is used only for the refusal scenario.
VM evidence never authorizes public profile selection, channel admission,
or any hardware claim.

## Scenario matrix

| Scenario | Expected outcome |
|---|---|
| `bootstrap-refusal` | The real pinned installer, run via the rendered bootstrap, refuses: the VM lacks allowlisted NPU hardware. Refusal exit recorded. |
| `dry-run` | Harness `--dry-run --yes` exits 0; nothing installed. |
| `install` | Harness `--yes` installs the exact selection; output verifies 15 release packages and reports reboot pending for `npu_firmware`. |
| `repeat` | Second `--yes` is an exact no-op. |
| `corruption` | With a corrupted served `release.json`, the run must fail closed (digest/signature refusal), then recover after `/restore`. |
| `repomd-corruption` | Same with `repodata/repomd.xml`. |
| `package-corruption` | A byte-flipped tools RPM is refused with unchanged inventory; restoring the original served bytes allows verified installation. |
| `reboot` | Install, then guest reboots; pending-activation semantics recorded pre-reboot. |
| `removal` | `dnf5 remove` of every runtime/profile package named by the test release leaves none of those package names installed. |
| `rollback` | Downgrade to the eleven exact signed Fedora rollback RPMs restores the recorded ordinary Fedora provider NEVRs. |
| `upgrade` | Rollback, then re-install of the 0.1.0 stack; final inventory equals the install scenario. |

Mutation scenarios record RPM inventories, exact argv, exits and truncated
command output in `run.json`; failures include their reason and block the
gate. The harness runs as the unprivileged guest user. Dry-run and repeat
assert unchanged inventories; removal asserts an empty remaining selection.

## Execution approval boundary

Booting the VM requires an explicit user approval given AFTER this runner
existed. The approval request names the exact invocation, the digest of
every input, the scenario list and the disk budget (fresh overlay per
scenario, ~3 GiB peak on the archhost evidence volume). No approval is
inferred from acquisition or preparation grants.
