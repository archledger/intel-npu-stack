<!-- SPDX-License-Identifier: Apache-2.0 -->
# Installing on Fedora 44 (x86_64)

Status: release **0.1.0** is published at
`https://archledger.github.io/intel-npu-stack/0.1.0/`
([GitHub release](https://github.com/archledger/intel-npu-stack/releases/tag/v0.1.0)).
It supports Fedora 44 x86_64 on allowlisted Lunar Lake hardware (PCI
`8086:643e`) with kernels `[7.2.5, 7.3.0)`, through the qualified Fedora 44
Lunar Lake profile on the stable channel. Each release is served from
`https://archledger.github.io/intel-npu-stack/<version>/`, as described in
[release-site.md](release-site.md). The directory has no index page, so
its URL alone returns 404; every other file in it is listed in the signed
[`SHA256SUMS`](https://archledger.github.io/intel-npu-stack/0.1.0/SHA256SUMS).
To verify before running, download `install.sh` and `install.sh.asc`, check
the signature against the release key, read the script, and then run it.

## What the release is made of

A release directory (produced by
`packaging/fedora/44/repository/assemble.py` from digest-verified inputs)
contains:

- `release.json`: installer metadata including stack release, profile digest,
  repository id/URL, repomd digest, and every package with its exact NEVR,
  architecture, filename, SHA256 and role (`runtime`, `devel`, `profile`).
- `packages/`: the exact signed RPM set (0.1.0: 16 packages).
- `repodata/`: signed repository metadata, including `repomd.xml.asc`.
- `profile.toml`: the platform profile the installer authenticates against
  `release.json`. Candidate assembly preserves candidate status; the VM fixture
  is separately labeled experimental. Production assembly requires a qualified
  profile. Installation never grants qualification.
- `evidence/spdx`, `evidence/notices`, `evidence/rollback`: SBOM documents,
  license notices, and the twelve exact Fedora rollback RPMs with their index,
  including the original Level Zero loader.
- `checksums.sha256` and `assembly-manifest.json`: reproducible output
  digests for every file above.

## Bootstrap command

Installation starts from a version-pinned bootstrap that downloads the
installer completely, verifies its exact SHA256, and only then executes it
with the caller's arguments untouched. The command is generated per release
from the actual asset by `install/render-bootstrap.py`; it is published
beside the release, never invented by hand. For release 0.1.0 the published
command, `primary-command.txt` on the release site, is:

```sh
(
    set -eu
    umask 077
    bootstrap_directory=$(mktemp -d) || exit 20
    trap 'rm -rf -- "$bootstrap_directory"' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    bootstrap_file=$bootstrap_directory/install.sh
    if ! curl --disable --fail --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 15 --max-time 180 --max-filesize 1048576 \
        --output "$bootstrap_file" -- https://archledger.github.io/intel-npu-stack/0.1.0/install.sh; then exit 20; fi
    [ -f "$bootstrap_file" ] && [ ! -L "$bootstrap_file" ] || exit 20
    if ! printf '%s  %s\n' '05c0f5ffeee515be12eba385fa000795c65e6dd70ccc6d84b4e0ba67d36e7d8e' "$bootstrap_file" | sha256sum --check --status; then exit 20; fi
    /bin/sh "$bootstrap_file" "$@"
)
```

The primary command's digest belongs to **`install.sh`**, not the installer
binary. Generate the bootstrap first (`--kind bootstrap`, binary URL/digest),
then the primary command (`--kind command`, bootstrap URL/digest). This exact
two-stage chain was exercised in the disposable Fedora VM. The release
workflow runs the published command with `--dry-run` against a local copy of
the site before publication, and against the live site afterwards.

`install/install.sh` (same generator, `--kind bootstrap`) embeds the same
download-verify-execute sequence as a standalone dispatcher and refuses to
run as root; privilege is requested only later, for the approved native
transaction.

From 0.1.1 the release notes also give a short form:

```sh
curl --proto '=https' --proto-redir '=https' -fsSL \
    https://archledger.github.io/intel-npu-stack/<version>/install.sh | sh
```

It trusts the HTTPS download of `install.sh` instead of checking its SHA-256;
everything after it is checked the same way. It allows HTTPS only, redirects
included. curl reports a failed download, but the pipeline exits with the
status of `sh`, so scripts should use the pinned command. Pass installer flags
after `sh -s --`, for example `| sh -s -- --dry-run`. `install.sh` runs
nothing until its last line, which passes an end marker after the caller's
arguments, so a download cut short cannot run part of it. The installer reads
its confirmation from the terminal, so the pipe does not answer it.

## Installer operation

`intel-npu-stack-install` runs as a normal user:

1. Fetches `release.json` over HTTPS from the pinned URL, checks its pinned
   digest, the detached signatures and the compiled-in release key
   (fail-closed: a build without pinned trust constants exits 20 at
   transport instead of trusting downloaded metadata).
2. Discovers platform facts and validates the request against the profile
   (Fedora 44, x86_64, allowlisted NPU hardware, kernel range).
3. Verifies the system Fedora repository configuration and the cached,
   signed project repository metadata; plans the exact DNF5 transaction
   (download-only) and validates every stored RPM signature and identity,
   including Fedora-pulled dependencies.
4. Shows the full plan and the exact privileged steps, then asks for
   confirmation on the controlling terminal (or requires `--yes`).

Flags: `--dry-run`, `--yes`, `--channel stable|experimental`
(`experimental` additionally requires `--accept-experimental-risk`),
`--with-python`, `--with-devel`, `--version`, `--help`.

## Exit codes and refusals

| Exit | Code | Meaning |
|---|---|---|
| 0 | none | Success (dry run, no-op, or verified installation). |
| 2 | usage / confirmation | Invalid flags, non-TTY without `--yes`, empty or wrong confirmation. |
| 10 | INSTALL_CAPABILITY_UNAVAILABLE | The release has no package for a requested optional capability (for example `--with-python` today: no reviewed Python binding exists yet). |
| 20 | INSTALL_INTEGRITY_FAILED / INSTALL_METADATA_INVALID / transport failures | Digest, signature or metadata verification failed; a release URL that cannot be fetched also exits 20 (fail-closed). |
| 21 | INSTALL_VERIFY_FAILED | Post-transaction re-observation found a missing/changed expected package or movement outside the selection. |
| 30 | platform/observation failures | Platform discovery, native RPM observation or Fedora source verification failed. |
| other | native replay codes | The privileged DNF5 replay's own exit status is reported verbatim and the prepared transaction is preserved for diagnosis. |

## Reboot and relogin are reported, never hidden

After a successful replay the installer re-queries the package database and
verifies every expected package at its exact NEVR. Providers whose profile
activation is `reboot` (the NPU firmware) or `relogin` are listed explicitly
(`Reboot required before these components become active: …`). A pending
reboot is not a failure, but the component is not active until it happens;
`intel-npu-stack doctor` keeps reporting the honest state.

## Removal and rollback

- Removal uses native DNF and the exact installed release selection from the
  authenticated manifest. Remove every selected runtime/profile package and
  any selected optional development package. Removing only `intel-npu-stack`
  does not remove all independently selected providers. The release key imported into the rpmdb during installation can
  be removed with
  `sudo rpmkeys --erase <fingerprint>`.
- Rollback resources ship with every release under `evidence/rollback`:
  the twelve exact signed Fedora RPMs recorded in `rollback-index.json`
  (with NEVRs and digests), including the Fedora Level Zero loader, that restore
  the pre-stack provider set. The lifecycle gate exercised all twelve downgrades
  and a subsequent upgrade through the integrated installer. Its retained
  baseline closure contains 718 digest-verified Fedora RPMs. The old dependency
  closure and original inventory must be available; the twelve rollback RPMs
  alone are not a complete dependency set for a minimal Cloud installation.
- Before a provider downgrade, remove the project packages that pin the new
  versions while retaining the dependency closure:
  `sudo dnf5 --setopt=clean_requirements_on_remove=False remove intel-npu-stack intel-npu-stack-profile intel-npu-stack-tools intel-npu-stack-firmware`.
  Then use native DNF with `localpkg_gpgcheck=True` to restore the exact,
  digest-verified old provider RPM selection (including development headers
  when they were originally installed), and verify the restored inventory.
- DNF5 owns transaction locking and native recovery. The installer preserves
  its private prepared-transaction directory (path printed on failure) for
  review; inspect native DNF/RPM state to determine which changes completed.

## What installation does not do

It does not activate hardware, replace GPU drivers or kernel modules, install
Python bindings that were never reviewed, start services, or mark the
candidate qualified. Those claims require their own gates.
