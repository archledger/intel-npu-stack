#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Isolated, memory-backed keyring for the protected release job.
#
#   release-keyring.sh import    needs RELEASE_SIGNING_KEY, RELEASE_SIGNING_PASSPHRASE and
#                                RELEASE_SIGNING_FINGERPRINT in the environment of this step only
#   release-keyring.sh destroy   stops the agent and removes the keyring (run with if: always())
#
# The keyring lives in RELEASE_GNUPGHOME (default /dev/shm/intel-npu-release-gnupg) on a tmpfs;
# the passphrase is written to <home>/passphrase (mode 0600) by shell builtins only and later
# reaches gpg and rpmsign as a file path. The key must be the only secret key and must match
# both the fingerprint variable and the committed release public key (RELEASE_PUBLIC_KEY,
# default crates/stack-install/src/trust/release-public.asc).
set -euo pipefail
umask 077

home=${RELEASE_GNUPGHOME:-/dev/shm/intel-npu-release-gnupg}
committed=${RELEASE_PUBLIC_KEY:-crates/stack-install/src/trust/release-public.asc}

refuse() {
  printf 'release keyring refused: %s\n' "$1" >&2
  exit 1
}

destroy() {
  if [ -d "$home" ]; then
    gpgconf --homedir "$home" --kill all >/dev/null 2>&1 || true
    rm -rf -- "$home"
  fi
}

destroy_on_failure() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    destroy
  fi
}

primary_fingerprints() {
  # Fingerprint of each primary key in colon listing order (the fpr record after sec/pub).
  awk -F: '$1 == "sec" || $1 == "pub" { want = 1; next } $1 == "fpr" && want { print $10; want = 0 }'
}

import_key() {
  [[ "$home" == /* && "$home" != *..* ]] || refuse "keyring path must be absolute"
  [ "$(stat -f -c %T "$(dirname -- "$home")")" = tmpfs ] || refuse "$(dirname -- "$home") is not a tmpfs"
  [ ! -e "$home" ] || refuse "$home already exists"
  [[ "${RELEASE_SIGNING_FINGERPRINT:-}" =~ ^[0-9A-F]{40}$ ]] || refuse "RELEASE_SIGNING_FINGERPRINT must be 40 uppercase hex digits"
  [ -n "${RELEASE_SIGNING_KEY:-}" ] || refuse "RELEASE_SIGNING_KEY is empty"
  [ -n "${RELEASE_SIGNING_PASSPHRASE:-}" ] || refuse "RELEASE_SIGNING_PASSPHRASE is empty"
  [ -f "$committed" ] || refuse "committed release public key $committed is missing"

  mkdir -m 0700 -- "$home"
  trap destroy_on_failure EXIT
  printf '%s\n' 'default-cache-ttl 0' 'max-cache-ttl 0' 'allow-loopback-pinentry' > "$home/gpg-agent.conf"
  printf '%s' "$RELEASE_SIGNING_KEY" | gpg --homedir "$home" --batch --no-tty --quiet --import 2>/dev/null \
    || refuse "the signing key could not be imported"
  printf '%s' "$RELEASE_SIGNING_PASSPHRASE" > "$home/passphrase"
  unset RELEASE_SIGNING_KEY RELEASE_SIGNING_PASSPHRASE

  mapfile -t secret < <(gpg --homedir "$home" --batch --with-colons --list-secret-keys | primary_fingerprints)
  [ "${#secret[@]}" -eq 1 ] || refuse "expected exactly one secret key, found ${#secret[@]}"
  [ "${secret[0]}" = "$RELEASE_SIGNING_FINGERPRINT" ] || refuse "secret key does not match RELEASE_SIGNING_FINGERPRINT"
  mapfile -t pinned < <(gpg --homedir "$home" --batch --with-colons --show-keys "$committed" | primary_fingerprints)
  [ "${#pinned[@]}" -eq 1 ] && [ "${pinned[0]}" = "$RELEASE_SIGNING_FINGERPRINT" ] \
    || refuse "secret key does not match the committed release public key"

  # Prove the passphrase unlocks the key before any release artifact is signed.
  printf 'intel-npu-stack keyring probe\n' | gpg --homedir "$home" --batch --no-tty --pinentry-mode loopback \
    --passphrase-file "$home/passphrase" --local-user "$RELEASE_SIGNING_FINGERPRINT" \
    --detach-sign --output /dev/null >/dev/null 2>&1 || refuse "the passphrase does not unlock the signing key"
  trap - EXIT
  printf 'gnupghome=%s\npassphrase_file=%s\n' "$home" "$home/passphrase"
}

case "${1:-}" in
  import) import_key ;;
  destroy) destroy ;;
  *) printf 'usage: %s import|destroy\n' "$0" >&2; exit 2 ;;
esac
