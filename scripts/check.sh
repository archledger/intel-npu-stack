#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
export CARGO_NET_OFFLINE=true

script_directory=${0%/*}
sh -n "$script_directory/check-fedora-packages.sh"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked
cargo run -p xtask --locked -- validate-profiles profiles
cargo run -p xtask --locked -- validate-profiles profiles/fedora/44
