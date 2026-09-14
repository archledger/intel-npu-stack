#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
if [ "$(id -u)" = 0 ]; then
  printf '%s\n' 'CI quality checks must run as an unprivileged user' >&2
  exit 1
fi
export CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=2

# Acquisition is explicit; the actual quality gate keeps its offline contract.
CARGO_NET_OFFLINE=false cargo fetch --locked
./scripts/check.sh
python3 packaging/fedora/44/repository/test-assemble.py
python3 packaging/fedora/44/repository/test-generate-release-profile.py
python3 install/test-bootstrap.py
python3 tests/vm/test-runner.py
python3 tests/vm/test-guest-lifecycle.py
python3 -m unittest discover -s scripts/ci -p 'test_*.py'
