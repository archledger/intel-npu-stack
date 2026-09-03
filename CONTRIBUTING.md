# Contributing

Develop behavior using a strict RED/GREEN/refactor cycle: first add a focused test and observe the expected failure, then implement the smallest passing change, then refactor while all tests remain green. Tests must exercise observable behavior and include relevant failure paths.

Run all commands with the committed lockfile and complete `./scripts/check.sh` before requesting review. Do not weaken validation, type checks, warnings, documentation checks, or tests to obtain a passing result.

Every project-authored Rust and shell source file must carry `SPDX-License-Identifier: Apache-2.0`. Preserve upstream notices and licenses for all third-party material.

Commits must be cryptographically signed and include a Developer Certificate of Origin sign-off (`git commit -S -s`). Do not fall back to unsigned commits if signing fails.
