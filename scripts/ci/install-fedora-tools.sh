#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 022

dnf5 --assumeyes --setopt=install_weak_deps=False install \
  binutils ca-certificates cmake cpio curl diffutils dwz elfutils findutils \
  gcc gcc-c++ git gnupg2 gtest-devel gzip ninja-build openssl patch python3 python3-pyyaml redhat-rpm-config \
  rpm-build rpm-sign rpmlint shadow-utils tar util-linux which

if ! id ci >/dev/null 2>&1; then
  useradd --create-home --uid 1001 ci
fi
