#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 "$script_directory/../packaging/fedora/44/package-gate.py" "$@"
