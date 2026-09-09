#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu

fail() {
    printf 'error: %s\n' "$1" >&2
    exit 1
}

canonical_directory() {
    candidate=$1
    label=$2
    case "$candidate" in
        /*) ;;
        *) fail "$label must be an absolute path" ;;
    esac
    [ -d "$candidate" ] || fail "$label must name an existing directory"
    (CDPATH=; cd "$candidate" && pwd -P) || fail "$label cannot be canonicalized"
}

[ "$#" -eq 2 ] || fail "usage: check-native.sh SDK_PREFIX BUILD_DIR"

sdk_prefix=$(canonical_directory "$1" "SDK_PREFIX")
build_directory=$(canonical_directory "$2" "BUILD_DIR")
case "$build_directory/" in
    "$sdk_prefix/"*) fail "BUILD_DIR must be outside SDK_PREFIX" ;;
    *) ;;
esac

for entry in \
    "$build_directory"/* \
    "$build_directory"/.[!.]* \
    "$build_directory"/..?*
do
    if [ -e "$entry" ] || [ -L "$entry" ]; then
        fail "BUILD_DIR must be empty"
    fi
done

script_directory=${0%/*}
if [ "$script_directory" = "$0" ]; then
    script_directory=.
fi
repository=$(CDPATH=; cd "$script_directory/.." && pwd -P) || fail "repository root cannot be resolved"

cmake \
    -S "$repository/native" \
    -B "$build_directory" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DINTEL_NPU_SDK_PREFIX="$sdk_prefix" \
    -DBUILD_TESTING=ON \
    -DCMAKE_FIND_USE_PACKAGE_REGISTRY=FALSE \
    -DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=FALSE
cmake --build "$build_directory" --config Release
ctest --test-dir "$build_directory" --build-config Release --output-on-failure

[ -x /usr/bin/readelf ] || fail "/usr/bin/readelf is required"

check_elf() {
    executable=$1
    dependency=$2
    [ -f "$executable" ] || fail "native helper is missing"

    header=$(/usr/bin/readelf -hW "$executable") || fail "cannot inspect native ELF header"
    case "$header" in
        *"Type:"*"DYN"*) ;;
        *) fail "native helper is not PIE" ;;
    esac

    program_headers=$(/usr/bin/readelf -lW "$executable") || fail "cannot inspect native program headers"
    case "$program_headers" in
        *"GNU_RELRO"*) ;;
        *) fail "native helper lacks GNU_RELRO" ;;
    esac
    case "$program_headers" in
        *"GNU_STACK"*"RWE"*) fail "native helper has an executable stack" ;;
        *"GNU_STACK"*) ;;
        *) fail "native helper lacks GNU_STACK metadata" ;;
    esac

    dynamic=$(/usr/bin/readelf -dW "$executable") || fail "cannot inspect native dynamic section"
    case "$dynamic" in
        *"BIND_NOW"*) ;;
        *) fail "native helper lacks immediate binding" ;;
    esac
    case "$dynamic" in
        *"FLAGS_1"*"PIE"*) ;;
        *) fail "native helper lacks the PIE dynamic flag" ;;
    esac
    case "$dynamic" in
        *"Shared library: [$dependency]"*) ;;
        *) fail "native helper lacks its required direct dependency" ;;
    esac
    case "$dynamic" in
        *"(RPATH)"*|*"(RUNPATH)"*) fail "native helper contains RPATH or RUNPATH" ;;
        *) ;;
    esac
}

check_elf "$build_directory/intel-npu-level-zero-probe" "libze_loader.so.1"
check_elf "$build_directory/intel-npu-openvino-probe" "libopenvino.so.2620"
