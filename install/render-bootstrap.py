# SPDX-License-Identifier: Apache-2.0
"""Render a version-pinned bootstrap from real release asset identities.

This module performs no acquisition or publication. The release assembler must
supply the actual installer URL and SHA256; no production endpoint is invented.
"""
import argparse
import re
import shlex
from pathlib import Path
from urllib.parse import urlsplit


SCRIPT = '''#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Generated for the exact @VERSION@ installer asset.
set -eu
umask 077

fail() {
    printf 'error: %s\\n' "$2" >&2
    exit "$1"
}

if [ "$#" -eq 1 ]; then
    case "$1" in
        --version) printf 'intel-npu-stack-install %s\\n' '@VERSION@'; exit 0 ;;
        --help)
            printf '%s\\n' 'Usage: install.sh [--dry-run] [--yes] [--channel stable|experimental]' \\
                '  [--accept-experimental-risk] [--with-python] [--with-devel]' \\
                '  [--version] [--help]' \\
                'Run as a normal user. Experimental requires explicit risk acknowledgement.'
            exit 0 ;;
    esac
fi

check_options() {
    bootstrap_channel=stable
    bootstrap_risk=false
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --dry-run|--yes|--with-python|--with-devel) ;;
            --accept-experimental-risk) bootstrap_risk=true ;;
            --channel)
                shift
                [ "$#" -gt 0 ] || fail 2 '--channel requires stable or experimental'
                bootstrap_channel=$1 ;;
            --channel=*) bootstrap_channel=${1#*=} ;;
            *) fail 2 'unknown or misplaced installer argument; use --help' ;;
        esac
        shift
    done
    case "$bootstrap_channel:$bootstrap_risk" in
        stable:false|experimental:true) ;;
        *) fail 2 'experimental requires --accept-experimental-risk; stable rejects that flag' ;;
    esac
}
check_options "$@"

bootstrap_uid=$(id -u) || fail 2 'cannot determine effective user ID'
case "$bootstrap_uid" in
    ''|*[!0-9]*) fail 2 'cannot determine effective user ID' ;;
    0) fail 2 'run as a normal user; privilege is requested only for the approved transaction' ;;
esac
for bootstrap_tool in curl sha256sum mktemp chmod rm; do
    command -v "$bootstrap_tool" >/dev/null 2>&1 || fail 20 'a required bootstrap tool is unavailable'
done
bootstrap_directory=$(mktemp -d) || fail 20 'cannot create a private download directory'
trap 'rm -rf -- "$bootstrap_directory"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
bootstrap_payload=$bootstrap_directory/installer

if ! curl --disable --fail --location --proto '=https' --proto-redir '=https' \\
    --connect-timeout 15 --max-time 180 --max-filesize 67108864 \\
    --output "$bootstrap_payload" -- @URL@; then
    fail 20 'installer download did not complete'
fi
[ -f "$bootstrap_payload" ] && [ ! -L "$bootstrap_payload" ] || fail 20 'download is not a regular file'
if ! printf '%s  %s\\n' '@SHA256@' "$bootstrap_payload" | sha256sum --check --status; then
    fail 20 'installer checksum mismatch'
fi
chmod 700 "$bootstrap_payload" || fail 20 'cannot prepare the verified installer'
"$bootstrap_payload" "$@"
'''


def validate_asset(version: str, url: str, digest: str) -> None:
    if not re.fullmatch(r'(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})', version):
        raise ValueError('release must be a numeric version triple')
    if not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ValueError('asset digest must be a lowercase SHA256')
    if len(url) > 2048 or not re.fullmatch(r'https://[A-Za-z0-9./_-]+', url):
        raise ValueError('asset URL must be an unambiguous HTTPS URL')
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.query or parsed.fragment:
        raise ValueError('asset URL must be HTTPS without query or fragment')
    labels = parsed.hostname.split('.')
    if len(labels) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
        raise ValueError('invalid asset hostname')
    segments = parsed.path.removeprefix('/').split('/')
    if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', part) for part in segments):
        raise ValueError('unsafe asset path')
    if not {version, 'v' + version}.intersection(segments) or {'latest', 'current', 'stable', 'experimental'}.intersection(segments):
        raise ValueError('asset URL must name the exact release version')


def render_bootstrap(version: str, installer_url: str, installer_sha256: str) -> str:
    validate_asset(version, installer_url, installer_sha256)
    return SCRIPT.replace('@VERSION@', version).replace('@URL@', shlex.quote(installer_url)).replace('@SHA256@', installer_sha256)



def render_install_command(version: str, bootstrap_url: str, bootstrap_sha256: str) -> str:
    """Render the primary download/checksum/execute command for an actual asset."""
    validate_asset(version, bootstrap_url, bootstrap_sha256)
    return """(
    set -eu
    umask 077
    bootstrap_directory=$(mktemp -d) || exit 20
    trap 'rm -rf -- "$bootstrap_directory"' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    bootstrap_file=$bootstrap_directory/install.sh
    if ! curl --disable --fail --location --proto '=https' --proto-redir '=https' \\
        --connect-timeout 15 --max-time 180 --max-filesize 1048576 \\
        --output "$bootstrap_file" -- @URL@; then exit 20; fi
    [ -f "$bootstrap_file" ] && [ ! -L "$bootstrap_file" ] || exit 20
    if ! printf '%s  %s\\n' '@SHA256@' "$bootstrap_file" | sha256sum --check --status; then exit 20; fi
    /bin/sh "$bootstrap_file" "$@"
)
""".replace('@URL@', shlex.quote(bootstrap_url)).replace('@SHA256@', bootstrap_sha256)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', required=True)
    parser.add_argument('--kind', choices=['bootstrap', 'command'], default='bootstrap')
    parser.add_argument('--asset-url', required=True)
    parser.add_argument('--asset-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    render = render_bootstrap if args.kind == 'bootstrap' else render_install_command
    text = render(args.release, args.asset_url, args.asset_sha256)
    # Never overwrite an earlier release asset, including through a symlink.
    with args.output.open('x') as output:
        output.write(text)


if __name__ == '__main__':
    main()
