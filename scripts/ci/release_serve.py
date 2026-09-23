#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Serve a composed site as the Pages host over local HTTPS and run the published install path against it.

  release_serve.py serve-test --site-root DIR [--repo DIR] [--user ci] [--work DIR] [--report FILE]
  release_serve.py serve-test --live [--repo DIR] [--user ci] [--work DIR] [--report FILE]

serve-test runs as root in a disposable container in which the Pages host of
the committed BASE_URL resolves only to 127.0.0.1 (for example
`--add-host archledger.github.io:127.0.0.1`). It creates a throwaway CA and a
certificate for that host, adds the CA to the system trust anchors, serves
--site-root (the directory holding <version>/) under the base URL's path on
127.0.0.1:443 and logs every request. Then, as the unprivileged --user:

  1. the site's primary command with --dry-run must get past release
     verification and stop at the platform (exit 10 INSTALL_PROFILE_UNSUPPORTED
     or exit 30 INSTALL_PLATFORM_*), never 0 or 20, after fetching exactly
     install.sh, the installer, release.json, release.json.sig and profile.toml;
  2. with one byte of the served release.json changed it must exit 20;
  3. with one byte of the served install.sh changed it must exit 20 before
     fetching anything else;
  4. DNF with gpgcheck and repo_gpgcheck against the committed key must load
     the repository and download every package, whose bytes and signatures must
     match release.json.

--live skips the local server and the corruption controls and runs 1 and 4
against the real host. Nothing is installed; the trust anchor is removed again.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.parse

import check_release
import release_trust

REPO = Path(__file__).resolve().parents[2]
SEGMENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]*')
FETCHED = ['install.sh', 'intel-npu-stack-install', 'release.json', 'release.json.sig', 'profile.toml']
ANCHOR = Path('/etc/pki/ca-trust/source/anchors/intel-npu-stack-serve-test.crt')
ERROR_LINE = re.compile(r'intel-npu-stack-install: .* \[([A-Z0-9_]+)\]')
TIMEOUT = 900


class ServeRefused(Exception):
    """A serve-test gate failed."""


def require(condition, message):
    if not condition:
        raise ServeRefused(message)


def location(base_url):
    """Host, served path prefix and version of a versioned base URL such as https://host/repo/0.1.0/."""
    parts = urllib.parse.urlsplit(base_url)
    segments = parts.path.strip('/').split('/')
    require(parts.scheme == 'https' and parts.hostname and not parts.query and not parts.fragment
            and parts.path.endswith('/') and len(segments) >= 2 and all(map(SEGMENT.fullmatch, segments)),
            'the base URL must be https://<host>/<path>/<version>/')
    return parts.hostname, '/' + '/'.join(segments[:-1]) + '/', segments[-1]


def served_path(prefix, raw):
    """The site-relative file for a request path, or None; only plain segments under the prefix are served."""
    parts = urllib.parse.urlsplit(raw)
    if parts.query or parts.fragment or not parts.path.startswith(prefix):
        return None
    relative = parts.path[len(prefix):]
    if not relative or not all(SEGMENT.fullmatch(segment) for segment in relative.split('/')):
        return None
    return relative


def corrupted(body):
    """The same bytes with exactly one byte changed."""
    return body[:-1] + bytes([body[-1] ^ 0x01]) if body else b'\0'


def classify(returncode, stderr):
    """verified: past release verification, stopped at the platform; integrity-refused: exit 20; else unexpected."""
    if returncode == 20:
        return 'integrity-refused'
    codes = [match.group(1) for match in map(ERROR_LINE.fullmatch, stderr.splitlines()) if match]
    if len(codes) == 1 and ((returncode == 10 and codes[0] == 'INSTALL_PROFILE_UNSUPPORTED')
                            or (returncode == 30 and codes[0].startswith('INSTALL_PLATFORM_'))):
        return 'verified'
    return 'unexpected'


def check_local(host, resolve=socket.getaddrinfo):
    """Refuse unless every address of the Pages host is 127.0.0.1, so no test request can reach the real site."""
    try:
        addresses = {entry[4][0] for entry in resolve(host, 443, proto=socket.IPPROTO_TCP)}
    except OSError:
        addresses = set()
    require(addresses == {'127.0.0.1'}, f'{host} must resolve only to 127.0.0.1 for the serve test, found '
            + (', '.join(sorted(addresses)) or 'nothing'))


def make_certificates(work, host):
    """A throwaway P-256 CA and a leaf certificate for host, valid for two days."""
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    ca, ca_key = work / 'ca.crt', work / 'ca.key'
    leaf, leaf_key, request = work / 'leaf.crt', work / 'leaf.key', work / 'leaf.csr'
    extensions = work / 'leaf.ext'
    extensions.write_text(f'subjectAltName=DNS:{host}\nextendedKeyUsage=serverAuth\n'
                          'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n')
    for argv in (
            ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', ca_key,
             '-out', ca, '-days', '2', '-subj', '/CN=intel-npu-stack serve-test CA',
             '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign'],
            ['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', leaf_key,
             '-out', request, '-subj', '/CN=' + host],
            ['x509', '-req', '-in', request, '-CA', ca, '-CAkey', ca_key, '-set_serial', '1', '-days', '2',
             '-out', leaf, '-extfile', extensions]):
        result = subprocess.run(['openssl', *map(str, argv)], capture_output=True, text=True, check=False,
                                stdin=subprocess.DEVNULL, timeout=120)
        require(result.returncode == 0, 'openssl failed: ' + result.stderr[-500:])
    return ca, leaf, leaf_key


class SiteServer:
    """HTTPS server for a site root under a path prefix, with an access log and a corruption switch."""

    def __init__(self, root, prefix, certificate, key, address=('127.0.0.1', 443)):
        self.root, self.prefix = Path(root).resolve(strict=True), prefix
        self.log, self.corrupt, self.lock = [], set(), threading.Lock()
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def do_GET(self):
                relative = served_path(server.prefix, self.path)
                path = server.root / relative if relative else None
                if (path is None or path.is_symlink() or not path.is_file()
                        or not path.resolve().is_relative_to(server.root)):
                    server.record(self.path, 404)
                    self.send_error(404)
                    return
                body = path.read_bytes()
                if relative in server.corrupt:
                    body = corrupted(body)
                server.record(self.path, 200)
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(address, Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, key)
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def record(self, path, status):
        with self.lock:
            self.log.append((path, status))

    def take_log(self):
        with self.lock:
            log, self.log = self.log, []
        return log

    @property
    def port(self):
        return self.httpd.server_address[1]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def run_primary(site_dir, user):
    """The site's primary command with --dry-run as an unprivileged user, from its own world-readable copy.

    The copy lives outside the work directory, which holds the throwaway CA key and stays private.
    """
    account = pwd.getpwnam(user)
    require(account.pw_uid != 0, 'the primary command must run as an unprivileged user')
    with tempfile.TemporaryDirectory(prefix='serve-test-command-') as directory:
        os.chmod(directory, 0o755)
        command = Path(directory) / 'primary-command.sh'
        shutil.copyfile(Path(site_dir) / 'primary-command.txt', command)
        os.chmod(command, 0o644)
        return subprocess.run(['runuser', '-u', user, '--', 'env', '-i', 'PATH=/usr/bin:/bin',
                               'HOME=' + account.pw_dir, 'LC_ALL=C.UTF-8', 'sh', str(command), '--dry-run'],
                              capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL,
                              timeout=TIMEOUT, cwd='/')


def dnf_commands(base_url, key, cache, destination, names):
    common = ['dnf5', '--assumeyes', '--setopt=reposdir=/nonexistent', f'--setopt=cachedir={cache}',
              f'--repofrompath=npu,{base_url}', '--setopt=npu.gpgcheck=1', '--setopt=npu.repo_gpgcheck=1',
              f'--setopt=npu.gpgkey=file://{key}', '--repo=npu']
    return [common + ['makecache'], common + ['download', f'--destdir={destination}', *names]]


def dnf_check(release, base_url, key, fingerprint, work):
    """Load the repository with signature checks and download every package; bytes and RPM signatures must match."""
    work = Path(work)
    root = work / 'dnf-download'
    (root / 'packages').mkdir(parents=True)
    names = sorted(entry['name'] for entry in release['packages'])
    for argv in dnf_commands(base_url, key, work / 'dnf-cache', root / 'packages', names):
        result = subprocess.run(argv, capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL,
                                timeout=TIMEOUT)
        require(result.returncode == 0, f'{argv[-1] if argv[-1] == "makecache" else "download"} failed: '
                + result.stderr[-1500:])
    for entry in release['packages']:
        path = root / 'packages' / entry['filename']
        require(path.is_file() and not path.is_symlink(), 'DNF did not download ' + entry['filename'])
        with path.open('rb') as stream:
            require(hashlib.file_digest(stream, 'sha256').hexdigest() == entry['sha256'],
                    'downloaded package differs from release.json: ' + entry['filename'])
    return check_release.verify_rpm_signatures(root, key, fingerprint, release)


def install_anchor(ca):
    require(os.geteuid() == 0, 'serve-test must run as root in a disposable container')
    require(not ANCHOR.exists(), f'{ANCHOR} already exists')
    shutil.copyfile(ca, ANCHOR)
    result = subprocess.run(['update-ca-trust', 'extract'], capture_output=True, text=True, check=False)
    require(result.returncode == 0, 'update-ca-trust failed: ' + result.stderr[-500:])


def remove_anchor():
    ANCHOR.unlink(missing_ok=True)
    subprocess.run(['update-ca-trust', 'extract'], capture_output=True, check=False)


def expect(result, wanted, label):
    outcome = classify(result.returncode, result.stderr)
    require(outcome == wanted, f'{label}: expected {wanted}, got exit {result.returncode} ({outcome}): '
            + result.stderr.strip()[-800:])
    return {'exit': result.returncode, 'class': outcome, 'stderr_tail': result.stderr.strip()[-400:]}


def serve_test(site_root, repo, user, work, live=False):
    values = release_trust.check_committed(repo)
    host, prefix, version = location(values['base_url'])
    require(version == values['version'], 'the base URL does not end in the release version')
    key = Path(repo) / release_trust.KEY_PATH
    report = {'schema_version': 1, 'base_url': values['base_url'], 'live': live}
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    if live:
        release = json.loads(Path(site_root, version, 'release.json').read_text()) if site_root else None
        with tempfile.TemporaryDirectory(dir=work) as scratch:
            site_dir = Path(scratch)
            fetched = subprocess.run(['curl', '--disable', '--fail', '--location', '--proto', '=https', '--max-time',
                                      '120', '--output', str(site_dir / 'primary-command.txt'), '--',
                                      values['base_url'] + 'primary-command.txt'], capture_output=True, check=False)
            require(fetched.returncode == 0, 'the live primary command could not be fetched')
            report['primary'] = expect(run_primary(site_dir, user), 'verified', 'live primary command')
        require(release is not None, '--live needs --site-root holding the published version for the DNF check')
        report['dnf_packages_verified'] = dnf_check(release, values['base_url'], key, values['primary_fingerprint'],
                                                    work)
        return report

    check_local(host)
    site_dir = Path(site_root) / version
    release = json.loads((site_dir / 'release.json').read_text())
    ca, leaf, leaf_key = make_certificates(work / 'tls', host)
    install_anchor(ca)
    try:
        with SiteServer(site_root, prefix, leaf, leaf_key) as server:
            result = run_primary(site_dir, user)
            report['primary'] = expect(result, 'verified', 'primary command')
            log = server.take_log()
            wanted = sorted((prefix + version + '/' + name, 200) for name in FETCHED)
            require(sorted(set(log)) == wanted and all(status == 200 for _, status in log),
                    f'the install path fetched {sorted(set(log))}, expected {wanted}')
            report['fetched'] = [path for path, _ in log]

            server.corrupt = {version + '/release.json'}
            report['corrupt_release_json'] = expect(run_primary(site_dir, user), 'integrity-refused',
                                                    'changed release.json')
            server.take_log()
            server.corrupt = {version + '/install.sh'}
            report['corrupt_install_sh'] = expect(run_primary(site_dir, user), 'integrity-refused',
                                                  'changed install.sh')
            log = server.take_log()
            require(log == [(prefix + version + '/install.sh', 200)],
                    'a changed install.sh must stop the command before anything else is fetched: ' + repr(log))
            server.corrupt = set()
            report['dnf_packages_verified'] = dnf_check(release, values['base_url'], key,
                                                        values['primary_fingerprint'], work)
    finally:
        remove_anchor()
    report['passed'] = True
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=['serve-test'])
    parser.add_argument('--site-root', type=Path)
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--repo', type=Path, default=REPO)
    parser.add_argument('--user', default='ci')
    parser.add_argument('--work', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(argv)
    if args.site_root is None:
        parser.error('serve-test requires --site-root')
    try:
        with tempfile.TemporaryDirectory(prefix='serve-test-') as scratch:
            report = serve_test(args.site_root, args.repo, args.user, args.work or Path(scratch), args.live)
        if args.report is not None:
            with open(args.report, 'x') as stream:
                stream.write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    except (ServeRefused, check_release.ReleaseRefused, release_trust.TrustRefused) as error:
        parser.exit(1, 'serve test refused: ' + str(error) + '\n')
    except (OSError, KeyError, ValueError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f'serve test refused: {error!r}\n')
    print(json.dumps({key: value for key, value in report.items() if key != 'fetched'}, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
