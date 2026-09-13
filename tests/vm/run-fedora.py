#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Run one isolated Fedora 44 VM lifecycle scenario. NO BOOT happens here
unless the caller runs this module with a fully verified, locked, bounded
environment; every refusal below exists so an unverified or unsafe run can
never start.

Isolation properties (asserted by tests/vm/test-runner.py):
- the cloud image is verified by SHA256 before anything else runs;
- the fixture release tree and guest harness are re-verified against the
  recorded result.json digests;
- a fresh qcow2 overlay is created per run and always removed afterwards;
- KVM is required; CPUs (<=4) and memory (<=8192 MiB) are bounded so the
  archhost build set keeps six logical CPUs free;
- networking is QEMU user-mode NAT only: no bridged adapter, no host port
  forwards, no USB/PCI passthrough, no host filesystem shares;
- the only host-side endpoint is a loopback-bound HTTPS fixture server that
  serves the release at the pinned path plus the guest control plane;
- on timeout the VM is killed, the overlay is removed and the lock released,
  with the cleanup recorded in run.json.

VM fixtures never authorize public profile selection: the guest harness uses
synthetic facts inside disposable machines only.
"""
from typing import NamedTuple

from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time

SCENARIOS = ('bootstrap-refusal', 'dry-run', 'install', 'repeat', 'corruption',
             'repomd-corruption', 'package-corruption', 'reboot', 'removal', 'rollback', 'upgrade')
GUEST_USER = 'runner'
RELEASE_PATH = '/intel-npu-stack/0.1.0/fedora/44/x86_64/'
GUEST_MOUNT = '/dev/disk/by-label/cidata'


class RunnerRefused(Exception):
    """A precondition, digest or isolation bound failed; nothing was started."""


class RunnerEnvironment(NamedTuple):
    scenario: str
    image: Path
    image_sha256: str
    fixture: Path
    output: Path
    kvm: Path
    cpus: int
    memory_megabytes: int
    timeout_seconds: int
    tool_path: Path
    port: int
    server_hostname: str
    lock: Path | None = None
    loopback_443_forward: bool = False
    disk_gigabytes: int = 5

    def tool(self, name):
        return str(self.tool_path/name)


def forwarder_unit(environment):
    """Transient privileged unit forwarding loopback 443 to the fixture
    server port for exactly this run; QEMU guestfwd proved single-shot and
    the pinned release URLs carry no explicit port."""
    return ['sudo', '-n', 'systemd-run', '--collect',
            f'--unit=intel-npu-vm-fixture-{environment.port}',
            'socat', 'TCP-LISTEN:443,bind=127.0.0.1,fork,reuseaddr',
            f'TCP:127.0.0.1:{environment.port}']


def forwarder_stop(environment):
    return ['sudo', '-n', 'systemctl', 'stop',
            f'intel-npu-vm-fixture-{environment.port}']


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(condition, message):
    if not condition:
        raise RunnerRefused(message)


def verify_environment(environment):
    require(environment.scenario in SCENARIOS,
            'unknown scenario: '+str(environment.scenario))
    require(environment.image.is_file(), 'VM image is missing')
    require(digest(environment.image) == environment.image_sha256,
            'image digest does not match the verified acquisition record')
    result_path = environment.fixture/'result.json'
    require(result_path.is_file(), 'fixture result record is missing')
    result = json.loads(result_path.read_text())
    require(result.get('passed') is True and result.get('test_only') is True,
            'fixture is not a passed test-only release record')
    for relative, expected in [('release-tree/release.json', result['metadata_sha256']),
                               ('binaries/build1/guest-harness', result['guest_harness_sha256']),
                               ('binaries/build1/intel-npu-stack-install',
                                result['installer_sha256'])]:
        path = environment.fixture/relative
        require(path.is_file() and digest(path) == expected,
                'fixture digest drift: '+relative)
    require(environment.output == Path(environment.output).resolve(),
            'output path must be absolute')
    require(not environment.output.exists() or not any(environment.output.iterdir()),
            'output path already exists and is not empty')
    require(environment.kvm.exists(), 'KVM device is unavailable: '+str(environment.kvm))
    require(1 <= environment.cpus <= 4,
            f'CPU request {environment.cpus} exceeds the isolated VM bound of 4')
    require(1024 <= environment.memory_megabytes <= 8192,
            f'memory request {environment.memory_megabytes} MiB exceeds the isolated VM bound')
    require(5 <= environment.disk_gigabytes <= 24, 'disk request exceeds the disposable 24 GiB bound')
    return result


def acquire_lock(environment):
    lock = environment.lock or environment.output.with_suffix('.lock')
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError as error:
        raise RunnerRefused('another scenario run holds the lock: '+str(lock)) from error
    (lock/'owner.json').write_text(json.dumps(
        {'pid': os.getpid(), 'started': time.time()})+'\n')
    return lock


def release_lock(lock):
    owner = lock/'owner.json'
    if owner.exists():
        owner.unlink()
    try:
        lock.rmdir()
    except OSError:
        return False
    return True


def seed_files(environment, certificate=None, guest_script=None):
    """Exact NoCloud seed contents for this scenario. The disposable test CA
    and the guest scenario engine are embedded verbatim."""
    import textwrap
    result = json.loads((environment.fixture/'result.json').read_text())
    certificate_text = textwrap.indent(
        certificate.read_text() if certificate else 'TEST-CA-PLACEHOLDER', '      ')
    script_text = textwrap.indent(
        guest_script.read_text() if guest_script else '# guest scenario engine', '      ')
    meta = {'instance-id': f'intel-npu-vm-{environment.scenario}', 'local-hostname': 'npu-vm'}
    user_data = f'''#cloud-config
hostname: npu-vm
users:
  - name: {GUEST_USER}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
ssh_pwauth: false
write_files:
  - path: /etc/hosts
    append: true
    content: |
      10.0.2.2 downloads.example.invalid
  - path: /etc/pki/ca-trust/source/anchors/intel-npu-test-ca.crt
    content: |
{certificate_text}
  - path: /usr/local/bin/guest-lifecycle.py
    permissions: '0755'
    content: |
{script_text}
runcmd:
  - [ update-ca-trust ]
  - [ sh, -c, "dnf5 --assumeyes install gnupg2 || dnf5 --assumeyes install gnupg2" ]
  - [ sh, -c, "dnf5 --assumeyes update rpm rpm-sequoia crypto-policies" ]
  - [ python3, /usr/local/bin/guest-lifecycle.py, --scenario, {environment.scenario},
      --server, https://downloads.example.invalid, --fingerprint, {result['primary_fingerprint']} ]
  - [ sh, -c, "sleep 5; systemctl poweroff" ]
'''
    return {'meta-data': json.dumps(meta).encode(),
            'user-data': user_data.encode()}


def build_seed_iso(environment, files):
    staging = tempfile.TemporaryDirectory()
    root = Path(staging.name)
    graft = []
    for name, content in files.items():
        (root/name).write_bytes(content)
        graft.append(f'{name}={root/name}')
    seed = environment.output/'seed.iso'
    subprocess.run([environment.tool('xorriso'), '-as', 'mkisofs', '-volid', 'cidata',
                    '-joliet', '-rock', '-graft-points', *graft, '-o', str(seed)],
                   check=True, capture_output=True)
    staging.cleanup()
    return seed


def create_overlay(environment):
    environment.output.mkdir(parents=True, exist_ok=True)
    overlay = environment.output/'overlay.qcow2'
    subprocess.run([environment.tool('qemu-img'), 'create', '-f', 'qcow2',
                    '-b', str(environment.image), '-F', 'qcow2', str(overlay)],
                   check=True, capture_output=True)
    if environment.disk_gigabytes > 5:
        subprocess.run([environment.tool('qemu-img'), 'resize', str(overlay),
                        f'{environment.disk_gigabytes}G'], check=True, capture_output=True)
    return overlay


def qemu_command(environment, overlay, seed):
    command = [
        environment.tool('qemu-system-x86_64'),
        '--enable-kvm', '-machine', 'q35', '-cpu', 'host',
        '-smp', str(environment.cpus), '-m', str(environment.memory_megabytes),
        '-drive', f'file={overlay},if=virtio,format=qcow2,cache=unsafe',
        '-drive', f'file={seed},if=virtio,media=cdrom,readonly=on',
        '-netdev', 'user,id=net0', '-device', 'virtio-net-pci,netdev=net0',
        '-nographic', '-monitor', 'none', '--no-reboot',
        '-serial', f'file:{environment.output/"serial.log"}',
    ]
    return command


class FixtureServer(ThreadingHTTPServer):
    """Loopback-bound HTTPS fixture server: the pinned release path, the guest
    binaries, and the test control plane (corrupt/restore/scenario-result)."""

    def __init__(self, environment, hostname, port):
        self.environment = environment
        self.corrupted = set()
        self.scenario_result = None
        super().__init__((hostname, port), FixtureHandler)

    @property
    def port(self):
        return self.server_address[1]

    def enable_tls(self, certificate, key):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.socket = context.wrap_socket(self.socket, server_side=True)


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass

    def fixture_path(self, path):
        server = self.server
        assert isinstance(server, FixtureServer)
        environment = server.environment
        if path.startswith(RELEASE_PATH):
            relative = path.removeprefix(RELEASE_PATH)
            if not relative or relative.startswith('/') or '..' in relative.split('/'):
                return None
            if relative == 'intel-npu-stack-install':
                return environment.fixture/'binaries/build1/intel-npu-stack-install'
            if relative == 'install.sh':
                return environment.fixture/'install.sh'
            return environment.fixture/'release-tree'/relative
        if path.startswith('/guest/'):
            name = path.removeprefix('/guest/')
            if name == 'install.sh':
                return environment.fixture/'install.sh'
            if name == 'primary-command.txt':
                return environment.fixture/'primary-command.txt'
            if name == 'public.asc':
                return environment.fixture/'test-public.asc'
            if name == 'fedora-inputs.json':
                return environment.fixture/'fedora-inputs.json'
            if name in {'guest-harness', 'intel-npu-stack-install'}:
                return environment.fixture/'binaries/build1'/name
            return None
        if path.startswith('/fedora-inputs/'):
            name = path.removeprefix('/fedora-inputs/')
            if '/' in name or '..' in name or not name.endswith('.rpm'):
                return None
            return environment.fixture/'fedora-inputs'/name
        return None

    def do_GET(self):
        path = self.path.split('?')[0]
        source = self.fixture_path(path)
        if source is None or not source.is_file():
            self.send_error(404)
            return
        body = source.read_bytes()
        target = path.removeprefix(RELEASE_PATH) if path.startswith(RELEASE_PATH) else path
        server = self.server
        assert isinstance(server, FixtureServer)
        if target in server.corrupted and body:
            index = len(body)//2
            body = body[:index]+bytes([body[index] ^ 0x01])+body[index+1:]
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length) if length else b'{}'
        path = self.path.split('?')[0]
        server = self.server
        assert isinstance(server, FixtureServer)
        if path == '/corrupt':
            server.corrupted.add(json.loads(body)['target'])
        elif path == '/restore':
            server.corrupted.clear()
        elif path == '/scenario-result':
            server.scenario_result = json.loads(body)
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')


def generate_certificate(environment):
    """A disposable self-signed test CA covering the pinned release hostname
    and the slirp gateway address; valid for the duration of one run."""
    environment.output.mkdir(parents=True, exist_ok=True)
    key = environment.output/'test-ca.key'
    certificate = environment.output/'test-ca.crt'
    subprocess.run([environment.tool('openssl'), 'req', '-x509', '-newkey', 'rsa:2048',
                    '-nodes', '-keyout', str(key), '-out', str(certificate),
                    '-days', '2', '-subj', '/CN=intel-npu-vm-fixtures',
                    '-addext', 'subjectAltName=DNS:downloads.example.invalid,IP:10.0.2.2'],
                   check=True, capture_output=True)
    return certificate, key


def run_scenario(environment):
    result_record = verify_environment(environment)
    environment.output.mkdir(parents=True, exist_ok=True)
    lock = acquire_lock(environment)
    overlay = None
    record = {'schema_version': 1, 'scenario': environment.scenario,
              'passed': False, 'timeout': False,
              'inputs': {'image_sha256': environment.image_sha256,
                         'metadata_sha256': result_record['metadata_sha256'],
                         'installer_sha256': result_record['installer_sha256'],
                         'guest_harness_sha256': result_record['guest_harness_sha256'],
                         'primary_fingerprint': result_record['primary_fingerprint']},
              'cleanup': {}}
    process = None
    if environment.loopback_443_forward:
        subprocess.run(forwarder_unit(environment), check=True, capture_output=True)
    try:
        certificate, key = generate_certificate(environment)
        seed = build_seed_iso(environment, seed_files(
            environment, certificate=certificate,
            guest_script=Path(__file__).with_name('guest-lifecycle.py')))
        overlay = create_overlay(environment)
        server = FixtureServer(environment, environment.server_hostname, environment.port)
        server.enable_tls(certificate, key)
        threaded = threading.Thread(target=server.serve_forever, daemon=True)
        threaded.start()
        command = qemu_command(environment, overlay=overlay, seed=seed)
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic()+environment.timeout_seconds
        reboot_requested = False
        record['reboots'] = 0
        while time.monotonic() < deadline:
            outcome = server.scenario_result
            if (environment.scenario == 'reboot' and record['reboots'] == 0
                    and outcome and outcome.get('stage') == 'reboot-requested'):
                reboot_requested = True
                record['pre_reboot_result'] = outcome
                server.scenario_result = None
            if process.poll() is not None:
                if reboot_requested and record['reboots'] == 0:
                    process.wait()
                    serial = environment.output/'serial.log'
                    if serial.exists():
                        serial.rename(environment.output/'serial-first-boot.log')
                    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    record['reboots'] = 1
                    continue
                break
            if server.scenario_result is not None:
                break
            time.sleep(1)
        record['timeout'] = (server.scenario_result is None
                             and process.poll() is None)
        record['scenario_result'] = server.scenario_result
        record['serial_log_bytes'] = (environment.output/'serial.log').stat().st_size \
            if (environment.output/'serial.log').exists() else 0
        record['passed'] = bool(server.scenario_result and server.scenario_result.get('passed'))
        server.shutdown()
        server.server_close()
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
            record['cleanup']['qemu_killed'] = True
        if overlay is not None and overlay.exists():
            overlay.unlink()
            record['cleanup']['overlay_removed'] = True
        if environment.loopback_443_forward:
            stopped = subprocess.run(forwarder_stop(environment), capture_output=True)
            record['cleanup']['forwarder_stopped'] = stopped.returncode == 0
        record['cleanup']['lock_released'] = release_lock(lock)
        (environment.output/'run.json').write_text(json.dumps(record, indent=2)+'\n')
    return record


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', required=True, choices=SCENARIOS)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--image-sha256', required=True)
    parser.add_argument('--fixture', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--kvm', default='/dev/kvm', type=Path)
    parser.add_argument('--cpus', default=4, type=int)
    parser.add_argument('--memory-megabytes', default=4096, type=int)
    parser.add_argument('--timeout-seconds', default=1800, type=int)
    parser.add_argument('--port', default=8443, type=int)
    parser.add_argument('--server-hostname', default='127.0.0.1')
    parser.add_argument('--loopback-443-forward', action='store_true')
    parser.add_argument('--disk-gigabytes', default=5, type=int)
    args = parser.parse_args(argv)
    environment = RunnerEnvironment(
        scenario=args.scenario, image=args.image, image_sha256=args.image_sha256,
        fixture=args.fixture, output=args.output, kvm=args.kvm, cpus=args.cpus,
        memory_megabytes=args.memory_megabytes, timeout_seconds=args.timeout_seconds,
        tool_path=Path('/usr/bin'), port=args.port, server_hostname=args.server_hostname,
        loopback_443_forward=args.loopback_443_forward, disk_gigabytes=args.disk_gigabytes)
    try:
        record = run_scenario(environment)
    except RunnerRefused as error:
        parser.exit(2, 'VM scenario runner refused: '+str(error)+'\n')
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
