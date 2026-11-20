"""Local collectors using one pinned SSH channel to a host-local HTTP broker."""

import base64
import json
import os
import queue
import shlex
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from vcf_hci.collector.oem import create_collector
from vcf_hci.enrichment import enrich_host_result
from vcf_hci.remote import executor
from vcf_hci.remote.ssh_target import validate_target as _target


class EsxiTransport:
    """Serialize bounded request/response frames; secrets never enter argv/logs."""

    max_connections = 1
    remote_only = True

    def __init__(self, target: dict, options: dict):
        self.target = _target(target)
        self.options = options
        self.runtime = tempfile.TemporaryDirectory(prefix='vcfr_esxi_')
        self.process: Optional[subprocess.Popen] = None
        self.lock = threading.Lock()
        self.frames: queue.Queue = queue.Queue(maxsize=2)
        self.cancelled = options.get('cancelled', lambda: False)
        self.count = 0

    def __enter__(self):
        try:
            identity, _, extra = executor._prepare_identity(self.target, self.runtime.name)
            source = Path(__file__).with_name('esxi_broker.py').read_text()
            command = '/bin/python3 -B -c ' + shlex.quote(source)
            argv = executor.build_ssh_argv(self.target, os.path.join(self.runtime.name, 'control'), command,
                                           identity_file=identity, batch_mode=False)
            argv[argv.index('ControlMaster=auto')] = 'ControlMaster=no'
            argv[argv.index('ControlPersist=60')] = 'ControlPersist=no'
            argv[1:1] = ['-F', os.devnull, '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no',
                         '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none', '-o', 'ConnectTimeout=8',
                         '-o', 'NumberOfPasswordPrompts=1', '-o', 'PreferredAuthentications=password,keyboard-interactive']
            self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL, env=executor._merged_env(extra))

            process = self.process
            assert process is not None and process.stdout is not None
            stdout = process.stdout

            def read_frames():
                try:
                    while True:
                        line = stdout.readline(12000001)
                        if not line or len(line) > 12000000:
                            break
                        self.frames.put(line, timeout=1)
                finally:
                    try:
                        self.frames.put(None, timeout=1)
                    except queue.Full:
                        pass

            threading.Thread(target=read_frames, daemon=True).start()
            self.discovery = self._receive(65)['ready']
            self.origin = 'https://' + self.discovery['address']
            self._send({k: self.options.get(k) for k in ('bmc_user', 'bmc_password', 'verify_ssl', 'ca_data', 'certificate_pin')})
            return self
        except Exception:
            self.close()
            raise

    def _send(self, frame):
        process = self.process
        if process is None or process.stdin is None:
            raise RuntimeError('ESXi broker is closed')
        process.stdin.write(json.dumps(frame).encode() + b'\n')
        process.stdin.flush()

    def _receive(self, timeout):
        for _ in range(max(1, int(timeout * 5))):
            if self.cancelled():
                self.close()
                raise RuntimeError('ESXi scan cancelled')
            try:
                frame = self.frames.get(timeout=0.2)
            except queue.Empty:
                continue
            if frame is None:
                raise RuntimeError('ESXi broker ended before completing the request')
            try:
                return json.loads(frame)
            except json.JSONDecodeError:
                raise RuntimeError('Invalid ESXi broker response') from None
        self.close()
        raise TimeoutError('ESXi broker deadline exceeded')

    def request(self, method, url, headers=None, body=None, timeout=15):
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or parsed.netloc != self.discovery['address']:
            raise ValueError('Off-target BMC request refused')
        path = parsed.path + ('?' + parsed.query if parsed.query else '')
        with self.lock:
            self._send({'method': method, 'path': path, 'timeout': timeout})
            response = self._receive(min(timeout, 20) + 5)
            self.count += 1
            return response['status'], response['headers'], base64.b64decode(response['body'], validate=True)

    def get_stats(self):
        return {'requests': self.count, 'transport': 'esxi_usb'}

    def close(self):
        process = self.process
        if process is not None:
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            if process.stdout:
                process.stdout.close()
            self.process = None
        self.runtime.cleanup()

    def __exit__(self, *_args):
        self.close()


def scan_host(host, ssh_user, ssh_password, host_key_pin, options=None):
    """Scan one explicitly selected Dell host; retain its logical identity locally."""
    options = dict(options or {})
    if not options.get('bmc_user') or not options.get('bmc_password'):
        raise ValueError('A separate BMC username and password are required')
    target = {'host': host, 'username': ssh_user, 'password': ssh_password, 'host_key': host_key_pin}
    with EsxiTransport(target, options) as transport:
        status, _, raw = transport.request('GET', transport.origin + '/redfish/v1/Systems', timeout=10)
        if status != 200:
            raise ValueError('BMC authentication or Systems discovery failed')
        try:
            members = json.loads(raw).get('Members', [])
            if len(members) != 1:
                raise ValueError('Expected exactly one system on this host')
            system_path = members[0]['@odata.id']
            status, _, raw = transport.request('GET', transport.origin + system_path, timeout=10)
            system = json.loads(raw)
        except json.JSONDecodeError:
            raise ValueError('BMC returned invalid JSON') from None
        if status != 200 or str(system.get('UUID', '')).replace('-', '').lower() != transport.discovery['uuid']:
            raise ValueError('ESXi and BMC UUID mismatch')
        from vcf_hci.wizard.dedupe import filter_esxi_targets
        keep, skipped = filter_esxi_targets([{'uuid': system.get('UUID', '')}], options.get('completed_bmc', []))
        if skipped and not keep:
            return skipped[0]
        if options.get('discovery_only'):
            return dict(transport.discovery, esxi_host=host, access_path='esxi_usb', identity_verified=True)
        with create_collector(transport.discovery['address'], options['bmc_user'], options['bmc_password'],
                              transport=transport) as collector:
            collector.host_timeout = 300
            collector._max_inner_workers = 1
            result = collector.run_assessment(scan_profile=options.get('profile', 'inventory-lite'))
            if not isinstance(result, dict):
                raise ValueError('ESXi collection did not return one host result')
            result['access_path'] = 'esxi_usb'
            result['acquisition'] = dict(transport.discovery, esxi_host=host, identity_verified=True)
            result.setdefault('system', {})['ip'] = transport.discovery.get('external_bmc_ip') or host
            enrich_host_result(result)
            return result
