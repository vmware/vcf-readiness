"""Bounded host-local Redfish broker. Executed as original source over SSH stdin.

No files, listener, forwarding, installation or managed configuration writes.
Only the already configured Dell USB interface is supported initially.
"""

import base64
import hashlib
import http.client
import ipaddress
import json
import re
import signal
import ssl
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit


def preflight():
    """Read existing state; require an unambiguous USB DHCP route."""
    def read(args):
        return subprocess.check_output(args, timeout=15, stderr=subprocess.DEVNULL).decode()

    platform = read(['esxcli', 'hardware', 'platform', 'get'])
    if 'Dell Inc.' not in platform:
        raise ValueError('Only Dell host interfaces have been validated')
    nic = read(['esxcli', 'network', 'nic', 'list'])
    if 'iDRAC Virtual NIC USB' not in nic:
        raise ValueError('No Dell USB NIC')
    routes = read(['esxcli', 'network', 'ip', 'route', 'ipv4', 'list'])
    interfaces = read(['esxcli', 'network', 'ip', 'interface', 'list'])
    addresses = read(['esxcli', 'network', 'ip', 'interface', 'ipv4', 'get'])
    candidates = []
    for lease in sorted(Path('/var/lib/dhcp').glob('dhclient-vmk*.leases'))[:16]:
        if lease.stat().st_size > 65536:
            continue
        vmk = lease.name.removeprefix('dhclient-').removesuffix('.leases')
        block = re.search(r'(?ms)^' + re.escape(vmk) + r'\n(.*?)(?=^vmk|\Z)', interfaces)
        if not block or 'defaultTcpipStack' not in block.group(1) or 'BMC' not in block.group(1):
            continue
        matches = re.findall(r'dhcp-server-identifier\s+([\d.]+);', lease.read_text())
        local = re.findall(r'fixed-address\s+([\d.]+);', lease.read_text())
        if not matches or not local:
            continue
        candidate = ipaddress.ip_address(matches[-1])
        source = ipaddress.ip_address(local[-1])
        if not candidate.is_link_local or candidate == source:
            continue
        if not re.search(r'^' + re.escape(vmk) + r'\s+' + re.escape(str(source)) + r'\s', addresses, re.M):
            continue
        if not any(vmk in line and candidate in ipaddress.ip_network(line.split()[0] + '/' + line.split()[1], strict=False)
                   for line in routes.splitlines() if len(line.split()) >= 4 and line.split()[0][0].isdigit()):
            continue
        candidates.append((str(candidate), vmk))
    if len(set(candidates)) != 1:
        raise ValueError('USB route absent or ambiguous')
    raw_uuid = re.search(r'UUID:\s*(.*)', platform)
    hexes = re.findall(r'0x([a-fA-F0-9]+)', raw_uuid.group(1) if raw_uuid else '')
    if len(hexes) != 16:
        raise ValueError('Host UUID unavailable')
    uuid_hex = ''.join('%02x' % int(x, 16) for x in hexes)
    serial = re.search(r'(?m)^\s*Serial Number:\s*(.*)$', platform)
    bmc = read(['esxcli', 'hardware', 'ipmi', 'bmc', 'get'])
    external = re.search(r'(?m)^\s*IPv4Address:\s*(.*)$', bmc)
    return {'address': candidates[0][0], 'interface': candidates[0][1], 'uuid': uuid_hex,
            'serial': serial.group(1).strip() if serial else '',
            'external_bmc_ip': external.group(1).strip() if external else ''}


def emit(frame):
    sys.stdout.write(json.dumps(frame) + '\n')
    sys.stdout.flush()


def main():
    signal.alarm(360)
    discovered = preflight()
    emit({'ready': discovered})
    config = json.loads(sys.stdin.buffer.readline(65537))
    context = ssl.create_default_context(cadata=config.get('ca_data') or None)
    if not config.get('verify_ssl', False):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    auth = 'Basic ' + base64.b64encode((config['bmc_user'] + ':' + config['bmc_password']).encode()).decode()
    pin = str(config.get('certificate_pin') or '').replace(':', '').lower()
    if pin and not re.fullmatch('[a-f0-9]{64}', pin):
        raise ValueError('Invalid BMC SHA256 pin')
    total = 0
    started = time.monotonic()
    for _ in range(1500):
        line = sys.stdin.buffer.readline(1048577)
        if not line:
            break
        if len(line) > 1048576 or time.monotonic() - started > 300:
            raise ValueError('Broker budget exceeded')
        item = json.loads(line)
        method, path = item['method'], item['path']
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc or parsed.fragment or not path.startswith('/redfish/v1') or '\\' in path or any(ord(c) < 32 for c in path):
            raise ValueError('Unapproved resource path')
        if '/actions' in parsed.path.lower() or '..' in parsed.path.split('/'):
            raise ValueError('Action or traversal refused')
        if method not in ('GET', 'HEAD', 'OPTIONS'):
            emit({'status': 405, 'headers': {}, 'body': ''})
            continue
        conn = http.client.HTTPSConnection(discovered['address'], timeout=min(20, max(1, int(item.get('timeout', 15)))), context=context)
        try:
            conn.connect()
            certificate = conn.sock.getpeercert(binary_form=True)
            if pin and (certificate is None or hashlib.sha256(certificate).hexdigest() != pin):
                raise ValueError('BMC certificate pin mismatch')
            headers = {'Accept': 'application/json'}
            headers['Authorization'] = auth
            conn.request(method, path, headers=headers)
            response = conn.getresponse()
            raw = response.read(8388609)
            total += len(raw)
            if len(raw) > 8388608 or total > 67108864:
                raise ValueError('Response budget exceeded')
            selected = {k: v for k, v in response.getheaders() if k.lower() in ('content-type', 'location', 'x-auth-token')}
            emit({'status': response.status, 'headers': selected, 'body': base64.b64encode(raw).decode()})
        finally:
            conn.close()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # No raw endpoint exceptions, authentication data or remote tracebacks.
        sys.exit(2)
