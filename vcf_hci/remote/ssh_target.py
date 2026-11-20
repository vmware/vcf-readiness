"""Shared pinned SSH password-target validation; no remote execution."""
import base64
import re
import struct

from vcf_hci.vault.jump_hosts import compute_ssh_fingerprint


class SshTargetError(ValueError):
    """A target or its pinned host key failed validation."""


def validate_target(target: dict) -> dict:
    if not isinstance(target, dict):
        raise SshTargetError('invalid_target')
    result = {key: target.get(key) for key in ('host', 'port', 'username', 'password', 'host_key')}
    result['port'] = 22 if result['port'] is None else result['port']
    host, username, password, key = (result[field] for field in ('host', 'username', 'password', 'host_key'))
    if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}', host):
        raise SshTargetError('invalid_target')
    if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', username):
        raise SshTargetError('invalid_target')
    if not isinstance(password, str) or not password or len(password) > 4096:
        raise SshTargetError('invalid_credentials')
    if not isinstance(result['port'], int) or isinstance(result['port'], bool) or not 1 <= result['port'] <= 65535:
        raise SshTargetError('invalid_port')
    if not isinstance(key, str) or len(key) > 16384 or '\n' in key or '\r' in key:
        raise SshTargetError('host_key_required')
    fields = key.split()
    allowed = ('ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521')
    if len(fields) != 2 or fields[0] not in allowed:
        raise SshTargetError('host_key_required')
    try:
        raw = base64.b64decode(fields[1], validate=True)
        wire_fields = []
        offset = 0
        while offset < len(raw):
            length = struct.unpack('>I', raw[offset:offset + 4])[0]
            offset += 4
            if length > 16384 or offset + length > len(raw):
                raise ValueError
            wire_fields.append(raw[offset:offset + length])
            offset += length
        if not wire_fields or wire_fields[0].decode('ascii') != fields[0]:
            raise ValueError
        if fields[0] == 'ssh-ed25519':
            if len(wire_fields) != 2 or len(wire_fields[1]) != 32:
                raise ValueError
        elif fields[0] == 'ssh-rsa':
            if len(wire_fields) != 3 or not 1 <= len(wire_fields[1]) <= 8 or not 128 <= len(wire_fields[2]) <= 2049:
                raise ValueError
            exponent = int.from_bytes(wire_fields[1], 'big')
            if exponent < 3 or exponent % 2 == 0:
                raise ValueError
        else:
            curve = fields[0].removeprefix('ecdsa-sha2-')
            point_length = {'nistp256': 65, 'nistp384': 97, 'nistp521': 133}[curve]
            if len(wire_fields) != 3 or wire_fields[1] != curve.encode('ascii') or len(wire_fields[2]) != point_length or wire_fields[2][0] != 4:
                raise ValueError
    except (ValueError, UnicodeError, struct.error):
        raise SshTargetError('invalid_host_key') from None
    if not compute_ssh_fingerprint(key)[1]:
        raise SshTargetError('invalid_host_key')
    result['auth_type'] = 'password'
    return result
