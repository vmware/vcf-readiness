"""Enforce a reviewed SHA-256 identity before any vCenter HTTP credentials."""

import hashlib
import hmac
import ssl

from vcf_hci.plugins.mtat.diagnostics import MtatError
from vcf_hci.tls_utils import normalize_thumbprint


def validated_pin(value: str) -> str:
    pin = normalize_thumbprint(value)
    if len(pin) != 64 or any(c not in '0123456789ABCDEF' for c in pin):
        raise ValueError('A certificate pin must be a SHA-256 fingerprint')
    return pin


class PinnedContext(ssl.SSLContext):
    def __new__(cls, pin: str):
        return super().__new__(cls, ssl.PROTOCOL_TLS_CLIENT)

    def __init__(self, pin: str) -> None:
        self.expected_pin = validated_pin(pin)
        self.check_hostname = False
        self.verify_mode = ssl.CERT_NONE

    def wrap_socket(self, *args, **kwargs):
        # HTTPSConnection performs TLS here before writing HTTP headers/body.
        sock = super().wrap_socket(*args, **kwargs)
        certificate = sock.getpeercert(binary_form=True)
        if not certificate:
            sock.close()
            raise MtatError('certificate_missing', 'vCenter did not present a certificate for pin verification.', 'tls')
        actual = hashlib.sha256(certificate).hexdigest().upper()
        if not hmac.compare_digest(actual, self.expected_pin):
            sock.close()
            raise MtatError('certificate_pin_mismatch',
                            'The vCenter certificate changed or does not match the reviewed SHA-256 pin. Stop and review its identity before trusting a new fingerprint.', 'tls')
        return sock
