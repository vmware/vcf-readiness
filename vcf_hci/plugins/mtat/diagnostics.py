"""Credential-safe MTAT diagnostics; never expose upstream exception text."""

import socket
import ssl


class MtatError(RuntimeError):
    def __init__(self, code: str, message: str, stage: str) -> None:
        super().__init__(message)
        self.code = code
        self.stage = stage


def connection_error(exc: Exception, stage: str = "connection") -> MtatError:
    if isinstance(exc, MtatError):
        return exc
    current = exc
    for _ in range(6):
        name = type(current).__name__
        if isinstance(current, ssl.SSLCertVerificationError):
            return MtatError("tls_certificate", "vCenter certificate verification failed. Use Review certificate to inspect and trust its SHA-256 fingerprint, or trust its CA.", stage)
        if name in {"InvalidLogin", "NotAuthenticated"}:
            return MtatError("authentication", "vCenter rejected authentication. Check the username (including its SSO domain), password and account status.", stage)
        if name == "NoPermission":
            return MtatError("permission", "vCenter denied inventory or performance access. Check this account's read permissions on the selected scope.", stage)
        if isinstance(current, socket.gaierror):
            return MtatError("dns", "The vCenter hostname could not be resolved from the machine running VCF-R.", stage)
        if isinstance(current, (TimeoutError, socket.timeout)):
            return MtatError("timeout", "The vCenter request timed out. Check connectivity and API responsiveness from the machine running VCF-R.", stage)
        if isinstance(current, ConnectionError):
            return MtatError("network", "The vCenter connection failed. Check its HTTPS port and network access from the machine running VCF-R.", stage)
        nested = getattr(current, "reason", None) or current.__cause__ or current.__context__
        if not isinstance(nested, Exception) or nested is current:
            break
        current = nested
    return MtatError("vcenter_query" if stage != "connection" else "vcenter_connection",
                     "vCenter %s failed. Check HTTPS connectivity, certificate trust, API access and account permissions." % stage, stage)
