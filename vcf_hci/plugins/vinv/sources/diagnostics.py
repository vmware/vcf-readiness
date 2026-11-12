"""Credential-safe vSphere inventory diagnostics and opt-in debug logging.

User-facing messages and log lines carry an error code, a stage and exception type names
only. Upstream exception text is never surfaced, because vCenter and transport errors can
echo user names, URLs or request content.
"""

from __future__ import annotations

import errno
import logging
import os
import socket
import ssl
import sys
import threading
from typing import Iterator, List, Mapping, Optional

from vcf_hci.plugins.mtat.diagnostics import MtatError

LOGGER_NAME = "vcf_assess.vinv"
DEBUG_ENV = "VCF_READINESS_VINV_DEBUG"
DEBUG_LOG_ENV = "VCF_READINESS_VINV_DEBUG_LOG"
_TRUE = {"1", "true", "yes", "on"}
_configure_lock = threading.Lock()
_configured_handlers: List[logging.Handler] = []

logger = logging.getLogger(LOGGER_NAME)

MESSAGES = {
    "sdk_unavailable": "The bundled vCenter SDK could not be loaded. Repair the VCF-R installation and its bundled pyVmomi wheel.",
    "tls_certificate": "vCenter certificate verification failed. Use Review certificate to inspect and trust its SHA-256 fingerprint, or add its CA to the system trust store.",
    "tls_handshake": "The TLS handshake with vCenter failed. Check that the endpoint is the vCenter HTTPS port and that no proxy intercepts the connection.",
    "certificate_pin_mismatch": "The vCenter certificate does not match the reviewed SHA-256 pin. No credentials were sent. Confirm the vCenter identity before trusting a new fingerprint.",
    "certificate_missing": "vCenter did not present a certificate, so the reviewed pin could not be checked. No credentials were sent.",
    "authentication": "vCenter rejected the login. Check the user name (including its SSO domain, for example readonly@vsphere.local), the password and whether the account is locked.",
    "permission": "vCenter denied read access to the inventory. Assign this account at least the Read-only role on the vCenter root, or on the selected cluster, with propagation.",
    "dns": "The vCenter hostname could not be resolved from the machine running VCF-R. Check DNS or use the vCenter IP address.",
    "connection_refused": "vCenter refused the connection. Check the HTTPS port (normally 443) and any firewall between VCF-R and vCenter.",
    "timeout": "The vCenter request timed out. Check connectivity and vCenter API responsiveness, or limit collection to one cluster.",
    "network": "The network connection to vCenter failed. Check routing, proxies and firewalls between VCF-R and vCenter.",
    "api_unsupported": "This vCenter does not support a property or method the inventory collector needs. Record the vCenter version and the reference for support.",
    "inventory_changed": "An inventory object was removed while it was being read. Retry the collection.",
    "vcenter_connection": "The vCenter connection failed. Check HTTPS connectivity, certificate trust and that the endpoint serves the vSphere API.",
    "vcenter_query": "A read-only vCenter inventory query failed. Check the account's read permissions and vCenter API health, then retry.",
    "cancelled": "The inventory collection was cancelled.",
    "deadline_exceeded": "The inventory collection exceeded its time limit. Limit collection to one cluster, or skip the datastore file listing, and retry.",
    "resource_limit": "The inventory is larger than this experimental collector's limits. Limit collection to one cluster.",
    "pagination": "vCenter returned inconsistent result pages. Retry the collection; if it repeats, record the reference for support.",
    "cluster_not_found": "The selected cluster was not found or is ambiguous. Discover clusters again and select one from the list.",
    "result_too_large": "The collected inventory is larger than the result size limit. Limit collection to one cluster or skip the datastore file listing.",
    "certificate_pin_invalid": "A certificate pin must be a SHA-256 fingerprint of 64 hexadecimal characters. Review the certificate again.",
    "endpoint_invalid": "vCenter endpoint must be an HTTPS host or URL without embedded credentials and with a valid port.",
    "internal": "The inventory collector hit an unexpected error while %s. Record the reference and enable vinv debug logging to capture the failing step.",
    "session_cleanup": "The vCenter session could not be closed cleanly. The result was discarded; retry the collection.",
}

_AUTH_FAULTS = {"InvalidLogin", "NotAuthenticated", "InvalidLocale", "PasswordExpired"}
_PERMISSION_FAULTS = {"NoPermission", "SecurityError", "RestrictedVersion"}
_UNSUPPORTED_FAULTS = {"NotSupported", "MethodNotFound", "NotImplemented", "InvalidType", "InvalidProperty"}
_CHANGED_FAULTS = {"ManagedObjectNotFound"}


class VinvError(RuntimeError):
    """A classified failure whose message is safe to show and log."""

    def __init__(self, code: str, stage: str, message: Optional[str] = None) -> None:
        super().__init__(message or MESSAGES.get(code) or "vSphere inventory %s failed." % stage)
        self.code = code
        self.stage = stage


class VinvRejected(VinvError, ValueError):
    """Input, scope or limit rejection raised by vinv itself before or during collection."""


def _chain(exc: BaseException) -> Iterator[BaseException]:
    seen = set()
    current: Optional[BaseException] = exc
    while current is not None and id(current) not in seen and len(seen) < 8:
        seen.add(id(current))
        yield current
        nested = getattr(current, "reason", None)
        if not isinstance(nested, BaseException):
            nested = current.__cause__ or current.__context__
        current = nested


def _fault_names(exc: BaseException) -> set:
    return {cls.__name__.rsplit(".", 1)[-1] for cls in type(exc).__mro__}


def _classify(exc: BaseException) -> Optional[str]:
    if isinstance(exc, VinvError):
        return exc.code
    if isinstance(exc, MtatError) and exc.code in ("certificate_pin_mismatch", "certificate_missing"):
        return exc.code
    names = _fault_names(exc)
    if names & _AUTH_FAULTS:
        return "authentication"
    if names & _PERMISSION_FAULTS:
        return "permission"
    if names & _CHANGED_FAULTS:
        return "inventory_changed"
    if names & _UNSUPPORTED_FAULTS:
        return "api_unsupported"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "tls_certificate"
    if isinstance(exc, ssl.SSLError):
        return "tls_handshake"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(exc, ConnectionError) or (isinstance(exc, OSError) and exc.errno in (
            errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNRESET, errno.ECONNABORTED)):
        return "network"
    return None


def connection_error(exc: BaseException, stage: str = "connection") -> VinvError:
    """Map any connection or query failure to a VinvError without keeping upstream text."""
    if isinstance(exc, VinvError):
        return exc
    for item in _chain(exc):
        code = _classify(item)
        if code:
            error = VinvError(code, "tls" if code.startswith("certificate_") else stage)
            break
    else:
        error = VinvError("vcenter_connection" if stage == "connection" else "vcenter_query", stage)
    logger.debug("vinv mapped failure: code=%s stage=%s chain=%s", error.code, error.stage, exception_summary(exc))
    return error


def unexpected_error(exc: BaseException, stage: str) -> VinvError:
    """Classify an unhandled failure; anything unrecognised is an internal collector error."""
    for item in _chain(exc):
        code = _classify(item)
        if code:
            return VinvError(code, "tls" if code.startswith("certificate_") else stage)
    return VinvError("internal", stage, MESSAGES["internal"] % stage)


def exception_summary(exc: BaseException) -> str:
    """Exception type chain plus the innermost frame location; never exception text."""
    names = [type(item).__name__ for item in _chain(exc)]
    frame = exc.__traceback__
    location = ""
    while frame is not None:
        code = frame.tb_frame.f_code
        location = "%s:%d in %s" % (os.path.basename(code.co_filename), frame.tb_lineno, code.co_name)
        frame = frame.tb_next
    return " <- ".join(names) + (" at " + location if location else "")


def pin_label(pin: str) -> str:
    return "sha256:%s…%s" % (pin[:8], pin[-4:]) if pin else "none"


def debug_enabled(environ: Optional[Mapping[str, str]] = None) -> bool:
    env = os.environ if environ is None else environ
    return str(env.get(DEBUG_ENV, "")).strip().lower() in _TRUE


def configure_debug_logging(environ: Optional[Mapping[str, str]] = None) -> bool:
    """Attach a DEBUG handler to the vinv logger once when the opt-in variable is set.

    The Web UI does not configure the shared ``vcf_assess`` logger, so vinv debug output
    would otherwise be dropped. The optional log file is created with owner-only access.
    """
    env = os.environ if environ is None else environ
    if not debug_enabled(env):
        return False
    with _configure_lock:
        if _configured_handlers:
            return True
        fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(name)s: %(message)s")
        handlers: List[logging.Handler] = [logging.StreamHandler(sys.stderr)]
        path = str(env.get(DEBUG_LOG_ENV, "")).strip()
        if path:
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                os.close(fd)
                handlers.append(logging.FileHandler(path, mode="a", encoding="utf-8"))
            except OSError:
                logger.warning("vinv debug log file could not be opened; logging to stderr only")
        for handler in handlers:
            handler.setFormatter(fmt)
            logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        _configured_handlers.extend(handlers)
    logger.debug("vinv debug logging enabled")
    return True


def reset_debug_logging() -> None:
    """Remove handlers added by configure_debug_logging (used by tests)."""
    with _configure_lock:
        for handler in _configured_handlers:
            logger.removeHandler(handler)
            handler.close()
        _configured_handlers.clear()
        logger.setLevel(logging.NOTSET)
        logger.propagate = True
