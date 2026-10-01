"""BMC Security Audit recursive redaction and sanitization.

Recursively scrubs secret keys, PEM private key blocks, URL credentials,
and environment-sensitive identifiers from security evidence and findings
before persistence, export, or reporting.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, List, Optional, Set

# Patterns for secret keys and credentials
SECRET_KEY_RE = re.compile(
    r"(password|passphrase|passcode|(?<![a-zA-Z])pin(?![a-zA-Z])|private.?key|security.?key(?!number)|"
    r"community|secret|credential|bind.?password|(?<![a-zA-Z])otp(?![a-zA-Z])|mfa.?seed|"
    r"recovery.?key|session.?token|auth.?token|bearer|pkcs.?12|pfx)",
    re.IGNORECASE,
)

PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----",
    re.IGNORECASE,
)

URI_USERINFO_RE = re.compile(r"://[^/@:\s]+:[^/@\s]+@")

SAFE_SECRET_LIKE_METADATA: Set[str] = {
    "NTP1SecurityKeyNumber",
    "NTP2SecurityKeyNumber",
    "NTP3SecurityKeyNumber",
    "CertificateType",
    "CertificateStatus",
    "MinimumPasswordScore",
    "PasswordMinimumLength",
    "PasswordRequireNumbers",
    "PasswordRequireRegex",
    "PasswordRequireSymbols",
    "PasswordRequireUppercase",
    "ForceChangePassword",
    "MinPasswordLength",
    "MaxPasswordLength",
    "PasswordExpirationDays",
    "PasswordHistory",
    "PasswordComplexity",
    "PasswordScore",
}

CERTIFICATE_BODY_KEYS: Set[str] = {
    "CertificateString",
    "certificateString",
    "CertificateBody",
    "certificateBody",
    "certificate_string",
    "certificate_body",
}

MASKED_VALUE_RE = re.compile(r"^\*+$")

SAFE_POLICY_SUFFIX_RE = re.compile(
    r"(length|score|require.*|regex|uppercase|numbers|symbols|history|expiration.*|status|type|number)$",
    re.IGNORECASE,
)

IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b")
NQN_RE = re.compile(r"\bnqn\.2014-08\.[a-zA-Z0-9.\-_:]+\b", re.IGNORECASE)
IQN_RE = re.compile(r"\biqn\.\d{4}-\d{2}\.[a-zA-Z0-9.\-_:]+\b", re.IGNORECASE)
EUI_RE = re.compile(r"\beui\.[0-9a-fA-F]{16}\b", re.IGNORECASE)
CORP_DOMAIN_RE = re.compile(r"[a-zA-Z0-9.-]+\.broadcom\.net", re.IGNORECASE)
LAB_DOMAIN_RE = re.compile(
    r"[a-zA-Z0-9.-]+\.(?:corp\.local|lab\.local|lvn\.broad)\b", re.IGNORECASE
)


def get_final_key_segment(key: str) -> str:
    """Extract the final key segment from dotted, slashed, or path-like strings."""
    parts = re.split(r"[./\\]", str(key))
    for part in reversed(parts):
        cleaned = part.strip()
        if cleaned:
            return cleaned
    return str(key).strip()


def is_secret_key(key: str) -> bool:
    """Determine if a key name represents a secret property that must be dropped."""
    segment = get_final_key_segment(key)
    segment_lower = segment.lower()

    # Check safe allowlist (case-insensitive)
    for safe in SAFE_SECRET_LIKE_METADATA:
        if segment_lower == safe.lower():
            return False

    # Check certificate raw body keys
    for cert_key in CERTIFICATE_BODY_KEYS:
        if segment_lower == cert_key.lower():
            return True

    # Check for secret keywords
    if SECRET_KEY_RE.search(segment):
        # Exclude safe policy and metric suffixes
        return not bool(SAFE_POLICY_SUFFIX_RE.search(segment))

    return False


def contains_pem_private_key(value: Any) -> bool:
    """Check if value is or contains a PEM private key block."""
    if isinstance(value, str):
        return bool(PEM_PRIVATE_KEY_RE.search(value))
    return False


def sanitize_uri_credentials(text: str) -> str:
    """Strip embedded username/password from URI strings.

    Example: 'https://admin:Secret123@192.168.1.10/path' -> 'https://192.168.1.10/path'
    """
    if not isinstance(text, str):
        return text
    # Strip user:pass@ credentials
    cleaned = URI_USERINFO_RE.sub("://", text)
    # Also strip remaining userinfo if any e.g. ://user@
    if "://" in cleaned and "@" in cleaned:
        cleaned = re.sub(r"://[^/@\s]+@", "://", cleaned)
    return cleaned


def is_masked_secret_value(value: Any) -> bool:
    """Check if a value represents a masked write-only secret placeholder."""
    if isinstance(value, str):
        s = value.strip()
        if MASKED_VALUE_RE.match(s) and len(s) >= 3:
            return True
        if s in ("********", "******", "REDACTED", "[REDACTED]"):
            return True
    return False


def sanitize_security_secrets(value: Any) -> Any:
    """Recursively scrub secrets from dicts, lists, and primitives.

    - Drops fields matching is_secret_key
    - Drops values containing PEM private keys
    - Replaces masked secret values ('********') with None
    - Strips credentials from URIs
    """
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            k_str = str(k)
            if is_secret_key(k_str):
                continue
            if contains_pem_private_key(v):
                continue
            sanitized_v = sanitize_security_secrets(v)
            out[k] = sanitized_v
        return out
    elif isinstance(value, list):
        out_list = []
        for item in value:
            if contains_pem_private_key(item):
                continue
            out_list.append(sanitize_security_secrets(item))
        return out_list
    elif isinstance(value, str):
        if is_masked_secret_value(value):
            return None
        return sanitize_uri_credentials(value)
    else:
        return value


def redact_security_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize a normalized security evidence dictionary.

    Ensures standard and OEM evidence contain zero secret keys,
    zero private keys, zero URL credentials, and no masked literals.
    """
    if not isinstance(evidence, dict):
        return {}

    scrubbed = sanitize_security_secrets(copy.deepcopy(evidence))
    return scrubbed


def redact_security_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sanitize normalized control findings.

    - Clears observed values that were masked strings ('********')
    - Preserves status and reason_code (e.g. unknown_write_only / WRITE_ONLY_SECRET)
    - Sanitizes nested evidence items
    """
    if not isinstance(findings, list):
        return []

    result = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        item = copy.deepcopy(f)

        # If observed was a masked secret, set to None while keeping write-only status
        observed = item.get("observed")
        if is_masked_secret_value(observed) or contains_pem_private_key(observed):
            item["observed"] = None

        # Sanitize evidence items attached to finding
        ev_list = item.get("evidence")
        if isinstance(ev_list, list):
            clean_ev = []
            for ev in ev_list:
                if isinstance(ev, dict):
                    ev_copy = dict(ev)
                    # Strip URI credentials
                    if "uri" in ev_copy and isinstance(ev_copy["uri"], str):
                        ev_copy["uri"] = sanitize_uri_credentials(ev_copy["uri"])
                    # If property was a secret key or raw_value was masked/secret
                    prop = str(ev_copy.get("property", ""))
                    if is_secret_key(prop):
                        ev_copy["raw_value"] = None
                        ev_copy["normalized_value"] = None
                    elif is_masked_secret_value(ev_copy.get("raw_value")) or contains_pem_private_key(ev_copy.get("raw_value")):
                        ev_copy["raw_value"] = None
                    elif is_masked_secret_value(ev_copy.get("normalized_value")) or contains_pem_private_key(ev_copy.get("normalized_value")):
                        ev_copy["normalized_value"] = None
                    clean_ev.append(ev_copy)
            item["evidence"] = clean_ev

        result.append(item)
    return result


def redact_security_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize a complete security payload (evidence and/or findings)."""
    if not isinstance(data, dict):
        return {}

    d = copy.deepcopy(data)
    if "evidence" in d and isinstance(d["evidence"], dict):
        d["evidence"] = redact_security_evidence(d["evidence"])
    if "findings" in d and isinstance(d["findings"], list):
        d["findings"] = redact_security_findings(d["findings"])
    # If the dict itself is an evidence dictionary
    if "schema_version" in d and ("standard" in d or "oem" in d):
        d = redact_security_evidence(d)

    return d


def _obfuscate_string_value(
    val: str,
    salt: str,
    host_alias: str,
    real_host: str = "",
    real_ip: str = "",
    real_sn: str = "",
    key: Optional[Any] = None,
) -> str:
    """Helper to scrub environment identifiers inside a string."""
    from vcf_hci.obfuscation import (
        _obf_eui,
        _obf_ip,
        _obf_iqn,
        _obf_label,
        _obf_mac,
        _obf_nqn,
    )

    s = sanitize_uri_credentials(val)

    if real_sn and len(real_sn) > 3:
        tok_sn = _obf_label(salt, "SN", real_sn)
        if key is not None:
            key.record("sn", real_sn, tok_sn)
        s = s.replace(real_sn, tok_sn)

    if real_host and len(real_host) > 3:
        if key is not None:
            key.record("hostname", real_host, host_alias)
        s = s.replace(real_host, host_alias)

    if real_ip and len(real_ip) > 6:
        tok_ip = _obf_ip(salt, real_ip)
        if key is not None:
            key.record("ip", real_ip, tok_ip)
        s = s.replace(real_ip, tok_ip)

    # Obfuscate remaining IPs
    def _ip_replace(match: re.Match) -> str:
        ip_str = match.group(0)
        # Skip RFC 5737 documentation/test addresses
        if ip_str.startswith("192.0.2.") or ip_str.startswith("198.51.100.") or ip_str.startswith("203.0.113."):
            return ip_str
        tok = _obf_ip(salt, ip_str)
        if key is not None:
            key.record("ip", ip_str, tok)
        return tok

    s = IPV4_RE.sub(_ip_replace, s)

    # Obfuscate MACs
    def _mac_replace(match: re.Match) -> str:
        mac_str = match.group(0)
        tok = _obf_mac(salt, mac_str)
        if key is not None:
            key.record("mac", mac_str, tok)
        return tok

    s = MAC_RE.sub(_mac_replace, s)

    # Obfuscate NQNs
    def _nqn_replace(match: re.Match) -> str:
        nqn_str = match.group(0)
        tok = _obf_nqn(salt, nqn_str)
        if key is not None:
            key.record("nqn", nqn_str, tok)
        return tok

    s = NQN_RE.sub(_nqn_replace, s)

    # Obfuscate IQNs
    def _iqn_replace(match: re.Match) -> str:
        iqn_str = match.group(0)
        tok = _obf_iqn(salt, iqn_str)
        if key is not None:
            key.record("iqn", iqn_str, tok)
        return tok

    s = IQN_RE.sub(_iqn_replace, s)

    # Obfuscate EUI-64
    def _eui_replace(match: re.Match) -> str:
        eui_str = match.group(0)
        tok = _obf_eui(salt, eui_str)
        if key is not None:
            key.record("eui", eui_str, tok)
        return tok

    s = EUI_RE.sub(_eui_replace, s)

    # Scrub internal domains
    s = CORP_DOMAIN_RE.sub("host.example.com", s)
    s = LAB_DOMAIN_RE.sub("host.example.com", s)

    return s


def _obfuscate_security_recursive(
    value: Any,
    salt: str,
    host_alias: str,
    real_host: str = "",
    real_ip: str = "",
    real_sn: str = "",
    key: Optional[Any] = None,
) -> Any:
    """Recursively scrub strings and structure within security payloads."""
    from vcf_hci.obfuscation import _obf_ip, _obf_label

    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            k_str = str(k)
            if is_secret_key(k_str):
                continue
            if contains_pem_private_key(v):
                continue

            # Special handling for certificate subject/issuer
            if k_str in ("Subject", "Issuer") and isinstance(v, dict):
                cert_party = {}
                for party_k, party_v in v.items():
                    if isinstance(party_v, str):
                        if party_k == "CommonName":
                            cert_party[party_k] = _obf_label(salt, "CN", party_v)
                        else:
                            cert_party[party_k] = _obfuscate_string_value(
                                party_v, salt, host_alias, real_host, real_ip, real_sn, key
                            )
                    else:
                        cert_party[party_k] = party_v
                out[k] = cert_party
                continue

            # Special handling for SANs
            if k_str in ("SAN", "SubjectAlternativeNames") and isinstance(v, list):
                san_list = []
                for entry in v:
                    if isinstance(entry, str):
                        if IPV4_RE.match(entry.strip()):
                            san_list.append(_obf_ip(salt, entry.strip()))
                        else:
                            san_list.append(_obf_label(salt, "dns", entry.strip()))
                    else:
                        san_list.append(entry)
                out[k] = san_list
                continue

            out[k] = _obfuscate_security_recursive(
                v, salt, host_alias, real_host, real_ip, real_sn, key
            )
        return out
    elif isinstance(value, list):
        out_list = []
        for item in value:
            if contains_pem_private_key(item):
                continue
            out_list.append(
                _obfuscate_security_recursive(
                    item, salt, host_alias, real_host, real_ip, real_sn, key
                )
            )
        return out_list
    elif isinstance(value, str):
        if is_masked_secret_value(value):
            return None
        return _obfuscate_string_value(
            value, salt, host_alias, real_host, real_ip, real_sn, key
        )
    else:
        return value


def obfuscate_security_data(
    data: Dict[str, Any],
    host_alias: str,
    salt: str,
    key: Optional[Any] = None,
    real_host: str = "",
    real_ip: str = "",
    real_sn: str = "",
) -> Dict[str, Any]:
    """Obfuscate environment-sensitive identifiers in security data.

    Recursively drops secrets, scrubs URI credentials, and replaces:
    - Hostnames with host_alias
    - IPv4 addresses with TEST-NET-1 (192.0.2.x) deterministic hashes
    - MAC addresses with 02:xx:xx:... locally-administered MAC hashes
    - Corporate / internal lab domain names with rainpole.net / host.example.com
    - Certificate Subject/Issuer common names and SANs with hash tokens
    Preserves non-secret algorithm metadata, port numbers, security statuses,
    and SecurityKeyNumber fields.
    """
    if not isinstance(data, dict):
        return {}

    # Step 1: Redact secrets first
    sanitized = redact_security_data(data)

    # Step 2: Obfuscate environment identifiers
    return _obfuscate_security_recursive(
        sanitized,
        salt=salt,
        host_alias=host_alias,
        real_host=real_host,
        real_ip=real_ip,
        real_sn=real_sn,
        key=key,
    )
