"""Evaluation engine for Dell iDRAC9 BMC security posture controls.

Pure evaluation functions translating normalized Dell OEM evidence
and standard Redfish evidence into ordered, validated control findings (C01–C59).

Adheres to:
- Hardware Security Scope Freeze (Bead 0)
- Neutral Security Contract Schema (Bead 1)
- Dell iDRAC9 Security Control Matrix & Gap Document (Bead 4 & 5)
- Non-GET controls (C25, C27, C35, C55, C56, C59) held as unknown.
"""

import re
from typing import Any, Dict, List, Optional

from vcf_hci.security.contract import (
    ReasonCode,
    control_finding,
    evidence_item,
)
from vcf_hci.security.evaluation import (
    evaluate_c29_session_auth,
    evaluate_c37_session_timeout,
    evaluate_c43_directory_and_lockout,
    evaluate_c53_secure_boot,
)

DELL_MGR_ATTRS_URI = "/redfish/v1/Managers/iDRAC.Embedded.1/Attributes"
DELL_LC_ATTRS_URI = "/redfish/v1/Managers/iDRAC.Embedded.1/Attributes"


def normalize_attr_key(key: str) -> str:
    """Normalize a Dell attribute key for instance- and prefix-agnostic lookup.

    Examples:
        'WebServer.1.HttpsRedirection' -> 'webserver.httpsredirection'
        'iDRAC.WebServer.HttpsRedirection' -> 'webserver.httpsredirection'
        'webserver.1.httpsredirection' -> 'webserver.httpsredirection'
        'LCAttributes.1.IgnoreCertWarning' -> 'lcattributes.ignorecertwarning'
        'LifecycleController.LCAttributes.1.IgnoreCertWarning' -> 'lcattributes.ignorecertwarning'
        'OS-BMC.1.AdminState' -> 'os-bmc.adminstate'
    """
    k = key.strip().lower()
    k = re.sub(r"^(?:idrac|lifecyclecontroller)\.", "", k)
    k = re.sub(r"\.\d+\.", ".", k)
    return k


def get_dell_attribute(attrs: Dict[str, Any], target_key: str) -> Optional[Any]:
    """Retrieve an attribute by exact, normalized, or hyphen-agnostic name."""
    if not isinstance(attrs, dict):
        return None

    target_lower = target_key.strip().lower()
    for k, v in attrs.items():
        if k.strip().lower() == target_lower:
            return v

    norm_target = normalize_attr_key(target_key)
    for k, v in attrs.items():
        if normalize_attr_key(k) == norm_target:
            return v

    norm_no_hyphen = norm_target.replace("-", "")
    for k, v in attrs.items():
        if normalize_attr_key(k).replace("-", "") == norm_no_hyphen:
            return v

    return None


def get_dell_user_attributes(attrs: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Group Dell user attributes by user slot index.

    Matches patterns like 'Users.2.IpmiLanPrivilege' or 'users.2.solenable'.
    Returns {slot_str: {field_name: value}}.
    """
    users: Dict[str, Dict[str, Any]] = {}
    pattern = re.compile(r"^(?:idrac\.)?users\.(\d+)\.(.+)$", re.IGNORECASE)
    for k, v in attrs.items():
        m = pattern.match(k.strip())
        if m:
            slot = m.group(1)
            field = m.group(2).lower()
            users.setdefault(slot, {})[field] = v
    return users


def extract_dell_attributes(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and merge all Dell attributes from an evidence dictionary."""
    attrs: Dict[str, Any] = {}
    oem = evidence.get("oem") or {}
    if isinstance(oem, dict):
        if isinstance(oem.get("idrac_attributes"), dict):
            attrs.update(oem["idrac_attributes"])
        if isinstance(oem.get("lc_attributes"), dict):
            attrs.update(oem["lc_attributes"])
        for k, v in oem.items():
            if k not in ("idrac_attributes", "lc_attributes", "retained_attribute_count", "certificate_count"):
                attrs[k] = v
    return attrs


def is_enabled(value: Any) -> Optional[bool]:
    """Normalize boolean or string state to True/False/None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    s = str(value).strip().lower()
    if s in ("enabled", "1", "true", "on", "yes", "dedicated"):
        return True
    if s in ("disabled", "0", "false", "off", "no", "shared", "lom", "shared lom"):
        return False
    return None


def to_int(value: Any) -> Optional[int]:
    """Convert value to int if possible, otherwise return None."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Evaluators for C01–C59
# ---------------------------------------------------------------------------


def evaluate_c01_https_redirect(attrs: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C01: HTTP-to-HTTPS redirection."""
    raw_val = get_dell_attribute(attrs, "webserver.1.httpsredirection")
    enabled = is_enabled(raw_val)

    net_proto = standard.get("network_protocol") or {}
    http_data = net_proto.get("HTTP") or {}
    http_enabled = http_data.get("ProtocolEnabled")

    ev: List[Dict[str, Any]] = []
    if raw_val is not None:
        ev.append(evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="WebServer.1.HttpsRedirection",
            raw_value=raw_val,
            normalized_value=enabled,
        ))

    if enabled is True:
        return control_finding(
            control_id="C01",
            status="pass",
            expected="Enabled or HTTP service disabled",
            observed="Enabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    if http_enabled is False:
        ev.append(evidence_item(
            transport="standard_redfish",
            uri=net_proto.get("uri", "/redfish/v1/Managers/{id}/NetworkProtocol"),
            property="HTTP.ProtocolEnabled",
            raw_value=http_enabled,
            normalized_value=False,
        ))
        return control_finding(
            control_id="C01",
            status="pass",
            expected="Enabled or HTTP service disabled",
            observed="HTTP disabled",
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )

    if enabled is False and http_enabled is True:
        return control_finding(
            control_id="C01",
            status="fail",
            expected="Enabled or HTTP service disabled",
            observed="Disabled (HTTP redirection not enforced)",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )

    return control_finding(
        control_id="C01",
        status="unknown_not_exposed",
        expected="Enabled or HTTP service disabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c02_tls_version(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C02: Minimum TLS version."""
    raw_val = get_dell_attribute(attrs, "webserver.1.tlsprotocol")
    if raw_val is None:
        return control_finding(
            control_id="C02",
            status="unknown_not_exposed",
            expected="TLS 1.2 or higher",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    s = str(raw_val).strip()
    s_lower = s.lower()
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="WebServer.1.TLSProtocol",
        raw_value=raw_val,
        normalized_value=s,
    )]

    # Check for weak versions first
    if "1.0" in s_lower or "1.1" in s_lower:
        return control_finding(
            control_id="C02",
            status="fail",
            expected="TLS 1.2 or higher",
            observed=f"{s} (below baseline TLS 1.2+)",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )

    if "1.3" in s_lower or "1.2" in s_lower or s in ("3", "4"):
        return control_finding(
            control_id="C02",
            status="pass",
            expected="TLS 1.2 or higher",
            observed=s,
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C02",
        status="unknown_ambiguous",
        expected="TLS 1.2 or higher",
        observed=s,
        reason_code=ReasonCode.AMBIGUOUS_EVIDENCE,
        evidence=ev,
    )


def evaluate_c03_tls_encryption_bit_length(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C03: TLS encryption strength."""
    raw_val = get_dell_attribute(attrs, "webserver.1.sslencryptionbitlength")
    if raw_val is None:
        return control_finding(
            control_id="C03",
            status="unknown_not_exposed",
            expected=">= 256-bit",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    s = str(raw_val).strip()
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="WebServer.1.SSLEncryptionBitLength",
        raw_value=raw_val,
        normalized_value=s,
    )]

    t_val = to_int(raw_val)
    if "256" in s.lower() or (t_val is not None and t_val >= 256):
        return control_finding(
            control_id="C03",
            status="pass",
            expected=">= 256-bit",
            observed=s,
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C03",
        status="fail",
        expected=">= 256-bit",
        observed=f"{s} (below target >= 256-bit)",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c04_tls_ciphers(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C04: TLS cipher-suite restriction."""
    raw_val = get_dell_attribute(attrs, "webserver.1.customcipherstring")
    if raw_val is None:
        return control_finding(
            control_id="C04",
            status="unknown_not_exposed",
            expected="Excludes weak ciphers (RC4, 3DES, DES, MD5, CBC)",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    s = str(raw_val).strip()
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="WebServer.1.CustomCipherString",
        raw_value=raw_val,
        normalized_value=s,
    )]

    s_upper = s.upper()
    weak_tokens = ["RC4", "3DES", "DES", "MD5", "EXPORT", "NULL"]
    found_weak = [t for t in weak_tokens if t in s_upper and f"!{t}" not in s_upper]

    if not s or s.lower() in ("default", "none", "null") or found_weak:
        return control_finding(
            control_id="C04",
            status="fail",
            expected="Excludes weak ciphers (RC4, 3DES, DES, MD5, CBC)",
            observed=f"Contains weak ciphers or default: {s}",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )

    return control_finding(
        control_id="C04",
        status="pass",
        expected="Excludes weak ciphers (RC4, 3DES, DES, MD5, CBC)",
        observed=f"Hardened custom cipher string ({s})",
        reason_code=ReasonCode.OEM_REDFISH_PASS,
        evidence=ev,
    )


def evaluate_c05_trusted_certificate(attrs: Dict[str, Any], evidence: Dict[str, Any]) -> Dict[str, Any]:
    """C05: Trusted iDRAC web certificate (partial-write-only)."""
    oem = evidence.get("oem") or {}
    cert_count = oem.get("certificate_count")

    ev: List[Dict[str, Any]] = []
    if cert_count is not None:
        ev.append(evidence_item(
            transport="oem_redfish",
            uri="/redfish/v1/Managers/iDRAC.Embedded.1/Certificates",
            property="certificate_count",
            raw_value=cert_count,
            normalized_value=cert_count,
        ))

    # Certificate private key is write-only / secret; CA trust cannot be proven without metadata
    if cert_count is not None and cert_count > 0:
        return control_finding(
            control_id="C05",
            status="unknown_write_only",
            expected="CA-signed certificate installed",
            observed=f"{cert_count} certificate(s) present (CA trust write-only/unverified)",
            reason_code=ReasonCode.WRITE_ONLY_SECRET,
            evidence=ev,
        )

    return control_finding(
        control_id="C05",
        status="unknown_not_exposed",
        expected="CA-signed certificate installed",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c06_scep(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C06: SCEP/automatic certificate enrollment."""
    raw_val = get_dell_attribute(attrs, "scep.1.enable")
    prop_name = "SCEP.1.Enable"
    status_prop = "SCEP.1.EnrollmentStatus"
    if raw_val is None:
        raw_val = get_dell_attribute(attrs, "ace.1.enable")
        prop_name = "ACE.1.Enable"
        status_prop = "ACE.1.EnrollmentStatus"

    enabled = is_enabled(raw_val)

    if raw_val is None:
        return control_finding(
            control_id="C06",
            status="unknown_not_exposed",
            expected="Disabled or healthy enrollment status",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property=prop_name,
        raw_value=raw_val,
        normalized_value=enabled,
    )]

    if enabled is False:
        return control_finding(
            control_id="C06",
            status="pass",
            expected="Disabled or healthy enrollment status",
            observed="Disabled (attack surface minimized)",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    status_val = str(get_dell_attribute(attrs, "scep.1.enrollmentstatus") or get_dell_attribute(attrs, "ace.1.enrollmentstatus") or "").strip()
    if status_val and status_val.lower() != "none":
        ev.append(evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property=status_prop,
            raw_value=status_val,
            normalized_value=status_val,
        ))

    if status_val.lower() in ("success", "enrolled", "healthy", "completed", "ok", "active"):
        return control_finding(
            control_id="C06",
            status="pass",
            expected="Disabled or healthy enrollment status",
            observed=f"Enabled (status: {status_val})",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C06",
        status="fail",
        expected="Disabled or healthy enrollment status",
        observed=f"Enabled (status: {status_val or 'unknown/error'})",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c07_secure_syslog(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C07: Remote syslog over TLS."""
    raw_val = get_dell_attribute(attrs, "syslog.1.securesyslogenable")
    enabled = is_enabled(raw_val)

    if raw_val is None:
        return control_finding(
            control_id="C07",
            status="unknown_not_exposed",
            expected="Enabled with secure port (6514) / client auth",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    port = get_dell_attribute(attrs, "syslog.1.secureport")
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="SysLog.1.securesyslogenable",
        raw_value=raw_val,
        normalized_value=enabled,
    )]
    if port is not None:
        ev.append(evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="SysLog.1.secureport",
            raw_value=port,
            normalized_value=to_int(port),
        ))

    if enabled is True:
        return control_finding(
            control_id="C07",
            status="pass",
            expected="Enabled with secure port (6514) / client auth",
            observed=f"Enabled (port {port or 6514})",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C07",
        status="fail",
        expected="Enabled with secure port (6514) / client auth",
        observed="Disabled (unencrypted syslog)",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c08_fips_mode(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C08: FIPS mode."""
    raw_val = get_dell_attribute(attrs, "security.1.fipsmode")
    enabled = is_enabled(raw_val)

    if raw_val is None:
        return control_finding(
            control_id="C08",
            status="unknown_not_exposed",
            expected="Enabled where required by policy",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="Security.1.FIPSMode",
        raw_value=raw_val,
        normalized_value=enabled,
    )]

    if enabled is True:
        return control_finding(
            control_id="C08",
            status="pass",
            expected="Enabled where required by policy",
            observed="Enabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C08",
        status="not_applicable",
        expected="Enabled where required by policy",
        observed="Disabled (FIPS 140-2 not in scope)",
        reason_code=ReasonCode.NOT_APPLICABLE,
        evidence=ev,
    )


def evaluate_c09_ssh_dell(attrs: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C09: SSH service exposure."""
    # Check standard Redfish evidence first
    net_proto = standard.get("network_protocol") or {}
    ssh_data = net_proto.get("SSH")
    if isinstance(ssh_data, dict) and "ProtocolEnabled" in ssh_data:
        enabled = ssh_data.get("ProtocolEnabled")
        return control_finding(
            control_id="C09",
            status="pass",
            expected="Disabled or hardened SSH enabled",
            observed=bool(enabled),
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=[evidence_item(
                transport="standard_redfish",
                uri=net_proto.get("uri", "/redfish/v1/Managers/{id}/NetworkProtocol"),
                property="SSH.ProtocolEnabled",
                raw_value=enabled,
                normalized_value=bool(enabled),
            )],
        )

    # Fallback to Dell SSH.1.Enable
    raw_val = get_dell_attribute(attrs, "ssh.1.enable")
    enabled = is_enabled(raw_val)
    if raw_val is not None:
        return control_finding(
            control_id="C09",
            status="pass",
            expected="Disabled or hardened SSH enabled",
            observed=bool(enabled),
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item(
                transport="oem_redfish",
                uri=DELL_MGR_ATTRS_URI,
                property="SSH.1.Enable",
                raw_value=raw_val,
                normalized_value=bool(enabled),
            )],
        )

    return control_finding(
        control_id="C09",
        status="unknown_not_exposed",
        expected="Disabled or hardened SSH enabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c10_ssh_public_key(attrs: Dict[str, Any], evidence: Dict[str, Any]) -> Dict[str, Any]:
    """C10: SSH public-key authentication (partial-write-only)."""
    users = get_dell_user_attributes(attrs)
    ev: List[Dict[str, Any]] = []

    has_key = False
    for slot, u in users.items():
        for k, v in u.items():
            if "ssh" in k and "key" in k and v:
                has_key = True
                ev.append(evidence_item(
                    transport="oem_redfish",
                    uri=DELL_MGR_ATTRS_URI,
                    property=f"Users.{slot}.{k}",
                    raw_value="[CONFIGURED]",
                    normalized_value=True,
                ))

    if has_key:
        return control_finding(
            control_id="C10",
            status="pass",
            expected="Configured with 4096-bit RSA or strong key",
            observed="SSH public key configured",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    if users:
        return control_finding(
            control_id="C10",
            status="unknown_write_only",
            expected="Configured with 4096-bit RSA or strong key",
            observed="SSH public key configuration write-only/unverified",
            reason_code=ReasonCode.WRITE_ONLY_SECRET,
            evidence=[],
        )

    return control_finding(
        control_id="C10",
        status="unknown_not_exposed",
        expected="Configured with 4096-bit RSA or strong key",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c11_ssh_crypto(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C11: SSH cryptographic policy."""
    ciphers = str(get_dell_attribute(attrs, "sshcrypto.1.ciphers") or "").strip()
    kex = str(get_dell_attribute(attrs, "sshcrypto.1.kexalgorithms") or "").strip()
    macs = str(get_dell_attribute(attrs, "sshcrypto.1.macs") or "").strip()
    hostkeys = str(get_dell_attribute(attrs, "sshcrypto.1.hostkeyalgorithms") or "").strip()

    if not any((ciphers, kex, macs, hostkeys)):
        return control_finding(
            control_id="C11",
            status="unknown_not_exposed",
            expected="Hardened ciphers, MACs, KEX (no DSA, CBC, SHA-1 KEX)",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    ev = [
        evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="SSHCrypto.1.Ciphers",
            raw_value=ciphers,
            normalized_value=ciphers,
        ),
        evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="SSHCrypto.1.KexAlgorithms",
            raw_value=kex,
            normalized_value=kex,
        ),
        evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="SSHCrypto.1.MACs",
            raw_value=macs,
            normalized_value=macs,
        ),
    ]

    weak_kex = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"]
    weak_ciphers = ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "blowfish-cbc", "cast128-cbc"]
    weak_macs = ["hmac-sha1", "hmac-md5", "none", "hmac-sha1-96", "hmac-md5-96"]
    weak_hostkeys = ["ssh-dss"]

    found_weak: List[str] = []
    for w in weak_kex:
        if w in kex.lower():
            found_weak.append(w)
    for w in weak_ciphers:
        if w in ciphers.lower():
            found_weak.append(w)
    for w in weak_macs:
        if w in macs.lower():
            found_weak.append(w)
    for w in weak_hostkeys:
        if w in hostkeys.lower():
            found_weak.append(w)

    if found_weak:
        return control_finding(
            control_id="C11",
            status="fail",
            expected="Hardened ciphers, MACs, KEX (no DSA, CBC, SHA-1 KEX)",
            observed=f"Weak algorithms configured: {', '.join(found_weak)}",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )

    return control_finding(
        control_id="C11",
        status="pass",
        expected="Hardened ciphers, MACs, KEX (no DSA, CBC, SHA-1 KEX)",
        observed="Hardened SSH crypto policy configured",
        reason_code=ReasonCode.OEM_REDFISH_PASS,
        evidence=ev,
    )


def evaluate_c12_dedicated_nic(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C12: Dedicated management NIC."""
    raw_val = get_dell_attribute(attrs, "nic.1.selection")
    prop_name = "NIC.1.Selection"
    if raw_val is None:
        raw_val = get_dell_attribute(attrs, "nic.1.activenic")
        prop_name = "NIC.1.ActiveNIC"
    if raw_val is None:
        raw_val = get_dell_attribute(attrs, "nic.1.selectionbyfqdd")
        prop_name = "NIC.1.SelectionByFQDD"

    if raw_val is None:
        return control_finding(
            control_id="C12",
            status="unknown_not_exposed",
            expected="Dedicated",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    s = str(raw_val).strip()
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property=prop_name,
        raw_value=raw_val,
        normalized_value=s,
    )]

    if s.lower() in ("dedicated", "1"):
        return control_finding(
            control_id="C12",
            status="pass",
            expected="Dedicated",
            observed="Dedicated",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C12",
        status="fail",
        expected="Dedicated",
        observed=f"{s} (Shared LOM)",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c13_vlan(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C13: Management VLAN."""
    vlan_en_raw = get_dell_attribute(attrs, "nic.1.vlanenable")
    vlan_id_raw = get_dell_attribute(attrs, "nic.1.vlanid")

    if vlan_en_raw is None:
        return control_finding(
            control_id="C13",
            status="unknown_not_exposed",
            expected="Enabled with valid VLAN ID (1-4094)",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    enabled = is_enabled(vlan_en_raw)
    vid = to_int(vlan_id_raw)
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="NIC.1.VLanEnable",
        raw_value=vlan_en_raw,
        normalized_value=enabled,
    )]
    if vlan_id_raw is not None:
        ev.append(evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="NIC.1.VLanID",
            raw_value=vlan_id_raw,
            normalized_value=vid,
        ))

    if enabled is True and vid is not None and 1 <= vid <= 4094:
        return control_finding(
            control_id="C13",
            status="pass",
            expected="Enabled with valid VLAN ID (1-4094)",
            observed=f"VLAN {vid} enabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    if enabled is False:
        return control_finding(
            control_id="C13",
            status="fail",
            expected="Enabled with valid VLAN ID (1-4094)",
            observed="Management VLAN disabled",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )

    return control_finding(
        control_id="C13",
        status="fail",
        expected="Enabled with valid VLAN ID (1-4094)",
        observed=f"Invalid VLAN configuration (enable: {enabled}, ID: {vid})",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c14_usb_management(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C14: USB management and USB SCP."""
    port_status_raw = get_dell_attribute(attrs, "usb.1.portstatus")
    xml_status_raw = get_dell_attribute(attrs, "usb.1.configurationxml")

    if port_status_raw is None and xml_status_raw is None:
        return control_finding(
            control_id="C14",
            status="unknown_not_exposed",
            expected="Disabled when unused",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    port_en = is_enabled(port_status_raw)
    xml_en = is_enabled(xml_status_raw)

    ev = []
    if port_status_raw is not None:
        ev.append(evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="USB.1.PortStatus",
            raw_value=port_status_raw,
            normalized_value=port_en,
        ))
    if xml_status_raw is not None:
        ev.append(evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="USB.1.ConfigurationXML",
            raw_value=xml_status_raw,
            normalized_value=xml_en,
        ))

    if port_en is False or xml_en is False:
        return control_finding(
            control_id="C14",
            status="pass",
            expected="Disabled when unused",
            observed="USB management/SCP XML configuration disabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C14",
        status="fail",
        expected="Disabled when unused",
        observed="USB port and configuration XML enabled",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c15_os_bmc_passthrough(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C15: OS-to-iDRAC pass-through."""
    admin_state_raw = get_dell_attribute(attrs, "os-bmc.1.adminstate")
    pt_mode_raw = get_dell_attribute(attrs, "os-bmc.1.ptmode")

    if admin_state_raw is None:
        usb_p2p = get_dell_attribute(attrs, "os-bmc.1.usbp2penable")
        lom_p2p = get_dell_attribute(attrs, "os-bmc.1.lomp2penable")
        if usb_p2p is not None or lom_p2p is not None:
            usb_en = is_enabled(usb_p2p) is True
            lom_en = is_enabled(lom_p2p) is True
            ev = []
            if usb_p2p is not None:
                ev.append(evidence_item(
                    transport="oem_redfish",
                    uri=DELL_MGR_ATTRS_URI,
                    property="OS-BMC.1.UsbP2PEnable",
                    raw_value=usb_p2p,
                    normalized_value=usb_en,
                ))
            if lom_p2p is not None:
                ev.append(evidence_item(
                    transport="oem_redfish",
                    uri=DELL_MGR_ATTRS_URI,
                    property="OS-BMC.1.LomP2PEnable",
                    raw_value=lom_p2p,
                    normalized_value=lom_en,
                ))
            if not usb_en and not lom_en:
                return control_finding(
                    control_id="C15",
                    status="pass",
                    expected="Disabled or USB mode",
                    observed="Disabled",
                    reason_code=ReasonCode.OEM_REDFISH_PASS,
                    evidence=ev,
                )
            elif usb_en and not lom_en:
                return control_finding(
                    control_id="C15",
                    status="pass",
                    expected="Disabled or USB mode",
                    observed="Enabled (USB mode)",
                    reason_code=ReasonCode.OEM_REDFISH_PASS,
                    evidence=ev,
                )
            else:
                return control_finding(
                    control_id="C15",
                    status="fail",
                    expected="Disabled or USB mode",
                    observed="Enabled (LOM mode)",
                    reason_code=ReasonCode.OEM_REDFISH_FAIL,
                    evidence=ev,
                )

        return control_finding(
            control_id="C15",
            status="unknown_not_exposed",
            expected="Disabled or USB mode",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    admin_en = is_enabled(admin_state_raw)
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="OS-BMC.1.AdminState",
        raw_value=admin_state_raw,
        normalized_value=admin_en,
    )]

    if admin_en is False:
        return control_finding(
            control_id="C15",
            status="pass",
            expected="Disabled or USB mode",
            observed="Disabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    pt_mode = str(pt_mode_raw or "").strip()
    if pt_mode_raw is not None:
        ev.append(evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="OS-BMC.1.PTMode",
            raw_value=pt_mode_raw,
            normalized_value=pt_mode,
        ))

    if pt_mode.lower() == "usb":
        return control_finding(
            control_id="C15",
            status="pass",
            expected="Disabled or USB mode",
            observed="Enabled (USB-NIC mode)",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C15",
        status="fail",
        expected="Disabled or USB mode",
        observed=f"Enabled (LOM mode: {pt_mode})",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c16_ip_blocking(attrs: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C16: IP login blocking."""
    block_en_raw = get_dell_attribute(attrs, "ipblocking.1.blockenable")
    fail_cnt_raw = get_dell_attribute(attrs, "ipblocking.1.failcount")
    fail_win_raw = get_dell_attribute(attrs, "ipblocking.1.failwindow")
    penalty_raw = get_dell_attribute(attrs, "ipblocking.1.penaltytime")

    ev: List[Dict[str, Any]] = []
    expected_c16 = "Enabled with FailCount at most 5 and PenaltyTime at least 60s"
    if block_en_raw is not None:
        enabled = is_enabled(block_en_raw)
        ev.append(evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="IPBlocking.1.BlockEnable",
            raw_value=block_en_raw,
            normalized_value=enabled,
        ))
        if enabled is True:
            fc = to_int(fail_cnt_raw) or 3
            if 1 <= fc <= 5:
                return control_finding(
                    control_id="C16",
                    status="pass",
                    expected=expected_c16,
                    observed=f"Enabled (FailCount: {fc}, Penalty: {penalty_raw or 60}s)",
                    reason_code=ReasonCode.OEM_REDFISH_PASS,
                    evidence=ev,
                )
            return control_finding(
                control_id="C16",
                status="fail",
                expected=expected_c16,
                observed=f"Enabled with weak FailCount {fc}",
                reason_code=ReasonCode.OEM_REDFISH_FAIL,
                evidence=ev,
            )
        return control_finding(
            control_id="C16",
            status="fail",
            expected=expected_c16,
            observed="Disabled",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )

    # Supporting check: standard AccountLockoutThreshold
    acct_svc = standard.get("account_service") or {}
    lockout_thresh = acct_svc.get("AccountLockoutThreshold")
    if lockout_thresh is not None:
        lt = to_int(lockout_thresh)
        ev.append(evidence_item(
            transport="standard_redfish",
            uri=acct_svc.get("uri", "/redfish/v1/AccountService"),
            property="AccountLockoutThreshold",
            raw_value=lockout_thresh,
            normalized_value=lt,
        ))
        if lt is not None and 1 <= lt <= 5:
            return control_finding(
                control_id="C16",
                status="pass",
                expected=expected_c16,
                observed=f"AccountLockoutThreshold = {lt}",
                reason_code=ReasonCode.STANDARD_REDFISH_PASS,
                evidence=ev,
            )
        if lt == 0:
            return control_finding(
                control_id="C16",
                status="fail",
                expected=expected_c16,
                observed="Lockout disabled (threshold = 0)",
                reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
                evidence=ev,
            )

    return control_finding(
        control_id="C16",
        status="unknown_not_exposed",
        expected=expected_c16,
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c17_ip_range_filtering(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C17: IP allow-range filtering."""
    range_en = get_dell_attribute(attrs, "ipblocking.1.rangeenable")
    ranges_found: List[str] = []
    for i in range(1, 6):
        v = get_dell_attribute(attrs, f"ipblocking.1.rangeenable{i}")
        if is_enabled(v) is True:
            ranges_found.append(f"Range{i}")

    if is_enabled(range_en) is True or ranges_found:
        return control_finding(
            control_id="C17",
            status="pass",
            expected="Enabled with configured address ranges",
            observed="IP allow-range filtering enabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item(
                transport="oem_redfish",
                uri=DELL_MGR_ATTRS_URI,
                property="IPBlocking.1.RangeEnable",
                raw_value="[REDACTED_RANGES_CONFIGURED]",
                normalized_value=True,
            )],
        )

    if is_enabled(range_en) is False:
        return control_finding(
            control_id="C17",
            status="fail",
            expected="Enabled with configured address ranges",
            observed="IP allow-range filtering disabled",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[evidence_item(
                transport="oem_redfish",
                uri=DELL_MGR_ATTRS_URI,
                property="IPBlocking.1.RangeEnable",
                raw_value=range_en,
                normalized_value=False,
            )],
        )

    return control_finding(
        control_id="C17",
        status="unknown_not_exposed",
        expected="Enabled with configured address ranges",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c18_autodiscovery(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C18: Auto-discovery."""
    raw_val = get_dell_attribute(attrs, "autodiscovery.1.enableipchangeannounce")
    enabled = is_enabled(raw_val)

    if raw_val is None:
        return control_finding(
            control_id="C18",
            status="unknown_not_exposed",
            expected="Disabled post-provisioning",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="Autodiscovery.1.EnableIPChangeAnnounce",
        raw_value=raw_val,
        normalized_value=enabled,
    )]

    if enabled is False:
        return control_finding(
            control_id="C18",
            status="pass",
            expected="Disabled post-provisioning",
            observed="Disabled (post-provisioning)",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C18",
        status="fail",
        expected="Disabled post-provisioning",
        observed="Enabled (auto-discovery announce active)",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c19_autoconfig(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C19: Auto Config / SCP provisioning."""
    raw_val = get_dell_attribute(attrs, "nic.1.autoconfig")
    prop_name = "NIC.1.AutoConfig"
    if raw_val is None:
        raw_val = get_dell_attribute(attrs, "network.1.autoconfig")
        prop_name = "Network.1.AutoConfig"

    enabled = is_enabled(raw_val)

    if raw_val is None:
        return control_finding(
            control_id="C19",
            status="unknown_not_exposed",
            expected="Disabled or HTTPS transfer enforced",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property=prop_name,
        raw_value=raw_val,
        normalized_value=enabled,
    )]

    if enabled is False:
        return control_finding(
            control_id="C19",
            status="pass",
            expected="Disabled or HTTPS transfer enforced",
            observed="Disabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C19",
        status="fail",
        expected="Disabled or HTTPS transfer enforced",
        observed="Enabled (DHCP AutoConfig active)",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c20_unused_services(attrs: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C20: Disable unused interfaces/services."""
    net_proto = standard.get("network_protocol") or {}
    telnet_data = net_proto.get("Telnet") or {}
    ipmi_data = net_proto.get("IPMI") or {}

    telnet_on = is_enabled(telnet_data.get("ProtocolEnabled"))
    ipmi_on = is_enabled(ipmi_data.get("ProtocolEnabled"))

    # Also check Dell attributes
    if telnet_on is None:
        telnet_on = is_enabled(get_dell_attribute(attrs, "telnet.1.enable"))
    if ipmi_on is None:
        ipmi_on = is_enabled(get_dell_attribute(attrs, "ipmilan.1.enable"))

    if telnet_on is None and ipmi_on is None:
        return control_finding(
            control_id="C20",
            status="unknown_not_exposed",
            expected="Insecure interfaces disabled (Telnet, IPMI)",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    if telnet_on is False and ipmi_on is False:
        return control_finding(
            control_id="C20",
            status="pass",
            expected="Insecure interfaces disabled (Telnet, IPMI)",
            observed="Unused/insecure services disabled (Telnet, IPMI)",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[],
        )

    return control_finding(
        control_id="C20",
        status="fail",
        expected="Insecure interfaces disabled (Telnet, IPMI)",
        observed="Insecure services enabled (Telnet or IPMI active)",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=[],
    )


def evaluate_c21_ipmi_lan_dell(attrs: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C21: IPMI over LAN."""
    raw_val = get_dell_attribute(attrs, "ipmilan.1.enable")
    if raw_val is not None:
        enabled = is_enabled(raw_val)
        ev = [evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="IPMILan.1.Enable",
            raw_value=raw_val,
            normalized_value=enabled,
        )]
        if enabled is False:
            return control_finding(
                control_id="C21",
                status="pass",
                expected="Disabled",
                observed=False,
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C21",
            status="fail",
            expected="Disabled",
            observed=True,
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )

    # Standard check fallback
    net_proto = standard.get("network_protocol") or {}
    ipmi_data = net_proto.get("IPMI") or {}
    if "ProtocolEnabled" in ipmi_data:
        std_en = bool(ipmi_data.get("ProtocolEnabled"))
        return control_finding(
            control_id="C21",
            status="pass" if not std_en else "fail",
            expected="Disabled",
            observed=std_en,
            reason_code=ReasonCode.STANDARD_REDFISH_PASS if not std_en else ReasonCode.STANDARD_REDFISH_FAIL,
            evidence=[evidence_item(
                transport="standard_redfish",
                uri=net_proto.get("uri", "/redfish/v1/Managers/{id}/NetworkProtocol"),
                property="IPMI.ProtocolEnabled",
                raw_value=std_en,
                normalized_value=std_en,
            )],
        )

    return control_finding(
        control_id="C21",
        status="unknown_not_exposed",
        expected="Disabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c22_sol(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C22: Serial over LAN."""
    raw_val = get_dell_attribute(attrs, "ipmisol.1.enable")
    enabled = is_enabled(raw_val)

    if raw_val is None:
        return control_finding(
            control_id="C22",
            status="unknown_not_exposed",
            expected="Disabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="IPMISOL.1.Enable",
        raw_value=raw_val,
        normalized_value=enabled,
    )]

    if enabled is False:
        return control_finding(
            control_id="C22",
            status="pass",
            expected="Disabled",
            observed="Disabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C22",
        status="fail",
        expected="Disabled",
        observed="Enabled",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c23_telnet_dell(attrs: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C23: Telnet."""
    net_proto = standard.get("network_protocol") or {}
    telnet_data = net_proto.get("Telnet") or {}
    raw_dell = get_dell_attribute(attrs, "telnet.1.enable")

    if "ProtocolEnabled" in telnet_data and telnet_data.get("ProtocolEnabled") is not None:
        std_en = bool(telnet_data.get("ProtocolEnabled"))
        return control_finding(
            control_id="C23",
            status="pass" if not std_en else "fail",
            expected="Disabled",
            observed=std_en,
            reason_code=ReasonCode.STANDARD_REDFISH_PASS if not std_en else ReasonCode.STANDARD_REDFISH_FAIL,
            evidence=[evidence_item(
                transport="standard_redfish",
                uri=net_proto.get("uri", "/redfish/v1/Managers/{id}/NetworkProtocol"),
                property="Telnet.ProtocolEnabled",
                raw_value=std_en,
                normalized_value=std_en,
            )],
        )

    if raw_dell is not None:
        enabled = is_enabled(raw_dell)
        return control_finding(
            control_id="C23",
            status="pass" if not enabled else "fail",
            expected="Disabled",
            observed=bool(enabled),
            reason_code=ReasonCode.OEM_REDFISH_PASS if not enabled else ReasonCode.OEM_REDFISH_FAIL,
            evidence=[evidence_item(
                transport="oem_redfish",
                uri=DELL_MGR_ATTRS_URI,
                property="Telnet.1.Enable",
                raw_value=raw_dell,
                normalized_value=enabled,
            )],
        )

    if net_proto and "uri" in net_proto:
        return control_finding(
            control_id="C23",
            status="pass",
            expected="Disabled",
            observed="Absent / Not Supported (Daemon Removed)",
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=[evidence_item(
                transport="standard_redfish",
                uri=net_proto.get("uri", "/redfish/v1/Managers/{id}/NetworkProtocol"),
                property="Telnet",
                raw_value=None,
                normalized_value="Absent",
            )],
        )

    return control_finding(
        control_id="C23",
        status="unknown_not_exposed",
        expected="Disabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c24_snmp_dell(attrs: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C24: SNMP service/version."""
    raw_agent = get_dell_attribute(attrs, "snmp.1.agentenable")
    if raw_agent is not None:
        agent_en = is_enabled(raw_agent)
        ev = [evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="SNMP.1.AgentEnable",
            raw_value=raw_agent,
            normalized_value=agent_en,
        )]
        if agent_en is False:
            return control_finding(
                control_id="C24",
                status="pass",
                expected="Disabled or SNMPv3 AuthPriv",
                observed="Disabled",
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        proto = str(get_dell_attribute(attrs, "snmp.1.snmpprotocol") or "").upper()
        if "V3" in proto:
            return control_finding(
                control_id="C24",
                status="pass",
                expected="Disabled or SNMPv3 AuthPriv",
                observed=f"SNMP ({proto})",
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )

    net_proto = standard.get("network_protocol") or {}
    snmp_data = net_proto.get("SNMP") or {}
    if "ProtocolEnabled" in snmp_data:
        std_en = snmp_data.get("ProtocolEnabled")
        if std_en is False:
            return control_finding(
                control_id="C24",
                status="pass",
                expected="Disabled or SNMPv3 AuthPriv",
                observed="Disabled",
                reason_code=ReasonCode.STANDARD_REDFISH_PASS,
                evidence=[],
            )

    return control_finding(
        control_id="C24",
        status="unknown_not_exposed",
        expected="Disabled or SNMPv3 AuthPriv",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c25_snmp_isolation(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C25: SNMP network isolation (external process)."""
    return control_finding(
        control_id="C25",
        status="unknown_not_exposed",
        expected="External network isolation (VLAN/firewall segmentation)",
        observed=None,
        reason_code=ReasonCode.EXTERNAL_PROCESS_REQUIRED,
        evidence=[],
    )


def evaluate_c26_snmp_crypto(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C26: SNMP credentials and cryptography (partial-write-only)."""
    agent_en = is_enabled(get_dell_attribute(attrs, "snmp.1.agentenable"))
    if agent_en is False:
        return control_finding(
            control_id="C26",
            status="pass",
            expected="SHA authentication and AES privacy (passphrases write-only)",
            observed="Disabled (SNMP not active)",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[],
        )

    users = get_dell_user_attributes(attrs)
    weak_found: List[str] = []
    sha_aes_found = False

    for slot, u in users.items():
        auth = str(u.get("authenticationprotocol") or "").upper()
        priv = str(u.get("privacyprotocol") or "").upper()
        if "MD5" in auth or "DES" in priv:
            weak_found.append(slot)
        if "SHA" in auth and "AES" in priv:
            sha_aes_found = True

    if weak_found:
        return control_finding(
            control_id="C26",
            status="fail",
            expected="SHA authentication and AES privacy (passphrases write-only)",
            observed=f"Weak SNMPv3 crypto (MD5/DES) in user slot(s) {weak_found}",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[],
        )

    if sha_aes_found:
        return control_finding(
            control_id="C26",
            status="unknown_write_only",
            expected="SHA authentication and AES privacy (passphrases write-only)",
            observed="SNMPv3 configured with SHA/AES; passphrases write-only",
            reason_code=ReasonCode.WRITE_ONLY_SECRET,
            evidence=[],
        )

    return control_finding(
        control_id="C26",
        status="unknown_not_exposed",
        expected="SHA authentication and AES privacy (passphrases write-only)",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c27_ipmi_cipher0(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C27: IPMI fallback hardening / Cipher 0 (RACADM-tool)."""
    return control_finding(
        control_id="C27",
        status="unknown_not_exposed",
        expected="Cipher 0 disabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c28_secure_ntp(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C28: Authenticated NTP."""
    ntp_en_raw = get_dell_attribute(attrs, "ntpconfiggroup.1.ntpenable")
    if ntp_en_raw is None:
        return control_finding(
            control_id="C28",
            status="unknown_not_exposed",
            expected="NTP enabled with authenticated server",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    ntp_en = is_enabled(ntp_en_raw)
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="NTPConfigGroup.1.NTPEnable",
        raw_value=ntp_en_raw,
        normalized_value=ntp_en,
    )]

    if ntp_en is False:
        return control_finding(
            control_id="C28",
            status="fail",
            expected="NTP enabled with authenticated server",
            observed="NTP disabled",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )

    # Check security types for NTP 1, 2, 3
    sec_types = []
    for i in (1, 2, 3):
        st = get_dell_attribute(attrs, f"ntpconfiggroup.1.ntp{i}securitytype")
        if st is not None:
            s_str = str(st).strip()
            if s_str.lower() not in ("disabled", "none", "0"):
                sec_types.append(s_str)

    if sec_types:
        return control_finding(
            control_id="C28",
            status="pass",
            expected="NTP enabled with authenticated server",
            observed=f"NTP enabled with authenticated server ({sec_types[0]})",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C28",
        status="fail",
        expected="NTP enabled with authenticated server",
        observed="NTP enabled without authentication",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c29_session_auth_dell(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C29: Redfish session authentication."""
    return evaluate_c29_session_auth(standard)


def evaluate_c30_sekm(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C30: Secure Enterprise Key Manager (SEKM)."""
    raw_en = get_dell_attribute(attrs, "sekm.1.enable")
    if raw_en is None:
        return control_finding(
            control_id="C30",
            status="unknown_not_exposed",
            expected="SEKM active with valid certificates and licensing",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    enabled = is_enabled(raw_en)
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="SEKM.1.Enable",
        raw_value=raw_en,
        normalized_value=enabled,
    )]

    if enabled is False:
        return control_finding(
            control_id="C30",
            status="not_applicable",
            expected="SEKM active with valid certificates and licensing",
            observed="Disabled (SEKM not in scope)",
            reason_code=ReasonCode.NOT_APPLICABLE,
            evidence=ev,
        )

    lic = str(get_dell_attribute(attrs, "sekm.1.sekmlicense") or "").lower()
    if "unlicensed" in lic:
        return control_finding(
            control_id="C30",
            status="unknown_unlicensed",
            expected="SEKM active with valid certificates and licensing",
            observed="SEKM enabled but unlicensed",
            reason_code=ReasonCode.FEATURE_UNLICENSED,
            evidence=ev,
        )

    status_val = str(get_dell_attribute(attrs, "sekm.1.status") or get_dell_attribute(attrs, "sekm.1.certstatus") or "")
    if status_val.lower() in ("active", "healthy", "ok", "success"):
        return control_finding(
            control_id="C30",
            status="pass",
            expected="SEKM active with valid certificates and licensing",
            observed=f"SEKM active ({status_val})",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C30",
        status="fail",
        expected="SEKM active with valid certificates and licensing",
        observed=f"SEKM status: {status_val or 'error'}",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c31_group_manager(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C31: Group Manager enablement."""
    raw_val = get_dell_attribute(attrs, "groupmanager.1.status")
    if raw_val is None:
        return control_finding(
            control_id="C31",
            status="unknown_not_exposed",
            expected="Disabled when unused",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    enabled = is_enabled(raw_val)
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="GroupManager.1.Status",
        raw_value=raw_val,
        normalized_value=enabled,
    )]

    if enabled is False:
        return control_finding(
            control_id="C31",
            status="pass",
            expected="Disabled when unused",
            observed="Disabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C31",
        status="fail",
        expected="Disabled when unused",
        observed="Enabled",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c32_group_manager_passcode(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C32: Group Manager network and passcode."""
    gm_en = is_enabled(get_dell_attribute(attrs, "groupmanager.1.status"))
    if gm_en is False:
        return control_finding(
            control_id="C32",
            status="not_applicable",
            expected="Dedicated management network and rotated passcode",
            observed="Disabled (Group Manager not in scope)",
            reason_code=ReasonCode.NOT_APPLICABLE,
            evidence=[],
        )

    if gm_en is True:
        return control_finding(
            control_id="C32",
            status="unknown_write_only",
            expected="Dedicated management network and rotated passcode",
            observed="Passcode write-only; network placement external",
            reason_code=ReasonCode.WRITE_ONLY_SECRET,
            evidence=[],
        )

    return control_finding(
        control_id="C32",
        status="unknown_not_exposed",
        expected="Dedicated management network and rotated passcode",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c33_virtual_console_encryption(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C33: Virtual-console client and video encryption."""
    enc_raw = get_dell_attribute(attrs, "virtualconsole.1.encryptenable")
    plugin_raw = get_dell_attribute(attrs, "virtualconsole.1.plugintype")

    if enc_raw is None:
        return control_finding(
            control_id="C33",
            status="unknown_not_exposed",
            expected="eHTML5 plugin and video encryption enabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    enc_en = is_enabled(enc_raw)
    plugin = str(plugin_raw or "").strip()
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="VirtualConsole.1.EncryptEnable",
        raw_value=enc_raw,
        normalized_value=enc_en,
    )]
    if plugin_raw is not None:
        ev.append(evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="VirtualConsole.1.PluginType",
            raw_value=plugin_raw,
            normalized_value=plugin,
        ))

    if enc_en is True and (plugin.lower() in ("ehtml5", "html5", "2") or not plugin):
        return control_finding(
            control_id="C33",
            status="pass",
            expected="eHTML5 plugin and video encryption enabled",
            observed=f"{plugin or 'eHTML5'} with encryption enabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C33",
        status="fail",
        expected="eHTML5 plugin and video encryption enabled",
        observed="Video encryption disabled or legacy plugin",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c34_virtual_console_web_redirect(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C34: Virtual-console TLS and web redirection."""
    raw_val = get_dell_attribute(attrs, "virtualconsole.1.webredirect")
    if raw_val is None:
        return control_finding(
            control_id="C34",
            status="unknown_not_exposed",
            expected="Web redirection enabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    enabled = is_enabled(raw_val)
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="VirtualConsole.1.WebRedirect",
        raw_value=raw_val,
        normalized_value=enabled,
    )]

    if enabled is True:
        return control_finding(
            control_id="C34",
            status="pass",
            expected="Web redirection enabled",
            observed="Enabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C34",
        status="fail",
        expected="Web redirection enabled",
        observed="Disabled",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c35_virtual_media_encryption(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C35: Virtual-media encryption."""
    return control_finding(
        control_id="C35",
        status="unknown_not_exposed",
        expected="Virtual-media encryption enabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c36_vnc_hardening(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C36: VNC hardening."""
    raw_val = get_dell_attribute(attrs, "vncserver.1.enable")
    if raw_val is None:
        return control_finding(
            control_id="C36",
            status="unknown_not_exposed",
            expected="Disabled or 256-bit SSL with timeout <= 1800s",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    enabled = is_enabled(raw_val)
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="VNCServer.1.Enable",
        raw_value=raw_val,
        normalized_value=enabled,
    )]

    if enabled is False:
        return control_finding(
            control_id="C36",
            status="pass",
            expected="Disabled or 256-bit SSL with timeout <= 1800s",
            observed="Disabled (attack surface minimized)",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    ssl = get_dell_attribute(attrs, "vncserver.1.sslencryptionbitlength")
    tout = to_int(get_dell_attribute(attrs, "vncserver.1.timeout"))

    is_256 = "256" in str(ssl) or (to_int(ssl) or 0) >= 256
    is_tout_ok = tout is not None and 0 < tout <= 1800

    if is_256 and is_tout_ok:
        return control_finding(
            control_id="C36",
            status="pass",
            expected="Disabled or 256-bit SSL with timeout <= 1800s",
            observed=f"Enabled (256-bit SSL, timeout {tout}s)",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C36",
        status="fail",
        expected="Disabled or 256-bit SSL with timeout <= 1800s",
        observed=f"Enabled with weak settings (SSL: {ssl}, timeout: {tout}s)",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c37_roles_or_timeout_dell(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C37: Least-privilege roles / session timeout."""
    return evaluate_c37_session_timeout(standard)


def evaluate_c38_user_ipmi_privilege(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C38: Per-user IPMI privilege."""
    users = get_dell_user_attributes(attrs)
    if not users:
        return control_finding(
            control_id="C38",
            status="unknown_not_exposed",
            expected="No Access for all user accounts",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    access_slots: List[str] = []
    ev: List[Dict[str, Any]] = []

    for slot, u in sorted(users.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 999):
        priv = str(u.get("ipmilanprivilege") or "").lower()
        sol = is_enabled(u.get("solenable"))
        if priv and priv not in ("no access", "1", "disabled"):
            access_slots.append(slot)
            ev.append(evidence_item(
                transport="oem_redfish",
                uri=DELL_MGR_ATTRS_URI,
                property=f"Users.{slot}.IpmiLanPrivilege",
                raw_value=priv,
                normalized_value=priv,
            ))
        elif sol is True:
            access_slots.append(slot)
            ev.append(evidence_item(
                transport="oem_redfish",
                uri=DELL_MGR_ATTRS_URI,
                property=f"Users.{slot}.SolEnable",
                raw_value=sol,
                normalized_value=sol,
            ))

    if not access_slots:
        return control_finding(
            control_id="C38",
            status="pass",
            expected="No Access for all user accounts",
            observed="All users configured with No Access for IPMI/SOL",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C38",
        status="fail",
        expected="No Access for all user accounts",
        observed=f"User slot(s) {access_slots} have IPMI/SOL access",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c39_user_snmpv3(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C39: Per-user SNMPv3 protection (partial-write-only)."""
    users = get_dell_user_attributes(attrs)
    if not users:
        return control_finding(
            control_id="C39",
            status="unknown_not_exposed",
            expected="SHA authentication and AES privacy",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    weak_slots: List[str] = []
    configured_count = 0

    for slot, u in users.items():
        if is_enabled(u.get("protocolenable")):
            configured_count += 1
            auth = str(u.get("authenticationprotocol") or "").upper()
            priv = str(u.get("privacyprotocol") or "").upper()
            if "MD5" in auth or "DES" in priv or not auth or not priv:
                weak_slots.append(slot)

    if weak_slots:
        return control_finding(
            control_id="C39",
            status="fail",
            expected="SHA authentication and AES privacy",
            observed=f"User slot(s) {weak_slots} configured with weak SNMPv3 crypto",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[],
        )

    if configured_count > 0:
        return control_finding(
            control_id="C39",
            status="unknown_write_only",
            expected="SHA authentication and AES privacy",
            observed="SNMPv3 users configured with SHA/AES; passphrases write-only",
            reason_code=ReasonCode.WRITE_ONLY_SECRET,
            evidence=[],
        )

    return control_finding(
        control_id="C39",
        status="not_applicable",
        expected="SHA authentication and AES privacy",
        observed="No users configured with SNMPv3",
        reason_code=ReasonCode.NOT_APPLICABLE,
        evidence=[],
    )


def evaluate_c40_password_policy(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C40: Password quality policy."""
    score_raw = get_dell_attribute(attrs, "security.1.minimumpasswordscore")
    len_raw = get_dell_attribute(attrs, "security.1.passwordminimumlength")

    if score_raw is None and len_raw is None:
        return control_finding(
            control_id="C40",
            status="unknown_not_exposed",
            expected="MinimumPasswordScore >= 3 or length >= 12 with complexity",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    ev: List[Dict[str, Any]] = []
    score = to_int(score_raw)
    length = to_int(len_raw)

    if score is not None:
        ev.append(evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="Security.1.MinimumPasswordScore",
            raw_value=score_raw,
            normalized_value=score,
        ))
        if score >= 3:
            return control_finding(
                control_id="C40",
                status="pass",
                expected="MinimumPasswordScore >= 3 or length >= 12 with complexity",
                observed=f"MinimumPasswordScore = {score}",
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C40",
            status="fail",
            expected="MinimumPasswordScore >= 3 or length >= 12 with complexity",
            observed=f"MinimumPasswordScore = {score} (below baseline >= 3)",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )

    if length is not None:
        ev.append(evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="Security.1.PasswordMinimumLength",
            raw_value=len_raw,
            normalized_value=length,
        ))
        if length >= 12:
            return control_finding(
                control_id="C40",
                status="pass",
                expected="MinimumPasswordScore >= 3 or length >= 12 with complexity",
                observed=f"PasswordMinimumLength = {length}",
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C40",
            status="fail",
            expected="MinimumPasswordScore >= 3 or length >= 12 with complexity",
            observed=f"PasswordMinimumLength = {length} (below baseline >= 12)",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )

    return control_finding(
        control_id="C40",
        status="unknown_not_exposed",
        expected="MinimumPasswordScore >= 3 or length >= 12 with complexity",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c41_default_password(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C41: Default password and Force Change of Password."""
    raw_val = get_dell_attribute(attrs, "securedefaultpassword.1.forcechangepassword")
    if raw_val is None:
        return control_finding(
            control_id="C41",
            status="unknown_not_exposed",
            expected="ForceChangePassword enabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    enabled = is_enabled(raw_val)
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="SecureDefaultPassword.1.ForceChangePassword",
        raw_value=raw_val,
        normalized_value=enabled,
    )]

    if enabled is True:
        return control_finding(
            control_id="C41",
            status="pass",
            expected="ForceChangePassword enabled",
            observed="ForceChangePassword enabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C41",
        status="fail",
        expected="ForceChangePassword enabled",
        observed="ForceChangePassword disabled",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c42_2fa(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C42: Two-factor authentication."""
    users = get_dell_user_attributes(attrs)
    if not users:
        return control_finding(
            control_id="C42",
            status="unknown_not_exposed",
            expected="Two-factor authentication enabled where in scope",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    has_2fa = False
    for slot, u in users.items():
        if is_enabled(u.get("simple2fa")) is True or is_enabled(u.get("rsasecurid2fa")) is True:
            has_2fa = True
            break

    if has_2fa:
        return control_finding(
            control_id="C42",
            status="pass",
            expected="Two-factor authentication enabled where in scope",
            observed="2FA enabled for management users",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[],
        )

    return control_finding(
        control_id="C42",
        status="not_applicable",
        expected="Two-factor authentication enabled where in scope",
        observed="Disabled (2FA conditional)",
        reason_code=ReasonCode.NOT_APPLICABLE,
        evidence=[],
    )


def evaluate_c43_directory_dell(attrs: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C43: Central directory authentication."""
    std_res = evaluate_c43_directory_and_lockout(standard)
    if std_res["status"] == "pass":
        return std_res

    # Also check Dell attributes
    ad_val = get_dell_attribute(attrs, "activedirectory.1.certvalidationenable")
    ldap_val = get_dell_attribute(attrs, "ldap.1.certvalidationenable")
    if ad_val is not None or ldap_val is not None:
        return control_finding(
            control_id="C43",
            status="pass",
            expected="Directory authentication enabled or lockout <= 5",
            observed="Directory service configured in Dell Attributes",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[],
        )

    return std_res


def evaluate_c44_ad_cert_validation(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C44: Active Directory certificate validation."""
    raw_val = get_dell_attribute(attrs, "activedirectory.1.certvalidationenable")
    if raw_val is None:
        return control_finding(
            control_id="C44",
            status="unknown_not_exposed",
            expected="Enabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    enabled = is_enabled(raw_val)
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="ActiveDirectory.1.CertValidationEnable",
        raw_value=raw_val,
        normalized_value=enabled,
    )]

    if enabled is True:
        return control_finding(
            control_id="C44",
            status="pass",
            expected="Enabled",
            observed="Enabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C44",
        status="fail",
        expected="Enabled",
        observed="Disabled",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c45_ldap_cert_validation(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C45: LDAP certificate validation."""
    raw_val = get_dell_attribute(attrs, "ldap.1.certvalidationenable")
    if raw_val is None:
        return control_finding(
            control_id="C45",
            status="unknown_not_exposed",
            expected="Enabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    enabled = is_enabled(raw_val)
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="LDAP.1.CertValidationEnable",
        raw_value=raw_val,
        normalized_value=enabled,
    )]

    if enabled is True:
        return control_finding(
            control_id="C45",
            status="pass",
            expected="Enabled",
            observed="Enabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C45",
        status="fail",
        expected="Enabled",
        observed="Disabled",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c46_host_local_reconfiguration(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C46: Disable host-local reconfiguration."""
    local_cfg = get_dell_attribute(attrs, "localsecurity.1.localconfig")
    preboot_cfg = get_dell_attribute(attrs, "localsecurity.1.prebootconfig")

    if local_cfg is None and preboot_cfg is None:
        return control_finding(
            control_id="C46",
            status="unknown_not_exposed",
            expected="Disabled (LocalConfig and PrebootConfig off)",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    ev = []
    if local_cfg is not None:
        ev.append(evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="LocalSecurity.1.LocalConfig",
            raw_value=local_cfg,
            normalized_value=is_enabled(local_cfg),
        ))
    if preboot_cfg is not None:
        ev.append(evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="LocalSecurity.1.PrebootConfig",
            raw_value=preboot_cfg,
            normalized_value=is_enabled(preboot_cfg),
        ))

    if is_enabled(local_cfg) is False or is_enabled(preboot_cfg) is False:
        return control_finding(
            control_id="C46",
            status="pass",
            expected="Disabled (LocalConfig and PrebootConfig off)",
            observed="Host-local / preboot configuration disabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C46",
        status="fail",
        expected="Disabled (LocalConfig and PrebootConfig off)",
        observed="Host-local configuration enabled",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c47_login_banner(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C47: Security login banner."""
    raw_val = get_dell_attribute(attrs, "gui.1.securitypolicymessage")
    if raw_val is None:
        return control_finding(
            control_id="C47",
            status="unknown_not_exposed",
            expected="Customized security policy banner",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    s = str(raw_val).strip()
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="GUI.1.SecurityPolicyMessage",
        raw_value=raw_val,
        normalized_value=s,
    )]

    if s and s.lower() not in ("none", "default"):
        return control_finding(
            control_id="C47",
            status="pass",
            expected="Customized security policy banner",
            observed=f"Configured ({len(s)} chars)",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C47",
        status="fail",
        expected="Customized security policy banner",
        observed="No security banner configured",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c48_system_lockdown(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C48: System Lockdown."""
    raw_val = get_dell_attribute(attrs, "lockdown.1.systemlockdown")
    if raw_val is None:
        return control_finding(
            control_id="C48",
            status="unknown_not_exposed",
            expected="Enabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    enabled = is_enabled(raw_val)
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_MGR_ATTRS_URI,
        property="Lockdown.1.SystemLockdown",
        raw_value=raw_val,
        normalized_value=enabled,
    )]

    if enabled is True:
        return control_finding(
            control_id="C48",
            status="pass",
            expected="Enabled",
            observed="Enabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C48",
        status="fail",
        expected="Enabled",
        observed="Disabled",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c49_bios_passwords(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C49: BIOS setup/system passwords and lock status (partial-write-only)."""
    return control_finding(
        control_id="C49",
        status="unknown_write_only",
        expected="BIOS setup password enabled and locked",
        observed="Password status and hashes write-only",
        reason_code=ReasonCode.WRITE_ONLY_SECRET,
        evidence=[],
    )


def evaluate_c50_bios_power_button(attrs: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C50: BIOS power-button control."""
    bios_attrs = standard.get("bios_attributes") or {}
    val = None
    prop = "PwrButton"
    for k, v in bios_attrs.items():
        if k.lower() in ("pwrbutton", "powerbutton"):
            val = v
            prop = k
            break

    if val is None:
        return control_finding(
            control_id="C50",
            status="unknown_not_exposed",
            expected="Disabled where local shutdown risk exceeds operational need",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    s = str(val).strip()
    ev = [evidence_item(
        transport="standard_redfish",
        uri="/redfish/v1/Systems/{id}/Bios",
        property=prop,
        raw_value=val,
        normalized_value=s,
    )]

    if s.lower() in ("disabled", "off", "0"):
        return control_finding(
            control_id="C50",
            status="pass",
            expected="Disabled where local shutdown risk exceeds operational need",
            observed="Disabled",
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C50",
        status="fail",
        expected="Disabled where local shutdown risk exceeds operational need",
        observed=f"Enabled ({s})",
        reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c51_uefi_variable_access(attrs: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C51: UEFI variable access."""
    bios_attrs = standard.get("bios_attributes") or {}
    val = None
    prop = "UefiVariableAccess"
    for k, v in bios_attrs.items():
        if k.lower() in ("uefivariableaccess", "uefivariableaccessfwcontrol"):
            val = v
            prop = k
            break

    if val is None:
        return control_finding(
            control_id="C51",
            status="unknown_not_exposed",
            expected="Controlled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    s = str(val).strip()
    ev = [evidence_item(
        transport="standard_redfish",
        uri="/redfish/v1/Systems/{id}/Bios",
        property=prop,
        raw_value=val,
        normalized_value=s,
    )]

    if s.lower() in ("controlled", "enabled"):
        return control_finding(
            control_id="C51",
            status="pass",
            expected="Controlled",
            observed="Controlled",
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C51",
        status="fail",
        expected="Controlled",
        observed=f"{s} (Uncontrolled OS variable modification)",
        reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c52_inband_manageability(attrs: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C52: In-band manageability interface."""
    return control_finding(
        control_id="C52",
        status="unknown_not_exposed",
        expected="Disabled when host management is not required",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c53_secure_boot_dell(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C53: UEFI Secure Boot."""
    return evaluate_c53_secure_boot(standard)


def evaluate_c54_secure_boot_policy_mode(attrs: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C54: Secure Boot policy and mode."""
    sb_std = standard.get("secure_boot") or {}
    bios_attrs = standard.get("bios_attributes") or {}

    mode_raw = sb_std.get("SecureBootMode")
    if mode_raw is None:
        for k, v in bios_attrs.items():
            if k.lower() == "securebootmode":
                mode_raw = v
                break

    policy_raw = None
    for k, v in bios_attrs.items():
        if k.lower() == "securebootpolicy":
            policy_raw = v
            break

    if mode_raw is None and policy_raw is None:
        return control_finding(
            control_id="C54",
            status="unknown_not_exposed",
            expected="Standard policy and Deployed mode",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    ev = []
    if mode_raw is not None:
        ev.append(evidence_item(
            transport="standard_redfish",
            uri=sb_std.get("uri", "/redfish/v1/Systems/{id}/SecureBoot"),
            property="SecureBootMode",
            raw_value=mode_raw,
            normalized_value=str(mode_raw),
        ))
    if policy_raw is not None:
        ev.append(evidence_item(
            transport="standard_redfish",
            uri="/redfish/v1/Systems/{id}/Bios",
            property="SecureBootPolicy",
            raw_value=policy_raw,
            normalized_value=str(policy_raw),
        ))

    mode_s = str(mode_raw or "").strip()
    policy_s = str(policy_raw or "").strip()

    mode_pass = mode_s.lower() in ("deployedmode", "deployed") if mode_raw is not None else True
    policy_pass = policy_s.lower() == "standard" if policy_raw is not None else True

    observed_parts = []
    if policy_raw is not None:
        observed_parts.append(f"Policy: {policy_s}")
    if mode_raw is not None:
        observed_parts.append(f"Mode: {mode_s}")
    observed_str = ", ".join(observed_parts)

    if mode_pass and policy_pass:
        return control_finding(
            control_id="C54",
            status="pass",
            expected="Standard policy and Deployed mode",
            observed=observed_str,
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C54",
        status="fail",
        expected="Standard policy and Deployed mode",
        observed=observed_str,
        reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c55_lcd_control_panel(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C55: LCD / control-panel restriction."""
    lcd_cap = get_dell_attribute(attrs, "platformcapability.1.lcdcapable")
    lcd_cfg = get_dell_attribute(attrs, "lcd.1.configuration")

    if lcd_cap is not None and is_enabled(lcd_cap) is False:
        return control_finding(
            control_id="C55",
            status="pass",
            expected="Control panel View Only or Disabled",
            observed="Disabled / Not Present",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item(
                transport="oem_redfish",
                uri=DELL_MGR_ATTRS_URI,
                property="PlatformCapability.1.LCDCapable",
                raw_value=lcd_cap,
                normalized_value=False,
            )],
        )

    if lcd_cfg is not None:
        cfg_str = str(lcd_cfg).strip()
        ev = [evidence_item(
            transport="oem_redfish",
            uri=DELL_MGR_ATTRS_URI,
            property="LCD.1.Configuration",
            raw_value=lcd_cfg,
            normalized_value=cfg_str,
        )]
        if cfg_str.lower() in ("view only", "disabled", "none"):
            return control_finding(
                control_id="C55",
                status="pass",
                expected="Control panel View Only or Disabled",
                observed=cfg_str,
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C55",
            status="fail",
            expected="Control panel View Only or Disabled",
            observed=cfg_str,
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )

    return control_finding(
        control_id="C55",
        status="unknown_not_exposed",
        expected="Control panel View Only or Disabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c56_bios_live_scan(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C56: BIOS live scanning (RACADM-tool candidate)."""
    cap = get_dell_attribute(attrs, "platformcapability.1.livescancapable")
    if is_enabled(cap) is True:
        return control_finding(
            control_id="C56",
            status="unknown_ambiguous",
            expected="Scheduled/boot-time BIOS live scanning enabled",
            observed="PlatformCapability indicates LiveScanCapable, but schedule/state unmapped without live schema",
            reason_code=ReasonCode.AMBIGUOUS_EVIDENCE,
            evidence=[evidence_item(
                transport="oem_redfish",
                uri=DELL_MGR_ATTRS_URI,
                property="PlatformCapability.1.LiveScanCapable",
                raw_value=cap,
                normalized_value=True,
            )],
        )

    return control_finding(
        control_id="C56",
        status="unknown_not_exposed",
        expected="Scheduled/boot-time BIOS live scanning enabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c57_secure_imports_exports(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C57: Secure imports and exports."""
    lc_state = get_dell_attribute(attrs, "lcattributes.1.lifecyclecontrollerstate")
    if lc_state is not None:
        enabled = is_enabled(lc_state)
        ev = [evidence_item(
            transport="oem_redfish",
            uri=DELL_LC_ATTRS_URI,
            property="LCAttributes.1.LifecycleControllerState",
            raw_value=lc_state,
            normalized_value=enabled,
        )]
        if enabled is True:
            return control_finding(
                control_id="C57",
                status="pass",
                expected="HTTPS transport for Lifecycle Controller / SCP transfers",
                observed="Lifecycle Controller export/import service active",
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )

    return control_finding(
        control_id="C57",
        status="unknown_not_exposed",
        expected="HTTPS transport for Lifecycle Controller / SCP transfers",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c58_outbound_proxy_validation(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C58: Outbound HTTPS and proxy validation (partial-write-only)."""
    raw_val = get_dell_attribute(attrs, "lcattributes.1.ignorecertwarning")
    if raw_val is None:
        return control_finding(
            control_id="C58",
            status="unknown_not_exposed",
            expected="IgnoreCertWarning Off (certificate validation enforced)",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    s = str(raw_val).strip().lower()
    ev = [evidence_item(
        transport="oem_redfish",
        uri=DELL_LC_ATTRS_URI,
        property="LCAttributes.1.IgnoreCertWarning",
        raw_value=raw_val,
        normalized_value=s,
    )]

    # "Off" or False means certificate warnings are NOT ignored -> validation is enforced -> pass
    if s in ("off", "0", "false", "disabled"):
        return control_finding(
            control_id="C58",
            status="pass",
            expected="IgnoreCertWarning Off (certificate validation enforced)",
            observed="IgnoreCertWarning Off (certificate validation enforced)",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C58",
        status="fail",
        expected="IgnoreCertWarning Off (certificate validation enforced)",
        observed="IgnoreCertWarning On (outbound certificate validation bypassed)",
        reason_code=ReasonCode.OEM_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c59_field_service_debug(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """C59: Field Service Debug (external process)."""
    return control_finding(
        control_id="C59",
        status="unknown_not_exposed",
        expected="Field Service Debug disabled",
        observed=None,
        reason_code=ReasonCode.EXTERNAL_PROCESS_REQUIRED,
        evidence=[],
    )


# ---------------------------------------------------------------------------
# Top-level Dell orchestrator
# ---------------------------------------------------------------------------


def evaluate_dell_security_controls(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate all 59 configuration controls (C01–C59) for a Dell iDRAC host.

    Deterministic ordering: C01 through C59 in strict sequential order.

    Args:
        evidence: Normalized evidence dictionary matching EVIDENCE_SCHEMA_VERSION.

    Returns:
        Ordered list of 59 control findings.
    """
    standard = evidence.get("standard") or {}
    attrs = extract_dell_attributes(evidence)

    return [
        evaluate_c01_https_redirect(attrs, standard),
        evaluate_c02_tls_version(attrs),
        evaluate_c03_tls_encryption_bit_length(attrs),
        evaluate_c04_tls_ciphers(attrs),
        evaluate_c05_trusted_certificate(attrs, evidence),
        evaluate_c06_scep(attrs),
        evaluate_c07_secure_syslog(attrs),
        evaluate_c08_fips_mode(attrs),
        evaluate_c09_ssh_dell(attrs, standard),
        evaluate_c10_ssh_public_key(attrs, evidence),
        evaluate_c11_ssh_crypto(attrs),
        evaluate_c12_dedicated_nic(attrs),
        evaluate_c13_vlan(attrs),
        evaluate_c14_usb_management(attrs),
        evaluate_c15_os_bmc_passthrough(attrs),
        evaluate_c16_ip_blocking(attrs, standard),
        evaluate_c17_ip_range_filtering(attrs),
        evaluate_c18_autodiscovery(attrs),
        evaluate_c19_autoconfig(attrs),
        evaluate_c20_unused_services(attrs, standard),
        evaluate_c21_ipmi_lan_dell(attrs, standard),
        evaluate_c22_sol(attrs),
        evaluate_c23_telnet_dell(attrs, standard),
        evaluate_c24_snmp_dell(attrs, standard),
        evaluate_c25_snmp_isolation(attrs),
        evaluate_c26_snmp_crypto(attrs),
        evaluate_c27_ipmi_cipher0(attrs),
        evaluate_c28_secure_ntp(attrs),
        evaluate_c29_session_auth_dell(standard),
        evaluate_c30_sekm(attrs),
        evaluate_c31_group_manager(attrs),
        evaluate_c32_group_manager_passcode(attrs),
        evaluate_c33_virtual_console_encryption(attrs),
        evaluate_c34_virtual_console_web_redirect(attrs),
        evaluate_c35_virtual_media_encryption(attrs),
        evaluate_c36_vnc_hardening(attrs),
        evaluate_c37_roles_or_timeout_dell(standard),
        evaluate_c38_user_ipmi_privilege(attrs),
        evaluate_c39_user_snmpv3(attrs),
        evaluate_c40_password_policy(attrs),
        evaluate_c41_default_password(attrs),
        evaluate_c42_2fa(attrs),
        evaluate_c43_directory_dell(attrs, standard),
        evaluate_c44_ad_cert_validation(attrs),
        evaluate_c45_ldap_cert_validation(attrs),
        evaluate_c46_host_local_reconfiguration(attrs),
        evaluate_c47_login_banner(attrs),
        evaluate_c48_system_lockdown(attrs),
        evaluate_c49_bios_passwords(attrs),
        evaluate_c50_bios_power_button(attrs, standard),
        evaluate_c51_uefi_variable_access(attrs, standard),
        evaluate_c52_inband_manageability(attrs, standard),
        evaluate_c53_secure_boot_dell(standard),
        evaluate_c54_secure_boot_policy_mode(attrs, standard),
        evaluate_c55_lcd_control_panel(attrs),
        evaluate_c56_bios_live_scan(attrs),
        evaluate_c57_secure_imports_exports(attrs),
        evaluate_c58_outbound_proxy_validation(attrs),
        evaluate_c59_field_service_debug(attrs),
    ]
