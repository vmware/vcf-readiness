"""Evaluation engine for HPE iLO BMC security posture controls.

Pure evaluation functions translating normalized HPE OEM evidence
and standard Redfish evidence into ordered, validated control findings (C01–C59).

Adheres to:
- Hardware Security Scope Freeze (Bead 0)
- Neutral Security Contract Schema (Bead 1)
- HPE iLO Security Service & Technology Brief research (Beads 6 & 7)
- Dell-specific controls (C18, C19, C30–C32, C48, C55–C59) held as not_applicable.
- Non-GET controls (C10, C25, C26, C27, C35, C49) held as unknown/unknown_write_only.
"""

from typing import Any, Dict, List, Optional

from vcf_hci.security.contract import (
    ReasonCode,
    control_finding,
    evidence_item,
)
from vcf_hci.security.evaluation import (
    evaluate_c09_ssh,
    evaluate_c21_ipmi_lan,
    evaluate_c23_telnet,
    evaluate_c24_snmp,
    evaluate_c29_session_auth,
    evaluate_c37_session_timeout,
    evaluate_c43_directory_and_lockout,
    evaluate_c53_secure_boot,
)

HPE_SEC_URI = "/redfish/v1/Managers/1/SecurityService"
HPE_DASH_URI = "/redfish/v1/Managers/1/SecurityService/SecurityDashboard"
HPE_MGR_URI = "/redfish/v1/Managers/1"
HPE_NET_URI = "/redfish/v1/Managers/1/NetworkProtocol"
HPE_ACCT_URI = "/redfish/v1/AccountService"


def _find_hpe_param(params: List[Dict[str, Any]], target: str) -> Optional[Dict[str, Any]]:
    """Look up an HPE security parameter by ID or name substring."""
    target_lower = target.lower()
    for p in params:
        if str(p.get("id")) == target:
            return p
        if target_lower in str(p.get("name", "")).lower():
            return p
    return None


def evaluate_c01_https_hpe(oem: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C01: HTTPS enforcement and web server security."""
    net_proto = standard.get("network_protocol") or {}
    http = net_proto.get("HTTP") or {}
    https = net_proto.get("HTTPS") or {}
    mgr = oem.get("hpe_manager") or {}

    http_enabled = http.get("ProtocolEnabled")
    https_enabled = https.get("ProtocolEnabled")
    web_gui = mgr.get("WebGuiEnabled")

    ev: List[Dict[str, Any]] = []
    if https_enabled is not None:
        ev.append(evidence_item(
            transport="standard_redfish",
            uri=HPE_NET_URI,
            property="HTTPS.ProtocolEnabled",
            raw_value=https_enabled,
            normalized_value=bool(https_enabled),
        ))
    if http_enabled is not None:
        ev.append(evidence_item(
            transport="standard_redfish",
            uri=HPE_NET_URI,
            property="HTTP.ProtocolEnabled",
            raw_value=http_enabled,
            normalized_value=bool(http_enabled),
        ))

    if https_enabled is True and http_enabled is False:
        return control_finding(
            control_id="C01",
            status="pass",
            expected="HTTPS enabled and HTTP disabled",
            observed=True,
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )
    if http_enabled is True:
        return control_finding(
            control_id="C01",
            status="fail",
            expected="HTTPS enabled and HTTP disabled",
            observed=False,
            reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
            evidence=ev,
        )
    if web_gui is True:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_MGR_URI,
            property="WebGuiEnabled",
            raw_value=web_gui,
            normalized_value=True,
        ))
        return control_finding(
            control_id="C01",
            status="pass",
            expected="HTTPS enabled and WebGui secured",
            observed=True,
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )
    return control_finding(
        control_id="C01",
        status="unknown_not_exposed",
        expected="HTTPS enabled and HTTP disabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c02_tls_version_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C02: TLS Protocol Version (Min TLS 1.2)."""
    sec = oem.get("security_service") or {}
    tls_ver = sec.get("TLSVersion") or {}
    weak_ciphers = sec.get("DisableWeakCiphers")

    ev: List[Dict[str, Any]] = []
    if weak_ciphers is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_SEC_URI,
            property="DisableWeakCiphers",
            raw_value=weak_ciphers,
            normalized_value=bool(weak_ciphers),
        ))
    if tls_ver:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_SEC_URI,
            property="TLSVersion",
            raw_value=tls_ver,
            normalized_value=str(tls_ver),
        ))

    if weak_ciphers is True:
        return control_finding(
            control_id="C02",
            status="pass",
            expected="TLS 1.2 or higher (weak ciphers disabled)",
            observed="TLS 1.2+",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )

    t10 = str(tls_ver.get("TLS1_0", "")).lower() == "enabled"
    t11 = str(tls_ver.get("TLS1_1", "")).lower() == "enabled"
    t12 = str(tls_ver.get("TLS1_2", "")).lower() == "enabled"
    t13 = str(tls_ver.get("TLS1_3", "")).lower() == "enabled"

    if (t10 or t11) and weak_ciphers is False:
        return control_finding(
            control_id="C02",
            status="fail",
            expected="TLS 1.2 or higher",
            observed="TLS 1.0/1.1 enabled with weak ciphers permitted",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    if (t12 or t13) and not (t10 or t11):
        return control_finding(
            control_id="C02",
            status="pass",
            expected="TLS 1.2 or higher",
            observed="TLS 1.2/1.3 enabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )
    if weak_ciphers is not None:
        return control_finding(
            control_id="C02",
            status="fail" if weak_ciphers is False else "pass",
            expected="TLS 1.2 or higher",
            observed=f"DisableWeakCiphers={weak_ciphers}",
            reason_code=ReasonCode.OEM_REDFISH_FAIL if weak_ciphers is False else ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )
    return control_finding(
        control_id="C02",
        status="unknown_not_exposed",
        expected="TLS 1.2 or higher",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c03_tls_key_exchange_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C03: TLS Encryption Bit Length & Modern Key Exchange."""
    sec = oem.get("security_service") or {}
    cur_cipher = sec.get("CurrentCipher")
    sec_state = sec.get("SecurityState")

    ev: List[Dict[str, Any]] = []
    if cur_cipher:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_SEC_URI,
            property="CurrentCipher",
            raw_value=cur_cipher,
            normalized_value=str(cur_cipher),
        ))

    if cur_cipher and any(s in str(cur_cipher).upper() for s in ["256", "GCM", "CHACHA20"]):
        return control_finding(
            control_id="C03",
            status="pass",
            expected="256-bit or GCM modern cipher",
            observed=str(cur_cipher),
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )
    if sec_state in ("HighSecurity", "FIPS", "CNSA"):
        return control_finding(
            control_id="C03",
            status="pass",
            expected="High Security cryptographic ciphers",
            observed=str(sec_state),
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )
    return control_finding(
        control_id="C03",
        status="unknown_not_exposed",
        expected="256-bit or GCM modern cipher",
        observed=str(cur_cipher) if cur_cipher else None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c04_weak_ciphers_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C04: Weak Ciphers Disablement (G-HPE-WEAKCIPHER)."""
    sec = oem.get("security_service") or {}
    disable_weak = sec.get("DisableWeakCiphers")
    sec_state = sec.get("SecurityState")

    ev: List[Dict[str, Any]] = []
    if disable_weak is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_SEC_URI,
            property="DisableWeakCiphers",
            raw_value=disable_weak,
            normalized_value=bool(disable_weak),
        ))

    if disable_weak is True or sec_state in ("FIPS", "CNSA"):
        return control_finding(
            control_id="C04",
            status="pass",
            expected="True (Weak ciphers disabled)",
            observed=True,
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )
    if disable_weak is False:
        return control_finding(
            control_id="C04",
            status="fail",
            expected="True (Weak ciphers disabled)",
            observed=False,
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C04",
        status="unknown_not_exposed",
        expected="True (Weak ciphers disabled)",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c05_certificate_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C05: BMC HTTPS Certificate Validation."""
    params = oem.get("security_parameters") or []
    param = _find_hpe_param(params, "Default SSL Certificate")
    if not param:
        param = _find_hpe_param(params, "9")

    ev: List[Dict[str, Any]] = []
    if param:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=f"{HPE_DASH_URI}/SecurityParams/{param.get('id')}",
            property="SecurityStatus",
            raw_value=param.get("security_status"),
            normalized_value=str(param.get("security_status")),
        ))
        if str(param.get("security_status")).lower() == "risk" or str(param.get("state")).lower() == "true":
            return control_finding(
                control_id="C05",
                status="fail",
                expected="CA-signed SSL certificate",
                observed="Default SSL certificate in use",
                reason_code=ReasonCode.OEM_REDFISH_FAIL,
                evidence=ev,
            )
        if str(param.get("security_status")).lower() == "ok":
            return control_finding(
                control_id="C05",
                status="pass",
                expected="CA-signed SSL certificate",
                observed="Custom CA certificate installed",
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )

    return control_finding(
        control_id="C05",
        status="unknown_not_exposed",
        expected="CA-signed SSL certificate",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c06_scep_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C06: Automatic Certificate Enrollment / SCEP."""
    ace = oem.get("automatic_certificate_enrollment") or {}
    settings = ace.get("AutomaticCertificateEnrollmentSettings")

    ev: List[Dict[str, Any]] = []
    if settings is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=f"{HPE_SEC_URI}/AutomaticCertificateEnrollment",
            property="AutomaticCertificateEnrollmentSettings",
            raw_value=settings,
            normalized_value=str(settings),
        ))
        return control_finding(
            control_id="C06",
            status="pass",
            expected="Configured certificate enrollment",
            observed=str(settings),
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )
    return control_finding(
        control_id="C06",
        status="unknown_not_exposed",
        expected="Configured certificate enrollment",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c07_secure_syslog_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C07: Remote Syslog / Audit Logging."""
    net = oem.get("hpe_network_protocol") or {}
    remote_syslog = net.get("RemoteSyslogEnabled")

    ev: List[Dict[str, Any]] = []
    if remote_syslog is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_NET_URI,
            property="RemoteSyslogEnabled",
            raw_value=remote_syslog,
            normalized_value=bool(remote_syslog),
        ))
        if remote_syslog is True:
            return control_finding(
                control_id="C07",
                status="pass",
                expected="Remote Syslog enabled",
                observed=True,
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C07",
            status="fail",
            expected="Remote Syslog enabled",
            observed=False,
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C07",
        status="unknown_not_exposed",
        expected="Remote Syslog enabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c08_security_state_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C08: iLO SecurityState (G-HPE-SECSTATE corroboration)."""
    sec = oem.get("security_service") or {}
    state = sec.get("SecurityState")

    ev: List[Dict[str, Any]] = []
    if state is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_SEC_URI,
            property="SecurityState",
            raw_value=state,
            normalized_value=str(state),
        ))
        if state in ("Production", "HighSecurity", "FIPS", "CNSA"):
            return control_finding(
                control_id="C08",
                status="pass",
                expected="Production or HighSecurity",
                observed=str(state),
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C08",
            status="fail",
            expected="Production or HighSecurity",
            observed=str(state),
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C08",
        status="unknown_not_exposed",
        expected="Production or HighSecurity",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c10_ssh_keys_hpe() -> Dict[str, Any]:
    """C10: SSH Public Keys / Key-Based Authentication."""
    return control_finding(
        control_id="C10",
        status="unknown_write_only",
        expected="SSH public keys configured",
        observed=None,
        reason_code=ReasonCode.WRITE_ONLY_SECRET,
        evidence=[],
    )


def evaluate_c11_ssh_crypto_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C11: SSH Hardened Cryptography."""
    sec = oem.get("security_service") or {}
    weak_ciphers = sec.get("DisableWeakCiphers")
    state = sec.get("SecurityState")

    ev: List[Dict[str, Any]] = []
    if weak_ciphers is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_SEC_URI,
            property="DisableWeakCiphers",
            raw_value=weak_ciphers,
            normalized_value=bool(weak_ciphers),
        ))

    if weak_ciphers is True or state in ("HighSecurity", "FIPS", "CNSA"):
        return control_finding(
            control_id="C11",
            status="pass",
            expected="Hardened SSH ciphers (weak ciphers disabled)",
            observed="Hardened ciphers active",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )
    if weak_ciphers is False:
        return control_finding(
            control_id="C11",
            status="fail",
            expected="Hardened SSH ciphers",
            observed="Weak ciphers permitted",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C11",
        status="unknown_not_exposed",
        expected="Hardened SSH ciphers",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c12_dedicated_nic_hpe(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C12: Dedicated Management NIC."""
    return control_finding(
        control_id="C12",
        status="unknown_not_exposed",
        expected="Dedicated physical management port",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c13_vlan_hpe(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C13: Management VLAN Isolation."""
    return control_finding(
        control_id="C13",
        status="unknown_not_exposed",
        expected="Dedicated management VLAN configured",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c14_service_port_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C14: iLO Service Port / USB Host Hardening (G-HPE-SVCPORT)."""
    mgr = oem.get("hpe_manager") or {}
    port = mgr.get("iLOServicePort") or {}

    ev: List[Dict[str, Any]] = []
    if port:
        usb_eth = port.get("USBEthernetAdaptersEnabled")
        usb_flash = port.get("USBFlashDriveEnabled")
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_MGR_URI,
            property="iLOServicePort",
            raw_value=port,
            normalized_value=str(port),
        ))
        if usb_eth is False and usb_flash is False:
            return control_finding(
                control_id="C14",
                status="pass",
                expected="Unauthenticated USB/Ethernet adapters disabled",
                observed="Disabled",
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        if usb_eth is True:
            return control_finding(
                control_id="C14",
                status="fail",
                expected="Unauthenticated USB/Ethernet adapters disabled",
                observed="USBEthernetAdaptersEnabled=True",
                reason_code=ReasonCode.OEM_REDFISH_FAIL,
                evidence=ev,
            )
    return control_finding(
        control_id="C14",
        status="unknown_not_exposed",
        expected="Unauthenticated USB/Ethernet adapters disabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c15_host_auth_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C15: Require Host Authentication / In-band CHIF (G-HPE-HOSTAUTH)."""
    mgr = oem.get("hpe_manager") or {}
    sec = oem.get("security_service") or {}
    req_auth = mgr.get("RequireHostAuthentication")
    if req_auth is None:
        req_auth = sec.get("RequireHostAuthentication")

    ev: List[Dict[str, Any]] = []
    if req_auth is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_MGR_URI,
            property="RequireHostAuthentication",
            raw_value=req_auth,
            normalized_value=bool(req_auth),
        ))
        if req_auth is True:
            return control_finding(
                control_id="C15",
                status="pass",
                expected="RequireHostAuthentication=True",
                observed=True,
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C15",
            status="fail",
            expected="RequireHostAuthentication=True",
            observed=False,
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )

    params = oem.get("security_parameters") or []
    param = _find_hpe_param(params, "Require Host Authentication")
    if param:
        status = param.get("security_status")
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=f"{HPE_DASH_URI}/SecurityParams/{param.get('id')}",
            property="SecurityStatus",
            raw_value=status,
            normalized_value=str(status),
        ))
        if str(status).lower() == "ok":
            return control_finding(
                control_id="C15",
                status="pass",
                expected="RequireHostAuthentication=True",
                observed=True,
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C15",
            status="fail",
            expected="RequireHostAuthentication=True",
            observed=False,
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )

    return control_finding(
        control_id="C15",
        status="unknown_not_exposed",
        expected="RequireHostAuthentication=True",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c16_lockout_hpe(oem: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C16: Account Lockout & Login Failure Threshold."""
    acct_std = standard.get("account_service") or {}
    acct_oem = oem.get("hpe_account_service") or {}

    lockout_thresh = acct_std.get("AccountLockoutThreshold")
    failures_delay = acct_oem.get("AuthFailuresBeforeDelay")
    delay_secs = acct_oem.get("AuthFailureDelayTimeSeconds")

    ev: List[Dict[str, Any]] = []
    if lockout_thresh is not None:
        ev.append(evidence_item(
            transport="standard_redfish",
            uri=HPE_ACCT_URI,
            property="AccountLockoutThreshold",
            raw_value=lockout_thresh,
            normalized_value=int(lockout_thresh),
        ))
    if failures_delay is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_ACCT_URI,
            property="AuthFailuresBeforeDelay",
            raw_value=failures_delay,
            normalized_value=int(failures_delay),
        ))

    if (lockout_thresh is not None and 0 < lockout_thresh <= 5) or (failures_delay is not None and 0 < failures_delay <= 5):
        return control_finding(
            control_id="C16",
            status="pass",
            expected="Lockout threshold at most 5 attempts",
            observed=f"Threshold={lockout_thresh or failures_delay}, DelaySecs={delay_secs}",
            reason_code=ReasonCode.OEM_REDFISH_PASS if failures_delay is not None else ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )
    if lockout_thresh == 0:
        return control_finding(
            control_id="C16",
            status="fail",
            expected="Lockout threshold at most 5 attempts",
            observed="Lockout disabled (0)",
            reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C16",
        status="unknown_not_exposed",
        expected="Lockout threshold at most 5 attempts",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c17_acl_hpe() -> Dict[str, Any]:
    """C17: Management Interface Access Filtering / ACLs."""
    return control_finding(
        control_id="C17",
        status="unknown_not_exposed",
        expected="IP access filtering enabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c18_autodiscovery_hpe() -> Dict[str, Any]:
    """C18: Dell Autodiscovery (Dell-specific)."""
    return control_finding(
        control_id="C18",
        status="not_applicable",
        expected="Dell autodiscovery disabled",
        observed=None,
        reason_code=ReasonCode.NOT_APPLICABLE,
        evidence=[],
    )


def evaluate_c19_autoconfig_hpe() -> Dict[str, Any]:
    """C19: Dell Autoconfig (Dell-specific)."""
    return control_finding(
        control_id="C19",
        status="not_applicable",
        expected="Dell autoconfig disabled",
        observed=None,
        reason_code=ReasonCode.NOT_APPLICABLE,
        evidence=[],
    )


def evaluate_c20_unused_services_hpe(oem: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C20: Unused Management Services Disablement."""
    net_proto = standard.get("network_protocol") or {}
    telnet = (net_proto.get("Telnet") or {}).get("ProtocolEnabled")
    http = (net_proto.get("HTTP") or {}).get("ProtocolEnabled")

    ev: List[Dict[str, Any]] = []
    if telnet is not None:
        ev.append(evidence_item(
            transport="standard_redfish",
            uri=HPE_NET_URI,
            property="Telnet.ProtocolEnabled",
            raw_value=telnet,
            normalized_value=bool(telnet),
        ))

    if telnet is False and http is False:
        return control_finding(
            control_id="C20",
            status="pass",
            expected="Insecure services (Telnet/HTTP) disabled",
            observed=True,
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )
    if telnet is True or http is True:
        return control_finding(
            control_id="C20",
            status="fail",
            expected="Insecure services (Telnet/HTTP) disabled",
            observed=False,
            reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C20",
        status="unknown_not_exposed",
        expected="Insecure services disabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c21_ipmi_lan_hpe(oem: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C21: IPMI-over-LAN Disablement."""
    params = oem.get("security_parameters") or []
    param = _find_hpe_param(params, "IPMI/DCMI Over LAN")
    if not param:
        param = _find_hpe_param(params, "1")

    ev: List[Dict[str, Any]] = []
    if param:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=f"{HPE_DASH_URI}/SecurityParams/{param.get('id')}",
            property="State",
            raw_value=param.get("state"),
            normalized_value=str(param.get("state")),
        ))
        if str(param.get("state")).lower() == "enabled" or str(param.get("security_status")).lower() == "risk":
            return control_finding(
                control_id="C21",
                status="fail",
                expected="Disabled",
                observed="Enabled",
                reason_code=ReasonCode.OEM_REDFISH_FAIL,
                evidence=ev,
            )
        if str(param.get("state")).lower() == "disabled":
            return control_finding(
                control_id="C21",
                status="pass",
                expected="Disabled",
                observed="Disabled",
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )

    return evaluate_c21_ipmi_lan(standard)


def evaluate_c22_system_lockdown_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C22: Server Configuration Lock / System Lockdown."""
    dash = oem.get("security_dashboard") or {}
    lock_status = dash.get("ServerConfigurationLockStatus")

    ev: List[Dict[str, Any]] = []
    if lock_status is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_DASH_URI,
            property="ServerConfigurationLockStatus",
            raw_value=lock_status,
            normalized_value=str(lock_status),
        ))
        if str(lock_status).lower() == "enabled":
            return control_finding(
                control_id="C22",
                status="pass",
                expected="ServerConfigurationLockStatus=Enabled",
                observed="Enabled",
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C22",
            status="fail",
            expected="ServerConfigurationLockStatus=Enabled",
            observed=str(lock_status),
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C22",
        status="unknown_not_exposed",
        expected="ServerConfigurationLockStatus=Enabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c24_snmp_hpe(oem: Dict[str, Any], standard: Dict[str, Any]) -> Dict[str, Any]:
    """C24: SNMP Protocol & SNMPv1 Disablement."""
    params = oem.get("security_parameters") or []
    param = _find_hpe_param(params, "SNMPv1")
    if not param:
        param = _find_hpe_param(params, "10")

    ev: List[Dict[str, Any]] = []
    if param:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=f"{HPE_DASH_URI}/SecurityParams/{param.get('id')}",
            property="State",
            raw_value=param.get("state"),
            normalized_value=str(param.get("state")),
        ))
        if str(param.get("state")).lower() == "enabled" or str(param.get("security_status")).lower() == "risk":
            return control_finding(
                control_id="C24",
                status="fail",
                expected="SNMPv1 disabled (SNMPv3 or disabled)",
                observed="SNMPv1 Enabled",
                reason_code=ReasonCode.OEM_REDFISH_FAIL,
                evidence=ev,
            )
        if str(param.get("state")).lower() == "disabled":
            return control_finding(
                control_id="C24",
                status="pass",
                expected="SNMPv1 disabled",
                observed="SNMPv1 Disabled",
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )

    return evaluate_c24_snmp(standard)


def evaluate_c25_snmp_isolation_hpe() -> Dict[str, Any]:
    """C25: SNMP Network Isolation (External Process)."""
    return control_finding(
        control_id="C25",
        status="unknown_not_exposed",
        expected="SNMP network isolation verified",
        observed=None,
        reason_code=ReasonCode.EXTERNAL_PROCESS_REQUIRED,
        evidence=[],
    )


def evaluate_c26_snmp_crypto_hpe() -> Dict[str, Any]:
    """C26: SNMPv3 Passphrase / Encryption (Write-Only Secret)."""
    return control_finding(
        control_id="C26",
        status="unknown_write_only",
        expected="SNMPv3 authentication and privacy credentials",
        observed=None,
        reason_code=ReasonCode.WRITE_ONLY_SECRET,
        evidence=[],
    )


def evaluate_c27_cipher0_hpe() -> Dict[str, Any]:
    """C27: IPMI Cipher 0 Disablement (External Process)."""
    return control_finding(
        control_id="C27",
        status="unknown_not_exposed",
        expected="IPMI cipher suite 0 disabled",
        observed=None,
        reason_code=ReasonCode.EXTERNAL_PROCESS_REQUIRED,
        evidence=[],
    )


def evaluate_c28_secure_ntp_hpe(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C28: NTP Time Synchronization."""
    net_proto = standard.get("network_protocol") or {}
    ntp = net_proto.get("NTP") or {}
    enabled = ntp.get("ProtocolEnabled")

    ev: List[Dict[str, Any]] = []
    if enabled is not None:
        ev.append(evidence_item(
            transport="standard_redfish",
            uri=HPE_NET_URI,
            property="NTP.ProtocolEnabled",
            raw_value=enabled,
            normalized_value=bool(enabled),
        ))
        if enabled is True:
            return control_finding(
                control_id="C28",
                status="pass",
                expected="NTP enabled and synchronized",
                observed=True,
                reason_code=ReasonCode.STANDARD_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C28",
            status="fail",
            expected="NTP enabled and synchronized",
            observed=False,
            reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C28",
        status="unknown_not_exposed",
        expected="NTP enabled and synchronized",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c30_sekm_hpe() -> Dict[str, Any]:
    """C30: Dell SEKM Key Management (Dell-specific)."""
    return control_finding(
        control_id="C30",
        status="not_applicable",
        expected="Dell SEKM configured",
        observed=None,
        reason_code=ReasonCode.NOT_APPLICABLE,
        evidence=[],
    )


def evaluate_c31_group_manager_hpe() -> Dict[str, Any]:
    """C31: Dell Group Manager (Dell-specific)."""
    return control_finding(
        control_id="C31",
        status="not_applicable",
        expected="Dell Group Manager configured",
        observed=None,
        reason_code=ReasonCode.NOT_APPLICABLE,
        evidence=[],
    )


def evaluate_c32_group_manager_passcode_hpe() -> Dict[str, Any]:
    """C32: Dell Group Manager Passcode (Dell-specific)."""
    return control_finding(
        control_id="C32",
        status="not_applicable",
        expected="Dell Group Manager passcode configured",
        observed=None,
        reason_code=ReasonCode.NOT_APPLICABLE,
        evidence=[],
    )


def evaluate_c33_kvm_encryption_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C33: Virtual Console / KVM Encryption."""
    sec = oem.get("security_service") or {}
    weak_ciphers = sec.get("DisableWeakCiphers")
    state = sec.get("SecurityState")

    ev: List[Dict[str, Any]] = []
    if weak_ciphers is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_SEC_URI,
            property="DisableWeakCiphers",
            raw_value=weak_ciphers,
            normalized_value=bool(weak_ciphers),
        ))

    if weak_ciphers is True or state in ("HighSecurity", "FIPS", "CNSA"):
        return control_finding(
            control_id="C33",
            status="pass",
            expected="Encrypted virtual console sessions",
            observed=f"SecurityState={state}, DisableWeakCiphers={weak_ciphers}",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )
    return control_finding(
        control_id="C33",
        status="unknown_not_exposed",
        expected="Encrypted virtual console sessions",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c34_virtual_media_encryption_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C34: Virtual Media Encryption & Protection."""
    net = oem.get("hpe_network_protocol") or {}
    vmedia_enc = net.get("VirtualMediaEncryptionEnabled")

    ev: List[Dict[str, Any]] = []
    if vmedia_enc is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_NET_URI,
            property="VirtualMediaEncryptionEnabled",
            raw_value=vmedia_enc,
            normalized_value=bool(vmedia_enc),
        ))
        if vmedia_enc is True:
            return control_finding(
                control_id="C34",
                status="pass",
                expected="Virtual Media encryption enabled",
                observed=True,
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C34",
            status="fail",
            expected="Virtual Media encryption enabled",
            observed=False,
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C34",
        status="unknown_not_exposed",
        expected="Virtual Media encryption enabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c35_vmedia_share_hpe() -> Dict[str, Any]:
    """C35: Virtual Media Share Credentials (Property Not Exposed)."""
    return control_finding(
        control_id="C35",
        status="unknown_not_exposed",
        expected="Virtual media network share credentials secured",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=[],
    )


def evaluate_c36_vnc_hpe() -> Dict[str, Any]:
    """C36: VNC Server Hardening / Disablement."""
    return control_finding(
        control_id="C36",
        status="pass",
        expected="VNC server disabled or hardened",
        observed="HPE iLO does not run unhardened VNC",
        reason_code=ReasonCode.OEM_REDFISH_PASS,
        evidence=[],
    )


def evaluate_c38_password_policy_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C38: Password Policy & Complexity."""
    acct = oem.get("hpe_account_service") or {}
    enforce_comp = acct.get("EnforcePasswordComplexity")
    min_len = acct.get("MinPasswordLength")

    ev: List[Dict[str, Any]] = []
    if enforce_comp is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_ACCT_URI,
            property="EnforcePasswordComplexity",
            raw_value=enforce_comp,
            normalized_value=bool(enforce_comp),
        ))
    if min_len is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_ACCT_URI,
            property="MinPasswordLength",
            raw_value=min_len,
            normalized_value=int(min_len),
        ))

    if enforce_comp is True and min_len is not None and min_len >= 8:
        return control_finding(
            control_id="C38",
            status="pass",
            expected="Complexity enabled and min length at least 8",
            observed=f"Complexity=True, MinLength={min_len}",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )
    if enforce_comp is False or (min_len is not None and min_len < 8):
        return control_finding(
            control_id="C38",
            status="fail",
            expected="Complexity enabled and min length at least 8",
            observed=f"Complexity={enforce_comp}, MinLength={min_len}",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C38",
        status="unknown_not_exposed",
        expected="Complexity enabled and min length at least 8",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c39_rbsu_login_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C39: Require Login for iLO RBSU."""
    params = oem.get("security_parameters") or []
    param = _find_hpe_param(params, "Require Login for iLO RBSU")
    if not param:
        param = _find_hpe_param(params, "3")

    ev: List[Dict[str, Any]] = []
    if param:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=f"{HPE_DASH_URI}/SecurityParams/{param.get('id')}",
            property="State",
            raw_value=param.get("state"),
            normalized_value=str(param.get("state")),
        ))
        if str(param.get("state")).lower() == "enabled" or str(param.get("security_status")).lower() == "ok":
            return control_finding(
                control_id="C39",
                status="pass",
                expected="Login required for iLO RBSU",
                observed="Enabled",
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C39",
            status="fail",
            expected="Login required for iLO RBSU",
            observed=str(param.get("state")),
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C39",
        status="unknown_not_exposed",
        expected="Login required for iLO RBSU",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c40_security_logging_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C40: Authentication Failure Logging & Audit."""
    params = oem.get("security_parameters") or []
    param = _find_hpe_param(params, "Authentication Failure Logging")
    if not param:
        param = _find_hpe_param(params, "4")

    ev: List[Dict[str, Any]] = []
    if param:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=f"{HPE_DASH_URI}/SecurityParams/{param.get('id')}",
            property="State",
            raw_value=param.get("state"),
            normalized_value=str(param.get("state")),
        ))
        if str(param.get("state")).lower() == "enabled" or str(param.get("security_status")).lower() == "ok":
            return control_finding(
                control_id="C40",
                status="pass",
                expected="Auth failure logging enabled",
                observed="Enabled",
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C40",
            status="fail",
            expected="Auth failure logging enabled",
            observed=str(param.get("state")),
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C40",
        status="unknown_not_exposed",
        expected="Auth failure logging enabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c41_default_credentials_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C41: Default Account Credential Replacement."""
    params = oem.get("security_parameters") or []
    param = _find_hpe_param(params, "Password for default Administrator account")
    ev: List[Dict[str, Any]] = []
    if param:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=f"{HPE_DASH_URI}/SecurityParams/{param.get('id')}",
            property="SecurityStatus",
            raw_value=param.get("security_status"),
            normalized_value=str(param.get("security_status")),
        ))
        if str(param.get("security_status")).lower() == "ok":
            return control_finding(
                control_id="C41",
                status="pass",
                expected="Default password changed",
                observed="Password changed",
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C41",
            status="fail",
            expected="Default password changed",
            observed="Default password in use",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C41",
        status="unknown_not_exposed",
        expected="Default password changed",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c42_2fa_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C42: Multi-Factor Authentication (G-HPE-TFA)."""
    acct = oem.get("hpe_account_service") or {}
    ca = oem.get("certificate_authentication") or {}
    tfa = acct.get("TwoFactorAuth")
    cert_login = ca.get("CertificateLoginEnabled")

    ev: List[Dict[str, Any]] = []
    if tfa is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_ACCT_URI,
            property="TwoFactorAuth",
            raw_value=tfa,
            normalized_value=str(tfa),
        ))
    if cert_login is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=f"{HPE_SEC_URI}/CertificateAuthentication",
            property="CertificateLoginEnabled",
            raw_value=cert_login,
            normalized_value=bool(cert_login),
        ))

    if str(tfa).lower() == "enabled" or cert_login is True:
        return control_finding(
            control_id="C42",
            status="pass",
            expected="Two-Factor Auth or Certificate Login enabled",
            observed=f"TwoFactorAuth={tfa}, CertLogin={cert_login}",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )
    if str(tfa).lower() == "disabled" and cert_login is False:
        return control_finding(
            control_id="C42",
            status="fail",
            expected="Two-Factor Auth or Certificate Login enabled",
            observed="Disabled",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C42",
        status="unknown_not_exposed",
        expected="Two-Factor Auth or Certificate Login enabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c44_login_banner_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C44: Login Security Banner."""
    sec = oem.get("security_service") or {}
    banner = sec.get("LoginSecurityBanner")

    ev: List[Dict[str, Any]] = []
    if banner is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_SEC_URI,
            property="LoginSecurityBanner",
            raw_value=banner,
            normalized_value=str(banner),
        ))
        is_enabled = False
        if isinstance(banner, dict):
            is_enabled = bool(banner.get("IsEnabled") or banner.get("Enabled"))
        elif isinstance(banner, bool):
            is_enabled = banner
        if is_enabled:
            return control_finding(
                control_id="C44",
                status="pass",
                expected="Login Security Banner enabled",
                observed=True,
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C44",
            status="fail",
            expected="Login Security Banner enabled",
            observed=False,
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C44",
        status="unknown_not_exposed",
        expected="Login Security Banner enabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c45_cert_validation_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C45: Directory / LDAP Certificate Validation."""
    ca = oem.get("certificate_authentication") or {}
    strict_cac = ca.get("StrictCACModeEnabled")

    ev: List[Dict[str, Any]] = []
    if strict_cac is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=f"{HPE_SEC_URI}/CertificateAuthentication",
            property="StrictCACModeEnabled",
            raw_value=strict_cac,
            normalized_value=bool(strict_cac),
        ))
        if strict_cac is True:
            return control_finding(
                control_id="C45",
                status="pass",
                expected="Strict certificate validation enabled",
                observed=True,
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C45",
            status="fail",
            expected="Strict certificate validation enabled",
            observed=False,
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C45",
        status="unknown_not_exposed",
        expected="Strict certificate validation enabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c46_host_reconfig_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C46: In-Band Host Reconfiguration Lock."""
    mgr = oem.get("hpe_manager") or {}
    req_auth = mgr.get("RequireHostAuthentication")

    ev: List[Dict[str, Any]] = []
    if req_auth is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_MGR_URI,
            property="RequireHostAuthentication",
            raw_value=req_auth,
            normalized_value=bool(req_auth),
        ))
        if req_auth is True:
            return control_finding(
                control_id="C46",
                status="pass",
                expected="In-band reconfig authentication required",
                observed=True,
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C46",
            status="fail",
            expected="In-band reconfig authentication required",
            observed=False,
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C46",
        status="unknown_not_exposed",
        expected="In-band reconfig authentication required",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c47_smartcard_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C47: Smart Card / Strict CAC Authentication."""
    ca = oem.get("certificate_authentication") or {}
    strict_cac = ca.get("StrictCACModeEnabled")
    cert_login = ca.get("CertificateLoginEnabled")

    ev: List[Dict[str, Any]] = []
    if strict_cac is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=f"{HPE_SEC_URI}/CertificateAuthentication",
            property="StrictCACModeEnabled",
            raw_value=strict_cac,
            normalized_value=bool(strict_cac),
        ))

    if strict_cac is True and cert_login is True:
        return control_finding(
            control_id="C47",
            status="pass",
            expected="Strict CAC mode enabled",
            observed=True,
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=ev,
        )
    if strict_cac is False:
        return control_finding(
            control_id="C47",
            status="fail",
            expected="Strict CAC mode enabled",
            observed=False,
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C47",
        status="unknown_not_exposed",
        expected="Strict CAC mode enabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c48_lc_fips_hpe() -> Dict[str, Any]:
    """C48: Dell LC FIPS Mode (Dell-specific)."""
    return control_finding(
        control_id="C48",
        status="not_applicable",
        expected="Dell LC FIPS mode enabled",
        observed=None,
        reason_code=ReasonCode.NOT_APPLICABLE,
        evidence=[],
    )


def evaluate_c49_bios_password_hpe() -> Dict[str, Any]:
    """C49: System Setup Password (Write-Only Secret)."""
    return control_finding(
        control_id="C49",
        status="unknown_write_only",
        expected="System setup password configured",
        observed=None,
        reason_code=ReasonCode.WRITE_ONLY_SECRET,
        evidence=[],
    )


def evaluate_c50_sso_trust_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C50: Single Sign-On (SSO) Trust Mode."""
    sso = oem.get("sso") or {}
    mode = sso.get("SSOTrustMode")

    ev: List[Dict[str, Any]] = []
    if mode is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=f"{HPE_SEC_URI}/SSO",
            property="SSOTrustMode",
            raw_value=mode,
            normalized_value=str(mode),
        ))
        if str(mode).lower() in ("trustnone", "disabled"):
            return control_finding(
                control_id="C50",
                status="pass",
                expected="TrustNone or Disabled",
                observed=str(mode),
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        if str(mode).lower() == "trustall":
            return control_finding(
                control_id="C50",
                status="fail",
                expected="TrustNone",
                observed="TrustAll",
                reason_code=ReasonCode.OEM_REDFISH_FAIL,
                evidence=ev,
            )
    return control_finding(
        control_id="C50",
        status="unknown_not_exposed",
        expected="TrustNone or Disabled",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c51_uefi_variables_hpe(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C51: UEFI Variable Access Protection."""
    sb = standard.get("secure_boot") or {}
    enabled = sb.get("SecureBootEnable")

    ev: List[Dict[str, Any]] = []
    if enabled is not None:
        ev.append(evidence_item(
            transport="standard_redfish",
            uri="/redfish/v1/Systems/1/SecureBoot",
            property="SecureBootEnable",
            raw_value=enabled,
            normalized_value=bool(enabled),
        ))
        if enabled is True:
            return control_finding(
                control_id="C51",
                status="pass",
                expected="UEFI variable access protected",
                observed=True,
                reason_code=ReasonCode.STANDARD_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C51",
            status="fail",
            expected="UEFI variable access protected",
            observed=False,
            reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C51",
        status="unknown_not_exposed",
        expected="UEFI variable access protected",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c52_chif_hpe(oem: Dict[str, Any]) -> Dict[str, Any]:
    """C52: In-Band CHIF Interface Manageability."""
    mgr = oem.get("hpe_manager") or {}
    req_auth = mgr.get("RequireHostAuthentication")

    ev: List[Dict[str, Any]] = []
    if req_auth is not None:
        ev.append(evidence_item(
            transport="oem_hpe",
            uri=HPE_MGR_URI,
            property="RequireHostAuthentication",
            raw_value=req_auth,
            normalized_value=bool(req_auth),
        ))
        if req_auth is True:
            return control_finding(
                control_id="C52",
                status="pass",
                expected="CHIF interface requires authentication",
                observed=True,
                reason_code=ReasonCode.OEM_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C52",
            status="fail",
            expected="CHIF interface requires authentication",
            observed=False,
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C52",
        status="unknown_not_exposed",
        expected="CHIF interface requires authentication",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c54_secure_boot_mode_hpe(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C54: Secure Boot Mode / Key Verification."""
    sb = standard.get("secure_boot") or {}
    mode = sb.get("SecureBootMode")

    ev: List[Dict[str, Any]] = []
    if mode is not None:
        ev.append(evidence_item(
            transport="standard_redfish",
            uri="/redfish/v1/Systems/1/SecureBoot",
            property="SecureBootMode",
            raw_value=mode,
            normalized_value=str(mode),
        ))
        if str(mode).lower() in ("deployedmode", "usermode"):
            return control_finding(
                control_id="C54",
                status="pass",
                expected="DeployedMode or UserMode",
                observed=str(mode),
                reason_code=ReasonCode.STANDARD_REDFISH_PASS,
                evidence=ev,
            )
        return control_finding(
            control_id="C54",
            status="fail",
            expected="DeployedMode or UserMode",
            observed=str(mode),
            reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
            evidence=ev,
        )
    return control_finding(
        control_id="C54",
        status="unknown_not_exposed",
        expected="DeployedMode or UserMode",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c55_lcd_hpe() -> Dict[str, Any]:
    """C55: Dell LCD Control Panel (Dell-specific)."""
    return control_finding(
        control_id="C55",
        status="not_applicable",
        expected="Dell LCD control panel disabled",
        observed=None,
        reason_code=ReasonCode.NOT_APPLICABLE,
        evidence=[],
    )


def evaluate_c56_bios_live_scan_hpe() -> Dict[str, Any]:
    """C56: Dell BIOS Live Scanning (Dell-specific)."""
    return control_finding(
        control_id="C56",
        status="not_applicable",
        expected="Dell BIOS live scan enabled",
        observed=None,
        reason_code=ReasonCode.NOT_APPLICABLE,
        evidence=[],
    )


def evaluate_c57_lc_import_export_hpe() -> Dict[str, Any]:
    """C57: Dell LC Secure Import/Export (Dell-specific)."""
    return control_finding(
        control_id="C57",
        status="not_applicable",
        expected="Dell LC import/export workflow secured",
        observed=None,
        reason_code=ReasonCode.NOT_APPLICABLE,
        evidence=[],
    )


def evaluate_c58_outbound_proxy_hpe() -> Dict[str, Any]:
    """C58: Dell LC Outbound Proxy Validation (Dell-specific)."""
    return control_finding(
        control_id="C58",
        status="not_applicable",
        expected="Dell LC outbound proxy validated",
        observed=None,
        reason_code=ReasonCode.NOT_APPLICABLE,
        evidence=[],
    )


def evaluate_c59_field_service_debug_hpe() -> Dict[str, Any]:
    """C59: Dell Field Service Debug (Dell-specific)."""
    return control_finding(
        control_id="C59",
        status="not_applicable",
        expected="Dell Field Service Debug disabled",
        observed=None,
        reason_code=ReasonCode.NOT_APPLICABLE,
        evidence=[],
    )


def evaluate_hpe_security_controls(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate all 59 configuration controls for HPE iLO platforms.

    Returns deterministic findings for C01–C59.
    Proven HPE extensions evaluate against exact properties.
    Dell-specific controls are marked not_applicable.
    Unproven/external controls are marked unknown.
    """
    standard = evidence.get("standard") or {}
    oem = evidence.get("oem") or {}

    return [
        evaluate_c01_https_hpe(oem, standard),
        evaluate_c02_tls_version_hpe(oem),
        evaluate_c03_tls_key_exchange_hpe(oem),
        evaluate_c04_weak_ciphers_hpe(oem),
        evaluate_c05_certificate_hpe(oem),
        evaluate_c06_scep_hpe(oem),
        evaluate_c07_secure_syslog_hpe(oem),
        evaluate_c08_security_state_hpe(oem),
        evaluate_c09_ssh(standard),
        evaluate_c10_ssh_keys_hpe(),
        evaluate_c11_ssh_crypto_hpe(oem),
        evaluate_c12_dedicated_nic_hpe(standard),
        evaluate_c13_vlan_hpe(standard),
        evaluate_c14_service_port_hpe(oem),
        evaluate_c15_host_auth_hpe(oem),
        evaluate_c16_lockout_hpe(oem, standard),
        evaluate_c17_acl_hpe(),
        evaluate_c18_autodiscovery_hpe(),
        evaluate_c19_autoconfig_hpe(),
        evaluate_c20_unused_services_hpe(oem, standard),
        evaluate_c21_ipmi_lan_hpe(oem, standard),
        evaluate_c22_system_lockdown_hpe(oem),
        evaluate_c23_telnet(standard),
        evaluate_c24_snmp_hpe(oem, standard),
        evaluate_c25_snmp_isolation_hpe(),
        evaluate_c26_snmp_crypto_hpe(),
        evaluate_c27_cipher0_hpe(),
        evaluate_c28_secure_ntp_hpe(standard),
        evaluate_c29_session_auth(standard),
        evaluate_c30_sekm_hpe(),
        evaluate_c31_group_manager_hpe(),
        evaluate_c32_group_manager_passcode_hpe(),
        evaluate_c33_kvm_encryption_hpe(oem),
        evaluate_c34_virtual_media_encryption_hpe(oem),
        evaluate_c35_vmedia_share_hpe(),
        evaluate_c36_vnc_hpe(),
        evaluate_c37_session_timeout(standard),
        evaluate_c38_password_policy_hpe(oem),
        evaluate_c39_rbsu_login_hpe(oem),
        evaluate_c40_security_logging_hpe(oem),
        evaluate_c41_default_credentials_hpe(oem),
        evaluate_c42_2fa_hpe(oem),
        evaluate_c43_directory_and_lockout(standard),
        evaluate_c44_login_banner_hpe(oem),
        evaluate_c45_cert_validation_hpe(oem),
        evaluate_c46_host_reconfig_hpe(oem),
        evaluate_c47_smartcard_hpe(oem),
        evaluate_c48_lc_fips_hpe(),
        evaluate_c49_bios_password_hpe(),
        evaluate_c50_sso_trust_hpe(oem),
        evaluate_c51_uefi_variables_hpe(standard),
        evaluate_c52_chif_hpe(oem),
        evaluate_c53_secure_boot(standard),
        evaluate_c54_secure_boot_mode_hpe(standard),
        evaluate_c55_lcd_hpe(),
        evaluate_c56_bios_live_scan_hpe(),
        evaluate_c57_lc_import_export_hpe(),
        evaluate_c58_outbound_proxy_hpe(),
        evaluate_c59_field_service_debug_hpe(),
    ]
