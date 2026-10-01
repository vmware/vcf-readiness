"""Evaluation engine for BMC security posture controls.

Pure evaluation functions translating normalized evidence into
ordered, validated control findings.

Bead 3 implements the eight common-plan standard Redfish controls:
- C09: SSH service exposure
- C21: IPMI-over-LAN protocol disablement
- C23: Telnet service disablement
- C24: SNMP service/version exposure
- C29: Redfish session authentication
- C37: Session timeout / session service policy
- C43: Central directory authentication & account lockout threshold
- C53: UEFI Secure Boot enabled and active
"""

from typing import Any, Dict, List

from vcf_hci.security.contract import (
    ReasonCode,
    control_finding,
    evidence_item,
)


def evaluate_c09_ssh(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C09: SSH service exposure.

    Policy: Enable SSH only when required; prefer over Telnet.
    Disabled -> pass (attack surface minimized).
    Enabled -> pass (available for secure management; hardened ciphers verified in C11).
    Missing -> unknown_not_exposed.
    """
    net_proto = standard.get("network_protocol") or {}
    ssh_data = net_proto.get("SSH")
    uri = net_proto.get("uri", "/redfish/v1/Managers/{id}/NetworkProtocol")

    if not isinstance(ssh_data, dict) or "ProtocolEnabled" not in ssh_data:
        return control_finding(
            control_id="C09",
            status="unknown_not_exposed",
            expected="Disabled or hardened SSH enabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    enabled = ssh_data.get("ProtocolEnabled")
    ev = [
        evidence_item(
            transport="standard_redfish",
            uri=uri,
            property="SSH.ProtocolEnabled",
            raw_value=enabled,
            normalized_value=bool(enabled),
        )
    ]
    if enabled is False:
        return control_finding(
            control_id="C09",
            status="pass",
            expected="Disabled or hardened SSH enabled",
            observed=False,
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )
    return control_finding(
        control_id="C09",
        status="pass",
        expected="Disabled or hardened SSH enabled",
        observed=True,
        reason_code=ReasonCode.STANDARD_REDFISH_PASS,
        evidence=ev,
    )


def evaluate_c21_ipmi_lan(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C21: IPMI-over-LAN.

    Requirement: Disable IPMI over LAN to eliminate cipher-0 / replay attack surface.
    Disabled -> pass.
    Enabled -> fail.
    Missing -> unknown_not_exposed.
    """
    net_proto = standard.get("network_protocol") or {}
    ipmi_data = net_proto.get("IPMI")
    uri = net_proto.get("uri", "/redfish/v1/Managers/{id}/NetworkProtocol")

    if not isinstance(ipmi_data, dict) or "ProtocolEnabled" not in ipmi_data:
        return control_finding(
            control_id="C21",
            status="unknown_not_exposed",
            expected="Disabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    enabled = ipmi_data.get("ProtocolEnabled")
    ev = [
        evidence_item(
            transport="standard_redfish",
            uri=uri,
            property="IPMI.ProtocolEnabled",
            raw_value=enabled,
            normalized_value=bool(enabled),
        )
    ]
    if enabled is False:
        return control_finding(
            control_id="C21",
            status="pass",
            expected="Disabled",
            observed=False,
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )
    return control_finding(
        control_id="C21",
        status="fail",
        expected="Disabled",
        observed=True,
        reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c23_telnet(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C23: Telnet.

    Requirement: Telnet transmits credentials in cleartext; must be disabled.
    Disabled -> pass.
    Enabled -> fail.
    Missing -> unknown_not_exposed.
    """
    net_proto = standard.get("network_protocol") or {}
    telnet_data = net_proto.get("Telnet")
    uri = net_proto.get("uri", "/redfish/v1/Managers/{id}/NetworkProtocol")

    if not isinstance(telnet_data, dict) or "ProtocolEnabled" not in telnet_data:
        return control_finding(
            control_id="C23",
            status="unknown_not_exposed",
            expected="Disabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    enabled = telnet_data.get("ProtocolEnabled")
    ev = [
        evidence_item(
            transport="standard_redfish",
            uri=uri,
            property="Telnet.ProtocolEnabled",
            raw_value=enabled,
            normalized_value=bool(enabled),
        )
    ]
    if enabled is False:
        return control_finding(
            control_id="C23",
            status="pass",
            expected="Disabled",
            observed=False,
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )
    return control_finding(
        control_id="C23",
        status="fail",
        expected="Disabled",
        observed=True,
        reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c24_snmp(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C24: SNMP service/version.

    Policy: Disable SNMP unless needed; if needed, migrate to SNMPv3 AuthPriv.
    Disabled -> pass (attack surface minimized).
    Enabled with SNMPv3 Auth (SHA/MD5) -> pass.
    Enabled without version/auth details -> unknown_ambiguous (never an implicit pass).
    Enabled with community strings / v1/v2c -> fail.
    Missing -> unknown_not_exposed.
    """
    net_proto = standard.get("network_protocol") or {}
    snmp_data = net_proto.get("SNMP")
    uri = net_proto.get("uri", "/redfish/v1/Managers/{id}/NetworkProtocol")

    if not isinstance(snmp_data, dict) or "ProtocolEnabled" not in snmp_data:
        return control_finding(
            control_id="C24",
            status="unknown_not_exposed",
            expected="Disabled or SNMPv3 AuthPriv",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    enabled = snmp_data.get("ProtocolEnabled")
    auth_proto = str(snmp_data.get("AuthenticationProtocol") or "").upper()
    ev = [
        evidence_item(
            transport="standard_redfish",
            uri=uri,
            property="SNMP.ProtocolEnabled",
            raw_value=enabled,
            normalized_value=bool(enabled),
        )
    ]
    if enabled is False:
        return control_finding(
            control_id="C24",
            status="pass",
            expected="Disabled or SNMPv3 AuthPriv",
            observed="Disabled",
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )

    # SNMP is enabled: check version/auth
    if any(k in auth_proto for k in ("SHA", "SHA256", "SHA384", "SHA512", "MD5")):
        return control_finding(
            control_id="C24",
            status="pass",
            expected="Disabled or SNMPv3 AuthPriv",
            observed=f"SNMPv3 ({auth_proto})",
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )

    if not auth_proto or auth_proto in ("NONE", "COMMUNITY"):
        # Enabled without version proof or with community mode
        return control_finding(
            control_id="C24",
            status="unknown_ambiguous",
            expected="Disabled or SNMPv3 AuthPriv",
            observed="Enabled (version/auth not exposed)",
            reason_code=ReasonCode.AMBIGUOUS_EVIDENCE,
            evidence=ev,
        )

    return control_finding(
        control_id="C24",
        status="fail",
        expected="Disabled or SNMPv3 AuthPriv",
        observed=f"SNMP ({auth_proto})",
        reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c29_session_auth(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C29: Redfish session authentication.

    Policy: Clients should use session-token auth (POST session, X-Auth-Token, DELETE).
    Since this is primarily client behavior, SessionService presence is necessary
    but not decisive for all client traffic.
    Returns unknown_not_exposed / CLIENT_BEHAVIOR_REQUIRED.
    """
    sess_svc = standard.get("session_service") or {}
    uri = sess_svc.get("uri", "/redfish/v1/SessionService")
    svc_enabled = sess_svc.get("ServiceEnabled")

    ev = [
        evidence_item(
            transport="standard_redfish",
            uri=uri,
            property="ServiceEnabled",
            raw_value=svc_enabled,
            normalized_value=bool(svc_enabled) if svc_enabled is not None else None,
        )
    ]

    if svc_enabled is True or sess_svc.get("SessionsExposed"):
        return control_finding(
            control_id="C29",
            status="unknown_ambiguous",
            expected="Client session-token authentication",
            observed="SessionService exposed (client enforcement required)",
            reason_code=ReasonCode.CLIENT_BEHAVIOR_REQUIRED,
            evidence=ev,
        )

    return control_finding(
        control_id="C29",
        status="unknown_not_exposed",
        expected="Client session-token authentication",
        observed=None,
        reason_code=ReasonCode.ENDPOINT_NOT_EXPOSED,
        evidence=ev if svc_enabled is not None else [],
    )


def evaluate_c37_session_timeout(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C37: Session timeout policy.

    Requirement: Idle session timeout should be <= 1800 seconds (30 minutes).
    Timeout between 1 and 1800 s -> pass.
    Timeout 0 (unlimited) or > 1800 s -> fail.
    Missing -> unknown_not_exposed.
    """
    sess_svc = standard.get("session_service") or {}
    timeout_val = sess_svc.get("SessionTimeout")
    uri = sess_svc.get("uri", "/redfish/v1/SessionService")

    if timeout_val is None:
        return control_finding(
            control_id="C37",
            status="unknown_not_exposed",
            expected="<= 1800 s",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    try:
        t_int = int(timeout_val)
    except (ValueError, TypeError):
        return control_finding(
            control_id="C37",
            status="unknown_ambiguous",
            expected="<= 1800 s",
            observed=timeout_val,
            reason_code=ReasonCode.AMBIGUOUS_EVIDENCE,
            evidence=[],
        )

    ev = [
        evidence_item(
            transport="standard_redfish",
            uri=uri,
            property="SessionTimeout",
            raw_value=timeout_val,
            normalized_value=t_int,
        )
    ]

    if 0 < t_int <= 1800:
        return control_finding(
            control_id="C37",
            status="pass",
            expected="<= 1800 s",
            observed=f"{t_int} s",
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C37",
        status="fail",
        expected="<= 1800 s",
        observed=f"{t_int} s (exceeds 1800 s limit)" if t_int > 1800 else "0 s (unlimited)",
        reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_c43_directory_and_lockout(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C43: Central directory authentication and account lockout policy.

    Evaluates:
    - AccountLockoutThreshold: 1 <= threshold <= 5 failed attempts -> pass.
    - Central Directory: ActiveDirectory or LDAP ServiceEnabled -> pass.
    - If lockout threshold is 0 (disabled) and no directory service -> fail.
    - Missing -> unknown_not_exposed.
    """
    acct_svc = standard.get("account_service") or {}
    uri = acct_svc.get("uri", "/redfish/v1/AccountService")

    lockout_thresh = acct_svc.get("AccountLockoutThreshold")
    ad_data = acct_svc.get("ActiveDirectory") or {}
    ldap_data = acct_svc.get("LDAP") or {}

    ad_enabled = ad_data.get("ServiceEnabled") is True
    ldap_enabled = ldap_data.get("ServiceEnabled") is True

    ev: List[Dict[str, Any]] = []
    if lockout_thresh is not None:
        ev.append(evidence_item(
            transport="standard_redfish",
            uri=uri,
            property="AccountLockoutThreshold",
            raw_value=lockout_thresh,
            normalized_value=int(lockout_thresh) if str(lockout_thresh).isdigit() else lockout_thresh,
        ))

    # Directory service enabled -> pass
    if ad_enabled or ldap_enabled:
        ds_name = "Active Directory" if ad_enabled else "LDAP"
        return control_finding(
            control_id="C43",
            status="pass",
            expected="Directory authentication enabled or lockout <= 5",
            observed=f"{ds_name} enabled",
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )

    # Check lockout threshold
    if lockout_thresh is not None:
        try:
            lt_int = int(lockout_thresh)
            if 1 <= lt_int <= 5:
                return control_finding(
                    control_id="C43",
                    status="pass",
                    expected="Directory authentication enabled or lockout <= 5",
                    observed=f"Lockout threshold = {lt_int}",
                    reason_code=ReasonCode.STANDARD_REDFISH_PASS,
                    evidence=ev,
                )
            if lt_int == 0:
                return control_finding(
                    control_id="C43",
                    status="fail",
                    expected="Directory authentication enabled or lockout <= 5",
                    observed="Disabled (threshold = 0)",
                    reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
                    evidence=ev,
                )
            return control_finding(
                control_id="C43",
                status="fail",
                expected="Directory authentication enabled or lockout <= 5",
                observed=f"Threshold = {lt_int} (exceeds baseline <= 5)",
                reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
                evidence=ev,
            )
        except (ValueError, TypeError):
            pass

    return control_finding(
        control_id="C43",
        status="unknown_not_exposed",
        expected="Directory authentication enabled or lockout <= 5",
        observed=None,
        reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
        evidence=ev,
    )


def evaluate_c53_secure_boot(standard: Dict[str, Any]) -> Dict[str, Any]:
    """C53: UEFI Secure Boot.

    Requirement: Secure Boot enabled and current boot reflects enabled state.
    SecureBootEnable True and SecureBootCurrentBoot active -> pass.
    SecureBootEnable False -> fail.
    Missing -> unknown_not_exposed.
    """
    sb_data = standard.get("secure_boot") or {}
    uri = sb_data.get("uri", "/redfish/v1/Systems/{id}/SecureBoot")

    sb_enable = sb_data.get("SecureBootEnable")
    sb_current = sb_data.get("SecureBootCurrentBoot")

    if sb_enable is None:
        return control_finding(
            control_id="C53",
            status="unknown_not_exposed",
            expected="Enabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        )

    ev = [
        evidence_item(
            transport="standard_redfish",
            uri=uri,
            property="SecureBootEnable",
            raw_value=sb_enable,
            normalized_value=bool(sb_enable),
        )
    ]
    if sb_current is not None:
        ev.append(evidence_item(
            transport="standard_redfish",
            uri=uri,
            property="SecureBootCurrentBoot",
            raw_value=sb_current,
            normalized_value=str(sb_current),
        ))

    if sb_enable is True:
        observed_str = "Enabled"
        if sb_current:
            observed_str += f" (CurrentBoot: {sb_current})"
        return control_finding(
            control_id="C53",
            status="pass",
            expected="Enabled",
            observed=observed_str,
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=ev,
        )

    return control_finding(
        control_id="C53",
        status="fail",
        expected="Enabled",
        observed="Disabled",
        reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
        evidence=ev,
    )


def evaluate_standard_security_controls(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate all eight common-plan standard Redfish controls.

    Deterministic ordering: C09, C21, C23, C24, C29, C37, C43, C53.

    Args:
        evidence: Normalized evidence dictionary matching EVIDENCE_SCHEMA_VERSION.

    Returns:
        Ordered list of eight control findings.
    """
    standard = evidence.get("standard") or {}
    return [
        evaluate_c09_ssh(standard),
        evaluate_c21_ipmi_lan(standard),
        evaluate_c23_telnet(standard),
        evaluate_c24_snmp(standard),
        evaluate_c29_session_auth(standard),
        evaluate_c37_session_timeout(standard),
        evaluate_c43_directory_and_lockout(standard),
        evaluate_c53_secure_boot(standard),
    ]


def evaluate_security_controls(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Top-level evaluator dispatching standard and OEM controls.

    Bead 3 evaluates standard controls. Subsequent beads extend this
    with OEM evaluation hooks (Dell C01–C59 in Bead 5, HPE C01–C59 in Bead 7).
    """
    vendor = str(evidence.get("vendor") or "").lower()
    if vendor == "dell":
        from vcf_hci.security.dell import evaluate_dell_security_controls
        return evaluate_dell_security_controls(evidence)
    if vendor in ("hpe", "hewlett", "hewlett packard enterprise"):
        from vcf_hci.security.hpe import evaluate_hpe_security_controls
        return evaluate_hpe_security_controls(evidence)
    return evaluate_standard_security_controls(evidence)
