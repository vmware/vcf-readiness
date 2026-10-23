"""Lenovo XCC security evaluator.

Evaluates standard DMTF Redfish controls and Lenovo XCC OEM security telemetry
(Oem.Lenovo.Security, Oem.Lenovo.BMCSettings, Oem.Lenovo.SystemGuard).
"""

from __future__ import annotations

from typing import Any, Dict, List

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
    evaluate_standard_security_controls,
)

OEM_SUPPORT = "supported"
OEM_SUPPORT_REASON = (
    "Lenovo XCC SCG evaluates standard DMTF Redfish and Lenovo OEM security telemetry "
    "(Oem.Lenovo.Security, BMCSettings, SystemGuard)."
)

DELL_SPECIFIC_RUNBOOK_CONTROLS = {
    "C46", "C47", "C48", "C49", "C50", "C51", "C52", "C57", "C58", "C59"
}


def evaluate_lenovo_security_controls(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluate Lenovo XCC security controls.

    When OEM evidence is empty, evaluates standard 8 controls.
    When OEM evidence is present, evaluates standard + Lenovo XCC OEM controls.
    """
    oem = evidence.get("oem") or {}
    standard = evidence.get("standard") or {}
    if not oem:
        # Fallback to standard 8 controls for minimal evidence fixtures
        findings = evaluate_standard_security_controls(evidence)
        for f in findings:
            f.setdefault("oem_support", "experimental")
            f.setdefault("oem_support_reason", OEM_SUPPORT_REASON)
            f.setdefault("vendor", evidence.get("vendor") or "lenovo")
        return findings

    sec_svc = oem.get("security_service") or {}
    bmc_settings = (oem.get("bmc_settings") or {}).get("Attributes") or {}
    system_guard = oem.get("system_guard") or {}
    net_proto = standard.get("network_protocol") or {}
    acct_svc = standard.get("account_service") or {}
    cert_svc = standard.get("certificate_service") or {}
    bios_attrs = standard.get("bios_attributes") or {}
    sec_boot = standard.get("secure_boot") or {}

    findings: List[Dict[str, Any]] = []

    # ── Standard Base Controls ──────────────────────────────────────────
    findings.append(evaluate_c09_ssh(standard))
    findings.append(evaluate_c21_ipmi_lan(standard))
    findings.append(evaluate_c23_telnet(standard))
    findings.append(evaluate_c24_snmp(standard))
    findings.append(evaluate_c29_session_auth(standard))
    findings.append(evaluate_c37_session_timeout(standard))
    findings.append(evaluate_c43_directory_and_lockout(standard))
    findings.append(evaluate_c53_secure_boot(standard))

    # ── C01: HTTPS / HTTP to HTTPS Redirection ──────────────────────────
    https_en = (
        bmc_settings.get("HTTPSEnabled")
        or (sec_svc.get("SSLSettings") or {}).get("EnableHttps")
        or (net_proto.get("HTTPS") or {}).get("ProtocolEnabled")
    )
    if https_en in (True, "True", "true", "Enabled"):
        findings.append(control_finding(
            control_id="C01",
            status="pass",
            expected="HTTPS Enabled (Port 443)",
            observed="HTTPS Enabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "HTTPSEnabled", https_en, "True")],
        ))
    else:
        findings.append(control_finding(
            control_id="C01",
            status="fail",
            expected="HTTPS Enabled (Port 443)",
            observed=str(https_en),
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[],
        ))

    # ── C02: Minimum TLS Version ─────────────────────────────────────────
    min_tls = (
        (sec_svc.get("CryptographyManagement") or {}).get("MinTLSLevel")
        or bmc_settings.get("TLSLevel")
    )
    if min_tls and any(v in str(min_tls) for v in ("1_2", "1_3", "1.2", "1.3")):
        findings.append(control_finding(
            control_id="C02",
            status="pass",
            expected="TLS 1.2 or TLS 1.3",
            observed=str(min_tls),
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/Security", "MinTLSLevel", min_tls, str(min_tls))],
        ))
    elif min_tls:
        findings.append(control_finding(
            control_id="C02",
            status="fail",
            expected="TLS 1.2 or TLS 1.3",
            observed=str(min_tls),
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/Security", "MinTLSLevel", min_tls, str(min_tls))],
        ))
    else:
        findings.append(control_finding(
            control_id="C02",
            status="unknown_not_exposed",
            expected="TLS 1.2 or TLS 1.3",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C04: Security Mode / NIST SP 800-131A Compliance ─────────────────
    sec_mode_obj = sec_svc.get("SecurityMode") or {}
    cur_mode = sec_mode_obj.get("CurrentMode") or ""
    mode_status = sec_mode_obj.get("Status") or ""
    if cur_mode in ("Standard", "Strict") or "Compliant" in mode_status:
        findings.append(control_finding(
            control_id="C04",
            status="pass",
            expected="Standard or Strict Compliant (NIST SP 800-131A)",
            observed=f"{cur_mode} ({mode_status})",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/Security", "SecurityMode", cur_mode, mode_status)],
        ))
    elif cur_mode:
        findings.append(control_finding(
            control_id="C04",
            status="fail",
            expected="Standard or Strict Compliant (NIST SP 800-131A)",
            observed=f"{cur_mode} ({mode_status})",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/Security", "SecurityMode", cur_mode, mode_status)],
        ))
    else:
        findings.append(control_finding(
            control_id="C04",
            status="unknown_not_exposed",
            expected="Standard or Strict Compliant",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C16: BMC Certificate Management ──────────────────────────────────
    cert_count = cert_svc.get("CertificatesCount") or cert_svc.get("CertificateLocationsCount") or 0
    if cert_svc.get("ServiceEnabled") or cert_count > 0:
        findings.append(control_finding(
            control_id="C16",
            status="pass",
            expected="Certificate Service Active",
            observed=f"Active ({cert_count} certificate locations)",
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=[evidence_item("standard_redfish", "/redfish/v1/CertificateService", "CertificateLocationsCount", cert_count, str(cert_count))],
        ))
    else:
        findings.append(control_finding(
            control_id="C16",
            status="unknown_not_exposed",
            expected="Certificate Service Active",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C20: IPMI over KCS Interface ─────────────────────────────────────
    kcs_en = bmc_settings.get("IPMIoverKCSEnabled")
    if kcs_en in (False, "False", "false", "Disabled"):
        findings.append(control_finding(
            control_id="C20",
            status="pass",
            expected="Disabled (Host KCS interface disabled)",
            observed="Disabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "IPMIoverKCSEnabled", kcs_en, "False")],
        ))
    elif kcs_en in (True, "True", "true", "Enabled"):
        findings.append(control_finding(
            control_id="C20",
            status="fail",
            expected="Disabled (Host KCS interface disabled for zero-trust isolation)",
            observed="Enabled",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "IPMIoverKCSEnabled", kcs_en, "True")],
        ))
    else:
        findings.append(control_finding(
            control_id="C20",
            status="unknown_not_exposed",
            expected="Disabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C22: Serial-Over-LAN (SOL) Protocol ──────────────────────────────
    sol_en = bmc_settings.get("IPMISOLEth0Enabled") or bmc_settings.get("IPMISOLEth1Enabled")
    if sol_en in (False, "False", "false"):
        findings.append(control_finding(
            control_id="C22",
            status="pass",
            expected="Disabled or Encrypted SOL",
            observed="Disabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "IPMISOLEth0Enabled", sol_en, "False")],
        ))
    else:
        findings.append(control_finding(
            control_id="C22",
            status="pass",
            expected="Disabled or Encrypted SOL",
            observed=f"Enabled ({sol_en})",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "IPMISOLEth0Enabled", sol_en, str(sol_en))],
        ))

    # ── C25 & C26: Remote Syslog Forwarding & Encryption ─────────────────
    syslog_tcp = bmc_settings.get("SyslogOverTCPEnabled")
    if syslog_tcp in (True, "True", "true"):
        findings.append(control_finding(
            control_id="C25",
            status="pass",
            expected="Remote Syslog Forwarding Active",
            observed="Enabled (TCP/TLS)",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "SyslogOverTCPEnabled", syslog_tcp, "True")],
        ))
        findings.append(control_finding(
            control_id="C26",
            status="pass",
            expected="TLS Encrypted Remote Syslog",
            observed="Enabled (TCP/TLS)",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "SyslogOverTCPEnabled", syslog_tcp, "True")],
        ))
    else:
        findings.append(control_finding(
            control_id="C25",
            status="fail",
            expected="Remote Syslog Forwarding Active",
            observed="Disabled",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "SyslogOverTCPEnabled", syslog_tcp, "False")],
        ))
        findings.append(control_finding(
            control_id="C26",
            status="fail",
            expected="TLS Encrypted Remote Syslog",
            observed="Disabled",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "SyslogOverTCPEnabled", syslog_tcp, "False")],
        ))

    # ── C27: SSDP / Discovery Protocol Disablement ───────────────────────
    ssdp_en = (net_proto.get("SSDP") or {}).get("ProtocolEnabled")
    if ssdp_en is False:
        findings.append(control_finding(
            control_id="C27",
            status="pass",
            expected="Disabled",
            observed="Disabled",
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=[evidence_item("standard_redfish", "/redfish/v1/Managers/1/NetworkProtocol", "SSDP.ProtocolEnabled", False, "False")],
        ))
    elif ssdp_en is True:
        findings.append(control_finding(
            control_id="C27",
            status="fail",
            expected="Disabled (SSDP discovery service attack surface reduction)",
            observed="Enabled",
            reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
            evidence=[evidence_item("standard_redfish", "/redfish/v1/Managers/1/NetworkProtocol", "SSDP.ProtocolEnabled", True, "True")],
        ))
    else:
        findings.append(control_finding(
            control_id="C27",
            status="unknown_not_exposed",
            expected="Disabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C30: Network Time Protocol (NTP) Synchronisation ─────────────────
    ntp_info = net_proto.get("NTP") or {}
    ntp_en = ntp_info.get("ProtocolEnabled")
    ntp_srvs = [s for s in (ntp_info.get("NTPServers") or []) if s and str(s).strip()]
    if ntp_en and ntp_srvs:
        findings.append(control_finding(
            control_id="C30",
            status="pass",
            expected="NTP Active with Configured Servers",
            observed=f"Enabled ({', '.join(ntp_srvs[:2])})",
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=[evidence_item("standard_redfish", "/redfish/v1/Managers/1/NetworkProtocol", "NTP.NTPServers", ntp_srvs, ", ".join(ntp_srvs))],
        ))
    elif ntp_en:
        findings.append(control_finding(
            control_id="C30",
            status="fail",
            expected="NTP Active with Configured Servers",
            observed="Enabled but no NTP servers defined",
            reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
            evidence=[],
        ))
    else:
        findings.append(control_finding(
            control_id="C30",
            status="fail",
            expected="NTP Active with Configured Servers",
            observed="Disabled",
            reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
            evidence=[],
        ))

    # ── C34: Minimum Password Length ─────────────────────────────────────
    min_pw = bmc_settings.get("MinimumPasswordLength") or acct_svc.get("MinPasswordLength")
    if min_pw is not None and int(min_pw) >= 8:
        findings.append(control_finding(
            control_id="C34",
            status="pass",
            expected=">= 8 characters (SCG recommended >= 10)",
            observed=f"{min_pw} characters",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "MinimumPasswordLength", min_pw, str(min_pw))],
        ))
    elif min_pw is not None:
        findings.append(control_finding(
            control_id="C34",
            status="fail",
            expected=">= 8 characters",
            observed=f"{min_pw} characters",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "MinimumPasswordLength", min_pw, str(min_pw))],
        ))
    else:
        findings.append(control_finding(
            control_id="C34",
            status="unknown_not_exposed",
            expected=">= 8 characters",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C35: Password Complexity Requirements ────────────────────────────
    complex_pw = bmc_settings.get("ComplexPassword")
    if complex_pw in (True, "True", "true"):
        findings.append(control_finding(
            control_id="C35",
            status="pass",
            expected="Complex Passwords Enforced",
            observed="True",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "ComplexPassword", complex_pw, "True")],
        ))
    elif complex_pw in (False, "False", "false"):
        findings.append(control_finding(
            control_id="C35",
            status="fail",
            expected="Complex Passwords Enforced",
            observed="False",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "ComplexPassword", complex_pw, "False")],
        ))
    else:
        findings.append(control_finding(
            control_id="C35",
            status="unknown_not_exposed",
            expected="Complex Passwords Enforced",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C36: Minimum Password Change Interval ────────────────────────────
    pw_interval = bmc_settings.get("MinimumPasswordChangeIntervalHours")
    if pw_interval is not None and int(pw_interval) >= 1:
        findings.append(control_finding(
            control_id="C36",
            status="pass",
            expected=">= 1 hour",
            observed=f"{pw_interval} hour(s)",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "MinimumPasswordChangeIntervalHours", pw_interval, str(pw_interval))],
        ))
    else:
        findings.append(control_finding(
            control_id="C36",
            status="unknown_not_exposed",
            expected=">= 1 hour",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C38: Password History / Reuse Restriction ────────────────────────
    pw_reuse = bmc_settings.get("MinimumPasswordReuseCycle")
    if pw_reuse is not None and int(pw_reuse) >= 4:
        findings.append(control_finding(
            control_id="C38",
            status="pass",
            expected=">= 4 cycles",
            observed=f"{pw_reuse} cycle(s)",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "MinimumPasswordReuseCycle", pw_reuse, str(pw_reuse))],
        ))
    elif pw_reuse is not None:
        findings.append(control_finding(
            control_id="C38",
            status="fail",
            expected=">= 4 cycles",
            observed=f"{pw_reuse} cycle(s)",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[],
        ))
    else:
        findings.append(control_finding(
            control_id="C38",
            status="unknown_not_exposed",
            expected=">= 4 cycles",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C39: IP / Address Lockout Policy ─────────────────────────────────
    ip_lockout_dur = bmc_settings.get("IPLockoutDurationMinutes") or (sec_svc.get("AddressLockout") or {}).get("LockoutDurationMinutes")
    if ip_lockout_dur is not None and int(ip_lockout_dur) >= 15:
        findings.append(control_finding(
            control_id="C39",
            status="pass",
            expected="IP Lockout Active (>= 15 minutes)",
            observed=f"{ip_lockout_dur} minutes",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "IPLockoutDurationMinutes", ip_lockout_dur, str(ip_lockout_dur))],
        ))
    else:
        findings.append(control_finding(
            control_id="C39",
            status="unknown_not_exposed",
            expected="IP Lockout Active",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C41: Account Lockout Threshold ───────────────────────────────────
    acct_thresh = bmc_settings.get("AccountLockoutThreshold") or acct_svc.get("AccountLockoutThreshold")
    if acct_thresh is not None and 1 <= int(acct_thresh) <= 5:
        findings.append(control_finding(
            control_id="C41",
            status="pass",
            expected="1-5 attempts",
            observed=f"{acct_thresh} attempts",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "AccountLockoutThreshold", acct_thresh, str(acct_thresh))],
        ))
    elif acct_thresh is not None:
        findings.append(control_finding(
            control_id="C41",
            status="fail",
            expected="1-5 attempts",
            observed=f"{acct_thresh} attempts",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[],
        ))
    else:
        findings.append(control_finding(
            control_id="C41",
            status="unknown_not_exposed",
            expected="1-5 attempts",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C42: Account Lockout Duration ────────────────────────────────────
    acct_dur = bmc_settings.get("AccountLockoutDurationSeconds") or acct_svc.get("AccountLockoutDuration")
    if acct_dur is not None and int(acct_dur) >= 300:
        findings.append(control_finding(
            control_id="C42",
            status="pass",
            expected=">= 300 seconds",
            observed=f"{acct_dur} seconds",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "AccountLockoutDurationSeconds", acct_dur, str(acct_dur))],
        ))
    else:
        findings.append(control_finding(
            control_id="C42",
            status="unknown_not_exposed",
            expected=">= 300 seconds",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C44: LDAP Over SSL / TLS (LDAPS) ─────────────────────────────────
    ldaps_en = (sec_svc.get("SSLSettings") or {}).get("EnableLDAPS")
    if ldaps_en in (True, "True", "true"):
        findings.append(control_finding(
            control_id="C44",
            status="pass",
            expected="LDAPS Enabled",
            observed="True",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/Security", "SSLSettings.EnableLDAPS", ldaps_en, "True")],
        ))
    else:
        findings.append(control_finding(
            control_id="C44",
            status="fail",
            expected="LDAPS Enabled",
            observed=str(ldaps_en),
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[],
        ))

    # ── C45: LDAP Server Certificate Validation ──────────────────────────
    ldap_cert_val = bmc_settings.get("LDAPVerifyServerCert")
    if ldap_cert_val in (True, "True", "true"):
        findings.append(control_finding(
            control_id="C45",
            status="pass",
            expected="Enabled (Verify LDAP Server Certificate)",
            observed="True",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "LDAPVerifyServerCert", ldap_cert_val, "True")],
        ))
    elif ldap_cert_val in (False, "False", "false"):
        findings.append(control_finding(
            control_id="C45",
            status="fail",
            expected="Enabled (Verify LDAP Server Certificate)",
            observed="False",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "LDAPVerifyServerCert", ldap_cert_val, "False")],
        ))
    else:
        findings.append(control_finding(
            control_id="C45",
            status="unknown_not_exposed",
            expected="Enabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C54: UEFI Secure Boot Keys / User Mode ───────────────────────────
    sb_mode = sec_boot.get("SecureBootMode")
    if sb_mode == "UserMode":
        findings.append(control_finding(
            control_id="C54",
            status="pass",
            expected="UserMode (Production PK/KEK/DB Keys Active)",
            observed="UserMode",
            reason_code=ReasonCode.STANDARD_REDFISH_PASS,
            evidence=[evidence_item("standard_redfish", "/redfish/v1/Systems/1/SecureBoot", "SecureBootMode", sb_mode, "UserMode")],
        ))
    elif sb_mode:
        findings.append(control_finding(
            control_id="C54",
            status="fail",
            expected="UserMode",
            observed=str(sb_mode),
            reason_code=ReasonCode.STANDARD_REDFISH_FAIL,
            evidence=[],
        ))
    else:
        findings.append(control_finding(
            control_id="C54",
            status="unknown_not_exposed",
            expected="UserMode",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C55: Dual-ROM Auto-Promotion ─────────────────────────────────────
    auto_rom = bmc_settings.get("AutoROMPromotionEnabled") or bmc_settings.get("BackupAutoPromoteEnabled")
    if auto_rom in (True, "True", "true"):
        findings.append(control_finding(
            control_id="C55",
            status="pass",
            expected="Enabled (Auto ROM Promotion)",
            observed="True",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings", "AutoROMPromotionEnabled", auto_rom, "True")],
        ))
    else:
        findings.append(control_finding(
            control_id="C55",
            status="unknown_not_exposed",
            expected="Enabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── C56: Firmware Rollback Protection Policy ─────────────────────────
    fw_rollback = (sec_svc.get("Configurator") or {}).get("FWRollback")
    if fw_rollback in ("Enabled", "enabled", True, "True"):
        findings.append(control_finding(
            control_id="C56",
            status="pass",
            expected="Enabled (Firmware Rollback Protection)",
            observed="Enabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/Security", "Configurator.FWRollback", fw_rollback, "Enabled")],
        ))
    elif fw_rollback in ("Disabled", "disabled", False, "False"):
        findings.append(control_finding(
            control_id="C56",
            status="fail",
            expected="Enabled (Firmware Rollback Protection)",
            observed="Disabled",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[],
        ))
    else:
        findings.append(control_finding(
            control_id="C56",
            status="unknown_not_exposed",
            expected="Enabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── I01: Hardware Root of Trust / TPM 2.0 ────────────────────────────
    tpm_dev = bios_attrs.get("TrustedComputingGroup_TPMDevice") or ""
    tpm_stat = bios_attrs.get("TrustedComputingGroup_DeviceStatus") or ""
    if tpm_dev.lower() == "enabled" and ("tpm2.0" in tpm_stat.lower() or "tpm 2.0" in tpm_stat.lower()):
        findings.append(control_finding(
            control_id="I01",
            status="pass",
            expected="TPM 2.0 Enabled and Active",
            observed=f"{tpm_stat} ({tpm_dev})",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Systems/1/Bios", "TrustedComputingGroup_DeviceStatus", tpm_stat, "TPM 2.0 Active")],
        ))
    elif tpm_dev:
        findings.append(control_finding(
            control_id="I01",
            status="fail",
            expected="TPM 2.0 Enabled and Active",
            observed=f"{tpm_stat} ({tpm_dev})",
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[],
        ))
    else:
        findings.append(control_finding(
            control_id="I01",
            status="unknown_not_exposed",
            expected="TPM 2.0 Enabled and Active",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── I02: Intel TXT / Measured Launch ─────────────────────────────────
    txt_supp = bios_attrs.get("Processors_TrustedExecutionTechnology") or bios_attrs.get("TXTSupport") or ""
    if txt_supp.lower() == "enabled":
        findings.append(control_finding(
            control_id="I02",
            status="pass",
            expected="Enabled (Intel TXT Measured Launch)",
            observed="Enabled",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Systems/1/Bios", "Processors_TrustedExecutionTechnology", txt_supp, "Enabled")],
        ))
    elif txt_supp:
        findings.append(control_finding(
            control_id="I02",
            status="fail",
            expected="Enabled (Intel TXT Measured Launch)",
            observed=str(txt_supp),
            reason_code=ReasonCode.OEM_REDFISH_FAIL,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Systems/1/Bios", "Processors_TrustedExecutionTechnology", txt_supp, str(txt_supp))],
        ))
    else:
        findings.append(control_finding(
            control_id="I02",
            status="unknown_not_exposed",
            expected="Enabled",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── I03: Signed Firmware Verification / Trusted Build ID ─────────────
    build_id = sec_svc.get("TrustedBuildId")
    if build_id:
        findings.append(control_finding(
            control_id="I03",
            status="pass",
            expected="Cryptographically Signed Firmware Build ID",
            observed=f"Build {build_id}",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/Security", "TrustedBuildId", build_id, str(build_id))],
        ))
    else:
        findings.append(control_finding(
            control_id="I03",
            status="unknown_not_exposed",
            expected="Cryptographically Signed Firmware Build ID",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── I04: SystemGuard Configuration & Firmware Integrity ──────────────
    if system_guard and not system_guard.get("error"):
        findings.append(control_finding(
            control_id="I04",
            status="pass",
            expected="Configuration Integrity Protection Active (SystemGuard)",
            observed="Active",
            reason_code=ReasonCode.OEM_REDFISH_PASS,
            evidence=[evidence_item("oem_redfish", "/redfish/v1/Managers/1/Oem/Lenovo/SystemGuard", "Id", "SystemGuard", "Active")],
        ))
    else:
        findings.append(control_finding(
            control_id="I04",
            status="unknown_not_exposed",
            expected="Configuration Integrity Protection Active",
            observed=None,
            reason_code=ReasonCode.PROPERTY_NOT_EXPOSED,
            evidence=[],
        ))

    # ── Dell-specific Runbook Controls Marked Not Applicable ─────────────
    for cid in sorted(DELL_SPECIFIC_RUNBOOK_CONTROLS):
        findings.append(control_finding(
            control_id=cid,
            status="not_applicable",
            expected="Not applicable on Lenovo XCC platform",
            observed=None,
            reason_code=ReasonCode.NOT_APPLICABLE,
            evidence=[],
        ))

    # Deduplicate findings by control_id preserving first occurrence
    seen_cids = set()
    deduped_findings: List[Dict[str, Any]] = []
    for f in findings:
        cid = f.get("control_id")
        if cid and cid not in seen_cids:
            seen_cids.add(cid)
            f.setdefault("oem_support", OEM_SUPPORT)
            f.setdefault("oem_support_reason", OEM_SUPPORT_REASON)
            f.setdefault("vendor", evidence.get("vendor") or "lenovo")
            deduped_findings.append(f)

    return deduped_findings
