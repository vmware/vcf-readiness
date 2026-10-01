"""
VCF Readiness Tool — BMC security configuration and audit evidence collection mixin.
"""
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

from vcf_hci.security.contract import collection_issue, empty_security_evidence

from .collect_system import (
    _extract_bmc_timezone_info,
    _extract_dns_servers,
    _extract_ntp_servers,
    _parse_iso_datetime,
)

if TYPE_CHECKING:
    class _CollectorBase:
        sys_uri: Optional[str]
        chassis_uri: Optional[str]
        mgr_uri: Optional[str]
        sys_sku: str
        host: str
        port: int
        username: str
        password: str
        session_token: Optional[str]
        verify_ssl: bool
        ca_bundle: Optional[str]
        timeout: float
        host_timeout: float
        scan_start_time: Optional[float]
        cancel_event: Any
        skip_host_set: Any
        skipped: bool
        timed_out: bool
        auth_failed: bool
        chassis_management_info: dict
        stage_callback: Any
        vendor: str
        _PCIE_SWITCH_NAMES: tuple
        def _get(self, endpoint: str, _retry: bool = True, timeout: int = 15, critical: bool = True) -> Optional[dict]: ...
        def _get_members(self, endpoint_or_data: Any, limit: int = 0, max_pages: int = 100) -> list: ...
        def _get_oem_raw(self, uri: str, timeout: Optional[float] = None) -> Optional[dict]: ...
        def _is_cancelled_or_skipped(self) -> bool: ...
        @staticmethod
        def _is_license_blocked(data: Optional[dict]) -> Optional[str]: ...
        def _resolve_product_name(self, raw_obj: dict, pcie_cache: Optional[list] = None) -> str: ...
        def oem_bios_date(self, sys_data: dict) -> str: ...
        def oem_sku(self, sys_data: dict) -> str: ...
        def oem_storage_endpoints(self) -> list: ...
        def oem_drive_endurance(self, drive_json: dict) -> Optional[float]: ...
        def oem_drive_metrics(self, drive_json: dict) -> dict: ...
        def oem_nic_firmware(self, adapter_json: dict) -> str: ...
        def oem_cpu_cache(self, proc_json: dict) -> list: ...
        def oem_memory_usage(self, sys_data: dict) -> dict: ...
        def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict: ...
        def oem_os_info(self, sys_data: dict) -> dict: ...
        def oem_handle_retry(self, data: dict, endpoint: str) -> bool: ...
        def oem_manager_paths(self) -> list: ...
        def oem_fastpath_roots(self) -> Optional[Tuple[list, list, list]]: ...
        def oem_security_evidence(self) -> dict: ...
else:
    _CollectorBase = object

logger = logging.getLogger("vcf_assess")


class _BmcSecurityMixin(_CollectorBase):
    """Mixin providing BMC security configuration hardening and evidence collection."""

    def _collect_syslog_info(self, net_proto: dict) -> tuple:
        """Helper to collect (syslog_enabled: bool, syslog_servers: list[str])."""
        syslog_enabled = False
        syslog_servers: list = []

        def _add_srv(addr):
            s = str(addr or "").strip()
            if s and s.lower() not in ("none", "null", "0.0.0.0", "disabled", "false", "") and s not in syslog_servers:
                syslog_servers.append(s)

        # 1. NetworkProtocol DMTF standard & generic keys
        for key in ("Syslog", "SyslogService", "SyslogServer", "RemoteSyslog"):
            cfg = net_proto.get(key) or {}
            if isinstance(cfg, dict):
                if cfg.get("ProtocolEnabled") or cfg.get("ServiceEnabled") or cfg.get("Enabled") or cfg.get("SyslogEnable"):
                    syslog_enabled = True
                # Extract servers from list
                for srv in (cfg.get("RemoteServers") or cfg.get("Servers") or cfg.get("SyslogServers") or []):
                    if isinstance(srv, dict):
                        _add_srv(srv.get("Address") or srv.get("IPAddress") or srv.get("HostName") or srv.get("Host") or srv.get("Server"))
                    elif isinstance(srv, str):
                        _add_srv(srv)
                for _k in ("Address", "IPAddress", "HostName", "Host", "Server", "RemoteServer", "SyslogServer"):
                    if cfg.get(_k):
                        _add_srv(cfg.get(_k))
                        syslog_enabled = True

        # 2. NetworkProtocol OEM keys (Dell, HPE, Supermicro, Cisco, Lenovo, Asrock, Asus)
        oem = net_proto.get("Oem") or {}
        dell_oem = oem.get("Dell") or {}
        if dell_oem.get("RemoteSyslogEnabled"):
            syslog_enabled = True
            for _k in ("RemoteSyslogServer", "RemoteSyslogServer1", "RemoteSyslogServer2", "RemoteSyslogServer3"):
                _add_srv(dell_oem.get(_k))

        hpe_oem = (oem.get("Hpe") or oem.get("HpCommon") or {})
        hpe_syslog = hpe_oem.get("RemoteSyslog") or {}
        if hpe_syslog.get("Enabled") or hpe_syslog.get("SyslogEnable"):
            syslog_enabled = True
            for _k in ("SyslogServer", "Server"):
                _add_srv(hpe_syslog.get(_k))

        smc_syslog = (oem.get("Supermicro") or {}).get("SyslogConfiguration") or {}
        if smc_syslog.get("SyslogEnable") or smc_syslog.get("Enable"):
            syslog_enabled = True
            for _k in ("SyslogServer1", "SyslogServer2", "Server"):
                _entry = smc_syslog.get(_k) or {}
                if isinstance(_entry, dict):
                    _add_srv(_entry.get("Address"))
                else:
                    _add_srv(_entry)

        # 3. LogServices probe under Manager if not yet found
        if not syslog_servers and self.mgr_uri:
            log_svc_members = self._get_members(f"{self.mgr_uri}/LogServices")
            for m in log_svc_members:
                m_id = str(m.get("@odata.id") or "")
                if "syslog" in m_id.lower() or "audit" in m_id.lower() or "sel" in m_id.lower():
                    ls = self._get(m_id)
                    if not ls:
                        continue
                    if ls.get("ServiceEnabled") or ls.get("SyslogEnable") or ls.get("Enabled"):
                        syslog_enabled = True
                    _rs = ls.get("SyslogFilter") or ls.get("SyslogServers") or ls.get("RemoteServers") or ls.get("Syslog") or {}
                    if isinstance(_rs, dict):
                        for _k in ("Address", "IPAddress", "HostName", "Server", "SyslogServer"):
                            if _rs.get(_k):
                                _add_srv(_rs.get(_k))
                                syslog_enabled = True
                    elif isinstance(_rs, list):
                        for item in _rs:
                            if isinstance(item, dict):
                                _add_srv(item.get("Address") or item.get("IPAddress") or item.get("HostName"))
                            elif isinstance(item, str):
                                _add_srv(item)

        if syslog_servers:
            syslog_enabled = True

        return syslog_enabled, syslog_servers

    def collect_bmc_security_config(self) -> dict:
        """Check BMC OOB security hardening posture via NetworkProtocol, AccountService, SessionService.

        Checks (in order):
          1. Remote syslog — is a SIEM/log destination configured on the BMC?
          2. HTTP disabled — plain HTTP should be off; HTTPS only.
          3. Telnet disabled — cleartext admin access.
          4. SNMP version — SNMPv1/v2c community strings vs SNMPv3 AuthPriv.
          5. IPMI over LAN — cipher-0 / replay vulnerabilities; disable if unused.
          6. Account lockout — threshold > 0 to block brute-force.
          7. Minimum password length — >= 8 chars baseline.
          8. Session timeout — idle session should auto-expire.

        Returns {"checks": [{"feature", "badge", "label", "note"}, ...], "overall_badge": str}.
        """
        checks = []

        # --- /Managers/{id}/NetworkProtocol ---
        net_proto = {}
        if self.mgr_uri:
            net_proto = self._get(f"{self.mgr_uri}/NetworkProtocol") or {}

        # 1. Remote syslog
        syslog_enabled, syslog_servers = self._collect_syslog_info(net_proto)

        if syslog_enabled and syslog_servers:
            _sl_label = f"Configured ({', '.join(syslog_servers[:2])}{'…' if len(syslog_servers) > 2 else ''})"
            _sl_note  = "BMC remote syslog is active — hardware events will forward to your SIEM or log target."
            _sl_badge = "success"
        elif syslog_enabled:
            _sl_label = "Enabled (no server configured)"
            _sl_note  = "Syslog is enabled but no destination address is set. Configure a remote syslog target."
            _sl_badge = "warning"
        else:
            _sl_label = "Not Configured"
            _sl_note  = (
                "No remote syslog destination found on this BMC. Configure syslog to forward "
                "hardware events and audit logs to a SIEM. If no SIEM is in use, "
                "VMware Aria Operations for Logs is the recommended target for VCF environments."
            )
            _sl_badge = "warning"
        checks.append({"feature": "BMC Remote Syslog", "badge": _sl_badge, "label": _sl_label, "note": _sl_note})

        if net_proto:
            # 2. HTTP (plaintext) access
            http_cfg = (net_proto.get("HTTP") or {}) if isinstance(net_proto, dict) else {}
            http_on = http_cfg.get("ProtocolEnabled") if isinstance(http_cfg, dict) else None
            if http_on is True:
                checks.append({
                    "feature": "BMC HTTP (Plaintext)",
                    "badge":   "warning",
                    "label":   "Enabled — disable",
                    "note":    "Plain HTTP exposes BMC credentials in transit. Disable in BMC network settings; use HTTPS only.",
                })
            elif http_on is False:
                checks.append({
                    "feature": "BMC HTTP (Plaintext)",
                    "badge":   "success",
                    "label":   "Disabled (HTTPS only)",
                    "note":    "Plaintext HTTP access to the BMC is disabled.",
                })
            else:
                checks.append({
                    "feature": "BMC HTTP (Plaintext)",
                    "badge":   "info",
                    "label":   "Not Exposed",
                    "note":    "Plaintext HTTP access state not exposed via Redfish NetworkProtocol.",
                })

            # 3. Telnet
            telnet_cfg = (net_proto.get("Telnet") or {}) if isinstance(net_proto, dict) else {}
            telnet_on = telnet_cfg.get("ProtocolEnabled") if isinstance(telnet_cfg, dict) else None
            if telnet_on is True:
                checks.append({
                    "feature": "BMC Telnet",
                    "badge":   "danger",
                    "label":   "Enabled — disable immediately",
                    "note":    "Telnet sends credentials in cleartext. Disable in BMC network settings and use SSH.",
                })
            elif telnet_on is False:
                checks.append({
                    "feature": "BMC Telnet",
                    "badge":   "success",
                    "label":   "Disabled",
                    "note":    "Telnet is disabled.",
                })
            else:
                checks.append({
                    "feature": "BMC Telnet",
                    "badge":   "info",
                    "label":   "Not Exposed",
                    "note":    "Telnet protocol status not exposed via Redfish NetworkProtocol.",
                })

            # 4. SNMP version
            snmp_cfg  = (net_proto.get("SNMP") or {}) if isinstance(net_proto, dict) else {}
            snmp_on   = snmp_cfg.get("ProtocolEnabled") if isinstance(snmp_cfg, dict) else None
            snmp_auth = str(snmp_cfg.get("AuthenticationProtocol") or "").upper() if isinstance(snmp_cfg, dict) else ""
            if snmp_on is True:
                if any(x in snmp_auth for x in ("MD5", "SHA", "SHA1", "SHA256", "SHA384", "SHA512")):
                    checks.append({
                        "feature": "SNMP",
                        "badge":   "success",
                        "label":   f"SNMPv3 ({snmp_auth})",
                        "note":    "SNMPv3 with authentication is configured on this BMC.",
                    })
                elif not snmp_auth:
                    checks.append({
                        "feature": "SNMP",
                        "badge":   "info",
                        "label":   "Enabled (version not exposed)",
                        "note":    "SNMP is enabled. Verify SNMPv3 AuthPriv is in use; disable SNMPv1/v2c community strings.",
                    })
                else:
                    checks.append({
                        "feature": "SNMP",
                        "badge":   "warning",
                        "label":   "SNMPv1/v2c (community-based)",
                        "note":    "Disable SNMPv1/v2c. Migrate to SNMPv3 with AuthPriv to meet CIS/STIG baselines.",
                    })
            elif snmp_on is False:
                checks.append({
                    "feature": "SNMP",
                    "badge":   "info",
                    "label":   "Disabled",
                    "note":    "SNMP is not in use on this BMC.",
                })
            else:
                checks.append({
                    "feature": "SNMP",
                    "badge":   "info",
                    "label":   "Not Exposed",
                    "note":    "SNMP protocol status not exposed via Redfish NetworkProtocol.",
                })

            # 5. IPMI over LAN (cipher-0 / replay attack surface)
            ipmi_cfg = (net_proto.get("IPMI") or {}) if isinstance(net_proto, dict) else {}
            ipmi_on = ipmi_cfg.get("ProtocolEnabled") if isinstance(ipmi_cfg, dict) else None
            if ipmi_on is True:
                checks.append({
                    "feature": "IPMI over LAN",
                    "badge":   "warning",
                    "label":   "Enabled",
                    "note":    "IPMI/IPMILAN over LAN has known CVEs (cipher-0 auth bypass). Disable if not required; manage via Redfish or SSH instead.",
                })
            elif ipmi_on is False:
                checks.append({
                    "feature": "IPMI over LAN",
                    "badge":   "success",
                    "label":   "Disabled",
                    "note":    "IPMI over LAN is disabled. OOB management uses Redfish API.",
                })
            else:
                checks.append({
                    "feature": "IPMI over LAN",
                    "badge":   "info",
                    "label":   "Not Exposed",
                    "note":    "IPMI over LAN protocol status not exposed via Redfish NetworkProtocol.",
                })
        else:
            ipmi_on = None
            for feat, note_text in (
                ("BMC HTTP (Plaintext)", "Plaintext HTTP access state not exposed via Redfish NetworkProtocol."),
                ("BMC Telnet", "Telnet protocol status not exposed via Redfish NetworkProtocol."),
                ("SNMP", "SNMP protocol status not exposed via Redfish NetworkProtocol."),
                ("IPMI over LAN", "IPMI over LAN protocol status not exposed via Redfish NetworkProtocol."),
            ):
                checks.append({
                    "feature": feat,
                    "badge":   "info",
                    "label":   "Not Exposed",
                    "note":    note_text,
                })

        # --- /AccountService ---
        acct_svc          = self._get("/AccountService") or {} if isinstance(self._get("/AccountService"), dict) else {}
        lockout_threshold = (
            acct_svc.get("AccountLockoutThreshold")
            if acct_svc.get("AccountLockoutThreshold") is not None
            else acct_svc.get("LockoutThreshold")
        ) if isinstance(acct_svc, dict) else None
        min_pw_len        = acct_svc.get("MinPasswordLength") if isinstance(acct_svc, dict) else None

        _lt_added = False
        if lockout_threshold is not None:
            try:
                _lt = int(lockout_threshold)
                if _lt == 0:
                    checks.append({
                        "feature": "Account Lockout",
                        "badge":   "warning",
                        "label":   "Disabled (threshold = 0)",
                        "note":    "Enable account lockout (≤5 failed attempts recommended) to block brute-force attacks.",
                    })
                else:
                    checks.append({
                        "feature": "Account Lockout",
                        "badge":   "success",
                        "label":   f"Enabled (after {_lt} attempts)",
                        "note":    f"BMC will lock accounts after {_lt} failed login attempts.",
                    })
                _lt_added = True
            except (ValueError, TypeError):
                pass
        if not _lt_added:
            checks.append({
                "feature": "Account Lockout",
                "badge":   "info",
                "label":   "Not Exposed",
                "note":    "Account lockout threshold not exposed via Redfish AccountService.",
            })

        _pw_added = False
        if min_pw_len is not None:
            try:
                _ml = int(min_pw_len)
                if _ml < 8:
                    checks.append({
                        "feature": "Min Password Length",
                        "badge":   "warning",
                        "label":   f"{_ml} chars (below baseline)",
                        "note":    "Set minimum BMC password length to ≥ 8 characters per VCF security baseline.",
                    })
                else:
                    checks.append({
                        "feature": "Min Password Length",
                        "badge":   "success",
                        "label":   f"{_ml} chars",
                        "note":    "Minimum password length meets baseline.",
                    })
                _pw_added = True
            except (ValueError, TypeError):
                pass
        if not _pw_added:
            checks.append({
                "feature": "Min Password Length",
                "badge":   "info",
                "label":   "Not Exposed",
                "note":    "Minimum password length not exposed via Redfish AccountService.",
            })

        # --- /SessionService ---
        sess_svc     = self._get("/SessionService") or {} if isinstance(self._get("/SessionService"), dict) else {}
        sess_timeout = sess_svc.get("SessionTimeout") if isinstance(sess_svc, dict) else None
        _st_added = False
        if sess_timeout is not None:
            try:
                _st = int(sess_timeout)
                if _st == 0:
                    checks.append({
                        "feature": "BMC Session Timeout",
                        "badge":   "warning",
                        "label":   "No timeout (unlimited)",
                        "note":    "Configure a session timeout (≤ 1800 s / 30 min) to limit idle session exposure.",
                    })
                elif _st > 3600:
                    checks.append({
                        "feature": "BMC Session Timeout",
                        "badge":   "warning",
                        "label":   f"{_st} s (> 1 hour)",
                        "note":    f"Session timeout of {_st} s is very long. Reduce to ≤ 1800 s for the VCF hardening baseline.",
                    })
                else:
                    checks.append({
                        "feature": "BMC Session Timeout",
                        "badge":   "success",
                        "label":   f"{_st // 60} min ({_st} s)",
                        "note":    "Session timeout is within the recommended range.",
                    })
                _st_added = True
            except (ValueError, TypeError):
                pass
        if not _st_added:
            checks.append({
                "feature": "BMC Session Timeout",
                "badge":   "info",
                "label":   "Not Exposed",
                "note":    "Session timeout not exposed via Redfish SessionService.",
            })

        # --- NTP & Time Drift checks ---
        ntp_servers = _extract_ntp_servers(net_proto)
        ntp_obj = net_proto.get("NTP") or {} if isinstance(net_proto, dict) else {}
        ntp_enabled = bool(
            ntp_obj.get("ProtocolEnabled", False)
            or ntp_obj.get("Enabled", False)
            or ntp_obj.get("ServiceEnabled", False)
        )

        if ntp_enabled and ntp_servers:
            _ntp_label = f"Configured ({', '.join(ntp_servers[:2])}{'…' if len(ntp_servers) > 2 else ''})"
            _ntp_note  = "NTP time synchronization is active on the BMC with valid server(s)."
            _ntp_badge = "success"
        elif ntp_enabled:
            _ntp_label = "Enabled (no servers configured)"
            _ntp_note  = "NTP protocol is enabled on the BMC, but no servers are configured. Time drift may occur."
            _ntp_badge = "warning"
        else:
            _ntp_label = "Disabled"
            _ntp_note  = "NTP is disabled on the BMC. Configure NTP servers to avoid time-skew issues in VCF."
            _ntp_badge = "warning"
        checks.append({"feature": "NTP Server Configuration", "badge": _ntp_badge, "label": _ntp_label, "note": _ntp_note})

        # --- DNS checks ---
        dns_servers = _extract_dns_servers(net_proto)
        dns_obj = net_proto.get("DNS") or net_proto.get("Dns") or {} if isinstance(net_proto, dict) else {}
        dns_enabled = bool(
            dns_obj.get("ProtocolEnabled", False)
            or dns_obj.get("Enabled", False)
            or dns_obj.get("ServiceEnabled", False)
        )
        if dns_servers:
            _dns_label = f"Configured ({', '.join(dns_servers[:2])}{'…' if len(dns_servers) > 2 else ''})"
            _dns_note  = "DNS name servers configured on BMC for name resolution."
            _dns_badge = "success"
        elif dns_enabled:
            _dns_label = "Enabled (no servers configured)"
            _dns_note  = "DNS protocol enabled on BMC, but no DNS name servers are configured."
            _dns_badge = "warning"
        else:
            _dns_label = "Not Configured"
            _dns_note  = "DNS name servers are not configured on the BMC."
            _dns_badge = "info"
        checks.append({"feature": "DNS Configuration", "badge": _dns_badge, "label": _dns_label, "note": _dns_note})

        # BMC Manager DateTime & Timezone checks
        mgr_data = self._get(self.mgr_uri) or {} if self.mgr_uri else {}
        bmc_dt_raw = mgr_data.get("DateTime") if isinstance(mgr_data, dict) else None
        tz_info = _extract_bmc_timezone_info(mgr_data, bmc_dt_raw)

        # BMC Timezone (UTC Baseline) check
        if tz_info["is_utc"]:
            _tz_badge = "success"
            _tz_label = f"UTC Standard ({tz_info['offset_str']})"
            _tz_note  = "BMC timezone is configured for UTC (compliant with VCF 9.1 time baseline)."
        elif tz_info["offset_str"] != "Unknown":
            _tz_badge = "warning"
            _tz_label = f"Non-UTC Offset ({tz_info['offset_str']})"
            _tz_note  = (
                f"BMC uses local timezone offset {tz_info['offset_str']} (VCF requires UTC across all BMCs). "
                f"Set BMC timezone to UTC to prevent certificate validation and authentication failures. "
                f"Remediation: (Dell) racadm set iDRAC.Time.Timezone UTC | (HPE) set /system1/timezone UTC"
            )
        else:
            _tz_badge = "info"
            _tz_label = "Not Exposed"
            _tz_note  = "BMC timezone offset not exposed by firmware."
        checks.append({"feature": "BMC Timezone", "badge": _tz_badge, "label": _tz_label, "note": _tz_note})

        # BMC Time Drift check
        if bmc_dt_raw:
            bmc_dt = _parse_iso_datetime(str(bmc_dt_raw))
            if bmc_dt:
                now_utc = datetime.now(timezone.utc)
                drift_sec = int(round((bmc_dt - now_utc).total_seconds()))
                abs_drift = abs(drift_sec)
                mins = abs_drift // 60
                secs = abs_drift % 60
                drift_fmt = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
                if abs_drift > 300:  # > 5 minutes
                    _td_badge = "danger" if abs_drift > 1800 else "warning"
                    _td_label = f"Time Drift Detected ({drift_fmt} skew)"
                    _tz_extra = ""
                    if not tz_info["is_utc"] and tz_info["offset_minutes"] != 0:
                        _tz_extra = f" (includes {abs(tz_info['offset_minutes'])}m timezone offset {tz_info['offset_str']})"
                    _td_note  = f"BMC clock differs from scan time by {drift_fmt}{_tz_extra} (BMC time: {bmc_dt_raw}). Correct BMC time/NTP and verify UTC timezone to prevent VCF certificate and authentication failures."
                else:
                    _td_badge = "success"
                    _td_label = f"In Sync ({drift_fmt} offset)"
                    _td_note  = f"BMC clock is synchronized with scan time (within 5 min threshold; offset: {drift_fmt})."
            else:
                _td_badge = "info"
                _td_label = "DateTime Unparseable"
                _td_note  = f"BMC DateTime value '{bmc_dt_raw}' could not be parsed as an ISO timestamp."
        else:
            _td_badge = "info"
            _td_label = "Not Exposed"
            _td_note  = "BMC Manager DateTime attribute not exposed by firmware."
        checks.append({"feature": "BMC Time Drift", "badge": _td_badge, "label": _td_label, "note": _td_note})

        # Overall worst-of badge
        if any(c["badge"] == "danger"  for c in checks):
            overall = "danger"
        elif any(c["badge"] == "warning" for c in checks):
            overall = "warning"
        elif checks and all(c["badge"] in ("success", "info") for c in checks):
            overall = "success"
        else:
            overall = "info"

        # Top-level indicators
        https_cfg = (net_proto.get("HTTPS") or {}) if isinstance(net_proto, dict) else {}
        https_on = https_cfg.get("ProtocolEnabled") if isinstance(https_cfg, dict) else None
        tls_ver = "TLS 1.2+" if https_on is True else None

        return {
            "checks": checks,
            "overall_badge": overall,
            "ipmi_lan_enabled": ipmi_on if isinstance(ipmi_on, bool) else None,
            "tls_version": tls_ver,
        }

    @staticmethod
    def _filter_network_protocol_evidence(raw_np: dict, uri: str) -> dict:
        proto_fields = (
            "ProtocolEnabled",
            "Port",
            "TimeoutSeconds",
            "EncryptionEnabled",
            "AuthenticationEnabled",
            "AuthenticationProtocol",
            "EncryptionProtocol",
            "CipherSuite",
            "SSLCipherSuite",
            "TLSVersion",
            "MinimumTLSVersion",
            "MaximumTLSVersion",
        )
        proto_names = (
            "HTTP",
            "HTTPS",
            "IPMI",
            "KVMIP",
            "NTP",
            "RDP",
            "RFB",
            "SNMP",
            "SSDP",
            "SSH",
            "Telnet",
            "VirtualMedia",
        )
        res: Dict[str, Any] = {
            "uri": uri,
            "@odata.type": raw_np.get("@odata.type"),
        }
        for name in proto_names:
            p_data = raw_np.get(name)
            if isinstance(p_data, dict):
                filtered_p: Dict[str, Any] = {k: p_data[k] for k in proto_fields if k in p_data}
                if name == "NTP":
                    for key in ("NTPServers", "StaticNTPServers", "NetworkSuppliedServers"):
                        if key in p_data:
                            val = p_data[key]
                            if isinstance(val, bool):
                                filtered_p[f"{key}Enabled"] = val
                            elif isinstance(val, (list, tuple)):
                                filtered_p[f"{key}Count"] = len(val)
                if "Certificates" in p_data and isinstance(p_data["Certificates"], dict):
                    filtered_p["CertificatesCount"] = 1
                res[name] = filtered_p
        return res

    @staticmethod
    def _filter_account_service_evidence(raw_acct: dict, uri: str) -> dict:
        acct_fields = (
            "@odata.type",
            "ServiceEnabled",
            "AuthFailureLoggingThreshold",
            "MinPasswordLength",
            "MaxPasswordLength",
            "AccountLockoutDuration",
            "AccountLockoutCounterResetAfter",
            "AccountLockoutCounterResetEnabled",
            "LocalAccountAuth",
        )
        res: Dict[str, Any] = {
            "uri": uri,
        }
        for k in acct_fields:
            if k in raw_acct:
                res[k] = raw_acct[k]

        # Mandatory DMTF property with fallback
        if "AccountLockoutThreshold" in raw_acct:
            res["AccountLockoutThreshold"] = raw_acct["AccountLockoutThreshold"]
        elif "LockoutThreshold" in raw_acct:
            res["AccountLockoutThreshold"] = raw_acct["LockoutThreshold"]

        # Directory services
        for ds_name in ("ActiveDirectory", "LDAP", "OAuth2", "TACACSplus", "RADIUS"):
            ds_data = raw_acct.get(ds_name)
            if isinstance(ds_data, dict):
                filtered_ds: Dict[str, Any] = {}
                for k in ("ServiceEnabled", "CertificateValidationEnabled", "AuthenticationType", "EncryptionType"):
                    if k in ds_data:
                        filtered_ds[k] = ds_data[k]
                for k in ("ServiceAddresses", "RemoteRoleMapping", "Certificates", "Domains", "SearchSettings"):
                    if k in ds_data and isinstance(ds_data[k], (list, tuple)):
                        filtered_ds[f"{k}Count"] = len(ds_data[k])
                res[ds_name] = filtered_ds

        # MFA
        mfa = raw_acct.get("MultiFactorAuth")
        if isinstance(mfa, dict):
            filtered_mfa: Dict[str, Any] = {}
            for k, item in mfa.items():
                if isinstance(item, dict):
                    filtered_item = {ik: item[ik] for ik in ("ServiceEnabled", "CertificateValidationEnabled", "AuthenticationType") if ik in item}
                    if filtered_item:
                        filtered_mfa[str(k)] = filtered_item
            if filtered_mfa:
                res["MultiFactorAuth"] = filtered_mfa

        return res

    @staticmethod
    def _filter_session_service_evidence(raw_sess: dict, uri: str) -> dict:
        res: Dict[str, Any] = {"uri": uri}
        for k in ("@odata.type", "ServiceEnabled", "SessionTimeout"):
            if k in raw_sess:
                res[k] = raw_sess[k]
        if "Sessions" in raw_sess:
            res["SessionsExposed"] = True
        return res

    @staticmethod
    def _filter_secure_boot_evidence(raw_sb: dict, uri: str) -> dict:
        res: Dict[str, Any] = {"uri": uri}
        for k in ("@odata.type", "SecureBootEnable", "SecureBootCurrentBoot", "SecureBootMode"):
            if k in raw_sb:
                res[k] = raw_sb[k]
        status = raw_sb.get("Status")
        if isinstance(status, dict) and "State" in status:
            res["StatusState"] = status["State"]
        return res

    @staticmethod
    def _filter_certificate_service_evidence(raw_cert: dict, uri: str) -> dict:
        res: Dict[str, Any] = {"uri": uri}
        for k in ("@odata.type", "ServiceEnabled"):
            if k in raw_cert:
                res[k] = raw_cert[k]
        for k in ("Certificates", "CertificateLocations"):
            if k in raw_cert and isinstance(raw_cert[k], (list, tuple)):
                res[f"{k}Count"] = len(raw_cert[k])
        return res

    def collect_bmc_security_evidence(self) -> Dict[str, Any]:
        """Collect standard DMTF Redfish security evidence and OEM security evidence.

        GET-only audit collection covering:
        - Manager NetworkProtocol (HTTPS, SSH, Telnet, HTTP, IPMI, SNMP, NTP, etc.)
        - AccountService (AccountLockoutThreshold, Password length, Directory services, MFA)
        - SessionService (SessionTimeout, Sessions link)
        - SecureBoot (SecureBootEnable, SecureBootCurrentBoot, SecureBootMode)
        - CertificateService (ServiceEnabled, CertificateLocations count)
        - OEM security evidence via self.oem_security_evidence()

        Returns:
            Dictionary matching EVIDENCE_SCHEMA_VERSION from vcf_hci.security.contract.
        """
        vendor = getattr(self, "vendor", "generic") or "generic"
        evidence = empty_security_evidence(vendor)
        collection_issues = evidence["collection_issues"]
        standard = evidence["standard"]

        # 1. Manager NetworkProtocol
        net_proto_uri = None
        if self.mgr_uri:
            mgr_data = self._get(self.mgr_uri) if hasattr(self, "_get") else {}
            if isinstance(mgr_data, dict) and "NetworkProtocol" in mgr_data:
                np_link = mgr_data["NetworkProtocol"]
                if isinstance(np_link, dict):
                    net_proto_uri = np_link.get("@odata.id")
            if not net_proto_uri:
                net_proto_uri = f"{self.mgr_uri}/NetworkProtocol"

        if net_proto_uri:
            raw_np = self._get(net_proto_uri) if hasattr(self, "_get") else None
            if isinstance(raw_np, dict) and not raw_np.get("error"):
                standard["network_protocol"] = self._filter_network_protocol_evidence(raw_np, net_proto_uri)
            else:
                collection_issues.append(collection_issue(
                    endpoint=net_proto_uri,
                    reason="NetworkProtocol not exposed or returned non-200",
                ))
        else:
            collection_issues.append(collection_issue(
                endpoint="/redfish/v1/Managers/{id}/NetworkProtocol",
                reason="Manager URI not discovered",
            ))

        # 2. AccountService
        acct_uri = "/redfish/v1/AccountService"
        raw_acct = self._get(acct_uri) if hasattr(self, "_get") else None
        if not raw_acct:
            acct_uri = "/AccountService"
            raw_acct = self._get(acct_uri) if hasattr(self, "_get") else None

        if isinstance(raw_acct, dict) and not raw_acct.get("error"):
            standard["account_service"] = self._filter_account_service_evidence(raw_acct, acct_uri)
        else:
            collection_issues.append(collection_issue(
                endpoint="/redfish/v1/AccountService",
                reason="AccountService not exposed or returned non-200",
            ))

        # 3. SessionService
        sess_uri = "/redfish/v1/SessionService"
        raw_sess = self._get(sess_uri) if hasattr(self, "_get") else None
        if not raw_sess:
            sess_uri = "/SessionService"
            raw_sess = self._get(sess_uri) if hasattr(self, "_get") else None

        if isinstance(raw_sess, dict) and not raw_sess.get("error"):
            standard["session_service"] = self._filter_session_service_evidence(raw_sess, sess_uri)
        else:
            collection_issues.append(collection_issue(
                endpoint="/redfish/v1/SessionService",
                reason="SessionService not exposed or returned non-200",
            ))

        # 4. SecureBoot
        sb_uri = None
        if self.sys_uri:
            sys_data = self._get(self.sys_uri) if hasattr(self, "_get") else {}
            if isinstance(sys_data, dict) and "SecureBoot" in sys_data:
                sb_link = sys_data["SecureBoot"]
                if isinstance(sb_link, dict):
                    sb_uri = sb_link.get("@odata.id")
            if not sb_uri:
                sb_uri = f"{self.sys_uri}/SecureBoot"

        if sb_uri:
            raw_sb = self._get(sb_uri) if hasattr(self, "_get") else None
            if isinstance(raw_sb, dict) and not raw_sb.get("error"):
                standard["secure_boot"] = self._filter_secure_boot_evidence(raw_sb, sb_uri)
            else:
                collection_issues.append(collection_issue(
                    endpoint=sb_uri,
                    reason="SecureBoot not exposed or returned non-200",
                ))
        else:
            collection_issues.append(collection_issue(
                endpoint="/redfish/v1/Systems/{id}/SecureBoot",
                reason="System URI not discovered",
            ))

        # 5. CertificateService (optional discovery)
        cert_uri = "/redfish/v1/CertificateService"
        raw_cert = self._get(cert_uri) if hasattr(self, "_get") else None
        if isinstance(raw_cert, dict) and not raw_cert.get("error"):
            standard["certificate_service"] = self._filter_certificate_service_evidence(raw_cert, cert_uri)

        # 6. Safe BIOS security attributes
        if getattr(self, "sys_uri", None):
            bios_uri = f"{self.sys_uri}/Bios"
            raw_bios = self._get(bios_uri) if hasattr(self, "_get") else None
            if isinstance(raw_bios, dict) and not raw_bios.get("error"):
                bios_attrs = raw_bios.get("Attributes") or {}
                if isinstance(bios_attrs, dict):
                    safe_bios_keys = {
                        "pwrbutton",
                        "powerbutton",
                        "uefivariableaccess",
                        "uefivariableaccessfwcontrol",
                        "secureboot",
                        "securebootmode",
                        "securebootpolicy",
                        "securebootstatus",
                    }
                    filtered_bios = {
                        k: v for k, v in bios_attrs.items()
                        if k.lower() in safe_bios_keys
                    }
                    if filtered_bios:
                        standard["bios_attributes"] = filtered_bios

        # 7. OEM security evidence via hook
        if hasattr(self, "oem_security_evidence"):
            try:
                evidence["oem"] = self.oem_security_evidence() or {}
            except Exception as exc:
                logger.debug("oem_security_evidence raised exception: %s", exc)
                collection_issues.append(collection_issue(
                    endpoint="oem_security_evidence",
                    reason=f"OEM collection error: {exc}",
                ))

        # 8. ComponentIntegrity (SPDM 1.2 Hardware Measurements & Root of Trust)
        ci_uri = "/redfish/v1/ComponentIntegrity"
        raw_ci = self._get(ci_uri) if hasattr(self, "_get") else None
        if isinstance(raw_ci, dict) and not raw_ci.get("error"):
            members = self._get_members(raw_ci) if hasattr(self, "_get_members") else (raw_ci.get("Members") or [])
            spdm_records = []
            for m in members:
                m_obj = m
                if isinstance(m, dict) and "@odata.id" in m and len(m) == 1:
                    m_obj = self._get(m["@odata.id"]) if hasattr(self, "_get") else None
                if isinstance(m_obj, dict) and not m_obj.get("error"):
                    itype = m_obj.get("ComponentIntegrityType")
                    target = m_obj.get("TargetComponentURI") or m_obj.get("Id")
                    spdm_info = m_obj.get("SPDM") or {}
                    oem_spdm = (m_obj.get("Oem") or {}).get("Dell", {}).get("SPDM", {}) if isinstance(m_obj.get("Oem"), dict) else {}
                    challenge_st = oem_spdm.get("DeviceChallengeStatus") or "Success"
                    m_set = spdm_info.get("MeasurementSet") or {}
                    m_count = len(m_set.get("Measurements") or []) if isinstance(m_set, dict) else 0
                    spdm_records.append({
                        "id": m_obj.get("Id", ""),
                        "type": str(itype or "SPDM"),
                        "version": str(m_obj.get("ComponentIntegrityTypeVersion") or "1.2"),
                        "target": str(target or ""),
                        "status": str(challenge_st),
                        "measurement_count": m_count,
                        "enabled": bool(m_obj.get("ComponentIntegrityEnabled", True)),
                    })
            if spdm_records:
                evidence["standard"]["component_integrity"] = spdm_records
                evidence["capabilities"]["spdm_integrity"] = spdm_records

        # 9. Supply Chain Verification (e.g. Dell SCV)
        idrac_attrs = (evidence.get("oem") or {}).get("idrac_attributes") or {}
        scv_ver = None
        for k, v in idrac_attrs.items():
            if "scv." in k.lower() and "certificateversion" in k.lower() and "firmware" not in k.lower():
                scv_ver = v
                break
        if scv_ver and str(scv_ver).strip().upper() not in ("NA", "NONE", ""):
            evidence["capabilities"]["dell_scv"] = str(scv_ver).strip()

        # 10. Cisco ACT2 Hardware Root of Trust (SUDI) & Manager Mode
        cisco_oem_sec = evidence.get("oem") or {}
        if isinstance(cisco_oem_sec, dict):
            sudi_info = cisco_oem_sec.get("hardware_sudi") or {}
            if isinstance(sudi_info, dict) and sudi_info.get("present"):
                evidence["capabilities"]["cisco_sudi"] = sudi_info.get("identity_type", "ACT2 ECC SUDI")
            mgr_mode = cisco_oem_sec.get("manager_mode")
            if mgr_mode:
                evidence["capabilities"]["cisco_manager_mode"] = str(mgr_mode).strip()

        return evidence
