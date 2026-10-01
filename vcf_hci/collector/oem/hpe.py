"""
VCF Readiness Tool — HPE iLO (ProLiant) OEM adapter.

Overrides OEM hook methods to read HPE-specific Redfish extensions:
  • BIOS release date  : Oem.Hpe.Bios.Current.Date
  • SKU / ProductId    : Oem.Hpe.ProductId
  • CPU cache          : Oem.Hpe.Cache[]
  • Memory usage       : Oem.Hpe.SystemUsage (CPU/mem utilization without TelemetryService)
  • License info       : Oem.Hpe.License.LicenseKey / LicenseTier
  • NIC firmware       : Oem.Hpe.AdapterDetails (used in collect_network_adapters)
  • Retry handling     : ResourceNotReadyRetry on NetworkAdapters while BMC scans

Known HPE quirks (handled inline in base methods):
  • iLO returns ResourceNotReadyRetry when a BMC task is in progress — retry once with 3s delay.
  • SmartStorage hierarchy at /Systems/{id}/SmartStorage/ArrayControllers (not standard /Storage).
  • Oem.Hpe.SystemUsage provides live CPU/memory utilization when TelemetryService is absent.
  • DriveBayCount may only cover the SAS/SATA segment of a split backplane.
"""
from typing import Any, Dict, List, Optional, Set, Tuple

from ...logging_utils import get_nested
from ..base import ExpandableCollectionsMap
from .generic import GenericCollector


class HPECollector(GenericCollector):
    """HPE iLO Redfish adapter."""

    VENDOR_MATCH = ("HPE", "HEWLETT", "HP")  # matched against Manufacturer string upper()
    vendor: str = "hpe"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._hpe_resource_directory: Optional[Set[str]] = None

    def _load_hpe_resource_directory(self) -> Set[str]:
        """Query /redfish/v1/ResourceDirectory once and index all available URIs.

        HPE iLO 5, 6, and 7 expose a monolithic ResourceDirectory containing every available
        endpoint on the BMC. Pre-indexing these instances eliminates speculative 404 queries.
        """
        if self._hpe_resource_directory is not None:
            return self._hpe_resource_directory

        rd_data = self._get("/redfish/v1/ResourceDirectory", critical=False)
        uris: Set[str] = set()
        if isinstance(rd_data, dict) and not rd_data.get("error"):
            instances = rd_data.get("Instances") or []
            for inst in instances:
                if isinstance(inst, dict):
                    uri = inst.get("@odata.id")
                    if uri and isinstance(uri, str):
                        clean = uri.rstrip("/")
                        uris.add(clean)
                        uris.add(f"{clean}/")
        self._hpe_resource_directory = uris
        return self._hpe_resource_directory

    def endpoint_in_resource_directory(self, endpoint: str) -> Optional[bool]:
        """Check if an endpoint URI is present in the HPE ResourceDirectory.

        Returns True if confirmed present, False if ResourceDirectory is loaded and
        endpoint is absent, or None if ResourceDirectory is empty/unsupported.
        """
        rd = self._load_hpe_resource_directory()
        if not rd:
            return None
        clean = endpoint.split("?")[0].rstrip("/")
        return clean in rd or f"{clean}/" in rd

    def oem_fastpath_roots(self) -> Optional[Tuple[List[str], List[str], List[str]]]:
        """HPE ProLiant fast-path root probe using ResourceDirectory when available."""
        rd = self._load_hpe_resource_directory()
        if rd and "/redfish/v1/Systems/1" in rd and "/redfish/v1/Chassis/1" in rd and "/redfish/v1/Managers/1" in rd:
            return (
                ["/redfish/v1/Systems/1"],
                ["/redfish/v1/Chassis/1"],
                ["/redfish/v1/Managers/1"],
            )
        return None

    def oem_expandable_collections(self) -> Dict[str, str]:
        """HPE ProLiant expandable collection endpoints.

        HPE iLO 5 (Gen10) and iLO 6 (Gen11) support OData $expand=. with MaxLevels: 1 on:
          - Systems/1/Memory
          - Chassis/1/Thermal or ThermalSubsystem/Fans
          - UpdateService/FirmwareInventory

        HPE iLO 5/6 strictly requires period syntax ($expand=.($levels=1)) because
        ExpandAll is false and NoLinks is true.

        HPE iLO 7 (Gen12) lifts these restrictions, advertising ExpandAll: true,
        MaxLevels: 5, and expands Chassis NetworkAdapters (levels=2) and Storage.
        """
        sys_uri = getattr(self, "sys_uri", None) or "/redfish/v1/Systems/1"
        chassis_uri = getattr(self, "chassis_uri", None) or "/redfish/v1/Chassis/1"
        mem_ep = f"{sys_uri}/Memory"
        thermal_ep = f"{chassis_uri}/Thermal"
        fans_ep = f"{chassis_uri}/ThermalSubsystem/Fans"
        fw_ep = "/redfish/v1/UpdateService/FirmwareInventory"
        net_ep = f"{chassis_uri}/NetworkAdapters"
        storage_ep = f"{sys_uri}/Storage"
        mapping = {
            "firmware": fw_ep,
            "memory": mem_ep,
            "thermal": thermal_ep,
            "thermal_fans": fans_ep,
            "fans": fans_ep,
        }
        levels_map = {
            "firmware": 1,
            fw_ep: 1,
            "memory": 1,
            mem_ep: 1,
            "thermal": 1,
            thermal_ep: 1,
            "thermal_fans": 1,
            "fans": 1,
            fans_ep: 1,
        }

        is_gen12_plus = getattr(self, "expand_max_levels", 1) >= 2 or getattr(self, "expand_syntax", "") == "*"
        if is_gen12_plus:
            mapping["network"] = net_ep
            mapping["network_adapters"] = net_ep
            mapping[net_ep] = net_ep
            mapping["storage"] = storage_ep
            mapping[storage_ep] = storage_ep
            levels_map["network"] = 2
            levels_map["network_adapters"] = 2
            levels_map[net_ep] = 2
            levels_map["storage"] = 1
            levels_map[storage_ep] = 1

        return ExpandableCollectionsMap(mapping, levels=levels_map)

    def oem_bios_date(self, sys_data: dict) -> str:
        """Read BIOS release date from Oem.Hpe or Oem.Hp hierarchy."""
        for oem_key in ("Hpe", "Hp"):
            for path in (("Bios", "Current", "Date"), ("Bios", "Date")):
                val = get_nested(sys_data, "Oem", oem_key, *path)
                if val and str(val).strip() not in ("N/A", "None", ""):
                    return str(val).strip()
        return "N/A"

    def oem_sku(self, sys_data: dict) -> str:
        """Read HPE ProductId (SKU) from top-level SKU, Oem.Hpe.ProductId, or Oem.Hp.ProductId."""
        sys_data = sys_data or {}
        return (
            sys_data.get("SKU")
            or get_nested(sys_data, "Oem", "Hpe", "ProductId", default="")
            or get_nested(sys_data, "Oem", "Hp", "ProductId", default="")
            or ""
        )

    def oem_cpu_cache(self, proc_json: dict) -> list:
        """Read CPU cache list from Oem.Hpe.Cache or Oem.Hp.Cache."""
        res = get_nested(proc_json, "Oem", "Hpe", "Cache") or get_nested(proc_json, "Oem", "Hp", "Cache", default=[])
        return res if isinstance(res, list) else []

    def oem_memory_usage(self, sys_data: dict) -> dict:
        """Read live memory utilization from Oem.Hpe.SystemUsage or Oem.Hp.SystemUsage."""
        res = get_nested(sys_data, "Oem", "Hpe", "SystemUsage") or get_nested(sys_data, "Oem", "Hp", "SystemUsage", default={})
        return res if isinstance(res, dict) else {}

    def oem_extract_bios_attributes(self, bios_data: dict) -> dict:
        """Extract BIOS attributes from HPE iLO 4 / 5 / 6.

        On modern iLO 5/6, attributes are nested under 'Attributes': {}.
        On legacy iLO 4 (Gen9), attributes may be flat top-level keys or under Oem.Hpe/Hp.
        """
        if not isinstance(bios_data, dict):
            return {}
        attrs = bios_data.get("Attributes")
        if isinstance(attrs, dict) and attrs:
            return attrs
        for oem_key in ("Hpe", "Hp"):
            oem_attrs = (
                get_nested(bios_data, "Oem", oem_key, "Attributes")
                or get_nested(bios_data, "Oem", oem_key, "Bios", "Attributes")
            )
            if isinstance(oem_attrs, dict) and oem_attrs:
                return oem_attrs
        # Fall back to top-level flat attributes (HPE iLO 4 / Gen9)
        flat = {
            k: v for k, v in bios_data.items()
            if not k.startswith("@") and k not in (
                "Id", "Name", "Description", "Type", "Actions", "Links", "links", "Oem", "Status", "Members", "attribute_count"
            ) and isinstance(v, (str, int, float, bool))
        }
        return flat

    def oem_storage_endpoints(self) -> list:
        """Add HPE SmartStorage controller paths to storage discovery."""
        endpoints = []
        if self.sys_uri:
            clean_sys = self.sys_uri.rstrip("/")
            endpoints.append(f"{clean_sys}/SmartStorage/ArrayControllers")
            endpoints.append(f"{clean_sys}/SmartStorage/HostBusAdapters")
            endpoints.append(f"{clean_sys}/SmartStorage")
        sys_data = getattr(self, "sys_data", {}) or {}
        for oem_key in ("Hpe", "Hp"):
            ss_href = get_nested(sys_data, "Oem", oem_key, "links", "SmartStorage", "href")
            if ss_href and ss_href.rstrip("/") not in endpoints:
                endpoints.append(ss_href.rstrip("/"))

        rd = self._load_hpe_resource_directory()
        if rd:
            return [ep for ep in endpoints if ep.rstrip("/") in rd or f"{ep.rstrip('/')}/" in rd]
        return endpoints

    def oem_handle_retry(self, data: dict, endpoint: str) -> bool:
        """Detect HPE iLO ResourceNotReadyRetry, InvalidOperationForSystemState, or transient ready errors."""
        data = data or {}
        ext_info = data.get("@Message.ExtendedInfo") or get_nested(data, "error", "@Message.ExtendedInfo", default=[]) or []
        transient_signatures = (
            "ResourceNotReadyRetry",
            "InvalidOperationForSystemState",
            "iLO is not ready",
            "ilo is not ready",
        )
        if isinstance(ext_info, dict):
            ext_info = [ext_info]
        elif not isinstance(ext_info, list):
            ext_info = []
        if isinstance(ext_info, list):
            for e in ext_info:
                if isinstance(e, dict):
                    mid = str(e.get("MessageId", ""))
                    m = str(e.get("Message", ""))
                    if any(sig in mid or sig in m for sig in transient_signatures):
                        return True
        err = data.get("error")
        if isinstance(err, dict):
            err_code = str(err.get("code", ""))
            err_msg = str(err.get("message", ""))
            if any(sig in err_code or sig in err_msg for sig in transient_signatures):
                return True
        direct_msg = str(data.get("message", ""))
        direct_code = str(data.get("code", ""))
        return any(sig in direct_code or sig in direct_msg for sig in transient_signatures)

    def oem_drive_metrics(self, drive_json: dict) -> dict:
        """Read HPE drive telemetry metrics from Oem.Hpe or HpeSmartStorageDiskDrive."""
        hpe_oem = get_nested(drive_json, "Oem", "Hpe", default={})
        res = {}
        if isinstance(hpe_oem, dict):
            poh = hpe_oem.get("PowerOnHours")
            if poh is not None:
                try:
                    res["power_on_hours"] = float(poh)
                except (TypeError, ValueError):
                    pass
            car_stat = hpe_oem.get("CarrierStatus")
            if car_stat:
                res["carrier_status"] = str(car_stat).strip()
            car_led = hpe_oem.get("CarrierLED")
            if car_led:
                res["carrier_led"] = str(car_led).strip()
            enc = hpe_oem.get("EncrypStatus") or hpe_oem.get("EncryptionStatus")
            if enc:
                res["security_status"] = str(enc).strip()
            part = hpe_oem.get("OptionPartNumber") or hpe_oem.get("PartNumber")
            if part:
                res["part_number"] = str(part).strip()

        # Also check root level or SmartStorage drive properties
        ssd_util = drive_json.get("SSDEnduranceUtilizationPercentage") or hpe_oem.get("SSDEnduranceUtilizationPercentage")
        if ssd_util is not None:
            try:
                res["life_used_pct"] = float(ssd_util)
                res["endurance_remaining_pct"] = max(0.0, 100.0 - float(ssd_util))
            except (TypeError, ValueError):
                pass

        max_temp = drive_json.get("MaximumTemperatureCelsius") or hpe_oem.get("MaximumTemperatureCelsius")
        if max_temp is not None:
            try:
                res["max_temp_c"] = float(max_temp)
            except (TypeError, ValueError):
                pass

        cur_temp = drive_json.get("CurrentTemperatureCelsius") or hpe_oem.get("CurrentTemperatureCelsius")
        if cur_temp is not None and "temperature_c" not in res:
            try:
                res["temperature_c"] = float(cur_temp)
            except (TypeError, ValueError):
                pass

        uncorr_r = drive_json.get("UncorrectedReadErrors")
        if uncorr_r is not None:
            try:
                res["uncorrectable_read_errors"] = int(uncorr_r)
            except (TypeError, ValueError):
                pass

        uncorr_w = drive_json.get("UncorrectedWriteErrors")
        if uncorr_w is not None:
            try:
                res["uncorrectable_write_errors"] = int(uncorr_w)
            except (TypeError, ValueError):
                pass

        return res

    def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict:
        """Detect HPE iLO license tier (Advanced, Standard, Expired)."""
        ilo_license = get_nested(mgr_data, "Oem", "Hpe", "License", default={})
        if not ilo_license:
            return {"license_name": "N/A", "badge": "", "vendor_note": ""}
        tier = ilo_license.get("LicenseType") or ilo_license.get("License", "Standard")
        tier_low = str(tier).lower()
        if "advanced" in tier_low or "essentials" in tier_low:
            return {
                "license_name": str(tier),
                "badge": f"<span class='badge success'>🟢 HPE iLO {tier}</span>",
                "vendor_note": (
                    "iLO Advanced enables KVM remote console, Federation, Directory "
                    "authentication, and advanced power regulation. All hardware inventory "
                    "in this report is available at the Standard tier."
                ),
            }
        elif "expired" in tier_low:
            return {
                "license_name": "iLO Advanced — License expired",
                "badge": "<span class='badge warning'>🟡 HPE iLO Advanced — License expired</span>",
                "vendor_note": (
                    "An iLO Advanced license was previously installed but has expired. "
                    "Hardware inventory (Storage, Memory, NICs, Thermal, PSU) remains fully "
                    "accessible. Performance telemetry (CPU/memory/PCIe utilisation metrics), "
                    "KVM remote console, Federation, and Directory auth are unavailable until "
                    "the license is renewed."
                ),
            }
        elif tier_low in ("unlicensed", "", "none"):
            return {
                "license_name": "iLO — No activation key",
                "badge": "<span class='badge warning'>🟡 HPE iLO — No activation key installed</span>",
                "vendor_note": (
                    "No iLO Advanced license key is installed. "
                    "Hardware inventory (Storage, Memory, NICs, Thermal, PSU) is fully "
                    "accessible at the base tier. Performance telemetry (TelemetryService — "
                    "CPU/memory/PCIe utilisation metrics), KVM remote console, Federation, "
                    "and Directory auth require an iLO Advanced license."
                ),
            }
        else:
            return {
                "license_name": str(tier),
                "badge": f"<span class='badge warning'>🟡 HPE iLO {tier}</span>",
                "vendor_note": (
                    "iLO Standard: hardware inventory (Storage, Memory, NICs, Thermal, "
                    "PSU) is fully accessible. Upgrade to iLO Advanced to enable KVM "
                    "remote console, Federation, Directory auth, performance telemetry "
                    "(CPU/memory/PCIe utilisation), and detailed power regulation."
                ),
            }

    def oem_security_evidence(self) -> Dict[str, Any]:
        """Collect HPE-native security evidence from iLO extensions (Bead 6).

        Discovers SecurityService from Manager.Oem.Hpe before documented fallback.
        Collects native properties:
          - SecurityService: SecurityState, DisableWeakCiphers, CurrentCipher, TLSVersion, LoginSecurityBanner
          - SecurityDashboard: OverallSecurityStatus, ServerConfigurationLockStatus
          - SecurityParameters: 11 native parameter assessments (IPMI, passwords, RBSU, host auth, etc.)
          - Manager Oem.Hpe: RequireHostAuthentication, iLOServicePort, RIBCLEnabled, WebGuiEnabled, SerialCLIStatus
          - NetworkProtocol Oem.Hpe: SMTPForTFAEnabled, AlertMailSMTPSecureEnabled, RemoteSyslogEnabled, VirtualMediaEncryptionEnabled
          - AccountService Oem.Hpe: TwoFactorAuth, AuthFailureLoggingThreshold, AuthFailureDelayTimeSeconds, AuthFailuresBeforeDelay, EnforcePasswordComplexity
          - Sub-links: CertificateAuthentication, SSO, AutomaticCertificateEnrollment, ESKM

        Strictly excludes passwords, credentials, keys, tokens, and certificate bodies.
        Does not invent Dell attributes or assign compliance verdicts.
        """
        mgr_uri = getattr(self, "mgr_uri", None)
        mgr_data: Dict[str, Any] = {}
        if mgr_uri and hasattr(self, "_get"):
            res = self._get(mgr_uri)
            if isinstance(res, dict) and not res.get("error"):
                mgr_data = res

        # 1. Manager Oem.Hpe properties
        oem_hpe_mgr = get_nested(mgr_data, "Oem", "Hpe", default={})
        hpe_mgr_evidence: Dict[str, Any] = {}
        if isinstance(oem_hpe_mgr, dict) and oem_hpe_mgr:
            hpe_mgr_evidence = {
                "RequireHostAuthentication": oem_hpe_mgr.get("RequireHostAuthentication"),
                "RIBCLEnabled": oem_hpe_mgr.get("RIBCLEnabled"),
                "WebGuiEnabled": oem_hpe_mgr.get("WebGuiEnabled"),
                "SerialCLIStatus": oem_hpe_mgr.get("SerialCLIStatus"),
                "iLOFunctionalityEnabled": oem_hpe_mgr.get("iLOFunctionalityEnabled"),
            }
            svc_port = oem_hpe_mgr.get("iLOServicePort")
            if isinstance(svc_port, dict):
                hpe_mgr_evidence["iLOServicePort"] = {
                    "iLOServicePortEnabled": svc_port.get("iLOServicePortEnabled"),
                    "USBEthernetAdaptersEnabled": svc_port.get("USBEthernetAdaptersEnabled"),
                    "USBFlashDriveEnabled": svc_port.get("USBFlashDriveEnabled"),
                    "MassStorageAuthenticationRequired": svc_port.get("MassStorageAuthenticationRequired"),
                }

        # 2. Discover SecurityService link from Manager Oem.Hpe before documented fallback
        sec_uri: Optional[str] = None
        links = get_nested(oem_hpe_mgr, "Links", default={})
        if isinstance(links, dict) and "SecurityService" in links:
            sec_link = links["SecurityService"]
            if isinstance(sec_link, dict):
                sec_uri = sec_link.get("@odata.id")
        if not sec_uri and mgr_uri:
            sec_uri = f"{mgr_uri}/SecurityService"

        # 3. SecurityService & sub-resources
        sec_service_evidence: Dict[str, Any] = {}
        dash_evidence: Dict[str, Any] = {}
        params_list: List[Dict[str, Any]] = []
        cert_auth_evidence: Dict[str, Any] = {}
        sso_evidence: Dict[str, Any] = {}
        ace_evidence: Dict[str, Any] = {}
        eskm_evidence: Dict[str, Any] = {}

        if sec_uri and hasattr(self, "_get"):
            sec_res = self._get(sec_uri)
            if isinstance(sec_res, dict) and not sec_res.get("error"):
                sec_service_evidence = {
                    "@odata.type": sec_res.get("@odata.type"),
                    "SecurityState": sec_res.get("SecurityState"),
                    "SecurityStateAllowableValues": sec_res.get("SecurityState@Redfish.AllowableValues"),
                    "DisableWeakCiphers": sec_res.get("DisableWeakCiphers"),
                    "CurrentCipher": sec_res.get("CurrentCipher"),
                    "TLSVersion": sec_res.get("TLSVersion"),
                    "LoginSecurityBanner": sec_res.get("LoginSecurityBanner"),
                }

                sec_links = sec_res.get("Links", {})
                if not isinstance(sec_links, dict):
                    sec_links = {}

                # SecurityDashboard
                dash_link = sec_links.get("SecurityDashboard")
                dash_uri = dash_link.get("@odata.id") if isinstance(dash_link, dict) else f"{sec_uri}/SecurityDashboard"
                dash_res = self._get(dash_uri)
                if isinstance(dash_res, dict) and not dash_res.get("error"):
                    dash_evidence = {
                        "@odata.type": dash_res.get("@odata.type"),
                        "OverallSecurityStatus": dash_res.get("OverallSecurityStatus"),
                        "ServerConfigurationLockStatus": dash_res.get("ServerConfigurationLockStatus"),
                    }

                    # SecurityParameters
                    params_link = dash_res.get("SecurityParameters")
                    params_uri = params_link.get("@odata.id") if isinstance(params_link, dict) else f"{dash_uri}/SecurityParams"
                    params_coll = self._get(params_uri)
                    if isinstance(params_coll, dict) and not params_coll.get("error"):
                        members = params_coll.get("Members", [])
                        if isinstance(members, list):
                            for m in members:
                                m_uri = m.get("@odata.id") if isinstance(m, dict) else None
                                if m_uri:
                                    p_data = self._get(m_uri)
                                    if isinstance(p_data, dict) and not p_data.get("error"):
                                        params_list.append({
                                            "id": p_data.get("Id"),
                                            "name": p_data.get("Name"),
                                            "state": p_data.get("State"),
                                            "security_status": p_data.get("SecurityStatus"),
                                            "recommended_action": p_data.get("RecommendedAction"),
                                            "description": p_data.get("Description"),
                                            "ignore": p_data.get("Ignore", False),
                                        })

                # CertificateAuthentication
                ca_link = sec_links.get("CertAuth")
                ca_uri = ca_link.get("@odata.id") if isinstance(ca_link, dict) else f"{sec_uri}/CertificateAuthentication"
                ca_res = self._get(ca_uri)
                if isinstance(ca_res, dict) and not ca_res.get("error"):
                    cert_auth_evidence = {
                        "CertificateLoginEnabled": ca_res.get("CertificateLoginEnabled"),
                        "StrictCACModeEnabled": ca_res.get("StrictCACModeEnabled"),
                    }

                # SSO
                sso_link = sec_links.get("SSO")
                sso_uri = sso_link.get("@odata.id") if isinstance(sso_link, dict) else f"{sec_uri}/SSO"
                sso_res = self._get(sso_uri)
                if isinstance(sso_res, dict) and not sso_res.get("error"):
                    sso_settings = sso_res.get("SSOsettings", {}) if isinstance(sso_res.get("SSOsettings"), dict) else {}
                    sso_evidence = {
                        "SSOTrustMode": sso_settings.get("SSOTrustMode", "TrustNone"),
                    }

                # AutomaticCertificateEnrollment
                ace_link = sec_links.get("AutomaticCertificateEnrollment")
                ace_uri = ace_link.get("@odata.id") if isinstance(ace_link, dict) else f"{sec_uri}/AutomaticCertificateEnrollment"
                ace_res = self._get(ace_uri)
                if isinstance(ace_res, dict) and not ace_res.get("error"):
                    ace_evidence = {
                        "AutomaticCertificateEnrollmentSettings": ace_res.get("AutomaticCertificateEnrollmentSettings"),
                    }

                # ESKM
                eskm_link = sec_links.get("ESKM")
                eskm_uri = eskm_link.get("@odata.id") if isinstance(eskm_link, dict) else f"{sec_uri}/ESKM"
                eskm_res = self._get(eskm_uri)
                if isinstance(eskm_res, dict) and not eskm_res.get("error"):
                    eskm_evidence = {
                        "KeyManagerConfig": eskm_res.get("KeyManagerConfig"),
                        "KeyServerRedundancyReq": eskm_res.get("KeyServerRedundancyReq"),
                    }

        # 4. NetworkProtocol Oem.Hpe
        hpe_net_evidence: Dict[str, Any] = {}
        np_uri = None
        if mgr_data and "NetworkProtocol" in mgr_data:
            np_val = mgr_data["NetworkProtocol"]
            if isinstance(np_val, dict):
                np_uri = np_val.get("@odata.id")
        if not np_uri and mgr_uri:
            np_uri = f"{mgr_uri}/NetworkProtocol"
        if np_uri and hasattr(self, "_get"):
            np_res = self._get(np_uri)
            if isinstance(np_res, dict) and not np_res.get("error"):
                oem_hpe_net = get_nested(np_res, "Oem", "Hpe", default={})
                if isinstance(oem_hpe_net, dict) and oem_hpe_net:
                    hpe_net_evidence = {
                        "SMTPForTFAEnabled": oem_hpe_net.get("SMTPForTFAEnabled"),
                        "AlertMailEnabled": oem_hpe_net.get("AlertMailEnabled"),
                        "AlertMailSMTPSecureEnabled": oem_hpe_net.get("AlertMailSMTPSecureEnabled"),
                        "RemoteSyslogEnabled": oem_hpe_net.get("RemoteSyslogEnabled"),
                        "VirtualMediaEncryptionEnabled": oem_hpe_net.get("VirtualMediaEncryptionEnabled"),
                    }

        # 5. AccountService Oem.Hpe
        hpe_acct_evidence: Dict[str, Any] = {}
        if hasattr(self, "_get"):
            acct_res = self._get("/redfish/v1/AccountService")
            if not (isinstance(acct_res, dict) and not acct_res.get("error")):
                acct_res = self._get("/AccountService")
            if isinstance(acct_res, dict) and not acct_res.get("error"):
                oem_hpe_acct = get_nested(acct_res, "Oem", "Hpe", default={})
                if isinstance(oem_hpe_acct, dict) and oem_hpe_acct:
                    hpe_acct_evidence = {
                        "TwoFactorAuth": oem_hpe_acct.get("TwoFactorAuth"),
                        "AuthFailureLoggingThreshold": oem_hpe_acct.get("AuthFailureLoggingThreshold"),
                        "AuthFailureDelayTimeSeconds": oem_hpe_acct.get("AuthFailureDelayTimeSeconds"),
                        "AuthFailuresBeforeDelay": oem_hpe_acct.get("AuthFailuresBeforeDelay"),
                        "EnforcePasswordComplexity": oem_hpe_acct.get("EnforcePasswordComplexity"),
                        "MinPasswordLength": oem_hpe_acct.get("MinPasswordLength"),
                    }

        return {
            "security_service": sec_service_evidence,
            "security_dashboard": dash_evidence,
            "security_parameters": params_list,
            "hpe_manager": hpe_mgr_evidence,
            "hpe_network_protocol": hpe_net_evidence,
            "hpe_account_service": hpe_acct_evidence,
            "certificate_authentication": cert_auth_evidence,
            "sso": sso_evidence,
            "automatic_certificate_enrollment": ace_evidence,
            "eskm": eskm_evidence,
        }

    def oem_normalize_bios_attributes(self, raw_attrs: dict) -> dict:
        """Normalize HPE ProLiant / Synergy BIOS attributes."""
        boot_fallback = getattr(self, "sys_summary", {}).get("raw_boot_mode") or getattr(self, "sys_summary", {}).get("boot_mode")
        return normalize_hpe_bios_attributes(raw_attrs, fallback_boot_mode=boot_fallback)


def normalize_hpe_bios_attributes(
    raw_attrs: Dict[str, Any],
    fallback_boot_mode: Optional[str] = None,
) -> Dict[str, Any]:
    """Normalize HPE ProLiant (Gen10–Gen12) and Synergy BIOS / RBSU attributes.

    Extracts canonical baseline settings:
      • WorkloadProfile / SysProfile: Workload Profile (Virtualization-MaxPerformance, etc.)
      • PowerRegulator: Static High Performance, OS Control, Dynamic Power Savings
      • MinProcIdlePower / ProcCStates: Minimum Processor Idle Power Core C-State (NoCStates, C6, etc.)
      • MinProcIdlePkgState: Minimum Processor Idle Power Package C-State (NoPkgCState, C6, etc.)
      • CollaborativePowerControl: Collaborative Power Control (Disabled / Enabled)
      • ProcVirtualization: Intel Virtualization Technology / AMD Virtualization
      • VtdSupport: Intel VT-d / AMD IOMMU
      • LogicalProc: Intel Hyper-Threading / AMD SMT
      • ProcTurboMode: Intel Turbo Boost / AMD Core Performance Boost
      • EnergyEfficientTurbo: Energy-Efficient Turbo (Disabled / Enabled)
      • NumaGroupSizeOpt / NodeInterleave: NUMA Group Size Optimization (Flat / Clustered)
      • SubNumaClustering: Sub-NUMA Clustering (Disabled / Enabled / Auto)
      • NumaNodesPerSocket: AMD NUMA Nodes Per Socket (NPS1 / NPS4)
      • DeterminismSlider: AMD Determinism Slider (Power / Performance / Auto)
      • SriovGlobalEnable: SR-IOV (Enabled / Disabled)
      • VmdSupport: Intel VMD state
      • BootMode: System boot mode (UEFI / Legacy)
    """
    normalized: Dict[str, Any] = {}
    if not isinstance(raw_attrs, dict):
        return normalized

    def _find_val(*keys: str) -> Optional[str]:
        for k in keys:
            if k in raw_attrs and raw_attrs[k] is not None:
                return str(raw_attrs[k]).strip()
            k_low = k.lower()
            for rk, rv in raw_attrs.items():
                if rv is not None and (rk.lower() == k_low or rk.lower().endswith("." + k_low) or rk.lower().endswith("_" + k_low)):
                    return str(rv).strip()
        return None

    # 1. WorkloadProfile / SysProfile
    val = _find_val("WorkloadProfile", "Workload_Profile", "SysProfile", "SystemProfile")
    if val:
        normalized["WorkloadProfile"] = val
        normalized["SysProfile"] = val

    # 2. PowerRegulator
    val = _find_val("PowerRegulator", "Power_Regulator")
    if val:
        normalized["PowerRegulator"] = val

    # 3. MinProcIdlePower / ProcCStates
    val = _find_val("MinProcIdlePower", "Min_Proc_Idle_Power", "ProcCStates", "CStates")
    if val:
        normalized["MinProcIdlePower"] = val
        normalized["ProcCStates"] = val

    # 4. MinProcIdlePkgState
    val = _find_val("MinProcIdlePkgState", "Min_Proc_Idle_Pkg_State")
    if val:
        normalized["MinProcIdlePkgState"] = val

    # 5. CollaborativePowerControl
    val = _find_val("CollaborativePowerControl", "Collaborative_Power_Control")
    if val:
        normalized["CollaborativePowerControl"] = val

    # 6. ProcVirtualization (VT-x / AMD-V)
    val = _find_val(
        "ProcVirtualization",
        "IntelProcVtd",
        "AmdVirtualization",
        "VirtualizationTechnology",
        "IntelVirtualizationTechnology",
    )
    if val:
        normalized["ProcVirtualization"] = val

    # 7. VtdSupport (VT-d / AMD IOMMU)
    val = _find_val("IntelProcVtd", "IntelVtd", "AmdIoMmu", "VtdSupport", "VT-d")
    if val:
        normalized["VtdSupport"] = val
        normalized["IntelProcVtd"] = val

    # 8. LogicalProc (HyperThreading / SMT)
    val = _find_val(
        "ProcHyperthreading",
        "Proc_Hyperthreading",
        "IntelHyperThreading",
        "AmdSmt",
        "HyperThreading",
        "LogicalProc",
    )
    if val:
        normalized["LogicalProc"] = val
        normalized["ProcHyperthreading"] = val

    # 9. ProcTurboMode (Turbo Boost / CPB)
    val = _find_val("ProcTurbo", "Turbo", "AmdCoreBoost", "ProcTurboMode", "TurboMode")
    if val:
        normalized["ProcTurboMode"] = val
        normalized["ProcTurbo"] = val

    # 10. EnergyEfficientTurbo
    val = _find_val("EnergyEfficientTurbo", "Energy_Efficient_Turbo")
    if val:
        normalized["EnergyEfficientTurbo"] = val

    # 11. NumaGroupSizeOpt / NodeInterleave
    val = _find_val("NumaGroupSizeOpt", "NUMAGroupSizeOpt", "NumaGroupSize")
    if val:
        normalized["NumaGroupSizeOpt"] = val
    val = _find_val("NodeInterleaving", "NodeInterleave")
    if val:
        normalized["NodeInterleave"] = val

    # 12. SubNumaClustering
    val = _find_val("SubNumaClustering", "SubNumaCluster", "SNC")
    if val:
        normalized["SubNumaClustering"] = val
        normalized["SubNumaCluster"] = val

    # 13. AMD NPS & Determinism
    val = _find_val("NumaNodesPerSocket", "NUMANodesPerSocket")
    if val:
        normalized["NumaNodesPerSocket"] = val
    val = _find_val("DeterminismSlider", "Determinism_Slider", "Determinism")
    if val:
        normalized["DeterminismSlider"] = val

    # 14. SriovGlobalEnable
    val = _find_val("Sriov", "SRIOV", "SriovGlobalEnable")
    if val:
        normalized["SriovGlobalEnable"] = val
        normalized["Sriov"] = val

    # 15. Intel VMD
    val = _find_val("IntelVmd", "VmdSupport", "VMDEnable")
    if val:
        normalized["VmdSupport"] = val
    else:
        vmd_keys = {
            k: v for k, v in raw_attrs.items()
            if any(s in k.lower() for s in ("vmd", "vroc", "nvmeraid", "nvme_raid"))
        }
        if vmd_keys:
            any_on = any(str(v).lower() in ("enabled", "true", "auto", "1", "enable") for v in vmd_keys.values())
            normalized["VmdSupport"] = "Enabled" if any_on else "Disabled"
        else:
            normalized["VmdSupport"] = "Disabled"

    # 16. BootMode
    val = _find_val("BootMode", "SystemBootMode", "BootSeqMode")
    if val:
        normalized["BootMode"] = val
    elif fallback_boot_mode:
        normalized["BootMode"] = str(fallback_boot_mode).strip()

    return normalized
