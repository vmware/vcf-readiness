"""
VCF Readiness Tool — system/memory/BIOS/BMC collection mixin.
"""
import logging
import re
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

if TYPE_CHECKING:
    class _CollectorBase:
        sys_uri: Optional[str]
        chassis_uri: Optional[str]
        chassis_uris: list
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
        def oem_pcie_link_status(self, dev_dict: dict) -> Optional[dict]: ...
        def oem_os_info(self, sys_data: dict) -> dict: ...
        def oem_handle_retry(self, data: dict, endpoint: str) -> bool: ...
        def oem_manager_paths(self) -> list: ...
        def oem_fastpath_roots(self) -> Optional[Tuple[list, list, list]]: ...
        def oem_job_queue(self, now_dt: Any = None) -> dict: ...
        def collect_job_queue(self, now_dt: Any = None) -> dict: ...
else:
    _CollectorBase = object

logger = logging.getLogger("vcf_assess")


_TPM_INTERFACE_LABELS = {
    "TPM2_0": "TPM 2.0",
    "TPM1_2": "TPM 1.2",
    "TCM1_0": "TCM 1.0",
}

# Lenovo ThinkSystem 8-channel per socket DIMM slot to (Socket, Channel letter) mapping
# Derived from published Lenovo hardware service documentation (SR650 V4 / SR630 V4 / SR650 V3):
# CPU 1 (Socket 1): CH0->A (7,8), CH1->B (5,6), CH2->C (3,4), CH3->D (1,2),
#                   CH4->E (9,10), CH5->F (11,12), CH6->G (13,14), CH7->H (15,16)
# CPU 2 (Socket 2): CH0->A (23,24), CH1->B (21,22), CH2->C (19,20), CH3->D (17,18),
#                   CH4->E (25,26), CH5->F (27,28), CH6->G (29,30), CH7->H (31,32)
LENOVO_THINKSYSTEM_8CH_DIMM_MAP = {
    1: (1, "D"), 2: (1, "D"),
    3: (1, "C"), 4: (1, "C"),
    5: (1, "B"), 6: (1, "B"),
    7: (1, "A"), 8: (1, "A"),
    9: (1, "E"), 10: (1, "E"),
    11: (1, "F"), 12: (1, "F"),
    13: (1, "G"), 14: (1, "G"),
    15: (1, "H"), 16: (1, "H"),
    17: (2, "D"), 18: (2, "D"),
    19: (2, "C"), 20: (2, "C"),
    21: (2, "B"), 22: (2, "B"),
    23: (2, "A"), 24: (2, "A"),
    25: (2, "E"), 26: (2, "E"),
    27: (2, "F"), 28: (2, "F"),
    29: (2, "G"), 30: (2, "G"),
    31: (2, "H"), 32: (2, "H"),
}


def _present_text(value: Any) -> str:
    text = str(value or "").strip()
    if text.lower() in ("", "none", "null", "n/a"):
        return ""
    return text


def computer_system_inventory(data: Optional[dict]) -> Dict[str, Any]:
    """Normalize standard ComputerSystem identity fields without inventing health.

    TrustedModules.InterfaceTypeSelection is reported as given. An enabled
    module is not assumed to be TPM 2.0, and a missing Status.Health is left
    blank rather than reported healthy.
    """
    payload = data if isinstance(data, dict) else {}
    status = payload.get("Status") if isinstance(payload.get("Status"), dict) else {}
    health = _present_text(status.get("Health"))
    health_rollup = _present_text(status.get("HealthRollup"))
    status_state = _present_text(status.get("State"))
    power_state = _present_text(payload.get("PowerState")) or "Unknown"

    modules = payload.get("TrustedModules") if isinstance(payload.get("TrustedModules"), list) else []
    module = next((item for item in modules if isinstance(item, dict)), {})
    module_status = module.get("Status") if isinstance(module.get("Status"), dict) else {}
    interface_raw = _present_text(module.get("InterfaceType") or module.get("InterfaceTypeSelection"))
    interface = _TPM_INTERFACE_LABELS.get(interface_raw, interface_raw)
    firmware = _present_text(module.get("FirmwareVersion") or module.get("FirmwareVersion2"))
    tpm_state = _present_text(module_status.get("State")) or ("Absent" if modules and not module else "Disabled")
    if not modules:
        tpm_state = "NotReported"
    fw_note = f" FW {firmware}" if firmware else ""

    if tpm_state in ("Absent", "NotPresent"):
        tpm_badge = "<span class='badge danger'>🔴 Not Present (Hardware Missing)</span>"
    elif tpm_state in ("Enabled", "EnabledAndActivated"):
        if interface == "TPM 2.0":
            tpm_badge = f"<span class='badge success'>🟢 Enabled (TPM 2.0 Active{fw_note})</span>"
        elif interface == "TPM 1.2":
            tpm_badge = f"<span class='badge warning'>🟡 Enabled (TPM 1.2{fw_note} — Upgrade Required)</span>"
        elif interface:
            tpm_badge = f"<span class='badge warning'>🟡 Enabled ({interface}{fw_note})</span>"
        else:
            tpm_badge = "<span class='badge warning'>🟡 Enabled (TPM interface not reported)</span>"
    elif tpm_state == "NotReported":
        tpm_badge = "<span class='badge info'>ℹ️ TPM Not Reported</span>"
    else:
        shown = interface or tpm_state
        tpm_badge = f"<span class='badge warning'>🟡 {shown}{fw_note} (Action Required)</span>"

    inventory: Dict[str, Any] = {
        "asset_tag": _present_text(payload.get("AssetTag")),
        "power_state": power_state,
        "health": health,
        "health_rollup": health_rollup,
        "status_state": status_state,
        "tpm_interface": interface,
        "tpm_firmware": firmware,
        "tpm_state": tpm_state,
        "tpm_status_badge": tpm_badge,
    }
    boot_progress = payload.get("BootProgress")
    if isinstance(boot_progress, dict) and boot_progress:
        inventory["boot_progress"] = {
            "last_state": _present_text(boot_progress.get("LastState")),
            "last_state_time": _present_text(boot_progress.get("LastStateTime")),
            "oem_last_state": _present_text(boot_progress.get("OemLastState")),
        }
    watchdog = payload.get("HostWatchdogTimer")
    if isinstance(watchdog, dict) and watchdog:
        watchdog_status = watchdog.get("Status") if isinstance(watchdog.get("Status"), dict) else {}
        inventory["watchdog"] = {
            "function_enabled": watchdog.get("FunctionEnabled"),
            "state": _present_text(watchdog_status.get("State")),
            "health": _present_text(watchdog_status.get("Health")),
            "timeout_action": _present_text(watchdog.get("TimeoutAction")),
            "warning_action": _present_text(watchdog.get("WarningAction")),
        }
    return inventory


def _parse_iso_datetime(dt_str: str) -> Optional[datetime]:
    if not dt_str or not isinstance(dt_str, str):
        return None
    s = dt_str.strip()
    if not s or s.upper() in ("UNKNOWN", "N/A", "NONE"):
        return None
    try:
        if s.endswith('Z') or s.endswith('z'):
            s = s[:-1] + '+00:00'
        if not re.search(r'[+-]\d{2}:?\d{2}$', s):
            s += '+00:00'
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        pass

    m = re.match(
        r'^(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:([+-]\d{2}):?(\d{2})|Z)?$',
        s, re.I
    )
    if m:
        try:
            year, month, day, hour, minute, second = map(int, m.groups()[:6])
            tz = timezone.utc
            if m.group(8) and m.group(9):
                tz_h = int(m.group(8))
                tz_m = int(m.group(9))
                if tz_h < 0:
                    tz_m = -tz_m
                tz = timezone(timedelta(hours=tz_h, minutes=tz_m))
            return datetime(year, month, day, hour, minute, second, tzinfo=tz)
        except (ValueError, TypeError):
            pass
    return None


def _extract_ntp_servers(net_proto: dict) -> list:
    servers = []
    def _add(s):
        if s is not None and isinstance(s, (str, int)):
            st = str(s).strip()
            if st and st.lower() not in ("none", "null", "0.0.0.0", "disabled", "false", "") and st not in servers:
                servers.append(st)

    if not isinstance(net_proto, dict):
        return servers

    ntp = net_proto.get("NTP") or {}
    if isinstance(ntp, dict):
        for key in ("NTPServers", "NetworkSuppliedServers", "StaticNTPServers", "Servers", "PrimaryNTP", "SecondaryNTP"):
            val = ntp.get(key)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        _add(item)
                    elif isinstance(item, dict):
                        _add(item.get("Address") or item.get("IPAddress") or item.get("Server") or item.get("HostName"))
            elif isinstance(val, (str, int)):
                _add(val)

        n_oem = ntp.get("Oem") or {}
        if isinstance(n_oem, dict):
            for v_val in n_oem.values():
                if isinstance(v_val, dict):
                    for k, v in v_val.items():
                        if isinstance(v, (str, int)) and ("ntp" in k.lower() or "server" in k.lower()):
                            _add(v)
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, (str, int)):
                                    _add(item)

    p_oem = net_proto.get("Oem") or {}
    if isinstance(p_oem, dict):
        for v_val in p_oem.values():
            if isinstance(v_val, dict):
                ntp_blk = v_val.get("NTP") or v_val.get("Ntp") or v_val.get("DellNetworkProtocol") or {}
                if isinstance(ntp_blk, dict):
                    for k, v in ntp_blk.items():
                        if isinstance(v, (str, int)) and ("ntp" in k.lower() or "server" in k.lower()):
                            _add(v)
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, (str, int)):
                                    _add(item)
    return servers


def _extract_dns_servers(net_proto: dict) -> list:
    servers = []
    def _add(s):
        if s is not None and isinstance(s, (str, int)):
            st = str(s).strip()
            if st and st.lower() not in ("none", "null", "0.0.0.0", "disabled", "false", "") and st not in servers:
                servers.append(st)

    if not isinstance(net_proto, dict):
        return servers

    dns = net_proto.get("DNS") or net_proto.get("Dns") or {}
    if isinstance(dns, dict):
        for key in ("NameServers", "StaticNameServers", "DomainNameServers", "Servers", "PrimaryDNS", "SecondaryDNS", "DNS"):
            val = dns.get(key)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        _add(item)
                    elif isinstance(item, dict):
                        _add(item.get("Address") or item.get("IPAddress") or item.get("Server") or item.get("HostName"))
            elif isinstance(val, (str, int)):
                _add(val)

        d_oem = dns.get("Oem") or {}
        if isinstance(d_oem, dict):
            for v_val in d_oem.values():
                if isinstance(v_val, dict):
                    for k, v in v_val.items():
                        if isinstance(v, (str, int)) and ("dns" in k.lower() or "nameserver" in k.lower() or "server" in k.lower()):
                            _add(v)
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, (str, int)):
                                    _add(item)

    p_oem = net_proto.get("Oem") or {}
    if isinstance(p_oem, dict):
        for v_val in p_oem.values():
            if isinstance(v_val, dict):
                dns_blk = v_val.get("DNS") or v_val.get("Dns") or v_val.get("DellNetworkProtocol") or {}
                if isinstance(dns_blk, dict):
                    for k, v in dns_blk.items():
                        if isinstance(v, (str, int)) and ("dns" in k.lower() or "nameserver" in k.lower() or "server" in k.lower()):
                            _add(v)
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, (str, int)):
                                    _add(item)
    return servers


def _extract_bmc_timezone_info(mgr_data: dict, bmc_dt_str: Optional[str] = None) -> dict:
    """Extract timezone offset, timezone name, and UTC compliance from BMC Manager data."""
    raw_offset = mgr_data.get("DateTimeLocalOffset") if isinstance(mgr_data, dict) else None
    tz_name = (mgr_data.get("TimeZone") or mgr_data.get("Timezone")) if isinstance(mgr_data, dict) else None

    offset_str = str(raw_offset).strip() if raw_offset is not None else ""
    if not offset_str and bmc_dt_str and isinstance(bmc_dt_str, str):
        s = bmc_dt_str.strip()
        if s.endswith(('Z', 'z')):
            offset_str = "+00:00"
        else:
            m = re.search(r'([+-]\d{2}:?\d{2})$', s)
            if m:
                offset_str = m.group(1)

    offset_minutes = 0
    is_utc = True
    if offset_str:
        m = re.match(r'^([+-])(\d{2}):?(\d{2})', offset_str)
        if m:
            sign = 1 if m.group(1) == '+' else -1
            hrs = int(m.group(2))
            mins = int(m.group(3))
            offset_minutes = sign * (hrs * 60 + mins)
            offset_str = f"{m.group(1)}{m.group(2)}:{m.group(3)}"
            is_utc = (offset_minutes == 0)
        elif offset_str in ("00:00", "0", "+0", "-0"):
            offset_str = "+00:00"
            is_utc = True

    if tz_name and isinstance(tz_name, str):
        tz_clean = tz_name.strip().upper()
        if tz_clean not in ("UTC", "GMT", "ETC/UTC", "ETC/GMT", "Z", ""):
            is_utc = False

    return {
        "offset_str": offset_str or ("+00:00" if is_utc else "Unknown"),
        "offset_minutes": offset_minutes,
        "is_utc": is_utc,
        "timezone_name": str(tz_name).strip() if tz_name else None,
    }


from vcf_hci.bios import (
    _detect_cpu_power_mode,
    _detect_memory_ras_modes,
    _detect_side_channel_settings,
)
from vcf_hci.collector.system_boot import collect_system_boot
from vcf_hci.collector.system_cpu import (
    _CPU_SUMMARY_PLACEHOLDERS as _CPU_SUMMARY_PLACEHOLDERS,
)
from vcf_hci.collector.system_cpu import (
    KNOWN_XEON_E5_E7_CORES as KNOWN_XEON_E5_E7_CORES,
)
from vcf_hci.collector.system_cpu import (
    _normalize_cpu_summary_model as _normalize_cpu_summary_model,
)
from vcf_hci.collector.system_cpu import (
    collect_processor_evidence,
    normalize_processor_summary,
    processor_summary_seed,
)
from vcf_hci.collector.system_cpu import (
    lookup_cpu_memory_channels as lookup_cpu_memory_channels,
)
from vcf_hci.collector.system_cpu import (
    lookup_xeon_e5_e7_cores as lookup_xeon_e5_e7_cores,
)
from vcf_hci.collector.system_identity import (
    build_chassis_only_summary,
    collect_chassis_hardware,
    collect_os_evidence,
    normalize_chassis_label,
    resolve_blade_evidence,
    resolve_system_identity,
)
from vcf_hci.logging_utils import get_nested


class _SystemMixin(_CollectorBase):
    """Collection methods: system summary, memory, BIOS, BMC, secure boot."""

    def _collect_enclosure_details(self) -> dict:
        """Inspect Chassis Links.ContainedBy or Enclosure Chassis for blade enclosure telemetry."""
        result = {
            "is_enclosure_contained": False,
            "enclosure_uri": "",
            "enclosure_name": "",
            "enclosure_model": "",
            "enclosure_serial": "",
            "enclosure_part_number": "",
            "tray_id": "",
            "node_power_watts": None,
            "chassis_power_watts": None,
            "chassis_input_power_watts": None,
        }
        enc_uri = None
        c1 = self._get(self.chassis_uri) if getattr(self, "chassis_uri", None) else {}
        if isinstance(c1, dict):
            c_links = c1.get("Links") or {}
            contained_by = c_links.get("ContainedBy")
            if isinstance(contained_by, dict) and contained_by.get("@odata.id"):
                enc_uri = contained_by.get("@odata.id")

        if not enc_uri:
            for cu in (getattr(self, "chassis_uris", None) or []):
                if cu and "enclosure" in cu.lower() and cu != getattr(self, "chassis_uri", None):
                    enc_uri = cu
                    break

        if not enc_uri:
            return result

        enc_data = self._get(enc_uri)
        if not isinstance(enc_data, dict) or enc_data.get("error"):
            # Try case-insensitive fallback if needed
            for cu in (getattr(self, "chassis_uris", None) or []):
                if cu.lower() == enc_uri.lower():
                    enc_data = self._get(cu)
                    if isinstance(enc_data, dict) and not enc_data.get("error"):
                        enc_uri = cu
                        break

        if not isinstance(enc_data, dict) or enc_data.get("error"):
            return result

        result["is_enclosure_contained"] = True
        result["enclosure_uri"] = enc_uri
        raw_name = str(enc_data.get("Name") or "").strip()
        pn = str(enc_data.get("PartNumber") or "").strip()
        sn = str(enc_data.get("SerialNumber") or (enc_data.get("Oem") or {}).get("Dell", {}).get("ServiceTag") or "").strip()
        model = str(enc_data.get("Model") or "").strip()

        # Known enclosure Part Numbers / Models
        if pn in ("P12783-001", "P12783-B21") or "e910" in raw_name.lower():
            if not raw_name or raw_name.lower() in ("computer system chassis", "chassis", "enclosure"):
                raw_name = "HPE Edgeline EL8000 5U Blade Infrastructure"
            if not model:
                model = "Edgeline EL8000"

        result["enclosure_name"] = raw_name or model or "Blade Enclosure"
        result["enclosure_model"] = model or raw_name
        result["enclosure_serial"] = sn
        result["enclosure_part_number"] = pn

        # OEM telemetry (HPE TrayID, Power)
        hpe_oem = (enc_data.get("Oem") or {}).get("Hpe") or {}
        if isinstance(hpe_oem, dict):
            result["tray_id"] = str(hpe_oem.get("TrayID") or "").strip()
            result["node_power_watts"] = hpe_oem.get("NodePowerWatts")
            result["chassis_power_watts"] = hpe_oem.get("ChassisPowerWatts")
            result["chassis_input_power_watts"] = hpe_oem.get("ChassisInputPowerWatts")

        return result

    def collect_system_summary(self) -> Optional[dict]:
        if getattr(self, "auth_failed", False):
            return None
        chassis_mgmt = getattr(self, "chassis_management_info", {}) or {}
        if not self.sys_uri:
            if chassis_mgmt and chassis_mgmt.get("is_modular_chassis"):
                return build_chassis_only_summary(self.host, chassis_mgmt, getattr(self, "server_hostname", None))
            return None
        data = self._get(self.sys_uri) or {}
        if not data:
            return None
        self.sys_data = data
        model = data.get("Model") or "Unknown Server"
        vendor = data.get("Manufacturer") or "Unknown Vendor"
        cpu_model, cpu_count, channels_per_socket, total_cores, total_threads = processor_summary_seed(data)
        has_collection = bool(self.sys_uri)
        processors_list = []
        for processor in collect_processor_evidence(self):
            if processor is None:
                self._has_gpu_processors = True
            else:
                processors_list.append(processor)
        cpu_summary = normalize_processor_summary(cpu_model, cpu_count, channels_per_socket, total_cores, total_threads, processors_list, has_collection)

        system_identity = computer_system_inventory(data)
        tpm_badge = system_identity["tpm_status_badge"]
        tpm_posture_note = ""

        bios_version = data.get("BiosVersion", "Unknown")
        bios_date = self.oem_bios_date(data)

        os_raw = collect_os_evidence(self, data)

        # scan_host resolves and verifies DNS only when explicitly requested.
        # Collection must not perform an implicit PTR lookup.
        dns_name = getattr(self, "server_hostname", None)

        identity = resolve_system_identity(self, data, model, vendor)
        self.sys_sku = identity["sku"]
        self.sys_model = identity["model"]
        chassis_label, hci_appliance = normalize_chassis_label(identity["model"], identity["vendor"], identity["sku"])
        boot = collect_system_boot(self, data)

        enclosure_info = self._collect_enclosure_details()
        chassis_label, is_blade = resolve_blade_evidence(identity["model"], identity["sku"], chassis_label, enclosure_info)
        chassis_hardware = collect_chassis_hardware(self, identity["chassis_candidates"])

        # When TrustedModules is absent, surface BIOS TPM/TXT/TME policy as explicit posture.
        if system_identity.get("tpm_state") == "NotReported":
            bios_ref = data.get("Bios") or {}
            bios_uri = bios_ref.get("@odata.id") if isinstance(bios_ref, dict) else (
                f"{self.sys_uri}/Bios" if getattr(self, "sys_uri", None) else None
            )
            _tpm_attrs = {}
            if bios_uri:
                _bj = self._get(bios_uri, critical=False) or {}
                _tpm_attrs = _bj.get("Attributes") if isinstance(_bj.get("Attributes"), dict) else {}

            # Lenovo ThinkSystem TCG TPM attributes
            _lnv_tpm_dev = str(_tpm_attrs.get("TrustedComputingGroup_TPMDevice") or "").strip()
            _lnv_tpm_stat = str(_tpm_attrs.get("TrustedComputingGroup_DeviceStatus") or "").strip()
            if _lnv_tpm_dev.lower() == "enabled" and ("tpm2.0" in _lnv_tpm_stat.lower() or "tpm 2.0" in _lnv_tpm_stat.lower() or "present" in _lnv_tpm_stat.lower()):
                system_identity["tpm_state"] = "Enabled"
                system_identity["tpm_interface"] = "TPM 2.0"
                system_identity["tpm_status_badge"] = "<span class='badge success'>🟢 Enabled (TPM 2.0 Active)</span>"
                tpm_badge = system_identity["tpm_status_badge"]
                tpm_posture_note = f"BIOS TCG: {_lnv_tpm_stat} (Device {_lnv_tpm_dev})"
                if not data.get("TrustedModules"):
                    data["TrustedModules"] = [{
                        "InterfaceType": "TPM2_0",
                        "Status": {"State": "Enabled", "Health": "OK"}
                    }]
            elif _lnv_tpm_dev.lower() in ("disabled", "disable"):
                system_identity["tpm_state"] = "Disabled"
                system_identity["tpm_interface"] = "TPM 2.0" if "tpm2.0" in _lnv_tpm_stat.lower() else "TPM"
                system_identity["tpm_status_badge"] = "<span class='badge warning'>🟡 Disabled (TPM Disabled in BIOS)</span>"
                tpm_badge = system_identity["tpm_status_badge"]
                tpm_posture_note = f"BIOS TCG: {_lnv_tpm_stat} (Device {_lnv_tpm_dev})"
            else:
                _tpm_pol = str(
                    _tpm_attrs.get("TPMSecurityPolicy")
                    or _tpm_attrs.get("TPM_KMSSupport")
                    or _tpm_attrs.get("SupermicroBIOS_BasedTPMProvisionSupport")
                    or ""
                ).strip()
                _txt = str(_tpm_attrs.get("TXTSupport") or _tpm_attrs.get("Processors_TrustedExecutionTechnology") or "").strip()
                _tme = str(_tpm_attrs.get("MemoryEncryption_TME_") or _tpm_attrs.get("MemoryEncryption") or "").strip()
                if _tpm_pol or _txt or _tme:
                    tpm_posture_note = (
                        f"TrustedModules not exposed by BMC; BIOS TPM policy={_tpm_pol or 'n/a'}, "
                        f"TXT={_txt or 'n/a'}, TME={_tme or 'n/a'}"
                    )
                    tpm_badge = (
                        "<span class='badge warning'>🟡 TPM Not Exposed "
                        f"(BIOS {_tpm_pol or 'policy unknown'})</span>"
                    )
                    system_identity["tpm_state"] = "BiosPolicyOnly"
                    system_identity["tpm_status_badge"] = tpm_badge

        # FixedBootOrder OEM (ESXi proof when HostName/OS absent)
        fixed_boot_order = {}
        if getattr(self, "sys_uri", None):
            _fbo = self._get(f"{self.sys_uri}/Oem/Supermicro/FixedBootOrder", critical=False) or {}
            if isinstance(_fbo, dict) and _fbo and not _fbo.get("error"):
                fixed_boot_order = {
                    "boot_mode_selected": str(_fbo.get("BootModeSelected") or "").strip(),
                    "fixed_boot_order": _fbo.get("FixedBootOrder"),
                    "uefi_hard_disk": _fbo.get("UEFIHardDisk"),
                    "uefi_network": _fbo.get("UEFINetwork"),
                }

        summary = {
            "ip": self.host,
            "hostname": data.get("HostName", self.host),
            "dns_name": dns_name,
            "vendor": identity['vendor'],
            "model": identity['model'],
            "sku": identity['sku'],
            "chassis_label": chassis_label,
            "is_blade": is_blade,
            "enclosure_info": enclosure_info,
            "hci_appliance": hci_appliance,
            "chassis_management_info": chassis_mgmt,
            "chassis_hardware": chassis_hardware,
            "tpm_posture_note": tpm_posture_note,
            "fixed_boot_order": fixed_boot_order,
            "serial_number": identity['serial_number'],
            "system_uuid": str(data.get("UUID") or "").strip(),
            "asset_tag": system_identity["asset_tag"],
            "power_state": system_identity["power_state"],
            "health": system_identity["health"],
            "health_rollup": system_identity["health_rollup"],
            "status_state": system_identity["status_state"],
            "tpm_interface": system_identity["tpm_interface"],
            "tpm_firmware": system_identity["tpm_firmware"],
            "tpm_state": system_identity["tpm_state"],
            "bios_version": bios_version,
            "bios_release_date": bios_date,
            "bios_eval": {},
            "raw_boot_mode": boot["boot_mode"],
            "boot_mode": boot['boot_mode'],
            "boot_eval": {},
            "boot_target": boot['boot_target'],
            "persistent_boot_target": boot['persistent_boot_target'],
            "boot_order": boot['boot_order'],
            "boot_order_details": boot['boot_order_details'],
            "boot_override": boot['boot_override'],
            "total_memory_gb": (
                (data.get("MemorySummary") or {}).get("TotalSystemMemoryGiB")
                or (round(((data.get("MemorySummary") or {}).get("TotalSystemMemoryKiB") or 0) / 1048576) if (data.get("MemorySummary") or {}).get("TotalSystemMemoryKiB") else 0)
                or (round(((data.get("MemorySummary") or {}).get("TotalSystemMemoryMiB") or 0) / 1024) if (data.get("MemorySummary") or {}).get("TotalSystemMemoryMiB") else 0)
                or 0
            ),
            "tpm_status_badge": tpm_badge,
            "os_raw": os_raw,
            "cpu_summary": cpu_summary,
        }
        if "boot_progress" in system_identity:
            summary["boot_progress"] = system_identity["boot_progress"]
        if "watchdog" in system_identity:
            summary["watchdog"] = system_identity["watchdog"]
        return summary


    def collect_memory_details(self, cpu_count: int, channels_per_socket: int) -> dict:
        empty = {"total_dimms_populated": 0, "dimm_size_breakdown": {}, "active_channels_count": 0, "expected_channels_total": 0, "channel_display": "Unknown", "low_dimm_warning": False, "failed_dimms": [], "dimm_list": []}
        if not self.sys_uri:
            return empty
        active_channels, dimm_sizes, total_dimms = set(), {}, 0
        failed_dimms = []
        dimm_list = []
        expected = cpu_count * channels_per_socket
        mem_uri = f"{self.sys_uri}/Memory"
        fetch_expand_fn = getattr(self, "_fetch_expanded_collection", None)
        if callable(fetch_expand_fn) and getattr(self, "expand_supported", False):
            mem_coll = fetch_expand_fn(mem_uri)
            mem_members = self._get_members(mem_coll) if mem_coll else []
        else:
            mem_members = self._get_members(mem_uri)
        if not mem_members:
            sys_obj = getattr(self, "sys_data", {}) or {}
            mem_href = (
                get_nested(sys_obj, "Oem", "Hp", "links", "Memory", "href")
                or get_nested(sys_obj, "Oem", "Hpe", "links", "Memory", "href")
            )
            if mem_href:
                if callable(fetch_expand_fn) and getattr(self, "expand_supported", False):
                    mem_coll = fetch_expand_fn(mem_href)
                    mem_members = self._get_members(mem_coll) if mem_coll else []
                else:
                    mem_members = self._get_members(mem_href)
        total_slots = len(mem_members)

        # Concurrently fetch DIMM details via sub-threadpool
        dimm_uris = []
        dimm_jsons = []
        for m in mem_members:
            m_uri = m.get("@odata.id") if isinstance(m, dict) else (m if isinstance(m, str) else "")
            if isinstance(m, dict) and (m.get("CapacityMiB") is not None or m.get("DeviceLocator") or m.get("MemoryDeviceType") or len(m) > 2):
                dimm_jsons.append(m)
            elif m_uri and hasattr(self, "_request_cache") and m_uri in self._request_cache:
                cached_dimm = self._request_cache[m_uri]
                if isinstance(cached_dimm, dict) and len(cached_dimm) > 1:
                    dimm_jsons.append(cached_dimm)
                else:
                    dimm_uris.append(m_uri)
            elif m_uri:
                dimm_uris.append(m_uri)

        if dimm_uris:
            max_w = min(getattr(self, "_get_phase_worker_count", lambda d: d)(3), len(dimm_uris))
            _wrap_task = getattr(self, "_wrap_phase_task", lambda fn: fn)
            pool = ThreadPoolExecutor(max_workers=max_w)
            try:
                futures = [pool.submit(_wrap_task(self._get), uri) for uri in dimm_uris]
                wait(futures, timeout=15.0)
                for f in futures:
                    if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                        break
                    try:
                        if f.done():
                            res = f.result()
                            if res:
                                dimm_jsons.append(res)
                    except Exception as exc:
                        logger.debug(f"Error fetching DIMM URI: {exc}")
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

        # Inspect DIMMs to detect duplicate locators, DevType pattern, or 0-indexed sockets
        raw_locators = [str(d.get("DeviceLocator") or "").strip() for d in dimm_jsons if d.get("DeviceLocator")]
        locators_are_duplicate = len(dimm_jsons) > 1 and len(set(raw_locators)) <= 1
        has_devtype_pattern = any(
            re.search(r"DevType\d+[_-]?", str(d.get("Id") or d.get("Name") or ""), re.IGNORECASE)
            for d in dimm_jsons
        )
        raw_ml_sockets = [
            int(d.get("MemoryLocation", {}).get("Socket"))
            for d in dimm_jsons
            if isinstance(d.get("MemoryLocation"), dict) and d.get("MemoryLocation", {}).get("Socket") is not None
        ]
        socket_is_zero_indexed = bool(raw_ml_sockets and min(raw_ml_sockets) == 0)

        for dimm_idx, dimm in enumerate(dimm_jsons):
            status = dimm.get("Status")
            if not isinstance(status, dict):
                status = {}
            raw_state = status.get("State")
            state = str(raw_state).strip() if raw_state is not None else ""
            raw_health = status.get("Health")
            health = str(raw_health).strip() if raw_health is not None else "OK"

            dimm_id = str(dimm.get("Id") or "").strip()
            dimm_name = str(dimm.get("Name") or "").strip()
            dev_locator = str(dimm.get("DeviceLocator") or "").strip()

            cleaned_id = re.sub(r"^DevType\d+[_-]?", "", dimm_id, flags=re.IGNORECASE).strip()
            cleaned_name = re.sub(r"^DevType\d+[_-]?", "", dimm_name, flags=re.IGNORECASE).strip()
            for cand in (cleaned_id, cleaned_name):
                m_dimm = re.match(r"^DIMM(\d+)$", cand, re.IGNORECASE)
                if m_dimm:
                    cleaned_id = f"DIMM {m_dimm.group(1)}"
                    break

            service_label = str(
                (dimm.get("Location") or {}).get("PartLocation", {}).get("ServiceLabel")
                or dimm.get("DeviceID") or ""
            ).strip()

            if cleaned_id.isdigit():
                if service_label and "DIMM" in service_label.upper():
                    cleaned_id = service_label
                elif cleaned_name and "DIMM" in cleaned_name.upper():
                    cleaned_id = cleaned_name
                else:
                    cleaned_id = f"DIMM {cleaned_id}"

            if locators_are_duplicate or has_devtype_pattern or not dev_locator:
                slot = service_label or cleaned_name or cleaned_id or dev_locator or f"DIMM {dimm_idx}"
            else:
                slot = dev_locator or service_label or cleaned_name or cleaned_id or "Unknown"

            cap_mib = int(dimm.get("CapacityMiB") or 0)

            is_populated = cap_mib > 0 and (state in ("Enabled", "OK", "StandbyOnline", "Unknown", "") or raw_state is None) and health.upper() not in ("CRITICAL", "FAILED")

            if is_populated:
                total_dimms += 1
                cap_gb = cap_mib // 1024
                label = f"{cap_gb} GB {dimm.get('MemoryType', 'DRAM')}"
                dimm_sizes[label] = dimm_sizes.get(label, 0) + 1

                mem_loc = dimm.get("MemoryLocation") or {}
                ml_socket = mem_loc.get("Socket")
                ml_channel = mem_loc.get("Channel")

                loc = slot.upper().strip()
                parsed_sock = None
                parsed_chan = None

                # Socket detection — three patterns in priority order:
                #
                # P1: Named CPU/PROC/SOCKET prefix (HPE "PROC 1 DIMM 1A",
                #     Lenovo "CPU1_DIMM_A1", Cisco "CPU2_DIMM_D2")
                #     Use [._\s-] delimiter instead of \b so "CPU2_" (underscore) works.
                m_named = re.search(r"(?:PROC|CPU|SOCKET)[._\s-]*([1-4])(?:[._\s-]|$)", loc)
                if m_named:
                    parsed_sock = int(m_named.group(1))
                else:
                    # P2: Standalone "P{N}" prefix (Supermicro "P1-DIMMA1", "P1_DIMM_A1";
                    #     Cisco inverted "DIMM_P2_B1") — must be bounded by delimiters.
                    m_pnum = re.search(r"(?:^|[._\s-])P([1-4])(?:[._\s-])", loc)
                    if m_pnum:
                        parsed_sock = int(m_pnum.group(1))

                # Channel detection — depends on which socket pattern fired:
                if parsed_sock is not None:
                    m_cpu = m_named or m_pnum
                    # Style A: letter immediately after DIMM keyword
                    #   Lenovo/Cisco "CPU1_DIMM_A1", Supermicro "P1-DIMMA1"
                    #   No \b before DIMM — underscore is \w so word-boundary fails on _DIMM_
                    m_ch = re.search(r"DIMM[_\s]*([A-L])(?:\d|\b)", loc)
                    if m_ch:
                        parsed_chan = m_ch.group(1)
                    else:
                        # Style B: digit precedes channel letter — HPE iLO4 "PROC 1 DIMM 1A"
                        m_ch = re.search(r"\b\d+([A-L])\b", loc)
                        if m_ch:
                            parsed_chan = m_ch.group(1)
                        else:
                            # Style C: Cisco "DIMM_P2_B1" — letter after the P{N} block
                            if m_cpu:
                                rest = loc[m_cpu.end():]
                                m_ch = re.search(r"\b([A-L])\d?\b", rest)
                                if m_ch:
                                    parsed_chan = m_ch.group(1)
                else:
                    # P3: Dell iDRAC — "DIMM A1", "DIMM B4", "DIMM.Socket.A1", "A1", "B8" — no CPU prefix.
                    #   Socket letter: A=1, B=2, C=3, D=4.
                    #   Slot number maps sequentially across channels within that socket.
                    #   Guard: only fire when there is no preceding CPU/P qualifier.
                    m_dell = re.search(r"^(?:DIMM(?:[._\s-]*SOCKET)?[._\s-]*)?([A-D])(\d+)$", loc) or re.search(r"\bDIMM(?:[._\s-]*SOCKET)?[._\s-]+([A-D])(\d+)\b", loc)
                    if m_dell:
                        parsed_sock = ord(m_dell.group(1)) - ord('A') + 1
                        slot_num = int(m_dell.group(2))
                        parsed_chan = chr(ord('A') + (slot_num - 1) % max(1, channels_per_socket))

                # Last resort: any standalone channel letter A-L in the string
                if parsed_chan is None:
                    m_ch = re.search(r"\b([A-L])\d?\b", loc)
                    if m_ch:
                        parsed_chan = m_ch.group(1)

                if ml_socket is not None:
                    final_sock = int(ml_socket) + 1 if socket_is_zero_indexed else int(ml_socket)
                elif parsed_sock is not None:
                    final_sock = parsed_sock
                else:
                    final_sock = 1
                if final_sock == 0:
                    final_sock = 1

                bogus_channel_telemetry = locators_are_duplicate or has_devtype_pattern

                if ml_channel is not None and not bogus_channel_telemetry:
                    if isinstance(ml_channel, int):
                        final_chan = chr(ord('A') + (ml_channel % max(1, channels_per_socket)))
                    else:
                        final_chan = str(ml_channel).strip().upper()
                elif parsed_chan is not None:
                    final_chan = parsed_chan
                else:
                    m_slot_num = re.search(r"\bDIMM\s*(\d+)\b", slot, re.IGNORECASE)
                    raw_slot = None
                    if m_slot_num:
                        raw_slot = int(m_slot_num.group(1))
                    elif mem_loc.get("Slot") is not None:
                        raw_slot = int(mem_loc["Slot"])
                    elif loc.isdigit():
                        raw_slot = int(loc)

                    is_lenovo_sys = (
                        getattr(self, "vendor", "").lower() == "lenovo"
                        or "LENOVO" in str((getattr(self, "sys_data", {}) or {}).get("Manufacturer") or "").upper()
                        or "THINKSYSTEM" in str((getattr(self, "sys_data", {}) or {}).get("Model") or "").upper()
                    )
                    if is_lenovo_sys and channels_per_socket == 8 and raw_slot in LENOVO_THINKSYSTEM_8CH_DIMM_MAP:
                        mapped_sock, mapped_chan = LENOVO_THINKSYSTEM_8CH_DIMM_MAP[raw_slot]
                        final_chan = mapped_chan
                        if ml_socket is None and parsed_sock is None:
                            final_sock = mapped_sock
                    elif isinstance(raw_slot, int) and channels_per_socket > 0:
                        # Map numeric slots (e.g. 1..32 on dual-socket Lenovo ThinkSystem SR650 V4)
                        # or 1-DPC slots (0..7 on AMD EPYC single socket)
                        if total_slots <= channels_per_socket * max(1, cpu_count):
                            chan_idx = raw_slot % channels_per_socket
                            final_chan = chr(ord('A') + chan_idx)
                        else:
                            slot_1based = raw_slot if raw_slot > 0 else (raw_slot + 1)
                            slot_in_sock = (slot_1based - 1) % (channels_per_socket * 2)
                            chan_idx = slot_in_sock // 2
                            final_chan = chr(ord('A') + (chan_idx % channels_per_socket))
                    elif ml_channel is not None:
                        if isinstance(ml_channel, int):
                            final_chan = chr(ord('A') + (ml_channel % max(1, channels_per_socket)))
                        else:
                            final_chan = str(ml_channel).strip().upper()
                    else:
                        final_chan = "A"

                active_channels.add(f"S{final_sock}-Ch{final_chan}")

                operating_spd = int(dimm.get("OperatingSpeedMhz") or dimm.get("ConfiguredSpeedMhz") or 0)
                _allowed = [s for s in (dimm.get("AllowedSpeedsMHz") or [])
                            if isinstance(s, (int, float)) and s > 0]
                rated_spd = int(max(_allowed)) if _allowed else operating_spd
                if not operating_spd:
                    operating_spd = rated_spd

                _part_number = str(dimm.get("PartNumber") or "N/A").strip()
                _serial_number = str(
                    dimm.get("SerialNumber")
                    or get_nested(dimm, "Oem", "Dell", "DellMemory", "SerialNumber")
                    or get_nested(dimm, "Oem", "Hpe", "SerialNumber")
                    or ""
                ).strip()

                metrics_raw = dimm.get("Metrics")
                correctable_ecc = None
                uncorrectable_ecc = None
                from vcf_hci.collector.metrics_fetch import resolve_metrics_link
                m_data = resolve_metrics_link(self, metrics_raw)
                correctable_ecc = m_data.get("CorrectableECCErrorCount")
                uncorrectable_ecc = m_data.get("UncorrectableECCErrorCount")
                if correctable_ecc is None:
                    dell_mem = ((dimm.get("Oem") or {}).get("Dell") or {}).get("DellMemory") or {}
                    correctable_ecc = dell_mem.get("CorrectableECCErrorCount")
                    uncorrectable_ecc = dell_mem.get("UncorrectableECCErrorCount")

                # High ECC error count flag
                if (correctable_ecc and isinstance(correctable_ecc, (int, float)) and correctable_ecc > 100) or \
                   (uncorrectable_ecc and isinstance(uncorrectable_ecc, (int, float)) and uncorrectable_ecc > 0):
                    if health in ("OK", "Ok", ""):
                        health = "Warning"

                dimm_list.append({
                    "slot": slot,
                    "slot_locator": slot,
                    "id": dimm_id,
                    "name": dimm_name,
                    "capacity_gb": cap_gb,
                    "type": dimm.get("MemoryType", "DRAM"),
                    "speed_mhz": operating_spd,
                    "max_speed_mhz": rated_spd,
                    "manufacturer": str(dimm.get("Manufacturer") or "Unknown").strip(),
                    "part_number": _part_number,
                    "serial_number": _serial_number,
                    "socket": final_sock,
                    "channel": final_chan,
                    "slot_num": mem_loc.get("Slot"),
                    "state": state if state else "Enabled",
                    "health": health if health else "OK",
                    "correctable_ecc": correctable_ecc,
                    "uncorrectable_ecc": uncorrectable_ecc,
                })

                if health not in ("OK", "Ok", ""):
                    failed_dimms.append({
                        "slot": slot, "state": state or "Enabled", "health": health,
                        "part_number": _part_number,
                        "serial_number": _serial_number,
                    })
            elif state not in ("Absent", ""):
                _failed_sn = str(
                    dimm.get("SerialNumber")
                    or get_nested(dimm, "Oem", "Dell", "DellMemory", "SerialNumber")
                    or get_nested(dimm, "Oem", "Hpe", "SerialNumber")
                    or ""
                ).strip()
                failed_dimms.append({
                    "slot": slot, "state": state or "Unknown", "health": health,
                    "part_number": str(dimm.get("PartNumber") or "N/A").strip(),
                    "serial_number": _failed_sn,
                })
        active_chan = len(active_channels) if active_channels else (total_dimms // 2 if total_dimms > 0 else 1)
        return {
            "total_dimms_populated": total_dimms,
            "slot_count": total_slots,
            "dimm_size_breakdown": dimm_sizes,
            "active_channels_count": active_chan,
            "expected_channels_total": expected,
            "channel_display": f"{total_dimms} DIMMs across {active_chan} Active Channel(s)",
            "low_dimm_warning": total_dimms <= 2,
            "failed_dimms": failed_dimms,
            "dimm_list": dimm_list,
        }


    def collect_bmc_license(self) -> dict:
        """Detect BMC license tier and surface any restrictions on data collection.

        Vendors covered and what their licensing means for this tool:

          Dell iDRAC    — all inventory accessible at every iDRAC tier;
                          Enterprise/Datacenter adds KVM + virtual media only
          HPE iLO       — Standard tier provides full inventory; Advanced adds
                          KVM, Federation, Directory auth, power regulation
          Lenovo XCC    — Standard provides full inventory; Advanced/Enterprise
                          add remote console, virtual media, LXCA integration
          Supermicro    — DCMS (SFT-DCMS-SINGLE) can gate Storage + Network
                          collection; probed live so a Quick run warns first
          Cisco IMC     — no inventory license gate; Intersight management
                          requires a separate Intersight licence
          Intel BMC /
          others        — generic LicenseService fallback
        """
        result = {"license_name": "N/A", "badge": "", "vendor_note": ""}
        if not self.mgr_uri:
            return result
        mgr_data = self._get(self.mgr_uri) or {}
        sys_data = (self._get(self.sys_uri) if self.sys_uri else {}) or {}

        # ── Dispatch to OEM hook method ────────────────────────────────────
        oem_lic = self.oem_license_info(mgr_data, sys_data)
        if oem_lic and oem_lic.get("license_name") != "N/A":
            return oem_lic

        mgr_oem = mgr_data.get("Oem", {})
        sys_oem = (sys_data or {}).get("Oem", {})
        vendor_up = str((sys_data or {}).get("Manufacturer", "")).upper()

        # ── HPE iLO ────────────────────────────────────────────────────────
        ilo_license = (mgr_oem.get("Hpe") or {}).get("License") or {}
        if ilo_license:
            tier = ilo_license.get("LicenseType") or ilo_license.get("License", "Standard")
            result["license_name"] = tier
            tier_low = str(tier).lower()
            if "advanced" in tier_low or "essentials" in tier_low:
                result["badge"] = f"<span class='badge success'>🟢 HPE iLO {tier}</span>"
                result["vendor_note"] = (
                    "iLO Advanced enables KVM remote console, Federation, Directory "
                    "authentication, and advanced power regulation. All hardware inventory "
                    "in this report is available at the Standard tier."
                )
            elif "expired" in tier_low:
                # iLO reports "Expired" specifically when a license WAS installed
                # but the subscription or trial period has since lapsed.
                result["license_name"] = "iLO Advanced — License expired"
                result["badge"] = (
                    "<span class='badge warning'>🟡 HPE iLO Advanced — License expired</span>"
                )
                result["vendor_note"] = (
                    "An iLO Advanced license was previously installed but has expired. "
                    "Hardware inventory (Storage, Memory, NICs, Thermal, PSU) remains fully "
                    "accessible. Performance telemetry (CPU/memory/PCIe utilisation metrics), "
                    "KVM remote console, Federation, and Directory auth are unavailable until "
                    "the license is renewed."
                )
            elif tier_low in ("unlicensed", "", "none"):
                result["license_name"] = "iLO — No activation key"
                result["badge"] = (
                    "<span class='badge warning'>🟡 HPE iLO — No activation key installed</span>"
                )
                result["vendor_note"] = (
                    "No iLO Advanced license key is installed. "
                    "Hardware inventory (Storage, Memory, NICs, Thermal, PSU) is fully "
                    "accessible at the base tier. Performance telemetry (TelemetryService — "
                    "CPU/memory/PCIe utilisation metrics), KVM remote console, Federation, "
                    "and Directory auth require an iLO Advanced license."
                )
            else:
                result["badge"] = f"<span class='badge warning'>🟡 HPE iLO {tier}</span>"
                result["vendor_note"] = (
                    "iLO Standard: hardware inventory (Storage, Memory, NICs, Thermal, "
                    "PSU) is fully accessible. Upgrade to iLO Advanced to enable KVM "
                    "remote console, Federation, Directory auth, performance telemetry "
                    "(CPU/memory/PCIe utilisation), and detailed power regulation."
                )
            return result

        # ── Dell iDRAC ─────────────────────────────────────────────────────
        if "Dell" in mgr_oem or "DELL" in vendor_up:
            mgr_name = str(mgr_data.get("Name", "") or mgr_data.get("Model", "")).upper()
            if "ENTERPRISE" in mgr_name or "DATACENTER" in mgr_name:
                tier, cls, icon = "Enterprise", "success", "🟢"
            elif "EXPRESS" in mgr_name or "BASIC" in mgr_name:
                tier, cls, icon = "Express", "warning", "🟡"
            else:
                tier, cls, icon = "iDRAC", "info", "ℹ️"
            result["license_name"] = f"Dell {tier}"
            result["badge"] = f"<span class='badge {cls}'>{icon} Dell {tier}</span>"
            result["vendor_note"] = (
                "All hardware inventory (Storage, Memory, NICs, Thermal, PSU) is "
                "fully accessible at every iDRAC license tier. iDRAC Enterprise / "
                "Datacenter adds remote KVM console, virtual media, and advanced "
                "configuration management."
            )
            return result

        # ── Cisco IMC ──────────────────────────────────────────────────────
        if self.mgr_uri.endswith("/CIMC") or "CISCO" in vendor_up:
            result["license_name"] = "Cisco IMC"
            result["badge"] = (
                "<span class='badge success'>🟢 Cisco IMC — no inventory license required</span>"
            )
            result["vendor_note"] = (
                "Cisco IMC provides full Redfish inventory access without additional "
                "licensing. Centralised management via Cisco Intersight requires a "
                "separate Intersight Infrastructure Service license."
            )
            return result

        # ── Supermicro ─────────────────────────────────────────────────────
        if "Supermicro" in sys_oem or "SUPERMICRO" in vendor_up:
            # Probe the Storage collection now (Quick run skips it) so an SE
            # knows DCMS is missing before committing to a full run.
            lic_msg = None
            if self.sys_uri:
                storage_coll = self._get(f"{self.sys_uri}/Storage") or {}
                lic_msg = self._is_license_blocked(storage_coll)
            if lic_msg:
                result["license_name"] = "Supermicro (DCMS required)"
                result["badge"] = (
                    "<span class='badge danger'>🔴 Supermicro DCMS License Required</span>"
                )
                result["vendor_note"] = (
                    "Storage and network adapter inventory require the "
                    "SFT-DCMS-SINGLE (DataCenter Management Suite) license. "
                    "System info, BIOS version, and event log are accessible "
                    "without DCMS. Purchase SFT-DCMS-SINGLE and activate it via "
                    "the BMC web interface or Supermicro Update Manager (SUM) "
                    "to enable full inventory collection."
                )
            else:
                result["license_name"] = "Supermicro (DCMS / OOB)"
                result["badge"] = (
                    "<span class='badge success'>🟢 Supermicro — Redfish access OK</span>"
                )
                result["vendor_note"] = (
                    "Basic inventory is accessible. If storage or network data is "
                    "missing, the SFT-DCMS-SINGLE license (DataCenter Management "
                    "Suite) may be required on older firmware versions."
                )
            return result

        # ── Lenovo XCC / XCC2 / XCC3 ───────────────────────────────────────
        xcc_tier_ids = {
            "XCC_Enterprised":  ("Enterprise", 3),
            "XCC_Advanced":     ("Advanced",   2),
            "XCC2_Platinum":    ("Platinum",   3),
            "BMC_Premier":      ("Premier",    3),
        }
        lic_svc = self._get("/redfish/v1/LicenseService/Licenses", timeout=5) or {}
        if lic_svc.get("Members") is not None:
            best_tier, best_rank = "Standard", 1
            for member in self._get_members(lic_svc):
                lic_id = str(member.get("@odata.id", "")).split("/")[-1]
                lic_detail = self._get(member.get("@odata.id"), timeout=5) or {}
                state = (lic_detail.get("Status") or {}).get("State", "")
                if state not in ("Enabled", ""):
                    continue
                if lic_id in xcc_tier_ids:
                    name, rank = xcc_tier_ids[lic_id]
                    if rank > best_rank:
                        best_tier, best_rank = name, rank
            result["license_name"] = f"XCC {best_tier}"
            if best_rank >= 3:
                result["badge"] = (
                    f"<span class='badge success'>"
                    f"🟢 XCC {best_tier} (full telemetry enabled)</span>"
                )
            elif best_rank == 2:
                result["badge"] = (
                    f"<span class='badge success'>🟢 XCC {best_tier}</span>"
                )
                result["vendor_note"] = (
                    "XCC Advanced installed. Remote console and OS deployment "
                    "via LXCA also require XCC Enterprise."
                )
            else:
                result["badge"] = (
                    "<span class='badge warning'>"
                    "🟡 XCC Standard (Advanced / Enterprise upgrade available)</span>"
                )
                result["vendor_note"] = (
                    "Hardware inventory is fully accessible at Standard tier. "
                    "Remote console, virtual media, and OS deployment via LXCA "
                    "require XCC Advanced + Enterprise upgrades."
                )
            return result

        # ── Generic LicenseService fallback ────────────────────────────────
        lic_ep = (mgr_data.get("Links") or {}).get("LicenseService") or {}
        if isinstance(lic_ep, dict) and lic_ep.get("@odata.id"):
            lic_data = self._get(lic_ep["@odata.id"]) or {}
            tier = lic_data.get("Name") or lic_data.get("LicenseType", "")
            if tier:
                result["license_name"] = tier
                result["badge"] = f"<span class='badge info'>ℹ️ License: {tier}</span>"
        return result


    def check_bios_attributes(self) -> dict:
        if not self.sys_uri:
            return {
                "attributes": {},
                "normalized_attributes": {},
                "vmd_keys_found": {},
                "vmd_enabled_flag": False,
                "vmd_pending_flag": None,
                "pending_vmd_keys": {},
                "pending_attributes": {},
                "bios_pending_reboot": False,
                "memory_ras": [],
                "cpu_power": [],
                "side_channel": [],
            }
        bios_data = self._get(f"{self.sys_uri}/Bios") or {}
        attrs = bios_data.get("Attributes")
        if not isinstance(attrs, dict) or not attrs:
            oem_attrs = self.oem_extract_bios_attributes(bios_data) if hasattr(self, "oem_extract_bios_attributes") else {}
            attrs = oem_attrs if isinstance(oem_attrs, dict) else {}
            if not attrs:
                # Fallback to /Bios/Settings if /Bios had no attributes (e.g. Cisco CIMC)
                s_obj = self._get(f"{self.sys_uri}/Bios/Settings")
                if isinstance(s_obj, dict):
                    s_attrs = s_obj.get("Attributes")
                    if isinstance(s_attrs, dict) and s_attrs:
                        attrs = dict(s_attrs)
            if not attrs and isinstance(bios_data, dict):
                # Flat attributes fallback (e.g. HPE iLO 4 / Gen9)
                attrs = {
                    k: v for k, v in bios_data.items()
                    if not k.startswith("@") and k not in (
                        "Id", "Name", "Description", "Type", "Actions", "Links", "links", "Oem", "Status", "Members", "attribute_count"
                    ) and isinstance(v, (str, int, float, bool))
                }
        else:
            attrs = dict(attrs)
        found = {}
        for key, val in attrs.items():
            if any(s in key.lower() for s in ["vmd", "vroc", "nvmeraid", "nvme_raid"]):
                found[key] = val
        enabled = any(str(v).lower() in ["enabled", "true", "auto", "1"] for v in found.values())

        # Check for pending BIOS settings (@Redfish.Settings)
        settings_info = bios_data.get("@Redfish.Settings")
        settings_uri = None
        if isinstance(settings_info, dict):
            settings_obj = settings_info.get("SettingsObject")
            if isinstance(settings_obj, dict):
                settings_uri = settings_obj.get("@odata.id")
            elif "@odata.id" in settings_info:
                settings_uri = settings_info.get("@odata.id")
        if not settings_uri and "@Redfish.Settings" in bios_data:
            settings_uri = f"{self.sys_uri}/Bios/Settings"

        pending_data = self._get(settings_uri) if settings_uri else None
        pending_attrs = pending_data.get("Attributes") if isinstance(pending_data, dict) else {}
        if not pending_attrs and isinstance(pending_data, dict):
            pending_attrs = {
                k: v for k, v in pending_data.items()
                if not k.startswith("@") and k not in (
                    "Id", "Name", "Description", "Type", "Actions", "Links", "links", "Oem", "Status", "Members", "attribute_count"
                ) and isinstance(v, (str, int, float, bool))
            }
        pending_attrs = pending_attrs if isinstance(pending_attrs, dict) else {}

        bios_pending_reboot = False
        vmd_pending_flag = None
        pending_found = {}

        if pending_attrs:
            for k, v in pending_attrs.items():
                if k not in attrs or attrs.get(k) != v:
                    bios_pending_reboot = True
                    break

            for key, val in pending_attrs.items():
                if any(s in key.lower() for s in ["vmd", "vroc", "nvmeraid", "nvme_raid"]):
                    pending_found[key] = val

            if pending_found:
                vmd_pending_flag = any(str(v).lower() in ["enabled", "true", "auto", "1"] for v in pending_found.values())

        v_oem = getattr(self, "vendor", None)
        if not v_oem and hasattr(self, "VENDOR_MATCH") and self.VENDOR_MATCH:
            v_oem = str(self.VENDOR_MATCH[0]).lower()
        sys_sum = getattr(self, "sys_summary", {}) or {}
        if not v_oem and sys_sum.get("vendor"):
            v_oem = str(sys_sum["vendor"]).lower()
        c_arch = (sys_sum.get("cpu_summary") or {}).get("architecture")

        normalized_attrs = self.oem_normalize_bios_attributes(attrs) if hasattr(self, "oem_normalize_bios_attributes") else {}
        if not isinstance(normalized_attrs, dict):
            normalized_attrs = {}

        return {
            "attributes": attrs,
            "normalized_attributes": normalized_attrs,
            "vmd_keys_found": found,
            "vmd_enabled_flag": enabled,
            "vmd_pending_flag": vmd_pending_flag,
            "pending_vmd_keys": pending_found,
            "pending_attributes": pending_attrs,
            "bios_pending_reboot": bios_pending_reboot,
            "memory_ras": _detect_memory_ras_modes(attrs, vendor=v_oem, architecture=c_arch),
            "cpu_power":  _detect_cpu_power_mode(attrs, vendor=v_oem, architecture=c_arch),
            "side_channel": _detect_side_channel_settings(attrs),
        }


    def collect_secure_boot_redfish(self) -> dict:
        """Retrieve Secure Boot status from the DMTF standard /Systems/{id}/SecureBoot endpoint.

        Supported by Dell iDRAC 9, HPE iLO 5/6, Lenovo XCC, Cisco IMC.
        Falls back gracefully (info badge) when the endpoint is absent or the BMC
        firmware is too old to expose it.
        """
        empty = {"enabled": None, "current_boot": None, "badge": "<span class='badge info'>ℹ️ Secure Boot: Not Exposed</span>"}
        if not self.sys_uri:
            return empty
        sb = self._get(f"{self.sys_uri}/SecureBoot") or {}
        if not sb or sb.get("error"):
            return empty
        enabled = sb.get("SecureBootEnable")
        current_boot = sb.get("SecureBootCurrentBoot")
        mode = sb.get("SecureBootMode") or sb.get("mode")

        is_enabled = enabled is True or str(enabled).strip().lower() in ("true", "enabled", "1")
        is_disabled = enabled is False or str(enabled).strip().lower() in ("false", "disabled", "0")
        is_cur_active = current_boot is True or str(current_boot).strip().lower() in ("true", "enabled", "1")
        is_cur_inactive = current_boot is False or str(current_boot).strip().lower() in ("false", "disabled", "0")

        if is_enabled and is_cur_active:
            badge = "<span class='badge success'>🟢 Secure Boot: Enabled &amp; Active</span>"
        elif is_enabled and is_cur_inactive:
            badge = "<span class='badge warning'>🟡 Secure Boot: Enabled but Inactive Last Boot — check DB/MOK keys</span>"
        elif is_enabled and current_boot is None:
            badge = "<span class='badge success'>🟢 Secure Boot: Enabled</span>"
        elif is_disabled:
            badge = "<span class='badge warning'>🟡 Secure Boot: Disabled — enable for VCF 9.1 security baseline</span>"
        else:
            badge = "<span class='badge info'>ℹ️ Secure Boot: Unknown (check BMC firmware)</span>"
        res = {"enabled": enabled, "current_boot": current_boot, "badge": badge}
        if mode:
            res["mode"] = mode
        return res


    def collect_bmc_firmware(self) -> dict:
        """Read BMC/management-controller firmware version from /Managers/{id}.

        Returns 'bmc_model', 'bmc_fw_version', and default placeholder structures
        for 'bmc_fw_eval' and 'badge' to be enriched post-collection.
        """
        empty = {"bmc_model": "N/A", "bmc_fw_version": "N/A", "bmc_fw_eval": {"badge": "<span class='badge info'>ℹ️ N/A</span>"}, "badge": "<span class='badge info'>ℹ️ BMC FW: N/A</span>"}
        if not self.mgr_uri:
            return empty
        mgr_data = self._get(self.mgr_uri) or {}
        if not mgr_data or mgr_data.get("error"):
            return empty
        fw_ver   = str(mgr_data.get("FirmwareVersion", "")).strip() or "N/A"
        mgr_model = str(mgr_data.get("Model", "") or mgr_data.get("Name", "") or "").strip().upper()
        return {
            "bmc_model": mgr_model or "BMC",
            "bmc_fw_version": fw_ver,
            "bmc_fw_eval": {"badge": f"<span class='badge info'>ℹ️ {fw_ver}</span>"},
            "badge": f"<span class='badge info'>ℹ️ BMC FW: {fw_ver}</span>",
        }


    def collect_software_inventory_os(self) -> dict:
        """Scan /redfish/v1/UpdateService/SoftwareInventory for a VMware ESXi entry.

        Dell iDRAC and HPE iLO often publish an ESXi component in the software
        inventory even when the iSM/AMS host agent is not installed, providing a
        reliable build number.  Returns the first matching entry as a dict with
        keys: os_name, os_version, os_build, source.  Returns {} on failure or
        when no ESXi entry is found.
        """
        upd = self._get("/redfish/v1/UpdateService", timeout=5) or {}
        inv_ref = upd.get("SoftwareInventory") or {}
        inv_link = inv_ref.get("@odata.id") if isinstance(inv_ref, dict) else None
        if not inv_link:
            return {}
        members = self._get_members(inv_link)
        _esxi_kw = {"ESXI", "VMWARE", "VSPHERE", "VMW_ESXI"}
        for m in members:
            item = self._get(m.get("@odata.id", "")) or {}
            name    = str(item.get("Name") or item.get("Id") or "").strip()
            name_up = name.upper().replace("-", "").replace("_", "")
            if any(kw in name_up for kw in _esxi_kw):
                version  = str(item.get("Version") or "").strip()
                # SoftwareId sometimes carries the full build number for Dell/HPE
                sw_id    = str(item.get("SoftwareId") or "").strip()
                # Attempt to extract a pure numeric build from Version or SoftwareId
                _build   = ""
                for _candidate in (sw_id, version):
                    _m = re.search(r'\b(\d{7,9})\b', _candidate)
                    if _m:
                        _build = _m.group(1)
                        break
                return {
                    "os_name":    name,
                    "os_version": version,
                    "os_build":   _build,
                    "source":     "SoftwareInventory",
                }
        return {}

    def collect_bmc_network_protocol(self) -> dict:
        """Collect NTP sync status, management network protocols, and VirtualMedia status."""
        result = {
            "ntp_enabled": False,
            "ntp_servers": [],
            "ntp_configured": False,
            "has_ntp_servers": False,
            "dns_enabled": False,
            "dns_servers": [],
            "dns_configured": False,
            "protocols": {},
            "virtual_media_inserted": False,
            "bmc_datetime": None,
            "datetime_local_offset": None,
            "is_utc": True,
            "timezone_name": None,
            "time_drift_seconds": None,
            "time_drift_detected": False,
            "badge": "<span class='badge info'>ℹ️ Network Protocol: N/A</span>",
        }
        if not self.mgr_uri:
            return result

        mgr_data = self._get(self.mgr_uri) or {}
        tz_info = {"offset_str": "+00:00", "offset_minutes": 0, "is_utc": True, "timezone_name": None}
        if isinstance(mgr_data, dict):
            bmc_dt_raw = mgr_data.get("DateTime")
            if bmc_dt_raw:
                result["bmc_datetime"] = str(bmc_dt_raw).strip()
                tz_info = _extract_bmc_timezone_info(mgr_data, result["bmc_datetime"])
                result["datetime_local_offset"] = tz_info["offset_str"]
                result["is_utc"] = tz_info["is_utc"]
                result["timezone_name"] = tz_info["timezone_name"]
                bmc_dt = _parse_iso_datetime(result["bmc_datetime"])
                if bmc_dt:
                    now_utc = datetime.now(timezone.utc)
                    drift_sec = int(round((bmc_dt - now_utc).total_seconds()))
                    result["time_drift_seconds"] = drift_sec
                    if abs(drift_sec) > 300:  # > 5 minutes threshold
                        result["time_drift_detected"] = True
            else:
                tz_info = _extract_bmc_timezone_info(mgr_data, None)
                result["datetime_local_offset"] = tz_info["offset_str"]
                result["is_utc"] = tz_info["is_utc"]
                result["timezone_name"] = tz_info["timezone_name"]

        net_proto = self._get(f"{self.mgr_uri}/NetworkProtocol") or {}
        if net_proto and not net_proto.get("error"):
            ntp = net_proto.get("NTP") or {}
            ntp_enabled = bool(
                ntp.get("ProtocolEnabled", False)
                or ntp.get("Enabled", False)
                or ntp.get("ServiceEnabled", False)
            )
            ntp_servers = _extract_ntp_servers(net_proto)
            result["ntp_enabled"] = ntp_enabled
            result["ntp_servers"] = ntp_servers
            result["has_ntp_servers"] = bool(ntp_servers)
            result["ntp_configured"] = bool(ntp_enabled and ntp_servers)

            dns = net_proto.get("DNS") or net_proto.get("Dns") or {}
            dns_enabled = bool(
                dns.get("ProtocolEnabled", False)
                or dns.get("Enabled", False)
                or dns.get("ServiceEnabled", False)
            ) if isinstance(dns, dict) else False
            dns_servers = _extract_dns_servers(net_proto)
            result["dns_enabled"] = dns_enabled
            result["dns_servers"] = dns_servers
            result["dns_configured"] = bool(dns_servers or (dns_enabled and dns_servers))

            protos = {}
            for proto_key in ("HTTP", "HTTPS", "SSH", "IPMI", "Telnet", "SNMP", "VirtualMedia"):
                p_obj = net_proto.get(proto_key) or {}
                if isinstance(p_obj, dict):
                    protos[proto_key] = {
                        "enabled": bool(p_obj.get("ProtocolEnabled", False)),
                        "port": p_obj.get("Port"),
                    }
            result["protocols"] = protos

        vm_coll = self._get(f"{self.mgr_uri}/VirtualMedia") or {}
        if vm_coll and isinstance(vm_coll.get("Members"), list):
            for m in self._get_members(vm_coll):
                vm_item = self._get(m.get("@odata.id", "")) or {}
                if vm_item.get("Inserted") or vm_item.get("Image"):
                    result["virtual_media_inserted"] = True
                    break

        if result["time_drift_detected"] and result["time_drift_seconds"] is not None:
            d_sec = abs(result["time_drift_seconds"])
            mins = d_sec // 60
            secs = d_sec % 60
            drift_str = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
            tz_tag = f" [{result['datetime_local_offset']}]" if (not result.get("is_utc") and result.get("datetime_local_offset") and result.get("datetime_local_offset") != "Unknown") else ""
            result["badge"] = f"<span class='badge danger'>🔴 Time Skew Detected ({drift_str}{tz_tag})</span>"
        elif result["ntp_enabled"] and result["ntp_servers"]:
            result["badge"] = f"<span class='badge success'>🟢 NTP Active ({', '.join(result['ntp_servers'][:2])})</span>"
        elif result["ntp_enabled"]:
            result["badge"] = "<span class='badge warning'>🟡 NTP Enabled (No Servers)</span>"
        else:
            result["badge"] = "<span class='badge warning'>🟡 NTP Disabled (Time Skew Risk)</span>"
        return result


    def collect_firmware_inventory(self) -> list:
        """Fetch complete hardware firmware inventory from /redfish/v1/UpdateService/FirmwareInventory."""
        fw_uri_base = "/redfish/v1/UpdateService/FirmwareInventory"
        fetch_expand_fn = getattr(self, "_fetch_expanded_collection", None)
        if callable(fetch_expand_fn) and getattr(self, "expand_supported", False):
            fw_inv = fetch_expand_fn(fw_uri_base) or {}
        else:
            fw_inv = self._get(fw_uri_base, timeout=15) or {}

        def _record_firmware_completeness(available: int, collected: int, cap: Optional[int]) -> None:
            truncated = collected < available
            meta = {
                "section": "firmware_inventory",
                "complete": not truncated,
                "truncated": truncated,
                "members_available": int(available),
                "members_collected": int(collected),
                "member_cap": cap if truncated else None,
            }
            if truncated:
                meta["reason"] = "firmware member cap"
            self._firmware_collection = meta

        if not fw_inv or not isinstance(fw_inv.get("Members"), list):
            _record_firmware_completeness(0, 0, None)
            return []
        items = []
        _skip_sw_keywords = [
            "oscollector", "driverpack", "servicemodule", "diagnostics",
            "lc.embedded", "bootstrapos", "dellos", "dellsoftware", "lifecyclecontroller",
            "flexutil", "internal-sd", "mezzanine-stub"
        ]
        members_to_fetch = []
        for member in self._get_members(fw_inv):
            if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                break
            try:
                fw_uri = member.get("@odata.id") if isinstance(member, dict) else None
                if not fw_uri:
                    continue
                fw_uri_low = fw_uri.lower()
                # Skip inactive rollback firmware versions and non-hardware software packages
                if "/previous-" in fw_uri_low or "previous" in fw_uri_low:
                    continue
                if any(sw in fw_uri_low for sw in _skip_sw_keywords):
                    continue

                if isinstance(member, dict) and member.get("Name") and member.get("Version"):
                    items.append(member)
                else:
                    members_to_fetch.append(fw_uri)
            except Exception as exc:
                logger.debug("Error inspecting firmware inventory member %s: %s", member, exc)

        # Deduplicate Installed-* vs Current-* entries for pre-expanded components
        if items:
            current_suffixes = set()
            for itm in items:
                uri = str(itm.get("@odata.id") or itm.get("Id") or "")
                last_seg = uri.rsplit('/', 1)[-1]
                if last_seg.startswith("Current-"):
                    suffix = last_seg.rsplit("__", 1)[-1] if "__" in last_seg else last_seg.replace("Current-", "", 1)
                    current_suffixes.add(suffix)
            if current_suffixes:
                deduped_items = []
                for itm in items:
                    uri = str(itm.get("@odata.id") or itm.get("Id") or "")
                    last_seg = uri.rsplit('/', 1)[-1]
                    if last_seg.startswith("Installed-"):
                        suffix = last_seg.rsplit("__", 1)[-1] if "__" in last_seg else last_seg.replace("Installed-", "", 1)
                        if suffix in current_suffixes:
                            continue
                    deduped_items.append(itm)
                items = deduped_items

        if members_to_fetch and not (callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped()):
            # Deduplicate Installed-* vs Current-* entries (Dell iDRAC exposes both for every component)
            current_suffixes = set()
            for uri in members_to_fetch:
                last_seg = uri.rsplit('/', 1)[-1]
                if last_seg.startswith("Current-"):
                    suffix = last_seg.rsplit("__", 1)[-1] if "__" in last_seg else last_seg.replace("Current-", "", 1)
                    current_suffixes.add(suffix)

            deduped_uris = []
            for uri in members_to_fetch:
                last_seg = uri.rsplit('/', 1)[-1]
                if last_seg.startswith("Installed-"):
                    suffix = last_seg.rsplit("__", 1)[-1] if "__" in last_seg else last_seg.replace("Installed-", "", 1)
                    if suffix in current_suffixes:
                        continue
                deduped_uris.append(uri)

            def _fw_uri_prio(uri: str) -> int:
                u_low = uri.lower()
                if any(k in u_low for k in ("bios", "idrac", "ilo", "bmc", "xcc", "cpld", "system", "nic", "embedded", "integrated", "raid", "controller")):
                    return 0
                if any(k in u_low for k in ("psu", "power", "fan", "backplane")):
                    return 1
                return 2

            deduped_uris.sort(key=_fw_uri_prio)

            if len(deduped_uris) >= 75:
                # Pathological collection ceiling: BMC has 75+ components (matching fishymetrics scale guardrail)
                logger.warning(
                    "[%s] Pathological firmware inventory count (%d >= 75). Enforcing priority ceiling of 35 items to prevent BMC exhaustion.",
                    getattr(self, "host", "unknown"),
                    len(deduped_uris),
                )
                members_to_fetch = [u for u in deduped_uris if _fw_uri_prio(u) <= 1][:35]
            elif getattr(self, "_throttled", False):
                members_to_fetch = deduped_uris[:25]
            else:
                members_to_fetch = deduped_uris[:40]

            _record_firmware_completeness(
                len(items) + len(deduped_uris),
                len(items) + len(members_to_fetch),
                len(members_to_fetch),
            )
            if len(deduped_uris) > len(members_to_fetch):
                logger.warning("[%s] Capping firmware inventory members from %d to %d prioritized items to reduce BMC load", getattr(self, "host", "unknown"), len(deduped_uris), len(members_to_fetch))

            def _fetch_fw_obj(uri: str) -> Optional[dict]:
                return self._get(uri, critical=False)

            max_w = min(getattr(self, "_get_phase_worker_count", lambda d: d)(3), max(1, len(members_to_fetch)))
            _wrap_task = getattr(self, "_wrap_phase_task", lambda fn: fn)
            fetched_objs = []
            pool = ThreadPoolExecutor(max_workers=max_w)
            try:
                futures = [pool.submit(_wrap_task(_fetch_fw_obj), uri) for uri in members_to_fetch]
                wait(futures, timeout=25.0)
                for fut in futures:
                    if callable(getattr(self, "_is_cancelled_or_skipped", None)) and self._is_cancelled_or_skipped():
                        break
                    try:
                        if fut.done():
                            res = fut.result()
                            if res and not res.get("error"):
                                fetched_objs.append(res)
                    except Exception as err:
                        logger.debug("Error fetching firmware inventory member: %s", err)

                items.extend(fetched_objs)
            finally:
                pool.shutdown(wait=False, cancel_futures=True)
        elif not getattr(self, "_firmware_collection", None):
            _record_firmware_completeness(len(items), len(items), None)

        parsed_items = []
        for fw_obj in items:
            if not isinstance(fw_obj, dict):
                continue
            name = str(fw_obj.get("Name") or fw_obj.get("Id") or "Unknown").strip()
            version = str(fw_obj.get("Version") or "N/A").strip()
            updateable = fw_obj.get("Updateable")
            comp_id = str(fw_obj.get("SoftwareId") or fw_obj.get("ComponentId") or fw_obj.get("Manufacturer") or "").strip()
            desc = str(fw_obj.get("Description") or "").strip()
            dev_ctx = str(
                get_nested(fw_obj, "Oem", "Hpe", "DeviceContext")
                or get_nested(fw_obj, "Oem", "Dell", "DeviceContext")
                or fw_obj.get("DeviceContext")
                or ""
            ).strip()
            fw_status = fw_obj.get("Status") if isinstance(fw_obj.get("Status"), dict) else {}
            status_health = fw_status.get("Health")
            status_state = fw_status.get("State")
            related_items = []
            raw_related = fw_obj.get("RelatedItem") or []
            if isinstance(raw_related, list):
                for r in raw_related:
                    if isinstance(r, dict) and r.get("@odata.id"):
                        related_items.append(str(r["@odata.id"]).strip())
                    elif isinstance(r, str) and r.strip():
                        related_items.append(r.strip())
            parsed_items.append({
                "id": str(fw_obj.get("Id") or "").strip(),
                "name": name,
                "version": version,
                "updateable": updateable,
                "component_id": comp_id,
                "description": desc,
                "device_context": dev_ctx,
                "release_date": str(fw_obj.get("ReleaseDate") or "").strip(),
                "lowest_supported_version": str(fw_obj.get("LowestSupportedVersion") or "").strip(),
                "status_health": str(status_health).strip() if status_health not in (None, "") else "",
                "status_state": str(status_state).strip() if status_state not in (None, "") else "",
                "related_items": related_items,
            })
        return parsed_items


