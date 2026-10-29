"""System/chassis/OS evidence ownership; the facade owns persistent state assignments."""
import re
from typing import Any, cast

from vcf_hci.collector.contracts import SystemCollector
from vcf_hci.constants import (
    DELL_MODEL_CHASSIS_DB,
    DELL_SKU_CHASSIS_DB,
    HCI_APPLIANCE_PATTERNS,
    HPE_SKU_CHASSIS_DB,
    LENOVO_MODEL_CHASSIS_DB,
)


def build_chassis_only_summary(host: str, chassis_mgmt: dict, dns_name: Any) -> dict:
    """Retain the non-compute enclosure-only result without collector state writes."""
    # DNS resolution is performed centrally only when --dns-lookup
    # (or certificate verification) explicitly requests it.
    m_model = chassis_mgmt.get("chassis_model") or "Modular Server Chassis"
    m_vendor = chassis_mgmt.get("vendor") or "Modular Chassis"
    m_mgr_name = chassis_mgmt.get("chassis_manager_name") or "Enclosure Management Controller"
    return {
        "ip": host,
        "hostname": chassis_mgmt.get("enclosure_name") or host,
        "dns_name": dns_name,
        "vendor": m_vendor,
        "model": f"{m_model} ({m_mgr_name})",
        "sku": "",
        "chassis_label": m_model,
        "hci_appliance": False,
        "serial_number": chassis_mgmt.get("chassis_serial") or "",
        "bios_version": "N/A (Chassis Management Module)",
        "bios_release_date": "N/A",
        "bios_eval": {"badge": "<span class='badge info'>ℹ️ Chassis Management Module</span>", "verdict": "CHASSIS_MANAGER"},
        "boot_mode": "N/A",
        "boot_eval": {"badge": "<span class='badge info'>ℹ️ Chassis Manager</span>", "verdict": "N/A"},
        "boot_target": "N/A",
        "persistent_boot_target": "N/A",
        "boot_order": [],
        "boot_order_details": [],
        "boot_override": {"is_active": False, "target": "None", "enabled": "Disabled", "mode": ""},
        "total_memory_gb": 0,
        "tpm_status_badge": "<span class='badge info'>ℹ️ Chassis Management Controller</span>",
        "os_raw": {
            "name": m_mgr_name,
            "version": "",
            "description": "Modular Enclosure Controller",
            "source": "Chassis Manager",
        },
        "cpu_summary": {
            "count": 0,
            "core_count": "N/A",
            "logical_count": "N/A",
            "cores_per_socket": None,
            "threads_per_socket": None,
            "ht_enabled": None,
            "base_freq_ghz": None,
            "max_freq_ghz": None,
            "model": f"Chassis Manager ({chassis_mgmt.get('sled_count', 0)} Sleds Managed)",
            "architecture": "Chassis Management Controller",
            "channels_per_socket": 0,
            "max_ram_speed_mhz": 0,
            "max_pcie_lanes_per_socket": 0,
            "verdict": "Modular Chassis Enclosure (Compute Sleds Assessed Separately)",
            "processor_id": None,
            "cache_list": [],
            "socket_label": "",
            "processors": [],
            "asymmetry_detected": False,
            "asymmetry_note": None,
        },
        "chassis_management_info": chassis_mgmt,
    }


def normalize_os_evidence(data: dict, _oem_os: dict, _dsi: dict, _dell_sys: dict, _hpe_host_os: dict, _csc_os_info: dict) -> dict:
    """Apply existing OEM/standard source precedence to already-acquired OS evidence."""
    raw_os_name = str(
        _oem_os.get("name")
        or _dsi.get("OSName")
        or _dell_sys.get("OSName")
        or _hpe_host_os.get("OsName")
        or _csc_os_info.get("OSName")
        or data.get("OSName")
        or ""
    ).strip()
    raw_os_ver = str(
        _oem_os.get("version")
        or _dsi.get("OSVersion")
        or _dell_sys.get("OSVersion")
        or _hpe_host_os.get("OsVersion")
        or _csc_os_info.get("OSVersion")
        or data.get("OSVersion")
        or ""
    ).strip()
    # HPE AMS provides a richer description string (e.g. "Build 20348.2227")
    raw_os_desc = str(_oem_os.get("description") or _hpe_host_os.get("OsDescription") or "").strip()

    powered_on_sec = _oem_os.get("powered_on_seconds")
    uptime_days = _oem_os.get("uptime_days")
    uptime_human = _oem_os.get("uptime_human")

    if _oem_os.get("source"):
        os_src = _oem_os.get("source")
    elif _dsi.get("OSName"):
        os_src = "Dell iSM"
    elif _dell_sys.get("OSName"):
        os_src = "Dell OEM"
    elif _hpe_host_os.get("OsName"):
        os_src = "HPE AMS"
    elif _csc_os_info.get("OSName"):
        os_src = "Cisco OEM"
    elif data.get("OSName"):
        os_src = "Redfish"
    else:
        os_src = ""

    return {'name': raw_os_name, 'version': raw_os_ver, 'description': raw_os_desc, 'source': os_src, 'powered_on_seconds': powered_on_sec, 'uptime_days': uptime_days, 'uptime_human': uptime_human}


def collect_os_evidence(self: SystemCollector, data: dict) -> dict:
    """Capture raw OEM maps before the existing OS hook, then normalize."""
    # ── OS detection from OEM fields (requires host-side agent) ──────────
    # Dell iDRAC: iSM (iDRAC Service Module) must be installed on host OS.
    # HPE iLO: AMS (Agentless Management Service) must be running on host.
    # Cisco CIMC: Intersight Device Connector or host driver integration.
    _oem_blk  = data.get("Oem") or {}
    _dell_oem = _oem_blk.get("Dell") or {}
    _hpe_oem  = _oem_blk.get("Hpe") or {}
    _csc_oem  = _oem_blk.get("Cisco") or {}
    # Dell exposes OS info under Oem.Dell.DSI (iSM path) or Oem.Dell.DellSystem
    _dsi      = _dell_oem.get("DSI") or {}
    _dell_sys = _dell_oem.get("DellSystem") or {}
    _hpe_host_os = _hpe_oem.get("HostOS") or {}
    _csc_os_info = _csc_oem.get("OsInfo") or {}

    # Allow OEM hook to query vendor-specific OS endpoints (e.g. Dell $select attribute filtering)
    _oem_os = self.oem_os_info(data) if hasattr(self, "oem_os_info") else {}

    return normalize_os_evidence(data, _oem_os, _dsi, _dell_sys, _hpe_host_os, _csc_os_info)


def resolve_system_identity(self: SystemCollector, data: dict, model: str, vendor: str) -> dict:
    """Resolve chassis/FRU identity and SKU without assigning consumed collector state."""
    serial_num = str(data.get("SerialNumber", "Unknown")).strip()

    # Fallback for partitioned or scale-up systems where Model / Serial / Manufacturer are missing in Partition0
    chassis_candidates = []
    if getattr(self, "chassis_uri", None):
        chassis_candidates.append(cast(str, self.chassis_uri))
    if getattr(self, "chassis_uris", None):
        for cu in self.chassis_uris:
            if cu not in chassis_candidates:
                chassis_candidates.append(cu)

    _placeholder_vendors = {
        "TO BE FILLED BY O.E.M.", "DEFAULT STRING", "SYSTEM MANUFACTURER",
        "UNKNOWN VENDOR", "UNKNOWN", "",
    }

    if (model in ("Unknown Server", "", None) or vendor.upper().strip() in _placeholder_vendors or serial_num in ("Unknown", "", None, "To Be Filled By O.E.M.")) and chassis_candidates:
        for c_uri in chassis_candidates:
            c_obj = self._get(c_uri) or {}
            if model in ("Unknown Server", "", None):
                c_model = c_obj.get("Model") or c_obj.get("Name")
                if c_model and str(c_model).lower() not in ("chassis", "enclosure", "unknown"):
                    model = str(c_model).strip()
            if vendor.upper().strip() in _placeholder_vendors:
                c_vendor = c_obj.get("Manufacturer") or c_obj.get("Vendor")
                if c_vendor and str(c_vendor).upper().strip() not in _placeholder_vendors:
                    vendor = str(c_vendor).strip()
            if serial_num in ("Unknown", "", None, "To Be Filled By O.E.M."):
                c_sn = c_obj.get("SerialNumber")
                if c_sn and str(c_sn).upper().strip() not in ("UNKNOWN", "NONE", "", "TO BE FILLED BY O.E.M."):
                    serial_num = str(c_sn).strip()
            if model not in ("Unknown Server", "", None) and vendor.upper().strip() not in _placeholder_vendors and serial_num not in ("Unknown", "", None, "To Be Filled By O.E.M."):
                break

    # Normalize known whitebox motherboards where SMBIOS vendor was left as default
    if vendor.upper().strip() in _placeholder_vendors:
        _model_up = model.upper().strip()
        if "ROMED8" in _model_up or "EPYCD8" in _model_up or "GENOAD8" in _model_up or "BERGAMOD8" in _model_up or "SP3" in _model_up:
            vendor = "ASRock Rack"
        elif _model_up.startswith(("X11", "X12", "X13", "H11", "H12", "H13", "SYS-")):
            vendor = "Supermicro"
        elif _model_up.startswith(("MZ31", "MZ32", "MZ71", "MZ72")):
            vendor = "Gigabyte"

    # FruInfo fallback for whitebox / OEM platforms where SMBIOS DMI was unpopulated
    _bad_sn = serial_num.upper().strip() in ("UNKNOWN", "", "NONE", "TO BE FILLED BY O.E.M.", "DEFAULT STRING")
    _bad_vendor = vendor.upper().strip() in _placeholder_vendors
    _bad_model = model in ("Unknown Server", "", None, "To Be Filled By O.E.M.")
    fru_board_part = ""
    if (_bad_sn or _bad_vendor or _bad_model) and self.sys_uri:
        fru_info = self._get(f"{self.sys_uri}/FruInfo")
        if isinstance(fru_info, dict):
            board = fru_info.get("Board") or {}
            prod = fru_info.get("Product") or {}
            chassis = fru_info.get("Chassis") or {}

            b_mfg = str(board.get("Manufacturer") or prod.get("Manufacturer") or "").strip()
            b_prod = str(board.get("ProductName") or prod.get("ProductName") or "").strip()
            b_sn = str(board.get("SerialNumber") or prod.get("SerialNumber") or chassis.get("SerialNumber") or "").strip()
            b_part = str(board.get("PartNumber") or prod.get("PartNumber") or "").strip()
            if b_part:
                fru_board_part = b_part

            if _bad_vendor and b_mfg and b_mfg.upper().strip() not in _placeholder_vendors:
                if b_mfg.upper() in ("ASROCKRACK", "ASROCK"):
                    vendor = "ASRock Rack"
                else:
                    vendor = b_mfg
            if _bad_model and b_prod and b_prod.upper().strip() not in _placeholder_vendors:
                model = b_prod
            if _bad_sn and b_sn and b_sn.upper().strip() not in ("UNKNOWN", "NONE", "", "TO BE FILLED BY O.E.M.", "DEFAULT STRING"):
                serial_num = b_sn

    # ── Server SKU / product number ───────────────────────────────────────
    # DMTF standard: System.SKU  |  HPE OEM fallback: Oem.Hpe.ProductId
    sku_raw = (
        self.oem_sku(data)
        or data.get("SKU")
        or ((data.get("Oem") or {}).get("Hpe") or {}).get("ProductId")
        or fru_board_part
        or ""
    ).strip().upper()
    if sku_raw.upper() == serial_num.upper():
        sku_raw = ""
    return {"model": model, "vendor": vendor, "serial_number": serial_num, "sku": sku_raw, "chassis_candidates": chassis_candidates}


def normalize_chassis_label(model: str, vendor: str, sku_raw: str) -> tuple:
    """Retain current SKU/model lookup and appliance classification."""
    # Chassis label — HPE/Dell: look up by SKU; Dell/Lenovo fallback: look up by model suffix
    _sku_db = HPE_SKU_CHASSIS_DB.get(sku_raw) or DELL_SKU_CHASSIS_DB.get(sku_raw)
    if _sku_db:
        chassis_label = _sku_db[1]
    else:
        _mkey = re.sub(r'^(?:PowerEdge|ProLiant|ThinkSystem)\s+', '', model, flags=re.I).upper().strip()
        _mkey = re.sub(r'[-]\d+$', '', _mkey)   # strip "-10" / "-24" XC variant suffixes
        _dell_db = DELL_MODEL_CHASSIS_DB.get(_mkey)
        if _dell_db:
            chassis_label = _dell_db[1]
        else:
            _lenovo_entry = LENOVO_MODEL_CHASSIS_DB.get(_mkey)
            if _lenovo_entry:
                chassis_label = _lenovo_entry.get("label", f"ThinkSystem {_mkey} · {_lenovo_entry.get('form_factor', '')}")
            else:
                chassis_label = ""

    # HCI appliance detection — iLO reports "ProLiant DX…"; iDRAC "XCxxx" / "VxRail Exxx"
    _model_vendor_str = f"{model} {vendor}".upper()
    hci_appliance = any(p.upper() in _model_vendor_str for p in HCI_APPLIANCE_PATTERNS)

    return chassis_label, hci_appliance


def resolve_blade_evidence(model: str, sku_raw: str, chassis_label: str, enclosure_info: dict) -> tuple:
    """Retain blade labels over current enclosure/model/SKU observations."""
    model_str = str(model).lower()
    sku_str = str(sku_raw).lower()
    is_cisco_b_blade = bool(
        re.search(r"\bucs[-_\s]?b|ucsb\b", model_str)
        or re.search(r"\bucs[-_\s]?b|ucsb\b", sku_str)
    )
    is_cisco_x_blade = bool(
        re.search(r"\bucs[-_\s]?x|ucsx\b", model_str)
        or re.search(r"\bucs[-_\s]?x|ucsx\b", sku_str)
    )
    is_blade = bool(
        enclosure_info.get("is_enclosure_contained")
        or "e910" in model_str
        or "blade" in model_str
        or "sled" in model_str
        or is_cisco_b_blade
        or is_cisco_x_blade
    )
    if not chassis_label:
        if is_cisco_b_blade:
            chassis_label = f"Cisco UCS B-Series Blade ({model})"
        elif is_cisco_x_blade:
            chassis_label = f"Cisco UCS X-Series Compute Node ({model})"
        elif enclosure_info.get("is_enclosure_contained"):
            chassis_label = f"Blade Sled · {enclosure_info.get('enclosure_name')}"
            if enclosure_info.get("tray_id"):
                chassis_label += f" (Tray {enclosure_info['tray_id']})"
        elif is_blade:
            chassis_label = f"Blade Server ({model})"

    return chassis_label, is_blade


def collect_chassis_hardware(self: SystemCollector, chassis_candidates: list) -> dict:
    """Read at most the original three chassis candidates in order."""
    # Chassis / board OEM identity (Supermicro BoardID / BoardSerial / GUID)
    chassis_hardware = {}
    for c_uri in chassis_candidates[:3]:
        c_obj = self._get(c_uri) or {}
        if not isinstance(c_obj, dict) or not c_obj:
            continue
        smc = ((c_obj.get("Oem") or {}).get("Supermicro") or {})
        if not isinstance(smc, dict):
            smc = {}
        chassis_hardware = {
            "manufacturer": str(c_obj.get("Manufacturer") or "").strip(),
            "model": str(c_obj.get("Model") or "").strip(),
            "part_number": str(c_obj.get("PartNumber") or "").strip(),
            "serial_number": str(c_obj.get("SerialNumber") or "").strip(),
            "board_serial": str(smc.get("BoardSerialNumber") or "").strip(),
            "board_id": str(smc.get("BoardID") or "").strip(),
            "guid": str(smc.get("GUID") or "").strip(),
        }
        if chassis_hardware.get("part_number") or chassis_hardware.get("board_id"):
            break

    return chassis_hardware
