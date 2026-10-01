"""
VCF Readiness Tool — Dell iDRAC (PowerEdge) OEM adapter.

Overrides OEM hook methods to read Dell-specific Redfish extensions:
  • BIOS release date  : Oem.Dell.DellSystem.BIOSReleaseDate
  • Drive endurance    : Oem.Dell.DellPhysicalDisk.RemainingRatedWriteEndurancePercent
  • CPU cache          : Oem.Dell.DellProcessor.Cache[]
  • OEM SKU            : Ignores System.SKU if it equals SerialNumber (Service Tag)

The base class already handles most Dell behaviour inline via vendor string
detection.  These hooks provide the recommended extension points for future
Dell-specific features.

Known Dell quirks (handled inline in base methods, documented here for reference):
  • iDRAC populates System.SKU with the Service Tag (e.g. 7SBKS13) rather than a product SKU.
  • iDRAC may return empty NICs/Storage when OS is not running (pre-boot state).
  • BOSS / NS204i drives appear in /Storage but should be flagged Boot-only.
  • DellEnclosure.SlotCount is the most reliable bay-count source.
"""
import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ...logging_utils import get_nested
from ..base import ExpandableCollectionsMap
from ..collect_system import _parse_iso_datetime
from ..pci_utils import normalize_pcie_gen, normalize_pcie_width
from .generic import GenericCollector

DELL_SECURITY_ATTRIBUTE_ALLOWLIST: Set[str] = {
    "activedirectory.1.certvalidationenable",
    "autodiscovery.1.enableipchangeannounce",
    "groupmanager.1.status",
    "gui.1.securitypolicymessage",
    "ipblocking.1.blockenable",
    "ipblocking.1.failcount",
    "ipblocking.1.failwindow",
    "ipblocking.1.penaltytime",
    "ipmisol.1.enable",
    "ldap.1.certvalidationenable",
    "localsecurity.1.localconfig",
    "localsecurity.1.prebootconfig",
    "lockdown.1.systemlockdown",
    "nic.1.autoconfig",
    "nic.1.selection",
    "nic.1.vlanenable",
    "nic.1.vlanid",
    "nic.1.vlanpriority",
    "ntpconfiggroup.1.ntp1securitykeynumber",
    "ntpconfiggroup.1.ntp1securitytype",
    "ntpconfiggroup.1.ntp2securitykeynumber",
    "ntpconfiggroup.1.ntp2securitytype",
    "ntpconfiggroup.1.ntp3securitykeynumber",
    "ntpconfiggroup.1.ntp3securitytype",
    "ntpconfiggroup.1.ntpenable",
    "os-bmc.1.adminstate",
    "os-bmc.1.ptmode",
    "scep.1.enable",
    "scep.1.enrollmentstatus",
    "security.1.fipsmode",
    "security.1.minimumpasswordscore",
    "security.1.passwordminimumlength",
    "security.1.passwordrequirenumbers",
    "security.1.passwordrequireregex",
    "security.1.passwordrequiresymbols",
    "security.1.passwordrequireuppercase",
    "ssh.1.enable",
    "ssh.1.timeout",
    "sshcrypto.1.ciphers",
    "sshcrypto.1.hostkeyalgorithms",
    "sshcrypto.1.kexalgorithms",
    "sshcrypto.1.macs",
    "syslog.1.secureclientauth",
    "syslog.1.secureport",
    "syslog.1.securesyslogenable",
    "usb.1.configurationxml",
    "usb.1.portstatus",
    "virtualconsole.1.encryptenable",
    "virtualconsole.1.plugintype",
    "virtualconsole.1.webredirect",
    "vncserver.1.enable",
    "vncserver.1.port",
    "vncserver.1.sslencryptionbitlength",
    "vncserver.1.timeout",
    "webserver.1.customcipherstring",
    "webserver.1.httpsredirection",
    "webserver.1.sslencryptionbitlength",
    "webserver.1.tlsprotocol",
    "securedefaultpassword.1.forcechangepassword",
    "platformcapability.1.livescancapable",
    "platformcapability.1.lcdcapable",
    "lcd.1.configuration",
    # iDRAC10 / 17G security extensions
    "redfishservice.1.enable",
    "telemetryservice.1.enable",
    "security.1.passwordcomplexity",
    "security.1.minpasswordage",
    "security.1.maxpasswordage",
    "nic.1.activenic",
    "nic.1.selectionbyfqdd",
    "nic.1.failoverbyfqdd",
    "os-bmc.1.usbp2penable",
    "os-bmc.1.lomp2penable",
    "network.1.autoconfig",
    "ipblocking.1.rangeenable",
    "ipblocking.1.rangeenable1",
    "ipblocking.1.rangeenable2",
    "ipblocking.1.rangeenable3",
    "ipblocking.1.rangeenable4",
    "ipblocking.1.rangeenable5",
    "ace.1.enable",
    "ace.1.enrollmentstatus",
    "ace.1.enrollmentaction",
    "scv.1.certificateversion",
    "scv.1.firmwarecertificateversion",
}

_SAFE_USER_ATTR_FIELDS: Set[str] = {
    "ipmilanprivilege",
    "ipmiserialprivilege",
    "solenable",
    "protocolenable",
    "authenticationprotocol",
    "privacyprotocol",
    "simple2fa",
    "rsasecurid2fa",
    "privilege",
}

_SAFE_SEKM_ATTR_FIELDS: Set[str] = {
    "enable",
    "sekmlicense",
    "status",
    "certstatus",
    "keymanagementtype",
}

_SAFE_LC_ATTR_FIELDS: Set[str] = {
    "ignorecertwarning",
    "collectsysteminventoryonrestart",
    "biostype",
    "partreplacement",
    "autodiscovery",
    "licensereplacement",
    "lifecyclecontrollerstate",
}

_SAFE_SNMP_ATTR_FIELDS: Set[str] = {
    "agentenable",
    "snmpprotocol",
    "trapformat",
    "port",
    "snmpv3enable",
}

_SAFE_IPMILAN_ATTR_FIELDS: Set[str] = {
    "enable",
    "privilegelimit",
}

_SECRET_KEY_FRAGMENTS: Tuple[str, ...] = (
    "password",
    "passphrase",
    "privatekey",
    "community",
    "secret",
    "token",
    "credential",
    "challenge",
    "bindpassword",
    "passcode",
    "seed",
    "otp",
)


def _is_secret_key(key: str) -> bool:
    """Check whether an attribute key segment indicates secret-bearing material."""
    k_low = key.lower()
    if k_low in DELL_SECURITY_ATTRIBUTE_ALLOWLIST:
        return False
    if "securitykeynumber" in k_low or "securitytype" in k_low:
        return False
    k_alnum = "".join(c for c in k_low if c.isalnum())
    return any(
        "".join(c for c in fragment.lower() if c.isalnum()) in k_alnum
        for fragment in _SECRET_KEY_FRAGMENTS
    )


def filter_dell_security_attributes(attrs: dict) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Filter raw Dell attributes against strict non-secret allowlists.

    Returns:
        Tuple of (retained_idrac_attributes, retained_lc_attributes).
    """
    if not isinstance(attrs, dict):
        return {}, {}

    idrac_retained: Dict[str, Any] = {}
    lc_retained: Dict[str, Any] = {}

    for k, v in attrs.items():
        k_str = str(k).strip()
        k_low = k_str.lower()

        if _is_secret_key(k_str):
            continue

        parts = k_low.split(".")
        prefix = parts[0] if parts else ""
        last_field = parts[-1] if len(parts) > 1 else ""

        is_allowed = (
            k_low in DELL_SECURITY_ATTRIBUTE_ALLOWLIST
            or (prefix == "users" and last_field in _SAFE_USER_ATTR_FIELDS)
            or (prefix == "sekm" and last_field in _SAFE_SEKM_ATTR_FIELDS)
            or (prefix == "lcattributes" and last_field in _SAFE_LC_ATTR_FIELDS)
            or (prefix == "snmp" and last_field in _SAFE_SNMP_ATTR_FIELDS)
            or (prefix == "ipmilan" and last_field in _SAFE_IPMILAN_ATTR_FIELDS)
        )

        if is_allowed:
            if prefix == "lcattributes":
                lc_retained[k_str] = v
            else:
                idrac_retained[k_str] = v

    return idrac_retained, lc_retained


def normalize_dell_bios_attributes(
    raw_attrs: Dict[str, Any],
    fallback_boot_mode: Optional[str] = None,
) -> Dict[str, Any]:
    """Normalize Dell BIOS attribute names and values across iDRAC generations.

    Inspects raw attributes dictionary (from /redfish/v1/Systems/.../Bios or
    Oem/Dell/DellAttributes) and extracts canonical baseline configuration settings:
      • SysProfile: System performance profile (e.g. PerfOptimized, Custom, PerfPerWattOptimizedDapc)
      • SubNumaCluster: Sub-NUMA Clustering (SNC) on Intel (e.g. Enabled, Disabled) or
                        AMD NumaNodesPerSocket (e.g. 1, 2, 4)
      • ProcVirtualization: Hardware virtualization (VT-x / AMD-V)
      • VmdSupport: Intel Volume Management Device state (Disabled / Enabled)
      • PcieAspm: PCIe Active State Power Management
      • LogicalProc: Logical processor (Hyper-Threading / SMT)
      • BootMode: System boot mode (Uefi / Bios)
      • ProcCStates: Processor C-States
      • ProcTurboMode: Processor Turbo Mode
      • SriovGlobalEnable: SR-IOV Global Enable
      • MemTest: BIOS memory testing
      • LatencyOptimizedMode: 17G Intel Xeon 6 LOM
      • PciMultiSegment: 17G AMD Turin PCIe multi-segment
      • ProcPwrPerf: CPU Power & Performance Mode (MaxPerf / OsDbpm)
      • ProcC1E: Processor C1E state
      • ApbDis: AMD Power Brake Disable (APBDIS)
      • DeterminismSlider: AMD Performance/Power Determinism
      • DfCState: AMD Data Fabric C-States
      • DfPstateFreqOptimizer: AMD Data Fabric P-State Optimizer
      • AmdCmnXgmiPstateControl: AMD xGMI P-State Control
      • AmdMaxXgmiSpeed: AMD xGMI Max Link Speed

    Args:
        raw_attrs: Raw attributes dictionary from Dell BIOS resource.
        fallback_boot_mode: Optional boot mode from system summary if absent in attributes.

    Returns:
        Dictionary of normalized canonical attribute keys and values.
    """
    normalized: Dict[str, Any] = {}
    if not isinstance(raw_attrs, dict):
        return normalized

    # 1. SysProfile
    for k in ("SysProfile", "SystemProfile", "PowerProfileSelect", "WorkloadProfile"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["SysProfile"] = str(raw_attrs[k]).strip()
            break

    # 2. SubNumaCluster / AMD NUMA
    for k in ("SubNumaCluster", "SubNumaClustering", "SNC", "SubNuma"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["SubNumaCluster"] = str(raw_attrs[k]).strip()
            break
    for k in ("NumaNodesPerSocket", "NumaNodesPerSocketSelection"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["NumaNodesPerSocket"] = str(raw_attrs[k]).strip()
            break
    if "CcxAsNumaDomain" in raw_attrs and raw_attrs["CcxAsNumaDomain"] is not None:
        normalized["CcxAsNumaDomain"] = str(raw_attrs["CcxAsNumaDomain"]).strip()

    # 3. ProcVirtualization
    for k in ("ProcVirtualization", "VirtualizationTechnology", "ProcVmx", "ProcSvm", "IntelVirtualizationTechnology"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["ProcVirtualization"] = str(raw_attrs[k]).strip()
            break

    # 4. VmdSupport
    for k in ("VmdSupport", "VmdMode", "VmdEnable", "IntelVMD"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["VmdSupport"] = str(raw_attrs[k]).strip()
            break
    if "VmdSupport" not in normalized:
        # Detect from VMD key patterns across PCIe / controller attributes
        vmd_keys = {
            k: v for k, v in raw_attrs.items()
            if any(s in k.lower() for s in ("vmd", "vroc", "nvmeraid", "nvme_raid"))
        }
        if vmd_keys:
            any_on = any(str(v).lower() in ("enabled", "true", "auto", "1") for v in vmd_keys.values())
            normalized["VmdSupport"] = "Enabled" if any_on else "Disabled"
        else:
            normalized["VmdSupport"] = "Disabled"

    # 5. PcieAspm
    for k in ("PcieAspmL1", "PcieAspm", "PchPcieAspm", "AspmSupport"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["PcieAspm"] = str(raw_attrs[k]).strip()
            break

    # 6. LogicalProc (HyperThreading)
    for k in ("LogicalProc", "HyperThreading", "ProcHyperThreading", "LogicalProcessor"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["LogicalProc"] = str(raw_attrs[k]).strip()
            break

    # 7. BootMode
    for k in ("BootMode", "BootModeSelect", "BootSeqMode"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["BootMode"] = str(raw_attrs[k]).strip()
            break
    if "BootMode" not in normalized and fallback_boot_mode:
        normalized["BootMode"] = str(fallback_boot_mode).strip()

    # 8. ProcCStates
    for k in ("ProcCStates", "CStates", "ProcC1E", "CpuCStates", "DfCState"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["ProcCStates"] = str(raw_attrs[k]).strip()
            break

    # 9. ProcTurboMode
    for k in ("ProcTurboMode", "TurboMode", "ControlledTurbo"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["ProcTurboMode"] = str(raw_attrs[k]).strip()
            break

    # 10. SriovGlobalEnable
    for k in ("SriovGlobalEnable", "SriovSupport", "Sriov"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["SriovGlobalEnable"] = str(raw_attrs[k]).strip()
            break

    # 11. MemTest
    for k in ("MemTest", "MemoryTest"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["MemTest"] = str(raw_attrs[k]).strip()
            break

    # 12. LatencyOptimizedMode (17G Intel Xeon 6 / GNR XCC)
    for k in ("BIOS.SysProfileSettings.LatencyOptimizedMode", "LatencyOptimizedMode", "LatencyOptMode"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["LatencyOptimizedMode"] = str(raw_attrs[k]).strip()
            break

    # 13. PciMultiSegment (17G AMD Turin)
    for k in ("BIOS.SysProfileSettings.PciMultiSegment", "PciMultiSegment", "PciMultiSegmentSupport", "PCIeMultiSegmentSupport"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["PciMultiSegment"] = str(raw_attrs[k]).strip()
            break

    # 14. CPU Power & Turbo settings
    for k in ("BIOS.SysProfileSettings.ProcPwrPerf", "ProcPwrPerf", "ProcPowerPerf"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["ProcPwrPerf"] = str(raw_attrs[k]).strip()
            break
    for k in ("BIOS.SysProfileSettings.ProcC1E", "ProcC1E", "C1E"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["ProcC1E"] = str(raw_attrs[k]).strip()
            break
    for k in ("BIOS.SysProfileSettings.EnergyEfficientTurbo", "EnergyEfficientTurbo"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["EnergyEfficientTurbo"] = str(raw_attrs[k]).strip()
            break
    for k in ("BIOS.SysProfileSettings.UncoreFrequency", "UncoreFrequency"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["UncoreFrequency"] = str(raw_attrs[k]).strip()
            break
    for k in ("BIOS.MemSettings.NodeInterleave", "NodeInterleave", "NodeInterleaving"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["NodeInterleave"] = str(raw_attrs[k]).strip()
            break
    for k in ("BIOS.SysProfileSettings.MemFrequency", "MemFrequency"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["MemFrequency"] = str(raw_attrs[k]).strip()
            break

    # 15. AMD Infinity Fabric & Determinism tokens (15G/16G/17G AMD EPYC)
    for k in ("BIOS.SysProfileSettings.ApbDis", "BIOS.ProcSettings.ApbDis", "ApbDis", "APBDIS", "DataFabricApbdis"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["ApbDis"] = str(raw_attrs[k]).strip()
            break
    for k in ("BIOS.SysProfileSettings.DeterminismSlider", "DeterminismSlider", "DeterminismControl", "Determinism"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["DeterminismSlider"] = str(raw_attrs[k]).strip()
            break
    for k in ("BIOS.SysProfileSettings.DfCState", "BIOS.ProcSettings.DfCState", "DfCState", "DataFabricCState", "DfCStates"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["DfCState"] = str(raw_attrs[k]).strip()
            break
    for k in ("BIOS.SysProfileSettings.DfPstateFreqOptimizer", "DfPstateFreqOptimizer", "DataFabricPstateOptimizer"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["DfPstateFreqOptimizer"] = str(raw_attrs[k]).strip()
            break
    for k in ("BIOS.SysProfileSettings.AmdCmnXgmiPstateControl", "AmdCmnXgmiPstateControl", "XgmiPstateControl", "XgmiPowerManagement"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["AmdCmnXgmiPstateControl"] = str(raw_attrs[k]).strip()
            break
    for k in ("BIOS.SysProfileSettings.AmdMaxXgmiSpeed", "AmdMaxXgmiSpeed", "XgmiMaxSpeed", "AmdXgmiSpeed"):
        if k in raw_attrs and raw_attrs[k] is not None:
            normalized["AmdMaxXgmiSpeed"] = str(raw_attrs[k]).strip()
            break

    return normalized


def _normalize_dell_job_entry(raw_job: dict, now_dt: datetime) -> Dict[str, Any]:
    """Normalize Dell LC Job or Redfish Task into a canonical telemetry record."""
    if not isinstance(raw_job, dict):
        return {}
    job_id = str(raw_job.get("Id") or "").strip()
    job_name = str(raw_job.get("Name") or raw_job.get("Description") or raw_job.get("JobType") or "").strip()

    raw_state = raw_job.get("JobState") or raw_job.get("TaskState") or "Unknown"
    state = str(raw_state).strip()

    raw_status = raw_job.get("JobStatus") or raw_job.get("TaskStatus") or ""
    status = str(raw_status).strip()

    message = str(raw_job.get("Message") or "").strip()
    msg_id = str(raw_job.get("MessageId") or "").strip()
    if not message and isinstance(raw_job.get("Messages"), list) and raw_job["Messages"]:
        first_msg = raw_job["Messages"][0]
        if isinstance(first_msg, dict):
            message = str(first_msg.get("Message") or "").strip()
            if not msg_id:
                msg_id = str(first_msg.get("MessageId") or "").strip()

    pct = raw_job.get("PercentComplete")
    pct_int = None
    if pct is not None:
        try:
            pct_int = int(pct)
        except (ValueError, TypeError):
            pass

    start_time_str = str(raw_job.get("StartTime") or raw_job.get("ActualRunningStartTime") or "").strip()
    end_time_str = str(raw_job.get("EndTime") or raw_job.get("CompletionTime") or raw_job.get("ActualRunningStopTime") or "").strip()
    job_type = str(raw_job.get("JobType") or "").strip()

    state_up = state.upper()
    status_up = status.upper()

    is_failed = (
        state_up in ("FAILED", "EXCEPTION", "KILLED")
        or status_up in ("FAILED", "CRITICAL")
        or ("FAILED" in message.upper() and state_up not in ("COMPLETED", "REBOOTCOMPLETED"))
    )

    is_pending_reboot = (
        state_up in ("REBOOTPENDING", "WAITINGFORREBOOT")
        or ("REBOOT" in state_up and state_up not in ("REBOOTCOMPLETED", "COMPLETED", "FAILED", "EXCEPTION"))
        or ("REBOOT" in job_type.upper() and state_up not in ("COMPLETED", "REBOOTCOMPLETED", "FAILED", "EXCEPTION"))
        or ("PENDING REBOOT" in message.upper() and state_up not in ("COMPLETED", "REBOOTCOMPLETED", "FAILED", "EXCEPTION"))
    )

    is_terminal = state_up in ("COMPLETED", "REBOOTCOMPLETED", "FAILED", "EXCEPTION", "KILLED", "CANCELLED", "CANCELED")
    is_stale = False
    duration_s = None

    start_dt = _parse_iso_datetime(start_time_str)
    if start_dt:
        if end_time_str:
            end_dt = _parse_iso_datetime(end_time_str)
            if end_dt:
                duration_s = max(0.0, (end_dt - start_dt).total_seconds())
        if duration_s is None:
            duration_s = max(0.0, (now_dt - start_dt).total_seconds())

        if not is_terminal and duration_s > 86400.0:
            is_stale = True

    return {
        "id": job_id,
        "name": job_name,
        "state": state,
        "status": status,
        "message": message,
        "message_id": msg_id,
        "percent_complete": pct_int,
        "start_time": start_time_str,
        "end_time": end_time_str,
        "job_type": job_type,
        "duration_seconds": round(duration_s, 1) if duration_s is not None else None,
        "is_failed": is_failed,
        "is_stale": is_stale,
        "is_pending_reboot": is_pending_reboot,
    }


class DellCollector(GenericCollector):
    """Dell iDRAC Redfish adapter."""

    VENDOR_MATCH = ("DELL", "IDRAC")  # matched against Manufacturer string upper()
    vendor = "dell"

    def oem_sku(self, sys_data: dict) -> str:
        """Dell iDRAC populates System.SKU with the Service Tag (e.g. 7SBKS13).
        Ignore SKU if it matches SerialNumber or 7-character Service Tag pattern.
        """
        sys_data = sys_data or {}
        sku = str(sys_data.get("SKU") or "").strip().upper()
        sn = str(sys_data.get("SerialNumber") or "").strip().upper()
        if sku and (sku == sn or re.match(r"^[A-Z0-9]{7}$", sku)):
            return ""
        return sku

    def oem_bios_date(self, sys_data: dict) -> str:
        """Read BIOS release date from Oem.Dell.DellSystem.BIOSReleaseDate."""
        return str(get_nested(sys_data, "Oem", "Dell", "DellSystem", "BIOSReleaseDate", default="N/A")).strip() or "N/A"

    def oem_extract_bios_attributes(self, bios_data: dict) -> dict:
        """Extract Dell BIOS attributes from standard or Dell OEM locations."""
        if isinstance(bios_data, dict):
            attrs = bios_data.get("Attributes")
            if isinstance(attrs, dict) and attrs:
                return attrs
            oem_dell = bios_data.get("Oem", {}).get("Dell", {})
            if isinstance(oem_dell, dict):
                for k in ("DellAttributes", "Attributes", "DellBiosAttributes"):
                    d_attrs = oem_dell.get(k)
                    if isinstance(d_attrs, dict) and d_attrs:
                        return d_attrs

        sys_uri = getattr(self, "sys_uri", None)
        if sys_uri:
            for ep in (
                f"{sys_uri}/Bios/DellAttributes",
                f"{sys_uri}/Oem/Dell/DellAttributes",
                f"{sys_uri}/DellAttributes",
            ):
                res = self._get(ep)
                if isinstance(res, dict):
                    attrs = res.get("Attributes") or res.get("DellAttributes")
                    if isinstance(attrs, dict) and attrs:
                        return attrs
                    if "Attributes" not in res and any(k in res for k in ("SysProfile", "ProcVirtualization")):
                        return res
        return {}

    def oem_normalize_bios_attributes(self, raw_attrs: dict) -> dict:
        """Normalize Dell BIOS attribute names across iDRAC generations."""
        sys_sum = getattr(self, "sys_summary", {}) or {}
        boot_fallback = sys_sum.get("raw_boot_mode") or sys_sum.get("boot_mode")
        return normalize_dell_bios_attributes(raw_attrs, fallback_boot_mode=boot_fallback)

    def _fetch_dell_smart_attributes(self, drive_json: dict) -> dict:
        """Fetch and extract Dell NVMe or drive SMART attributes."""
        smart = get_nested(drive_json, "Oem", "Dell", "DellNVMeSMARTAttributes")
        if not smart:
            smart = get_nested(drive_json, "Oem", "Dell", "DellDriveSMARTAttributes")
        if not smart:
            smart = drive_json.get("DellNVMeSMARTAttributes") or drive_json.get("DellDriveSMARTAttributes")
        if isinstance(smart, dict) and "@odata.id" in smart and len(smart) == 1:
            resp = self._get(smart["@odata.id"])
            if resp and isinstance(resp, dict):
                smart = resp
        return smart if isinstance(smart, dict) else {}

    def oem_drive_endurance(self, drive_json: dict) -> Optional[float]:
        """Read remaining write endurance from Oem.Dell.DellPhysicalDisk or DellNVMeSMARTAttributes."""
        val = get_nested(drive_json, "Oem", "Dell", "DellPhysicalDisk", "RemainingRatedWriteEndurancePercent")
        if val is not None:
            try:
                return float(val)
            except (TypeError, ValueError):
                pass
        smart = self._fetch_dell_smart_attributes(drive_json)
        life_used = smart.get("LifeUsedPercent")
        if life_used is not None:
            try:
                return max(0.0, 100.0 - float(life_used))
            except (TypeError, ValueError):
                pass
        return None

    def oem_cpu_cache(self, proc_json: dict) -> list:
        """Read CPU cache list from Oem.Dell.DellProcessor.Cache."""
        res = get_nested(proc_json, "Oem", "Dell", "DellProcessor", "Cache", default=[])
        return res if isinstance(res, list) else []

    def oem_drive_metrics(self, drive_json: dict) -> dict:
        """Read Dell physical disk telemetry metrics from Oem.Dell.DellPhysicalDisk and DellNVMeSMARTAttributes."""
        dell_oem = get_nested(drive_json, "Oem", "Dell", "DellPhysicalDisk", default={})
        res = {}
        if isinstance(dell_oem, dict):
            poh = dell_oem.get("OperationHours") or dell_oem.get("PowerOnHoursCount") or dell_oem.get("PowerOnHours")
            if poh is not None:
                try:
                    res["power_on_hours"] = float(poh)
                except (TypeError, ValueError):
                    pass
            sec = dell_oem.get("SecurityState") or dell_oem.get("EncryptionStatus")
            if sec:
                res["security_status"] = str(sec).strip()
            part = dell_oem.get("DellPartNumber") or dell_oem.get("PPID") or dell_oem.get("PartNumber")
            if part:
                res["part_number"] = str(part).strip()
            pred = dell_oem.get("PredictiveFailureState") or dell_oem.get("PredictiveFailure")
            if pred is not None:
                if isinstance(pred, bool):
                    res["predictive_failure"] = pred
                elif isinstance(pred, str):
                    res["predictive_failure"] = pred.lower() in ("true", "1", "yes", "predictive", "critical")

            pcie_cap_w = dell_oem.get("PCIeCapableLinkWidth")
            if pcie_cap_w:
                res["pcie_capable_width"] = str(pcie_cap_w).strip()
            pcie_neg_w = dell_oem.get("PCIeNegotiatedLinkWidth")
            if pcie_neg_w:
                res["pcie_negotiated_width"] = str(pcie_neg_w).strip()

            asp = dell_oem.get("AvailableSparePercent")
            if asp is not None:
                try:
                    res["available_spare_pct"] = float(asp)
                except (TypeError, ValueError):
                    pass

            sec_cap = dell_oem.get("SystemEraseCapability") or dell_oem.get("CryptographicEraseCapable")
            if sec_cap:
                sec_str = str(sec_cap).strip()
                res["crypto_erase_capable"] = "capable" in sec_str.lower() or "cryptographicerase" in sec_str.lower()
                res["erase_capability"] = sec_str

            err_desc = dell_oem.get("ErrorDescription")
            if err_desc and str(err_desc).strip().lower() not in ("none", "null", "n/a", ""):
                res["error_description"] = str(err_desc).strip()

        # Supplement with NVMe SMART attributes (TBW, composite temp, unsafe shutdowns, spares)
        smart = self._fetch_dell_smart_attributes(drive_json)
        if smart:
            spoh = smart.get("PowerOnHours")
            if spoh is not None and "power_on_hours" not in res:
                try:
                    res["power_on_hours"] = float(spoh)
                except (TypeError, ValueError):
                    pass

            du_w = smart.get("DataUnitsWrittenMB")
            if du_w is not None:
                try:
                    res["tbw_written"] = round(float(du_w) / 1_000_000, 2)
                except (TypeError, ValueError):
                    pass

            temp_k = smart.get("CompositeTemperatureKelvin")
            if temp_k is not None:
                try:
                    k_val = float(temp_k)
                    res["temperature_c"] = round(k_val - 273.15, 1) if k_val > 150 else round(k_val, 1)
                except (TypeError, ValueError):
                    pass

            du_r = smart.get("DataUnitsReadMB")
            if du_r is not None:
                try:
                    val_r = float(du_r)
                    if val_r >= 0:
                        res["tbr_read"] = round(val_r / 1_000_000, 2)
                except (TypeError, ValueError):
                    pass

            crit_warn = smart.get("CriticalWarningsCount") or smart.get("CriticalWarning")
            if crit_warn is not None:
                try:
                    res["critical_warnings"] = int(crit_warn)
                except (TypeError, ValueError):
                    pass

            busy_min = smart.get("ControllerBusyTimeMinutes")
            if busy_min is not None:
                try:
                    res["controller_busy_time"] = int(busy_min)
                except (TypeError, ValueError):
                    pass

            pwr_cyc = smart.get("PowerCycleCount")
            if pwr_cyc is not None:
                try:
                    res["power_cycles"] = int(pwr_cyc)
                except (TypeError, ValueError):
                    pass

            h_read = smart.get("HostReadCommandsCount")
            if h_read is not None:
                try:
                    res["host_read_commands"] = int(h_read)
                except (TypeError, ValueError):
                    pass

            h_write = smart.get("HostWriteCommandsCount")
            if h_write is not None:
                try:
                    res["host_write_commands"] = int(h_write)
                except (TypeError, ValueError):
                    pass

            asp_thresh = smart.get("AvailableSpareThresholdPercent") or smart.get("AvailableSpareThreshold")
            if asp_thresh is not None:
                try:
                    res["available_spare_threshold"] = float(asp_thresh)
                except (TypeError, ValueError):
                    pass

            err_info = smart.get("ErrorInfoCount") or smart.get("NumOfErrorInfoLogEntries")
            if err_info is not None:
                try:
                    res["error_log_entries"] = int(err_info)
                except (TypeError, ValueError):
                    pass

            bad_flash = smart.get("BadFlashBlock")
            if bad_flash is not None and "bad_nand_blocks" not in res:
                try:
                    res["bad_nand_blocks"] = int(bad_flash)
                except (TypeError, ValueError):
                    pass

            uncorr = smart.get("UncorrectableError")
            if uncorr is not None and "uncorrectable_read_errors" not in res:
                try:
                    res["uncorrectable_read_errors"] = int(uncorr)
                except (TypeError, ValueError):
                    pass

            us = smart.get("UnsafeShutdownsCount") or smart.get("UnsafeShutdowns")
            if us is not None:
                try:
                    res["unsafe_shutdowns"] = int(us)
                except (TypeError, ValueError):
                    pass

            asp_smart = smart.get("AvailableSparePercent")
            if asp_smart is not None and "available_spare_pct" not in res:
                try:
                    res["available_spare_pct"] = float(asp_smart)
                except (TypeError, ValueError):
                    pass

            life_used = smart.get("LifeUsedPercent")
            if life_used is not None:
                try:
                    res["life_used_pct"] = float(life_used)
                    res["endurance_remaining_pct"] = max(0.0, 100.0 - float(life_used))
                except (TypeError, ValueError):
                    pass

            m_err = smart.get("MediaDataIntegrityErrorsCount")
            if m_err is not None:
                try:
                    res["media_errors"] = int(m_err)
                except (TypeError, ValueError):
                    pass

        return res

    def oem_port_transceiver(self, port_json: dict) -> Dict[str, Any]:
        """Extract Dell Network Transceiver details (form factor, optics/DAC, vendor, part number, DDM)."""
        dell_oem = get_nested(port_json, "Oem", "Dell", default={})
        if not isinstance(dell_oem, dict):
            return {}
        xcvr = dell_oem.get("DellNetworkTransceiver")
        if not xcvr or not isinstance(xcvr, dict):
            xcvrs_link = dell_oem.get("DellNetworkTransceivers")
            if isinstance(xcvrs_link, dict) and xcvrs_link.get("@odata.id"):
                resp = self._get(xcvrs_link["@odata.id"])
                if resp and isinstance(resp, dict):
                    xcvr = resp
        if isinstance(xcvr, dict) and "@odata.id" in xcvr and len(xcvr) == 1:
            resp = self._get(xcvr["@odata.id"])
            if resp and isinstance(resp, dict):
                xcvr = resp
        if not isinstance(xcvr, dict):
            return {}

        ident = xcvr.get("IdentifierType") or xcvr.get("Identifier") or ""
        iface = xcvr.get("InterfaceType") or ""
        vendor = xcvr.get("VendorName") or xcvr.get("Manufacturer") or ""
        pn = xcvr.get("PartNumber") or ""
        sn = xcvr.get("SerialNumber") or ""

        # DDM Telemetry extraction (RX/TX optical power, temp, laser bias, voltage)
        metrics = dell_oem.get("DellNetworkTransceiverPortMetrics")
        if not isinstance(metrics, dict):
            metrics_link = dell_oem.get("DellNetworkTransceiverPortMetricsCollection")
            if isinstance(metrics_link, dict) and metrics_link.get("@odata.id"):
                resp = self._get(metrics_link["@odata.id"])
                if resp and isinstance(resp, dict):
                    metrics = resp
        if isinstance(metrics, dict) and "@odata.id" in metrics and len(metrics) <= 2:
            resp = self._get(metrics["@odata.id"])
            if resp and isinstance(resp, dict):
                metrics = resp
        if not isinstance(metrics, dict):
            metrics = xcvr.get("DellNetworkTransceiverPortMetrics") or xcvr.get("Metrics")
            if not isinstance(metrics, dict):
                metrics = {}

        def _to_flt(val: Any) -> Optional[float]:
            if val is None or val == "" or val == "N/A":
                return None
            try:
                return float(val)
            except (ValueError, TypeError):
                return None

        # RX Power: dBm directly or convert raw mW / uW to dBm (10 * log10(P))
        rx_power_dbm = None
        rx_dbm = _to_flt(metrics.get("RXInputPowerdBm") or metrics.get("RxPowerdBm") or metrics.get("rx_power_dbm") or xcvr.get("rx_power_dbm"))
        if rx_dbm is not None:
            rx_power_dbm = round(rx_dbm, 2)
        else:
            rx_mw = _to_flt(metrics.get("RXInputPowermW") or metrics.get("RxPowermW") or metrics.get("rx_power_mw"))
            if rx_mw is not None and rx_mw > 0:
                rx_power_dbm = round(10.0 * math.log10(rx_mw), 2)
            else:
                rx_uw = _to_flt(metrics.get("RXInputPoweruW") or metrics.get("RxPoweruW"))
                if rx_uw is not None and rx_uw > 0:
                    rx_power_dbm = round(10.0 * math.log10(rx_uw / 1000.0), 2)

        # TX Power: dBm directly or convert raw mW / uW to dBm (10 * log10(P))
        tx_power_dbm = None
        tx_dbm = _to_flt(metrics.get("TXOutputPowerdBm") or metrics.get("TxPowerdBm") or metrics.get("tx_power_dbm") or xcvr.get("tx_power_dbm"))
        if tx_dbm is not None:
            tx_power_dbm = round(tx_dbm, 2)
        else:
            tx_mw = _to_flt(metrics.get("TXOutputPowermW") or metrics.get("TxPowermW") or metrics.get("tx_power_mw"))
            if tx_mw is not None and tx_mw > 0:
                tx_power_dbm = round(10.0 * math.log10(tx_mw), 2)
            else:
                tx_uw = _to_flt(metrics.get("TXOutputPoweruW") or metrics.get("TxPoweruW"))
                if tx_uw is not None and tx_uw > 0:
                    tx_power_dbm = round(10.0 * math.log10(tx_uw / 1000.0), 2)

        temp_c = _to_flt(metrics.get("TemperatureCelsius") or metrics.get("temperature_c") or metrics.get("Temperature") or xcvr.get("temperature_c"))
        if temp_c is not None:
            temp_c = round(temp_c, 2)

        bias_ma = _to_flt(metrics.get("TXBiasCurrentmA") or metrics.get("TxBiasCurrentmA") or metrics.get("laser_bias_current_ma") or metrics.get("BiasCurrentmA") or xcvr.get("laser_bias_current_ma"))
        if bias_ma is not None:
            bias_ma = round(bias_ma, 2)

        voltage_v = _to_flt(metrics.get("VoltageValueVolts") or metrics.get("voltage_v") or metrics.get("Voltage") or metrics.get("SupplyVoltage") or xcvr.get("voltage_v"))
        if voltage_v is not None:
            voltage_v = round(voltage_v, 2)

        return {
            "identifier_type": str(ident).strip() if ident else "N/A",
            "interface_type": str(iface).strip() if iface else "N/A",
            "vendor_name": str(vendor).strip() if vendor else "N/A",
            "part_number": str(pn).strip() if pn else "N/A",
            "serial_number": str(sn).strip() if sn else "N/A",
            "rx_power_dbm": rx_power_dbm,
            "tx_power_dbm": tx_power_dbm,
            "temperature_c": temp_c,
            "laser_bias_current_ma": bias_ma,
            "voltage_v": voltage_v,
        }

    def oem_pcie_link_status(self, dev_dict: dict) -> Optional[Dict[str, Any]]:
        """Extract Dell iDRAC-specific PCIe link width and speed telemetry.

        Inspects DellNIC / DellFC nests and Dell PCIeDevice extensions.
        """
        if not isinstance(dev_dict, dict):
            return None

        oem = dev_dict.get("Oem") or {}
        dell = oem.get("Dell") or {}
        dell_nic = dell.get("DellNIC") or dell.get("DellFC") or {}
        if not isinstance(dell_nic, dict):
            dell_nic = {}

        if not dell_nic:
            controllers = dev_dict.get("Controllers") or []
            if isinstance(controllers, list):
                for c in controllers:
                    if isinstance(c, dict):
                        c_dell = (c.get("Oem") or {}).get("Dell", {}).get("DellNIC")
                        if isinstance(c_dell, dict) and c_dell:
                            dell_nic = c_dell
                            break

        raw_bus_width = dell_nic.get("DataBusWidth") or dev_dict.get("DataBusWidth")
        raw_slot_type = dell_nic.get("SlotType") or dev_dict.get("SlotType")

        width = normalize_pcie_width(raw_bus_width)
        gen = normalize_pcie_gen(raw_slot_type)

        if width is None and gen is None:
            return None

        return {
            "current_pcie_type": f"Gen{gen}" if gen else None,
            "max_pcie_type": f"Gen{gen}" if gen else None,
            "current_pcie_width": width,
            "max_pcie_width": width,
            "negotiated_gen": gen,
            "max_gen": gen,
            "negotiated_lanes": width,
            "max_lanes": width,
        }

    def oem_gpu_sensors(self) -> List[Dict[str, Any]]:
        """Collect GPU thermal, power brake, and slot sensors from Oem.Dell.DellGPUSensors."""
        if not getattr(self, "sys_uri", None):
            return []
        sensors_uri = f"{self.sys_uri}/Oem/Dell/DellGPUSensors"
        members = self._get_members(sensors_uri)
        results = []
        for m in members:
            m_uri = m.get("@odata.id") if isinstance(m, dict) else (m if isinstance(m, str) else None)
            if not m_uri:
                continue
            s_obj = self._get(m_uri)
            if not s_obj or not isinstance(s_obj, dict):
                continue
            dev_id = str(s_obj.get("DeviceID") or s_obj.get("Id") or "").strip()
            slot_num = None
            slot_m = re.search(r"Slot\.(\d+)", dev_id, re.IGNORECASE)
            if slot_m:
                slot_num = slot_m.group(1)
            results.append({
                "device_id": dev_id,
                "slot": f"PCIe Slot {slot_num}" if slot_num else "",
                "slot_number": int(slot_num) if slot_num else None,
                "primary_temp_c": s_obj.get("PrimaryGPUTemperatureCelsius"),
                "max_operating_temp_c": s_obj.get("MaximumGPUOperatingTemperatureCelsius"),
                "slowdown_temp_c": s_obj.get("MinimumGPUHardwareSlowdownTemperatureCelsius"),
                "shutdown_temp_c": s_obj.get("GPUShutdownTemperatureCelsius"),
                "power_brake_status": str(s_obj.get("PowerBrakeStatus") or "Released").strip(),
                "thermal_alert_status": str(s_obj.get("ThermalAlertStatus") or "NotPending").strip(),
            })
        return results

    def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict:
        """Detect Dell iDRAC license tier (Enterprise, Express, Basic)."""
        mgr_name = str((mgr_data or {}).get("Name", "") or (mgr_data or {}).get("Model", "")).upper()
        if "ENTERPRISE" in mgr_name or "DATACENTER" in mgr_name:
            tier, cls, icon = "Enterprise", "success", "🟢"
        elif "EXPRESS" in mgr_name or "BASIC" in mgr_name:
            tier, cls, icon = "Express", "warning", "🟡"
        else:
            tier, cls, icon = "iDRAC", "info", "ℹ️"
        return {
            "license_name": f"Dell {tier}",
            "badge": f"<span class='badge {cls}'>{icon} Dell {tier}</span>",
            "vendor_note": (
                "All hardware inventory (Storage, Memory, NICs, Thermal, PSU) is "
                "fully accessible at every iDRAC license tier. iDRAC Enterprise / "
                "Datacenter adds remote KVM console, virtual media, and advanced "
                "configuration management."
            ),
        }

    def oem_os_info(self, sys_data: dict) -> dict:
        """Extract Dell iSM OS metadata and continuous power-on uptime via $select-filtered Attributes.

        Probes /Managers/System.Embedded.1/Attributes?$select=ServerOS.* or
        /Managers/iDRAC.Embedded.1/Attributes?$select=ServerOS.* with fallback to unparameterized Attributes.
        """
        attrs = {}
        mgr = (getattr(self, "mgr_uri", None) or "").rstrip("/")
        if mgr:
            select_paths = [f"{mgr}/Attributes?$select=ServerOS.*"]
            full_paths = [f"{mgr}/Attributes"]
        else:
            select_paths = [
                "/redfish/v1/Managers/iDRAC.Embedded.1/Attributes?$select=ServerOS.*",
                "/redfish/v1/Managers/System.Embedded.1/Attributes?$select=ServerOS.*",
            ]
            full_paths = [
                "/redfish/v1/Managers/iDRAC.Embedded.1/Attributes",
                "/redfish/v1/Managers/System.Embedded.1/Attributes",
            ]

        # Try $select-filtered Manager Attributes for low-latency, compact payload
        for p in select_paths:
            res = self._get(p, _retry=False, timeout=5, critical=False)
            if res and isinstance(res, dict) and not res.get("error"):
                attrs = res.get("Attributes") or {}
                if attrs:
                    break

        # Fallback without query params if $select was rejected (HTTP 400/501 on older BMCs)
        if not attrs:
            for base_p in full_paths:
                res = self._get(base_p, _retry=False, timeout=5, critical=False)
                if res and isinstance(res, dict) and not res.get("error"):
                    attrs = res.get("Attributes") or {}
                    if attrs:
                        break

        if not isinstance(attrs, dict):
            attrs = {}

        os_name = str(attrs.get("ServerOS.1.OSName") or "").strip()
        os_ver = str(attrs.get("ServerOS.1.OSVersion") or "").strip()
        poh_raw = attrs.get("ServerOS.1.ServerPoweredOnTime")

        powered_on_sec = None
        uptime_days = None
        uptime_human = None

        if poh_raw is not None:
            try:
                powered_on_sec = float(poh_raw)
                days_total = powered_on_sec / 86400.0
                uptime_days = round(days_total, 1)
                if days_total >= 1.0:
                    d = int(days_total)
                    h = int((powered_on_sec % 86400) // 3600)
                    uptime_human = f"{d}d {h}h"
                else:
                    h = int(powered_on_sec // 3600)
                    m = int((powered_on_sec % 3600) // 60)
                    uptime_human = f"{h}h {m}m"
            except (ValueError, TypeError):
                pass

        res = {}
        if os_name:
            res["name"] = os_name
        if os_ver:
            res["version"] = os_ver
        if os_name or os_ver or powered_on_sec is not None:
            res["source"] = "Dell iSM"
        if powered_on_sec is not None:
            res["powered_on_seconds"] = powered_on_sec
            res["uptime_days"] = uptime_days
            res["uptime_human"] = uptime_human
        return res

    def oem_fastpath_roots(self) -> Optional[Tuple[List[str], List[str], List[str]]]:
        """Dell iDRAC fast-path root probe for standard monolithic rack/tower servers.
        Shortcuts System.Embedded.1, Chassis.Embedded.1, and iDRAC.Embedded.1 in a single check.
        Falls back to standard enumeration on modular (blade) or non-standard systems.
        """
        test_sys = self._get("/redfish/v1/Systems/System.Embedded.1")
        if test_sys and isinstance(test_sys, dict) and not test_sys.get("error"):
            return (
                ["/redfish/v1/Systems/System.Embedded.1"],
                ["/redfish/v1/Chassis/System.Embedded.1"],
                ["/redfish/v1/Managers/iDRAC.Embedded.1"],
            )
        return None

    def oem_security_evidence(self) -> Dict[str, Any]:
        """Collect non-secret Dell OEM security evidence from iDRAC & Lifecycle Controller.

        Probes DellAttributes from manager endpoint, filters through safe non-secret
        allowlists, and captures certificate capability metadata.
        """
        raw_attrs = {}
        paths = []
        if getattr(self, "mgr_uri", None):
            paths.append(f"{self.mgr_uri}/Attributes")
        paths.extend([
            "/redfish/v1/Managers/iDRAC.Embedded.1/Attributes",
            "/redfish/v1/Managers/System.Embedded.1/Attributes",
        ])

        for p in paths:
            resp = self._get(p)
            if resp and isinstance(resp, dict) and not resp.get("error"):
                attrs = resp.get("Attributes")
                if isinstance(attrs, dict) and attrs:
                    raw_attrs = attrs
                    break

        if not raw_attrs:
            # Dell 17G (iDRAC 10) partitioned DellAttributes endpoints
            mgr = getattr(self, "mgr_uri", None) or "/redfish/v1/Managers/iDRAC.Embedded.1"
            sub_paths = [
                f"{mgr}/Oem/Dell/DellAttributes/iDRAC.Embedded.1",
                f"{mgr}/Oem/Dell/DellAttributes/LifecycleController.Embedded.1",
                f"{mgr}/Oem/Dell/DellAttributes/System.Embedded.1",
                f"{mgr}/Oem/Dell/DellAttributes/DataStore",
            ]
            # Dynamically inspect Links.Oem.Dell.DellAttributes on Manager
            mgr_obj = self._get(mgr) if mgr else None
            if isinstance(mgr_obj, dict):
                dell_links = (
                    get_nested(mgr_obj, "Links", "Oem", "Dell", "DellAttributes", default=[])
                    or get_nested(mgr_obj, "Oem", "Dell", "DellAttributes", default=[])
                )
                if isinstance(dell_links, list):
                    for dl in dell_links:
                        dl_uri = dl.get("@odata.id") if isinstance(dl, dict) else (dl if isinstance(dl, str) else None)
                        if dl_uri and dl_uri not in sub_paths:
                            sub_paths.append(dl_uri)

            combined = {}
            for sp in sub_paths:
                resp = self._get(sp, critical=False)
                if resp and isinstance(resp, dict) and not resp.get("error"):
                    attrs = resp.get("Attributes")
                    if isinstance(attrs, dict):
                        combined.update(attrs)
                    elif not attrs:
                        # Fallback for flat dictionary responses
                        flat = {k: v for k, v in resp.items() if not str(k).startswith("@") and k not in ("Id", "Name", "Description")}
                        if flat:
                            combined.update(flat)
            if combined:
                raw_attrs = combined

        idrac_attrs, lc_attrs = filter_dell_security_attributes(raw_attrs)

        cert_count = 0
        if getattr(self, "mgr_uri", None):
            cert_res = self._get(f"{self.mgr_uri}/Certificates")
            if cert_res and isinstance(cert_res, dict) and not cert_res.get("error"):
                members = cert_res.get("Members")
                if isinstance(members, (list, tuple)):
                    cert_count = len(members)

        return {
            "idrac_attributes": idrac_attrs,
            "lc_attributes": lc_attrs,
            "retained_attribute_count": len(idrac_attrs) + len(lc_attrs),
            "certificate_count": cert_count,
        }

    def oem_handle_retry(self, data: dict, endpoint: str) -> bool:
        """Detect Dell iDRAC transient busy or not-ready errors (e.g. SYS518, data sources unavailable)."""
        data = data or {}
        ext_info = data.get("@Message.ExtendedInfo") or get_nested(data, "error", "@Message.ExtendedInfo", default=[]) or []
        transient_signatures = ("SYS518", "data sources are unavailable", "Data sources are unavailable")
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

    def oem_job_queue(self, now_dt: Optional[datetime] = None) -> Dict[str, Any]:
        """Probe and audit Dell iDRAC Lifecycle Controller (LC) job queue.

        Probes /redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs (with fallback
        to /redfish/v1/JobService/Jobs and /redfish/v1/TaskService/Tasks).
        Extracts job attributes (Id, Name, JobState/JobStatus, Message, PercentComplete, StartTime),
        flags jobs running or scheduled for > 24 hours as STALE, and classifies
        total, failed, stale, and pending_reboot jobs.

        Guaranteed strictly read-only: never modifies, cancels, or purges the job queue.
        """
        if now_dt is None:
            now_dt = datetime.now(timezone.utc)
        elif now_dt.tzinfo is None:
            now_dt = now_dt.replace(tzinfo=timezone.utc)

        mgr_uri = getattr(self, "mgr_uri", None) or "/redfish/v1/Managers/iDRAC.Embedded.1"
        candidate_endpoints = [
            f"{mgr_uri}/Oem/Dell/Jobs",
            "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs",
            "/redfish/v1/JobService/Jobs",
            "/redfish/v1/TaskService/Tasks",
        ]
        seen = set()
        deduped = []
        for ep in candidate_endpoints:
            if ep not in seen:
                seen.add(ep)
                deduped.append(ep)

        target_ep = None
        coll_data = None
        for ep in deduped:
            if hasattr(self, "_fetch_expanded_collection"):
                res = self._fetch_expanded_collection(ep)
            else:
                res = self._get(ep)
            if res and isinstance(res, dict) and ("Members" in res or "Members@odata.count" in res):
                target_ep = ep
                coll_data = res
                break

        if coll_data is None or target_ep is None:
            return {}

        raw_members = coll_data.get("Members") or []
        total_count = coll_data.get("Members@odata.count")
        if total_count is None:
            total_count = len(raw_members)

        # Process members:
        # If members are already embedded objects (from $expand), process up to 50 without network overhead.
        # If members are raw @odata.id references requiring network GETs, bound strictly to 10 most recent
        # to prevent worker starvation and collection timeouts on busy/fragile BMCs.
        is_expanded = bool(raw_members and isinstance(raw_members[0], dict) and any(k in raw_members[0] for k in ("JobState", "TaskState", "PercentComplete", "Name")))
        cap = 50 if is_expanded else 10
        members_to_process = raw_members[:cap]
        parsed_jobs = []

        for m in members_to_process:
            if getattr(self, "_consecutive_timeouts", 0) >= 2 or getattr(self, "timed_out", False):
                break
            job_obj = None
            if isinstance(m, dict):
                if "JobState" in m or "TaskState" in m or "PercentComplete" in m:
                    job_obj = m
                elif "@odata.id" in m:
                    job_obj = self._get(m["@odata.id"], critical=False)
            elif isinstance(m, str):
                job_obj = self._get(m, critical=False)

            if isinstance(job_obj, dict):
                norm = _normalize_dell_job_entry(job_obj, now_dt)
                if norm.get("id") or norm.get("name"):
                    parsed_jobs.append(norm)

        failed_count = sum(1 for j in parsed_jobs if j.get("is_failed"))
        stale_count = sum(1 for j in parsed_jobs if j.get("is_stale"))
        reboot_count = sum(1 for j in parsed_jobs if j.get("is_pending_reboot"))

        if failed_count > 0 or stale_count > 0:
            queue_status = "WARNING"
        elif reboot_count > 0:
            queue_status = "PENDING_REBOOT"
        else:
            queue_status = "OK"

        return {
            "total_jobs": total_count,
            "failed_jobs": failed_count,
            "stale_jobs": stale_count,
            "pending_reboot_jobs": reboot_count,
            "status": queue_status,
            "endpoint": target_ep,
            "jobs": parsed_jobs,
        }

    def oem_expandable_collections(self) -> Dict[str, str]:
        """Dell iDRAC expandable collection endpoints.

        Dell iDRAC (14G–17G, iDRAC9 ≥ 3.00, iDRAC10) supports OData $expand=*($levels=1)
        on FirmwareInventory, EthernetInterfaces, ThermalSubsystem/Fans, and Memory.
        """
        sys_uri = getattr(self, "sys_uri", None) or "/redfish/v1/Systems/System.Embedded.1"
        chassis_uri = getattr(self, "chassis_uri", None) or "/redfish/v1/Chassis/System.Embedded.1"
        mgr_uri = getattr(self, "mgr_uri", None) or "/redfish/v1/Managers/iDRAC.Embedded.1"
        return ExpandableCollectionsMap({
            "firmware": "/redfish/v1/UpdateService/FirmwareInventory",
            "network": f"{sys_uri}/EthernetInterfaces",
            "thermal_fans": f"{chassis_uri}/ThermalSubsystem/Fans",
            "fans": f"{chassis_uri}/ThermalSubsystem/Fans",
            "memory": f"{sys_uri}/Memory",
            "jobs": f"{mgr_uri}/Oem/Dell/Jobs",
        })


