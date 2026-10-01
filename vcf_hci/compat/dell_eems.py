"""
VCF Readiness Tool — Dell PowerEdge EEMS Canonical Message Decoder (Layer B).

Translates Dell Enterprise Event Message System (EEMS) codes and raw IPMI sensor
identifiers into domain categorization, VCF 9.1 / vSAN ESA impact ratings,
plain-language technical explanations, and concrete hardware remediation steps.
"""
import re
from typing import Any, Dict, NamedTuple, Optional, Tuple


class DellEemsInfo(NamedTuple):
    """Decoded Dell EEMS event metadata and VCF 9.1 remediation guidance."""

    code: str
    domain: str
    severity: str
    vcf_impact: str
    explanation: str
    remediation: str
    doc_url: str
    is_vcf_blocker: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert entry into serializable dictionary."""
        return {
            "code": self.code,
            "domain": self.domain,
            "severity": self.severity,
            "vcf_impact": self.vcf_impact,
            "explanation": self.explanation,
            "remediation": self.remediation,
            "doc_url": self.doc_url,
            "is_vcf_blocker": self.is_vcf_blocker,
        }


DELL_GUIDE_BASE_URL: str = (
    "https://www.dell.com/support/manuals/en-us/poweredge-r740xd/error_event_message_guide_c/"
)
DELL_GUIDE_ROOT_URL: str = (
    "https://www.dell.com/support/manuals/en-us/poweredge-r740xd/error_event_message_guide_c/"
    "poweredge-servers-error-and-event-messages-eems?guid=guid-96cc49ee-fa46-4249-adb6-e0c9a3cbdb1f&lang=en-us"
)

# Regex to detect Dell EEMS event codes: 2-5 uppercase letters followed by 3-4 digits
# (e.g. PSU0001, AMP0302, MEM0001, CPU0005, STOR0001, UEFI0001, LC0001, TST100)
_DELL_CODE_PATTERN = re.compile(r"\b([A-Z]{2,5}\d{3,4})\b")

# Category GUIDs and section slugs for Dell PowerEdge Reference Guide chapters
DELL_EEMS_CATEGORY_GUIDS: Dict[str, Dict[str, str]] = {
    "ACC": {"guid": "guid-01f8e996-2a3b-4044-8f02-594434364bc5", "section": "accaccelerator-event-messages"},
    "AMP": {"guid": "guid-53482bb3-798c-4759-b5be-71b459212231", "section": "ampamperage-event-messages"},
    "ASR": {"guid": "guid-bb59b706-ee2b-4a98-a3e2-8be083774b0d", "section": "asrauto-system-reset-event-messages"},
    "BAR": {"guid": "guid-14b04b2a-64b6-430f-8c07-8346e0d23b6c", "section": "barbackuprestore-event-messages"},
    "BAT": {"guid": "guid-2f178717-1f38-4166-aaf7-af1c1cbeee66", "section": "batbattery-event-event-messages"},
    "BEZL": {"guid": "guid-15d55faf-474e-4204-a1f4-2d631786007b", "section": "bezlbezel-air-filter-sensor-event-messages"},
    "BIOS": {"guid": "guid-555864f0-2533-43c3-8e84-cab040e67194", "section": "biosbios-management-event-messages"},
    "BOOT": {"guid": "guid-2e539a1a-9ae5-406c-b768-ee4cb7587281", "section": "bootboot-control-event-messages"},
    "CBL": {"guid": "guid-b36bfe4c-90f0-4577-a51f-03e3b88a20a2", "section": "cblcable-event-messages"},
    "CPU": {"guid": "guid-d3557ad0-4758-42d3-9121-8d18bab1ab91", "section": "cpuprocessor-event-messages"},
    "CPUA": {"guid": "guid-d3557ad0-4758-42d3-9121-8d18bab1ab91", "section": "cpuprocessor-event-messages"},
    "CPWR": {"guid": "guid-0f6fbc66-58fa-4d7d-a957-b5e3dd475893", "section": "cpwrpower-configuration-event-messages"},
    "CTL": {"guid": "guid-cca18a06-d8d1-4047-9abb-e05508bc4f1d", "section": "ctlstorage-controller-event-messages"},
    "CUMP": {"guid": "guid-428ac998-0c7c-4cc4-b8ef-7d36e4f13d64", "section": "cumpupdate-manager-plugin-event-messages"},
    "DIAG": {"guid": "guid-426b816b-4e7e-4db6-bf28-8089872e5739", "section": "diagdiagnostics-event-messages"},
    "ENC": {"guid": "guid-a57ad658-549d-4747-bd28-a8120c631b27", "section": "encstorage-enclosure-event-messages"},
    "FAN": {"guid": "guid-6ac562d6-81c0-4881-8742-28853228da16", "section": "fanfan-event-event-messages"},
    "FC": {"guid": "guid-a558ccb6-b485-4dc7-9d14-2a3010497555", "section": "fcfibre-channel-event-messages"},
    "FLDC": {"guid": "guid-568b5d48-bfbb-459c-9ba6-519a93d9d1d2", "section": "fldcfluid-cache-event-messages"},
    "GPU": {"guid": "guid-a664e01d-1785-403d-94a8-d5e8fe0fba68", "section": "gpugraphics-processing-unit-event-messages"},
    "HWC": {"guid": "guid-9e52a11f-b453-4a28-83ee-d49354f14c09", "section": "hwchardware-config-event-messages"},
    "MEM": {"guid": "guid-21907359-4d9d-4319-87ea-1428444a007b", "section": "memmemory-event-messages"},
    "NIC": {"guid": "guid-90b48c4d-7488-4c2c-b31c-6de4f68681f8", "section": "nicnic-configuration-event-messages"},
    "NINT": {"guid": "guid-103c18db-2417-4d1a-bfee-03c00ff19b5c", "section": "nintinterface-event-messages"},
    "NNOD": {"guid": "guid-0346688f-1f79-4bc2-9589-096aa3277483", "section": "nnodnode-event-messages"},
    "NVCH": {"guid": "guid-0ebcc744-9011-4b86-af5f-7abe73f20eda", "section": "nvchchassis-event-messages"},
    "OSE": {"guid": "guid-96455b91-c4a8-4146-ab1f-2dc6088bb88e", "section": "oseos-event-event-messages"},
    "PCI": {"guid": "guid-5cbae8ab-1e63-4868-86f8-edf202bc62b0", "section": "pcipci-device-event-messages"},
    "PDR": {"guid": "guid-a1aea204-644e-40a7-a2d6-407846fb73fe", "section": "pdrphysical-disk-event-messages"},
    "PST": {"guid": "guid-149130fa-9995-452c-9172-551eebe559c3", "section": "pstbios-post-event-messages"},
    "PSU": {"guid": "guid-a830aecc-63d1-4032-8bc0-7523037d3b56", "section": "psupower-supply-event-messages"},
    "PSUA": {"guid": "guid-a830aecc-63d1-4032-8bc0-7523037d3b56", "section": "psupower-supply-event-messages"},
    "PWR": {"guid": "guid-be9590cf-d70c-4a3c-b85b-12c71733afb7", "section": "pwrpower-usage-event-messages"},
    "RAC": {"guid": "guid-a01094fe-33eb-44cf-a660-a45ef9c56702", "section": "racrac-event-event-messages"},
    "RDU": {"guid": "guid-f2266b18-390a-49a4-8529-26b104160b81", "section": "rduredundancy-event-messages"},
    "SEC": {"guid": "guid-7dbdd871-f80b-4acb-ac7b-552d63fe240f", "section": "secsecurity-event-event-messages"},
    "SEL": {"guid": "guid-3abcfb28-c4cc-497f-9c33-bc7750415187", "section": "selsystem-event-log-event-messages"},
    "SRV": {"guid": "guid-5d6cf5d2-e65a-40b4-8470-ba4d9354117f", "section": "srvsupport-assist-event-messages"},
    "STOR": {"guid": "guid-9ea2fda4-df5d-46e4-ba3c-a89090647517", "section": "storstorage-event-messages"},
    "SWC": {"guid": "guid-c02e4a1b-ac07-4926-b988-8edbd46e144e", "section": "swcsoftware-config-event-messages"},
    "SYS": {"guid": "guid-b6228634-4b5c-45ed-9cbc-810343ab3eca", "section": "syssystem-info-event-messages"},
    "TMP": {"guid": "guid-a41c38b5-08bf-4bde-b761-ca81165dc921", "section": "tmptemperature-event-messages"},
    "TMPS": {"guid": "guid-1a291ff3-8ab5-4e18-b0de-f7c908c3f343", "section": "tmpstemperature-statistics-event-messages"},
    "TST": {"guid": "guid-c5b145df-c44d-45ee-a532-eba04e646874", "section": "tsttest-alert-event-messages"},
    "UEFI": {"guid": "guid-60a1e424-7b4d-4b5f-9dc4-1a4c51b6d109", "section": "uefiuefi-event-event-messages"},
    "VDR": {"guid": "guid-61b9638d-9a91-4bbd-be60-3ca92de48d38", "section": "vdrvirtual-disk-event-messages"},
    "VLT": {"guid": "guid-c40d5f5f-b9cc-43bb-9cbb-b191f09f0fbc", "section": "vltvoltage-event-messages"},
}


def build_dell_eems_guide_url(code_or_prefix: str) -> str:
    """Build a direct link to the Dell PowerEdge EEMS Reference Guide chapter for a code or prefix.

    If a specific chapter GUID is mapped for the prefix, constructs a direct chapter URL.
    Otherwise, routes to the Master Guide Root TOC where all 140+ EEMS categories
    are indexed with working chapter links.
    """
    token = str(code_or_prefix or "").strip().upper()
    prefix_match = re.match(r"^([A-Z]+)", token)
    prefix = prefix_match.group(1) if prefix_match else token
    entry = DELL_EEMS_CATEGORY_GUIDS.get(prefix)
    if entry:
        guid = entry.get("guid", "")
        section = entry.get("section", "")
        if section and guid and guid != "guid-96cc49ee-fa46-4249-adb6-e0c9a3cbdb1f":
            return f"{DELL_GUIDE_BASE_URL}{section}?guid={guid}&lang=en-us"
        return DELL_GUIDE_ROOT_URL
    return DELL_GUIDE_ROOT_URL


# Direct mapping from Dell IPMI sensor hex codes to canonical Dell EEMS alphanumeric codes
DELL_HEX_TO_EEMS_CODE: Dict[str, str] = {
    # Power Supply & Redundancy
    "0b01ffff": "RDU0012",
    "1ffff": "RDU0012",
    "0b010000": "RDU0011",
    "0b02ffff": "RDU0013",
    "3ffff": "PSU0003",
    "6f00ffff": "BAT0015",
    "6f01ffff": "PSU0001",
    "6f03ffff": "PSU0003",
    "6f030000": "PSU0003",
    "6f06ffff": "PSU0006",
    "6fa6ffff": "PWR0001",
    "ef00ffff": "PSU0001",
    # Cooling & Fans
    "01520004": "FAN0001",
    "81529a04": "FAN0001",
    # Thermal & Temperature
    "0157a1a1": "TMP0118",
    "0159e2e2": "CPU0001",
    # CPU Machine Check
    "07a60140": "CPU0000",
    # Memory
    "07a3c001": "MEM0001",
    "07a3c020": "MEM0001",
    "07a3c180": "MEM0001",
    "07a7c140": "MEM0007",
    "6f0f81ff": "MEM0001",
    "6fa0c140": "MEM0001",
    "6fa1c001": "MEM0001",
    "6fa1c040": "MEM0001",
    "6fa1c140": "MEM0001",
    "6fa1c201": "MEM0001",
    "6fa1c210": "MEM0001",
    "744e4241": "MEM0701",
    "744ef141": "MEM0701",
    "7452d544": "MEM0702",
    "74a10306": "MEM0702",
    "74a10346": "MEM0702",
    # BIOS & POST
    "6f0fd0ff": "BIOS0001",
    "6f0fd2ff": "BIOS0001",
    "fd0ff": "BIOS0001",
    # Chassis Intrusion & Security
    "6f8002ff": "SEC0033",
    "6f8000ff": "SEC0031",
    "6f8001ff": "SEC0000",
    "802ff": "SEC0033",
    "6fa0ff04": "SEC0001",
    # Hardware Configuration
    "6fa41100": "HWC8010",
    "6fa411ff": "HWC8011",
    # PCIe & Bus Fatal Errors
    "6fa91800": "PCI0001",
    "6faa2881": "PCI0001",
    "6fac004b": "PCI0001",
    "6fac0063": "PCI0001",
    "6fac00d7": "PCI0001",
    "6fac0163": "PCI0001",
    "6fac104a": "PCI0001",
    "6fac283c": "PCI0001",
    "6fac00c4": "PCI0001",
    "6fac01c4": "PCI0001",
    "6fac09c0": "PCI0001",
    "6fa100d1": "PST0258",
    # Drives & Drive Bays
    "a017": "PDR1016",
    "a0112": "PDR1016",
    "a0113": "PDR1016",
    "efa00002": "PDR1002",
}

# Clean-room canonical knowledge catalog of high-impact Dell EEMS codes.
# Keyed by uppercase EEMS code.
KNOWN_DELL_EEMS_CODES: Dict[str, Dict[str, Any]] = {
    # ── CPU Subsystem ──
    "CPU0000": {
        "domain": "CPU",
        "severity": "Critical",
        "vcf_impact": "VCF Blocker",
        "is_vcf_blocker": True,
        "explanation": "CPU internal fatal error or machine check exception (IERR/MCE) detected on processor.",
        "remediation": "Check processor seating and thermal status. Run Dell ePSA hardware diagnostics; replace defective CPU if exception recurs.",
    },
    "CPU0001": {
        "domain": "CPU",
        "severity": "Critical",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Processor core temperature reached or exceeded critical thermal threshold, triggering throttling or emergency shutdown.",
        "remediation": "Inspect heatsink contact, thermal interface material, and chassis cooling fan operation before provisioning ESXi.",
    },
    "CPU0005": {
        "domain": "CPU",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Processor thermal sensor warning threshold exceeded.",
        "remediation": "Verify chassis fan cages and airflow baffles are installed; clean dust buildup from CPU heatsinks.",
    },
    "CPU0023": {
        "domain": "CPU",
        "severity": "Critical",
        "vcf_impact": "VCF Blocker",
        "is_vcf_blocker": True,
        "explanation": "UPI/QPI coherent fabric interconnect error or fatal protocol error detected between processor sockets.",
        "remediation": "Reseat CPU sockets and inspect pins for damage. Replace affected CPU or system board if fabric errors persist.",
    },
    # ── Memory Subsystem ──
    "MEM0001": {
        "domain": "Memory",
        "severity": "Critical",
        "vcf_impact": "VCF Blocker",
        "is_vcf_blocker": True,
        "explanation": "Multi-bit uncorrectable ECC error detected on memory module, halting transaction execution.",
        "remediation": "Identify failing DIMM slot from iDRAC SEL; replace defective DIMM before commissioning node into cluster.",
    },
    "MEM0007": {
        "domain": "Memory",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Memory health monitor detected excessive correctable errors or degradation on memory device.",
        "remediation": "Reboot system to trigger BIOS post-package repair (PPR) self-healing, or schedule proactive DIMM replacement.",
    },
    "MEM0701": {
        "domain": "Memory",
        "severity": "Critical",
        "vcf_impact": "VCF Blocker",
        "is_vcf_blocker": True,
        "explanation": "Critical memory diagnostic failure or unrecoverable DIMM fault reported during initialization.",
        "remediation": "Reseat memory module in designated slot. Replace failed DIMM if memory BIST continues to report critical failure.",
    },
    "MEM0702": {
        "domain": "Memory",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Diagnostic warning or non-critical error threshold reached on memory device.",
        "remediation": "Verify memory population conforms to channel symmetry guidelines; inspect DIMM socket contacts.",
    },
    # ── Storage Subsystem ──
    "STOR0001": {
        "domain": "Storage",
        "severity": "Critical",
        "vcf_impact": "vSAN ESA Blocker",
        "is_vcf_blocker": True,
        "explanation": "Storage controller encountered fatal hardware failure or firmware fault, disabling disk subsystem.",
        "remediation": "Replace failed storage controller or adapter card. For vSAN ESA repurposing, ensure native HBA mode is configured.",
    },
    "STOR0026": {
        "domain": "Storage",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Storage controller write-cache is degraded or disabled, forcing write-through caching.",
        "remediation": "Verify controller cache battery/supercapacitor status; replace degraded battery unit or configure controller to pass-through mode.",
    },
    "PDR1002": {
        "domain": "Storage",
        "severity": "Warning",
        "vcf_impact": "vSAN ESA Blocker",
        "is_vcf_blocker": True,
        "explanation": "Predictive drive failure (SMART alert) detected on physical disk indicating impending media failure.",
        "remediation": "Replace the failing physical disk before initializing or repurposing the host for vSAN ESA.",
    },
    "PDR1016": {
        "domain": "Storage",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Physical drive removed or disconnected from drive bay backplane.",
        "remediation": "Verify target drive is securely latched into drive bay and check SAS/NVMe backplane cabling.",
    },
    # ── Battery Subsystem ──
    "BAT0015": {
        "domain": "Battery",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Storage controller cache battery voltage is low, depleted, or failed, forcing write-through cache mode.",
        "remediation": "Replace depleted PERC battery unit. If repurposing node for vSAN ESA, switch controller to HBA/pass-through mode.",
    },
    "BAT0017": {
        "domain": "Battery",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Storage controller RAID battery unit is absent or not detected.",
        "remediation": "Install supported RAID cache battery module, or switch controller to HBA mode for vSAN.",
    },
    # ── Network Subsystem ──
    "NIC100": {
        "domain": "Network",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Network physical link down detected on adapter interface port.",
        "remediation": "Verify network cable and optical transceiver seating; confirm upstream switch port is administratively enabled and configured.",
    },
    "NIC101": {
        "domain": "Network",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Network link flap or packet degradation detected on physical adapter port.",
        "remediation": "Inspect optical transceiver power levels via DDM; reseat or replace patch cable.",
    },
    # ── Intel VMD Subsystem ──
    "VMD0001": {
        "domain": "Storage",
        "severity": "Critical",
        "vcf_impact": "vSAN ESA Blocker",
        "is_vcf_blocker": True,
        "explanation": "Intel Volume Management Device (VMD) domain conflict or unexpected NVMe topology detected.",
        "remediation": "Disable Intel VMD in System BIOS settings for native direct-attached NVMe passthrough required by vSAN ESA.",
    },
    "VMD0002": {
        "domain": "Storage",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Intel VMD controller encountered device enumeration failure on NVMe endpoints.",
        "remediation": "Verify NVMe drive firmware baselines; disable Intel VMD in BIOS if targeting vSAN ESA deployment.",
    },
    # ── Hardware Security Subsystem ──
    "SEC0001": {
        "domain": "Security",
        "severity": "Critical",
        "vcf_impact": "VCF Blocker",
        "is_vcf_blocker": True,
        "explanation": "Intel TXT or TPM initialization fault detected during boot phase.",
        "remediation": "Ensure TPM 2.0 is Enabled and Activated in System BIOS; reset TPM endorsement hierarchy if state is corrupted.",
    },
    "SEC0031": {
        "domain": "Security",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Server chassis top cover opened or intrusion switch triggered while system power was active.",
        "remediation": "Close server chassis cover and secure latch; clear chassis intrusion alert in iDRAC.",
    },
    "SEC0033": {
        "domain": "Security",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Server chassis top cover opened or disturbed while system power was off.",
        "remediation": "Verify physical security of server enclosure and secure top cover latch.",
    },
    # ── Power Supply Subsystem ──
    "PSU0001": {
        "domain": "Power",
        "severity": "Critical",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Power supply unit reported fatal hardware failure, loss of output, or absent state.",
        "remediation": "Reseat or replace the failed power supply unit to restore redundant power delivery.",
    },
    "PSU0003": {
        "domain": "Power",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Power supply unit lost input AC/DC power while seated in chassis.",
        "remediation": "Inspect PDU feed, power cord, and circuit breaker feeding the affected power supply.",
    },
    "PSU0006": {
        "domain": "Power",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Power supply units installed in chassis have mismatched wattage or rating specifications.",
        "remediation": "Ensure all installed power supply units share identical wattage, voltage ratings, and efficiency levels.",
    },
    # ── Cooling & Fan Subsystem ──
    "FAN0001": {
        "domain": "Thermal",
        "severity": "Critical",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Cooling fan tachometer RPM dropped below lower critical threshold or fan stalled.",
        "remediation": "Replace failing fan module immediately to prevent thermal throttling of CPUs and NVMe drives.",
    },
    "FAN0002": {
        "domain": "Thermal",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Cooling fan speed dropped below warning threshold or is running degraded.",
        "remediation": "Inspect fan rotor for debris or cable obstruction; replace fan module if speed remains degraded.",
    },
    # ── PCIe Bus Subsystem ──
    "PCI0001": {
        "domain": "PCIe",
        "severity": "Critical",
        "vcf_impact": "VCF Blocker",
        "is_vcf_blocker": True,
        "explanation": "Fatal I/O bus error or PCIe Advanced Error Reporting (AER) uncorrectable error detected on bus component.",
        "remediation": "Reseat PCIe adapter card in slot; inspect slot pins and update adapter firmware. Replace defective card if fatal bus errors persist.",
    },
    "PCI1360": {
        "domain": "PCIe",
        "severity": "Critical",
        "vcf_impact": "VCF Blocker",
        "is_vcf_blocker": True,
        "explanation": "A bus fatal error was detected on a component at the specified PCIe slot.",
        "remediation": "Reseat PCIe adapter in slot; clean gold slot fingers; inspect PCIe riser; update device firmware or replace defective PCIe adapter.",
    },
    "PCI1318": {
        "domain": "PCIe",
        "severity": "Critical",
        "vcf_impact": "VCF Blocker",
        "is_vcf_blocker": True,
        "explanation": "A fatal error was detected on a PCIe component at a bus/device/function address.",
        "remediation": "Inspect system SEL logs for the exact B/D/F; identify associated card, reseat or replace adapter.",
    },
    # ── System Power & Redundancy ──
    "PWR0001": {
        "domain": "Power",
        "severity": "Critical",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "System halted or throttled because aggregate power demand exceeded PSU capacity.",
        "remediation": "Upgrade power supply units to higher wattage models or adjust power budget / capping policy in iDRAC.",
    },
    "RDU0011": {
        "domain": "Power",
        "severity": "OK",
        "vcf_impact": "Informational",
        "is_vcf_blocker": False,
        "explanation": "Power supply redundancy is fully restored and operating normally.",
        "remediation": "No remediation required.",
    },
    "RDU0012": {
        "domain": "Power",
        "severity": "Critical",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Power supply redundancy lost; system is operating on a single power supply feed.",
        "remediation": "Restore power feed or replace offline power supply to recover N+1 power redundancy.",
    },
    "RDU0013": {
        "domain": "Power",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "Power supply redundancy degraded; secondary supply cannot guarantee full workload peak demand.",
        "remediation": "Check both PSU feeds and verify all power cables are plugged into live PDU circuits.",
    },
    # ── Hardware Configuration & POST ──
    "HWC8010": {
        "domain": "Hardware Config",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "System Configuration Check operation detected an issue with installed hardware components.",
        "remediation": "Review iDRAC Lifecycle Controller log to determine which riser or card is misconfigured or unsupported.",
    },
    "HWC8011": {
        "domain": "Hardware Config",
        "severity": "Critical",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "System Configuration Check operation detected multiple hardware topology or riser issues.",
        "remediation": "Verify all installed components conform to Dell server minimum and supported configuration rules.",
    },
    "PST0258": {
        "domain": "Security",
        "severity": "Warning",
        "vcf_impact": "Hardware Degraded",
        "is_vcf_blocker": False,
        "explanation": "AMD Platform Security Processor (PSP) detected a security-related issue while booting the server.",
        "remediation": "Inspect system event log for PSP error details and ensure BIOS/microcode firmware is up to date.",
    },
}

# Prefix-based domain categorization and guidance fallback for unmapped Dell EEMS codes
_PREFIX_DOMAIN_FALLBACKS: Dict[str, Tuple[str, str, str, str, str]] = {
    # (domain, severity, vcf_impact, explanation_template, remediation)
    "CPU": (
        "CPU",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge processor subsystem event logged by BMC ({code}).",
        "Review CPU health metrics and Lifecycle Controller log for processor details.",
    ),
    "CPUA": (
        "CPU",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge processor subsystem event logged by BMC ({code}).",
        "Review CPU health metrics and Lifecycle Controller log for processor details.",
    ),
    "MEM": (
        "Memory",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge memory subsystem event logged by BMC ({code}).",
        "Review memory diagnostic logs; check DIMM slot health in iDRAC.",
    ),
    "STOR": (
        "Storage",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge storage subsystem event logged by BMC ({code}).",
        "Inspect storage controller, virtual disks, and physical disk health in iDRAC.",
    ),
    "CTL": (
        "Storage",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge storage controller event logged by BMC ({code}).",
        "Check storage controller firmware baseline and battery backup unit health.",
    ),
    "PDR": (
        "Storage",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge physical disk event logged by BMC ({code}).",
        "Inspect physical disk SMART metrics and verify drive seating in bay.",
    ),
    "VDR": (
        "Storage",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge virtual disk event logged by BMC ({code}).",
        "Verify virtual disk status and RAID configuration in iDRAC Storage inventory.",
    ),
    "ENC": (
        "Storage",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge storage enclosure event logged by BMC ({code}).",
        "Inspect enclosure power modules, cooling fans, and SAS backplane cables.",
    ),
    "BAT": (
        "Battery",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge battery subsystem event logged by BMC ({code}).",
        "Check battery state and charge level in iDRAC storage controller properties.",
    ),
    "NIC": (
        "Network",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge network interface event logged by BMC ({code}).",
        "Verify physical network cable link state and switch port configuration.",
    ),
    "NINT": (
        "Network",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge network interface event logged by BMC ({code}).",
        "Inspect network port status and transceivers in iDRAC Network inventory.",
    ),
    "FC": (
        "Network",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge Fibre Channel controller event logged by BMC ({code}).",
        "Check FC HBA port link state, WWPN registration, and SAN switch zoning.",
    ),
    "VMD": (
        "Storage",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge Intel VMD event logged by BMC ({code}).",
        "Check Intel VMD settings in BIOS and NVMe device attachments.",
    ),
    "SEC": (
        "Security",
        "Warning",
        "Informational",
        "Dell PowerEdge hardware security event logged by BMC ({code}).",
        "Inspect chassis physical latches and verify TPM/Secure Boot configuration.",
    ),
    "PSU": (
        "Power",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge power supply event logged by BMC ({code}).",
        "Inspect power supplies, AC cords, and power redundancy status in iDRAC.",
    ),
    "PSUA": (
        "Power",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge power supply event logged by BMC ({code}).",
        "Inspect power supplies, AC cords, and power redundancy status in iDRAC.",
    ),
    "PWR": (
        "Power",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge power management event logged by BMC ({code}).",
        "Check system power consumption, power budget, and capping settings.",
    ),
    "RDU": (
        "Power",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge power redundancy event logged by BMC ({code}).",
        "Verify all power supplies are connected to active power feeds.",
    ),
    "AMP": (
        "Power",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge current/amperage event logged by BMC ({code}).",
        "Review server amperage draw and PDU circuit loading.",
    ),
    "VLT": (
        "Power",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge voltage regulation event logged by BMC ({code}).",
        "Check system board voltage rails and power supply health in iDRAC.",
    ),
    "FAN": (
        "Thermal",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge cooling fan event logged by BMC ({code}).",
        "Inspect cooling fan RPM speeds and clean airflow passages.",
    ),
    "TMP": (
        "Thermal",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge temperature sensor event logged by BMC ({code}).",
        "Verify datacenter ambient temperature, cooling airflow, and heatsink seating.",
    ),
    "TMPS": (
        "Thermal",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge temperature statistics event logged by BMC ({code}).",
        "Review server thermal history and fan speed profiles in iDRAC.",
    ),
    "PCI": (
        "PCIe",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge PCIe bus or adapter event logged by BMC ({code}).",
        "Inspect PCIe cards and slots for errors in iDRAC hardware inventory.",
    ),
    "BIOS": (
        "BIOS/POST",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge BIOS event logged by BMC ({code}).",
        "Review BIOS boot settings and update system firmware if issues persist.",
    ),
    "BOOT": (
        "BIOS/POST",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge boot sequence event logged by BMC ({code}).",
        "Verify UEFI boot order and available bootable devices.",
    ),
    "UEFI": (
        "BIOS/POST",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge UEFI event logged by BMC ({code}).",
        "Check UEFI firmware configuration and Secure Boot keys.",
    ),
    "PST": (
        "BIOS/POST",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge POST diagnostic event logged by BMC ({code}).",
        "Review POST diagnostic screen and Lifecycle Controller error logs.",
    ),
    "HWC": (
        "Hardware Config",
        "Warning",
        "Hardware Degraded",
        "Dell PowerEdge hardware configuration event logged by BMC ({code}).",
        "Review hardware configuration rules and riser topology.",
    ),
}


def extract_dell_code(
    message_id: Optional[str],
    message: Optional[str] = "",
) -> Optional[str]:
    """Extract a Dell EEMS code (e.g. 'PSU0001', 'MEM0001') from message_id or message text.

    Also translates raw Dell IPMI sensor hex codes (e.g. '0b01ffff' -> 'RDU0012')
    and dynamic hex prefixes ('efa0...' -> 'PDR1016', '6fac...' -> 'PCI0001').
    """
    clean_id = str(message_id or "").strip()
    if clean_id.lower() in ("n/a", "none", "-", "unknown", ""):
        clean_id = ""

    # 1. Direct hex mapping check
    if clean_id:
        lower_id = clean_id.lower()
        if lower_id in DELL_HEX_TO_EEMS_CODE:
            return DELL_HEX_TO_EEMS_CODE[lower_id]
        if lower_id.startswith("efa0"):
            return "PDR1016"
        if lower_id.startswith("6fac"):
            return "PCI0001"

    # 2. Match standard alphanumeric code pattern
    for candidate in [clean_id, message]:
        if not candidate:
            continue
        m = _DELL_CODE_PATTERN.search(str(candidate))
        if m:
            return m.group(1).upper()

    return None


def decode_dell_message_id(
    message_id: Optional[str],
    message: Optional[str] = "",
) -> Optional[DellEemsInfo]:
    """Decode a Dell EEMS message ID into structured hardware guidance and VCF impact.

    Handles:
      - Pure alphanumeric codes ('MEM0001', 'PSU0001', 'TST100')
      - Redfish registry message IDs ('IDRAC.1.6.MEM0001', 'Base.1.0.PSU0001')
      - IPMI sensor hex strings ('0b01ffff', '6fa1c001', 'efa00113')
      - Message-embedded codes ('Predictive failure on physical disk PDR1002')

    Falls back to prefix parsing (e.g. CPU*, MEM*, STOR*) for unknown codes.
    Returns None if no valid Dell event identifier could be determined.
    """
    code = extract_dell_code(message_id, message)
    if not code:
        return None

    doc_url = build_dell_eems_guide_url(code)

    # 1. Exact match in canonical knowledge catalog
    if code in KNOWN_DELL_EEMS_CODES:
        entry = KNOWN_DELL_EEMS_CODES[code]
        return DellEemsInfo(
            code=code,
            domain=entry["domain"],
            severity=entry["severity"],
            vcf_impact=entry["vcf_impact"],
            explanation=entry["explanation"],
            remediation=entry["remediation"],
            doc_url=doc_url,
            is_vcf_blocker=entry.get("is_vcf_blocker", False),
        )

    # 2. Prefix fallback categorization
    prefix_match = re.match(r"^([A-Z]+)", code)
    prefix = prefix_match.group(1) if prefix_match else code

    if prefix in _PREFIX_DOMAIN_FALLBACKS:
        domain, sev, vcf_imp, expl_tmpl, remed = _PREFIX_DOMAIN_FALLBACKS[prefix]
        return DellEemsInfo(
            code=code,
            domain=domain,
            severity=sev,
            vcf_impact=vcf_imp,
            explanation=expl_tmpl.format(code=code),
            remediation=remed,
            doc_url=doc_url,
            is_vcf_blocker=False,
        )

    # 3. Universal graceful fallback
    return DellEemsInfo(
        code=code,
        domain="General",
        severity="Informational",
        vcf_impact="Informational",
        explanation=f"Dell PowerEdge event logged by BMC ({code}).",
        remediation=f"Consult Dell PowerEdge Error and Event Messages Reference Guide for {code}.",
        doc_url=doc_url,
        is_vcf_blocker=False,
    )
