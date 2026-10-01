"""
VCF Readiness Tool — Vendor System Event Log (SEL / IML) Guide Links & Event Resolvers.

Provides authoritative vendor documentation links for System Event Logs:
- Dell PowerEdge EEMS (12G–17G Reference Guide): Alphanumeric codes and pre-built IPMI hex mapping
- HPE ProLiant IML (Gen10/11/12 Guide): Class.code decimal and hex parsing into docDisplay URLs
- Cisco UCS IMC Faults: 11-chapter mapping covering all F-codes, flt* names, and fault prefixes
- Lenovo ThinkSystem XCC: Direct knowledge-base query and guide links
- Supermicro BMC IPMI: Authoritative IPMI SEL reference manual
"""
import html
import re
import urllib.parse
from typing import Dict, Optional

from vcf_hci.compat.dell_eems import (
    build_dell_eems_guide_url,
    decode_dell_message_id,
)


def normalize_vendor(vendor: Optional[str]) -> str:
    """Normalize server vendor string into canonical vendor identifier."""
    if not vendor:
        return "generic"
    v = str(vendor).strip().lower()
    if "dell" in v:
        return "dell"
    if "hpe" in v or "hewlett" in v:
        return "hpe"
    if "cisco" in v:
        return "cisco"
    if "lenovo" in v:
        return "lenovo"
    if "supermicro" in v or "super micro" in v:
        return "supermicro"
    if "quanta" in v or "qct" in v:
        return "quanta"
    if "gigabyte" in v or "giga-byte" in v:
        return "gigabyte"
    return "generic"


DELL_GUIDE_BASE_URL: str = (
    "https://www.dell.com/support/manuals/en-us/poweredge-r740xd/error_event_message_guide_c/"
)
DELL_GUIDE_ROOT_URL: str = (
    "https://www.dell.com/support/manuals/en-us/poweredge-r740xd/error_event_message_guide_c/"
    "poweredge-servers-error-and-event-messages-eems?guid=guid-96cc49ee-fa46-4249-adb6-e0c9a3cbdb1f&lang=en-us"
)


# Official vendor documentation guides for System Event Logs / Faults
VENDOR_SEL_GUIDES: Dict[str, Dict[str, str]] = {
    "dell": {
        "vendor_name": "Dell PowerEdge",
        "guide_title": "Dell PowerEdge Servers Error and Event Messages Reference Guide (EEMs)",
        "url": DELL_GUIDE_ROOT_URL,
        "badge_label": "Dell EEMS Guide",
        "short_name": "Dell EEMS",
    },
    "hpe": {
        "vendor_name": "HPE ProLiant",
        "guide_title": "Integrated Management Log Messages and Troubleshooting Guide for HPE ProLiant Gen10, Gen11, and Gen12",
        "url": "https://support.hpe.com/hpesc/public/docDisplay?docId=ilogen12-msg-en_us&docLocale=en_US",
        "badge_label": "HPE IML Guide",
        "short_name": "HPE IML",
    },
    "cisco": {
        "vendor_name": "Cisco UCS",
        "guide_title": "Cisco UCS Integrated Management Controller Faults Reference Guide",
        "url": (
            "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/fault/reference/guide/"
            "b_Cisco_UCS_IMC_Faults_Reference_Guide/b_Cisco_UCS_IMC_Faults_Reference_Guide_chapter_01010.html"
        ),
        "badge_label": "Cisco Faults Guide",
        "short_name": "Cisco IMC Faults",
    },
    "lenovo": {
        "vendor_name": "Lenovo ThinkSystem",
        "guide_title": "Lenovo ThinkSystem XClarity Controller (XCC) Events Reference Guide",
        "url": "https://pubs.lenovo.com/sr650-v4/xcc_error_messages",
        "badge_label": "Lenovo XCC Guide",
        "short_name": "Lenovo XCC",
    },
    "supermicro": {
        "vendor_name": "Supermicro",
        "guide_title": "Supermicro BMC IPMI User's Guide (SEL Reference)",
        "url": "https://www.supermicro.com/manuals/other/IPMI_Users_Guide.pdf",
        "badge_label": "Supermicro SEL Guide",
        "short_name": "Supermicro SEL",
    },
    "quanta": {
        "vendor_name": "Quanta Cloud Technology",
        "guide_title": "Quanta / QCT BMC and Server Support Reference",
        "url": "https://www.qct.io",
        "badge_label": "Quanta SEL Guide",
        "short_name": "Quanta SEL",
    },
    "gigabyte": {
        "vendor_name": "GIGABYTE",
        "guide_title": "GIGABYTE Enterprise Server Documentation & SEL Reference",
        "url": "https://www.gigabyte.com/Enterprise/Server",
        "badge_label": "GIGABYTE SEL Guide",
        "short_name": "GIGABYTE SEL",
    },
}

# Regex to detect Dell EEMS event codes: 2-5 uppercase letters followed by 3-4 digits
# (e.g. PSU0001, AMP0302, MEM0001, CPU0005, STOR0001, UEFI0001, LC0001, TST100)
_DELL_CODE_PATTERN = re.compile(r"\b([A-Z]{2,5}\d{3,4})\b")

# Direct mapping from Dell IPMI sensor hex codes / legacy event identifiers to Dell EEMS metadata.
# Each entry maps:
#   "eems": Canonical Dell EEMS alphanumeric code (e.g. RDU0012, PSU0003, PDR1016)
#   "guid": Direct topic GUID in the Dell PowerEdge Servers Error and Event Messages Reference Guide
#   "section": Slug identifier for the specific chapter in Dell's Reference Guide
#   "title": Human-readable EEMS event title
DELL_HEX_TO_EEMS_MAP: Dict[str, Dict[str, str]] = {
    # Power Supply & Redundancy
    "0b01ffff": {
        "eems": "RDU0012",
        "guid": "guid-f2266b18-390a-49a4-8529-26b104160b81",
        "section": "rduredundancy-event-messages",
        "title": "Power supply redundancy is lost.",
    },
    "1ffff": {
        "eems": "RDU0012",
        "guid": "guid-f2266b18-390a-49a4-8529-26b104160b81",
        "section": "rduredundancy-event-messages",
        "title": "Power supply redundancy is lost.",
    },
    "0b010000": {
        "eems": "RDU0011",
        "guid": "guid-f2266b18-390a-49a4-8529-26b104160b81",
        "section": "rduredundancy-event-messages",
        "title": "The power supplies are redundant.",
    },
    "0b02ffff": {
        "eems": "RDU0013",
        "guid": "guid-f2266b18-390a-49a4-8529-26b104160b81",
        "section": "rduredundancy-event-messages",
        "title": "Power supply redundancy is degraded.",
    },
    "3ffff": {
        "eems": "PSU0003",
        "guid": "guid-a830aecc-63d1-4032-8bc0-7523037d3b56",
        "section": "psupower-supply-event-messages",
        "title": "The power input for power supply is lost.",
    },
    "6f00ffff": {
        "eems": "BAT0015",
        "guid": "guid-2f178717-1f38-4166-aaf7-af1c1cbeee66",
        "section": "batbattery-event-event-messages",
        "title": "The battery is low.",
    },
    "6f01ffff": {
        "eems": "PSU0001",
        "guid": "guid-a830aecc-63d1-4032-8bc0-7523037d3b56",
        "section": "psupower-supply-event-messages",
        "title": "Power supply failed.",
    },
    "6f03ffff": {
        "eems": "PSU0003",
        "guid": "guid-a830aecc-63d1-4032-8bc0-7523037d3b56",
        "section": "psupower-supply-event-messages",
        "title": "The Power Supply Unit (PSU) is not receiving input power because of issues in PSU or cable connections.",
    },
    "6f030000": {
        "eems": "PSU0003",
        "guid": "guid-a830aecc-63d1-4032-8bc0-7523037d3b56",
        "section": "psupower-supply-event-messages",
        "title": "The Power Supply Unit (PSU) is not receiving input power because of issues in PSU or cable connections.",
    },
    "6f06ffff": {
        "eems": "PSU0006",
        "guid": "guid-a830aecc-63d1-4032-8bc0-7523037d3b56",
        "section": "psupower-supply-event-messages",
        "title": "Power supply is incorrectly configured.",
    },
    "6fa6ffff": {
        "eems": "PWR0001",
        "guid": "guid-be9590cf-d70c-4a3c-b85b-12c71733afb7",
        "section": "pwrpower-usage-event-messages",
        "title": "The system halted because system power exceeds capacity.",
    },
    "ef00ffff": {
        "eems": "PSU0001",
        "guid": "guid-a830aecc-63d1-4032-8bc0-7523037d3b56",
        "section": "psupower-supply-event-messages",
        "title": "Power supply is absent or failed.",
    },
    # Cooling & Fans
    "01520004": {
        "eems": "FAN0001",
        "guid": "guid-6ac562d6-81c0-4881-8742-28853228da16",
        "section": "fanfan-event-event-messages",
        "title": "Fan RPM is less than the lower critical threshold.",
    },
    "81529a04": {
        "eems": "FAN0001",
        "guid": "guid-6ac562d6-81c0-4881-8742-28853228da16",
        "section": "fanfan-event-event-messages",
        "title": "Fan RPM is less than the lower warning threshold.",
    },
    # Thermal & Temperature
    "0157a1a1": {
        "eems": "TMP0118",
        "guid": "guid-a41c38b5-08bf-4bde-b761-ca81165dc921",
        "section": "tmptemperature-event-messages",
        "title": "System inlet temperature is greater than the upper warning threshold.",
    },
    "0159e2e2": {
        "eems": "CPU0001",
        "guid": "guid-d3557ad0-4758-42d3-9121-8d18bab1ab91",
        "section": "cpuprocessor-event-messages",
        "title": "CPU temperature is greater than the upper critical threshold.",
    },
    # CPU Machine Check
    "07a60140": {
        "eems": "CPU0000",
        "guid": "guid-d3557ad0-4758-42d3-9121-8d18bab1ab91",
        "section": "cpuprocessor-event-messages",
        "title": "CPU machine check error detected.",
    },
    # Memory (Errors, Self-Heal, Thresholds)
    "07a3c001": {
        "eems": "MEM0001",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "Memory error detected on transaction at DIMM. Reboot system for auto-healing.",
    },
    "07a3c020": {
        "eems": "MEM0001",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "Memory error detected on transaction at DIMM. Reboot system for auto-healing.",
    },
    "07a3c180": {
        "eems": "MEM0001",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "Memory error detected on transaction at DIMM. Reboot system for auto-healing.",
    },
    "07a7c140": {
        "eems": "MEM0007",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "Memory health monitor detected degradation in DIMM. Reboot to initiate self-heal.",
    },
    "6f0f81ff": {
        "eems": "MEM0001",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "Memory is detected, but is not configurable.",
    },
    "6fa0c140": {
        "eems": "MEM0001",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "Correctable memory error logging disabled for memory device.",
    },
    "6fa1c001": {
        "eems": "MEM0001",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "Multi-bit memory errors detected on memory device. Replace DIMM.",
    },
    "6fa1c040": {
        "eems": "MEM0001",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "Multi-bit memory errors detected on memory device. Replace DIMM.",
    },
    "6fa1c140": {
        "eems": "MEM0001",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "Multi-bit memory errors detected on memory device. Replace DIMM.",
    },
    "6fa1c201": {
        "eems": "MEM0001",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "Multi-bit memory errors detected on memory device. Replace DIMM.",
    },
    "6fa1c210": {
        "eems": "MEM0001",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "Multi-bit memory errors detected on memory device. Replace DIMM.",
    },
    "744e4241": {
        "eems": "MEM0701",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "A critical diagnostic event occurred in memory device.",
    },
    "744ef141": {
        "eems": "MEM0701",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "A critical diagnostic event occurred in memory device.",
    },
    "7452d544": {
        "eems": "MEM0702",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "Diagnostic warning event in memory device. Reseat device.",
    },
    "74a10306": {
        "eems": "MEM0702",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "Diagnostic warning event in memory device. Check device and system config.",
    },
    "74a10346": {
        "eems": "MEM0702",
        "guid": "guid-21907359-4d9d-4319-87ea-1428444a007b",
        "section": "memmemory-event-messages",
        "title": "Diagnostic warning event in memory device. Check device and system config.",
    },
    # BIOS & POST
    "6f0fd0ff": {
        "eems": "BIOS0001",
        "guid": "guid-555864f0-2533-43c3-8e84-cab040e67194",
        "section": "biosbios-management-event-messages",
        "title": "System BIOS has halted.",
    },
    "6f0fd2ff": {
        "eems": "BIOS0001",
        "guid": "guid-555864f0-2533-43c3-8e84-cab040e67194",
        "section": "biosbios-management-event-messages",
        "title": "High-severity issue occurred at POST phase resulting in BIOS abrupt stop.",
    },
    "fd0ff": {
        "eems": "BIOS0001",
        "guid": "guid-555864f0-2533-43c3-8e84-cab040e67194",
        "section": "biosbios-management-event-messages",
        "title": "System BIOS has halted.",
    },
    # Chassis Intrusion & Security
    "6f8002ff": {
        "eems": "SEC0033",
        "guid": "guid-7dbdd871-f80b-4acb-ac7b-552d63fe240f",
        "section": "secsecurity-event-event-messages",
        "title": "The chassis is open while the power is off.",
    },
    "6f8000ff": {
        "eems": "SEC0031",
        "guid": "guid-7dbdd871-f80b-4acb-ac7b-552d63fe240f",
        "section": "secsecurity-event-event-messages",
        "title": "The chassis is open while the power is on.",
    },
    "6f8001ff": {
        "eems": "SEC0000",
        "guid": "guid-7dbdd871-f80b-4acb-ac7b-552d63fe240f",
        "section": "secsecurity-event-event-messages",
        "title": "The chassis is open.",
    },
    "802ff": {
        "eems": "SEC0033",
        "guid": "guid-7dbdd871-f80b-4acb-ac7b-552d63fe240f",
        "section": "secsecurity-event-event-messages",
        "title": "The chassis is open while the power is off.",
    },
    "6fa0ff04": {
        "eems": "SEC0001",
        "guid": "guid-7dbdd871-f80b-4acb-ac7b-552d63fe240f",
        "section": "secsecurity-event-event-messages",
        "title": "SINIT ACM detected Intel TXT problem at boot.",
    },
    # Hardware Configuration
    "6fa41100": {
        "eems": "HWC8010",
        "guid": "guid-9e52a11f-b453-4a28-83ee-d49354f14c09",
        "section": "hwchardware-config-event-messages",
        "title": "System Configuration Check operation resulted in an issue.",
    },
    "6fa411ff": {
        "eems": "HWC8011",
        "guid": "guid-9e52a11f-b453-4a28-83ee-d49354f14c09",
        "section": "hwchardware-config-event-messages",
        "title": "System Configuration Check operation resulted in multiple issues.",
    },
    # PCIe & Bus Fatal Errors
    "6fa91800": {
        "eems": "PCI0001",
        "guid": "guid-5cbae8ab-1e63-4868-86f8-edf202bc62b0",
        "section": "pcipci-device-event-messages",
        "title": "Fatal IO error detected on bus component.",
    },
    "6faa2881": {
        "eems": "PCI0001",
        "guid": "guid-5cbae8ab-1e63-4868-86f8-edf202bc62b0",
        "section": "pcipci-device-event-messages",
        "title": "Bus fatal error detected on component at slot.",
    },
    "6fac004b": {
        "eems": "PCI0001",
        "guid": "guid-5cbae8ab-1e63-4868-86f8-edf202bc62b0",
        "section": "pcipci-device-event-messages",
        "title": "Fatal error detected on bus component.",
    },
    "6fac0063": {
        "eems": "PCI0001",
        "guid": "guid-5cbae8ab-1e63-4868-86f8-edf202bc62b0",
        "section": "pcipci-device-event-messages",
        "title": "Fatal error detected on bus component.",
    },
    "6fac00d7": {
        "eems": "PCI0001",
        "guid": "guid-5cbae8ab-1e63-4868-86f8-edf202bc62b0",
        "section": "pcipci-device-event-messages",
        "title": "Fatal error detected on bus component.",
    },
    "6fac0163": {
        "eems": "PCI0001",
        "guid": "guid-5cbae8ab-1e63-4868-86f8-edf202bc62b0",
        "section": "pcipci-device-event-messages",
        "title": "Fatal error detected on bus component.",
    },
    "6fac104a": {
        "eems": "PCI0001",
        "guid": "guid-5cbae8ab-1e63-4868-86f8-edf202bc62b0",
        "section": "pcipci-device-event-messages",
        "title": "Fatal error detected on bus component.",
    },
    "6fac283c": {
        "eems": "PCI0001",
        "guid": "guid-5cbae8ab-1e63-4868-86f8-edf202bc62b0",
        "section": "pcipci-device-event-messages",
        "title": "Fatal error detected on bus component.",
    },
    "6fac00c4": {
        "eems": "PCI0001",
        "guid": "guid-5cbae8ab-1e63-4868-86f8-edf202bc62b0",
        "section": "pcipci-device-event-messages",
        "title": "Fatal error detected on bus component.",
    },
    "6fac01c4": {
        "eems": "PCI0001",
        "guid": "guid-5cbae8ab-1e63-4868-86f8-edf202bc62b0",
        "section": "pcipci-device-event-messages",
        "title": "Fatal error detected on bus component.",
    },
    "6fac09c0": {
        "eems": "PCI0001",
        "guid": "guid-5cbae8ab-1e63-4868-86f8-edf202bc62b0",
        "section": "pcipci-device-event-messages",
        "title": "Fatal error detected on bus component.",
    },
    "6fa100d1": {
        "eems": "PST0258",
        "guid": "guid-149130fa-9995-452c-9172-551eebe559c3",
        "section": "pstbios-post-event-messages",
        "title": "The AMD Platform Security Processor (PSP) detected a security-related issue while booting the server.",
    },
    # Drives & Drive Bays (PDR)
    "a017": {
        "eems": "PDR1016",
        "guid": "guid-a1aea204-644e-40a7-a2d6-407846fb73fe",
        "section": "pdrphysical-disk-event-messages",
        "title": "Drive is removed from disk drive bay.",
    },
    "a0112": {
        "eems": "PDR1016",
        "guid": "guid-a1aea204-644e-40a7-a2d6-407846fb73fe",
        "section": "pdrphysical-disk-event-messages",
        "title": "Drive is removed from disk drive bay.",
    },
    "a0113": {
        "eems": "PDR1016",
        "guid": "guid-a1aea204-644e-40a7-a2d6-407846fb73fe",
        "section": "pdrphysical-disk-event-messages",
        "title": "Drive is removed from disk drive bay.",
    },
    "efa00002": {
        "eems": "PDR1002",
        "guid": "guid-a1aea204-644e-40a7-a2d6-407846fb73fe",
        "section": "pdrphysical-disk-event-messages",
        "title": "A predictive failure detected on drive in disk drive bay.",
    },
}

# Dell EEMS Prefix to Chapter Section & GUID mapping in the PowerEdge Reference Guide
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

# Cisco UCS IMC Faults Reference Guide — 11-Chapter Catalog & URLs
CISCO_CHAPTER_URLS: Dict[str, Dict[str, str]] = {
    "chassis": {
        "title": "Chassis-Related Faults",
        "url": "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/fault/reference/guide/b_Cisco_UCS_IMC_Faults_Reference_Guide/b_Cisco_UCS_IMC_Faults_Reference_Guide_chapter_01.html",
    },
    "fan": {
        "title": "Fan-Related Faults",
        "url": "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/fault/reference/guide/b_Cisco_UCS_IMC_Faults_Reference_Guide/b_Cisco_UCS_IMC_Faults_Reference_Guide_chapter_010.html",
    },
    "io": {
        "title": "I/O Module-Related Faults",
        "url": "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/fault/reference/guide/b_Cisco_UCS_IMC_Faults_Reference_Guide/b_Cisco_UCS_IMC_Faults_Reference_Guide_chapter_011.html",
    },
    "sel": {
        "title": "System Event Log-Related Faults",
        "url": "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/fault/reference/guide/b_Cisco_UCS_IMC_Faults_Reference_Guide/b_Cisco_UCS_IMC_Faults_Reference_Guide_chapter_0100.html",
    },
    "sem": {
        "title": "SEM Faults",
        "url": "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/fault/reference/guide/b_Cisco_UCS_IMC_Faults_Reference_Guide/m_sem_faults.html",
    },
    "memory": {
        "title": "Memory-Related Faults",
        "url": "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/fault/reference/guide/b_Cisco_UCS_IMC_Faults_Reference_Guide/b_Cisco_UCS_IMC_Faults_Reference_Guide_chapter_0101.html",
    },
    "processor": {
        "title": "Processor-Related Faults",
        "url": "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/fault/reference/guide/b_Cisco_UCS_IMC_Faults_Reference_Guide/b_Cisco_UCS_IMC_Faults_Reference_Guide_chapter_0110.html",
    },
    "psu": {
        "title": "Power Supply-Related Faults",
        "url": "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/fault/reference/guide/b_Cisco_UCS_IMC_Faults_Reference_Guide/b_Cisco_UCS_IMC_Faults_Reference_Guide_chapter_0111.html",
    },
    "server": {
        "title": "Server-Related Faults",
        "url": "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/fault/reference/guide/b_Cisco_UCS_IMC_Faults_Reference_Guide/b_Cisco_UCS_IMC_Faults_Reference_Guide_chapter_01000.html",
    },
    "storage": {
        "title": "Storage-Related Faults",
        "url": "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/fault/reference/guide/b_Cisco_UCS_IMC_Faults_Reference_Guide/b_Cisco_UCS_IMC_Faults_Reference_Guide_chapter_01001.html",
    },
    "overview": {
        "title": "Overview",
        "url": "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/fault/reference/guide/b_Cisco_UCS_IMC_Faults_Reference_Guide/b_Cisco_UCS_IMC_Faults_Reference_Guide_chapter_01010.html",
    },
}

# Prefix-based chapter routing for Cisco IMC Fault names
CISCO_PREFIX_TO_CHAPTER: Dict[str, str] = {
    "fltEquipmentFan": "fan",
    "fltEquipmentPsu": "psu",
    "fltPowerChassis": "psu",
    "fltPowerBudget": "sem",
    "fltMemory": "memory",
    "fltDcx": "memory",
    "fltProcessor": "processor",
    "fltStorage": "storage",
    "fltPLX": "storage",
    "fltEquipmentIOCard": "io",
    "fltEquipmentSystemIOController": "io",
    "fltEquipmentChassis": "chassis",
    "fltChassisOpen": "chassis",
    "fltSysdebug": "sel",
    "fltBiosUnit": "sem",
    "fltComputeBoardFailedSecureFuse": "sem",
    "fltCompute": "server",
    "fltAdapter": "server",
    "fltAdaptor": "server",
    "fltMgmt": "server",
    "fltIncompatible": "server",
}

# Direct mapping for all 230 F-codes and flt* names in Cisco UCS IMC Faults Reference Guide
CISCO_FAULT_TO_CHAPTER_MAP: Dict[str, str] = {
    "F0174": "processor",
    "F0175": "processor",
    "F0176": "processor",
    "F0177": "processor",
    "F0178": "processor",
    "F0179": "processor",
    "F0180": "processor",
    "F0181": "processor",
    "F0184": "memory",
    "F0185": "memory",
    "F0186": "memory",
    "F0187": "memory",
    "F0188": "memory",
    "F0190": "memory",
    "F0191": "memory",
    "F0203": "server",
    "F0207": "server",
    "F0310": "server",
    "F0313": "server",
    "F0320": "server",
    "F0321": "server",
    "F0322": "server",
    "F0323": "server",
    "F0324": "server",
    "F0325": "server",
    "F0326": "server",
    "F0327": "server",
    "F0328": "server",
    "F0329": "server",
    "F0330": "server",
    "F0331": "server",
    "F0332": "server",
    "F0409": "chassis",
    "F0410": "chassis",
    "F0411": "chassis",
    "F0412": "psu",
    "F0413": "psu",
    "F0414": "psu",
    "F0415": "psu",
    "F0416": "psu",
    "F0417": "psu",
    "F0418": "psu",
    "F0419": "psu",
    "F0420": "psu",
    "F0421": "psu",
    "F0422": "psu",
    "F0423": "psu",
    "F0424": "psu",
    "F0460": "sel",
    "F0461": "sel",
    "F0462": "sel",
    "F0510": "fan",
    "F0511": "fan",
    "F0512": "fan",
    "F0513": "fan",
    "F0514": "fan",
    "F0515": "fan",
    "F0727": "io",
    "F0728": "io",
    "F0729": "io",
    "F0730": "io",
    "F0731": "io",
    "F0744": "sem",
    "F0833": "server",
    "F0834": "server",
    "F0835": "server",
    "F0836": "server",
    "F0945": "server",
    "F0986": "server",
    "F0987": "server",
    "F0996": "server",
    "F0997": "server",
    "F1004": "server",
    "F1005": "server",
    "F1006": "server",
    "F1007": "server",
    "F1008": "storage",
    "F1009": "storage",
    "F1010": "storage",
    "F1011": "storage",
    "F1012": "storage",
    "F1013": "storage",
    "F1014": "storage",
    "F1015": "storage",
    "F1016": "storage",
    "F1017": "storage",
    "F1018": "storage",
    "F1019": "storage",
    "F1020": "storage",
    "F1021": "storage",
    "F1022": "storage",
    "F1023": "storage",
    "F1024": "storage",
    "F1025": "storage",
    "F1026": "storage",
    "F1027": "storage",
    "F1028": "storage",
    "F1029": "storage",
    "F1100": "storage",
    "F1101": "storage",
    "F1102": "storage",
    "F1103": "storage",
    "F1104": "storage",
    "F1105": "storage",
    "F1212": "server",
    "F1213": "server",
    "F1320": "server",
    "F1321": "server",
    "F1322": "server",
    "F1744": "io",
    "F1828": "psu",
    "F1935": "sem",
    "F1936": "sem",
    "fltAdapterUnitMissing": "server",
    "fltAdaptorHostIfLink-down": "server",
    "fltBiosUnitFD0FailedSecurityVerification": "sem",
    "fltChassisOpenServer": "chassis",
    "fltComputeBoardCmosVoltageThresholdCritical": "server",
    "fltComputeBoardCmosVoltageThresholdNonRecoverable": "server",
    "fltComputeBoardFailedSecureFuseValidation": "sem",
    "fltComputeBoardMotherBoardVoltageLowerThresholdCritical": "server",
    "fltComputeBoardMotherBoardVoltageThresholdLowerNonRecoverable": "server",
    "fltComputeBoardMotherBoardVoltageThresholdUpperNonRecoverable": "server",
    "fltComputeBoardMotherBoardVoltageUpperThresholdCritical": "server",
    "fltComputeBoardPowerError": "server",
    "fltComputeBoardPowerFail": "server",
    "fltComputeBoardPowerUsageProblem": "server",
    "fltComputeBoardThermalProblem": "server",
    "fltComputeIOHubThermalNonCritical": "server",
    "fltComputeIOHubThermalThresholdCritical": "server",
    "fltComputeIOHubThermalThresholdNonRecoverable": "server",
    "fltComputePhysicalBiosPostTimeout": "server",
    "fltComputePhysicalPostfailure": "server",
    "fltComputePhysicalUnidentified": "server",
    "fltComputeRtcBatteryInoperable": "server",
    "fltDcxHealthCritical": "memory",
    "fltDcxMediaError": "memory",
    "fltDcxPlatformComponentCritical": "memory",
    "fltDcxSecurityNonceMismatch": "memory",
    "fltDcxThermalCritical": "memory",
    "fltEquipmentChassisThermalThresholdCritical": "chassis",
    "fltEquipmentChassisThermalThresholdNonCritical": "chassis",
    "fltEquipmentChassisThermalThresholdNonRecoverable": "chassis",
    "fltEquipmentFanDegraded": "fan",
    "fltEquipmentFanMissing": "fan",
    "fltEquipmentFanModuleThermalThresholdCritical": "psu",
    "fltEquipmentFanModuleThermalThresholdNonCritical": "psu",
    "fltEquipmentFanModuleThermalThresholdNonRecoverable": "psu",
    "fltEquipmentFanPerfThresholdCritical": "fan",
    "fltEquipmentFanPerfThresholdNonCritical": "fan",
    "fltEquipmentFanPerfThresholdNonRecoverable": "fan",
    "fltEquipmentIOCardRemoved": "io",
    "fltEquipmentIOCardThermalProblem": "io",
    "fltEquipmentIOCardThermalThresholdCritical": "io",
    "fltEquipmentIOCardThermalThresholdNonCritical": "io",
    "fltEquipmentIOCardThermalThresholdNonRecoverable": "io",
    "fltEquipmentPsuIdentity": "psu",
    "fltEquipmentPsuInoperable": "psu",
    "fltEquipmentPsuInputError": "psu",
    "fltEquipmentPsuMissing": "psu",
    "fltEquipmentPsuOffline": "psu",
    "fltEquipmentPsuPerfThresholdCritical": "psu",
    "fltEquipmentPsuPerfThresholdNonCritical": "psu",
    "fltEquipmentPsuPerfThresholdNonRecoverable": "psu",
    "fltEquipmentPsuPowerSupplyProblem": "psu",
    "fltEquipmentPsuPowerThreshold": "psu",
    "fltEquipmentPsuThermalThresholdCritical": "psu",
    "fltEquipmentPsuThermalThresholdNonCritical": "psu",
    "fltEquipmentPsuThermalThresholdNonRecoverable": "psu",
    "fltEquipmentPsuUnsupported": "psu",
    "fltEquipmentPsuVoltageThresholdCritical": "psu",
    "fltEquipmentPsuVoltageThresholdNonCritical": "psu",
    "fltEquipmentPsuVoltageThresholdNonRecoverable": "psu",
    "fltEquipmentSystemIOControllerRemoved": "io",
    "fltEquipmentTpmTpmMismatch": "server",
    "fltIncompatibleHardwareDetected": "server",
    "fltIntersightGenericCode": "storage",
    "fltMemoryArrayVoltageThresholdCritical": "memory",
    "fltMemoryArrayVoltageThresholdNonRecoverable": "memory",
    "fltMemoryUnitDegraded": "memory",
    "fltMemoryUnitDisabled": "memory",
    "fltMemoryUnitIdentityUnestablishable": "memory",
    "fltMemoryUnitInoperable": "memory",
    "fltMemoryUnitThermalThresholdCritical": "memory",
    "fltMemoryUnitThermalThresholdNonCritical": "memory",
    "fltMemoryUnitThermalThresholdNonRecoverable": "memory",
    "fltMgmtHealthStatusHealthCriticalIssue": "server",
    "fltMgmtHealthStatusHealthMajorIssue": "server",
    "fltMgmtHealthStatusHealthWarningIssue4": "overview",
    "fltMgmtIfMissing": "server",
    "fltPLXHealthCritical": "storage",
    "fltPciEquipSlotUnsecure": "sem",
    "fltPowerBudgetPowerBudgetBmcProblem": "server",
    "fltPowerBudgetPowerBudgetCmcProblem": "server",
    "fltPowerBudgetPowerCapReachedCommit": "sem",
    "fltPowerChassisMemberChassisPsuRedundanceFailure": "psu",
    "fltProcessorUnitDisabled": "processor",
    "fltProcessorUnitInoperable": "processor",
    "fltProcessorUnitThermalNonCritical": "processor",
    "fltProcessorUnitThermalThresholdCritical": "processor",
    "fltProcessorUnitThermalThresholdNonRecoverable": "processor",
    "fltProcessorUnitVoltageThresholdCritical": "processor",
    "fltProcessorUnitVoltageThresholdNonCritical": "processor",
    "fltProcessorUnitVoltageThresholdNonRecoverable": "processor",
    "fltStorageControllerInoperable": "storage",
    "fltStorageControllerPatrolReadFailed": "storage",
    "fltStorageFlexFlashCardInoperable": "storage",
    "fltStorageFlexFlashCardMissing": "storage",
    "fltStorageFlexFlashControllerInoperable": "storage",
    "fltStorageFlexFlashControllerUnhealthy": "storage",
    "fltStorageFlexFlashVirtualDriveDegraded": "storage",
    "fltStorageFlexFlashVirtualDriveInoperable": "storage",
    "fltStorageLocalDiskCopybackFailed": "storage",
    "fltStorageLocalDiskDegraded": "storage",
    "fltStorageLocalDiskInoperable": "storage",
    "fltStorageLocalDiskLifeTimeLapse": "storage",
    "fltStorageLocalDiskLinkDegraded": "storage",
    "fltStorageLocalDiskMissing": "storage",
    "fltStorageLocalDiskRebuildFailed": "storage",
    "fltStorageLocalDiskSlotEpUnusable": "server",
    "fltStorageRaidBatteryDegraded": "storage",
    "fltStorageRaidBatteryInoperable": "storage",
    "fltStorageRaidBatteryRelearnAborted": "storage",
    "fltStorageRaidBatteryRelearnFailed": "storage",
    "fltStorageSasExpanderAccessibility": "storage",
    "fltStorageSasExpanderDegraded": "storage",
    "fltStorageVirtualDriveConsistencyCheckFailed": "storage",
    "fltStorageVirtualDriveDegraded": "storage",
    "fltStorageVirtualDriveInoperable": "storage",
    "fltStorageVirtualDriveReconstructionFailed": "storage",
    "fltSysdebugMEpLogMEpLogFull": "sel",
    "fltSysdebugMEpLogMEpLogLow": "sel",
    "fltSysdebugMEpLogMEpLogVeryLow": "sel",
}


def build_dell_guide_url(code_or_prefix: str) -> str:
    """Build a direct link to the Dell PowerEdge EEMS Reference Guide chapter for a code or prefix.

    If a specific chapter GUID is mapped for the prefix, constructs a direct chapter URL.
    Otherwise, safely routes to the Master Guide Root TOC where all 140+ EEMS categories
    are indexed with working chapter links, avoiding 'Data is not available for the Topic' errors.
    """
    return build_dell_eems_guide_url(code_or_prefix)


def get_vendor_sel_guide(vendor: Optional[str]) -> Optional[Dict[str, str]]:
    """Return the SEL guide descriptor dictionary for a vendor, or None if unknown/generic."""
    norm = normalize_vendor(vendor)
    return VENDOR_SEL_GUIDES.get(norm)


def extract_dell_event_code(message_id: Optional[str], message: Optional[str] = "") -> Optional[str]:
    """Extract a Dell EEMS event code (e.g. PSU0001) from message_id or message text.

    Handles pure codes ('PSU0001'), Redfish registry IDs ('IDRAC.1.6.PSU0001',
    'Base.1.0.PSU0001'), and message text prefixes.
    """
    for candidate in [message_id, message]:
        if not candidate:
            continue
        m = _DELL_CODE_PATTERN.search(str(candidate))
        if m:
            return m.group(1).upper()
    return None


def clean_event_search_query(message: Optional[str]) -> str:
    """Clean an event message string into a focused search query."""
    if not message:
        return ""
    text = str(message).strip().strip(".:;,")
    if not text:
        return ""
    # Take first sentence if multiple sentences exist
    first_sent = re.split(r"[.!?]\s+", text)[0].strip()
    return first_sent or text


def resolve_dell_event_info(
    message_id: Optional[str],
    message: Optional[str] = "",
) -> Dict[str, str]:
    """Resolve Dell event metadata (EEMS code, direct guide URL, and title).

    Checks in order:
      1. Pre-built mapping of IPMI sensor hex codes (e.g. 0b01ffff -> RDU0012, 6f03ffff -> PSU0003, efa00113 -> PDR1016)
      2. Dynamic pattern match for efa0.... drive removal codes -> PDR1016
      3. Alphanumeric Dell EEMS code extracted from message_id or message text (e.g. PSU0001, IDRAC.1.6.AMP0302, TST100)
      4. Category GUID / chapter in the Dell PowerEdge Reference Guide based on prefix
      5. Fallback to Dell PowerEdge EEMS Guide root
    """
    clean_id = str(message_id or "").strip().lower()
    decoded = decode_dell_message_id(message_id, message)

    def _enrich(d: Dict[str, str]) -> Dict[str, str]:
        if decoded:
            d["domain"] = decoded.domain
            d["severity"] = decoded.severity
            d["vcf_impact"] = decoded.vcf_impact
            d["explanation"] = decoded.explanation
            d["remediation"] = decoded.remediation
            d["is_vcf_blocker"] = str(decoded.is_vcf_blocker)
        return d

    # 1. Direct hex mapping
    if clean_id in DELL_HEX_TO_EEMS_MAP:
        entry = DELL_HEX_TO_EEMS_MAP[clean_id]
        eems = entry["eems"]
        guid = entry["guid"]
        sec = entry["section"]
        if guid and guid != "guid-96cc49ee-fa46-4249-adb6-e0c9a3cbdb1f" and sec:
            guide_url = f"{DELL_GUIDE_BASE_URL}{sec}?guid={guid}&lang=en-us"
        else:
            guide_url = VENDOR_SEL_GUIDES["dell"]["url"]
        return _enrich({
            "eems": eems,
            "url": guide_url,
            "title": entry["title"],
            "display": f"{message_id} ({eems})",
        })

    # 2. Dynamic drive bay hex match (efa0.... -> PDR1016)
    if clean_id.startswith("efa0"):
        guide_url = (
            f"{DELL_GUIDE_BASE_URL}pdrphysical-disk-event-messages"
            "?guid=guid-a1aea204-644e-40a7-a2d6-407846fb73fe&lang=en-us"
        )
        return _enrich({
            "eems": "PDR1016",
            "url": guide_url,
            "title": "Drive is removed from disk drive bay.",
            "display": f"{message_id} (PDR1016)",
        })

    # Dynamic PCI bus fatal error match (6fac.... -> PCI0001)
    if clean_id.startswith("6fac"):
        guide_url = (
            f"{DELL_GUIDE_BASE_URL}pcipci-device-event-messages"
            "?guid=guid-5cbae8ab-1e63-4868-86f8-edf202bc62b0&lang=en-us"
        )
        return _enrich({
            "eems": "PCI0001",
            "url": guide_url,
            "title": "Fatal error detected on bus component.",
            "display": f"{message_id} (PCI0001)",
        })

    # 3. Extract EEMS code
    code = extract_dell_event_code(message_id, message)
    if code:
        guide_url = build_dell_guide_url(code)
        return _enrich({
            "eems": code,
            "url": guide_url,
            "title": f"Dell PowerEdge EEMS Code {code}",
            "display": code,
        })

    # 4. Clean search query fallback (for unmapped hex or other messages)
    query = clean_event_search_query(message)
    if query:
        query_lower = query.lower()
        if "power supply redundancy is lost" in query_lower or "lost psu redundancy" in query_lower:
            return _enrich({
                "eems": "RDU0012",
                "url": (
                    f"{DELL_GUIDE_BASE_URL}rduredundancy-event-messages"
                    "?guid=guid-f2266b18-390a-49a4-8529-26b104160b81&lang=en-us"
                ),
                "title": "Power supply redundancy is lost.",
                "display": f"{message_id} (RDU0012)" if message_id else "RDU0012",
            })
        if "not receiving input power" in query_lower:
            return _enrich({
                "eems": "PSU0003",
                "url": (
                    f"{DELL_GUIDE_BASE_URL}psupower-supply-event-messages"
                    "?guid=guid-a830aecc-63d1-4032-8bc0-7523037d3b56&lang=en-us"
                ),
                "title": "The Power Supply Unit (PSU) is not receiving input power because of issues in PSU or cable connections.",
                "display": f"{message_id} (PSU0003)" if message_id else "PSU0003",
            })
        if "removed from disk drive bay" in query_lower or "drive is removed" in query_lower:
            return _enrich({
                "eems": "PDR1016",
                "url": (
                    f"{DELL_GUIDE_BASE_URL}pdrphysical-disk-event-messages"
                    "?guid=guid-a1aea204-644e-40a7-a2d6-407846fb73fe&lang=en-us"
                ),
                "title": "Drive is removed from disk drive bay.",
                "display": f"{message_id} (PDR1016)" if message_id else "PDR1016",
            })
        if "chassis is open" in query_lower:
            return _enrich({
                "eems": "SEC0033",
                "url": (
                    f"{DELL_GUIDE_BASE_URL}secsecurity-event-event-messages"
                    "?guid=guid-7dbdd871-f80b-4acb-ac7b-552d63fe240f&lang=en-us"
                ),
                "title": "The chassis is open while the power is off.",
                "display": f"{message_id} (SEC0033)" if message_id else "SEC0033",
            })
        if "system configuration check" in query_lower:
            return _enrich({
                "eems": "HWC8010",
                "url": (
                    f"{DELL_GUIDE_BASE_URL}hwchardware-config-event-messages"
                    "?guid=guid-9e52a11f-b453-4a28-83ee-d49354f14c09&lang=en-us"
                ),
                "title": "The System Configuration Check operation resulted in an issue.",
                "display": f"{message_id} (HWC8010)" if message_id else "HWC8010",
            })
        if "battery is low" in query_lower:
            return _enrich({
                "eems": "BAT0015",
                "url": (
                    f"{DELL_GUIDE_BASE_URL}batbattery-event-event-messages"
                    "?guid=guid-2f178717-1f38-4166-aaf7-af1c1cbeee66&lang=en-us"
                ),
                "title": "The battery is low.",
                "display": f"{message_id} (BAT0015)" if message_id else "BAT0015",
            })
        if "power exceeds capacity" in query_lower:
            return _enrich({
                "eems": "PWR0001",
                "url": (
                    f"{DELL_GUIDE_BASE_URL}pwrpower-usage-event-messages"
                    "?guid=guid-be9590cf-d70c-4a3c-b85b-12c71733afb7&lang=en-us"
                ),
                "title": "The system halted because system power exceeds capacity.",
                "display": f"{message_id} (PWR0001)" if message_id else "PWR0001",
            })
        if "platform security processor" in query_lower or "psp" in query_lower:
            return _enrich({
                "eems": "PST0258",
                "url": (
                    f"{DELL_GUIDE_BASE_URL}pstbios-post-event-messages"
                    "?guid=guid-149130fa-9995-452c-9172-551eebe559c3&lang=en-us"
                ),
                "title": "The AMD Platform Security Processor (PSP) detected a security-related issue while booting the server.",
                "display": f"{message_id} (PST0258)" if message_id else "PST0258",
            })
        if "fatal error was detected" in query_lower or "fatal error detected" in query_lower:
            return _enrich({
                "eems": "PCI0001",
                "url": (
                    f"{DELL_GUIDE_BASE_URL}pcipci-device-event-messages"
                    "?guid=guid-5cbae8ab-1e63-4868-86f8-edf202bc62b0&lang=en-us"
                ),
                "title": "Fatal error detected on bus component.",
                "display": f"{message_id} (PCI0001)" if message_id else "PCI0001",
            })

    # 5. Fallback to Dell guide root
    return _enrich({
        "eems": "",
        "url": VENDOR_SEL_GUIDES["dell"]["url"],
        "title": VENDOR_SEL_GUIDES["dell"]["guide_title"],
        "display": str(message_id or ""),
    })


def resolve_hpe_event_info(
    message_id: Optional[str],
    message: Optional[str] = "",
) -> Dict[str, str]:
    """Resolve HPE IML event metadata and direct troubleshooting guide URL.

    Redfish IML messages on HPE ProLiant record event IDs as <class_decimal>.<code_decimal>
    (e.g. '19.22', '2.35', '10.5920', '51.7', '50.1122').
    Converts decimal or hex class and code into the canonical HPE Gen12 IML Guide URL:
      https://support.hpe.com/hpesc/public/docDisplay?docId=ilogen12-msg-en_us&page=class0x{class_hex:04x}code0x{code_hex:04x}-gen12.html
    """
    clean_id = str(message_id or "").strip()

    # 1. Decimal class.code pattern (e.g. 19.22, 10.5920, 2.35)
    m_dec = re.match(r"^(\d+)\.(\d+)$", clean_id)
    if m_dec:
        c_dec, code_dec = int(m_dec.group(1)), int(m_dec.group(2))
        c_hex, code_hex = f"{c_dec:04x}", f"{code_dec:04x}"
        url = (
            f"https://support.hpe.com/hpesc/public/docDisplay?docId=ilogen12-msg-en_us&"
            f"page=class0x{c_hex}code0x{code_hex}-gen12.html"
        )
        return {
            "class_code": f"0x{c_hex}/0x{code_hex}",
            "url": url,
            "title": f"HPE IML Event Class 0x{c_hex} Code 0x{code_hex}",
            "display": f"{clean_id} (0x{c_hex}/0x{code_hex})",
        }

    # 2. Hex class.code or class0x...code0x... pattern
    m_hex = re.search(r"class0x([0-9a-fA-F]+)code0x([0-9a-fA-F]+)", clean_id.lower())
    if not m_hex:
        m_hex = re.search(r"0x([0-9a-fA-F]+)[\.:]0x([0-9a-fA-F]+)", clean_id.lower())
    if m_hex:
        c_val = int(m_hex.group(1), 16)
        code_val = int(m_hex.group(2), 16)
        c_hex, code_hex = f"{c_val:04x}", f"{code_val:04x}"
        url = (
            f"https://support.hpe.com/hpesc/public/docDisplay?docId=ilogen12-msg-en_us&"
            f"page=class0x{c_hex}code0x{code_hex}-gen12.html"
        )
        return {
            "class_code": f"0x{c_hex}/0x{code_hex}",
            "url": url,
            "title": f"HPE IML Event Class 0x{c_hex} Code 0x{code_hex}",
            "display": f"{clean_id}",
        }

    # 3. Check message text for 'Error Class : 0xXXXX | Error Code: 0xYYYY'
    if message:
        m_msg = re.search(
            r"Error\s+Class\s*:\s*0x([0-9a-fA-F]+).*?Error\s+Code\s*:\s*0x([0-9a-fA-F]+)",
            str(message),
            re.IGNORECASE,
        )
        if m_msg:
            c_val = int(m_msg.group(1), 16)
            code_val = int(m_msg.group(2), 16)
            c_hex, code_hex = f"{c_val:04x}", f"{code_val:04x}"
            url = (
                f"https://support.hpe.com/hpesc/public/docDisplay?docId=ilogen12-msg-en_us&"
                f"page=class0x{c_hex}code0x{code_hex}-gen12.html"
            )
            return {
                "class_code": f"0x{c_hex}/0x{code_hex}",
                "url": url,
                "title": f"HPE IML Event Class 0x{c_hex} Code 0x{code_hex}",
                "display": f"{clean_id} (0x{c_hex}/0x{code_hex})" if clean_id else f"0x{c_hex}/0x{code_hex}",
            }

    # 4. Search query fallback
    query = clean_event_search_query(message)
    if query:
        return {
            "class_code": "",
            "url": f"https://support.hpe.com/hpesc/public/search#q={urllib.parse.quote(query)}",
            "title": f"Search HPE Support for: {query}",
            "display": clean_id,
        }

    # 5. Top-level guide fallback
    return {
        "class_code": "",
        "url": VENDOR_SEL_GUIDES["hpe"]["url"],
        "title": VENDOR_SEL_GUIDES["hpe"]["guide_title"],
        "display": clean_id,
    }


def resolve_cisco_event_info(
    message_id: Optional[str],
    message: Optional[str] = "",
) -> Dict[str, str]:
    """Resolve Cisco IMC Fault metadata and direct guide chapter URL."""
    clean_id = str(message_id or "").strip()

    # 1. Exact match in full Cisco catalog (F-codes or flt* names)
    if clean_id in CISCO_FAULT_TO_CHAPTER_MAP:
        ch_key = CISCO_FAULT_TO_CHAPTER_MAP[clean_id]
        ch_entry = CISCO_CHAPTER_URLS[ch_key]
        return {
            "code": clean_id,
            "url": ch_entry["url"],
            "title": f"Cisco IMC Fault {clean_id} ({ch_entry['title']})",
            "display": clean_id,
        }

    # 2. Match F-code regex (e.g. F0409, F0462) in message_id or message
    for candidate in [clean_id, message]:
        if not candidate:
            continue
        m_f = re.search(r"\b(F\d{4})\b", str(candidate))
        if m_f:
            f_code = m_f.group(1).upper()
            if f_code in CISCO_FAULT_TO_CHAPTER_MAP:
                ch_key = CISCO_FAULT_TO_CHAPTER_MAP[f_code]
                ch_entry = CISCO_CHAPTER_URLS[ch_key]
                return {
                    "code": f_code,
                    "url": ch_entry["url"],
                    "title": f"Cisco IMC Fault {f_code} ({ch_entry['title']})",
                    "display": f"{clean_id} ({f_code})" if clean_id and clean_id != f_code else f_code,
                }

    # 3. Match flt* symbol in message_id or message
    for candidate in [clean_id, message]:
        if not candidate:
            continue
        m_flt = re.search(r"\b(flt[A-Za-z0-9_-]+)\b", str(candidate))
        if m_flt:
            flt_name = m_flt.group(1)
            if flt_name in CISCO_FAULT_TO_CHAPTER_MAP:
                ch_key = CISCO_FAULT_TO_CHAPTER_MAP[flt_name]
                ch_entry = CISCO_CHAPTER_URLS[ch_key]
                return {
                    "code": flt_name,
                    "url": ch_entry["url"],
                    "title": f"Cisco IMC Fault {flt_name} ({ch_entry['title']})",
                    "display": flt_name,
                }
            for pfx, ch_key in CISCO_PREFIX_TO_CHAPTER.items():
                if flt_name.startswith(pfx):
                    ch_entry = CISCO_CHAPTER_URLS[ch_key]
                    return {
                        "code": flt_name,
                        "url": ch_entry["url"],
                        "title": f"Cisco IMC Fault {flt_name} ({ch_entry['title']})",
                        "display": flt_name,
                    }

    # 4. Search query fallback
    query = clean_event_search_query(message)
    if query:
        return {
            "code": "",
            "url": f"https://www.cisco.com/c/en/us/search.html#q={urllib.parse.quote(query)}",
            "title": f"Search Cisco Support for: {query}",
            "display": clean_id,
        }

    # 5. Top-level guide fallback
    return {
        "code": "",
        "url": VENDOR_SEL_GUIDES["cisco"]["url"],
        "title": VENDOR_SEL_GUIDES["cisco"]["guide_title"],
        "display": clean_id,
    }


def resolve_sel_event_url(
    vendor: Optional[str],
    message_id: Optional[str],
    message: Optional[str] = "",
) -> Optional[str]:
    """Resolve an event-specific URL or fallback vendor guide URL for an SEL entry.

    For Dell PowerEdge:
      Resolves directly to the exact chapter and GUID within Dell's PowerEdge Servers
      Error and Event Messages Reference Guide (EEMs).
      Maps IPMI hex sensor codes to their corresponding EEMS code and manual section.

    For HPE ProLiant:
      Resolves directly to the HPE Gen12 IML Messages and Troubleshooting Guide topic
      derived from decimal class.code (e.g. 19.22 -> class0x0013code0x0016-gen12.html).

    For Cisco UCS:
      Resolves directly to the Cisco IMC Faults Reference Guide chapter based on F-codes,
      flt* fault names, and component fault prefixes.

    For Lenovo:
      Queries Lenovo Data Center Support search for the alert.

    For Supermicro:
      Returns the top-level Supermicro IPMI SEL Reference Guide PDF.
    """
    norm = normalize_vendor(vendor)
    guide = VENDOR_SEL_GUIDES.get(norm)
    if not guide:
        return None

    if norm == "dell":
        info = resolve_dell_event_info(message_id, message)
        return info["url"]

    if norm == "hpe":
        info = resolve_hpe_event_info(message_id, message)
        return info["url"]

    if norm == "cisco":
        info = resolve_cisco_event_info(message_id, message)
        return info["url"]

    if norm == "lenovo":
        query = clean_event_search_query(message)
        if query:
            return f"https://datacentersupport.lenovo.com/us/en/search?query={urllib.parse.quote(query)}"
        return guide["url"]

    # Other vendors return top-level guide URL
    return guide["url"]


def render_vendor_guide_button(vendor: Optional[str]) -> str:
    """Render a tasteful external link button to the vendor SEL guide.

    Suitable for placement above or alongside the SEL table header.
    Returns an empty string if vendor is unknown or generic.
    """
    guide = get_vendor_sel_guide(vendor)
    if not guide:
        return ""

    escaped_url = html.escape(guide["url"])
    escaped_title = html.escape(guide["guide_title"])
    escaped_label = html.escape(guide["badge_label"])

    return (
        f'<a href="{escaped_url}" target="_blank" rel="noopener noreferrer" '
        f'class="btn-link" style="display:inline-flex;align-items:center;gap:.35rem;'
        f'font-size:.8rem;padding:.2rem .55rem;border-radius:4px;border:1px solid var(--border);'
        f'background:var(--card);text-decoration:none;font-weight:500" '
        f'title="{escaped_title}">'
        f'<span>{escaped_label}</span> <span style="font-size:.72rem">↗</span></a>'
    )


def render_sel_message_id_cell(
    vendor: Optional[str],
    message_id: Optional[str],
    message: Optional[str] = "",
) -> str:
    """Render the Message ID table cell, making it clickable when a guide URL is resolved."""
    msg_id_str = str(message_id or "").strip()
    if not msg_id_str or msg_id_str.upper() in ("N/A", "NONE", "-", "UNKNOWN"):
        return "<code style='color:var(--text-muted)'>N/A</code>"

    norm = normalize_vendor(vendor)
    if norm == "dell":
        info = resolve_dell_event_info(message_id, message)
        url = info["url"]
        display_text = info["display"]
        escaped_id = html.escape(display_text)
        escaped_url = html.escape(url)
        title_text = f"Dell EEMS Reference: {info['title']}"
        remediation = info.get("remediation")
        if remediation:
            title_text = f"{title_text} — Remediation: {remediation}"
        return (
            f'<a href="{escaped_url}" target="_blank" rel="noopener noreferrer" '
            f'style="color:var(--primary);text-decoration:none" title="{html.escape(title_text)}">'
            f'<code style="font-weight:600;text-decoration:underline">{escaped_id}</code> '
            f'<span style="font-size:.72rem">↗</span></a>'
        )

    if norm == "hpe":
        info = resolve_hpe_event_info(message_id, message)
        url = info["url"]
        display_text = info["display"]
        escaped_id = html.escape(display_text)
        escaped_url = html.escape(url)
        title_text = info["title"]
        return (
            f'<a href="{escaped_url}" target="_blank" rel="noopener noreferrer" '
            f'style="color:var(--primary);text-decoration:none" title="{html.escape(title_text)}">'
            f'<code style="font-weight:600;text-decoration:underline">{escaped_id}</code> '
            f'<span style="font-size:.72rem">↗</span></a>'
        )

    if norm == "cisco":
        info = resolve_cisco_event_info(message_id, message)
        url = info["url"]
        display_text = info["display"]
        escaped_id = html.escape(display_text)
        escaped_url = html.escape(url)
        title_text = info["title"]
        return (
            f'<a href="{escaped_url}" target="_blank" rel="noopener noreferrer" '
            f'style="color:var(--primary);text-decoration:none" title="{html.escape(title_text)}">'
            f'<code style="font-weight:600;text-decoration:underline">{escaped_id}</code> '
            f'<span style="font-size:.72rem">↗</span></a>'
        )

    escaped_id = html.escape(msg_id_str)
    url = resolve_sel_event_url(vendor, message_id, message)

    if url:
        escaped_url = html.escape(url)
        title_text = f"Open vendor reference guide for {msg_id_str}"
        return (
            f'<a href="{escaped_url}" target="_blank" rel="noopener noreferrer" '
            f'style="color:var(--primary);text-decoration:none" title="{html.escape(title_text)}">'
            f'<code style="font-weight:600;text-decoration:underline">{escaped_id}</code> '
            f'<span style="font-size:.72rem">↗</span></a>'
        )

    return f"<code>{escaped_id}</code>"
