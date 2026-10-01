"""BMC Security Audit control catalog and metadata.

Provides human-readable titles, architectural groupings, default audit transports,
and evaluation confidence levels for all 84 defined controls (C01-C59, O01-O16, I01-I09).
"""

from typing import Dict, List

# Group definitions and display labels
GROUP_BASELINE = "baseline"
GROUP_CONDITIONAL = "conditional"
GROUP_DELL_RUNBOOK = "dell_runbook"
GROUP_OPERATIONAL = "operational"
GROUP_ASSURANCE = "assurance"

GROUP_LABELS: Dict[str, str] = {
    GROUP_BASELINE: "Baseline Hardening Controls (VCF SCG Alignment)",
    GROUP_CONDITIONAL: "Conditional Hardening Controls (Environment Dependent)",
    GROUP_DELL_RUNBOOK: "OEM Runbook & Procedural Controls (Dell-Specific)",
    GROUP_OPERATIONAL: "Operational Recommendations (Lifecycle & Governance)",
    GROUP_ASSURANCE: "Hardware & Platform Assurance Capabilities",
}

GROUP_ORDER: List[str] = [
    GROUP_BASELINE,
    GROUP_CONDITIONAL,
    GROUP_DELL_RUNBOOK,
    GROUP_OPERATIONAL,
    GROUP_ASSURANCE,
]

# Control catalog: ID -> metadata mapping
# Covers all 84 controls defined in the BMC Security Architecture
CONTROL_CATALOG: Dict[str, Dict[str, str]] = {
    # -------------------------------------------------------------------------
    # Baseline Hardening Controls (C01-C59 configuration subset)
    # -------------------------------------------------------------------------
    "C01": {
        "id": "C01",
        "title": "HTTP-to-HTTPS Redirection",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C02": {
        "id": "C02",
        "title": "Minimum TLS Version",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C03": {
        "id": "C03",
        "title": "TLS Encryption Strength",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C04": {
        "id": "C04",
        "title": "TLS Cipher-Suite Restriction",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C05": {
        "id": "C05",
        "title": "Trusted iDRAC Web Certificate",
        "group": GROUP_BASELINE,
        "confidence": "Medium",
        "transport": "Dell OEM Redfish",
    },
    "C06": {
        "id": "C06",
        "title": "SCEP / Automated Certificate Enrollment",
        "group": GROUP_CONDITIONAL,
        "confidence": "Medium",
        "transport": "Dell OEM Redfish",
    },
    "C07": {
        "id": "C07",
        "title": "Remote Syslog over TLS",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C08": {
        "id": "C08",
        "title": "FIPS Mode",
        "group": GROUP_CONDITIONAL,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C09": {
        "id": "C09",
        "title": "SSH Service Exposure",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Standard Redfish",
    },
    "C10": {
        "id": "C10",
        "title": "SSH Public-Key Authentication",
        "group": GROUP_CONDITIONAL,
        "confidence": "Medium",
        "transport": "Dell OEM Redfish",
    },
    "C11": {
        "id": "C11",
        "title": "SSH Cryptographic Policy",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C12": {
        "id": "C12",
        "title": "Dedicated Management NIC",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C13": {
        "id": "C13",
        "title": "Management VLAN",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C14": {
        "id": "C14",
        "title": "USB Management & USB SCP",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C15": {
        "id": "C15",
        "title": "OS-to-iDRAC Pass-Through",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C16": {
        "id": "C16",
        "title": "IP Login Blocking",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C17": {
        "id": "C17",
        "title": "IP Allow-Range Filtering",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C18": {
        "id": "C18",
        "title": "Auto-Discovery",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C19": {
        "id": "C19",
        "title": "Auto Config / SCP Provisioning",
        "group": GROUP_BASELINE,
        "confidence": "Medium",
        "transport": "Dell OEM Redfish",
    },
    "C20": {
        "id": "C20",
        "title": "Disable Unused Interfaces & Services",
        "group": GROUP_BASELINE,
        "confidence": "Medium",
        "transport": "Dell OEM Redfish",
    },
    "C21": {
        "id": "C21",
        "title": "IPMI over LAN Disablement",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Standard Redfish",
    },
    "C22": {
        "id": "C22",
        "title": "Serial over LAN Hardening",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C23": {
        "id": "C23",
        "title": "Telnet Service Disablement",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Standard Redfish",
    },
    "C24": {
        "id": "C24",
        "title": "SNMP Service Exposure & SNMPv3",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Standard Redfish",
    },
    "C25": {
        "id": "C25",
        "title": "SNMP Network Isolation",
        "group": GROUP_CONDITIONAL,
        "confidence": "High",
        "transport": "External Process",
    },
    "C26": {
        "id": "C26",
        "title": "SNMP Credentials & Cryptography",
        "group": GROUP_BASELINE,
        "confidence": "Medium",
        "transport": "Dell OEM Redfish",
    },
    "C27": {
        "id": "C27",
        "title": "IPMI Fallback Hardening / Cipher 0",
        "group": GROUP_CONDITIONAL,
        "confidence": "Low",
        "transport": "Vendor Tool",
    },
    "C28": {
        "id": "C28",
        "title": "Authenticated NTP",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C29": {
        "id": "C29",
        "title": "Redfish Session Authentication",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Standard Redfish",
    },
    "C30": {
        "id": "C30",
        "title": "Secure Enterprise Key Manager (SEKM)",
        "group": GROUP_DELL_RUNBOOK,
        "confidence": "Medium",
        "transport": "Dell OEM Redfish",
    },
    "C31": {
        "id": "C31",
        "title": "Group Manager Enablement",
        "group": GROUP_DELL_RUNBOOK,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C32": {
        "id": "C32",
        "title": "Group Manager Network & Passcode",
        "group": GROUP_DELL_RUNBOOK,
        "confidence": "Medium",
        "transport": "Dell OEM Redfish",
    },
    "C33": {
        "id": "C33",
        "title": "Virtual Console Client & Video Encryption",
        "group": GROUP_CONDITIONAL,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C34": {
        "id": "C34",
        "title": "Virtual Console TLS & Web Redirection",
        "group": GROUP_CONDITIONAL,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C35": {
        "id": "C35",
        "title": "Virtual Media Encryption",
        "group": GROUP_CONDITIONAL,
        "confidence": "Low",
        "transport": "Dell OEM Redfish",
    },
    "C36": {
        "id": "C36",
        "title": "VNC Server Hardening",
        "group": GROUP_CONDITIONAL,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C37": {
        "id": "C37",
        "title": "Least-Privilege Roles & Session Timeout",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Standard Redfish",
    },
    "C38": {
        "id": "C38",
        "title": "Per-User IPMI Privilege",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C39": {
        "id": "C39",
        "title": "Per-User SNMPv3 Protection",
        "group": GROUP_BASELINE,
        "confidence": "Medium",
        "transport": "Dell OEM Redfish",
    },
    "C40": {
        "id": "C40",
        "title": "Password Quality Policy",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C41": {
        "id": "C41",
        "title": "Default Password & Force Change",
        "group": GROUP_BASELINE,
        "confidence": "Medium",
        "transport": "Dell OEM Redfish",
    },
    "C42": {
        "id": "C42",
        "title": "Two-Factor Authentication",
        "group": GROUP_BASELINE,
        "confidence": "Medium",
        "transport": "Dell OEM Redfish",
    },
    "C43": {
        "id": "C43",
        "title": "Central Directory Authentication & Lockout",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Standard Redfish",
    },
    "C44": {
        "id": "C44",
        "title": "Active Directory Certificate Validation",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C45": {
        "id": "C45",
        "title": "LDAP Certificate Validation",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C46": {
        "id": "C46",
        "title": "Disable Host-Local Reconfiguration",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C47": {
        "id": "C47",
        "title": "Security Login Banner",
        "group": GROUP_CONDITIONAL,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C48": {
        "id": "C48",
        "title": "System Lockdown",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Dell OEM Redfish",
    },
    "C49": {
        "id": "C49",
        "title": "BIOS Setup/System Passwords & Lock Status",
        "group": GROUP_CONDITIONAL,
        "confidence": "Medium",
        "transport": "Dell OEM Redfish",
    },
    "C50": {
        "id": "C50",
        "title": "BIOS Power-Button Control",
        "group": GROUP_CONDITIONAL,
        "confidence": "Medium",
        "transport": "Standard Redfish",
    },
    "C51": {
        "id": "C51",
        "title": "UEFI Variable Access",
        "group": GROUP_CONDITIONAL,
        "confidence": "Medium",
        "transport": "Standard Redfish",
    },
    "C52": {
        "id": "C52",
        "title": "In-Band Manageability Interface",
        "group": GROUP_CONDITIONAL,
        "confidence": "Medium",
        "transport": "Standard Redfish",
    },
    "C53": {
        "id": "C53",
        "title": "UEFI Secure Boot",
        "group": GROUP_BASELINE,
        "confidence": "High",
        "transport": "Standard Redfish",
    },
    "C54": {
        "id": "C54",
        "title": "Secure Boot Policy & Mode",
        "group": GROUP_CONDITIONAL,
        "confidence": "Medium",
        "transport": "Standard Redfish",
    },
    "C55": {
        "id": "C55",
        "title": "LCD / Control-Panel Restriction",
        "group": GROUP_CONDITIONAL,
        "confidence": "Low",
        "transport": "Vendor Tool",
    },
    "C56": {
        "id": "C56",
        "title": "BIOS Live Scanning",
        "group": GROUP_DELL_RUNBOOK,
        "confidence": "Low",
        "transport": "Vendor Tool",
    },
    "C57": {
        "id": "C57",
        "title": "Secure Imports & Exports",
        "group": GROUP_DELL_RUNBOOK,
        "confidence": "Medium",
        "transport": "Dell OEM Redfish",
    },
    "C58": {
        "id": "C58",
        "title": "Outbound HTTPS & Proxy Validation",
        "group": GROUP_DELL_RUNBOOK,
        "confidence": "Medium",
        "transport": "Dell OEM Redfish",
    },
    "C59": {
        "id": "C59",
        "title": "Field Service Debug (FSD)",
        "group": GROUP_DELL_RUNBOOK,
        "confidence": "High",
        "transport": "External Process",
    },
    # -------------------------------------------------------------------------
    # Operational Recommendations (O01-O16)
    # -------------------------------------------------------------------------
    "O01": {
        "id": "O01",
        "title": "Isolated Management Network",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "External Process",
    },
    "O02": {
        "id": "O02",
        "title": "Firmware Currency",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "Standard Redfish",
    },
    "O03": {
        "id": "O03",
        "title": "Signed Update & Rollback",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "Standard Redfish",
    },
    "O04": {
        "id": "O04",
        "title": "Certificate Lifecycle",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "Vendor Tool",
    },
    "O05": {
        "id": "O05",
        "title": "FIPS Change Control",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "Dell OEM Redfish",
    },
    "O06": {
        "id": "O06",
        "title": "Credential & Passcode Rotation",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "Vendor Tool",
    },
    "O07": {
        "id": "O07",
        "title": "Account & Privilege Review",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "Standard Redfish",
    },
    "O08": {
        "id": "O08",
        "title": "Auto Config Credential Containment",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "External Process",
    },
    "O09": {
        "id": "O09",
        "title": "Java Console Verification",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "External Process",
    },
    "O10": {
        "id": "O10",
        "title": "SEKM Lifecycle Governance",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "Vendor Tool",
    },
    "O11": {
        "id": "O11",
        "title": "Secure Boot Certificate Governance",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "Vendor Tool",
    },
    "O12": {
        "id": "O12",
        "title": "Secure Disposal & Repurposing",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "Dell OEM Redfish",
    },
    "O13": {
        "id": "O13",
        "title": "Security-Event Monitoring",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "Standard Redfish",
    },
    "O14": {
        "id": "O14",
        "title": "Vulnerability Scanning Disposition",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "External Process",
    },
    "O15": {
        "id": "O15",
        "title": "Superroot Governance",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "External Process",
    },
    "O16": {
        "id": "O16",
        "title": "Applicability & Exception Review",
        "group": GROUP_OPERATIONAL,
        "confidence": "Varies",
        "transport": "External Process",
    },
    # -------------------------------------------------------------------------
    # Hardware & Platform Assurance Capabilities (I01-I09)
    # -------------------------------------------------------------------------
    "I01": {
        "id": "I01",
        "title": "Silicon Root of Trust",
        "group": GROUP_ASSURANCE,
        "confidence": "Varies",
        "transport": "Vendor Tool",
    },
    "I02": {
        "id": "I02",
        "title": "Cryptographically Verified Trusted Boot",
        "group": GROUP_ASSURANCE,
        "confidence": "Varies",
        "transport": "Standard Redfish",
    },
    "I03": {
        "id": "I03",
        "title": "SELinux inside BMC",
        "group": GROUP_ASSURANCE,
        "confidence": "Varies",
        "transport": "External Process",
    },
    "I04": {
        "id": "I04",
        "title": "Signed Firmware Enforcement",
        "group": GROUP_ASSURANCE,
        "confidence": "Varies",
        "transport": "Standard Redfish",
    },
    "I05": {
        "id": "I05",
        "title": "Non-Root Internal Services",
        "group": GROUP_ASSURANCE,
        "confidence": "Varies",
        "transport": "External Process",
    },
    "I06": {
        "id": "I06",
        "title": "BMC Credential Vault",
        "group": GROUP_ASSURANCE,
        "confidence": "Varies",
        "transport": "External Process",
    },
    "I07": {
        "id": "I07",
        "title": "BIOS Recovery & Hardware RoT",
        "group": GROUP_ASSURANCE,
        "confidence": "Varies",
        "transport": "Dell OEM Redfish",
    },
    "I08": {
        "id": "I08",
        "title": "Built-In SNMP Safeguards",
        "group": GROUP_ASSURANCE,
        "confidence": "Varies",
        "transport": "Vendor Tool",
    },
    "I09": {
        "id": "I09",
        "title": "Lifecycle Security Auditing",
        "group": GROUP_ASSURANCE,
        "confidence": "Varies",
        "transport": "Standard Redfish",
    },
}


def get_control_metadata(control_id: str) -> Dict[str, str]:
    """Retrieve metadata for a control ID, falling back to clean defaults if unknown."""
    if control_id in CONTROL_CATALOG:
        return CONTROL_CATALOG[control_id]
    return {
        "id": control_id,
        "title": f"Control {control_id}",
        "group": GROUP_BASELINE,
        "confidence": "Medium",
        "transport": "Standard Redfish",
    }


def get_control_title(control_id: str) -> str:
    """Return the display title for a control ID."""
    return get_control_metadata(control_id).get("title", control_id)


def get_control_group(control_id: str) -> str:
    """Return the architectural group identifier for a control ID."""
    return get_control_metadata(control_id).get("group", GROUP_BASELINE)


def get_control_confidence(control_id: str) -> str:
    """Return the confidence level for a control ID."""
    return get_control_metadata(control_id).get("confidence", "Medium")


def get_control_transport(control_id: str) -> str:
    """Return the primary audit transport for a control ID."""
    return get_control_metadata(control_id).get("transport", "Standard Redfish")
