"""
VCF Readiness Tool — shared constants and lookup tables.

All data-only: URL templates, compatibility lookup tables, hardware databases.
No imports beyond Python stdlib re and Optional.
"""
import re
from typing import Optional

TOOL_VERSION = "9.8.3"

# Combined HTML tabbed report iframe srcdoc embedding cap
COMBINED_HTML_MAX_HOSTS = 4096
COMBINED_HTML_DEFAULT_MAX_HOSTS = 64
# Gzip uncompressed fleet JSON summary when payload exceeds 1 MiB
FLEET_JSON_GZIP_MIN_BYTES = 1_048_576
# Split fleet JSON summary into chunks when host count exceeds 100
FLEET_JSON_CHUNK_HOSTS = 100
# Split fleet JSON summary into chunks when uncompressed size exceeds 8 MiB
FLEET_JSON_CHUNK_MAX_BYTES = 8_388_608
LIVE_VSAN_HCL_JSON_URL = "https://vvs.broadcom.com/service/vsan/all.json.gz"
BROADCOM_KB_428874_URL = "https://knowledge.broadcom.com/external/article/428874"
BCG_BASE_URL = "https://compatibilityguide.broadcom.com/search?persona=live"
BCG_CASCADE_LAKE_SERVER_QUERY = (
    "https://compatibilityguide.broadcom.com/search?program=server&persona=live"
    "&column=partnerName&order=asc"
    "&productReleaseVersion=%5BESXi+9.0%7C%7CESXi+9.1%5D"
    "&partnerName=%5BHPE%7C%7CDell%7C%7CLenovo%7C%7CCisco%7C%7CFujitsu%5D"
    "&cpuSeries=%5BIntel+Xeon+Gold+6200%2F5200+%28Cascade-Lake-SP%2FRefresh%29+Series"
    "%7C%7CIntel+Xeon+Platinum+8200+%28Cascade-Lake-SP%2FRefresh%29+Series"
    "%7C%7CIntel+Xeon+Silver+4200%2C+Bronze+3200+%28Cascade-Lake-SP%2FRefresh%29+Series%5D"
    "&activePage=1&activeDelta=20"
)

# Major Tier-1 OEM server families confirmed on Broadcom Compatibility Guide (BCG)
# for Skylake-SP / Cascade-Lake-SP on ESXi 9.0 / 9.1
BCG_OEM_CERTIFIED_SERVERS = {
    "HPE": [r"DL3[68]0\s*GEN10", r"DL5[68]0\s*GEN10", r"SYNERGY\s*480\s*GEN10", r"APOLLO", r"BL460C\s*GEN10", r"DX3[68]0\s*GEN10"],
    "HEWLETT": [r"DL3[68]0\s*GEN10", r"DL5[68]0\s*GEN10", r"SYNERGY\s*480\s*GEN10", r"APOLLO", r"BL460C\s*GEN10", r"DX3[68]0\s*GEN10"],
    "CISCO": [r"UCS[C]?[-_\s]*[CB]?[248]\d0[-_\s]*M5", r"UCS[C]?[-_\s]*S3260[-_\s]*M5", r"HX(?:AF)?[24]\d0C[-_\s]*M5"],
    "DELL": [r"POWEREDGE\s*R[6789]40", r"POWEREDGE\s*C6420", r"POWEREDGE\s*MX[78]40C", r"POWEREDGE\s*[RT][456]40", r"XC[67]40"],
    "LENOVO": [r"THINKSYSTEM\s*SR[689][3560]0", r"THINKSYSTEM\s*S[DN]530", r"THINKSYSTEM\s*S[NT]550", r"THINKAGILE\s*HX[1357]320"],
    "SUPERMICRO": [r"SYS-[12567]\d{2}9", r"SYS-E300", r"AS-[24]\d{3}"],
    "FUJITSU": [r"PRIMERGY\s*RX25[34]0\s*M5", r"PRIMERGY\s*CX25[567]0\s*M5"],
    "HITACHI": [r"HA8000V/DL3[68]0\s*GEN10"],
}
BCG_SEARCH_SSD_TEMPLATE = (
    "https://compatibilityguide.broadcom.com/search?program=ssd&persona=live"
    "&keyword={model}&supportedReleases=%5BESXi+9.1+%28vSAN+9.1%29%7C%7CESXi+9.0+%28vSAN++9.0%29%5D"
)
MTAT_GITHUB_URL = "https://github.com/VMware/MTAT"

# ---------------------------------------------------------------------------
# VCF Management Domain Sizing & Headroom Reference
# Sources:
# - Broadcom TechDocs: Planning and Preparation for VMware Cloud Foundation 9.1
# - Broadcom TechDocs: VCF Fleet Sizing Models (Simple, HA - Medium, HA - Large)
# ---------------------------------------------------------------------------
VCF_PLANNING_WORKBOOK_URL = (
    "https://techdocs.broadcom.com/us/en/vmware-cis/vcf/vcf-9-0-and-later/9-1/planning-and-preparatio-0.html"
)
VCF_SIZER_URL = "https://vcf.broadcom.com/tools/vsansizer/home"
VCF_CONFIG_MAX_URL = "https://configmax.broadcom.com/"

VCF_MANAGEMENT_PROFILES = [
    {
        "id": "mvp",
        "name": "Core MVP (Minimal Bring-Up)",
        "short_name": "Core MVP",
        "vcpu": 14,
        "ram": 61,
        "nvme": 2.0,
        "min_hosts": 4,
        "desc": "SDDC Manager (4 vCPU / 16 GB) + vCenter Small (4 vCPU / 21 GB) + NSX Manager 1× Medium (6 vCPU / 24 GB)",
    },
    {
        "id": "simple",
        "name": "Simple Non-HA (VCF 9.1 Fleet Model)",
        "short_name": "Simple Non-HA",
        "vcpu": 42,
        "ram": 128,
        "nvme": 2.5,
        "min_hosts": 4,
        "desc": "VCF Management Services (1× CP + 2× Workers) + SDDC Mgr + vCenter Small + NSX Medium",
    },
    {
        "id": "ha_medium",
        "name": "HA - Medium (Standard Production)",
        "short_name": "HA - Medium",
        "vcpu": 98,
        "ram": 308,
        "nvme": 5.0,
        "min_hosts": 4,
        "desc": "3× NSX Manager Medium HA + VCF Operations Medium HA + vCenter Medium + SDDC Mgr",
    },
    {
        "id": "ha_large",
        "name": "HA - Large (Enterprise Multi-Cluster)",
        "short_name": "HA - Large",
        "vcpu": 188,
        "ram": 630,
        "nvme": 9.0,
        "min_hosts": 4,
        "desc": "3× NSX Manager Large HA + 3× Operations Large HA + 3× Automation Large HA + vCenter Large + SDDC Mgr",
    },
]

# ---------------------------------------------------------------------------
# Dell TechDirect API — warranty and component inventory (OAuth2 client creds)
# Register at https://techdirect.dell.com to obtain client_id / client_secret.
# ---------------------------------------------------------------------------
DELL_TECHDIRECT_OAUTH_URL      = "https://apigtwb2c.us.dell.com/auth/oauth/v2/token"
DELL_TECHDIRECT_WARRANTY_URL   = "https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlements"
DELL_TECHDIRECT_COMPONENTS_URL = "https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-components"
DELL_TECHDIRECT_HEADER_URL     = "https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-header"
DELL_TECHDIRECT_REGISTER_URL   = "https://techdirect.dell.com/portal/AboutAPIs.aspx"
VCF_OPS_DEMO_URL = "https://youtu.be/cyyIEU4yyKg?si=wUDY_vZC0mMXY7ZB&t=1451"
KB_TRIMODE = "https://knowledge.broadcom.com/external/article/314305/vsan-support-of-nvme-devices-behind-trim.html"
ESXI_KB_URL = "https://knowledge.broadcom.com/external/article/316595/build-numbers-and-versions-of-vmware-esx.html"

# ---------------------------------------------------------------------------
# ESXi build-number → version label + lifecycle status lookup table
# ---------------------------------------------------------------------------
# Source: Broadcom KB 316595 (ESXI_KB_URL above).
# Keys are the numeric build strings reported by BMCs in SoftwareInventory or
# the Oem.*.HostOS.OsVersion field.  Values: (update_label, lifecycle).
# lifecycle: "Current" | "Upgrade Available" | "EOL — <date>"
ESXI_BUILD_TABLE: dict = {
    # ── ESXi 6.5 ────────────────────────────────────────────────────────────
    "4564106":  ("ESXi 6.5 GA",       "EOL — Oct 2022"),
    "5224529":  ("ESXi 6.5a",         "EOL — Oct 2022"),
    "5969303":  ("ESXi 6.5 U1",       "EOL — Oct 2022"),
    "7388607":  ("ESXi 6.5 U2",       "EOL — Oct 2022"),
    "10884925": ("ESXi 6.5 U2g",      "EOL — Oct 2022"),
    "13004448": ("ESXi 6.5 U3",       "EOL — Oct 2022"),
    "14990892": ("ESXi 6.5 U3b",      "EOL — Oct 2022"),
    "15256549": ("ESXi 6.5 U3d",      "EOL — Oct 2022"),
    "17477841": ("ESXi 6.5 U3n",      "EOL — Oct 2022"),
    "20502893": ("ESXi 6.5 P08",      "EOL — Oct 2022"),
    # ── ESXi 6.7 ────────────────────────────────────────────────────────────
    "8169922":  ("ESXi 6.7 GA",       "EOL — Nov 2022"),
    "9214924":  ("ESXi 6.7 U1",       "EOL — Nov 2022"),
    "11675023": ("ESXi 6.7 U2",       "EOL — Nov 2022"),
    "13006603": ("ESXi 6.7 U3",       "EOL — Nov 2022"),
    "15160138": ("ESXi 6.7 U3a",      "EOL — Nov 2022"),
    "15820472": ("ESXi 6.7 U3b",      "EOL — Nov 2022"),
    "16316930": ("ESXi 6.7 U3f",      "EOL — Nov 2022"),
    "17700523": ("ESXi 6.7 U3n",      "EOL — Nov 2022"),
    "19195723": ("ESXi 6.7 EP20",     "EOL — Nov 2022"),
    "20497097": ("ESXi 6.7 P08",      "EOL — Nov 2022"),
    "21836395": ("ESXi 6.7 EP22",     "EOL — Nov 2022"),
    # ── ESXi 7.0 ────────────────────────────────────────────────────────────
    "15843807": ("ESXi 7.0 GA",       "EOL — Apr 2025"),
    "16324942": ("ESXi 7.0b",         "EOL — Apr 2025"),
    "16850804": ("ESXi 7.0 U1",       "EOL — Apr 2025"),
    "17119627": ("ESXi 7.0 U1a",      "EOL — Apr 2025"),
    "17325551": ("ESXi 7.0 U1c",      "EOL — Apr 2025"),
    "17551050": ("ESXi 7.0 U1d",      "EOL — Apr 2025"),
    "17630552": ("ESXi 7.0 U2",       "EOL — Apr 2025"),
    "17867351": ("ESXi 7.0 U2a",      "EOL — Apr 2025"),
    "18426014": ("ESXi 7.0 U2a",      "EOL — Apr 2025"),
    "18538813": ("ESXi 7.0 U2c",      "EOL — Apr 2025"),
    "18905247": ("ESXi 7.0 U2d",      "EOL — Apr 2025"),
    "19193900": ("ESXi 7.0 U3",       "EOL — Apr 2025"),
    "19290878": ("ESXi 7.0 U3a",      "EOL — Apr 2025"),
    "19482537": ("ESXi 7.0 U3c",      "EOL — Apr 2025"),
    "19898904": ("ESXi 7.0 U3d",      "EOL — Apr 2025"),
    "20036589": ("ESXi 7.0 U3e",      "EOL — Apr 2025"),
    "20328353": ("ESXi 7.0 U3f",      "EOL — Apr 2025"),
    "20842708": ("ESXi 7.0 U3g",      "EOL — Apr 2025"),
    "21313628": ("ESXi 7.0 U3j",      "EOL — Apr 2025"),
    "21424296": ("ESXi 7.0 U3k",      "EOL — Apr 2025"),
    "21686933": ("ESXi 7.0 U3l",      "EOL — Apr 2025"),
    "22348816": ("ESXi 7.0 U3m",      "EOL — Apr 2025"),
    "23307199": ("ESXi 7.0 U3o",      "EOL — Apr 2025"),
    "23794027": ("ESXi 7.0 U3p",      "EOL — Apr 2025"),
    "24585291": ("ESXi 7.0 U3s",      "EOL — Apr 2025"),
    # ── ESXi 8.0 ────────────────────────────────────────────────────────────
    "20513097": ("ESXi 8.0 GA",       "Upgrade Available"),
    "21203435": ("ESXi 8.0 U1",       "Upgrade Available"),
    "21495797": ("ESXi 8.0 U1a",      "Upgrade Available"),
    "21813344": ("ESXi 8.0 U1b",      "Upgrade Available"),
    "22088125": ("ESXi 8.0 U1c",      "Upgrade Available"),
    "22380479": ("ESXi 8.0 U2",       "Upgrade Available"),
    "22481200": ("ESXi 8.0 U2a",      "Upgrade Available"),
    "23305546": ("ESXi 8.0 U2b",      "Upgrade Available"),
    "23516665": ("ESXi 8.0 U2c",      "Upgrade Available"),
    "23825572": ("ESXi 8.0 U2d",      "Upgrade Available"),
    "24022510": ("ESXi 8.0 U3",       "Upgrade Available"),
    "24280767": ("ESXi 8.0 U3a",      "Upgrade Available"),
    "24585383": ("ESXi 8.0 U3b",      "Upgrade Available"),
    "24674464": ("ESXi 8.0 U3c",      "Upgrade Available"),
    "25213978": ("ESXi 8.0 U3d",      "Upgrade Available"),
    "25447217": ("ESXi 8.0 U3e",      "Upgrade Available"),
    # ── ESXi 9.0 ────────────────────────────────────────────────────────────
    "24414501": ("ESXi 9.0 GA",       "Upgrade Available"),
    # ── ESXi 9.1 ────────────────────────────────────────────────────────────
    "25974101": ("ESXi 9.1 GA",       "Current"),
    "26123456": ("ESXi 9.1a",         "Current"),
}

# ---------------------------------------------------------------------------
# OS end-of-life / lifecycle classification table
# ---------------------------------------------------------------------------
# Each entry: (regex_pattern, eol_label, badge_class)
# Patterns are matched case-insensitively against the full "os_name os_version" string.
# First match wins.
OS_EOL_TABLE: list = [
    # ESXi — ordered newest-first so partial matches on major don't shadow minor
    (r"ESXi\s+9\.",        "Current",          "success"),
    (r"ESXi\s+8\.",        "Upgrade Available","warning"),
    (r"ESXi\s+7\.",        "EOL — Apr 2025",   "danger"),
    (r"ESXi\s+6\.",        "EOL — Oct 2022",   "danger"),
    (r"VMware ESXi",       "Check Version",    "warning"),
    # Windows Server
    (r"Windows Server 2025",                         "Current",        "success"),
    (r"Windows Server 2022",                         "Current",        "success"),
    (r"Windows Server 2019",                         "Current",        "success"),
    (r"Windows Server 2016",                         "Current",        "success"),
    (r"Windows Server 2012",                         "EOL — Oct 2023", "danger"),
    (r"Windows Server 2008",                         "EOL — Jan 2020", "danger"),
    # RHEL / CentOS
    (r"Red Hat.*\s9\.|RHEL\s*9",                     "Current",        "success"),
    (r"Red Hat.*\s8\.|RHEL\s*8",                     "Current",        "success"),
    (r"Red Hat.*\s7\.|RHEL\s*7|CentOS\s*7",          "EOL — Jun 2024", "danger"),
    (r"Red Hat.*\s6\.|RHEL\s*6|CentOS\s*6",          "EOL — Nov 2020", "danger"),
    # Ubuntu LTS
    (r"Ubuntu\s+24\.",                               "Current",        "success"),
    (r"Ubuntu\s+22\.",                               "Current",        "success"),
    (r"Ubuntu\s+20\.",                               "EOL — Apr 2025", "warning"),
    (r"Ubuntu\s+18\.",                               "EOL — Apr 2023", "danger"),
    (r"Ubuntu\s+16\.",                               "EOL — Apr 2021", "danger"),
    # SUSE
    (r"SUSE.*15",                                    "Current",        "success"),
    (r"SUSE.*12",                                    "EOL — Oct 2024", "warning"),
]

GENERIC_NAME_BLOCKLIST = [
    "network adapter view", "network adapter", "adapter", "unknown",
    "pcie device", "ethernet controller", "device", "none", "n/a",
    "system ethernet interface",   # Dell iDRAC BMC virtual port — not a real data NIC
    "unknown network adapter",
    "ethernet network adapter",    # HPE iLO generic PCIe NIC name — fall through to Model
    "poweredge rx5xx lom board",   # Dell generic LOM board description
]

# ---------------------------------------------------------------------------
# HPE ProLiant SKU → Chassis configuration database
# ---------------------------------------------------------------------------
# Maps HPE order-number (SKU / ProductId) → (front_bays, chassis_label).
# front_bays = number of physical drive bays in the standard front backplane;
# does NOT include optional rear-drive or Universal Media Bay add-ons.
# Used as the highest-priority source for synthetic empty-bay generation when
# iLO's DriveBayCount only reports the SAS/SATA segment of a split backplane.
#
# Source: HPE QuickSpecs for each server family (public, Jul 2026).
# Add entries as new SKUs are encountered in the field.
HPE_SKU_CHASSIS_DB = {
    # ── DL360 Gen10 (1U · Skylake-SP / Cascade Lake-SP) ────────────────────
    "867958-B21": (4,  "DL360 Gen10 · 4 LFF"),
    "875965-B21": (4,  "DL360 Gen10 · 4 LFF (TAA)"),
    "867959-B21": (8,  "DL360 Gen10 · 8 SFF"),
    "875966-B21": (8,  "DL360 Gen10 · 8 SFF (TAA)"),
    "867960-B21": (10, "DL360 Gen10 · 10 SFF Premium NVMe"),
    "875967-B21": (10, "DL360 Gen10 · 10 SFF Premium NVMe (TAA)"),
    # ── DL360 Gen10 updated CTO (Cascade Lake refresh, P1xxxx) ─────────────
    "P19765-B21": (4,  "DL360 Gen10 · 4 LFF NC"),
    "P19768-B21": (4,  "DL360 Gen10 · 4 LFF NC (TAA)"),
    "P19766-B21": (8,  "DL360 Gen10 · 8 SFF NC"),
    "P19769-B21": (8,  "DL360 Gen10 · 8 SFF NC (TAA)"),
    "P36394-B21": (8,  "DL360 Gen10 · 8 SFF BC (Trusted Supply Chain)"),
    "P56949-B21": (8,  "DL360 Gen10 · 8 SFF BC NC"),
    # ── DL360 Gen10 Plus (1U · Ice Lake / Sapphire Rapids, P28xxx) ─────────
    "P28947-B21": (4,  "DL360 Gen10 Plus · 4 LFF NC"),
    "P28948-B21": (8,  "DL360 Gen10 Plus · 8 SFF NC"),
    "P28950-B21": (8,  "DL360 Gen10 Plus · 8 SFF NC (TAA)"),
    # ── DL380 Gen10 (2U · Skylake-SP / Cascade Lake-SP, 826xxx/868xxx) ─────
    "826564-B21": (8,  "DL380 Gen10 · 8 SFF Entry"),
    "868709-B21": (8,  "DL380 Gen10 · 8 SFF CTO"),
    "868710-B21": (8,  "DL380 Gen10 · 8 LFF CTO"),
    "868704-B21": (24, "DL380 Gen10 · 24 SFF CTO"),
    "868706-B21": (12, "DL380 Gen10 · 12 LFF CTO"),
    # ── DL380 Gen10 Plus (2U · Ice Lake / Sapphire Rapids, P05xxx) ─────────
    "P05171-B21": (8,  "DL380 Gen10 Plus · 8 SFF NC"),
    "P05172-B21": (24, "DL380 Gen10 Plus · 24 SFF NC"),
    "P05173-B21": (12, "DL380 Gen10 Plus · 12 LFF NC"),
    "P24740-B21": (8,  "DL380 Gen10 Plus · 8 SFF NC"),
    "P43357-B21": (8,  "DL380 Gen10 Plus · 8 SFF"),
    # ── DL325 Gen10 Plus (1U · AMD EPYC) ────────────────────────────────────
    "P21440-B21": (8,  "DL325 Gen10 Plus · 8 SFF NC"),
    "P38477-B21": (8,  "DL325 Gen10 Plus v2 · 8 SFF NC"),
    # ── DL345 Gen10 Plus (2U · AMD EPYC) ────────────────────────────────────
    "P39366-B21": (8,  "DL345 Gen10 Plus · 8 SFF NC"),
    "P39367-B21": (24, "DL345 Gen10 Plus · 24 SFF NC"),
}

# ---------------------------------------------------------------------------
# Maps Dell order SKU (e.g. 321-BCQQ) → (front_bays, chassis_label).
# ---------------------------------------------------------------------------
DELL_SKU_CHASSIS_DB = {
    # ── PowerEdge R640 (10x2.5" / 8x2.5" / 4x3.5") ───────────────────────────
    "321-BCQQ": (10, "PowerEdge R640 2.5\" Chassis · 10 SFF (up to 8 NVMe)"),
    "321-BCQR": (10, "PowerEdge R640 2.5\" Chassis · 10 SFF Direct NVMe"),
    "321-BCQS": (8,  "PowerEdge R640 2.5\" Chassis · 8 SFF SAS/SATA"),
    "321-BCQT": (4,  "PowerEdge R640 3.5\" Chassis · 4 LFF SAS/SATA"),
    "321-BCQU": (10, "PowerEdge R640 2.5\" Chassis · 10 SFF SAS/SATA/NVMe"),
    # ── PowerEdge R740 / R740xd ─────────────────────────────────────────────
    "321-BCQV": (16, "PowerEdge R740 2.5\" Chassis · 16 SFF SAS/SATA"),
    "321-BCQW": (24, "PowerEdge R740xd 2.5\" Chassis · 24 SFF SAS/SATA/NVMe"),
    "321-BCQX": (12, "PowerEdge R740xd 3.5\" Chassis · 12 LFF SAS/SATA"),
    # ── PowerEdge R650 / R660 ───────────────────────────────────────────────
    "321-BGXG": (10, "PowerEdge R650 2.5\" Chassis · 10 SFF (up to 8 NVMe)"),
    "321-BHXF": (10, "PowerEdge R660 2.5\" Chassis · 10 SFF (up to 8 NVMe)"),
    "321-BHXG": (16, "PowerEdge R660 2.5\" Chassis · 16 EDSFF E3.S NVMe"),
}

# ---------------------------------------------------------------------------
# Multi-vendor model-name → chassis configuration database
# ---------------------------------------------------------------------------
# Keyed by the normalized model suffix (uppercase, vendor prefix stripped,
# variant suffix like "-10"/"-24" removed).  Matches System.Model returned by
# iDRAC / iLO / IMC Redfish.
#
# Vendor prefixes stripped before lookup:
#   "PowerEdge " (Dell)  |  "ProLiant " (HPE)  |  nothing (Cisco / VxRail / XC)
#
# (max_front_bays, chassis_label)
# max_front_bays = largest possible front-bay count for this chassis family.
# Dell iDRAC reliably reports DellEnclosure.SlotCount so this DB is used
# primarily for display labels and as a fallback when SlotCount is missing.
#
# Source: Dell/HPE/Cisco Technical Guides (public, Jul 2026).
DELL_MODEL_CHASSIS_DB = {
    # ── 14th Gen Intel (Skylake-SP / Cascade Lake-SP) ───────────────────────
    "R640":    (10, "PowerEdge R640 · 14G 1U"),
    "R740":    (16, "PowerEdge R740 · 14G 2U"),
    "R740XD":  (24, "PowerEdge R740xd · 14G 2U"),
    "R740XD2": (24, "PowerEdge R740xd2 · 14G 2U"),
    "R840":    (16, "PowerEdge R840 · 14G 2U 4-socket"),
    "R940":    (24, "PowerEdge R940 · 14G 4U"),
    "R940XA":  (12, "PowerEdge R940xa · 14G 4U GPU"),
    # ── 14th Gen AMD (EPYC Naples) ───────────────────────────────────────────
    "R7425":   (24, "PowerEdge R7425 · 14G 2U AMD EPYC"),
    # ── 15th Gen Intel (Ice Lake Xeon Scalable) ──────────────────────────────
    "R650":    (10, "PowerEdge R650 · 15G 1U"),
    "R650XS":  (10, "PowerEdge R650xs · 15G 1U Single-socket"),
    "R750":    (24, "PowerEdge R750 · 15G 2U"),
    "R750XA":  (8,  "PowerEdge R750xa · 15G 2U GPU"),
    "R750XS":  (16, "PowerEdge R750xs · 15G 2U"),
    # ── 15th Gen AMD (EPYC Rome / Milan) ─────────────────────────────────────
    "R7515":   (24, "PowerEdge R7515 · 15G 2U Single-socket AMD EPYC"),
    "R7525":   (24, "PowerEdge R7525 · 15G 2U AMD EPYC"),
    # ── 16th Gen Intel (Sapphire Rapids Xeon Scalable) ───────────────────────
    "R660":    (10, "PowerEdge R660 · 16G 1U"),
    "R660XS":  (10, "PowerEdge R660xs · 16G 1U Single-socket"),
    "R760":    (24, "PowerEdge R760 · 16G 2U"),
    "R760XA":  (8,  "PowerEdge R760xa · 16G 2U GPU"),
    "R760XD2": (24, "PowerEdge R760xd2 · 16G 2U Dense"),
    # ── 16th Gen AMD (EPYC Genoa) ────────────────────────────────────────────
    "R7615":   (24, "PowerEdge R7615 · 16G 2U Single-socket AMD EPYC"),
    "R7625":   (24, "PowerEdge R7625 · 16G 2U AMD EPYC"),
    # ── 17th Gen Intel (Granite Rapids / Xeon 6) ─────────────────────────────
    "R670":    (10, "PowerEdge R670 · 17G 1U"),
    "R770":    (24, "PowerEdge R770 · 17G 2U"),
    # ── 17th Gen AMD (EPYC Turin) ────────────────────────────────────────────
    "R7715":   (24, "PowerEdge R7715 · 17G 2U Single-socket AMD EPYC"),
    "R7725":   (24, "PowerEdge R7725 · 17G 2U AMD EPYC"),
    # ── Dell XC / XC Plus (HCI appliances, iDRAC model = "XCxxx") ─────────────
    "XC640":   (10, "Dell XC640 · HCI Appliance (14G)"),
    "XC740XD": (24, "Dell XC740xd · HCI Appliance (14G)"),
    "XC6420":  (6,  "Dell XC6420 · HCI Appliance (14G)"),
    "XC6520":  (10, "Dell XC6520 · HCI Appliance (15G)"),
    "XC660XS": (4,  "Dell XC660xs · HCI Appliance XC Plus (16G)"),
    "XC660":   (10, "Dell XC660 · HCI Appliance XC Plus (16G)"),
    "XC760":   (24, "Dell XC760 · HCI Appliance XC Plus (16G)"),
    "XC760XA": (6,  "Dell XC760xa · HCI Appliance XC Plus GPU (16G)"),
    "XC7625":  (24, "Dell XC7625 · HCI Appliance XC Plus AMD (16G)"),
    "XC4000":  (8,  "Dell XC4000 · HCI Appliance XC Plus Edge"),
    # ── Dell VxRail (iDRAC model = "VxRail Exxx/Pxxx/…") ─────────────────────
    # Drive bay counts mirror the underlying PowerEdge platform.
    "VXRAIL E460": (10, "Dell VxRail E460 · 14G 1U · 10 SFF"),
    "VXRAIL E560": (10, "Dell VxRail E560 · 15G 1U · 10 SFF"),
    "VXRAIL E560F":(10, "Dell VxRail E560F · 15G 1U NVMe · 10 SFF"),
    "VXRAIL E560N":(10, "Dell VxRail E560N · 15G 1U NVMe · 10 SFF"),
    "VXRAIL E660": (10, "Dell VxRail E660 · 16G 1U · 10 SFF"),
    "VXRAIL E660F":(10, "Dell VxRail E660F · 16G 1U NVMe · 10 SFF"),
    "VXRAIL E665": (10, "Dell VxRail E665 · 16G 1U AMD · 10 SFF"),
    "VXRAIL P470": (16, "Dell VxRail P470 · 14G 2U · 16 SFF"),
    "VXRAIL P570": (16, "Dell VxRail P570 · 15G 2U · 16 SFF"),
    "VXRAIL P570F":(16, "Dell VxRail P570F · 15G 2U NVMe · 16 SFF"),
    "VXRAIL P670F":(16, "Dell VxRail P670F · 16G 2U NVMe · 16 SFF"),
    "VXRAIL P675F":(16, "Dell VxRail P675F · 16G 2U AMD NVMe · 16 SFF"),
    "VXRAIL S470": (16, "Dell VxRail S470 · 14G 2U Storage · 16 SFF"),
    "VXRAIL S570": (16, "Dell VxRail S570 · 15G 2U Storage · 16 SFF"),
    "VXRAIL S670": (16, "Dell VxRail S670 · 16G 2U Storage · 16 SFF"),
    "VXRAIL V470": (16, "Dell VxRail V470 · 14G 2U vSAN · 16 SFF"),
    "VXRAIL V570": (16, "Dell VxRail V570 · 15G 2U vSAN · 16 SFF"),
    "VXRAIL V570F":(16, "Dell VxRail V570F · 15G 2U vSAN NVMe · 16 SFF"),
    "VXRAIL V670F":(16, "Dell VxRail V670F · 16G 2U vSAN NVMe · 16 SFF"),
    "VXRAIL D560": (24, "Dell VxRail D560 · 15G 2U Dense · 24 SFF"),
    "VXRAIL D560F":(24, "Dell VxRail D560F · 15G 2U Dense NVMe · 24 SFF"),
    "VXRAIL G560": (10, "Dell VxRail G560 · 15G 1U GPU · 10 SFF"),
    "VXRAIL G560F":(10, "Dell VxRail G560F · 15G 1U GPU NVMe · 10 SFF"),
    "VXRAIL VP-760":(24, "Dell VxRail VP-760 · 16G 2U vSAN Plus · 24 SFF"),
    "VXRAIL VP-7625":(24,"Dell VxRail VP-7625 · 16G 2U AMD vSAN Plus · 24 SFF"),
    # ── HPE ProLiant DX series (HCI appliance, iLO model = "ProLiant DX…") ────
    # ProLiant prefix is stripped before lookup, so keys are "DX360 GEN10" etc.
    "DX360 GEN10":        (10, "HPE ProLiant DX360 Gen10 · HCI Appliance · 10 SFF"),
    "DX380 GEN10":        (8,  "HPE ProLiant DX380 Gen10 · HCI Appliance · 8 SFF"),
    "DX380 GEN10 24SFF":  (24, "HPE ProLiant DX380 Gen10 · HCI Appliance · 24 SFF"),
    "DX380 GEN10 12LFF":  (12, "HPE ProLiant DX380 Gen10 · HCI Appliance · 12 LFF"),
    "DX385 GEN10 PLUS":   (24, "HPE ProLiant DX385 Gen10 Plus · HCI Appliance AMD · 24 SFF"),
    "DX360 GEN12":        (10, "HPE ProLiant DX360 Gen12 · HCI Appliance · 10 NVMe"),
    "DX380 GEN12":        (24, "HPE ProLiant DX380 Gen12 · HCI Appliance · 24 NVMe / 12 LFF"),
    # ── HPE SimpliVity OmniStack (iLO model = "SimpliVity 380 Gen10" etc.) ────
    "SIMPLIVITY 380 GEN9":   (8,  "HPE SimpliVity 380 Gen9 · HCI Appliance · 8 SFF"),
    "SIMPLIVITY 380 GEN10":  (8,  "HPE SimpliVity 380 Gen10 · HCI Appliance · 8 SFF"),
    "SIMPLIVITY 380 GEN10 PLUS": (8, "HPE SimpliVity 380 Gen10 Plus · HCI Appliance · 8 SFF"),
    "SIMPLIVITY 325 GEN10 PLUS": (8, "HPE SimpliVity 325 Gen10 Plus · HCI Appliance AMD · 8 SFF"),
    # ── Cisco HyperFlex (IMC model = "HXAF220C-M5SX" etc., no prefix to strip) ─
    "HXAF220C-M5SX":  (10, "Cisco HyperFlex HXAF220c M5 · HCI Appliance · 10 SFF"),
    "HXAF220C-M6SX":  (10, "Cisco HyperFlex HXAF220c M6 · HCI Appliance · 10 SFF"),
    "HX220C-M5SX":    (10, "Cisco HyperFlex HX220c M5 · HCI Appliance · 10 SFF"),
    "HX220C-M6SX":    (10, "Cisco HyperFlex HX220c M6 · HCI Appliance · 10 SFF"),
    "HXAF240C-M5SX":  (24, "Cisco HyperFlex HXAF240c M5 · HCI Appliance · 24 SFF"),
    "HX240C-M5SX":    (24, "Cisco HyperFlex HX240c M5 · HCI Appliance · 24 SFF"),
    "HX480C-M5SX":    (48, "Cisco HyperFlex HX480c M5 · HCI Appliance · 48 SFF"),
}

# Lenovo ThinkSystem chassis definitions
# Mapping model name suffix (after "ThinkSystem " prefix) to bay counts and labels.
# Source: Lenovo Press Product Guides (https://lenovopress.lenovo.com).
LENOVO_MODEL_CHASSIS_DB = {
    "SR630":    {"bays": 10, "form_factor": "1U", "drive_sizes": ["2.5"], "label": "ThinkSystem SR630 · 1U"},
    "SR630 V2": {"bays": 10, "form_factor": "1U", "drive_sizes": ["2.5", "EDSFF"], "label": "ThinkSystem SR630 V2 · 1U"},
    "SR650":    {"bays": 24, "form_factor": "2U", "drive_sizes": ["2.5", "3.5"], "label": "ThinkSystem SR650 · 2U"},
    "SR650 V2": {"bays": 24, "form_factor": "2U", "drive_sizes": ["2.5", "3.5"], "label": "ThinkSystem SR650 V2 · 2U"},
    "SR650 V3": {"bays": 24, "form_factor": "2U", "drive_sizes": ["2.5", "3.5", "EDSFF"], "label": "ThinkSystem SR650 V3 · 2U"},
}

# Substrings that identify HCI appliance / converged-infrastructure OEM hardware.
# These patterns are matched case-insensitively against "{Model} {Vendor}".
# Kept as a flat tuple so iteration is O(n); add new patterns as platforms emerge.
#
# Platform mapping (internal — not shown verbatim in reports):
#   " DX"            HPE OEM appliance (DX360/380/385 — bundled HCI stack)
#   "XC640" …        Dell OEM appliance (XC / XC Plus series)
#   "VXRAIL"         Dell VxRail (VMware-validated HCI)
#   "SIMPLIVITY"     HPE SimpliVity (OmniStack HCI)
#   "OMNISTACK"      HPE SimpliVity legacy name
#   "POWERFLEX"      Dell PowerFlex (software-defined storage appliance)
#   "HXAF", "HX220C" Cisco HyperFlex (UCS-based HCI)
#   "HX240C", "HX480C" Cisco HyperFlex large nodes
HCI_APPLIANCE_PATTERNS = (
    " DX",                                    # HPE: "ProLiant DX…" (space prevents hostname false hits)
    "XC640", "XC740", "XC760", "XC660",       # Dell XC / XC Plus
    "XC7625", "XC4000", "XC6420", "XC6520",
    "VXRAIL",                                 # Dell VxRail
    "SIMPLIVITY", "OMNISTACK",                # HPE SimpliVity
    "POWERFLEX",                              # Dell PowerFlex
    "HXAF", "HX220C", "HX240C", "HX480C",    # Cisco HyperFlex
)

BIOS_BASELINES = {
    # ── Dell 14G Intel (Skylake-SP / Cascade Lake-SP) ─────────────────────────
    # min_spectre per Dell KB 000178106 (Jan–Feb 2018 initial spectre microcode)
    "POWEREDGE R640":   {"latest": "2.24.0", "min_recommended": "2.23.0", "min_spectre": "1.3.7"},
    "POWEREDGE R740":   {"latest": "2.24.0", "min_recommended": "2.23.0", "min_spectre": "1.3.7"},
    "POWEREDGE R740XD": {"latest": "2.24.0", "min_recommended": "2.23.0", "min_spectre": "1.3.7"},
    "POWEREDGE R940":   {"latest": "2.24.0", "min_recommended": "2.23.0", "min_spectre": "1.3.7"},
    "POWEREDGE R440":   {"latest": "2.24.0", "min_recommended": "2.23.0", "min_spectre": "1.3.7"},
    "POWEREDGE R540":   {"latest": "2.24.0", "min_recommended": "2.23.0", "min_spectre": "1.3.7"},
    "POWEREDGE T640":   {"latest": "2.24.0", "min_recommended": "2.23.0", "min_spectre": "1.3.7"},
    "POWEREDGE C6420":  {"latest": "2.24.0", "min_recommended": "2.23.0", "min_spectre": "1.3.7"},
    "POWEREDGE FC640":  {"latest": "2.24.0", "min_recommended": "2.23.0", "min_spectre": "1.3.7"},
    "POWEREDGE M640":   {"latest": "2.24.0", "min_recommended": "2.23.0", "min_spectre": "1.3.7"},
    "POWEREDGE C4140":  {"latest": "2.24.0", "min_recommended": "2.23.0", "min_spectre": "1.1.6"},
    # ── Dell 14G AMD (EPYC Naples) ────────────────────────────────────────────
    "POWEREDGE R7425":  {"latest": "1.21.0", "min_recommended": "1.20.0", "min_spectre": "1.0.9"},
    "POWEREDGE R7415":  {"latest": "1.21.0", "min_recommended": "1.20.0", "min_spectre": "1.0.9"},
    "POWEREDGE R6415":  {"latest": "1.21.0", "min_recommended": "1.20.0", "min_spectre": "1.0.9"},
    # ── Dell 15G (Ice Lake-SP / Sapphire Rapids) — shipped post-spectre era ──
    "POWEREDGE R650":   {"latest": "1.12.0", "min_recommended": "1.11.0", "min_spectre": "1.0.0"},
    "POWEREDGE R750":   {"latest": "1.12.0", "min_recommended": "1.11.0", "min_spectre": "1.0.0"},
    "POWEREDGE R650XS": {"latest": "1.12.0", "min_recommended": "1.11.0", "min_spectre": "1.0.0"},
    "POWEREDGE R750XA": {"latest": "1.12.0", "min_recommended": "1.11.0", "min_spectre": "1.0.0"},
    "POWEREDGE R450":   {"latest": "1.12.0", "min_recommended": "1.11.0", "min_spectre": "1.0.0"},
    "POWEREDGE R550":   {"latest": "1.12.0", "min_recommended": "1.11.0", "min_spectre": "1.0.0"},
    "POWEREDGE R6525":  {"latest": "2.14.0", "min_recommended": "2.13.0", "min_spectre": "2.2.0"},
    "POWEREDGE R7525":  {"latest": "2.14.0", "min_recommended": "2.13.0", "min_spectre": "2.2.0"},
    # ── Dell 16G (Sapphire / Emerald Rapids) — shipped post-spectre era ───────
    "POWEREDGE R660":   {"latest": "1.8.0",  "min_recommended": "1.7.0",  "min_spectre": "1.0.0"},
    "POWEREDGE R760":   {"latest": "1.8.0",  "min_recommended": "1.7.0",  "min_spectre": "1.0.0"},
    "POWEREDGE R660XS": {"latest": "1.8.0",  "min_recommended": "1.7.0",  "min_spectre": "1.0.0"},
    "POWEREDGE R760XA": {"latest": "1.8.0",  "min_recommended": "1.7.0",  "min_spectre": "1.0.0"},
    "POWEREDGE R960":   {"latest": "1.8.0",  "min_recommended": "1.7.0",  "min_spectre": "1.0.0"},
    "POWEREDGE R6625":  {"latest": "1.8.0",  "min_recommended": "1.7.0",  "min_spectre": "1.0.0"},
    "POWEREDGE R7625":  {"latest": "1.8.0",  "min_recommended": "1.7.0",  "min_spectre": "1.0.0"},
    # ── Dell 17G (Xeon 6 / Turin) — shipped post-spectre era ──────────────────
    "POWEREDGE R670":   {"latest": "1.4.4",  "min_recommended": "1.2.0",  "min_spectre": "1.0.0"},
    "POWEREDGE R770":   {"latest": "1.2.4",  "min_recommended": "1.1.0",  "min_spectre": "1.0.0"},
    "POWEREDGE R7715":  {"latest": "1.7.7",  "min_recommended": "1.6.4",  "min_spectre": "1.0.0", "vsan_catalog": "1.6.4"},
    "POWEREDGE R6715":  {"latest": "1.7.7",  "min_recommended": "1.6.4",  "min_spectre": "1.0.0", "vsan_catalog": "1.6.4"},
    "POWEREDGE R7725":  {"latest": "1.7.7",  "min_recommended": "1.6.4",  "min_spectre": "1.0.0", "vsan_catalog": "1.6.4"},
    "POWEREDGE R6725":  {"latest": "1.7.7",  "min_recommended": "1.6.4",  "min_spectre": "1.0.0", "vsan_catalog": "1.6.4"},
    # ── HPE Gen10 (Skylake-SP / Cascade Lake-SP) ──────────────────────────────
    # min_spectre ~U30 v1.22 per HPE Customer Advisory a00039267en_us (Feb 2018)
    "PROLIANT DL360 GEN10": {"latest": "U30 v3.00", "min_recommended": "U30 v2.90", "min_spectre": "U30 v1.22"},
    "PROLIANT DL380 GEN10": {"latest": "U30 v3.00", "min_recommended": "U30 v2.90", "min_spectre": "U30 v1.22"},
    "PROLIANT DL580 GEN10": {"latest": "U17 v3.00", "min_recommended": "U17 v2.90", "min_spectre": "U17 v1.22"},
    "PROLIANT BL460C GEN10":{"latest": "U34 v3.00", "min_recommended": "U34 v2.90", "min_spectre": "U34 v1.22"},
    # ── HPE Gen10 Plus (Ice Lake-SP) — shipped post-spectre era ───────────────
    "PROLIANT DL360 GEN10 PLUS": {"latest": "U32 v2.80", "min_recommended": "U32 v2.70", "min_spectre": "U32 v1.00"},
    "PROLIANT DL380 GEN10 PLUS": {"latest": "U32 v2.80", "min_recommended": "U32 v2.70", "min_spectre": "U32 v1.00"},
    # ── HPE Gen11 (Sapphire Rapids) — shipped post-spectre era ────────────────
    "PROLIANT DL360 GEN11":  {"latest": "U64 v1.60", "min_recommended": "U64 v1.50", "min_spectre": "U64 v1.00"},
    "PROLIANT DL380 GEN11":  {"latest": "U60 v1.60", "min_recommended": "U60 v1.50", "min_spectre": "U60 v1.00"},
    "PROLIANT DL380A GEN11": {"latest": "U58 v2.44", "min_recommended": "U58 v2.00", "min_spectre": "U58 v1.00"},
    "PROLIANT DL560 GEN11":  {"latest": "U36 v1.60", "min_recommended": "U36 v1.50", "min_spectre": "U36 v1.00"},
    # ── Lenovo ThinkSystem Gen 1 (Skylake-SP / Cascade Lake-SP) ──────────────
    # Redfish BiosVersion format: "[IVE-2.93]" — parse_version_tuple extracts 2.93
    # min_spectre per Lenovo LEN-22133: firmware IVE116Y (Jun 2018) ≈ [IVE-1.16]
    "THINKSYSTEM SR630": {"latest": "IVE-5.00", "min_recommended": "IVE-4.90", "min_spectre": "IVE-1.16"},
    "THINKSYSTEM SR650": {"latest": "IVE-5.00", "min_recommended": "IVE-4.90", "min_spectre": "IVE-1.16"},
    "THINKSYSTEM SR850": {"latest": "IVE-5.00", "min_recommended": "IVE-4.90", "min_spectre": "IVE-1.16"},
    "THINKSYSTEM SR860": {"latest": "IVE-5.00", "min_recommended": "IVE-4.90", "min_spectre": "IVE-1.16"},
    "THINKSYSTEM SR950": {"latest": "IVE-5.00", "min_recommended": "IVE-4.90", "min_spectre": "IVE-1.16"},
    "THINKSYSTEM SN550": {"latest": "IVE-5.00", "min_recommended": "IVE-4.90", "min_spectre": "IVE-1.16"},
    "THINKSYSTEM SN850": {"latest": "IVE-5.00", "min_recommended": "IVE-4.90", "min_spectre": "IVE-1.16"},
    # ── Lenovo ThinkSystem Gen 2 / 3 (Ice Lake / Sapphire Rapids) ─────────────
    # Shipped post-spectre; min_spectre = 1.00 (first firmware release)
    "THINKSYSTEM SR630 V2": {"latest": "TEE-2.00", "min_recommended": "TEE-1.90", "min_spectre": "TEE-1.00"},
    "THINKSYSTEM SR650 V2": {"latest": "TEE-2.00", "min_recommended": "TEE-1.90", "min_spectre": "TEE-1.00"},
    "THINKSYSTEM SR850 V2": {"latest": "TEE-2.00", "min_recommended": "TEE-1.90", "min_spectre": "TEE-1.00"},
    "THINKSYSTEM SR860 V2": {"latest": "TEE-2.00", "min_recommended": "TEE-1.90", "min_spectre": "TEE-1.00"},
    "THINKSYSTEM SR630 V3": {"latest": "AFE-3.00", "min_recommended": "AFE-2.90", "min_spectre": "AFE-1.00"},
    "THINKSYSTEM SR650 V3": {"latest": "AFE-3.00", "min_recommended": "AFE-2.90", "min_spectre": "AFE-1.00"},
    # ── Lenovo ThinkAgile HX/VX (based on ThinkSystem nodes) ─────────────────
    "THINKAGILE HX1320": {"latest": "IVE-5.00", "min_recommended": "IVE-4.90", "min_spectre": "IVE-1.22"},
    "THINKAGILE HX3320": {"latest": "IVE-5.00", "min_recommended": "IVE-4.90", "min_spectre": "IVE-1.22"},
    "THINKAGILE HX5520": {"latest": "IVE-5.00", "min_recommended": "IVE-4.90", "min_spectre": "IVE-1.22"},
    "THINKAGILE HX7520": {"latest": "IVE-5.00", "min_recommended": "IVE-4.90", "min_spectre": "IVE-1.22"},
    "THINKAGILE VX3520": {"latest": "IVE-5.00", "min_recommended": "IVE-4.90", "min_spectre": "IVE-1.22"},
    "THINKAGILE VX7520": {"latest": "IVE-5.00", "min_recommended": "IVE-4.90", "min_spectre": "IVE-1.22"},
    # ── Supermicro X11 Purley (Skylake-SP / Cascade Lake-SP 2P) ─────────────
    # X11-Purley stable spectre BIOS shipped in 2018; conservative min_spectre = "2.0"
    # per Supermicro security advisory Intel-SA-00088
    "SYS-1029U": {"latest": "4.4", "min_recommended": "4.3", "min_spectre": "2.0"},
    "SYS-2029U": {"latest": "4.4", "min_recommended": "4.3", "min_spectre": "2.0"},
    "SYS-6029P": {"latest": "4.4", "min_recommended": "4.3", "min_spectre": "2.0"},
    "SYS-2049U": {"latest": "4.4", "min_recommended": "4.3", "min_spectre": "2.0"},
    "SYS-1019P": {"latest": "4.4", "min_recommended": "4.3", "min_spectre": "2.0"},
    # ── Supermicro X12 (Ice Lake) / H12 (AMD EPYC Rome/Milan) ────────────────
    # All shipped post-spectre era; min_spectre = first released version
    "SYS-120U":  {"latest": "2.9", "min_recommended": "2.8", "min_spectre": "1.0"},
    "SYS-220U":  {"latest": "2.9", "min_recommended": "2.8", "min_spectre": "1.0"},
    "AS-2124BT": {"latest": "2.9", "min_recommended": "2.8", "min_spectre": "1.0"},
    "AS-4124GS": {"latest": "2.9", "min_recommended": "2.8", "min_spectre": "1.0"},
    # ── Supermicro X13 / H13 (Sapphire Rapids / EPYC Genoa) ─────────────────
    "SYS-121H":  {"latest": "1.4", "min_recommended": "1.3", "min_spectre": "1.0"},
    "SYS-221H":  {"latest": "1.4", "min_recommended": "1.3", "min_spectre": "1.0"},
    "AS-2125HS": {"latest": "1.4", "min_recommended": "1.3", "min_spectre": "1.0"},
    # ── Quanta Platforms ─────────────────────────────────────────────────────
    "QUANTAGRID D42A-2U": {"latest": "3A08.01", "min_recommended": "3A06.01", "min_spectre": "3A01.00"},
    # ── GIGABYTE Platforms ───────────────────────────────────────────────────
    "H262-Z63-00": {"latest": "C27", "min_recommended": "C20", "min_spectre": "C10"},
    # ── Cisco C-Series M5 (Skylake-SP / Cascade Lake-SP) ────────────────────
    # Cisco Redfish BiosVersion: "C220M5.4.1.2b.0.0323202048" — parse_version_tuple gets 4.1.2
    # M5 servers are on the 4.3(2.x) release train; stable spectre microcode from 3.1(2g) / 3.1.2.
    "UCSC-C220-M5": {"latest": "4.3.2", "min_recommended": "4.2.3", "min_spectre": "3.1.2"},
    "UCSC-C240-M5": {"latest": "4.3.2", "min_recommended": "4.2.3", "min_spectre": "3.1.2"},
    "UCSC-C480-M5": {"latest": "4.3.2", "min_recommended": "4.2.3", "min_spectre": "3.1.2"},
    "HX220C-M5SX":  {"latest": "4.3.2", "min_recommended": "4.2.3", "min_spectre": "3.1.2"},
    "HX240C-M5SX":  {"latest": "4.3.2", "min_recommended": "4.2.3", "min_spectre": "3.1.2"},
    "HXAF220C-M5SX":{"latest": "4.3.2", "min_recommended": "4.2.3", "min_spectre": "3.1.2"},
    # ── Cisco C-Series M6 (Ice Lake) — 6.0(2.x) HUU release train ────────────
    "UCSC-C220-M6": {"latest": "6.0.2", "min_recommended": "4.3.2", "min_spectre": "4.2.1"},
    "UCSC-C240-M6": {"latest": "6.0.2", "min_recommended": "4.3.2", "min_spectre": "4.2.1"},
    "HX220C-M6SX":  {"latest": "6.0.2", "min_recommended": "4.3.2", "min_spectre": "4.2.1"},
    "HXAF220C-M6SX":{"latest": "6.0.2", "min_recommended": "4.3.2", "min_spectre": "4.2.1"},
    # ── Cisco C-Series M7 (Sapphire Rapids) — 6.0(2.x) HUU release train ────
    "UCSC-C220-M7": {"latest": "6.0.2", "min_recommended": "4.3.2", "min_spectre": "4.2.1"},
    "UCSC-C240-M7": {"latest": "6.0.2", "min_recommended": "4.3.2", "min_spectre": "4.2.1"},
}

# NVMe drive firmware baselines — keyed by model-number prefix (uppercase).
# Follows the same BIOS_BASELINES → evaluate_bios_version() pattern.
# "latest" = newest qualified firmware on Broadcom BCG; "min_recommended" = minimum
# field-safe version.  BCG SSD link in the drive table is always the authoritative source.
NVME_FW_BASELINES = {
    "MZQL2":   {"latest": "GXA8302Q", "min_recommended": "GXA7302Q"},  # Samsung PM9A3
    "MZQLB":   {"latest": "EDA5602Q", "min_recommended": "EDA5302Q"},  # Samsung PM983
    "MZWLJ":   {"latest": "GDC7502Q", "min_recommended": "GDC7501Q"},  # Samsung PM9A1 (PCIe 4)
    "KCD6X":   {"latest": "1TCRS105", "min_recommended": "1TCRS102"},  # Kioxia CD6-R
    "KCD61":   {"latest": "1TCRS105", "min_recommended": "1TCRS102"},  # Kioxia CD6-V
    "SSDPE2":  {"latest": "VDV10184", "min_recommended": "VDV10110"},  # Intel P4610/P4510
    "SSDPF2":  {"latest": "23L1A004", "min_recommended": "23L1A002"},  # Intel P5800X (Optane — vSAN-ineligible but track FW)
    "MTFDHAL": {"latest": "M6DN001",  "min_recommended": "M6DN000"},   # Micron 9300
    "MTFDKBA": {"latest": "D3CD001",  "min_recommended": "D3CC000"},   # Micron 9400 Pro
    "WUS4BB":  {"latest": "B001",     "min_recommended": "A005"},      # WD Ultrastar DC P5600
}

# BMC / Management Controller firmware baselines.
# Keyed on a distinctive substring of the manager Model or FirmwareVersion string
# (uppercased).  "min_spectre" = minimum version where BMC firmware first included
# mitigations for speculative-execution related BMC-side CVEs.
BMC_FW_BASELINES = {
    # Dell iDRAC 10 (17G)
    "IDRAC10":        {"latest": "1.30.07.10",  "min_recommended": "1.10.17.00", "min_spectre": "1.00.00.00"},
    "17G MONOLITHIC": {"latest": "1.30.07.10",  "min_recommended": "1.10.17.00", "min_spectre": "1.00.00.00"},
    "17G":            {"latest": "1.30.07.10",  "min_recommended": "1.10.17.00", "min_spectre": "1.00.00.00"},
    # Dell iDRAC 9 (14G, 15G, 16G) — DSA-2025-046 (CVE-2025-26482) fixed in 7.00.00.181
    "IDRAC9":         {"latest": "7.20.70.50",  "min_recommended": "7.00.00.181", "min_spectre": "3.30.30"},
    "IDRAC 9":        {"latest": "7.20.70.50",  "min_recommended": "7.00.00.181", "min_spectre": "3.30.30"},
    "14G MONOLITHIC": {"latest": "7.20.70.50",  "min_recommended": "7.00.00.181", "min_spectre": "3.30.30"},
    "14G":            {"latest": "7.20.70.50",  "min_recommended": "7.00.00.181", "min_spectre": "3.30.30"},
    "15G MONOLITHIC": {"latest": "7.20.70.50",  "min_recommended": "7.00.00.181", "min_spectre": "3.30.30"},
    "15G":            {"latest": "7.20.70.50",  "min_recommended": "7.00.00.181", "min_spectre": "3.30.30"},
    "16G MONOLITHIC": {"latest": "7.20.70.50",  "min_recommended": "7.00.00.181", "min_spectre": "3.30.30"},
    "16G":            {"latest": "7.20.70.50",  "min_recommended": "7.00.00.181", "min_spectre": "3.30.30"},
    # Dell iDRAC 8 (13G legacy)
    "IDRAC8":         {"latest": "2.82.82.82",  "min_recommended": "2.82.00.00",  "min_spectre": "2.50.50.50"},
    "IDRAC 8":        {"latest": "2.82.82.82",  "min_recommended": "2.82.00.00",  "min_spectre": "2.50.50.50"},
    "13G MONOLITHIC": {"latest": "2.82.82.82",  "min_recommended": "2.82.00.00",  "min_spectre": "2.50.50.50"},
    "13G":            {"latest": "2.82.82.82",  "min_recommended": "2.82.00.00",  "min_spectre": "2.50.50.50"},
    # HPE iLO 5
    "ILO 5":   {"latest": "3.10",        "min_recommended": "3.00",         "min_spectre": "1.40"},
    # HPE iLO 6
    "ILO 6":   {"latest": "1.70",        "min_recommended": "1.60",         "min_spectre": "1.00"},
    # Lenovo XCC / XCC2 — firmware version returned as numeric string e.g. "8.90" (XCC) or "1.42" (XCC2)
    # Ref: Lenovo XClarity Controller support portal https://datacentersupport.lenovo.com
    "XCC":     {"latest": "8.90",        "min_recommended": "8.80",         "min_spectre": "2.00"},
    # Cisco IMC (C-Series BMC) — version matches BundleVersion portion (e.g. 4.3(2.x) for M5, 6.0(2.x) for M6/M7)
    # Ref: Cisco UCS C-Series Integrated Management Controller Firmware HUU guides
    "CIMC":    {"latest": "4.3.2",       "min_recommended": "4.2.3",        "min_spectre": "3.1.0"},
    # Supermicro BMC / IPMI firmware
    "SUPERMICRO BMC": {"latest": "3.76",  "min_recommended": "3.70",         "min_spectre": "3.20"},
    # Quanta BMC (AST2500 baseboard management controller)
    "AST2500":        {"latest": "3.14.19", "min_recommended": "3.14.19",   "min_spectre": "1.00"},
    # GIGABYTE server BMC (AMI MegaRAC / 410810600)
    "410810600":      {"latest": "12.84.13", "min_recommended": "12.84.13", "min_spectre": "1.00"},
    "12.84":          {"latest": "12.84.13", "min_recommended": "12.84.13", "min_spectre": "1.00"},
}

# Per-vendor side-channel security advisory URLs.
# Keyed on uppercase vendor name fragment matching sys_info["vendor"].upper().
# Value: (url, display_label) tuple used to generate advisory hyperlinks in the HTML report.
_VENDOR_SIDE_CHANNEL_LINKS = {
    "DELL":       ("https://www.dell.com/support/kbdoc/en-us/000178106",
                   "Dell KB 000178106 — Spectre/Meltdown Impact on PowerEdge"),
    "HPE":        ("https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-a00039267en_us",
                   "HPE Advisory a00039267 — Side-Channel Analysis Mitigation"),
    "HEWLETT":    ("https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-a00039267en_us",
                   "HPE Advisory a00039267 — Side-Channel Analysis Mitigation"),
    "LENOVO":     ("https://support.lenovo.com/solutions/len-22133",
                   "Lenovo LEN-22133 — Speculative Execution Side Channel Variants"),
    "SUPERMICRO": ("https://www.supermicro.com/en/support/security_Intel-SA-00088",
                   "Supermicro Security Advisory Intel-SA-00088"),
    "CISCO":      ("https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180104-cpusidechannel",
                   "Cisco Advisory cisco-sa-20180104-cpusidechannel"),
    "QUANTA":     ("https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00088.html",
                   "Intel-SA-00088 — Spectre/Meltdown (Quanta/QCT platforms)"),
    "GIGABYTE":   ("https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00088.html",
                   "Intel-SA-00088 — Spectre/Meltdown (GIGABYTE platforms)"),
}

# Per-vendor server & BMC security hardening guides.
# Keyed on uppercase vendor / BMC substring.
DEFAULT_HARDENING_GUIDE = {
    "url": "https://github.com/vmware/vcf-security-and-compliance-guidelines",
    "label": "VCF Hardening Guidelines",
    "title": "VMware Cloud Foundation Security and Compliance Guidelines",
    "docs": [
        {
            "url": "https://github.com/vmware/vcf-security-and-compliance-guidelines",
            "label": "VCF Hardening Guidelines",
            "title": "VMware Cloud Foundation Security and Compliance Guidelines",
        }
    ],
}

# Joint CISA/NSA Cybersecurity Information Sheet (CSI): Harden Baseboard Management Controllers
CISA_NSA_BMC_GUIDE = {
    "url": "https://media.defense.gov/2023/Jun/14/2003241405/-1/-1/0/CSI_HARDEN_BMCS.PDF",
    "label": "CISA/NSA BMC Hardening Guide",
    "title": "CISA / NSA Cybersecurity Information Sheet: Harden Baseboard Management Controllers",
}

VENDOR_HARDENING_GUIDES = {
    "DELL": {
        "url": "https://www.dell.com/support/manuals/en-us/idrac9-lifecycle-controller-v5.x-series/idrac9_security_configuration_guide/",
        "label": "Dell iDRAC Hardening Guide",
        "title": "iDRAC9 Security Configuration Guide",
        "docs": [
            {
                "url": "https://www.dell.com/support/manuals/en-us/idrac9-lifecycle-controller-v5.x-series/idrac9_security_configuration_guide/",
                "label": "Dell iDRAC Hardening Guide",
                "title": "iDRAC9 Security Configuration Guide",
            },
            {
                "url": "https://dl.dell.com/content/manual30213951-idrac9-security-configuration-guide.pdf",
                "label": "iDRAC9 Security Guide (PDF)",
                "title": "iDRAC9 Security Configuration Guide (PDF)",
            },
        ],
    },
    "IDRAC": {
        "url": "https://www.dell.com/support/manuals/en-us/idrac9-lifecycle-controller-v5.x-series/idrac9_security_configuration_guide/",
        "label": "Dell iDRAC Hardening Guide",
        "title": "iDRAC9 Security Configuration Guide",
        "docs": [
            {
                "url": "https://www.dell.com/support/manuals/en-us/idrac9-lifecycle-controller-v5.x-series/idrac9_security_configuration_guide/",
                "label": "Dell iDRAC Hardening Guide",
                "title": "iDRAC9 Security Configuration Guide",
            },
            {
                "url": "https://dl.dell.com/content/manual30213951-idrac9-security-configuration-guide.pdf",
                "label": "iDRAC9 Security Guide (PDF)",
                "title": "iDRAC9 Security Configuration Guide (PDF)",
            },
        ],
    },
    "HPE": {
        "url": "https://www.hpe.com/info/iLO",
        "label": "HPE iLO Security Documentation",
        "title": "HPE iLO Security Documentation Hub",
        "docs": [
            {
                "url": "https://www.hpe.com/info/iLO",
                "label": "HPE iLO Security Documentation",
                "title": "HPE iLO Security Documentation Hub",
            },
            {
                "url": "https://servermanagementportal.ext.hpe.com/docs/redfishservices/ilos/supplementdocuments/securityservice",
                "label": "iLO Redfish Security Service",
                "title": "HPE iLO Redfish Security Service (Security States & TLS)",
            },
        ],
    },
    "HEWLETT": {
        "url": "https://www.hpe.com/info/iLO",
        "label": "HPE iLO Security Documentation",
        "title": "HPE iLO Security Documentation Hub",
        "docs": [
            {
                "url": "https://www.hpe.com/info/iLO",
                "label": "HPE iLO Security Documentation",
                "title": "HPE iLO Security Documentation Hub",
            },
            {
                "url": "https://servermanagementportal.ext.hpe.com/docs/redfishservices/ilos/supplementdocuments/securityservice",
                "label": "iLO Redfish Security Service",
                "title": "HPE iLO Redfish Security Service (Security States & TLS)",
            },
        ],
    },
    "ILO": {
        "url": "https://www.hpe.com/info/iLO",
        "label": "HPE iLO Security Documentation",
        "title": "HPE iLO Security Documentation Hub",
        "docs": [
            {
                "url": "https://www.hpe.com/info/iLO",
                "label": "HPE iLO Security Documentation",
                "title": "HPE iLO Security Documentation Hub",
            },
            {
                "url": "https://servermanagementportal.ext.hpe.com/docs/redfishservices/ilos/supplementdocuments/securityservice",
                "label": "iLO Redfish Security Service",
                "title": "HPE iLO Redfish Security Service (Security States & TLS)",
            },
        ],
    },
    "LENOVO": {
        "url": "https://lenovopress.lenovo.com/lp1260-how-to-harden-the-security-of-your-thinksystem-server",
        "label": "Lenovo XCC Hardening Guide",
        "title": "How to Harden the Security of your ThinkSystem Server and Management Applications",
        "docs": [
            {
                "url": "https://lenovopress.lenovo.com/lp1260-how-to-harden-the-security-of-your-thinksystem-server",
                "label": "Lenovo XCC Hardening Guide",
                "title": "How to Harden the Security of your ThinkSystem Server and Management Applications",
            },
            {
                "url": "https://lenovopress.lenovo.com/lp1260.pdf",
                "label": "Lenovo Hardening Paper (PDF)",
                "title": "How to Harden the Security of your ThinkSystem Server (PDF)",
            },
        ],
    },
    "XCC": {
        "url": "https://lenovopress.lenovo.com/lp1260-how-to-harden-the-security-of-your-thinksystem-server",
        "label": "Lenovo XCC Hardening Guide",
        "title": "How to Harden the Security of your ThinkSystem Server and Management Applications",
        "docs": [
            {
                "url": "https://lenovopress.lenovo.com/lp1260-how-to-harden-the-security-of-your-thinksystem-server",
                "label": "Lenovo XCC Hardening Guide",
                "title": "How to Harden the Security of your ThinkSystem Server and Management Applications",
            },
            {
                "url": "https://lenovopress.lenovo.com/lp1260.pdf",
                "label": "Lenovo Hardening Paper (PDF)",
                "title": "How to Harden the Security of your ThinkSystem Server (PDF)",
            },
        ],
    },
    "CISCO": {
        "url": "https://www.cisco.com/c/en/us/products/collateral/servers-unified-computing/compute-security-hardening-guide-standalone-wp.pdf",
        "label": "Cisco IMC Hardening Guide",
        "title": "Cisco Compute Security Hardening Guide (Standalone / CIMC)",
        "docs": [
            {
                "url": "https://www.cisco.com/c/en/us/products/collateral/servers-unified-computing/compute-security-hardening-guide-standalone-wp.pdf",
                "label": "Cisco IMC Hardening Guide",
                "title": "Cisco Compute Security Hardening Guide (Standalone / CIMC)",
            },
            {
                "url": "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/gui/config/guide/6_0/b_cisco_ucs_c-series_gui_configuration_guide_6-0.html",
                "label": "Cisco IMC GUI Config Guide",
                "title": "Cisco UCS C-Series Integrated Management Controller GUI Configuration Guide, Release 6.0",
            },
        ],
    },
    "CIMC": {
        "url": "https://www.cisco.com/c/en/us/products/collateral/servers-unified-computing/compute-security-hardening-guide-standalone-wp.pdf",
        "label": "Cisco IMC Hardening Guide",
        "title": "Cisco Compute Security Hardening Guide (Standalone / CIMC)",
        "docs": [
            {
                "url": "https://www.cisco.com/c/en/us/products/collateral/servers-unified-computing/compute-security-hardening-guide-standalone-wp.pdf",
                "label": "Cisco IMC Hardening Guide",
                "title": "Cisco Compute Security Hardening Guide (Standalone / CIMC)",
            },
            {
                "url": "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/gui/config/guide/6_0/b_cisco_ucs_c-series_gui_configuration_guide_6-0.html",
                "label": "Cisco IMC GUI Config Guide",
                "title": "Cisco UCS C-Series Integrated Management Controller GUI Configuration Guide, Release 6.0",
            },
        ],
    },
    "SUPERMICRO": {
        "url": "https://www.supermicro.com/products/nfo/files/IPMI/Best_Practices_BMC_Security.pdf",
        "label": "Supermicro BMC Security Best Practices",
        "title": "Supermicro BMC Security Best Practices",
        "docs": [
            {
                "url": "https://www.supermicro.com/products/nfo/files/IPMI/Best_Practices_BMC_Security.pdf",
                "label": "Supermicro BMC Security Best Practices",
                "title": "Supermicro BMC Security Best Practices",
            },
            {
                "url": "https://www.supermicro.com/products/nfo/files/IPMI/BMC_Server_Management_Feature_Guide.pdf",
                "label": "Supermicro BMC Feature Guide",
                "title": "Supermicro BMC Server Management Feature Guide",
            },
        ],
    },
    "INTEL": {
        "url": "https://www.intel.com/content/www/us/en/support/articles/000055785/server-products.html",
        "label": "Intel BMC Security Guide",
        "title": "Intel Server Systems BMC and BIOS Security Configuration Guide",
        "docs": [
            {
                "url": "https://www.intel.com/content/www/us/en/support/articles/000055785/server-products.html",
                "label": "Intel BMC Security Guide",
                "title": "Intel Server Systems BMC and BIOS Security Configuration Guide",
            },
            {
                "url": "https://cdrdv2-public.intel.com/840799/BMC_BIOS_Security_GoodPractices.pdf",
                "label": "Intel BMC Good Practices (PDF)",
                "title": "Intel Server Systems BMC & BIOS Security Good Practices (PDF)",
            },
        ],
    },
    "QUANTA": {
        "url": "https://www.qct.io",
        "label": "Quanta Security Guide",
        "title": "Quanta Cloud Technology Server Management & Security Guide",
        "docs": [
            {
                "url": "https://www.qct.io",
                "label": "Quanta Security Guide",
                "title": "Quanta Cloud Technology Server Management & Security Guide",
            },
        ],
    },
    "GIGABYTE": {
        "url": "https://www.gigabyte.com/Enterprise/Server",
        "label": "GIGABYTE Server Security Guide",
        "title": "GIGABYTE Server Management and Security Guidelines",
        "docs": [
            {
                "url": "https://www.gigabyte.com/Enterprise/Server",
                "label": "GIGABYTE Server Security Guide",
                "title": "GIGABYTE Server Management and Security Guidelines",
            },
        ],
    },
}

# CVE coverage tiers based on BIOS release date.
# Each entry: (cutoff_date_str, tier_int, tier_label, badge_class, description)
# A BIOS is assigned the HIGHEST tier whose cutoff_date <= bios_release_date.
# cutoff_date = first date when the relevant Intel/AMD microcode batch was broadly
# available in OEM BIOS releases.  None as cutoff means "no upper bound" (current tier).
_CVE_TIERS = [
    # Tier 0 — completely unmitigated (BIOS predates Jan 2018 disclosure)
    ("2018-01-05", 0, "No Side-Channel Coverage",
     "danger",
     "BIOS predates the Jan 2018 Spectre/Meltdown disclosure. No microcode "
     "patches for CVE-2017-5715, CVE-2017-5753, or CVE-2017-5754."),
    # Tier 1 — initial Spectre V1/V2 + Meltdown microcode (Jan-Aug 2018)
    ("2018-08-14", 1, "Spectre/Meltdown Initial",
     "danger",
     "Covers initial Spectre V2 (CVE-2017-5715) and Meltdown. Missing L1TF "
     "(CVE-2018-3646), MDS (CVE-2019-11135), and SRBDS (CVE-2020-0543)."),
    # Tier 2 — + L1TF / Foreshadow (Intel Aug 2018 microcode batch)
    ("2019-05-14", 2, "Spectre + L1TF",
     "warning",
     "Covers Spectre/Meltdown + L1TF/Foreshadow (CVE-2018-3620, CVE-2018-3646). "
     "Missing MDS (CVE-2019-11135) and SRBDS (CVE-2020-0543)."),
    # Tier 3 — + MDS / TAA / RIDL / Fallout (Intel May 2019 microcode)
    ("2020-06-09", 3, "Spectre + L1TF + MDS",
     "warning",
     "Covers Spectre/Meltdown/L1TF + MDS/TAA (CVE-2019-11135, CVE-2019-11091). "
     "Missing SRBDS (CVE-2020-0543). Recommended minimum for Cascade Lake."),
    # Tier 4 — + SRBDS / CrossTalk (Intel Jun 2020 microcode)
    ("2024-03-12", 4, "Spectre + L1TF + MDS + SRBDS",
     "success",
     "Covers Spectre/Meltdown/L1TF/MDS + SRBDS (CVE-2020-0543). "
     "Adequate for most deployments. Missing RFDS (CVE-2023-28746, Intel 4th Gen+ only)."),
    # Tier 5 — + RFDS / Register File Data Sampling (Intel IPU 2024.1)
    (None, 5, "Full Current Coverage",
     "success",
     "Full side-channel microcode coverage including RFDS (CVE-2023-28746, "
     "Intel Sapphire Rapids and newer only). Recommended for all deployments."),
]

# QLC NVMe model-number prefixes — all confirmed against vendor datasheets and
# ordering codes across every capacity/form-factor variant.  Drives matching
# any of these prefixes have rated endurance < 1 DWPD (QLC NAND).
# Also: any model string containing the literal "QLC" is caught at runtime.
QLC_NVME_PREFIXES = (
    # ── Samsung BM1743 (PCIe Gen5, QLC V-NAND, 0.2–0.26 DWPD) ──────────────
    # Samsung uses MZW for U.2/U.3 and MZ3 for EDSFF — both needed.
    "MZWMO",     # BM1743 U.2: MZWMO15THCLF / MZWMO30THCLF / MZWMO61THCLF / MZWMOA2THCPA
    "MZ3MO",     # BM1743 E3.S: MZ3MO30THCLF (EDSFF form-factor byte differs from U.2)
    # Samsung PM9C3 (PCIe Gen5 QLC): MZWL prefix is NOT safe — MZWLJ = PM9A1 TLC.
    # PM9C3 will be caught by the literal "QLC" check or the >4 TB capacity heuristic
    # once a unique confirmed prefix is available.
    # ── Micron 6500 ION (PCIe Gen4, QLC, 30.72 TB only) ────────────────────
    "MTFDKCC",   # 6500 ION U.3 (SFF-8639): MTFDKCC30T7TGR
    "MTFDKBN",   # 6500 ION E1.L: MTFDKBN30T7TGR
    # ── Micron 6600 ION (PCIe Gen5, G9 QLC NAND, 30–245 TB) ────────────────
    # MTFDL = Gen5; Gen4 uses MTFDK — MTFDKBA (9400 Pro, TLC) is safely excluded
    "MTFDL",     # all FF: MTFDLAL (U.2) / MTFDLBQ (E3.S) / MTFDLBN (E1.L) / MTFDLBR (E3.L)
    # ── Kioxia LC9 (PCIe Gen5, BiCS Gen8 QLC, 30–245 TB) ───────────────────
    "RLC9",      # SIE/SED/FIPS across 2.5"/E3.S/E3.L: RLC9CZB / RLC9EZB / RLC9CZV / RLC9EZV
    # ── Solidigm D5-P5430 (PCIe Gen4, 192L 3D QLC, 3.84–30.72 TB, 0.58 DWPD) ─
    "SBFPF",     # all FF: SBFPF2BU (U.2) / SBFPFABU (E3.S) / SBFPFUBU (E1.S)
    # ── Kioxia CD8P-V (QLC, U.3) & FL6 (QLC, EDSFF) ────────────────────────
    "KCD8",      # CD8P-V U.3 — broader than KCD8P to catch future CD8 variants
    "KCF8",      # FL6 EDSFF E3.S
    "KFF8",      # FL6 EDSFF E1.S
    # ── SK Hynix PE8010 / PE8011 (QLC NVMe U.2) ────────────────────────────
    "SHGP",
    # ── WD Ultrastar DC SN860 (QLC NVMe) ────────────────────────────────────
    "WUS4CB",
    # ── Intel D5-P4326 (QLC NVMe U.2) ───────────────────────────────────────
    "SSDPE2NV",
    # ── Dell Express Flash CM5 NVMe (OEM-branded QLC) ───────────────────────
    "CM5",
    # ── Seagate Nytro 5550H (QLC, EDSFF E1.S) ───────────────────────────────
    "STJN",
)

# ---------------------------------------------------------------------------
# GPU / Accelerator static specification database
# ---------------------------------------------------------------------------
# Each entry: regex pattern (matched case-insensitively against the Redfish
# device name) → spec dict.  Patterns are tried in order; first match wins.
# Keys:
#   vram         — VRAM size string
#   arch         — GPU microarchitecture
#   mig          — supports NVIDIA Multi-Instance GPU partitioning
#   vgpu         — supports hardware virtualisation (NVIDIA vGPU / AMD MxGPU /
#                  Intel SR-IOV); requires additional software license
#   vgpu_note    — vGPU license/profile detail shown in the GPU tab
#   pais_note    — relevance for Private AI Infrastructure (PAIS) workloads
#   vdi_note     — relevance for Horizon VDI on VCF
_GPU_SPECS_DB = [
    # ── NVIDIA Blackwell ─────────────────────────────────────────────────────
    (r"\bB200\b",    {"vram": "192 GB HBM3e",  "arch": "Blackwell", "mig": True,  "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; supports up to 7 MIG instances (MIG 3g.96gb / 1g.24gb profiles).",
                      "pais_note": "Primary training GPU for large frontier models; NVLink 5.0 scale-out.",
                      "vdi_note":  "Not a vGPU/VDI workload card — requires NVLink topology."}),
    (r"\bB100\b",    {"vram": "192 GB HBM3e",  "arch": "Blackwell", "mig": True,  "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; MIG-capable with same profiles as B200.",
                      "pais_note": "Inference and fine-tuning at scale; pairs with ConnectX-8 for NVLink Fusion.",
                      "vdi_note":  "Not intended for VDI profiles."}),
    # ── NVIDIA Hopper ────────────────────────────────────────────────────────
    (r"\bH200\b",    {"vram": "141 GB HBM3e",  "arch": "Hopper",    "mig": True,  "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; up to 7 MIG instances (1g.20gb–3g.80gb profiles).",
                      "pais_note": "Best-in-class inference for LLMs; HBM3e bandwidth ideal for mixture-of-experts (MoE) models.",
                      "vdi_note":  "vGPU supported via NVIDIA AI Enterprise; not a primary VDI card."}),
    (r"\bH100\b.*\bSXM\b|\bH100.*SXM", {"vram": "80 GB HBM3",   "arch": "Hopper", "mig": True, "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; up to 7 MIG instances; NVLink 4.0 interconnect.",
                      "pais_note": "Top-tier training and inference; NVLink 4.0 scale-out to 256 GPUs.",
                      "vdi_note":  "vGPU capable; NVIDIA AI Enterprise license required."}),
    (r"\bH100\b",    {"vram": "80 GB HBM2e (PCIe)",  "arch": "Hopper", "mig": True, "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; up to 7 MIG instances; PCIe 5.0 host attach.",
                      "pais_note": "Full PCIe variant for rack-scale AI inferencing; supports NVIDIA Triton.",
                      "vdi_note":  "vGPU capable; NVIDIA AI Enterprise license required."}),
    # ── NVIDIA Ada Lovelace ──────────────────────────────────────────────────
    (r"\bL40S\b",    {"vram": "48 GB GDDR6",   "arch": "Ada Lovelace", "mig": False, "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; time-slicing and MIG-like partitioning via vGPU; up to 10 vGPU profiles.",
                      "pais_note": "Versatile inference + rendering; suitable for multi-modal AI workloads on VCF.",
                      "vdi_note":  "Excellent VDI card: 48 GB can run 24–48 concurrent vGPU sessions (2–4 GB profiles)."}),
    (r"\bL40\b(?!S)", {"vram": "48 GB GDDR6",  "arch": "Ada Lovelace", "mig": False, "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; time-sliced vGPU; combines rendering + compute.",
                      "pais_note": "Graphics-intensive AI pipelines; ray-tracing + CUDA on same card.",
                      "vdi_note":  "Strong VDI card for 3D-accelerated Horizon desktops; 48 GB supports large session counts."}),
    (r"\bL4\b",      {"vram": "24 GB GDDR6",   "arch": "Ada Lovelace", "mig": False, "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; time-sliced vGPU; 72W TDP makes it dense-deployment friendly.",
                      "pais_note": "Low-power inference at the edge; good $/token for small models.",
                      "vdi_note":  "Good low-power VDI option; 24 GB supports 12–24 sessions at 1–2 GB profiles."}),
    # ── NVIDIA Ampere datacenter ─────────────────────────────────────────────
    (r"\bA100\b.*80|A100.*HBM2e.*80", {"vram": "80 GB HBM2e", "arch": "Ampere", "mig": True, "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; up to 7 MIG instances (1g.10gb–3g.40gb); NVLink 3.0.",
                      "pais_note": "Standard training GPU for large language models; NVLink 3.0 scale-out.",
                      "vdi_note":  "vGPU capable but oversized for VDI; best reserved for AI workloads."}),
    (r"\bA100\b",    {"vram": "40 GB HBM2",    "arch": "Ampere",    "mig": True,  "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; up to 7 MIG instances (1g.5gb–3g.20gb); NVLink 3.0.",
                      "pais_note": "Workhorse training and inference GPU; supports NVLINK scale-out.",
                      "vdi_note":  "vGPU capable; commonly used for AI-assisted Horizon workloads."}),
    (r"\bA40\b",     {"vram": "48 GB GDDR6",   "arch": "Ampere",    "mig": False, "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; time-sliced vGPU; 4× NVLink not present (PCIe only).",
                      "pais_note": "Rendering + AI inference; ideal for mixed VDI and PAIS workloads on same host.",
                      "vdi_note":  "Well-suited for 3D-accelerated Horizon VDI; 48 GB supports high session density."}),
    (r"\bA30\b",     {"vram": "24 GB HBM2",    "arch": "Ampere",    "mig": True,  "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; up to 4 MIG instances (1g.6gb–2g.12gb).",
                      "pais_note": "Compact MIG-capable GPU for multi-tenant AI inferencing at scale.",
                      "vdi_note":  "Supported for vGPU; smaller frame buffer limits concurrent 3D session count."}),
    (r"\bA16\b",     {"vram": "64 GB GDDR6 (4×16 GB)", "arch": "Ampere", "mig": False, "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; quad-GPU MXM module; 4×16 GB GDDR6; purpose-built for VDI density.",
                      "pais_note": "Not targeted for AI training; use for VDI or light inference.",
                      "vdi_note":  "Purpose-built VDI GPU; excellent session density for Horizon 8 with NVIDIA GRID."}),
    (r"\bA10\b",     {"vram": "24 GB GDDR6",   "arch": "Ampere",    "mig": False, "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; time-sliced vGPU; single-slot design.",
                      "pais_note": "Entry-level inference acceleration; suitable for chatbot and RAG workloads.",
                      "vdi_note":  "Popular VDI card; 24 GB supports 12–24 sessions at 1–2 GB profiles."}),
    (r"\bA2\b",      {"vram": "16 GB GDDR6",   "arch": "Ampere",    "mig": False, "vgpu": True,
                      "vgpu_note": "Requires NVIDIA AI Enterprise; low-profile 60W TDP; time-sliced vGPU.",
                      "pais_note": "Edge inference for lightweight models; fits low-profile slots.",
                      "vdi_note":  "Low-power VDI option for thin-and-light deployments."}),
    # ── NVIDIA Turing / Volta datacenter ────────────────────────────────────
    (r"\bT4\b",      {"vram": "16 GB GDDR6",   "arch": "Turing",    "mig": False, "vgpu": True,
                      "vgpu_note": "Requires NVIDIA vGPU / AI Enterprise; time-sliced profiles (T4-1Q to T4-16Q).",
                      "pais_note": "Legacy inference card; still widely deployed; consider L4 for refresh.",
                      "vdi_note":  "Very common Horizon VDI card; 16 GB supports 8–16 sessions; good $/session."}),
    (r"\bV100\b.*32|V100.*HBM2.*32", {"vram": "32 GB HBM2", "arch": "Volta", "mig": False, "vgpu": True,
                      "vgpu_note": "Requires NVIDIA vGPU / AI Enterprise; time-sliced profiles.",
                      "pais_note": "Previous-gen training GPU; still viable for fine-tuning smaller models.",
                      "vdi_note":  "vGPU capable; older generation — plan for A/L-series refresh."}),
    (r"\bV100\b",    {"vram": "16 GB HBM2",    "arch": "Volta",     "mig": False, "vgpu": True,
                      "vgpu_note": "Requires NVIDIA vGPU / AI Enterprise; time-sliced profiles.",
                      "pais_note": "Previous-gen training GPU; suitable for NLP fine-tuning up to 7B parameters.",
                      "vdi_note":  "vGPU capable; older generation — plan for A/L-series refresh."}),
    # ── NVIDIA consumer top-tier ─────────────────────────────────────────────
    (r"\bRTX\s*5090\b", {"vram": "32 GB GDDR7",  "arch": "Blackwell", "mig": False, "vgpu": False,
                      "vgpu_note": "No NVIDIA vGPU / MIG support on consumer GeForce GPUs.",
                      "pais_note": "Consumer card — no ECC; not recommended for production AI inference on VCF.",
                      "vdi_note":  "Not supported for Horizon vGPU (no GRID driver); suitable for bare-metal GPU passthrough only."}),
    (r"\bRTX\s*5080\b", {"vram": "16 GB GDDR7",  "arch": "Blackwell", "mig": False, "vgpu": False,
                      "vgpu_note": "No NVIDIA vGPU / MIG support on consumer GeForce GPUs.",
                      "pais_note": "Consumer card — no ECC; not recommended for production AI on VCF.",
                      "vdi_note":  "Not supported for Horizon vGPU; GPU passthrough only."}),
    (r"\bRTX\s*4090\b", {"vram": "24 GB GDDR6X", "arch": "Ada Lovelace", "mig": False, "vgpu": False,
                      "vgpu_note": "No NVIDIA vGPU / MIG support on consumer GeForce GPUs.",
                      "pais_note": "Consumer card — no ECC; may be used for dev/test AI workloads with passthrough.",
                      "vdi_note":  "Not supported for Horizon vGPU; GPU passthrough only."}),
    (r"\bRTX\s*4080\b", {"vram": "16 GB GDDR6X", "arch": "Ada Lovelace", "mig": False, "vgpu": False,
                      "vgpu_note": "No NVIDIA vGPU / MIG support on consumer GeForce GPUs.",
                      "pais_note": "Consumer card — not recommended for production PAIS.",
                      "vdi_note":  "Not supported for Horizon vGPU; GPU passthrough only."}),
    # ── AMD Instinct datacenter ──────────────────────────────────────────────
    (r"\bMI300X\b",  {"vram": "192 GB HBM3",   "arch": "CDNA 3",    "mig": False, "vgpu": True,
                      "vgpu_note": "AMD MxGPU (SR-IOV native); up to 8 VFs per GPU; no separate license fee.",
                      "pais_note": "Largest VRAM pool in class; ideal for LLM inference (full 70B+ models in a single GPU).",
                      "vdi_note":  "AMD MxGPU SR-IOV supported with Horizon; no per-GPU license surcharge."}),
    (r"\bMI300A\b",  {"vram": "128 GB HBM3",   "arch": "CDNA 3",    "mig": False, "vgpu": True,
                      "vgpu_note": "Integrated CPU+GPU APU; AMD MxGPU SR-IOV; up to 8 VFs.",
                      "pais_note": "APU design with unified memory; strong for HPC workloads collocated with AI.",
                      "vdi_note":  "MxGPU SR-IOV supported; unique APU form-factor requires specific platform support."}),
    (r"\bMI250X\b",  {"vram": "128 GB HBM2e",  "arch": "CDNA 2",    "mig": False, "vgpu": True,
                      "vgpu_note": "AMD MxGPU SR-IOV; up to 8 VFs per GPU.",
                      "pais_note": "Dual-die OAM module; strong FP64 for HPC+AI mixed workloads.",
                      "vdi_note":  "MxGPU supported; large TDP (560W) requires open-air or liquid-cooled chassis."}),
    (r"\bMI210\b",   {"vram": "64 GB HBM2e",   "arch": "CDNA 2",    "mig": False, "vgpu": True,
                      "vgpu_note": "AMD MxGPU SR-IOV; up to 8 VFs per GPU.",
                      "pais_note": "PCIe form-factor CDNA 2; good for inference and HPC on standard PCIe platforms.",
                      "vdi_note":  "MxGPU supported in Horizon; suitable for medium-density VDI."}),
    (r"\bMI100\b",   {"vram": "32 GB HBM2",    "arch": "CDNA 1",    "mig": False, "vgpu": True,
                      "vgpu_note": "AMD MxGPU SR-IOV; up to 8 VFs per GPU.",
                      "pais_note": "Previous-gen; CDNA 1 still capable for training/fine-tuning smaller models.",
                      "vdi_note":  "MxGPU supported; plan for MI200/MI300 upgrade for AI workloads."}),
    # ── AMD consumer top-tier ────────────────────────────────────────────────
    (r"\bRX\s*9070\s*XT\b", {"vram": "16 GB GDDR6",  "arch": "RDNA 4", "mig": False, "vgpu": False,
                      "vgpu_note": "No MxGPU SR-IOV on consumer Radeon cards.",
                      "pais_note": "Consumer card; no ECC; not recommended for production PAIS on VCF.",
                      "vdi_note":  "Not supported for Horizon vGPU; passthrough only."}),
    (r"\bRX\s*7900\s*XTX\b", {"vram": "24 GB GDDR6", "arch": "RDNA 3", "mig": False, "vgpu": False,
                      "vgpu_note": "No MxGPU SR-IOV on consumer Radeon cards.",
                      "pais_note": "Consumer card; no ECC; not recommended for production PAIS on VCF.",
                      "vdi_note":  "Not supported for Horizon vGPU; passthrough only."}),
    # ── Intel datacenter ─────────────────────────────────────────────────────
    (r"\bGaudi\s*3\b", {"vram": "128 GB HBM2e", "arch": "Gaudi 3",  "mig": False, "vgpu": True,
                      "vgpu_note": "Intel SR-IOV supported; up to 8 VFs; no per-GPU license required.",
                      "pais_note": "Competitive inference throughput for LLMs; strong FP8 tensor performance.",
                      "vdi_note":  "SR-IOV VF supported for Horizon; verify driver support on ESXi."}),
    (r"\bGaudi\s*2\b", {"vram": "96 GB HBM2e",  "arch": "Gaudi 2",  "mig": False, "vgpu": True,
                      "vgpu_note": "Intel SR-IOV supported; up to 8 VFs.",
                      "pais_note": "Previous-gen Gaudi; suitable for transformer-based inference.",
                      "vdi_note":  "SR-IOV VF supported; verify driver support on ESXi."}),
    (r"\bFlex\s*170\b", {"vram": "32 GB GDDR6",  "arch": "Xe-HP",   "mig": False, "vgpu": True,
                      "vgpu_note": "Intel SR-IOV; up to 16 VFs per GPU; purpose-built for media streaming and VDI.",
                      "pais_note": "Light inference workloads; strong AV1 encode/decode for media pipelines.",
                      "vdi_note":  "Excellent VDI card: SR-IOV with up to 16 VFs; supports Horizon with Intel GVT-d."}),
    (r"\bFlex\s*140\b", {"vram": "16 GB GDDR6",  "arch": "Xe-HP",   "mig": False, "vgpu": True,
                      "vgpu_note": "Intel SR-IOV; up to 8 VFs per GPU; single-slot low-profile.",
                      "pais_note": "Low-profile entry-level AI inference; fits dense 1U servers.",
                      "vdi_note":  "SR-IOV VF for Horizon VDI; low-profile form factor enables high GPU density."}),
]


def _lookup_gpu_specs(gpu_name: str) -> Optional[dict]:
    """Return the first matching entry from _GPU_SPECS_DB for the given GPU name, or None."""
    for pattern, specs in _GPU_SPECS_DB:
        if re.search(pattern, gpu_name, re.I):
            return specs
    return None

