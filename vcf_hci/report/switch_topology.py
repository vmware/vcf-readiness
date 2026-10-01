"""
VCF HCI Readiness Tool — Switch Intelligence, Buffer Taxonomy, & ToR Topology Engine.

Classifies switches based on:
1. Packet Buffer capacity and ASIC family (Broadcom Jericho/Qumran/Trident/Tomahawk,
   Cisco Silicon One/Cloudscale, Juniper Q5) based on Michael Buraglio's Packet Buffer
   Reference (https://port-buffers.forwardingplane.net/) and Jim Warner's UCSC research.
2. High Radix / Modular Chassis form factors (Nexus 7000/7700, Arista 7500/7800, etc.).
3. Cisco Fabric Extender (FEX / Nexus 2000) detection and oversubscription warnings.
4. Fleet-wide ToR leaf switch pair correlation and cabling redundancy auditing.
"""

import html
import re
from typing import Any, Dict, List, Optional, Set, Tuple

# ── Buffer Capability Tiers ───────────────────────────────────────────────────
BUFFER_TIER_ULTRA_DEEP = "ultra_deep"  # VOQ + Multi-GB external DRAM/HBM (Jericho/Qumran/Q5/Silicon One)
BUFFER_TIER_DEEP       = "deep"        # 100MB+ on-chip shared SRAM (Trident 4, Tomahawk 4/5, Cloudscale GX2)
BUFFER_TIER_STANDARD   = "standard"    # 9MB–64MB on-chip shared buffer (Trident+/II/3, Tomahawk 1-3, Cloudscale EX/FX)

# ── Known Switch Hardware Catalog & ASIC Mapping ──────────────────────────────
# Patterns matched against (model, system_desc, switch_name)
SWITCH_HARDWARE_CATALOG = [
    # ── Arista Ultra-Deep Buffer (Jericho / Jericho2 / Jericho3 / Qumran) ───────
    {
        "patterns": [r"7500R3", r"7800R3", r"7800", r"7500R2", r"7500R", r"7504R", r"7508R", r"7512R", r"7516R", r"DCS-750", r"DCS-780"],
        "vendor": "Arista",
        "asic_family": "Broadcom Jericho2 / Jericho3 (VOQ)",
        "buffer_tier": BUFFER_TIER_ULTRA_DEEP,
        "buffer_desc": "Up to 32 GB VOQ Packet Buffer (External HBM/DRAM)",
        "form_factor": "modular_chassis",
        "is_high_radix": True,
    },
    {
        "patterns": [r"7280R3", r"7280R2", r"7280R", r"7280SR", r"7280CR", r"7280PR", r"7280TR", r"DCS-7280", r"7020R", r"7020SR", r"DCS-7020R"],
        "vendor": "Arista",
        "asic_family": "Broadcom Jericho2 / Qumran2c (VOQ)",
        "buffer_tier": BUFFER_TIER_ULTRA_DEEP,
        "buffer_desc": "4–16 GB VOQ Packet Buffer (External DRAM)",
        "form_factor": "fixed_1ru",
        "is_high_radix": False,
    },
    # ── Arista Deep Buffer (Trident 4 / Tomahawk 4 / 5) ─────────────────────────
    {
        "patterns": [r"7050X4", r"7060X5", r"7300X4", r"DCS-7050X4", r"DCS-7060X5"],
        "vendor": "Arista",
        "asic_family": "Broadcom Trident 4 / Tomahawk 4 (132 MB Shared)",
        "buffer_tier": BUFFER_TIER_DEEP,
        "buffer_desc": "132 MB On-Chip Unified Shared Buffer",
        "form_factor": "fixed_1ru",
        "is_high_radix": True,
    },
    # ── Arista Modular Chassis (Legacy 7500/7300) ──────────────────────────────
    {
        "patterns": [r"7504", r"7508", r"7512", r"7304", r"7308", r"7324", r"7328", r"7500E"],
        "vendor": "Arista",
        "asic_family": "Virtual Output Port (VoQ) Multi-ASIC",
        "buffer_tier": BUFFER_TIER_ULTRA_DEEP,
        "buffer_desc": "3 GB+ per Line Card (External Buffer)",
        "form_factor": "modular_chassis",
        "is_high_radix": True,
    },
    # ── Arista Standard Fixed Leaf (7050 / 7060 / 7150) ────────────────────────
    {
        "patterns": [r"7050", r"7060", r"7150", r"7010", r"7250"],
        "vendor": "Arista",
        "asic_family": "Broadcom Trident II/3 / Tomahawk",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "12–32 MB On-Chip Shared Buffer",
        "form_factor": "fixed_1ru",
        "is_high_radix": False,
    },

    # ── Cisco Ultra-Deep Buffer (Jericho / Silicon One / NCS) ──────────────────
    {
        "patterns": [r"N9K-X9636C-R", r"N9K-C9636C-R", r"N9K-X9636Q-R", r"Nexus 9300-R", r"Nexus 9500-R", r"9300-R", r"9500-R"],
        "vendor": "Cisco",
        "asic_family": "Broadcom Jericho+ / Jericho2 (VOQ)",
        "buffer_tier": BUFFER_TIER_ULTRA_DEEP,
        "buffer_desc": "4–8 GB Deep Packet Buffer per ASIC",
        "form_factor": "fixed_1ru",
        "is_high_radix": False,
    },
    {
        "patterns": [r"Cisco 8201", r"Cisco 8202", r"Cisco 8800", r"8804", r"8808", r"8812", r"8818", r"Cisco 8000"],
        "vendor": "Cisco",
        "asic_family": "Cisco Silicon One Q100/Q200 (HBM Deep Buffer)",
        "buffer_tier": BUFFER_TIER_ULTRA_DEEP,
        "buffer_desc": "Integrated High Bandwidth Memory (HBM) Deep Buffer",
        "form_factor": "modular_chassis",
        "is_high_radix": True,
    },
    {
        "patterns": [r"NCS-5500", r"NCS-5501", r"NCS-55A1", r"NCS-540", r"NCS-560", r"NCS-5700", r"NCS 55", r"NCS 54", r"NCS 57"],
        "vendor": "Cisco",
        "asic_family": "Broadcom Jericho / Jericho2 (VOQ)",
        "buffer_tier": BUFFER_TIER_ULTRA_DEEP,
        "buffer_desc": "Up to 8 GB External GDDR5/DDR4 VOQ Buffer",
        "form_factor": "fixed_1ru",
        "is_high_radix": False,
    },
    # ── Cisco Deep Buffer (CloudScale GX2 / 9300-GX) ───────────────────────────
    {
        "patterns": [r"9332D-GX2", r"9364C-GX", r"93180YC-GX", r"Nexus 9300-GX", r"GX2A", r"GX2B"],
        "vendor": "Cisco",
        "asic_family": "Cisco CloudScale GX2 (80–250 MB Shared)",
        "buffer_tier": BUFFER_TIER_DEEP,
        "buffer_desc": "80–250 MB On-Chip Shared Packet Buffer",
        "form_factor": "fixed_1ru",
        "is_high_radix": True,
    },
    # ── Cisco Modular Chassis (Nexus 7000 / 7700 / 9500 / 6500 / Cat 9600) ───
    {
        "patterns": [r"Nexus 7000", r"Nexus 7700", r"Nexus 77\d{2}", r"Nexus 70\d{2}", r"N7K", r"N77", r"Nexus 9500", r"Nexus 95\d{2}", r"N95", r"Catalyst 9600", r"Catalyst 6500", r"WS-C65", r"C9600"],
        "vendor": "Cisco",
        "asic_family": "Cisco Modular Fabric Architecture",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "Modular Crossbar / VoQ Line Card Architecture",
        "form_factor": "modular_chassis",
        "is_high_radix": True,
    },
    # ── Cisco Nexus 2000 / FEX (Fabric Extender) ──────────────────────────────
    {
        "patterns": [r"Nexus 2000", r"Nexus 2\d{3}", r"N2K", r"N2248", r"N2232", r"N2224", r"N2348", r"Fabric Extender", r"FEX"],
        "vendor": "Cisco",
        "asic_family": "Cisco Fabric Extender (Unbuffered / Remote Line Card)",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "Unbuffered Port Multiplier (Oversubscribed Uplinks)",
        "form_factor": "fixed_1ru",
        "is_high_radix": False,
        "is_fex": True,
    },
    # ── Cisco Standard Fixed ToR (Nexus 9300 / 5000 / 3000) ────────────────────
    {
        "patterns": [r"Nexus 9300", r"Nexus 93\d{2}", r"Nexus 5000", r"Nexus 55\d{2}", r"Nexus 56\d{2}", r"Nexus 3000", r"Nexus 31\d{2}", r"Nexus 32\d{2}", r"Nexus 3064", r"N9K", r"N5K", r"N3K"],
        "vendor": "Cisco",
        "asic_family": "Cisco CloudScale / Algoboost / Trident",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "12–40 MB On-Chip Shared Buffer",
        "form_factor": "fixed_1ru",
        "is_high_radix": False,
    },

    # ── Juniper Ultra-Deep Buffer (Q5 / HMC) ───────────────────────────────────
    {
        "patterns": [r"QFX10002", r"QFX10008", r"QFX10016", r"PTX1000", r"PTX10008", r"PTX10016", r"QFX10000"],
        "vendor": "Juniper",
        "asic_family": "Juniper Q5 ASIC (Hybrid Memory Cube / HMC)",
        "buffer_tier": BUFFER_TIER_ULTRA_DEEP,
        "buffer_desc": "3 GB to 64 GB HMC Ultra-Deep Packet Buffer",
        "form_factor": "modular_chassis" if any(x in ["QFX10008", "QFX10016", "PTX10008", "PTX10016"] for x in ["QFX10008"]) else "fixed_1ru",
        "is_high_radix": True,
    },
    # ── Juniper Standard Leaf (QFX5100 / QFX5120 / QFX5200) ───────────────────
    {
        "patterns": [r"QFX5100", r"QFX5110", r"QFX5120", r"QFX5200", r"QFX5210", r"QFX5220", r"EX4300", r"EX4600"],
        "vendor": "Juniper",
        "asic_family": "Broadcom Trident II/3 / Tomahawk",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "12–32 MB On-Chip Shared Buffer",
        "form_factor": "fixed_1ru",
        "is_high_radix": False,
    },

    # ── Dell PowerSwitch (S-Series / Z-Series) ─────────────────────────────────
    {
        "patterns": [r"S5248", r"S5232", r"S5296", r"S5200", r"S5448", r"S5400", r"Z9264", r"Z9332", r"Z9432"],
        "vendor": "Dell",
        "asic_family": "Broadcom Trident 3 / Trident 4 / Tomahawk 3",
        "buffer_tier": BUFFER_TIER_DEEP if any(x in ["S54", "Z94"] for x in ["S54"]) else BUFFER_TIER_STANDARD,
        "buffer_desc": "32–132 MB On-Chip Shared Buffer",
        "form_factor": "fixed_1ru",
        "is_high_radix": bool(any(x in ["Z9264", "Z9332", "Z9432", "S5232"] for x in ["Z9264"])),
    },
    {
        "patterns": [r"S4048", r"S4148", r"S4128", r"S4810", r"S4820", r"S6000", r"S6100", r"S5048", r"S3048", r"N3048", r"N4032"],
        "vendor": "Dell",
        "asic_family": "Broadcom Trident+ / Trident II / Trident 3",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "9–32 MB On-Chip Shared Buffer",
        "form_factor": "fixed_1ru",
        "is_high_radix": False,
    },

    # ── HPE / Aruba CX ────────────────────────────────────────────────────────
    {
        "patterns": [r"Aruba 8400", r"FlexFabric 12900", r"FlexFabric 12500", r"FlexFabric 10500", r"12900", r"12500", r"10500"],
        "vendor": "HPE",
        "asic_family": "Modular Crossbar Switching Architecture",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "Modular Line Card Distributed Buffers",
        "form_factor": "modular_chassis",
        "is_high_radix": True,
    },
    {
        "patterns": [r"Aruba 8325", r"Aruba 8320", r"Aruba 8360", r"FlexFabric 5900", r"FlexFabric 5940", r"FlexFabric 5950", r"5900AF", r"5940", r"5950"],
        "vendor": "HPE",
        "asic_family": "Broadcom Trident II/3 / Tomahawk",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "12–32 MB On-Chip Shared Buffer",
        "form_factor": "fixed_1ru",
        "is_high_radix": False,
    },

    # ── Dell PowerEdge MX / Modular Chassis Fabric Modules ──────────────────────
    {
        "patterns": [r"MX9116n", r"MX9116", r"PowerEdge MX9116n"],
        "vendor": "Dell",
        "asic_family": "Broadcom Trident 3 (MX Fabric Switching Engine)",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "32 MB Unified Packet Buffer (25GbE / 100GbE FSE)",
        "form_factor": "modular_chassis",
        "is_high_radix": True,
    },
    {
        "patterns": [r"MX7116n", r"MX7116", r"PowerEdge MX7116n"],
        "vendor": "Dell",
        "asic_family": "Direct Fabric Expander Module (FEM)",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "Zero-Latency Direct Fabric Expander to MX9116n FSE",
        "form_factor": "modular_chassis",
        "is_high_radix": False,
    },
    {
        "patterns": [r"MX5108n", r"MX5108", r"PowerEdge MX5108n"],
        "vendor": "Dell",
        "asic_family": "Broadcom Trident 3 (MX Ethernet Switch)",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "25GbE / 10GbE Unified Chassis Switch",
        "form_factor": "modular_chassis",
        "is_high_radix": False,
    },
    {
        "patterns": [r"MXG610s", r"MXG610", r"PowerEdge MXG610s"],
        "vendor": "Brocade / Dell",
        "asic_family": "Brocade Gen 6 FC ASIC (Condor 4)",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "32G Fibre Channel SAN Fabric Switch for MX7000",
        "form_factor": "modular_chassis",
        "is_high_radix": False,
    },
    {
        "patterns": [r"Force10 MXL", r"M8024-k", r"M8024", r"M6348", r"FN410s", r"FN410t", r"FN2210s"],
        "vendor": "Dell",
        "asic_family": "Dell PowerEdge M1000e / FX2 Fabric IOM",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "10GbE / 40GbE Chassis Fabric Switch Module",
        "form_factor": "modular_chassis",
        "is_high_radix": False,
    },

    # ── HPE Synergy Virtual Connect Modules ───────────────────────────────────
    {
        "patterns": [r"Virtual Connect SE 100Gb", r"VC SE 100Gb", r"F32 Module", r"Synergy 100Gb"],
        "vendor": "HPE",
        "asic_family": "Broadcom Tomahawk / Trident 3 (Virtual Connect)",
        "buffer_tier": BUFFER_TIER_DEEP,
        "buffer_desc": "100GbE High-Performance Virtual Connect Fabric",
        "form_factor": "modular_chassis",
        "is_high_radix": True,
    },
    {
        "patterns": [r"Virtual Connect SE 40Gb", r"VC SE 40Gb", r"F8 Module", r"Virtual Connect SE 16Gb", r"Virtual Connect SE 32Gb", r"Synergy 10Gb", r"Synergy 20Gb"],
        "vendor": "HPE",
        "asic_family": "HPE Synergy Virtual Connect Fabric Architecture",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "Converged Virtual Connect Ethernet & FC Fabric",
        "form_factor": "modular_chassis",
        "is_high_radix": False,
    },

    # ── Cisco UCS Fabric Interconnects & IOMs ──────────────────────────────────
    {
        "patterns": [r"UCS-FI-6536", r"UCS 6536", r"UCS-FI-6454", r"UCS 6454", r"UCS-FI-6332", r"UCS 6332", r"UCS 6248", r"UCS 6296"],
        "vendor": "Cisco",
        "asic_family": "Cisco Unified Computing Fabric Architecture",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "Unified Ethernet & Fibre Channel Fabric Interconnect",
        "form_factor": "modular_chassis",
        "is_high_radix": True,
    },
    {
        "patterns": [r"UCS 2408", r"UCS-IOM-2408", r"UCS 2208", r"UCS 2204", r"UCS-IOM-2208", r"UCS-IOM-2204"],
        "vendor": "Cisco",
        "asic_family": "Cisco UCS Chassis IOM (Fabric Multiplexer)",
        "buffer_tier": BUFFER_TIER_STANDARD,
        "buffer_desc": "Chassis Fabric Multiplexer to UCS Fabric Interconnect",
        "form_factor": "modular_chassis",
        "is_high_radix": False,
    },

    # ── Edgecore / Whitebox Deep Buffer (Qumran / Jericho) ─────────────────────
    {
        "patterns": [r"AS5916", r"AS7316", r"AGR130", r"CSR320", r"S9510", r"AS7816"],
        "vendor": "Edgecore",
        "asic_family": "Broadcom Qumran-AX / Qumran-MX (VOQ)",
        "buffer_tier": BUFFER_TIER_ULTRA_DEEP,
        "buffer_desc": "2–8 GB Deep Packet Buffer (External DRAM)",
        "form_factor": "fixed_1ru",
        "is_high_radix": False,
    },
]


def detect_fex(switch_name: str, system_desc: str, port_names: Optional[List[str]] = None) -> Tuple[bool, str]:
    """Detect if a switch or connected port is a Cisco Nexus 2000 / Fabric Extender (FEX).

    Returns (is_fex, reason_text).
    """
    s_name = str(switch_name or "").strip()
    s_desc = str(system_desc or "").strip()
    full_text = f"{s_name} {s_desc}".lower()

    # 1. Model / System description matching FEX tokens
    fex_kw = ["nexus 2000", "nexus2000", "n2k", "n2248", "n2232", "n2224", "n2348", "fabric extender"]
    for kw in fex_kw:
        if kw in full_text:
            return True, f"Identified via switch description/model matching '{kw.upper()}'."

    # 2. Port naming convention matching Cisco FEX chassis slots 100..199
    # e.g., Ethernet101/1/1, Eth102/1/12, port 101/1/1, Eth 150/1/1
    fex_port_regex = re.compile(r'(?:ethernet|eth|port|gigabitethernet|tengigabitethernet)?\s*1\d{2}/\d+/\d+', re.IGNORECASE)
    fex_port_short_regex = re.compile(r'(?:ethernet|eth|port)?\s*1\d{2}/\d+', re.IGNORECASE)

    if port_names:
        for p in port_names:
            p_str = str(p or "").strip()
            if fex_port_regex.search(p_str) or fex_port_short_regex.search(p_str):
                return True, f"Connected port '{p_str}' matches Cisco FEX remote slot numbering (100–199)."

    return False, ""


def classify_switch(
    switch_name: str,
    chassis_id: str = "",
    system_desc: str = "",
    port_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Classify switch hardware, buffer tier, form factor, and FEX characteristics."""
    s_name = str(switch_name or "").strip()
    s_desc = str(system_desc or "").strip()
    s_chassis = str(chassis_id or "").strip()
    combined_meta = f"{s_name} {s_desc}".strip()

    # Default baseline classification
    vendor = "Generic / Unknown"
    asic_family = "DMTF Standard Switch Silicon"
    buffer_tier = BUFFER_TIER_STANDARD
    buffer_desc = "Standard DC Shared Memory Buffer"
    form_factor = "fixed_1ru"
    is_high_radix = False
    is_fex = False
    fex_reason = ""

    # Check FEX first
    is_fex, fex_reason = detect_fex(s_name, s_desc, port_names)
    if is_fex:
        vendor = "Cisco"
        asic_family = "Cisco Fabric Extender (FEX)"
        form_factor = "fixed_1ru"
        buffer_desc = "Unbuffered Port Multiplier (Shared Uplinks)"

    # Match against catalog
    if not is_fex:
        for entry in SWITCH_HARDWARE_CATALOG:
            matched = False
            entry_pats = entry.get("patterns")
            if isinstance(entry_pats, (list, tuple)):
                for pat in entry_pats:
                    if isinstance(pat, str) and re.search(pat, combined_meta, re.IGNORECASE):
                        matched = True
                        break
            if matched:
                vendor = str(entry.get("vendor", "Generic / Unknown"))
                asic_family = str(entry.get("asic_family", "Generic / Merchant Silicon"))
                buffer_tier = str(entry.get("buffer_tier", BUFFER_TIER_STANDARD))
                buffer_desc = str(entry.get("buffer_desc", "Standard Packet Buffer"))
                form_factor = str(entry.get("form_factor", "fixed_1ru"))
                is_high_radix = bool(entry.get("is_high_radix", False))
                if entry.get("is_fex"):
                    is_fex = True
                    fex_reason = "Identified via switch hardware catalog pattern."
                break

    # Infer vendor if still unknown
    if vendor == "Generic / Unknown":
        if any(x in combined_meta.lower() for x in ["cisco", "nexus", "catalyst", "ios", "nx-os"]):
            vendor = "Cisco"
        elif any(x in combined_meta.lower() for x in ["arista", "eos"]):
            vendor = "Arista"
        elif any(x in combined_meta.lower() for x in ["juniper", "junos", "qfx"]):
            vendor = "Juniper"
        elif any(x in combined_meta.lower() for x in ["dell", "poweredge", "os10", "force10"]):
            vendor = "Dell"
        elif any(x in combined_meta.lower() for x in ["hpe", "aruba", "procurve", "comware"]):
            vendor = "HPE"

    # Check Modular Chassis triggers
    chassis_triggers = [
        "nexus 7000", "nexus 7700", "nexus 9500", "n7k", "n77", "n95",
        "catalyst 9600", "catalyst 6500", "cisco 8800", "7500", "7800", "7300",
        "qfx10008", "qfx10016", "ex9200", "mx480", "mx960", "aruba 8400", "12900"
    ]
    if any(t in combined_meta.lower() for t in chassis_triggers):
        form_factor = "modular_chassis"
        is_high_radix = True

    # Badges HTML
    badges_html: List[str] = []
    if is_fex:
        badges_html.append(
            "<span class='badge warning' style='font-size:.76rem;padding:.2rem .45rem' "
            "title='Cisco Fabric Extender (Nexus 2000 / FEX) detected. Shared uplink oversubscription without local switching.'>"
            "⚠️ Potential Cisco FEX"
            "</span>"
        )
    elif buffer_tier == BUFFER_TIER_ULTRA_DEEP:
        badges_html.append(
            "<span class='badge success' style='font-size:.76rem;padding:.2rem .45rem' "
            f"title='{html.escape(str(buffer_desc))} — VOQ architecture absorbs microbursts for vSAN ESA & NVMe-oF.'>"
            "🛡️ Ultra-Deep Buffer (VOQ)"
            "</span>"
        )
    elif buffer_tier == BUFFER_TIER_DEEP:
        badges_html.append(
            "<span class='badge success' style='font-size:.76rem;padding:.2rem .45rem' "
            f"title='{html.escape(str(buffer_desc))} — 100MB+ high-capacity unified on-chip shared packet buffer.'>"
            "🛡️ Deep Buffer"
            "</span>"
        )

    if form_factor == "modular_chassis" or is_high_radix:
        badges_html.append(
            "<span class='badge info' style='font-size:.76rem;padding:.2rem .45rem' "
            "title='High Radix Modular Chassis / Spine Switch with high port density.'>"
            "🏢 High Radix / Modular Chassis"
            "</span>"
        )

    return {
        "vendor": vendor,
        "asic_family": asic_family,
        "buffer_tier": buffer_tier,
        "buffer_desc": buffer_desc,
        "form_factor": form_factor,
        "is_chassis": (form_factor == "modular_chassis"),
        "is_high_radix": is_high_radix,
        "is_fex": is_fex,
        "fex_reason": fex_reason,
        "badges_html": " ".join(badges_html),
    }


def build_fleet_switch_topology(all_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate LLDP/CDP connections across all hosts in a fleet scan.

    Returns:
      {
        "switches": dict of switch_id -> switch_summary_dict,
        "leaf_pairs": list of dicts describing detected ToR leaf switch pairs,
        "single_switches": list of switch_ids not paired,
        "dual_homed_hosts": list of hostname/IP strings,
        "single_homed_hosts": list of hostname/IP strings,
        "fex_attached_hosts": list of hostname/IP strings,
        "miscabled_hosts": list of hostname/IP strings,
        "stats": {
           "total_switches": int,
           "tor_switches_count": int,
           "mgmt_switches_count": int,
           "leaf_pairs_count": int,
           "dual_homed_count": int,
           "single_homed_count": int,
           "redundancy_pct": float,
           "deep_buffer_count": int,
           "fex_count": int,
        }
      }
    """
    switches: Dict[str, Dict[str, Any]] = {}
    host_to_switches: Dict[str, Set[str]] = {}
    host_to_hs_switches: Dict[str, Set[str]] = {}
    host_meta: Dict[str, Dict[str, Any]] = {}

    for res in (all_results or []):
        if not isinstance(res, dict):
            continue
        sys_data = res.get("system") or {}
        hostname = str(sys_data.get("hostname") or sys_data.get("ip") or "Unknown-Host").strip()
        host_ip = str(sys_data.get("ip") or sys_data.get("bmc_ip") or "").strip()
        host_vendor = str(sys_data.get("vendor") or "Unknown").strip()
        host_model = str(sys_data.get("model") or "").strip()

        host_meta[hostname] = {
            "hostname": hostname,
            "ip": host_ip,
            "vendor": host_vendor,
            "model": host_model,
        }
        host_to_switches.setdefault(hostname, set())
        host_to_hs_switches.setdefault(hostname, set())

        lldp_list = res.get("lldp_neighbors") or []
        for n in lldp_list:
            if not isinstance(n, dict):
                continue
            sw_name = str(n.get("switch_name") or "").strip()
            ch_id = str(n.get("chassis_id") or "").strip()
            sw_port = str(n.get("switch_port") or "").strip()
            local_iface = str(n.get("local_iface") or "").strip()
            local_mac = str(n.get("local_mac") or "").strip()
            mgmt_ip = str(n.get("mgmt_ipv4") or "").strip()
            sys_desc = str(n.get("system_desc") or "").strip()
            source = str(n.get("source") or "nic").strip().lower()

            # Canonical switch key: Prefer non-empty switch hostname, fallback to chassis MAC
            sw_key = sw_name or ch_id
            if not sw_key:
                continue

            host_to_switches[hostname].add(sw_key)
            if source != "mgmt":
                host_to_hs_switches[hostname].add(sw_key)

            mgmt_ipv6 = str(n.get("mgmt_ipv6") or "").strip()
            vlan_id = n.get("management_vlan_id")

            if sw_key not in switches:
                switches[sw_key] = {
                    "switch_id": sw_key,
                    "switch_name": sw_name or "Unknown Hostname",
                    "chassis_id": ch_id,
                    "mgmt_ipv4": mgmt_ip,
                    "mgmt_ipv6": mgmt_ipv6,
                    "management_vlan_id": vlan_id,
                    "system_desc": sys_desc,
                    "sources": set(),
                    "ports": set(),
                    "connected_hosts": set(),
                    "connections": [],
                }

            sw = switches[sw_key]
            sw["sources"].add(source)
            if sw_port:
                sw["ports"].add(sw_port)
            if ch_id and not sw["chassis_id"]:
                sw["chassis_id"] = ch_id
            if mgmt_ip and not sw["mgmt_ipv4"]:
                sw["mgmt_ipv4"] = mgmt_ip
            if mgmt_ipv6 and not sw.get("mgmt_ipv6"):
                sw["mgmt_ipv6"] = mgmt_ipv6
            if vlan_id is not None and sw.get("management_vlan_id") is None:
                sw["management_vlan_id"] = vlan_id
            if sys_desc and (not sw["system_desc"] or len(sys_desc) > len(sw["system_desc"])):
                sw["system_desc"] = sys_desc

            sw["connected_hosts"].add(hostname)
            sw["connections"].append({
                "hostname": hostname,
                "host_ip": host_ip,
                "local_iface": local_iface,
                "local_mac": local_mac,
                "switch_port": sw_port,
                "management_vlan_id": vlan_id,
                "mgmt_ipv6": mgmt_ipv6,
                "source": source,
            })

    # Classify each switch
    deep_buffer_count = 0
    fex_count = 0
    tor_switches_count = 0
    mgmt_switches_count = 0

    for sw_key, sw in switches.items():
        port_list = sorted(list(sw["ports"]))
        classification = classify_switch(
            switch_name=sw["switch_name"],
            chassis_id=sw["chassis_id"],
            system_desc=sw["system_desc"],
            port_names=port_list,
        )
        sw.update(classification)

        # Determine switch role
        sources = sw["sources"]
        if "nic" in sources and "mgmt" in sources:
            sw["role"] = "Hybrid / Shared LOM"
            sw["role_tag"] = "hybrid"
            tor_switches_count += 1
        elif "nic" in sources:
            sw["role"] = "ToR High-Speed Leaf"
            sw["role_tag"] = "tor"
            tor_switches_count += 1
        else:
            sw["role"] = "Dedicated Management / OOB"
            sw["role_tag"] = "mgmt"
            mgmt_switches_count += 1

        if sw.get("buffer_tier") in (BUFFER_TIER_ULTRA_DEEP, BUFFER_TIER_DEEP):
            deep_buffer_count += 1
        if sw.get("is_fex"):
            fex_count += 1

    # ── ToR Leaf Pair Correlation Algorithm ───────────────────────────────────
    # Score pairs of ToR switches based on host co-occurrence
    high_speed_keys = [k for k, s in switches.items() if s.get("role_tag") in ("tor", "hybrid")]
    pair_candidates: List[Tuple[int, str, str, List[str]]] = []

    for i in range(len(high_speed_keys)):
        for j in range(i + 1, len(high_speed_keys)):
            sw_a = high_speed_keys[i]
            sw_b = high_speed_keys[j]
            hosts_a = switches[sw_a]["connected_hosts"]
            hosts_b = switches[sw_b]["connected_hosts"]
            common_hosts = sorted(list(hosts_a.intersection(hosts_b)))
            if len(common_hosts) >= 2 or (len(common_hosts) == 1 and len(all_results) <= 2):
                pair_candidates.append((len(common_hosts), sw_a, sw_b, common_hosts))

    # Sort pair candidates descending by co-occurrence count
    pair_candidates.sort(key=lambda x: x[0], reverse=True)

    paired_switches: Set[str] = set()
    leaf_pairs: List[Dict[str, Any]] = []

    for score, sw_a, sw_b, common_hosts in pair_candidates:
        if sw_a in paired_switches or sw_b in paired_switches:
            continue
        paired_switches.add(sw_a)
        paired_switches.add(sw_b)

        all_pair_hosts = sorted(list(switches[sw_a]["connected_hosts"].union(switches[sw_b]["connected_hosts"])))
        single_sw_a_hosts = sorted(list(switches[sw_a]["connected_hosts"] - set(common_hosts)))
        single_sw_b_hosts = sorted(list(switches[sw_b]["connected_hosts"] - set(common_hosts)))

        leaf_pairs.append({
            "pair_id": f"PAIR-{sw_a[:6]}-{sw_b[:6]}",
            "switch_a": switches[sw_a],
            "switch_b": switches[sw_b],
            "dual_homed_hosts": common_hosts,
            "single_homed_a_hosts": single_sw_a_hosts,
            "single_homed_b_hosts": single_sw_b_hosts,
            "all_hosts": all_pair_hosts,
            "co_occurrence_count": len(common_hosts),
        })

    single_switches = [k for k in high_speed_keys if k not in paired_switches]

    # ── Host Redundancy & Cabling Audits ──────────────────────────────────────
    dual_homed_hosts: List[str] = []
    single_homed_hosts: List[str] = []
    fex_attached_hosts: List[str] = []
    miscabled_hosts: List[str] = []

    for hostname, sw_set in host_to_hs_switches.items():
        if len(sw_set) >= 2:
            dual_homed_hosts.append(hostname)
        elif len(sw_set) == 1:
            single_homed_hosts.append(hostname)
            # Check if host has multiple NICs on the same single switch (mis-cabled)
            sw_key = list(sw_set)[0]
            host_conns = [c for c in switches[sw_key]["connections"] if c["hostname"] == hostname and c["source"] == "nic"]
            if len(host_conns) >= 2:
                miscabled_hosts.append(hostname)

        # Check if connected to any FEX
        for sw_k in sw_set:
            if switches.get(sw_k, {}).get("is_fex"):
                if hostname not in fex_attached_hosts:
                    fex_attached_hosts.append(hostname)

    total_scanned_hosts = len(all_results)
    redundancy_pct = (len(dual_homed_hosts) / total_scanned_hosts * 100.0) if total_scanned_hosts > 0 else 0.0

    return {
        "switches": switches,
        "leaf_pairs": leaf_pairs,
        "single_switches": single_switches,
        "dual_homed_hosts": sorted(dual_homed_hosts),
        "single_homed_hosts": sorted(single_homed_hosts),
        "fex_attached_hosts": sorted(fex_attached_hosts),
        "miscabled_hosts": sorted(miscabled_hosts),
        "stats": {
            "total_switches": len(switches),
            "tor_switches_count": tor_switches_count,
            "mgmt_switches_count": mgmt_switches_count,
            "leaf_pairs_count": len(leaf_pairs),
            "dual_homed_count": len(dual_homed_hosts),
            "single_homed_count": len(single_homed_hosts),
            "redundancy_pct": round(redundancy_pct, 1),
            "deep_buffer_count": deep_buffer_count,
            "fex_count": fex_count,
        },
    }
