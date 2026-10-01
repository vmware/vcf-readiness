"""
CPU architecture, EVC baseline, and NUMA/chiplet profile evaluation for VCF 9.1.
"""
import re

from .chassis import _is_oem_chassis_certified


def evaluate_cpu(cpu_model: str, vendor: str = "", model: str = "") -> tuple:
    """Returns (badge_html, arch_label, channels_per_socket, max_ram_speed_mhz, max_pcie_lanes_per_socket)."""
    s = str(cpu_model).upper()

    # ── 1. Embedded & Microserver CPUs (Check BEFORE generic family matchers) ──────────
    # AMD Ryzen Embedded (V1000/V1500/V2000/V3000/R1000 e.g. V1500B, V1807B, V3C64, R1606G)
    if re.search(r"\b(V1\d{3}|V2\d{3}|V3\d{3}|R1\d{3}|V1500B|V1807B|V3C64|R1606G)\b", s) or "RYZEN EMBEDDED" in s:
        return "\U0001f534 Not VCF-Eligible", "AMD Ryzen Embedded SOC (Dual-Channel DDR4)", 2, 3200, 16

    # AMD EPYC Embedded 3000 Series (3101, 3201, 3251, 3301, 3401, 3451)
    if re.search(r"\bEPYC\s*3\d{3}\b|\b(3101|3201|3251|3301|3401|3451)\b", s) or "EPYC EMBEDDED 3" in s:
        return "\U0001f534 Unsupported for VCF 9.x", "AMD EPYC Embedded 3000 Series (4 Channel DDR4)", 4, 2666, 64

    # Intel Xeon D-1700 / D-2700 / D-2800 / D-1800 (Ice Lake-D 4-Channel)
    # D-1700: 32 lanes PCIe 4.0; D-2700: 64 lanes PCIe 4.0 — use 64 to cover D-2700
    if re.search(r"\bXEON\s+D[-\s]?(17|27|28|18)\d\d", s) or re.search(r"\bD-(17|27|28|18)\d\d", s) or "ICE LAKE-D" in s:
        return "\U0001f7e1 Deprecated Mode", "Intel Xeon D (Ice Lake-D 4 Channel DDR4)", 4, 2933, 64

    # Intel Xeon D-1500 / D-1600 / D-2100 (Broadwell-DE / Skylake-D 2-Channel)
    if re.search(r"\bXEON\s+D[-\s]?(15|16|21)\d\d", s) or re.search(r"\bD-(15|16|21)\d\d", s) or "BROADWELL-DE" in s:
        return "\U0001f534 Unsupported for VCF 9.x", "Intel Xeon D-1500/1600 (Broadwell-DE Microserver)", 2, 2400, 16

    # Intel Xeon E / Xeon E3 (Entry Workstation / Server Platform)
    if re.search(r"\bE3-1\d{3}", s) or re.search(r"\bXEON\s+E[-\s]?2[123]\d\d", s):
        return "\U0001f534 Unsupported for VCF 9.x", "Intel Xeon E/E3 Entry Platform (Dual-Channel)", 2, 3200, 16

    # Intel Atom Microserver / Networking SOC (Denverton / Snow Ridge / C3000 / P5000)
    if any(k in s for k in ["DENVERTON", "SNOW RIDGE"]) or re.search(r"\bATOM\b|\bC3[3579]\d\d\b|\bP59?\d\d\b", s):
        return "\U0001f534 Unsupported for VCF 9.x", "Intel Atom Microserver/Networking SOC", 2, 2400, 16


    # ── 2. AMD EPYC Server Processors ──────────────────────────────────────────
    # AMD EPYC 9005 Series (Turin) — 160 PCIe 5.0 lanes
    if re.search(r"EPYC\s*9\d\d5|TURIN", s) or "9005" in s:
        return "\U0001f7e2 Fully Supported", "AMD EPYC 9005 Turin Series (12 Channel DDR5)", 12, 6400, 160

    # AMD EPYC 9004 Series (Genoa / Bergamot / Genoa-X) — 128 PCIe 5.0 lanes
    if re.search(r"EPYC\s*9\d\d4|GENOA|BERGAMOT", s) or "9004" in s:
        return "\U0001f7e2 Fully Supported", "AMD EPYC 9004 Genoa/Bergamo Series (12 Channel DDR5)", 12, 4800, 128

    # AMD EPYC 8004 Series (Siena) — 96 PCIe 5.0 lanes
    if re.search(r"EPYC\s*8\d\d4|SIENA", s) or "8004" in s:
        return "\U0001f7e2 Fully Supported", "AMD EPYC 8004 Siena Series (6 Channel DDR5)", 6, 4800, 96

    # AMD EPYC 7002 / 7003 Series (Rome / Milan) — 128 PCIe 4.0 lanes
    if re.search(r"EPYC\s*7\d\d[23]|ROME|MILAN", s) or any(k in s for k in ["7002", "7003"]):
        return "\U0001f7e2 Fully Supported", "AMD EPYC 7002/7003 Rome/Milan Series (8 Channel DDR4)", 8, 3200, 128

    # AMD EPYC 7001 Series (Naples) — 128 PCIe 3.0 lanes
    if re.search(r"EPYC\s*7\d\d1|NAPLES", s) or "7001" in s:
        return "\U0001f7e2 Fully Supported", "AMD EPYC 7001 Naples Series (8 Channel DDR4)", 8, 2666, 128


    # ── 3. Intel Xeon 6 / Granite Rapids / Sierra Forest ────────────────────────
    # Xeon 6900 Series (LGA 7529 Granite Rapids-AP) — 96 PCIe 5.0 lanes
    if re.search(r"\b69\d\d[PE]\b", s) or re.search(r"\bXEON\s*6\s*69\d\d\b", s) or any(k in s for k in ["6900P", "6900E", "XEON 6900", "GRANITE RAPIDS-AP"]):
        return "\U0001f7e2 Fully Supported", "Intel Xeon 6 6900 Series (12 Channel DDR5 / MRDIMM)", 12, 6400, 96

    # Xeon 6700 / 6500 Series (Granite Rapids-SP / Sierra Forest) — 80 PCIe 5.0 lanes
    if re.search(r"\b6[57]\d\d[PE]\b", s) or re.search(r"\bXEON\s*6\s*6[57]\d\d\b", s) or any(k in s for k in ["6700P", "6700E", "6500P", "6500E", "XEON 6700", "XEON 6500", "GRANITE RAPIDS", "SIERRA FOREST"]):
        return "\U0001f7e2 Fully Supported", "Intel Xeon 6 6700/6500 Series (8 Channel DDR5)", 8, 6400, 80


    # ── 4. Intel Xeon Scalable Generations ──────────────────────────────────────
    # 5th Gen Emerald Rapids — 80 PCIe 5.0 lanes
    if "EMERALD RAPIDS" in s or "EMERALD" in s or re.search(r"\b[34568]5\d\d[+VNYPUQFLS]*\b", s):
        return "\U0001f7e2 Fully Supported", "Intel Emerald Rapids 5th Gen (8 Channel DDR5)", 8, 5600, 80

    # 4th Gen Sapphire Rapids — 80 PCIe 5.0 lanes
    if any(k in s for k in ["SAPPHIRE RAPIDS", "SAPPHIRE"]) or re.search(r"\b[34568]4\d\d[+HMNPUVYQS]*\b", s):
        return "\U0001f7e2 Fully Supported", "Intel Sapphire Rapids 4th Gen (8 Channel DDR5)", 8, 4800, 80

    # 3rd Gen Ice Lake-SP — 64 PCIe 4.0 lanes
    if any(k in s for k in ["ICE LAKE"]) or re.search(r"\b[34568]3\d\d[+NSTUYPVQ]*\b", s):
        return "\U0001f7e2 Fully Supported", "Intel Ice Lake-SP 3rd Gen (8 Channel DDR4)", 8, 3200, 64

    # 2nd Gen Cascade Lake-SP — 48 PCIe 3.0 lanes
    if re.search(r"\b[345689]2\d\d[+UYTRLSM]*\b", s) or "CASCADE" in s or "CASCADE LAKE" in s:
        return "\U0001f7e2 VCF 9.x Supported", "Intel Cascade Lake-SP 2nd Gen (6 Channel DDR4)", 6, 2933, 48

    # 1st Gen Skylake-SP — 48 PCIe 3.0 lanes
    if re.search(r"\b[34568]1\d\d[+TFMP]*\b", s) or "SKYLAKE" in s:
        if _is_oem_chassis_certified(vendor, model):
            return "\U0001f7e1 Supported (Override Required)", "Intel Skylake-SP 1st Gen (6 Channel DDR4)", 6, 2666, 48
        return "\U0001f7e1 Supported (Override Required - Verify with OEM)", "Intel Skylake-SP 1st Gen (6 Channel DDR4)", 6, 2666, 48


    # ── 5. Legacy Intel & Consumer CPU Fallbacks ─────────────────────────────────
    # Legacy Intel (Haswell/Broadwell E5/E7 v3/v4) — 40 PCIe 3.0 lanes
    if any(k in s for k in ["HASWELL", "BROADWELL", " V3 ", " V4 ", "E5-", "E7-"]):
        return "\U0001f534 Unsupported for VCF 9.x", "Legacy Intel (Pre-Skylake 4 Channel DDR4)", 4, 2133, 40

    # Consumer Intel CPUs (Core, Celeron, Pentium, Core Ultra)
    if re.search(r"\bCORE\s+(ULTRA\s+)?(I[3579]\b|\d{3,4}[UMPHTK])", s) or \
       re.search(r"\b(CORE\s+)?(I[3579][-\s]\d{4,5})", s) or \
       any(k in s for k in ["CELERON", "PENTIUM", "CORE ULTRA"]) or \
       re.search(r"\b(CORE\s+)?I[3579]\b", s):
        return "\U0001f534 Not VCF-Eligible", "Consumer Intel CPU — VCF requires Xeon (Skylake-SP or newer)", 2, 3200, 20

    # Consumer AMD CPUs (Ryzen, Athlon, APU)
    if any(k in s for k in ["RYZEN", "ATHLON"]) or \
       re.search(r"\bA[468]-\d{4}\b", s):
        return "\U0001f534 Not VCF-Eligible", "Consumer AMD CPU — VCF requires EPYC", 2, 3200, 24

    return "\U0001f7e1 Unverified / Unknown CPU", "Unknown CPU Architecture (Manual Verification Required)", 8, 3200, 64


def get_cpu_deep_profile(cpu_model: str, arch_label: str, max_pcie_lanes: int = 64, cores_per_socket: int = 0) -> dict:
    """Return enriched CPU profile for the deep-dive accordion.

    Returns a dict with:
      evc_baseline, vendor_tier, tier_badge_class, tier_badge_html,
      numa_config, chiplet_desc, pcie_gen, typical_l3_mb, is_intel, is_amd,
      numa_topology (dict: numa_nodes_default, numa_nodes_max, chiplets_count,
                           cores_per_chiplet, cores_per_tile, has_io_die, io_dies_count,
                           die_label, die_config_name, package_socket)
    """
    s  = str(cpu_model).upper()
    al = str(arch_label).upper()

    # ── PCIe generation from lane budget ────────────────────────────────
    if max_pcie_lanes >= 80:
        pcie_gen = "PCIe 5.0"
    elif max_pcie_lanes >= 64:
        pcie_gen = "PCIe 4.0"
    else:
        pcie_gen = "PCIe 3.0"

    is_intel = "INTEL" in s or "XEON" in s
    is_amd   = "AMD" in s or "EPYC" in s

    # ── Vendor tier ─────────────────────────────────────────────────────
    tier_badge_html = ""
    vendor_tier = ""
    tier_badge_class = "info"

    if is_intel:
        _tier_m = re.search(r"\b(Platinum|Gold|Silver|Bronze)\b", cpu_model, re.I)
        if _tier_m:
            vendor_tier = _tier_m.group(1).capitalize()
            _tier_colors = {
                "Platinum": ("warning", "🥇 Platinum"),
                "Gold":     ("success", "🥈 Gold"),
                "Silver":   ("info",    "⬜ Silver"),
                "Bronze":   ("warning", "🟫 Bronze"),
            }
            tier_badge_class, _tier_label = _tier_colors.get(vendor_tier, ("info", vendor_tier))
            tier_badge_html = f"<span class='badge {tier_badge_class}'>{_tier_label} Series</span>"
        elif "XEON 6" in s or re.search(r"\b6[35679]\d\d[PE]?\b", s):
            # Xeon 6: P-core (performance) vs E-core (efficiency)
            _num_m = re.search(r"\b(6[35679]\d\d)([PE])?\b", s)
            if _num_m and _num_m.group(2) == "E":
                vendor_tier = "E-core"
                tier_badge_class = "info"
                tier_badge_html = "<span class='badge info'>⚡ Xeon 6 E-core (Efficiency)</span>"
            else:
                vendor_tier = "P-core"
                tier_badge_class = "success"
                tier_badge_html = "<span class='badge success'>🚀 Xeon 6 P-core (Performance)</span>"
    elif is_amd:
        # Derive EPYC series from the 4-digit model number's structure:
        # first digit = generation tier (7/8/9), last digit = sub-generation (1/2/3/4/5)
        # The regex must tolerate letter suffixes like P, X, F on model numbers (e.g. 8354P)
        _epyc_num_m = re.search(r"EPYC\s+(\d)(\d{2})(\d)[A-Z0-9]*", s)
        if not _epyc_num_m:
            _epyc_num_m = re.search(r"\b(\d)(\d{2})(\d)[A-Z]?\b", s)
        if _epyc_num_m:
            _gen_lead = _epyc_num_m.group(1)   # "9" / "8" / "7"
            _gen_last = _epyc_num_m.group(3)   # "5" = Turin, "4" = Genoa/Siena, "3" = Milan, "2" = Rome, "1" = Naples
            _series_lookup = {
                ("9", "5"): ("9005", "Turin",   "success"),
                ("9", "4"): ("9004", "Genoa",   "success"),
                ("8", "4"): ("8004", "Siena",   "info"),
                ("7", "3"): ("7003", "Milan",   "success"),
                ("7", "2"): ("7002", "Rome",    "success"),
                ("7", "1"): ("7001", "Naples",  "info"),
            }
            _series_info = _series_lookup.get((_gen_lead, _gen_last))
            if _series_info:
                _snum, _codename, _cls = _series_info
                # Detect Bergamo variant (9004 dense — model numbers ending in F or 128+ core variant)
                if _snum == "9004" and re.search(r"\b97\d\d\b", s):
                    _codename = "Bergamo"
                vendor_tier = f"EPYC {_snum} \u201c{_codename}\u201d"
                tier_badge_class = _cls
                tier_badge_html = f"<span class='badge {_cls}'>AMD {vendor_tier}</span>"
        if not tier_badge_html:
            vendor_tier = "EPYC"
            tier_badge_html = "<span class='badge success'>AMD EPYC</span>"

    # ── EVC baseline ────────────────────────────────────────────────────
    # Keys checked against arch_label (upper-cased) first, then cpu_model; first match wins.
    # For 7002/7003 which share an arch_label, the model number disambiguates.
    _EVC_MAP = [
        ("GRANITE RAPIDS",      "Intel\u00ae Granite Rapids Generation"),
        ("XEON 6 6900",         "Intel\u00ae Granite Rapids Generation"),
        ("XEON 6 6700",         "Intel\u00ae Granite Rapids Generation"),
        ("XEON 6 6500",         "Intel\u00ae Granite Rapids Generation"),
        ("EMERALD RAPIDS",      "Intel\u00ae Emerald Rapids Generation"),
        ("SAPPHIRE RAPIDS",     "Intel\u00ae Sapphire Rapids Generation"),
        ("ICE LAKE",            "Intel\u00ae Ice Lake Generation"),
        ("CASCADE LAKE",        "Intel\u00ae Cascade Lake Generation"),
        ("SKYLAKE",             "Intel\u00ae Skylake Generation"),
        ("XEON D",              "Intel\u00ae Skylake Generation"),
        ("TURIN",               "AMD\u00ae Turin Generation"),
        ("9005",                "AMD\u00ae Turin Generation"),
        ("GENOA",               "AMD\u00ae Genoa Generation"),
        ("BERGAMO",             "AMD\u00ae Genoa Generation"),
        ("9004",                "AMD\u00ae Genoa Generation"),
        ("SIENA",               "AMD\u00ae Genoa Generation"),
        ("8004",                "AMD\u00ae Genoa Generation"),
        ("MILAN",               "AMD\u00ae Milan Generation"),
        ("7003",                "AMD\u00ae Milan Generation"),
        ("ROME",                "AMD\u00ae Rome Generation"),
        ("7002",                "AMD\u00ae Rome Generation"),
        ("NAPLES",              "AMD\u00ae Naples Generation"),
        ("7001",                "AMD\u00ae Naples Generation"),
    ]
    evc_baseline = "Unknown"
    # For AMD 7002/7003 which share the same arch_label, derive from model number directly
    if is_amd and _epyc_num_m:
        _lead = _epyc_num_m.group(1)
        _last = _epyc_num_m.group(3)
        _evc_direct = {
            ("9", "5"): "AMD\u00ae Turin Generation",
            ("9", "4"): "AMD\u00ae Genoa Generation",
            ("8", "4"): "AMD\u00ae Genoa Generation",   # Siena shares Genoa EVC baseline in vSphere
            ("7", "3"): "AMD\u00ae Milan Generation",
            ("7", "2"): "AMD\u00ae Rome Generation",
            ("7", "1"): "AMD\u00ae Naples Generation",
        }.get((_lead, _last))
        if _evc_direct:
            evc_baseline = _evc_direct
    if evc_baseline == "Unknown":
        for _kw, _evc in _EVC_MAP:
            if _kw in al:
                evc_baseline = _evc
                break

    # ── NUMA / chiplet architecture lookup ──────────────────────────────
    numa_config = ""
    chiplet_desc = ""
    numa_topology: dict = {}

    # Check if CPU is Granite Rapids (Xeon 6 P-core)
    is_gnr_p = False
    if is_intel and ("GRANITE RAPIDS" in s or "GRANITE RAPIDS" in al or re.search(r"\b6[35679]\d\d[P]?\b", s) or "XEON 6" in s or "XEON 6" in al):
        if not (re.search(r"\b6[57]\d\dE\b", s) or "SIERRA FOREST" in s or "CRESTMONT" in s):
            is_gnr_p = True

    if is_gnr_p:
        cps = cores_per_socket
        if cps <= 0:
            if "69" in s or "6900" in al:
                cps = 128
            elif "67" in s or "6700" in al:
                cps = 64
            elif "65" in s or "6500" in al:
                cps = 32
            elif "63" in s or "6300" in al:
                cps = 16
            else:
                cps = 32

        if cps <= 20:
            die_config_name = "LCC (Low Core Count)"
            chiplets_count = 1
            cores_per_tile = [cps]
            io_dies_count = 2
            package_socket = "LGA4710s"
            dn = 1
            mn = 2
            die_lbl = "P-core Tile"
            channels = 8
        elif cps <= 48:
            die_config_name = "HCC (High Core Count)"
            chiplets_count = 1
            cores_per_tile = [cps]
            io_dies_count = 2
            package_socket = "LGA4710s"
            dn = 1
            mn = 2
            die_lbl = "P-core Tile"
            channels = 8
        elif cps <= 86:
            die_config_name = "XCC (Extreme Core Count)"
            chiplets_count = 2
            c1 = cps // 2 + cps % 2
            c2 = cps // 2
            cores_per_tile = [c1, c2]
            io_dies_count = 2
            package_socket = "LGA4710s"
            dn = 1
            mn = 4
            die_lbl = "P-core Tile"
            channels = 8
        else:  # >= 87 cores
            die_config_name = "UCC (Ultra Core Count)"
            chiplets_count = 3
            c_base = cps // 3
            c_rem = cps % 3
            cores_per_tile = [c_base + (1 if i < c_rem else 0) for i in range(3)]
            io_dies_count = 2
            package_socket = "LGA7529"
            dn = 1
            mn = 4
            die_lbl = "P-core Tile"
            channels = 12

            numa_config = f"{package_socket} · {die_config_name.split()[0]} {chiplets_count} P-core tile{'s' if chiplets_count > 1 else ''} + 2 I/O dies"

        if die_config_name.startswith("HCC"):
            tile_desc = "Single High Core Count (HCC) P-core compute tile (up to 48 cores) flanked by 2 I/O dies. All cores reside on a single compute die."
        elif die_config_name.startswith("LCC"):
            tile_desc = "Single Low Core Count (LCC) P-core compute tile (8–20 cores) flanked by 2 I/O dies."
        elif die_config_name.startswith("XCC"):
            tile_desc = "Dual Extreme Core Count (XCC) P-core compute tiles (56–86 cores) flanked by 2 I/O dies."
        else:
            tile_desc = "Triple Ultra Core Count (UCC) P-core compute tiles (96–128 cores) flanked by 2 I/O dies."

        snc_note = (
            "1 NUMA node default with SNC disabled (all compute tiles unified into 1 NUMA domain; "
            f"SNC-2{'/' if mn > 2 else ''}{'4' if mn > 2 else ''} optional via BIOS)."
        ) if mn > 1 else "1 NUMA node per socket."

        chiplet_desc = (
            f"Granite Rapids-{'AP' if 'UCC' in die_config_name else 'SP'} — {package_socket} socket. "
            f"{tile_desc} {snc_note} "
            f"{channels}-channel DDR5{' / MRDIMM' if channels == 12 else ''}."
        )

        numa_topology = {
            "numa_nodes_default": dn,
            "numa_nodes_max":     mn,
            "chiplets_count":     chiplets_count,
            "cores_per_chiplet":  cores_per_tile[0],
            "cores_per_tile":     cores_per_tile,
            "has_io_die":         True,
            "io_dies_count":      io_dies_count,
            "die_label":          die_lbl,
            "die_config_name":    die_config_name,
            "package_socket":     package_socket,
        }

    if not numa_config or not chiplet_desc:
        _NUMA_DATA = [
            ("XEON 6 6900", "LGA7529 · 4 P-core tiles + I/O die",
             "Granite Rapids-AP (GNR-AP) — LGA7529 socket. Up to 4 Redwood Cove P-core tiles per die "
             "delivering 64\u2013128 P-cores per socket. Designed for memory-bandwidth-intensive workloads; "
             "supports SNC-2/4 for sub-socket NUMA partitioning. Compatible with 12-channel DDR5/MRDIMM."),
            ("XEON 6 6700", "LGA4710s · P-core + I/O die",
             "Granite Rapids-SP (GNR-SP) — LGA4710s socket. Dual-tile design (P-core compute tile + I/O die). "
             "32\u201364 Redwood Cove P-cores per socket. 1 NUMA node default (SNC-2 optional). "
             "8-channel DDR5."),
            ("XEON 6 6500", "LGA4710s · E-core multi-tile",
             "Sierra Forest (SRF) — LGA4710s socket. Dense multi-tile E-core design (Crestmont). "
             "Up to 288 E-cores per socket optimised for cloud-native and I/O-bound workloads. "
             "2 NUMA nodes default. 8-channel DDR5."),
            ("EMERALD RAPIDS", "LGA4677 · Monolithic (EMR)",
             "Emerald Rapids (EMR) — LGA4677 socket. Refreshed monolithic die with up to 60-core SKUs. "
             "Drop-in compatible with Sapphire Rapids platforms. "
             "1 NUMA node per socket (SNC-2/4 optional via BIOS). 8-channel DDR5."),
            ("SAPPHIRE RAPIDS", "LGA4677 · 4-tile chiplet (SPR)",
             "Sapphire Rapids (SPR) — LGA4677 socket. 4-tile Golden Cove architecture with an embedded I/O die. "
             "Some SKUs support HBM2e on-package memory. "
             "1 NUMA node per socket (SNC-2/4 optional). 8-channel DDR5."),
            ("ICE LAKE", "LGA4189 · Monolithic die",
             "Ice Lake-SP (ICX) — LGA4189 socket. Monolithic Sunny Cove die. "
             "Up to 40 cores per socket. 1 NUMA node per socket (SNC-2/4 optional). "
             "8-channel DDR4-3200."),
            ("CASCADE LAKE", "LGA3647 · Monolithic die",
             "Cascade Lake-SP (CLX) — LGA3647 socket. Monolithic Skylake-derived die with AVX-512 VNNI. "
             "Up to 28 cores. 1 NUMA node per socket "
             "(Cluster-on-Die \u2014 COD \u2014 optional on \u226520-core SKUs). 6-channel DDR4-2933."),
            ("SKYLAKE", "LGA3647 · Monolithic die",
             "Skylake-SP (SKX) — LGA3647 socket. Monolithic die with AVX-512 debut. "
             "Up to 28 cores. 1 NUMA node per socket (COD optional for \u226520-core SKUs). "
             "6-channel DDR4-2666. Note: Installation and upgrade on ESX 9.x requires CPU support override per Broadcom KB 428874."),
            ("TURIN", "SP5 \u00b7 Up to 12 Zen 5 CCDs + I/O die",
             "AMD EPYC 9005 (Turin) \u2014 SP5 socket. Up to 12 Zen 5 chiplets (CCD) plus a central I/O die (MCM). "
             "Up to 192 cores per socket. NPS-1 recommended for vSphere (NPS-2/4 optional). "
             "12-channel DDR5-6400 with LRDIMM/RDIMM support."),
            ("9005", "SP5 \u00b7 Up to 12 Zen 5 CCDs + I/O die",
             "AMD EPYC 9005 (Turin) \u2014 SP5 socket. Up to 12 Zen 5 chiplets (CCD) plus a central I/O die (MCM). "
             "Up to 192 cores per socket. NPS-1 recommended for vSphere (NPS-2/4 optional). "
             "12-channel DDR5-6400 with LRDIMM/RDIMM support."),
            ("BERGAMO", "SP5 \u00b7 12 Zen 4c CCDs + I/O die (dense)",
             "AMD EPYC 9004 Bergamo \u2014 SP5 socket. Dense variant with 12 Zen 4c (compact) CCDs + I/O die. "
             "Up to 128 E-type cores per socket optimised for cloud-native workloads. "
             "NPS-1/2/4. 12-channel DDR5-4800."),
            ("GENOA", "SP5 \u00b7 Up to 12 Zen 4 CCDs + I/O die",
             "AMD EPYC 9004 (Genoa) \u2014 SP5 socket. Up to 12 Zen 4 chiplets (CCD) plus a central I/O die (MCM). "
             "Up to 96 cores per socket. NPS-1 recommended for vSphere (NPS-2/4 optional). "
             "12-channel DDR5-4800."),
            ("9004", "SP5 \u00b7 Up to 12 Zen 4 CCDs + I/O die",
             "AMD EPYC 9004 (Genoa/Bergamo) \u2014 SP5 socket. Up to 12 Zen 4/4c chiplets + I/O die. "
             "Up to 96 (Genoa) or 128 (Bergamo) cores per socket. NPS-1/2/4. 12-channel DDR5."),
            ("SIENA", "SP6 \u00b7 Up to 6 Zen 4c CCDs + I/O die",
             "AMD EPYC 8004 (Siena) \u2014 SP6 socket (single-socket platforms only). "
             "Up to 6 Zen 4c chiplets + I/O die. Up to 64 cores. "
             "NPS-1/2. 6-channel DDR5-4800."),
            ("8004", "SP6 \u00b7 Up to 6 Zen 4c CCDs + I/O die",
             "AMD EPYC 8004 (Siena) \u2014 SP6 socket (single-socket platforms only). "
             "Up to 6 Zen 4c chiplets + I/O die. Up to 64 cores. "
             "NPS-1/2. 6-channel DDR5-4800."),
            ("MILAN", "SP3 \u00b7 Up to 8 Zen 3 CCDs + I/O die",
             "AMD EPYC 7003 (Milan) \u2014 SP3 socket. Up to 8 Zen 3 CCDs plus a central I/O die (MCM). "
             "Up to 64 cores per socket. NPS-1 recommended for vSphere (NPS-2/4 optional). "
             "8-channel DDR4-3200."),
            ("7003", "SP3 \u00b7 Up to 8 Zen 3 CCDs + I/O die",
             "AMD EPYC 7003 (Milan) \u2014 SP3 socket. Up to 8 Zen 3 chiplets + I/O die. "
             "Up to 64 cores per socket. NPS-1/2/4. 8-channel DDR4-3200."),
            ("ROME", "SP3 \u00b7 Up to 8 Zen 2 CCDs + I/O die",
             "AMD EPYC 7002 (Rome) \u2014 SP3 socket. Up to 8 Zen 2 CCDs plus a central I/O die (MCM). "
             "Up to 64 cores per socket. NPS-1 recommended. 8-channel DDR4-3200."),
            ("7002", "SP3 \u00b7 Up to 8 Zen 2 CCDs + I/O die",
             "AMD EPYC 7002 (Rome) \u2014 SP3 socket. Up to 8 Zen 2 chiplets + I/O die. "
             "Up to 64 cores. NPS-1/2/4. 8-channel DDR4-3200."),
            ("NAPLES", "SP3 \u00b7 4\u00d7 dual-CCD Zen 1 modules",
             "AMD EPYC 7001 (Naples) \u2014 SP3 socket. 4 multi-chip modules each containing 2 Zen 1 core complexes. "
             "Up to 32 cores per socket. First-generation EPYC \u2014 NPS-1/2 supported. "
             "8-channel DDR4-2666."),
            ("7001", "SP3 \u00b7 4\u00d7 dual-CCD Zen 1 modules",
             "AMD EPYC 7001 (Naples) \u2014 SP3. Up to 32 Zen 1 cores. NPS-1/2. 8-channel DDR4-2666."),
        ]
        for _kw, _nc, _cd in _NUMA_DATA:
            if _kw in al:
                if not numa_config:
                    numa_config  = _nc
                if not chiplet_desc:
                    chiplet_desc = _cd
                break

    # ── Typical L3 fallback when Redfish exposes no cache ───────────────
    _L3_FALLBACK = [
        ("XEON 6 6900",     "Up to 480 MB (per socket)"),
        ("XEON 6 6700",     "Up to 504 MB (per socket)"),
        ("XEON 6 6500",     "Up to 504 MB (per socket)"),
        ("EMERALD RAPIDS",  "Up to 60 MB (per socket)"),
        ("SAPPHIRE RAPIDS", "Up to 60 MB (per socket)"),
        ("ICE LAKE",        "Up to 60 MB (per socket)"),
        ("CASCADE LAKE",    "Up to 38.5 MB (per socket)"),
        ("SKYLAKE",         "Up to 38.5 MB (per socket)"),
        ("TURIN",           "Up to 768 MB (per socket)"),
        ("9005",            "Up to 768 MB (per socket)"),
        ("BERGAMO",         "Up to 1152 MB (per socket)"),
        ("GENOA",           "Up to 384 MB (per socket)"),
        ("9004",            "Up to 1152 MB (per socket — Bergamo-X / standard 384 MB)"),
        ("SIENA",           "Up to 256 MB (per socket)"),
        ("8004",            "Up to 256 MB (per socket)"),
        ("MILAN",           "Up to 256 MB (per socket)"),
        ("7003",            "Up to 256 MB (per socket)"),
        ("ROME",            "Up to 256 MB (per socket)"),
        ("7002",            "Up to 256 MB (per socket)"),
        ("NAPLES",          "Up to 64 MB (per socket)"),
        ("7001",            "Up to 64 MB (per socket)"),
    ]
    typical_l3_mb = ""
    for _kw, _l3 in _L3_FALLBACK:
        if _kw in al:
            typical_l3_mb = _l3
            break

    if not numa_topology:
        # ── Structured NUMA / chiplet topology data ──────────────────────────
        # Used to drive the visual CPU topology diagram in the HTML report.
        _TOPO_DATA = [
            ("XEON 6 6900",     1, 4,  4,  32, True,  "P-core Tile"),
            ("XEON 6 6700",     1, 2,  2,  32, True,  "P-core Tile"),   # GNR-SP; same arch_label as SRF
            ("EMERALD RAPIDS",  1, 4,  1,  60, False, "Monolithic Die"),
            ("SAPPHIRE RAPIDS", 1, 4,  4,  15, True,  "Compute Tile"),
            ("ICE LAKE",        1, 4,  1,  40, False, "Monolithic Die"),
            ("CASCADE LAKE",    1, 2,  1,  28, False, "Monolithic Die"),
            ("SKYLAKE",         1, 2,  1,  28, False, "Monolithic Die"),
            ("TURIN",           1, 4,  12, 16, True,  "Zen 5 CCD"),
            ("9005",            1, 4,  12, 16, True,  "Zen 5 CCD"),
            ("GENOA",           1, 4,  12, 8,  True,  "Zen 4 CCD"),     # skipped for 97xx Bergamo SKUs
            ("BERGAMO",         1, 4,  16, 8,  True,  "Zen 4c CCD"),
            ("9004",            1, 4,  12, 8,  True,  "Zen 4 CCD"),
            ("SIENA",           1, 2,  6,  8,  True,  "Zen 4c CCD"),
            ("8004",            1, 2,  6,  8,  True,  "Zen 4c CCD"),
            ("MILAN",           1, 4,  8,  8,  True,  "Zen 3 CCD"),
            ("7003",            1, 4,  8,  8,  True,  "Zen 3 CCD"),
            ("ROME",            1, 4,  8,  8,  True,  "Zen 2 CCD"),
            ("7002",            1, 4,  8,  8,  True,  "Zen 2 CCD"),
            ("NAPLES",          1, 2,  4,  8,  True,  "Zen 1 Module"),
            ("7001",            1, 2,  4,  8,  True,  "Zen 1 Module"),
        ]
        _is_bergamo_cpu = bool(re.search(r"\b97\d\d[A-Z0-9]?\b", s))
        for _kw, _dn, _mn, _nc, _cpc, _hio, _dl in _TOPO_DATA:
            if _kw in al:
                if _kw == "GENOA" and _is_bergamo_cpu:
                    continue   # fall through to BERGAMO entry for 97xx SKUs

                if cores_per_socket > 0 and _nc > 0:
                    c_base = cores_per_socket // _nc
                    c_rem = cores_per_socket % _nc
                    c_list = [c_base + (1 if i < c_rem else 0) for i in range(_nc)]
                else:
                    c_list = [_cpc] * _nc

                numa_topology = {
                    "numa_nodes_default": _dn,
                    "numa_nodes_max":     _mn,
                    "chiplets_count":     _nc,
                    "cores_per_chiplet":  c_list[0] if c_list else _cpc,
                    "cores_per_tile":     c_list,
                    "has_io_die":         _hio,
                    "io_dies_count":      1 if _hio else 0,
                    "die_label":          _dl,
                    "die_config_name":    "",
                    "package_socket":     "",
                }
                break

    return {
        "evc_baseline":    evc_baseline,
        "vendor_tier":     vendor_tier,
        "tier_badge_class":tier_badge_class,
        "tier_badge_html": tier_badge_html,
        "numa_config":     numa_config,
        "chiplet_desc":    chiplet_desc,
        "pcie_gen":        pcie_gen,
        "typical_l3_mb":   typical_l3_mb,
        "is_intel":        is_intel,
        "is_amd":          is_amd,
        "numa_topology":   numa_topology,
    }
