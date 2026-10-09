"""
VCF Readiness Tool — Consumer SSD Detection & Guardrails.

Detects client/consumer-grade SSDs (e.g. Samsung EVO/PRO/QVO, Crucial MX/BX,
WD Blue/Black, Kingston, Intel 660p) that lack enterprise Power Loss Protection
(PLP) capacitors and enterprise write endurance.

Prevents false qualification of consumer SSDs as vSAN OSA or ESA eligible.
"""

import re
from typing import Optional

# Samsung enterprise model prefixes and part number families
_SAMSUNG_ENTERPRISE_PREFIXES = (
    "MZQL",  # PM983 / PM9A3 U.2/M.2 PCIe Gen4
    "MZWL",  # PM1733 / PM1735 enterprise U.2 PCIe Gen4
    "MZXL",  # PM1735 enterprise AIC
    "MZIL",  # PM1643 / PM1653 SAS-3 enterprise
    "MZPL",  # PM1725 / PM1725a/b NVMe enterprise
    "MZ1L",  # PM983 NF1 / M.2 enterprise
    "MZ7L",  # PM893 / PM897 SATA enterprise
    "MZ7K",  # SM883 SATA enterprise
    "MZ8L",  # Enterprise SATA
)

_SAMSUNG_CONSUMER_3DIGIT_PATTERN = re.compile(
    r"\b(750|830|840|850|860|870|950|960|970|980|990)\b", re.IGNORECASE
)

_SAMSUNG_ENTERPRISE_SERIES_PATTERN = re.compile(
    r"\b(PM|SM|BM|SV)\s*(\d{3,4}|[0-9][A-Z][0-9])[A-Z0-9]*\b", re.IGNORECASE
)

_MICRON_ENTERPRISE_SERIES_PATTERN = re.compile(
    r"\b(5100|5200|5300|5400|7300|7400|7450|9300|9400|6500|7500)\b", re.IGNORECASE
)

_WD_ENTERPRISE_SERIES_PATTERN = re.compile(
    r"\b(ULTRASTAR|DC\s*SN\d+|DC\s*SS\d+|DC\s*HC\d+|WUS\d+|WUH\d+)\b", re.IGNORECASE
)

_KINGSTON_ENTERPRISE_SERIES_PATTERN = re.compile(
    r"\b(DC\s*[1456]\d{2,3}|SEDC\d+)\b", re.IGNORECASE
)

_INTEL_ENTERPRISE_SERIES_PATTERN = re.compile(
    r"\b(D[357]-|P[45][56]10|P4500|P4600|P5500|P5800X|DC\s*P\d+|DC\s*S\d+|SSDSC2K[GB]|SSDSC2B[AB])\b", re.IGNORECASE
)


def detect_consumer_drive(model: str, manufacturer: str = "") -> Optional[str]:
    """Return a descriptive reason if the drive is a known consumer/client SSD.

    Returns None if the drive is enterprise-grade, server OEM branded, or unverified.
    """
    m = str(model or "").strip()
    if not m or m.lower() in ("unknown", "n/a", "empty", "none"):
        return None

    man = str(manufacturer or "").strip()
    full = f"{man} {m}".upper()
    m_up = m.upper()

    # ──────────────────────────────────────────────────────────────────────────
    # 1. Samsung Consumer vs Enterprise
    # ──────────────────────────────────────────────────────────────────────────
    is_samsung = "SAMSUNG" in full or m_up.startswith("MZ") or m_up.startswith("SEC")
    if is_samsung:
        # Check enterprise exemptions first
        if _SAMSUNG_ENTERPRISE_SERIES_PATTERN.search(m_up):
            return None
        if any(m_up.startswith(p) for p in _SAMSUNG_ENTERPRISE_PREFIXES):
            return None
        # Check for OEM vendor rebrands that retain enterprise models
        if any(k in m_up for k in ["PM8", "PM9", "PM17", "SM8", "SM9"]):
            return None

        # Detect Samsung Consumer series:
        # Keywords: EVO, PRO, QVO, PLUS
        if any(k in m_up for k in ["EVO", "PRO", "QVO", "PLUS"]):
            return f"Samsung Consumer SSD ({m})"
        # 3-digit client lines: 750, 830, 840, 850, 860, 870, 950, 960, 970, 980, 990
        if _SAMSUNG_CONSUMER_3DIGIT_PATTERN.search(m_up):
            return f"Samsung Consumer SSD ({m})"
        # Consumer part number prefixes: MZ-7... (SATA EVO/PRO), MZ-V... (NVMe EVO/PRO), MZ-N... (M.2 SATA)
        if re.search(r"\bMZ-[789VN]", m_up):
            return f"Samsung Consumer SSD ({m})"

    # ──────────────────────────────────────────────────────────────────────────
    # 2. Crucial / Micron Consumer vs Enterprise
    # ──────────────────────────────────────────────────────────────────────────
    is_crucial_or_micron = "CRUCIAL" in full or m_up.startswith("CT") or "MICRON" in full
    if is_crucial_or_micron:
        # Enterprise Micron exemptions
        if _MICRON_ENTERPRISE_SERIES_PATTERN.search(m_up) or m_up.startswith("MTFD"):
            return None

        # Crucial Consumer series
        if re.search(r"(MX|BX)[1-5]\d{2}", m_up):
            return f"Crucial Consumer SSD ({m})"
        if re.search(r"\b(P[1235](\s*PLUS)?|T[57]0[05])\b", m_up):
            return f"Crucial Consumer SSD ({m})"
        if re.search(r"\bCT\d{3,4}(MX|BX|P|T)", m_up):
            return f"Crucial Consumer SSD ({m})"
        if "CT" in m_up and any(k in m_up for k in ["MX", "BX", "P1", "P2", "P3", "P5", "SSD"]):
            return f"Crucial Consumer SSD ({m})"

    # ──────────────────────────────────────────────────────────────────────────
    # 3. Western Digital / SanDisk Consumer vs Enterprise
    # ──────────────────────────────────────────────────────────────────────────
    is_wd = any(k in full for k in ["WESTERN DIGITAL", "WDC", "SANDISK"]) or m_up.startswith("WD")
    if is_wd:
        # Enterprise exemptions
        if _WD_ENTERPRISE_SERIES_PATTERN.search(m_up) or m_up.startswith("WUS") or m_up.startswith("WUH"):
            return None

        # Consumer series
        if re.search(r"\b(WD\s*)?(BLUE|GREEN|BLACK|RED\s*SSD)\b", m_up) or "WD_BLACK" in m_up:
            return f"Western Digital Consumer SSD ({m})"
        if any(k in m_up for k in ["SA510", "SN350", "SN550", "SN570", "SN580", "SN750", "SN770", "SN850"]):
            return f"Western Digital Consumer SSD ({m})"
        if re.search(r"\bSANDISK\s+(PLUS|ULTRA|EXTREME|SSD\s*PLUS)\b", m_up):
            return f"SanDisk Consumer SSD ({m})"
        if re.search(r"\bWDS\d+[A-Z0-9]+", m_up):
            return f"Western Digital Consumer SSD ({m})"

    # ──────────────────────────────────────────────────────────────────────────
    # 4. Kingston Consumer vs Enterprise
    # ──────────────────────────────────────────────────────────────────────────
    is_kingston = "KINGSTON" in full or m_up.startswith("SA400") or m_up.startswith("SKC") or m_up.startswith("SNV")
    if is_kingston:
        # Enterprise exemptions
        if _KINGSTON_ENTERPRISE_SERIES_PATTERN.search(m_up):
            return None

        # Consumer series
        if re.search(r"(A400|A1000|A2000|NV1|NV2|NV3|KC600|KC2500|KC3000|FURY|SSDNOW|UV400|UV500|V300)", m_up):
            return f"Kingston Consumer SSD ({m})"
        if any(p in m_up for p in ["SA400", "SKC", "SNV"]):
            return f"Kingston Consumer SSD ({m})"

    # ──────────────────────────────────────────────────────────────────────────
    # 5. Intel Consumer vs Enterprise
    # ──────────────────────────────────────────────────────────────────────────
    is_intel = "INTEL" in full
    if is_intel:
        # Enterprise exemptions
        if _INTEL_ENTERPRISE_SERIES_PATTERN.search(m_up):
            return None

        # Consumer series
        if re.search(r"\b(600P|660P|665P|670P|760P|540S|545S|530|520)\b", m_up):
            return f"Intel Consumer SSD ({m})"
        if "SSDPEKNW" in m_up or "SSDSC2KW" in m_up:
            return f"Intel Consumer SSD ({m})"

    # ──────────────────────────────────────────────────────────────────────────
    # 6. Other Common Consumer SSD Brands
    # ──────────────────────────────────────────────────────────────────────────
    if "SABRENT" in full or ("ROCKET" in full and not any(k in full for k in ["RAID", "CONTROLLER"])):
        return f"Sabrent Consumer SSD ({m})"

    if "CORSAIR" in full or re.search(r"\bMP(510|600|700)\b", m_up):
        return f"Corsair Consumer SSD ({m})"

    if ("HYNIX" in full or "SKHYNIX" in full) and any(k in m_up for k in ["GOLD", "PLATINUM", "P31", "P41"]):
        return f"SK Hynix Consumer SSD ({m})"

    if "TEAMGROUP" in full or re.search(r"\b(MP33|MP34|VULCAN|GX[12])\b", m_up):
        return f"TeamGroup Consumer SSD ({m})"

    if "ADATA" in full or "XPG" in full or re.search(r"\b(SU650|SU800|SX8200)\b", m_up):
        return f"ADATA Consumer SSD ({m})"

    if re.search(r"\b(CS900|CS2130|CS2140|CS3030|CS3040|XLR8)\b", m_up):
        return f"PNY Consumer SSD ({m})"

    if "SILICON POWER" in full or "SPCC" in full or re.search(r"\b(A55|A60|A80|UD90)\b", m_up):
        return f"Silicon Power Consumer SSD ({m})"

    if "BARRACUDA" in full or "FIRECUDA" in full:
        return f"Seagate Consumer SSD ({m})"

    return None


def is_consumer_drive(model: str, manufacturer: str = "") -> bool:
    """Convenience boolean check for consumer SSD detection."""
    return detect_consumer_drive(model, manufacturer) is not None
