"""
VCF Readiness Tool — Broadcom Compatibility Guide deep-link generator.

BCGLinkGenerator builds single-click BCG search URLs for servers, CPUs,
SSDs, NICs, HBAs, and GPUs using OEM-specific keyword cleaning rules.
"""
import logging
import re
import urllib.parse
from typing import Dict, Optional, Tuple, Union

from .collector.pci_utils import normalize_pci_id
from .constants import BCG_BASE_URL

logger = logging.getLogger("vcf_assess")

_LOGGED_DEBUG_MSGS = set()


class BCGLinkGenerator:
    """Constructs single-click Broadcom Compatibility Guide search URLs."""

    @staticmethod
    def _log_debug_once(msg: str):
        if msg not in _LOGGED_DEBUG_MSGS:
            if len(_LOGGED_DEBUG_MSGS) > 5000:
                _LOGGED_DEBUG_MSGS.clear()
            _LOGGED_DEBUG_MSGS.add(msg)
            logger.debug(msg)

    # Maps (model_number // 100 * 100) → exact BCG cpuSeries taxonomy string.
    # Gold 6xxx and 5xxx share a combined series entry on BCG; Silver 4xxx and
    # Bronze 3xxx are also sometimes combined. Cascade Lake strings are
    # confirmed from live BCG getAllFilterValues; Ice Lake Gold requires trailing space;
    # Emerald Rapids uses space, not hyphen.
    _INTEL_CPU_SERIES: dict = {
        # Skylake-SP (1st Gen Xeon Scalable)
        8100: "Intel Xeon Platinum 8100 (Skylake-SP) Series",
        6100: "Intel Xeon Gold 6100/5100, Silver 4100, Bronze 3100 (Skylake-SP) Series",
        5100: "Intel Xeon Gold 6100/5100, Silver 4100, Bronze 3100 (Skylake-SP) Series",
        4100: "Intel Xeon Gold 6100/5100, Silver 4100, Bronze 3100 (Skylake-SP) Series",
        3100: "Intel Xeon Gold 6100/5100, Silver 4100, Bronze 3100 (Skylake-SP) Series",
        # Cascade Lake-SP (2nd Gen Xeon Scalable)
        8200: "Intel Xeon Platinum 8200 (Cascade-Lake-SP) Series",
        6200: "Intel Xeon Gold 6200/5200 (Cascade-Lake-SP/Refresh) Series",
        5200: "Intel Xeon Gold 6200/5200 (Cascade-Lake-SP/Refresh) Series",
        4200: "Intel Xeon Silver 4200, Bronze 3200 (Cascade-Lake-SP/Refresh) Series",
        3200: "Intel Xeon Silver 4200, Bronze 3200 (Cascade-Lake-SP/Refresh) Series",
        # Ice Lake-SP (3rd Gen Xeon Scalable) — note trailing space on Gold in BCG taxonomy
        8300: "Intel Xeon Platinum 8300 (Ice-Lake-SP) Series",
        6300: "Intel Xeon Gold 6300/5300 (Ice-Lake-SP) Series ",
        5300: "Intel Xeon Gold 6300/5300 (Ice-Lake-SP) Series ",
        4300: "Intel Xeon Silver 4300 (Ice-Lake-SP) Series",
        3300: "Intel Xeon Silver 4300 (Ice-Lake-SP) Series",
        # Sapphire Rapids-SP (4th Gen Xeon Scalable)
        8400: "Intel Xeon Platinum 8400 (Sapphire-Rapids-SP) Series",
        6400: "Intel Xeon Gold 6400/5400 (Sapphire-Rapids-SP) Series",
        5400: "Intel Xeon Gold 6400/5400 (Sapphire-Rapids-SP) Series",
        4400: "Intel Xeon Silver 4400, Bronze 3400 (Sapphire-Rapids-SP) Series",
        3400: "Intel Xeon Silver 4400, Bronze 3400 (Sapphire-Rapids-SP) Series",
        # Emerald Rapids-SP (5th Gen Xeon Scalable) — note space, not hyphen in BCG taxonomy
        8500: "Intel Xeon Platinum 8500 (Emerald Rapids-SP) Series",
        6500: "Intel Xeon Gold 6500/5500 (Emerald Rapids-SP) Series",
        5500: "Intel Xeon Gold 6500/5500 (Emerald Rapids-SP) Series",
        4500: "Intel Xeon Silver 4500, Bronze 3500 (Emerald Rapids-SP) Series",
        3500: "Intel Xeon Silver 4500, Bronze 3500 (Emerald Rapids-SP) Series",
    }

    # Map normalized vendor tokens to exact Broadcom Compatibility Guide partner names.
    _BCG_PARTNERS: dict = {
        "DELL": "Dell",
        "HPE": "Hewlett Packard Enterprise",
        "HEWLETT PACKARD ENTERPRISE": "Hewlett Packard Enterprise",
        "HEWLETT-PACKARD": "Hewlett Packard Enterprise",
        "HP": "Hewlett Packard Enterprise",
        "CISCO": "Cisco",
        "LENOVO": "Lenovo",
        "SUPERMICRO": "Supermicro Computer, Inc",
        "FUJITSU": "Fujitsu",
        "HITACHI": "Hitachi Vantara",
        "HUAWEI": "Huawei Technologies Co., Ltd.",
        "INSPUR": "IEIT SYSTEMS Co., Ltd.",
        "IEIT": "IEIT SYSTEMS Co., Ltd.",
        "INTEL": "Intel Corporation",
        "NUTANIX": "Nutanix",
        "ORACLE": "Oracle",
        "QUANTA": "Quanta Computer Inc.",
        "XFUSION": "xFusion Digital Technologies Co., Ltd",
    }

    # Broadcom Compatibility Guide (BCG) CPU Program mappings for AMD:
    # Maps normalized 32-bit CPUID hex string -> (productId, series_name)
    _AMD_CPUID_SERIES: dict = {
        "0x00800F10": (124, "AMD EPYC 7001 Series"),
        "0x00800F11": (124, "AMD EPYC 7001 Series"),
        "0x00800F12": (124, "AMD EPYC 7001 Series"),
        "0x00830F10": (134, "AMD EPYC 7002/7Fx2/7Hx2 Series"),
        "0x00830F00": (134, "AMD EPYC 7002/7Fx2/7Hx2 Series"),
        "0x00A00F11": (145, "AMD EPYC 7003/7003X Series"),
        "0x00A00F12": (145, "AMD EPYC 7003/7003X Series"),
        "0x00A00F10": (145, "AMD EPYC 7003/7003X Series"),
        "0x00A10F11": (158, "AMD EPYC 9004 Series"),
        "0x00A10F12": (158, "AMD EPYC 9004 Series"),
        "0x00AA0F02": (158, "AMD EPYC 9004 Series"),
        "0x00B00F21": (169, "AMD EPYC 9005 Series"),
        "0x00B10F10": (169, "AMD EPYC 9005 Series"),
        "0x00B00F20": (169, "AMD EPYC 9005 Series"),
        "0x00600F10": (57, "AMD Opteron 4200 Series"),
        "0x00600F20": (76, "AMD Opteron 6300 Series"),
        "0x00700F00": (89, "AMD Opteron X1100 Series"),
        "0x00630F00": (100, "AMD Opteron X2250 Series"),
        "0x00810F10": (150, "AMD Ryzen Embedded V1000 Series"),
    }

    # Exact BCG server platform catalog mapping:
    # (partner, normalized_model_key, cpu_series) -> (productId, canonical_model_name)
    _SERVER_PRODUCT_IDS: Dict[Tuple[str, str, str], Tuple[int, str]] = {
        # --- Cisco UCS C-Series (Ice Lake / 3rd Gen Xeon Scalable) ---
        ("Cisco", "UCS-C240-M6S", "Intel Xeon Platinum 8300 (Ice-Lake-SP) Series"): (53126, "Cisco UCS-C240-M6S"),
        ("Cisco", "UCS-C240-M6S", "Intel Xeon Gold 6300/5300 (Ice-Lake-SP) Series "): (53117, "Cisco UCS-C240-M6S"),
        ("Cisco", "UCS-C240-M6SN", "Intel Xeon Platinum 8300 (Ice-Lake-SP) Series"): (53130, "Cisco UCS-C240-M6SN"),
        ("Cisco", "UCS-C240-M6SN", "Intel Xeon Gold 6300/5300 (Ice-Lake-SP) Series "): (53121, "Cisco UCS-C240-M6SN"),
        ("Cisco", "UCS-C240-M6SX", "Intel Xeon Platinum 8300 (Ice-Lake-SP) Series"): (53132, "Cisco UCS-C240-M6SX"),
        ("Cisco", "UCS-C240-M6SX", "Intel Xeon Gold 6300/5300 (Ice-Lake-SP) Series "): (53119, "Cisco UCS-C240-M6SX"),
        ("Cisco", "UCS-C240-M6L", "Intel Xeon Platinum 8300 (Ice-Lake-SP) Series"): (53128, "Cisco UCS-C240-M6L"),
        ("Cisco", "UCS-C240-M6L", "Intel Xeon Gold 6300/5300 (Ice-Lake-SP) Series "): (55533, "Cisco UCS-C240-M6L"),
        ("Cisco", "UCS-C220-M6S", "Intel Xeon Platinum 8300 (Ice-Lake-SP) Series"): (53125, "Cisco UCS-C220-M6S"),
        ("Cisco", "UCS-C220-M6S", "Intel Xeon Gold 6300/5300 (Ice-Lake-SP) Series "): (53115, "Cisco UCS-C220-M6S"),
        ("Cisco", "UCS-C220-M6S", "Intel Xeon Silver 4300 (Ice-Lake-SP) Series"): (64458, "Cisco UCS-C220-M6S"),
        ("Cisco", "UCS-C220-M6N", "Intel Xeon Platinum 8300 (Ice-Lake-SP) Series"): (53127, "Cisco UCS-C220-M6N"),
        ("Cisco", "UCS-C220-M6N", "Intel Xeon Gold 6300/5300 (Ice-Lake-SP) Series "): (53116, "Cisco UCS-C220-M6N"),
        # --- Cisco UCS C-Series (Cascade Lake / 2nd Gen Xeon Scalable) ---
        ("Cisco", "UCS-C240-M5S", "Intel Xeon Platinum 8200 (Cascade-Lake-SP) Series"): (47519, "Cisco UCS C240 M5S"),
        ("Cisco", "UCS-C240-M5S", "Intel Xeon Gold 6200/5200 (Cascade-Lake-SP/Refresh) Series"): (48229, "Cisco UCS C240 M5S"),
        # --- Dell PowerEdge ---
        ("Dell", "R750", "Intel Xeon Platinum 8300 (Ice-Lake-SP) Series"): (51125, "Dell PowerEdge R750"),
        ("Dell", "R750", "Intel Xeon Gold 6300/5300 (Ice-Lake-SP) Series "): (52682, "Dell PowerEdge R750"),
        ("Dell", "R650", "Intel Xeon Platinum 8300 (Ice-Lake-SP) Series"): (51127, "Dell PowerEdge R650"),
        ("Dell", "R650", "Intel Xeon Gold 6300/5300 (Ice-Lake-SP) Series "): (52681, "Dell PowerEdge R650"),
        ("Dell", "R740", "Intel Xeon Platinum 8200 (Cascade-Lake-SP) Series"): (47512, "Dell PowerEdge R740"),
        ("Dell", "R740", "Intel Xeon Gold 6200/5200 (Cascade-Lake-SP/Refresh) Series"): (47548, "Dell PowerEdge R740"),
        ("Dell", "R740XD", "Intel Xeon Platinum 8200 (Cascade-Lake-SP) Series"): (47511, "Dell PowerEdge R740xd"),
        ("Dell", "R640", "Intel Xeon Platinum 8200 (Cascade-Lake-SP) Series"): (47501, "Dell PowerEdge R640"),
        # --- HPE ProLiant ---
        ("Hewlett Packard Enterprise", "DL380 GEN10", "Intel Xeon Platinum 8200 (Cascade-Lake-SP) Series"): (46385, "HPE ProLiant DL380 Gen10"),
        ("Hewlett Packard Enterprise", "DL360 GEN10", "Intel Xeon Platinum 8200 (Cascade-Lake-SP) Series"): (46428, "HPE ProLiant DL360 Gen10"),
    }

    @staticmethod
    def _enc(s: str) -> str:
        return urllib.parse.quote(str(s), safe="")

    @staticmethod
    def cpu_detail(product_id: Union[int, str], series_name: str = "") -> str:
        """Build a direct BCG CPU series detail URL with productId and optional redirectFrom."""
        pid = str(product_id or "").strip()
        if not pid:
            return ""
        url = (
            f"https://compatibilityguide.broadcom.com/detail?program=cpu"
            f"&productId={BCGLinkGenerator._enc(pid)}&persona=live&column=cpuSeries&order=asc"
        )
        if series_name:
            url += f"&redirectFrom={urllib.parse.quote(str(series_name).strip(), safe='/')}"
        return url

    @staticmethod
    def normalize_server_model_key(partner: str, model: str) -> str:
        """Normalize OEM server model string to canonical lookup key."""
        m = str(model or "").strip()
        p = str(partner or "").strip().upper()
        if "CISCO" in p:
            m = re.sub(r"(?i)^cisco\s+(?:systems(?:\s+inc\.?)?)?\s*", "", m).strip()
            m = re.sub(r"(?i)^UCS[C]?[-_\s]*", "UCS-", m).strip()
            if re.match(r"(?i)^C[1248]\d{2}", m):
                m = f"UCS-{m}"
            m = re.sub(r"[-\s]+", "-", m).strip("-")
            return m.upper()
        elif "DELL" in p:
            m = re.sub(r"(?i)^(?:dell(?:\s+inc\.?)?\s+)?(?:poweredge|powervault|precision)\s+", "", m).strip()
            m = re.sub(r"(?i)^dell\s+", "", m).strip()
            m = re.sub(r"[-\s]+", " ", m).strip()
            return m.upper()
        elif "HPE" in p or "HEWLETT" in p:
            m = re.sub(r"(?i)^(?:hpe|hewlett\s+packard(?:\s+enterprise)?)\s+", "", m).strip()
            m = re.sub(r"(?i)^(?:proliant|synergy|apollo)\s+", "", m).strip()
            m = re.sub(r"[-\s]+", " ", m).strip()
            return m.upper()
        return m.upper()

    @staticmethod
    def lookup_server_product_id(
        partner: Optional[str],
        model: str,
        cpu_series: Optional[str] = "",
    ) -> Optional[Tuple[int, str]]:
        """Lookup exact BCG server productId and display model name.

        Returns (product_id, redirect_model_name) if mapped, otherwise None.
        """
        if not partner or not model or not cpu_series:
            return None
        norm_model = BCGLinkGenerator.normalize_server_model_key(partner, model)
        return BCGLinkGenerator._SERVER_PRODUCT_IDS.get((partner, norm_model, cpu_series))

    @staticmethod
    def server_detail(
        product_id: Union[int, str],
        partner: str = "",
        cpu_series: str = "",
        keyword: str = "",
        model_name: str = "",
    ) -> str:
        """Build a direct BCG server detail URL using Broadcom productId."""
        pid = str(product_id or "").strip()
        if not pid:
            return ""
        url = (
            f"https://compatibilityguide.broadcom.com/detail?program=server"
            f"&productId={BCGLinkGenerator._enc(pid)}&persona=live"
        )
        if partner:
            url += f"&partnerName={BCGLinkGenerator._enc(f'[{partner}]')}"
        if cpu_series:
            url += f"&cpuSeries={BCGLinkGenerator._enc(f'[{cpu_series}]')}"
        if keyword:
            url += f"&keyword={BCGLinkGenerator._enc(keyword)}"
        url += "&column=partnerName&order=asc"
        if model_name:
            url += f"&redirectFrom={BCGLinkGenerator._enc(model_name)}"
        return url

    @staticmethod
    def resolve_partner(vendor: str) -> Optional[str]:
        """Resolve a server vendor string to the exact BCG partnerName filter value."""
        if not vendor:
            return None
        v_upper = str(vendor).strip().upper()
        # Check longest matching keys first to match e.g. 'HEWLETT PACKARD' before 'HP'
        for k in sorted(BCGLinkGenerator._BCG_PARTNERS.keys(), key=len, reverse=True):
            if k in v_upper:
                return BCGLinkGenerator._BCG_PARTNERS[k]
        return None

    @staticmethod
    def resolve_cpu_series(
        cpu_model: Union[str, dict, None] = "",
        processor_id: str = "",
    ) -> Optional[str]:
        """Resolve CPU model or CPUID to the exact BCG cpuSeries taxonomy string.

        Returns None if the series cannot be determined with 100% confidence,
        allowing callers to fall back safely without triggering false negatives.
        """
        if isinstance(cpu_model, dict):
            if not processor_id:
                processor_id = str(cpu_model.get("processor_id") or "")
            cpu_model = str(cpu_model.get("model") or "")

        model_str = str(cpu_model or "").strip()
        pid_str = str(processor_id or "").strip()

        if not pid_str and (
            model_str.upper().startswith("0X")
            or (len(model_str) == 8 and bool(re.fullmatch(r"[0-9A-Fa-f]{8}", model_str)))
        ):
            pid_str = model_str
            model_str = ""

        norm_pid = ""
        if pid_str:
            p_clean = pid_str.strip()
            if p_clean.upper().startswith("0X"):
                p_clean = p_clean[2:]
            if re.fullmatch(r"[0-9A-Fa-f]{1,8}", p_clean):
                norm_pid = f"0x{int(p_clean, 16):08X}"

        clean = re.sub(r"\(R\)|\(TM\)|@\s*[\d.]+\s*GHz?", "", model_str, flags=re.I).strip()
        clean = " ".join(clean.split())
        s = clean.upper()

        # 1. Match AMD EPYC by CPUID
        if norm_pid and norm_pid in BCGLinkGenerator._AMD_CPUID_SERIES:
            _pid, s_name = BCGLinkGenerator._AMD_CPUID_SERIES[norm_pid]
            if norm_pid in ("0x00A10F11", "0x00AA0F02") and (
                "8004" in clean or "SIENA" in s or bool(re.search(r"\b8\d{3}\b", clean))
            ):
                return "AMD EPYC 8004 Series"
            return s_name

        # 2. Match AMD EPYC by model string
        if re.search(r"(?i)\bamd\b|\bepyc\b|\bopteron\b", s):
            if re.search(r"\b8\d{3}\b|\b8004\b|\bSiena\b", clean, re.I):
                return "AMD EPYC 8004 Series"
            if re.search(r"\b9\d{2}5\b|\b9005\b|\bTurin\b", clean, re.I):
                return "AMD EPYC 9005 Series"
            if re.search(r"\b9\d{2}4\b|\b9004\b|\bGenoa\b|\bBergamo\b", clean, re.I):
                return "AMD EPYC 9004 Series"
            if re.search(r"\b7\d{2}3[A-Z]*\b|\b7003\b|\bMilan\b", clean, re.I):
                return "AMD EPYC 7003/7003X Series"
            if re.search(r"\b7[0-9]{2}2[A-Z]*\b|\b7[FH]x2\b|\b7[FH]\d{2}\b|\b7H12\b|\b7002\b|\bRome\b", clean, re.I):
                return "AMD EPYC 7002/7Fx2/7Hx2 Series"
            if re.search(r"\b7\d{2}1[A-Z]*\b|\b7001\b|\bNaples\b", clean, re.I):
                return "AMD EPYC 7001 Series"
            epyc_m = re.search(r"\b(\d)(\d{2})(\d)[A-Z]*\b", clean)
            if epyc_m:
                first_d, last_d = epyc_m.group(1), epyc_m.group(3)
                if first_d == "7" and last_d == "2":
                    return "AMD EPYC 7002/7Fx2/7Hx2 Series"
                if first_d == "7" and last_d == "3":
                    return "AMD EPYC 7003/7003X Series"
                if first_d == "7" and last_d == "1":
                    return "AMD EPYC 7001 Series"
                if first_d == "8" and last_d == "4":
                    return "AMD EPYC 8004 Series"
                if first_d == "9" and last_d == "4":
                    return "AMD EPYC 9004 Series"
                if first_d == "9" and last_d == "5":
                    return "AMD EPYC 9005 Series"

        # 3. Match Intel Xeon 6 (Granite Rapids / Sierra Forest)
        xeon6_m = re.search(r'(?:Xeon\s*6|\bXeon\b.*?\b(6[3579]\d{2}[PE]|6\d{3}[PE])\b)', clean, re.I)
        if xeon6_m:
            code = xeon6_m.group(1) if xeon6_m.group(1) else ""
            if "69" in code:
                return "Intel Xeon 6900P (Granite Rapids-AP) Series"
            return "Intel Xeon 6500P/6700P (Granite Rapids-SP) Series"

        # 4. Match Intel Xeon Scalable (Gen 1-5)
        m_intel = re.search(r'(Platinum|Gold|Silver|Bronze)\s+(\d{4}[A-Z+]*)', clean, re.I)
        if not m_intel and re.search(r"(?i)\bintel\b|\bxeon\b", s):
            m_num = re.search(r'\b(\d{4})[A-Z+]*\b', clean)
            if m_num:
                num = int(m_num.group(1))
                first = num // 1000
                tier_guess = "Platinum" if first == 8 else ("Gold" if first in (5, 6) else ("Silver" if first == 4 else "Bronze"))
                class _MockM:
                    def group(self, idx):
                        return tier_guess if idx == 1 else str(num)
                m_intel = _MockM()

        if m_intel:
            num_str = m_intel.group(2)[:4]
            if num_str.isdigit():
                floor_num = (int(num_str) // 100) * 100
                series = BCGLinkGenerator._INTEL_CPU_SERIES.get(floor_num)
                if series:
                    return series

        # 5. Match older Intel Xeon E5-2600 v2/v3/v4
        if re.search(r"(?i)\bintel\b|\bxeon\b", s):
            m_e5 = re.search(r'E5-26\d{2}(?:\s*(v[234]))?', clean, re.I)
            if m_e5:
                ver = m_e5.group(1).lower() if m_e5.group(1) else ""
                if ver == "v4":
                    return "Intel Xeon E5-2600-v4 Series"
                if ver == "v3":
                    return "Intel Xeon E5-2600-v3 Series"
                if ver == "v2":
                    return "Intel Xeon E5-2600-v2 Series"
                return "Intel Xeon E5-2600 Series"

        return None

    @staticmethod
    def server(
        vendor: str = "",
        model: str = "",
        cpu_model: Union[str, dict, None] = "",
        processor_id: str = "",
    ) -> str:
        """Build BCG server search URL with OEM-specific keyword cleaning and optional filters.

        BCG's search filters by partnerName and cpuSeries when available, and
        matches keyword against the model field. OEM vendor prefixes and chassis
        noise are stripped so that the search targets the exact model.
        """
        v = str(vendor or "").upper()
        m = str(model or "").strip()

        if "DELL" in v:
            # Redfish: "PowerEdge R640" → BCG wants just "R640"
            kw = re.sub(r"(?i)^(poweredge|powervault|precision)\s+", "", m).strip()
        elif "HPE" in v or "HEWLETT" in v:
            # Redfish: "ProLiant DL380 Gen10" → BCG wants "DL380 Gen10"
            kw = re.sub(r"(?i)^(proliant|synergy|apollo)\s+", "", m).strip()
        elif "CISCO" in v:
            # Redfish: "UCSC-C240-M5SX" → BCG has "Cisco UCS-C240-M5SX" (preserves hyphen)
            kw = re.sub(r"(?i)^UCS[A-Z]?-", "", m).strip()
        elif "LENOVO" in v:
            # Redfish: "ThinkSystem SR650" → BCG wants "SR650"
            kw = re.sub(r"(?i)^(thinksystem|thinkagile)\s+", "", m).strip()
        elif "SUPERMICRO" in v:
            # Redfish: "SYS-1029U-TR4" → BCG wants "1029U-TR4" (strip chassis prefix)
            kw = re.sub(r"(?i)^(?:SYS|SSG|SBA|SBI)-", "", m).strip()
        else:
            kw = m

        partner = BCGLinkGenerator.resolve_partner(vendor)
        cpu_series = BCGLinkGenerator.resolve_cpu_series(cpu_model, processor_id)

        # Check for direct server productId mapping
        lookup = BCGLinkGenerator.lookup_server_product_id(partner, m, cpu_series)
        if lookup:
            pid, redirect_name = lookup
            return BCGLinkGenerator.server_detail(
                product_id=pid,
                partner=partner or "",
                cpu_series=cpu_series or "",
                keyword=kw,
                model_name=redirect_name,
            )

        url = f"{BCG_BASE_URL}&program=server"
        if partner:
            url += f"&partnerName={BCGLinkGenerator._enc(f'[{partner}]')}"
        if cpu_series:
            url += f"&cpuSeries={BCGLinkGenerator._enc(f'[{cpu_series}]')}"
        if kw:
            url += f"&keyword={BCGLinkGenerator._enc(kw)}"
        url += "&column=partnerName&order=asc"
        return url

    @staticmethod
    def storage(model: str, part_number: str = "", media_type: str = "") -> str:
        """Build a BCG SSD/NVMe or HDD search URL.

        Strategy:
        - Detect magnetic media (HDD/SMR) to use program=hdd vs program=ssd.
        - Dell chassis part numbers (TW-XXXXXX-..., CN-XXXXXX-..., PH-XXXXXX-...,
          SG-XXXXXX-..., KR-XXXXXX-..., TH-XXXXXX-...) are system-level OEM stamps.
          Detect and bypass them for SSDs to use clean model codes; for spinning HDDs,
          extract the 5-character DPN (e.g. 'RWR8F') to query partNumber=[...].
        - When a specific physical drive product ID or ODM model code is identified
          (e.g. HPE 'VK001920GWSXK', 'MR000240GWFLU', Intel 'SSDSC2KG960G8R',
          Toshiba 'PX05SMB080Y', Micron 'MTFDDAV240TCB', Kioxia 'KCD6XLUL3T84'):
          Use Broadcom BCG's structured 'productId=[...]' query filter. This resolves
          the BCG limitation where 'keyword' searches fail against the Product Id index.
        - When the drive identifier is a marketing series name ('P4500', 'P5600', 'PM1725b'):
          Use 'keyword' search, appending '&partners=[Dell]' if explicitly Dell-branded.
        """
        pn = str(part_number or "").strip()
        mdl = str(model or "").strip()
        media = str(media_type or "").upper()
        is_magnetic = any(k in media for k in ("HDD", "SMR", "MAGNETIC", "HARD"))
        program = "hdd" if is_magnetic else "ssd"

        # Dell chassis PPID barcode patterns (e.g. CN-0RWR8F-..., TW-033R2T-..., etc.)
        _dell_chassis_pn = re.compile(
            r"^(?:TW|CN|PH|SG|PF|1F|KR|TH|JP|MY|VN|ID|MX|BR|CZ|PL)-[0-9A-Z]{5,6}",
            re.I,
        )
        _generic = {
            "N/A", "NONE", "UNKNOWN", "NOT AVAILABLE", "NOTAVAILABLE",
            "NOT APPLICABLE", "UNAVAILABLE", "NOT INSTALLED", "NULL", "", "0"
        }

        # For spinning HDDs: BCG's 'program=hdd' does not support productId.
        # If a Dell chassis PPID is present, extract the 5-character DPN (e.g. 'RWR8F')
        # and search via partNumber=[...] for 100% precision.
        if is_magnetic:
            m_dpn = re.match(r"^[A-Z]{2}-0?([0-9A-Z]{5})-", pn, re.I)
            if m_dpn:
                dpn = m_dpn.group(1).upper()
                return (
                    f"https://compatibilityguide.broadcom.com/search?persona=live&program=hdd"
                    f"&supportedReleases=%5BESXi+9.1+%28vSAN+9.1%29%7C%7CESXi+9.0+%28vSAN++9.0%29%5D"
                    f"&column=brandName&order=asc"
                    f"&partNumber=%5B{urllib.parse.quote(dpn)}%5D"
                    f"&activePage=1&activeDelta=20"
                )

        pn_is_usable = (
            bool(pn)
            and pn.upper() not in _generic
            and not _dell_chassis_pn.match(pn)
            and len(pn) >= 6
        )

        cand = pn if pn_is_usable else ""

        # Extract meaningful drive ID from the model string
        # Strip leading OEM vendor prefix ("Dell ", "HPE ", etc.)
        _oem_pfx = re.compile(
            r"^(?:DELL|HP[E]?|LENOVO|CISCO|IBM|FUJITSU|HUAWEI|NEC|INTEL|SAMSUNG|MICRON|TOSHIBA|KIOXIA|SEAGATE|WD|WESTERN DIGITAL)\s+",
            re.I,
        )
        clean = _oem_pfx.sub("", mdl).strip()
        # Remove capacity tokens (1.0TB, 400GB, 960 GB) and generic descriptor words
        clean = re.sub(r"\b[\d.]+\s*[TG]B\b", "", clean, flags=re.I)
        clean = re.sub(
            r"(?i)\b(express|flash|nvme|pcie|u\.2|ssd|sata|sas|hot.plug|"
            r"sff|lff|hhhl|fhhl|enterprise|value|mixed|use|read|write|"
            r"intensive|endurance|performance|small|form|factor)\b",
            "",
            clean,
        )
        clean = " ".join(clean.split())

        # Pick the first token that contains BOTH letters and digits — that's
        # the drive model identifier (P4500, SSDSC2BX40, PM983, MZ7LH960…)
        tokens = clean.split()
        kw = next(
            (t for t in tokens if re.search(r"[A-Za-z]", t) and re.search(r"\d", t)),
            " ".join(tokens[:2]) if tokens else mdl,
        )

        if not cand:
            cand = kw

        # Check if candidate is a specific physical drive product ID or ODM part number
        # (e.g. HPE 'VK001920GWSXK', 'MR000240GWFLU', Intel 'SSDSC2KG960G8R',
        # Toshiba 'PX05SMB080Y', Micron 'MTFDDAV240TCB', Kioxia 'KCD6XLUL3T84').
        # Broadcom Compatibility Guide's 'keyword' query fails against the Product Id
        # index; structured 'productId=[...]' yields exact certified entries.
        # Conversely, generic marketing families (P4500, P5600, PM1725b) are indexed
        # in marketing text and must continue using keyword queries.
        is_pid = (
            not is_magnetic
            and bool(cand)
            and 8 <= len(cand) <= 40
            and len(cand.split()) == 1
            and bool(re.search(r"[A-Za-z]", cand))
            and bool(re.search(r"\d", cand))
            and not bool(re.match(r"^(?:P|PM|CM|CD|PE)\d{3,4}[A-Za-z]?$", cand, re.I))
        )

        if is_pid:
            return (
                f"https://compatibilityguide.broadcom.com/search?persona=live&program=ssd"
                f"&supportedReleases=%5BESXi+9.1+%28vSAN+9.1%29%7C%7CESXi+9.0+%28vSAN++9.0%29%5D"
                f"&column=partnerName&order=asc"
                f"&productId=%5B{urllib.parse.quote(cand)}%5D"
                f"&activePage=1&activeDelta=20"
            )

        # Only apply Dell partner filter when the drive is explicitly Dell-branded
        # (model string leads with "Dell"). ODM drives (e.g. Intel, Toshiba) that
        # happen to carry Dell chassis PNs may be indexed under the ODM's BCG entry.
        is_dell_branded = bool(re.search(r"(?i)^dell\b", mdl))
        partner = "&partners=%5BDell%5D" if is_dell_branded else ""

        return (
            f"{BCG_BASE_URL}&program={program}&keyword={BCGLinkGenerator._enc(kw)}"
            "&supportedReleases=%5BESXi+9.1+%28vSAN+9.1%29%7C%7CESXi+9.0+%28vSAN++9.0%29%5D"
            f"{partner}"
        )

    @staticmethod
    def pci_exact(
        vid: str,
        did: str,
        svid: str = "",
        ssid: str = "",
        program: str = "io",
        release_filter: bool = True,
        device_type: str = "",
    ) -> str:
        """Build exact PCI ID search URL using Broadcom BCG structured query parameters.

        e.g., https://compatibilityguide.broadcom.com/search?program=io&persona=live&column=brandName&order=asc&productReleaseVersion=%5BESXi+9.1%7C%7CESXi+9.0%5D&vid=%5B14e4%5D&did=%5B1805%5D&svid=%5B14e4%5D&maxSsid=%5B159a%5D&activePage=1&activeDelta=20
        """
        v = normalize_pci_id(vid).upper()
        d = normalize_pci_id(did).upper()
        sv = normalize_pci_id(svid).upper()
        ss = normalize_pci_id(ssid).upper()

        if not (v and d):
            return f"https://compatibilityguide.broadcom.com/search?program={program}&persona=live"

        params = [
            f"program={program}",
            "persona=live",
            "column=brandName",
            "order=asc",
        ]

        if release_filter:
            if program in ("ssd", "hdd"):
                params.append("supportedReleases=%5BESXi+9.1+%28vSAN+9.1%29%7C%7CESXi+9.0+%28vSAN++9.0%29%5D")
            elif program in ("vsanio", "rdmanic"):
                params.append("productReleaseVersion=%5BESXi+9.1+%28vSAN+9.1%29%7C%7CESXi+9.0+%28vSAN+9.0%29%5D")
            elif program == "io":
                params.append("productReleaseVersion=%5BESXi+9.1%7C%7CESXi+9.0%5D")

        if device_type:
            params.append(f"ioDeviceType=%5B{urllib.parse.quote(device_type)}%5D")

        if v:
            params.append(f"vid=%5B{v}%5D")
        if d:
            params.append(f"did=%5B{d}%5D")
        if sv:
            params.append(f"svid=%5B{sv}%5D")
        if ss:
            ssid_key = "ssid" if program in ("ssd", "hdd") else "maxSsid"
            params.append(f"{ssid_key}=%5B{ss}%5D")

        params.extend(["activePage=1", "activeDelta=20"])

        return "https://compatibilityguide.broadcom.com/search?" + "&".join(params)

    @staticmethod
    def pci_generic_fallback(vid: str, did: str, program: str = "io") -> str:
        """Build generic chipset PCI search URL using vid and did parameters."""
        return BCGLinkGenerator.pci_exact(vid, did, svid="", ssid="", program=program, release_filter=True)

    @staticmethod
    def storage_exact(
        model: str,
        part_number: str = "",
        vid: str = "",
        did: str = "",
        svid: str = "",
        ssid: str = "",
        media_type: str = "",
    ) -> str:
        """Build BCG storage search URL using exact PCI ID quad when available, falling back to model search."""
        v = normalize_pci_id(vid)
        d = normalize_pci_id(did)
        media = str(media_type or "").upper()
        is_magnetic = any(k in media for k in ("HDD", "SMR", "MAGNETIC", "HARD"))
        program = "hdd" if is_magnetic else "ssd"

        if v and d:
            BCGLinkGenerator._log_debug_once(
                f"BCG Storage search using exact PCI IDs: VID={v}, DID={d}, "
                f"SVID={svid or 'none'}, SSID={ssid or 'none'} (model='{model}')"
            )
            return BCGLinkGenerator.pci_exact(v, d, svid, ssid, program=program, release_filter=True)
        BCGLinkGenerator._log_debug_once(
            f"BCG Storage search for '{model}': using model/part-number keyword search."
        )
        return BCGLinkGenerator.storage(model, part_number, media_type=media_type)

    # Decoded: [ESXi 9.1||ESXi 9.0]  — same concept as the SSD filter but
    # without the vSAN qualifier so it matches IO/NIC entries that are indexed
    # against the bare hypervisor release rather than the vSAN bundle.
    _IO_V9_RELEASES = (
        "&supportedReleases=%5BESXi+9.1%7C%7CESXi+9.0%5D"
    )

    @staticmethod
    def io_device(name: str) -> str:
        """BCG IO/NIC/HBA search pre-filtered to vSphere 9.1 / 9.0."""
        clean = BCGLinkGenerator._clean_nic_name(name)
        return (
            f"{BCG_BASE_URL}&program=io&keyword={BCGLinkGenerator._enc(clean)}"
            f"{BCGLinkGenerator._IO_V9_RELEASES}"
        )

    @staticmethod
    def io_device_fw(name: str, firmware: str) -> str:
        """BCG IO search with firmware version appended to keyword.

        Useful for direct firmware-to-listing cross-check: e.g. searching for
        "ConnectX-5 16.35.1012" or "QLE2692 8.07.00" lands on BCG entries where
        the SE can confirm the installed firmware appears in the supported list.
        Returns the plain io_device link when firmware is unknown.
        """
        clean = BCGLinkGenerator._clean_nic_name(name)
        fw = str(firmware or "").strip()
        if not fw or fw.upper() in ("N/A", "UNKNOWN", ""):
            return BCGLinkGenerator.io_device(clean)
        kw = f"{clean} {fw}".strip()
        return (
            f"{BCG_BASE_URL}&program=io&keyword={BCGLinkGenerator._enc(kw)}"
            f"{BCGLinkGenerator._IO_V9_RELEASES}"
        )

    @staticmethod
    def fc_hba(name: str) -> str:
        """BCG IO search for a Fibre Channel HBA using only the core model number.

        Verbose Redfish adapter strings (e.g. "Emulex LPe35000-M Dual-Port 32Gb
        Fibre Channel Adapter") produce zero BCG results when used verbatim.
        This method extracts just the model token so the search lands directly on
        the HCL entry.

        Supported families:
          Broadcom / Emulex Prism  : LPe35000, LPe36000
          Broadcom / Emulex Prism+ : LPe37000, LPe38000
          Marvell / QLogic 32G     : QLE2770, QLE2772, QLE2774
          Marvell / QLogic 64G     : QLE2870, QLE2872, QLE2874
        """
        n = (name or "").strip()
        # Emulex/Broadcom Prism / Prism+ family (LPe35xxx–LPe38xxx)
        lpe = re.search(r"\b(LPe3[5678]\d{3,4}[A-Z0-9\-]*)", n, re.I)
        if lpe:
            kw = lpe.group(1).upper()
            return (
                f"{BCG_BASE_URL}&program=io&keyword={BCGLinkGenerator._enc(kw)}"
                f"{BCGLinkGenerator._IO_V9_RELEASES}"
            )
        # Marvell QLogic: QLE2770–QLE2774 (32G) and QLE2870–QLE2874 (64G)
        qle_fc = re.search(r"\b(QLE2[78]7[024][A-Z0-9\-]*)", n, re.I)
        if qle_fc:
            kw = qle_fc.group(1).upper()
            return (
                f"{BCG_BASE_URL}&program=io&keyword={BCGLinkGenerator._enc(kw)}"
                f"{BCGLinkGenerator._IO_V9_RELEASES}"
            )
        # Generic fallback: clean the name and use standard io_device
        return BCGLinkGenerator.io_device(BCGLinkGenerator._clean_nic_name(n))

    @staticmethod
    def cna_ethernet(name: str, driver: str = "") -> str:
        """BCG IO search for the Ethernet (NIC) persona of a CNA / VIC adapter."""
        clean = BCGLinkGenerator._clean_nic_name(name)
        kw = f"{clean} {driver}".strip() if driver else clean
        return (
            f"{BCG_BASE_URL}&program=io&keyword={BCGLinkGenerator._enc(kw)}"
            f"{BCGLinkGenerator._IO_V9_RELEASES}"
        )

    @staticmethod
    def cna_fc(name: str, driver: str = "") -> str:
        """BCG IO search for the Fibre Channel / FCoE (vHBA) persona of a CNA / VIC adapter."""
        clean = BCGLinkGenerator._clean_nic_name(name)
        kw = f"{clean} {driver}".strip() if driver else clean
        return (
            f"{BCG_BASE_URL}&program=io&keyword={BCGLinkGenerator._enc(kw)}"
            f"{BCGLinkGenerator._IO_V9_RELEASES}"
        )

    @staticmethod
    def _clean_nic_name(name: str) -> str:
        """Extract the core model identifier from a verbose NIC/IO adapter description.

        Redfish model strings often carry speed, port-count, form-factor, and
        vendor-prefix tokens that cause zero BCG results when used verbatim
        (e.g. "MLNX 25GbE 2P ConnectX4LX RNDC" → BCG wants "ConnectX-4 Lx").
        Priority: Cisco VIC → FlexFabric → ConnectX → Intel model# → Broadcom BCM# → QLogic QL# →
        Chelsio T# → Solarflare SFN# → generic strip fallback.
        """
        n = str(name or "").strip()

        # Cisco VIC: "Cisco UCS VIC 1457 Quad Port 10/25G", "VIC 1387", "VIC 1225"
        vic = re.search(r"\bVIC[-\s]?(\d{4,5}[A-Za-z0-9\-]*)", n, re.I)
        if vic:
            return f"VIC {vic.group(1)}"

        # HPE FlexFabric: "HPE FlexFabric 20Gb 2-port 650FLB", "FlexFabric 580FLB"
        ff = re.search(r"FlexFabric.*?(\b\d{3,4}(?:FLR|FLB|SFP|T|M|i)?[A-Za-z0-9\-\+]*)", n, re.I)
        if ff and re.search(r"\d", ff.group(1)) and not re.match(r"^\d+G", ff.group(1), re.I):
            return f"FlexFabric {ff.group(1)}"

        # Mellanox/NVIDIA ConnectX: "ConnectX4LX", "ConnectX-5", "ConnectX-6 Dx"
        cx = re.search(r"ConnectX[-\s]?(\d+)\s*([A-Za-z]+)?", n, re.I)
        if cx:
            num = cx.group(1)
            raw = (cx.group(2) or "").upper()
            # Only recognised model suffixes (Lx, Dx, Ex, Vx) are kept;
            # form-factor tokens like OCP, RNDC, PCIe are silently dropped.
            sfx = {"LX": " Lx", "DX": " Dx", "EX": " Ex", "VX": " Vx"}.get(raw, "")
            return f"ConnectX-{num}{sfx}"

        # Intel: E810[-…], XXV710, XL710, X710, X550, X540, X520, I350, I210, etc.
        intel = re.search(
            r"\b(E\d{3,4}[-A-Z0-9]*|XXV\d{3,4}[A-Z0-9\-]*|XL\d{3,4}[A-Z0-9\-]*"
            r"|X\d{3,4}[A-Z0-9\-]*|I\d{3,4}[A-Z0-9\-]*)\b",
            n, re.I
        )
        if intel:
            return intel.group(1).upper()

        # Broadcom NetXtreme: BCM57xxx, BCM5xxx (with explicit BCM prefix in string)
        bcm = re.search(r"\b(BCM\d{4,6}[A-Z0-9\-]*)\b", n, re.I)
        if bcm:
            return bcm.group(1).upper()

        # Broadcom NIC with "BRCM" vendor abbreviation (no BCM prefix on chip number):
        # "BRCM 4P 25G SFP 57504S OCP NIC" → "BCM57504"
        if re.search(r"\bBRCM\b", n, re.I):
            brcm_chip = re.search(r"\b(5[5-9]\d{3})", n)
            if brcm_chip:
                return f"BCM{brcm_chip.group(1)}"

        # QLogic/Marvell FastLinQ: QL41xxx, QLE2xxx, etc.
        # No trailing \b so "QL41262HMKR-DE" returns "QL41262" (just the model base).
        ql = re.search(r"\b(QLE?\d{4,6})", n, re.I)
        if ql:
            return ql.group(1).upper()

        # Chelsio T-series: T6225, T62100, T520
        chelsio = re.search(r"\b(T\d{4,5}[-A-Z0-9]*)\b", n, re.I)
        if chelsio:
            return chelsio.group(1)

        # Solarflare / Xilinx SFN-series
        sfn = re.search(r"\b(SFN[-\w]+)\b", n, re.I)
        if sfn:
            return sfn.group(1).upper()

        # HPE NIC model numbers: 562FLR-SFP+, 331i, 631FLR-SFP28, 530FLR-SFP+, 562SFP+, 561T, etc.
        hpe_nic = re.search(r"\b(\d{3}(?:FLR|FLB|SFP|T|M|i)[A-Za-z0-9\-\+]*)", n, re.I)
        if hpe_nic:
            return hpe_nic.group(1)

        # Generic fallback: strip speed/port/form-factor tokens and vendor prefix
        # Also handles HPE-style names ("HPE Eth 10/25Gb 2p 631FLR-SFP28 Adptr"):
        #   • dual-speed tokens: 10/25Gb, 1/10GbE, etc.  (must precede single-speed strip)
        #   • HPE / Hpe vendor prefix
        #   • Abbreviated "Eth" (Ethernet) and "Adptr"/"Adpt" (Adapter)
        cleaned_symbols = re.sub(r"[\[\]\(\)]", " ", n)
        cleaned_symbols = re.sub(
            r"(?i)\b(?:inc|incorporated|and\s+subsidiaries|subsidiaries|corp|corporation|llc|ltd|limited|co|company|technologies|technology)\b\.?",
            " ",
            cleaned_symbols
        )
        cleaned_symbols = re.sub(
            r"(?i)\b(?:embedded|integrated|slot|partition)\b|\b(?:partition|port)\s*\d+\b",
            " ",
            cleaned_symbols
        )
        stripped = re.sub(
            r"(?i)\b\d+/\d+\s*[Gg][Bb][Ee]?\b"                                # 10/25Gb, 1/10GbE
            r"|\b(mlnx|mellanox|intel|broadcom|brcm|qlogic|chelsio|solarflare|marvell|emulex|oce|infiniband|hpe)\b"
            r"|\b\d+[\-\s]*(?:port|p)\b"                                      # 2-port, 4-port, 2p, 4p
            r"|\b\d+\s*[Gg][Bb][Ee]?\b|\b\d+\s*[Gg]\b"                        # 10Gb, 25G
            r"|(?<![A-Za-z0-9\-])\b(?:q?sfp(?:\+|\d+)?|pcie|ocp|rndc|rdma|adapter|adptr|adpt|network|ethernet|eth|flexfabric|gigabit|controller|card|nic)\b",
            "", cleaned_symbols, flags=re.I
        ).strip()
        cleaned = " ".join(stripped.split())
        if cleaned and re.search(r"[A-Za-z]", cleaned):
            return cleaned
        for v in ["Broadcom", "Mellanox", "Intel", "QLogic", "Chelsio", "Solarflare", "Marvell", "Emulex", "HPE", "Cisco"]:
            if re.search(rf"\b{v}\b", n, re.I):
                return v
        return n

    @staticmethod
    def io_nic(name: str, firmware: str = "") -> tuple:
        """Return (io_hcl_url, vsan_nic_url) for a NIC adapter.

        io_hcl_url   — BCG IO HCL filtered to vSphere 9.1/9.0; includes firmware
                       version in keyword when known for direct cross-check.
        vsan_nic_url — BCG RDMA NIC HCL filtered to vSAN 9.1/9.0 bundle; a match here
                       indicates the NIC is certified for vSAN (RDMA/RoCE capable).

        Both use the cleaned model identifier rather than the raw Redfish description
        to avoid zero-result searches from overly verbose marketing names.
        """
        clean = BCGLinkGenerator._clean_nic_name(name)
        fw = str(firmware or "").strip()
        kw = f"{clean} {fw}".strip() if fw and fw.upper() not in ("N/A", "UNKNOWN", "") else clean
        io_url = (
            f"{BCG_BASE_URL}&program=io&keyword={BCGLinkGenerator._enc(kw)}"
            f"{BCGLinkGenerator._IO_V9_RELEASES}"
        )
        vsan_url = (
            f"{BCG_BASE_URL}&program=rdmanic&keyword={BCGLinkGenerator._enc(clean)}"
            "&supportedReleases=%5BESXi+9.1+%28vSAN+9.1%29%7C%7CESXi+9.0+%28vSAN+9.0%29%5D"
        )
        return io_url, vsan_url

    @staticmethod
    def io_nic_exact(name: str, firmware: str = "", vid: str = "", did: str = "", svid: str = "", ssid: str = "") -> tuple:
        """Build exact BCG IO & vSAN RDMA NIC search URLs using PCI IDs when available, falling back to model search."""
        v = normalize_pci_id(vid).upper()
        d = normalize_pci_id(did).upper()
        sv = normalize_pci_id(svid).upper()
        ss = normalize_pci_id(ssid).upper()

        if v and d:
            BCGLinkGenerator._log_debug_once(
                f"BCG IO NIC search using exact PCI IDs: VID={v}, DID={d}, "
                f"SVID={sv or 'none'}, SSID={ss or 'none'} (name='{name}')"
            )
            io_url = BCGLinkGenerator.pci_exact(v, d, sv, ss, program="io", release_filter=True, device_type="Network")
            vsan_url = BCGLinkGenerator.pci_exact(v, d, sv, ss, program="rdmanic", release_filter=True, device_type="Network")
            return io_url, vsan_url

        clean_kw = BCGLinkGenerator._clean_nic_name(name)
        BCGLinkGenerator._log_debug_once(
            f"BCG IO NIC search for '{name}': using model keyword search for '{clean_kw}'."
        )
        return BCGLinkGenerator.io_nic(name, firmware)

    @staticmethod
    def cpu(cpu_model: Union[str, dict, None] = "", processor_id: str = "") -> str:
        """Build BCG CPU URL.

        For AMD EPYC processors, resolves to the direct BCG CPU series detail page
        using the Broadcom productId and exact cpuSeries redirectFrom taxonomy,
        determined via CPUID (e.g. 0x00830F10 -> Rome, productId 134) or model
        heuristics (e.g. EPYC 7402 -> Rome, productId 134).

        For Intel Xeon Scalable CPUs (1st-5th Gen), uses the BCG cpuSeries filter
        with the exact BCG taxonomy string so the search lands directly on the
        right generation page.

        Falls back to a keyword search (or CPUID keyword search if unknown hex
        CPUID is provided).
        """
        if isinstance(cpu_model, dict):
            if not processor_id:
                processor_id = str(cpu_model.get("processor_id") or "")
            cpu_model = str(cpu_model.get("model") or "")

        model_str = str(cpu_model or "").strip()
        pid_str = str(processor_id or "").strip()

        # If processor_id is omitted but cpu_model looks like a hex CPUID:
        if not pid_str and (
            model_str.upper().startswith("0X")
            or (len(model_str) == 8 and bool(re.fullmatch(r"[0-9A-Fa-f]{8}", model_str)))
        ):
            pid_str = model_str
            model_str = ""

        # Normalize CPUID to 0xXXXXXXXX uppercase hex
        norm_pid = ""
        if pid_str:
            p_clean = pid_str.strip()
            if p_clean.upper().startswith("0X"):
                p_clean = p_clean[2:]
            if re.fullmatch(r"[0-9A-Fa-f]{1,8}", p_clean):
                norm_pid = f"0x{int(p_clean, 16):08X}"

        clean = re.sub(r"\(R\)|\(TM\)|@\s*[\d.]+\s*GHz?", "", model_str, flags=re.I).strip()
        clean = " ".join(clean.split())
        s = clean.upper()

        # 1. Match AMD EPYC / Opteron by CPUID
        if norm_pid and norm_pid in BCGLinkGenerator._AMD_CPUID_SERIES:
            prod_id, series_name = BCGLinkGenerator._AMD_CPUID_SERIES[norm_pid]
            # Disambiguate Siena (8004) vs Genoa (9004) if shared CPUID
            if norm_pid in ("0x00A10F11", "0x00AA0F02") and (
                "8004" in clean or "SIENA" in s or bool(re.search(r"\b8\d{3}\b", clean))
            ):
                prod_id, series_name = 159, "AMD EPYC 8004 Series"
            return BCGLinkGenerator.cpu_detail(prod_id, series_name)

        # 2. Check for AMD processor by model string
        if re.search(r"(?i)\bamd\b|\bepyc\b|\bopteron\b", s):
            # Check generation / series from model
            if re.search(r"\b8\d{3}\b|\b8004\b|\bSiena\b", clean, re.I):
                return BCGLinkGenerator.cpu_detail(159, "AMD EPYC 8004 Series")
            if re.search(r"\b9\d{2}5\b|\b9005\b|\bTurin\b", clean, re.I):
                return BCGLinkGenerator.cpu_detail(169, "AMD EPYC 9005 Series")
            if re.search(r"\b9\d{2}4\b|\b9004\b|\bGenoa\b|\bBergamo\b", clean, re.I):
                return BCGLinkGenerator.cpu_detail(158, "AMD EPYC 9004 Series")
            if re.search(r"\b7\d{2}3[A-Z]*\b|\b7003\b|\bMilan\b", clean, re.I):
                return BCGLinkGenerator.cpu_detail(145, "AMD EPYC 7003/7003X Series")
            if re.search(r"\b7[0-9]{2}2[A-Z]*\b|\b7[FH]x2\b|\b7[FH]\d{2}\b|\b7H12\b|\b7002\b|\bRome\b", clean, re.I):
                return BCGLinkGenerator.cpu_detail(134, "AMD EPYC 7002/7Fx2/7Hx2 Series")
            if re.search(r"\b7\d{2}1[A-Z]*\b|\b7001\b|\bNaples\b", clean, re.I):
                return BCGLinkGenerator.cpu_detail(124, "AMD EPYC 7001 Series")

            # General 4-digit EPYC numbering scheme: e.g. 7402 -> Rome, 7763 -> Milan
            epyc_m = re.search(r"\b(\d)(\d{2})(\d)[A-Z]*\b", clean)
            if epyc_m:
                first_d, last_d = epyc_m.group(1), epyc_m.group(3)
                if first_d == "7" and last_d == "2":
                    return BCGLinkGenerator.cpu_detail(134, "AMD EPYC 7002/7Fx2/7Hx2 Series")
                if first_d == "7" and last_d == "3":
                    return BCGLinkGenerator.cpu_detail(145, "AMD EPYC 7003/7003X Series")
                if first_d == "7" and last_d == "1":
                    return BCGLinkGenerator.cpu_detail(124, "AMD EPYC 7001 Series")
                if first_d == "8" and last_d == "4":
                    return BCGLinkGenerator.cpu_detail(159, "AMD EPYC 8004 Series")
                if first_d == "9" and last_d == "4":
                    return BCGLinkGenerator.cpu_detail(158, "AMD EPYC 9004 Series")
                if first_d == "9" and last_d == "5":
                    return BCGLinkGenerator.cpu_detail(169, "AMD EPYC 9005 Series")

            # Opteron checks
            if re.search(r"\b63\d{2}\b|\b6300\b", clean):
                return BCGLinkGenerator.cpu_detail(76, "AMD Opteron 6300 Series")
            if re.search(r"\b43\d{2}\b|\b4300\b", clean):
                return BCGLinkGenerator.cpu_detail(78, "AMD Opteron 4300 Series")
            if re.search(r"\b33\d{2}\b|\b3300\b", clean):
                return BCGLinkGenerator.cpu_detail(82, "AMD Opteron 3300 Series")
            if re.search(r"\b62\d{2}\b|\b6200\b", clean):
                return BCGLinkGenerator.cpu_detail(58, "AMD Opteron 6200 Series")
            if re.search(r"\b42\d{2}\b|\b4200\b", clean):
                return BCGLinkGenerator.cpu_detail(57, "AMD Opteron 4200 Series")
            if re.search(r"\b32\d{2}\b|\b3200\b", clean):
                return BCGLinkGenerator.cpu_detail(79, "AMD Opteron 3200 Series")

            if norm_pid:
                return f"{BCG_BASE_URL}&program=cpu&keyword={norm_pid}&column=cpuSeries&order=asc"

            num_m = re.search(r"\b(\d{4,5}[A-Z+]*)\b", clean)
            kw = f"EPYC {num_m.group(1)}" if num_m else re.sub(
                r"(?i)\bamd\b|\bprocessor\b|\bcpu\b", "", clean).strip()
            return f"{BCG_BASE_URL}&program=cpu&keyword={BCGLinkGenerator._enc(kw)}"

        # 3. Intel processors
        if re.search(r"(?i)\bintel\b|\bxeon\b", s):
            series_name = BCGLinkGenerator.resolve_cpu_series(cpu_model, processor_id)
            if series_name:
                enc = BCGLinkGenerator._enc(f"[{series_name}]")
                return (
                    f"{BCG_BASE_URL}&program=cpu"
                    f"&cpuSeries={enc}"
                    "&column=cpuSeries&order=asc"
                )

            num_m = re.search(r"\b(\d{4,5})[A-Z+]*\b", clean)
            if num_m:
                kw = f"Intel Xeon {num_m.group(0)}"
            else:
                kw = re.sub(r"(?i)\bprocessor\b|\bcpu\b", "", clean).strip()

            if norm_pid:
                return f"{BCG_BASE_URL}&program=cpu&keyword={norm_pid}&column=cpuSeries&order=asc"
            return f"{BCG_BASE_URL}&program=cpu&keyword={BCGLinkGenerator._enc(kw)}"

        # 4. Unknown CPU model / fallback
        if norm_pid:
            return f"{BCG_BASE_URL}&program=cpu&keyword={norm_pid}&column=cpuSeries&order=asc"
        kw = re.sub(r"(?i)\bprocessor\b|\bcpu\b", "", clean).strip()
        return f"{BCG_BASE_URL}&program=cpu&keyword={BCGLinkGenerator._enc(kw)}"

    @staticmethod
    def intel_ark(cpu_model: str) -> str:
        """Build Intel ARK search URL for a given CPU model string."""
        clean = re.sub(r"\(R\)|\(TM\)|@\s*[\d.]+\s*GHz?", "", str(cpu_model or ""), flags=re.I).strip()
        clean = " ".join(clean.split())
        return f"https://ark.intel.com/content/www/us/en/ark/search.html#@Processors&q={BCGLinkGenerator._enc(clean)}"

    @staticmethod
    def amd_product(cpu_model: str) -> str:
        """Build AMD product search URL for a given EPYC CPU model string."""
        model_str = str(cpu_model or "")
        num_m = re.search(r"\b(\d{4,5}[A-Z+]*)\b", model_str)
        kw = f"EPYC {num_m.group(1)}" if num_m else re.sub(r"(?i)\bamd\b|\bprocessor\b|\bcpu\b", "", model_str).strip()
        return f"https://www.amd.com/en/search?q={BCGLinkGenerator._enc(kw)}"

    @staticmethod
    def gpu(gpu_model: str) -> str:
        """Build a BCG GPU/accelerator search URL with a short, targeted keyword.

        Raw model names from BMC firmware are often very long (e.g. "Intel Data Center GPU
        Flex 140") and produce zero BCG results.  Extract only the meaningful model token.
        Priority: NVIDIA card code → AMD MI code → Intel Flex/Gaudi code → 2-token fallback.
        """
        name = (gpu_model or "").strip()
        # NVIDIA datacenter & consumer: H100, H200, A100, A40, A30, L40S, L4, T4, V100,
        # RTX 4090, RTX 5090, etc.
        m = re.search(
            r'\b(H\d{3}[A-Z]?|A\d{2,3}[A-Z]?|L\d{2,3}[A-Z]?|V100|T4|RTX\s*\d{4}\s*[A-Za-z]*)\b',
            name, re.I)
        if m:
            return f"{BCG_BASE_URL}&program=sptg&keyword={BCGLinkGenerator._enc(m.group(1).strip())}"
        # AMD Instinct: MI300X, MI250X, MI210, MI100, etc.
        m = re.search(r'\bMI\s*\d{3}[A-Z]?\b', name, re.I)
        if m:
            return f"{BCG_BASE_URL}&program=sptg&keyword={BCGLinkGenerator._enc(m.group(0).strip())}"
        # Intel datacenter: Flex 140, Flex 170, Gaudi 2, Gaudi 3
        m = re.search(r'\b(Flex\s*\d{3}|Gaudi\s*\d)\b', name, re.I)
        if m:
            return f"{BCG_BASE_URL}&program=sptg&keyword={BCGLinkGenerator._enc(m.group(1).strip())}"
        # Fallback: first two tokens with more than 2 characters
        tokens = [t for t in re.split(r'\s+', name) if len(t) > 2][:2]
        kw = ' '.join(tokens) if tokens else name
        return f"{BCG_BASE_URL}&program=sptg&keyword={BCGLinkGenerator._enc(kw)}"

    @staticmethod
    def device_detail(product_id: str, program: str = "ssd") -> str:
        """Build a direct BCG device detail URL using Broadcom product ID and program."""
        pid = str(product_id or "").strip()
        prog = str(program or "ssd").strip().lower()
        if not pid:
            return ""
        prog_map = {
            "nic": "rdmanic",
            "controller": "vsanio",
            "drives": "ssd",
        }
        prog = prog_map.get(prog, prog)
        return f"https://compatibilityguide.broadcom.com/detail?productId={BCGLinkGenerator._enc(pid)}&program={BCGLinkGenerator._enc(prog)}"

    @staticmethod
    def prefer_device_or_search(product_id: str, device_program: str, fallback_func, *args, **kwargs) -> str:
        """Return direct BCG detail URL if product_id is present, otherwise call fallback_func."""
        if product_id:
            url = BCGLinkGenerator.device_detail(product_id, device_program)
            if url:
                return url
        return fallback_func(*args, **kwargs)

