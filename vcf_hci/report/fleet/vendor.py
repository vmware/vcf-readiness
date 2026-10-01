"""OEM vendor normalization helper for fleet reports."""


def normalize_oem_vendor(vendor_raw: str) -> str:
    """Normalize raw BMC/system vendor string to a clean OEM display name."""
    v = (vendor_raw or "").strip()
    if not v:
        return "Unknown"
    v_upper = v.upper()
    if "DELL" in v_upper:
        return "Dell"
    if any(k in v_upper for k in ("HPE", "HEWLETT", "HP")):
        return "HPE"
    if "SUPER" in v_upper or "SUPERMICRO" in v_upper:
        return "Supermicro"
    if "CISCO" in v_upper or "CIMC" in v_upper:
        return "Cisco"
    if "LENOVO" in v_upper or "IBM" in v_upper:
        return "Lenovo"
    if "FUJITSU" in v_upper:
        return "Fujitsu"
    if "HUAWEI" in v_upper:
        return "Huawei"
    if "NEC" in v_upper:
        return "NEC"
    if "INSPUR" in v_upper:
        return "Inspur"
    return v.split()[0].title()
