"""
Modular chassis & OEM certification evaluation for VCF 9.1.
"""
import re

from ..constants import BCG_OEM_CERTIFIED_SERVERS


def _is_oem_chassis_certified(vendor: str, model: str) -> bool:
    if not vendor or not model:
        return False
    v_up = str(vendor).upper()
    m_up = str(model).upper()
    for oem_key, patterns in BCG_OEM_CERTIFIED_SERVERS.items():
        if oem_key in v_up or any(re.search(pat, m_up, re.I) for pat in patterns):
            if any(re.search(pat, m_up, re.I) for pat in patterns):
                return True
    return False
