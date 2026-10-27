"""Shared presentation of the tool's existing OEM chassis qualification rules."""

import re

from vcf_hci.compat.chassis import _is_oem_chassis_certified

KNOWN_VSPHERE_OEMS = {
    'DELL', 'HPE', 'HEWLETT', 'LENOVO', 'CISCO', 'FUJITSU', 'HUAWEI', 'NEC',
    'SUPERMICRO', 'QUANTA', 'QCT', 'GIGABYTE', 'INTEL',
}


def chassis_qualification(system: dict, cpu_verdict: str = '') -> dict:
    """Reuse host-card qualification; a vendor approval note is not a denial.

    These are existing tool rules, not a claim of a live BCG certification lookup.
    Appliance/TQR and missing chassis information remain unverified here.
    """
    vendor = str(system.get('vendor') or '').upper()
    model = str(system.get('model') or '').strip()
    known_oem = any(name in vendor for name in KNOWN_VSPHERE_OEMS)
    appliance = bool(system.get('hci_appliance')) or 'NUTANIX' in vendor or model.upper().startswith('NX-') or ' NX-' in f' {model.upper()}'
    valid_model = model.lower() not in ('', 'unknown', 'n/a', 'not available', 'not specified', 'system product name', 'to be filled by o.e.m.')
    qualified = not appliance and valid_model and (_is_oem_chassis_certified(vendor, model) or known_oem)
    vendor_approval = ('DELL' in vendor and bool(re.search(r'R[23456789]40|T[1346]40|C6420|MX[78]40C|XC[679]40', model, re.I))) or 'verify with oem' in cpu_verdict.lower() or 'confirm with vendor' in cpu_verdict.lower()
    return {'qualified': bool(qualified), 'vendor_approval': vendor_approval, 'appliance_tqr': appliance}
