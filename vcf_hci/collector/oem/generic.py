"""
VCF Readiness Tool — Generic (pure DMTF) Redfish collector.

Starting point for adding support for a new BMC vendor.
Copy this file to oem/<vendor>.py, rename the class, implement only the
hooks that differ from standard DMTF behaviour, and register the class in
oem/__init__.py.
"""
from vcf_hci.collector.base import BaseRedfishCollector


class GenericCollector(BaseRedfishCollector):
    """Pure DMTF-compliant Redfish collector.

    All OEM hook methods return their DMTF defaults.  Use this as your
    base class when adding support for a new vendor.
    """
    # No overrides — everything runs from the DMTF defaults in BaseRedfishCollector.
