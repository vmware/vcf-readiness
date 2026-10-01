"""
VCF Readiness Tool — collector package.

Exports UniversalRedfishCollector (the combined class) and the
create_collector() OEM factory function.

Usage
-----
from vcf_hci.collector import UniversalRedfishCollector
# or use the OEM-aware factory:
from vcf_hci.collector import create_collector
collector = create_collector(host, user, password)
result = collector.run_assessment()
"""
from .base import BaseRedfishCollector
from .crawler import (
    RedfishCrawler,
    categorize_action,
    extract_resource_actions,
    normalize_redfish_uri,
)
from .oem import (
    CiscoCollector,
    DellCollector,
    GenericCollector,
    GigabyteCollector,
    HPECollector,
    IntelBMCCollector,
    LenovoCollector,
    QuantaCollector,
    SupermicroCollector,
    create_collector,
)

# Backward-compatible alias: UniversalRedfishCollector is the DMTF base class.
# Existing code that directly instantiates UniversalRedfishCollector continues
# to work; new code should prefer create_collector() for OEM-specific behaviour.
UniversalRedfishCollector = BaseRedfishCollector

__all__ = [
    "BaseRedfishCollector",
    "CiscoCollector",
    "DellCollector",
    "GenericCollector",
    "GigabyteCollector",
    "HPECollector",
    "IntelBMCCollector",
    "LenovoCollector",
    "QuantaCollector",
    "RedfishCrawler",
    "SupermicroCollector",
    "UniversalRedfishCollector",
    "categorize_action",
    "create_collector",
    "extract_resource_actions",
    "normalize_redfish_uri",
]
