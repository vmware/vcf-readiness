"""
vcf_hci.servicetag — Dell Service Tag lookup and ESA readiness assessment.

Provides:
  DellTechDirectClient   — OAuth2 client for the Dell TechDirect API
  evaluate_esa_from_components — vSAN ESA readiness from a TechDirect BOM
  summarise_warranty     — compact warranty summary dict for HTML report cards

Credentials required:
  Register at https://techdirect.dell.com to obtain a client_id and client_secret.
  The VCF Readiness GUI stores these in the OS keychain under the key
  'dell-techdirect'.  This module is zero-dependency (stdlib only) and never
  reads credentials from disk directly — the caller is responsible for passing
  them in.

This feature is optional and disabled by default.  No part of the main Redfish
scan pipeline imports from this package unless Dell TechDirect credentials are
explicitly configured.
"""
from vcf_hci.servicetag.dell_api import DellTechDirectClient
from vcf_hci.servicetag.esa_evaluator import (
    evaluate_esa_from_components,
    summarise_warranty,
)

__all__ = [
    "DellTechDirectClient",
    "evaluate_esa_from_components",
    "summarise_warranty",
]
