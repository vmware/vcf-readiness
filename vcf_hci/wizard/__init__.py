"""Unified scan-wizard scope, credential rules, and host identity dedupe."""

from vcf_hci.wizard.dedupe import filter_esxi_targets, same_host
from vcf_hci.wizard.scope import Scope, credentials_needed, hcl_required, next_step, previous_step

__all__ = [
    "Scope",
    "credentials_needed",
    "filter_esxi_targets",
    "hcl_required",
    "next_step",
    "previous_step",
    "same_host",
]
