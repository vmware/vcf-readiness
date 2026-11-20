"""Sidecar metadata. This object must never be embedded into an MTAT CSV."""

from __future__ import annotations

from vcf_hci.plugins.mtat.constants import (
    CONTRACT_REVISION,
    FEATURE_ID,
    LIFECYCLE,
    MTAT_CONTRACT,
    SCHEMA_VERSION,
    SECRET_FRAGMENTS,
    WARNING,
)
from vcf_hci.plugins.mtat.models import Assessment


def build_manifest(assessment: Assessment, product_version: str) -> dict:
    document = {
        "schema": SCHEMA_VERSION,
        "contract_revision": CONTRACT_REVISION,
        "feature_id": FEATURE_ID,
        "feature_lifecycle": LIFECYCLE,
        "warning": WARNING,
        "mtat_contract": MTAT_CONTRACT,
        "product_version": product_version,
        "source": {
            "kind": assessment.source_kind,
            "label": assessment.source_label,
            "version": assessment.source_version,
            "tls_verified": assessment.tls_verified,
            "validation_lane": assessment.validation_lane,
        },
        "range_name": assessment.range_name,
        "eligibility_policy": assessment.policy,
        "acknowledged": assessment.acknowledged,
        "warnings": list(assessment.warnings),
        "metrics": [
            {"host": row.host_name, "metric": item.metric, "source_key": item.source_key, "encoding": item.encoding, "authority": item.authority}
            for row in assessment.hosts for item in row.provenance
        ],
        "current_policy_reasons": [
            {"vm": row.vm_name, "reasons": list(row.current_policy_reasons)} for row in assessment.vms
        ],
    }
    _reject_secrets(document)
    return document


def _reject_secrets(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if any(fragment in str(key).lower() for fragment in SECRET_FRAGMENTS):
                raise ValueError("manifest contains a secret field")
            _reject_secrets(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_secrets(child)
