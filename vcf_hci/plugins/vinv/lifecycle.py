"""Default-on Experimental availability for vSphere Inventory Export and Reconciliation."""

from __future__ import annotations

from vcf_hci.plugins.vinv.constants import (
    FEATURE_ID,
    FEATURE_NAME,
    LIFECYCLE,
    SCHEMA_VERSION,
    WARNING,
)


def disabled_body() -> dict:
    return {"error_code": "experimental_vinv_disabled", "error": WARNING}


def catalog_entry(enabled: bool = True) -> dict:
    return {
        "id": FEATURE_ID,
        "name": FEATURE_NAME,
        "inbox": True,
        "lifecycle": LIFECYCLE,
        "enabled": enabled,
        "schema_version": SCHEMA_VERSION,
        "warning": WARNING,
        "enablement": "Available in Plugins. Acknowledge experimental collection before connecting.",
        "sources": [
            {"kind": "vcenter", "readiness": "experimental"},
            {"kind": "vinv-xlsx", "readiness": "experimental"},
        ],
    }
