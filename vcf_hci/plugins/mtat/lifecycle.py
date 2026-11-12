"""Experimental MTAT is available by default; collection still requires acknowledgement."""

from __future__ import annotations

from typing import Mapping, Optional

from vcf_hci.plugins.mtat.constants import FEATURE_ID, FEATURE_NAME, LIFECYCLE, MTAT_CONTRACT, WARNING


def experimental_enabled(cli_flag: bool = False, environ: Optional[Mapping[str, str]] = None) -> bool:
    # Legacy arguments are accepted for callers from earlier versions.
    return True


def disabled_body() -> dict:
    return {"error_code": "experimental_mtat_disabled", "error": WARNING}


def catalog_entry(enabled: bool = True) -> dict:
    return {
        "id": FEATURE_ID,
        "name": FEATURE_NAME,
        "inbox": True,
        "lifecycle": LIFECYCLE,
        "enabled": enabled,
        "mtat_contract": MTAT_CONTRACT,
        "warning": WARNING,
        "enablement": "Available in Plugins. Acknowledge experimental collection before connecting.",
        "sources": [
            {"kind": "vcenter", "readiness": "unvalidated"},
            {"kind": "operations-rest", "readiness": "unvalidated"},
            {"kind": "operations-xlsx", "readiness": "unvalidated"},
        ],
    }
