"""Identity match between a BMC Redfish capture and an ESXi SSH capture.

MAC addresses are never an identity key. See docs/ESXI_SSH_DEDUPE.md.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Sequence, Set, Tuple

from vcf_hci.plugins.vinv.reconcile import _norm_host_token, _norm_serial, _short_hostname, uuid_variants


def _text(record: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    nested = record.get("system")
    if isinstance(nested, Mapping):
        for key in keys:
            value = nested.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def identity_keys(record: Mapping[str, Any]) -> Set[str]:
    keys: Set[str] = set()
    raw_uuid = _text(record, "uuid", "smbios_uuid", "system_uuid", "serial_uuid")
    canonical, swapped = uuid_variants(raw_uuid)
    if canonical:
        keys.add("uuid:" + canonical)
    if swapped and swapped != canonical:
        keys.add("uuid:" + swapped)
    # A model SKU is not a serial: every host of the same model shares it.
    serial = _norm_serial(_text(record, "serial", "serial_number", "service_tag", "system_serial"))
    if serial:
        keys.add("serial:" + serial)
    host = _norm_host_token(_text(record, "hostname", "name", "esxi_host", "bmc_host"))
    if host:
        keys.add("host:" + _short_hostname(host))
    return keys


def same_host(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    a, b = identity_keys(left), identity_keys(right)
    for prefix in ("uuid:", "serial:", "host:"):
        x = {key for key in a if key.startswith(prefix)}
        y = {key for key in b if key.startswith(prefix)}
        if x and y:
            return bool(x & y)
    return False


def filter_esxi_targets(
    candidates: Sequence[Mapping[str, Any]],
    completed_bmc: Iterable[Mapping[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Drop ESXi SSH targets already captured by BMC in this session."""
    known = [dict(item) for item in completed_bmc]
    keep: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for candidate in candidates:
        row = dict(candidate)
        if any(same_host(row, done) for done in known):
            row["skip_reason"] = "skipped: already captured via BMC"
            skipped.append(row)
        else:
            keep.append(row)
    return keep, skipped
