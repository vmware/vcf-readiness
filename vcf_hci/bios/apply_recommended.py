"""Gated Dell/HPE BIOS recommended-settings apply (Avenue 1).

WARNING: This module can MUTATE BMC BIOS pending settings via Redfish PATCH.
The readiness CLI and Salt highstate must keep apply disabled by default.

Defaults:
  - dry_run=True
  - apply requires apply=True AND confirm=True
  - Lenovo/Cisco → experimental_not_implemented
  - Never auto-reboots the host
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Sequence

from vcf_hci.bios.recommend import build_recommend_report

# Canonical → common OEM AttributeRegistry-style names for PATCH payloads.
_DELL_KEY_MAP = {
    "BootMode": ["BootMode"],
    "ProcVirtualization": ["ProcVirtualization"],
    "VtdSupport": ["ProcVtForDirectedIo", "IntelVtForDirectedIo"],
    "VmdSupport": ["VmdEnable", "VmdSupport"],
    "SriovGlobalEnable": ["SriovGlobalEnable"],
    "LogicalProc": ["LogicalProc"],
    "ProcTurboMode": ["ProcTurboMode"],
    "NodeInterleave": ["NodeInterleave"],
}

_HPE_KEY_MAP = {
    "BootMode": ["BootMode"],
    "ProcVirtualization": ["ProcVirtualization"],
    "VtdSupport": ["IntelProcVtd", "AmdIoMmu"],
    "VmdSupport": ["IntelVmd", "VmdSupport"],
    "SriovGlobalEnable": ["Sriov", "SriovGlobalEnable"],
    "LogicalProc": ["ProcHyperthreading", "LogicalProc"],
    "ProcTurboMode": ["ProcTurbo"],
    "NodeInterleave": ["NodeInterleaving", "NodeInterleave"],
}

# Recommended PATCH values (best-effort; OEM enums vary)
_RECOMMENDED_VALUES = {
    "BootMode": "Uefi",
    "ProcVirtualization": "Enabled",
    "VtdSupport": "Enabled",
    "VmdSupport": "Disabled",
    "SriovGlobalEnable": "Enabled",
    "LogicalProc": "Enabled",
    "ProcTurboMode": "Enabled",
    "NodeInterleave": "Disabled",
}


def _vendor_key(vendor: Optional[str]) -> str:
    v = str(vendor or "").strip().lower()
    if "dell" in v:
        return "dell"
    if "hpe" in v or "hewlett" in v:
        return "hpe"
    if "lenovo" in v:
        return "lenovo"
    if "cisco" in v:
        return "cisco"
    return "generic"


def _resolve_oem_keys(canonical: str, vendor_key: str, present_attrs: Dict[str, Any]) -> Optional[str]:
    mapping = _DELL_KEY_MAP if vendor_key == "dell" else _HPE_KEY_MAP
    for candidate in mapping.get(canonical, [canonical]):
        if candidate in present_attrs:
            return candidate
        # case-insensitive
        for k in present_attrs:
            if k.lower() == candidate.lower():
                return k
    # Fall back to first mapped name even if not present (pending create)
    keys = mapping.get(canonical)
    return keys[0] if keys else None


def build_apply_plan(
    recommend_report: Dict[str, Any],
    bios_attrs: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Translate recommend deltas into OEM attribute PATCH plan (no network)."""
    vendor_key = recommend_report.get("vendor_key") or _vendor_key(recommend_report.get("vendor"))
    if vendor_key in ("lenovo", "cisco"):
        return {
            "status": "experimental_not_implemented",
            "vendor_key": vendor_key,
            "changes": [],
            "note": "Lenovo/Cisco BIOS apply is not implemented in Avenue 1 (awareness only).",
        }
    if vendor_key not in ("dell", "hpe"):
        return {
            "status": "unsupported",
            "vendor_key": vendor_key,
            "changes": [],
            "note": "BIOS apply supported for Dell/HPE only.",
        }

    attrs = dict(bios_attrs or {})
    changes: List[Dict[str, Any]] = []
    for cand in recommend_report.get("apply_candidates") or []:
        canonical = str(cand.get("attribute") or "")
        if canonical not in _RECOMMENDED_VALUES:
            continue
        oem_key = _resolve_oem_keys(canonical, vendor_key, attrs)
        if not oem_key:
            continue
        changes.append({
            "canonical": canonical,
            "oem_attribute": oem_key,
            "current_value": cand.get("current_value"),
            "target_value": _RECOMMENDED_VALUES[canonical],
            "tier": cand.get("tier"),
        })

    return {
        "status": "ready",
        "vendor_key": vendor_key,
        "changes": changes,
        "apply_time": "OnReset",
        "note": "PATCH Bios/Settings stages changes; host reboot required to activate. No auto-reboot.",
    }


def _patch_bios_settings(
    host: str,
    username: str,
    password: str,
    sys_uri: str,
    attributes: Dict[str, Any],
    apply_time: str = "OnReset",
    verify_ssl: bool = False,
    timeout: int = 60,
) -> Dict[str, Any]:
    """PATCH /Systems/{id}/Bios/Settings with Attributes + SettingsApplyTime."""
    settings_uri = f"{sys_uri.rstrip('/')}/Bios/Settings"
    if not settings_uri.startswith("http"):
        # sys_uri may be path-only
        base = host if host.startswith("http") else f"https://{host}"
        url = f"{base.rstrip('/')}{settings_uri}"
    else:
        url = settings_uri

    payload = {
        "Attributes": attributes,
        "@Redfish.SettingsApplyTime": {
            "ApplyTime": apply_time,
        },
    }
    body = json.dumps(payload).encode("utf-8")
    auth = base64.b64encode(f"{username}:{password}".encode()).decode()
    req = urllib.request.Request(url, data=body, method="PATCH")
    req.add_header("Authorization", f"Basic {auth}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    req.add_header("If-Match", "*")

    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            data = {}
            try:
                data = json.loads(raw) if raw.strip() else {}
            except Exception:
                data = {"raw": raw[:500]}
            return {
                "status": "success",
                "http_code": resp.getcode(),
                "settings_uri": url,
                "response": data,
            }
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")[:800]
        return {
            "status": "error",
            "http_code": exc.code,
            "settings_uri": url,
            "error": f"HTTP {exc.code}: {exc.reason}",
            "response_body": err_body,
        }
    except Exception as exc:
        return {
            "status": "error",
            "settings_uri": url,
            "error": str(exc),
        }


def apply_recommended(
    host: str,
    username: str,
    password: str,
    bios_attrs: Optional[Dict[str, Any]] = None,
    vendor: Optional[str] = None,
    model: Optional[str] = None,
    sys_uri: str = "/redfish/v1/Systems/1",
    power_path: str = "either",
    is_esa_candidate: bool = False,
    apply: bool = False,
    confirm: bool = False,
    dry_run: bool = True,
    verify_ssl: bool = False,
    attribute_whitelist: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Build recommend report + apply plan; optionally PATCH Dell/HPE Bios/Settings.

    Safety gates:
      - dry_run defaults True
      - live apply requires apply=True and confirm=True and dry_run=False
    """
    report = build_recommend_report(
        bios_attrs or {},
        vendor=vendor,
        model=model,
        power_path=power_path,
        is_esa_candidate=is_esa_candidate,
    )
    plan = build_apply_plan(report, bios_attrs=bios_attrs)

    if plan.get("status") == "experimental_not_implemented":
        return {
            "status": "experimental_not_implemented",
            "host": host,
            "recommend": report,
            "plan": plan,
            "mutated": False,
        }

    changes = list(plan.get("changes") or [])
    if attribute_whitelist:
        allow = {str(a) for a in attribute_whitelist}
        changes = [c for c in changes if c.get("canonical") in allow or c.get("oem_attribute") in allow]
        plan = dict(plan)
        plan["changes"] = changes

    result: Dict[str, Any] = {
        "status": "dry_run" if dry_run or not (apply and confirm) else "pending",
        "host": host,
        "recommend": report,
        "plan": plan,
        "mutated": False,
        "reboot_required": bool(changes),
        "warning": (
            "MUTATES BMC BIOS pending settings when apply=True, confirm=True, dry_run=False. "
            "Never auto-reboots."
        ),
    }

    live = bool(apply and confirm and not dry_run)
    if not live:
        result["status"] = "dry_run"
        result["note"] = (
            "No changes written. Re-invoke with apply=True, confirm=True, dry_run=False to PATCH."
        )
        return result

    if not changes:
        result["status"] = "noop"
        result["note"] = "No apply candidates to write."
        return result

    attrs_payload = {c["oem_attribute"]: c["target_value"] for c in changes}
    patch_result = _patch_bios_settings(
        host=host,
        username=username,
        password=password,
        sys_uri=sys_uri,
        attributes=attrs_payload,
        apply_time=str(plan.get("apply_time") or "OnReset"),
        verify_ssl=verify_ssl,
    )
    result["patch"] = patch_result
    result["mutated"] = patch_result.get("status") == "success"
    result["status"] = "applied" if result["mutated"] else "error"
    result["pending_attributes"] = attrs_payload
    return result
