"""
VCF Readiness Tool — OS information evaluation module.
"""
import re
from typing import Any, Dict

from vcf_hci.collector.async_helpers import _h
from vcf_hci.constants import ESXI_BUILD_TABLE, ESXI_KB_URL, OS_EOL_TABLE


def _evaluate_os_info(os_raw: Dict[str, Any], sw_inv: Dict[str, Any]) -> Dict[str, Any]:
    """Combine OEM-sourced OS data with SoftwareInventory enrichment.

    os_raw  — dict from system["os_raw"]: {name, version, description, source}
    sw_inv  — dict from collect_software_inventory_os(): {os_name, os_version, os_build, source}

    Returns a fully-populated host_os dict ready for use in HTML reports.
    Keys:
      os_name, os_version, os_build, os_description,
      esxi_update_label, eol_label, eol_badge, source,
      kb_url, badge, agent_note, vcf_upgrade_note
    """
    # Prefer OEM agent data (richer OS name) when available; fall back to
    # SoftwareInventory which is more widely available but may give terse names.
    oem_name  = (os_raw.get("name")    or "").strip()
    oem_ver   = (os_raw.get("version") or "").strip()
    oem_desc  = (os_raw.get("description") or "").strip()
    oem_src   = (os_raw.get("source")  or "").strip()

    sw_name   = (sw_inv.get("os_name")    or "").strip()
    sw_ver    = (sw_inv.get("os_version") or "").strip()
    sw_build  = (sw_inv.get("os_build")   or "").strip()
    sw_src    = (sw_inv.get("source")     or "").strip()

    # Resolved values: OEM fields take priority for name/version
    os_name    = oem_name  or sw_name  or ""
    os_version = oem_ver   or sw_ver   or ""
    os_build   = sw_build  or ""       # SoftwareInventory is primary build source
    os_desc    = oem_desc  or ""
    source     = oem_src   or sw_src   or ""

    # Attempt to extract a build number from the version string if not yet found
    if not os_build and os_version:
        _bm = re.search(r'\b(\d{7,9})\b', os_version)
        if _bm:
            os_build = _bm.group(1)

    # ── ESXi build-number → update label resolution ──────────────────────────
    esxi_update_label = ""
    kb_url            = ""
    is_esxi = bool(re.search(r'esxi|vmware|vsphere', os_name, re.I)
                   or re.search(r'esxi|vmware|vsphere', os_version, re.I))

    if is_esxi:
        kb_url = ESXI_KB_URL
        # 1. Direct lookup by numeric build
        if os_build and os_build in ESXI_BUILD_TABLE:
            esxi_update_label = ESXI_BUILD_TABLE[os_build][0]
        else:
            # 2. Try to derive label from version string (e.g. "8.0.3" → "ESXi 8.0 U3")
            _vm = re.match(r'(\d+\.\d+)(?:\.\d+)?', os_version)
            if _vm:
                esxi_update_label = f"ESXi {_vm.group(1)}"
        # Normalise display name for terse BMC strings like "VMW_ESXI" or "ESX"
        if not oem_name and sw_name:
            _clean = re.sub(r'(?i)^VMW[_\-]?', '', sw_name).strip()
            os_name = f"VMware {_clean}" if _clean.upper().startswith("ESXI") else sw_name

    # ── EOL / lifecycle classification ───────────────────────────────────────
    # Match against the combined "name version" string for breadth
    _os_lookup_str = f"{os_name} {os_version} {esxi_update_label}"
    eol_label = ""
    eol_class = "info"
    for _pat, _label, _cls in OS_EOL_TABLE:
        if re.search(_pat, _os_lookup_str, re.I):
            eol_label = _label
            eol_class = _cls
            break

    if not eol_label:
        if os_name:
            eol_label = "Lifecycle Unknown"
            eol_class = "info"
        else:
            eol_label = "Not Reported"
            eol_class = "info"

    eol_badge = f"<span class='badge {eol_class}'>{_h(eol_label)}</span>"

    # ── VCF 9.1 upgrade path note ────────────────────────────────────────────
    vcf_upgrade_note = ""
    if is_esxi:
        _vm_ver = re.match(r'(\d+)', os_version)
        _esxi_major = int(_vm_ver.group(1)) if _vm_ver else 0
        if _esxi_major and _esxi_major < 9:
            vcf_upgrade_note = (
                f"Upgrade to ESXi 9.1 required for VCF 9.1 — "
                f"currently running ESXi {_esxi_major}.x"
            )

    # ── Agent requirement note ────────────────────────────────────────────────
    if source in ("Dell iSM", "HPE AMS", "Cisco OEM", "Redfish"):
        agent_note = f"Reported via {source}"
    elif source == "SoftwareInventory":
        agent_note = "Detected via Redfish SoftwareInventory (no host agent required)"
    else:
        agent_note = "Host agent not detected — install iSM (Dell) or AMS (HPE) for full OS details"

    # ── Main summary badge ────────────────────────────────────────────────────
    if not os_name:
        badge = "<span class='badge info'>ℹ️ OS: Not Reported (no host agent)</span>"
    elif eol_class == "danger":
        _label = esxi_update_label or os_name
        badge = f"<span class='badge danger'>🔴 {_h(_label)} — {_h(eol_label)}</span>"
    elif eol_class == "warning":
        _label = esxi_update_label or os_name
        badge = f"<span class='badge warning'>🟡 {_h(_label)} — {_h(eol_label)}</span>"
    else:
        _label = esxi_update_label or os_name
        badge = f"<span class='badge success'>🟢 {_h(_label)}</span>"

    powered_on_sec = os_raw.get("powered_on_seconds")
    uptime_days    = os_raw.get("uptime_days")
    uptime_human   = os_raw.get("uptime_human")

    uptime_badge = ""
    if uptime_human:
        uptime_badge = f"<span class='badge info'>⏱️ Uptime: {_h(uptime_human)}</span>"

    return {
        "os_name":            os_name,
        "os_version":         os_version,
        "os_build":           os_build,
        "os_description":     os_desc,
        "esxi_update_label":  esxi_update_label,
        "eol_label":          eol_label,
        "eol_badge":          eol_badge,
        "source":             source,
        "kb_url":             kb_url,
        "badge":              badge,
        "agent_note":         agent_note,
        "vcf_upgrade_note":   vcf_upgrade_note,
        "powered_on_seconds": powered_on_sec,
        "uptime_days":        uptime_days,
        "uptime_human":       uptime_human,
        "uptime_badge":       uptime_badge,
    }
