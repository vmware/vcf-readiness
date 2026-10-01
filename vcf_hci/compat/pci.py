"""
PCI device compatibility, driver/firmware correlation, and PCIe lane budget evaluation for VCF 9.1.
"""
from typing import Optional

from ..collector.pci_utils import (
    normalize_pci_id,
    normalize_pcie_gen,
    normalize_pcie_width,
)
from .firmware import evaluate_driver_firmware_recommendation

_EVAL_PCI_COMPAT_CACHE = {}
_EVAL_PCI_CACHE_MAX = 2048


def evaluate_pci_compatibility(
    vid: str,
    did: str,
    svid: str = "",
    ssid: str = "",
    model_name: str = "",
    fw_ver: str = "",
    hcl_data: Optional[dict] = None,
) -> dict:
    """Evaluate Broadcom BCG compatibility for a PCI component based on VID:DID:SVID:SSID."""
    cache_key = (
        vid, did, svid, ssid, model_name, fw_ver,
        id(hcl_data) if hcl_data else 0
    )
    if cache_key in _EVAL_PCI_COMPAT_CACHE:
        return _EVAL_PCI_COMPAT_CACHE[cache_key]

    v = normalize_pci_id(vid)
    d = normalize_pci_id(did)
    sv = normalize_pci_id(svid)
    ss = normalize_pci_id(ssid)

    quad = f"{v}:{d}:{sv}:{ss}" if (v and d and sv and ss) else ""
    pair = f"{v}:{d}" if (v and d) else ""

    hcl = hcl_data or {}
    quads = (hcl.get("quads") or hcl.get("_pci_quads", {})) if isinstance(hcl, dict) else {}
    pairs = (hcl.get("pairs") or hcl.get("_pci_pairs", {})) if isinstance(hcl, dict) else {}

    # ── Evaluate Driver & Firmware Recommendations ──────────────────────────────
    driver_fw_eval = evaluate_driver_firmware_recommendation(
        vid=vid, did=did, svid=svid, ssid=ssid, model_name=model_name, fw_ver=fw_ver, hcl_data=hcl_data
    )

    # ── Case 1: Exact Quad Match ──────────────────────────────────────────────
    exact_match = None
    if quad and quad in quads:
        exact_match = quads[quad]
    elif quad and quad in hcl:
        exact_match = hcl[quad]

    if exact_match:
        releases = exact_match.get("releases", []) if isinstance(exact_match, dict) else []
        if not releases and isinstance(exact_match, dict):
            rel_mat = exact_match.get("release_matrix") or exact_match.get("releaseMatrix")
            if isinstance(rel_mat, dict):
                releases = list(rel_mat.keys())
        tier_str = str(exact_match.get("tier", exact_match) if isinstance(exact_match, dict) else exact_match).upper()
        rel_str = " ".join(str(r).upper() for r in releases) + " " + tier_str

        has_91 = "9.1" in rel_str or "ESXI 9.1" in rel_str or "VSAN 9.1" in rel_str
        has_90 = "9.0" in rel_str or "ESXI 9.0" in rel_str or "VSAN 9.0" in rel_str

        if has_91:
            res_dict = {
                "badge": "<span class='badge success'>\U0001f7e2 ESXi 9.1 Certified</span>",
                "verdict_code": "ESXI_91_CERTIFIED",
                "status": "success",
                "supported_releases": releases or ["ESXi 9.1", "ESXi 9.0"],
                "note": f"Exact PCI match ({quad}) confirmed on Broadcom HCL for ESXi 9.1.",
                "action_required": "",
                "pci_quad": quad,
                "pci_pair": pair,
            }
        elif has_90:
            res_dict = {
                "badge": "<span class='badge warning'>\U0001f7e1 ESXi 9.0 Certified Only</span>",
                "verdict_code": "ESXI_90_ONLY",
                "status": "warning",
                "supported_releases": releases or ["ESXi 9.0"],
                "note": f"Exact PCI match ({quad}) certified on ESXi 9.0, pending ESXi 9.1 re-qualification.",
                "action_required": "Verify ESXi 9.1 driver/firmware release schedule with vendor.",
                "pci_quad": quad,
                "pci_pair": pair,
            }
        elif not releases:
            res_dict = {
                "badge": "<span class='badge warning'>\U0001f7e1 Unverified / Pending HCL Certification</span>",
                "verdict_code": "UNVERIFIED_HCL",
                "status": "warning",
                "supported_releases": [],
                "note": f"Exact PCI match ({quad}) found on HCL but contains no certified release details.",
                "action_required": "Verify device certification on Broadcom HCL for ESXi 9.1.",
                "pci_quad": quad,
                "pci_pair": pair,
            }
        else:
            res_dict = {
                "badge": "<span class='badge danger'>\U0001f534 Not Certified for ESXi 9.x</span>",
                "verdict_code": "UNSUPPORTED",
                "status": "danger",
                "supported_releases": releases,
                "note": f"Exact PCI match ({quad}) exists on HCL but is not certified for ESXi 9.x.",
                "action_required": "Hardware upgrade or supported NIC/HBA required for VCF 9.",
                "pci_quad": quad,
                "pci_pair": pair,
            }
        res_dict.update(driver_fw_eval)
        return res_dict

    # ── Case 2: SVID/SSID Mismatch (Same VID:DID chip exists on HCL, but quad differs) ──
    pair_matches = []
    if pair and pair in pairs:
        pair_matches = pairs[pair]
    elif pair and pair in hcl:
        val = hcl[pair]
        pair_matches = val if isinstance(val, list) else [val]

    if pair_matches:
        note = f"OEM SSID mismatch ({quad or pair}). Generic chipset ({pair}) is listed on Broadcom BCG."
        if driver_fw_eval.get("io_product_id"):
            best_mod = (driver_fw_eval.get("matched_entry") or {}).get("model") or "Generic family"
            note = (
                f"OEM SSID mismatch ({quad or pair}). Generic chipset ({pair}) is listed on Broadcom BCG "
                f"({best_mod}, Product ID: {driver_fw_eval['io_product_id']})."
            )
        res_dict = {
            "badge": "<span class='badge warning'>\U0001f7e1 Potential Match (SSID Mismatch)</span>",
            "verdict_code": "POTENTIAL_MATCH_SSID_MISMATCH",
            "status": "warning",
            "supported_releases": [],
            "note": note,
            "action_required": "Work with your account team and vsan-hcl.pdl@broadcom.com to see if there is an equivalency.",
            "pci_quad": quad,
            "pci_pair": pair,
        }
        res_dict.update(driver_fw_eval)
        return res_dict

    # ── Case 3: Missing / Unmatched PCI ID -> Fallback ───────────────────────
    res_dict = {
        "badge": "<span class='badge info'>ℹ️ Model Search Fallback</span>",
        "verdict_code": "MODEL_SEARCH_FALLBACK",
        "status": "info",
        "supported_releases": [],
        "note": f"No exact PCI ID match for {quad or pair or model_name or 'device'}. Verifying via model name search.",
        "action_required": "Confirm exact model string on Broadcom BCG.",
        "pci_quad": quad,
        "pci_pair": pair,
    }
    res_dict.update(driver_fw_eval)
    if len(_EVAL_PCI_COMPAT_CACHE) > _EVAL_PCI_CACHE_MAX:
        _EVAL_PCI_COMPAT_CACHE.clear()
    _EVAL_PCI_COMPAT_CACHE[cache_key] = res_dict
    return res_dict


def evaluate_pcie_lane_budget(pcie_slots: list, cpu_lane_budget_per_socket: int, socket_count: int = 1) -> dict:
    """Compare the sum of populated slot lane widths against the CPU root-complex lane budget.

    This catches CPU-side bifurcation and hidden PCIe switches: if more PCIe lane-width
    is visible in populated slots than the CPU silicon can physically provide, a switch
    or lane-splitter must be in the path even if no switch chip appeared in the PCIe
    device list (e.g. an on-board switch with no Redfish device entry).

    Only populated slots with a known lane width are counted — empty slots consume
    no CPU lanes. M.2 slots are included since they draw from the same CPU root complex.

    Returns:
        cpu_lane_budget       int   — max lanes from CPU silicon across all sockets
        observed_lanes        int   — sum of populated slot physical lane widths
        over_budget           bool  — observed > cpu_lane_budget (switch implied)
        near_budget           bool  — utilization >= 85% but not over budget
        utilization_pct       int   — observed / budget × 100
        populated_slot_count  int   — slots included in the sum
        note                  str   — human-readable finding (empty string when clean)
    """
    if not cpu_lane_budget_per_socket:
        return {
            "cpu_lane_budget": 0, "observed_lanes": 0, "over_budget": False,
            "near_budget": False, "utilization_pct": 0,
            "populated_slot_count": 0, "note": "",
        }
    populated = [s for s in (pcie_slots or []) if s.get("populated") and s.get("lanes")]
    observed  = sum(s["lanes"] for s in populated)
    budget    = cpu_lane_budget_per_socket * max(socket_count or 1, 1)
    over      = observed > budget
    pct       = round((observed / budget) * 100) if budget else 0
    near      = (not over) and pct >= 85

    if over:
        note = (
            f"Observed {observed} PCIe lanes across {len(populated)} populated slot(s), "
            f"exceeding the CPU root-complex budget of {budget} lanes "
            f"({cpu_lane_budget_per_socket}/socket × {max(socket_count or 1, 1)} socket(s)). "
            f"A PCIe switch or lane-splitter is present in the platform even if no switch "
            f"chip was identified in the PCIe device list — verify the Broadcom HCL covers "
            f"all downstream NVMe devices and that per-drive lane width meets vSAN ESA minimums."
        )
    elif near:
        note = (
            f"PCIe lane utilization at {pct}% ({observed}/{budget} lanes). "
            f"Approaching CPU root-complex budget — any additional PCIe devices "
            f"may require a switch or bifurcation."
        )
    else:
        note = ""

    return {
        "cpu_lane_budget":      budget,
        "observed_lanes":       observed,
        "over_budget":          over,
        "near_budget":          near,
        "utilization_pct":      pct,
        "populated_slot_count": len(populated),
        "note":                 note,
    }


def evaluate_pcie_link_health(adapter_info: dict) -> dict:
    """Evaluate negotiated PCIe link width and speed health for an adapter or PCIe device.

    Detects:
      - Width downgrade: current_width < max_width (e.g. operating at x4 when capable of x8).
      - Speed downgrade: current_speed < max_speed (e.g. operating at Gen3 when capable of Gen4).
      - Excludes expected downgrades where card is placed in a lower-capability mechanical slot.

    Args:
        adapter_info: Dictionary describing the network adapter or PCIe device.

    Returns:
        dict with keys:
          degraded (bool): True if link is degraded below expected capability.
          width_degraded (bool): True if lane width is degraded.
          speed_degraded (bool): True if generation speed is degraded.
          current_pcie_type (Optional[str]): e.g. "Gen3"
          max_pcie_type (Optional[str]): e.g. "Gen4"
          current_pcie_width (Optional[int]): e.g. 4
          max_pcie_width (Optional[int]): e.g. 8
          finding (str): Formatted warning finding or empty string.
          remediation (str): Remediation advice or empty string.
          badge (str): HTML badge or empty string.
    """
    if not isinstance(adapter_info, dict):
        return {
            "degraded": False,
            "width_degraded": False,
            "speed_degraded": False,
            "current_pcie_type": None,
            "max_pcie_type": None,
            "current_pcie_width": None,
            "max_pcie_width": None,
            "finding": "",
            "remediation": "",
            "badge": "",
        }

    # Extract current and max width
    cur_w = normalize_pcie_width(
        adapter_info.get("current_pcie_width")
        or adapter_info.get("negotiated_lanes")
        or adapter_info.get("lanes")
    )
    max_w = normalize_pcie_width(
        adapter_info.get("max_pcie_width")
        or adapter_info.get("max_lanes")
    )

    # Extract current and max gen/speed
    cur_g = normalize_pcie_gen(
        adapter_info.get("current_pcie_type")
        or adapter_info.get("negotiated_gen")
        or adapter_info.get("pcie_type")
    )
    max_g = normalize_pcie_gen(
        adapter_info.get("max_pcie_type")
        or adapter_info.get("max_gen")
    )

    # Slot capability ceilings (to exclude intentional down-slotting)
    slot_info = adapter_info.get("slot") if isinstance(adapter_info.get("slot"), dict) else {}
    slot_max_w = normalize_pcie_width(
        adapter_info.get("slot_max_width")
        or adapter_info.get("slot_max_lanes")
        or adapter_info.get("slot_lanes")
        or slot_info.get("lanes")
        or slot_info.get("max_lanes")
    )
    slot_max_g = normalize_pcie_gen(
        adapter_info.get("slot_max_type")
        or adapter_info.get("slot_max_gen")
        or adapter_info.get("slot_pcie_type")
        or slot_info.get("pcie_type")
        or slot_info.get("max_pcie_type")
    )

    effective_max_w = max_w
    if max_w is not None and slot_max_w is not None:
        effective_max_w = min(max_w, slot_max_w)

    effective_max_g = max_g
    if max_g is not None and slot_max_g is not None:
        effective_max_g = min(max_g, slot_max_g)

    width_degraded = bool(
        cur_w is not None
        and effective_max_w is not None
        and cur_w < effective_max_w
    )
    speed_degraded = bool(
        cur_g is not None
        and effective_max_g is not None
        and cur_g < effective_max_g
    )

    degraded = width_degraded or speed_degraded

    card_name = (
        adapter_info.get("name")
        or adapter_info.get("model")
        or adapter_info.get("id")
        or "PCIe Device"
    )

    current_type_str = f"Gen{cur_g}" if cur_g is not None else None
    max_type_str = f"Gen{effective_max_g}" if effective_max_g is not None else None

    finding = ""
    remediation = ""
    badge = ""

    if degraded:
        curr_parts = []
        if cur_g is not None:
            curr_parts.append(f"Gen{cur_g}")
        if cur_w is not None:
            curr_parts.append(f"x{cur_w}")
        curr_desc = " ".join(curr_parts) or "Degraded"

        cap_parts = []
        if effective_max_g is not None:
            cap_parts.append(f"Gen{effective_max_g}")
        if effective_max_w is not None:
            cap_parts.append(f"x{effective_max_w}")
        cap_desc = " ".join(cap_parts) or "Full"

        finding = (
            f"Degraded PCIe Link on {card_name}: Operating at {curr_desc} (Capable: {cap_desc})"
        )
        remediation = (
            "Inspect riser card seating, clean slot contacts, or check BIOS slot bifurcation settings."
        )
        badge = f"<span class='badge warning'>⚠️ PCIe Link Degraded ({curr_desc})</span>"

    return {
        "degraded": degraded,
        "width_degraded": width_degraded,
        "speed_degraded": speed_degraded,
        "current_pcie_type": current_type_str,
        "max_pcie_type": max_type_str,
        "current_pcie_width": cur_w,
        "max_pcie_width": effective_max_w,
        "finding": finding,
        "remediation": remediation,
        "badge": badge,
    }
