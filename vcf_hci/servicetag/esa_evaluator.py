"""
VCF Readiness Tool — vSAN ESA readiness evaluator from Dell TechDirect BOM.

Takes the component list and header dict returned by DellTechDirectClient.get_all()
for a single service tag and produces a readiness assessment compatible with the
shape used by VCF9CompatibilityEngine throughout the rest of the tool.

vSAN ESA requirements evaluated here:
  1. No hardware RAID / PERC controller attached to the storage path
  2. ≥ 2 direct-attached NVMe drives
  3. ≥ 1 NIC ≥ 25 GbE (determines ESA-Ready vs. ESA Storage Met)

Dell component descriptions follow the order-code format:
  "780-BCDI: No RAID"
  "405-AAVW: PERC H750 Adapter, RAID"
  "540-BCOF: Mellanox ConnectX-5 Dual Port 10/25GbE SFP28, OCP NIC 3.0"
  "400-ATJL: 1.92TB SSD NVMe Mixed Use Express Flash, 2.5in Drive"
"""
import logging
import re
from typing import List, Optional

logger = logging.getLogger("vcf_assess")

# ---------------------------------------------------------------------------
# Pattern constants
# ---------------------------------------------------------------------------

# Matches any PERC or hardware-RAID controller description
_PERC_PATTERN = re.compile(
    r"\bPERC\b"
    r"|\bRAID\b(?![\s\w]*No RAID)"   # "RAID" not preceded by "No RAID"
    r"|\bH\d{3}[A-Z]?\b.*(?:adapter|controller|raid)"
    r"|\bHBA\d{3}\b",
    re.IGNORECASE,
)

# Matches NVMe drives (direct-attach)
_NVME_DRIVE_PATTERN = re.compile(
    r"\bNVMe\b"
    r"|\bNVM Express\b"
    r"|\bExpress Flash\b"
    r"|\bPCIe.*SSD\b"
    r"|\bEDSFF\b"
    r"|\bE3\.S\b"
    r"|\bE1\.L\b",
    re.IGNORECASE,
)

# Matches 25 GbE or faster NICs
_NIC_25G_PATTERN = re.compile(
    r"\b25\s*GbE\b"
    r"|\b25\s*Gb\b"
    r"|\b25G\b"
    r"|\b100\s*GbE\b"
    r"|\b100\s*Gb\b"
    r"|\b100G\b"
    r"|\b200\s*GbE\b"
    r"|\b400\s*GbE\b"
    r"|\bInfiniband\b",
    re.IGNORECASE,
)

# "No RAID" — explicit "no hardware RAID" line item
_NO_RAID_PATTERN = re.compile(r"\bNo\s+RAID\b", re.IGNORECASE)

# Storage controller item codes (Dell 3-digit prefix 405-xxxx)
_STORAGE_CTRL_CODE = re.compile(r"^405-", re.IGNORECASE)

# Network adapter item codes (Dell 540-xxxx)
_NIC_CODE = re.compile(r"^540-", re.IGNORECASE)

# Drive item codes (Dell 400-xxxx)
_DRIVE_CODE = re.compile(r"^400-", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Public evaluator
# ---------------------------------------------------------------------------

def evaluate_esa_from_components(
    components: List[dict],
    header: dict,
    model_db: Optional[dict] = None,
) -> dict:
    """
    Evaluate vSAN ESA readiness from a Dell TechDirect component list.

    Args:
        components: list of component dicts from DellTechDirectClient.get_all()
                    Each dict has keys: itemNumber, description, quantity, unitPrice.
        header:     asset-header dict (serviceTag, systemDescription, shipDate …)
        model_db:   optional DELL_MODEL_CHASSIS_DB for model-level fallback

    Returns a dict:
      {
        "verdict":         "ESA Ready" | "ESA Storage Met" | "Not ESA Ready" | "Unknown",
        "badge":           "success" | "warning" | "danger" | "info",
        "has_perc":        bool,
        "nvme_count":      int,
        "has_25g_nic":     bool,
        "no_raid_explicit": bool,
        "perc_items":      [str, ...],    # matching PERC/RAID descriptions
        "nvme_items":      [str, ...],    # matching NVMe drive descriptions
        "nic_items":       [str, ...],    # matching ≥25 GbE NIC descriptions
        "notes":           [str, ...],    # human-readable explanation bullets
        "data_source":     "components" | "model_inference" | "none",
      }
    """
    result = {
        "verdict":          "Unknown",
        "badge":            "info",
        "has_perc":         False,
        "nvme_count":       0,
        "has_25g_nic":      False,
        "no_raid_explicit": False,
        "perc_items":       [],
        "nvme_items":       [],
        "nic_items":        [],
        "notes":            [],
        "data_source":      "none",
    }

    if not components:
        # Fall back to model-name inference if no component data
        return _infer_from_model(header.get("systemDescription", ""), result, model_db)

    result["data_source"] = "components"

    for comp in components:
        item_num = str(comp.get("itemNumber", "")).upper()
        desc     = str(comp.get("description", ""))
        qty      = int(comp.get("quantity", 1) or 1)

        if not desc:
            continue

        # Explicit "No RAID"
        if _NO_RAID_PATTERN.search(desc):
            result["no_raid_explicit"] = True
            continue

        # PERC / HW RAID controller detection
        is_storage_ctrl = bool(_STORAGE_CTRL_CODE.match(item_num))
        if is_storage_ctrl or _PERC_PATTERN.search(desc):
            if _PERC_PATTERN.search(desc):
                result["has_perc"] = True
                result["perc_items"].append(desc.strip())
            continue

        # NVMe drive detection
        is_drive = bool(_DRIVE_CODE.match(item_num))
        if (is_drive or "SSD" in desc.upper() or "HDD" in desc.upper()):
            if _NVME_DRIVE_PATTERN.search(desc):
                result["nvme_count"] += qty
                result["nvme_items"].append(f"{qty}× {desc.strip()}")

        # NIC detection (25 GbE+)
        is_nic = bool(_NIC_CODE.match(item_num))
        if is_nic or "NIC" in desc.upper() or "Ethernet" in desc or "GbE" in desc:
            if _NIC_25G_PATTERN.search(desc):
                result["has_25g_nic"] = True
                result["nic_items"].append(desc.strip())

    return _apply_verdict(result)


def _apply_verdict(result: dict) -> dict:
    """Apply the vSAN ESA verdict logic and populate human-readable notes."""
    notes = result["notes"]

    # PERC / HW RAID
    if result["has_perc"]:
        notes.append(
            "Hardware RAID controller detected — vSAN ESA requires NVMe "
            "drives to be presented directly without a RAID controller."
        )
        for p in result["perc_items"]:
            notes.append(f"  · {p}")
        result["verdict"] = "Not ESA Ready"
        result["badge"]   = "danger"
        return result

    if result["no_raid_explicit"]:
        notes.append("No hardware RAID controller ('No RAID' line item confirmed).")

    # NVMe count
    if result["nvme_count"] >= 2:
        notes.append(
            f"{result['nvme_count']} NVMe drive(s) found — vSAN ESA minimum of 2 met."
        )
    elif result["nvme_count"] == 1:
        notes.append(
            "Only 1 NVMe drive found — vSAN ESA requires at least 2 direct-attached NVMe drives."
        )
        result["verdict"] = "Not ESA Ready"
        result["badge"]   = "danger"
        return result
    else:
        notes.append(
            "No NVMe drives detected in the original configuration — "
            "vSAN ESA requires ≥ 2 direct-attached NVMe drives."
        )
        result["verdict"] = "Not ESA Ready"
        result["badge"]   = "danger"
        return result

    # NIC speed
    if result["has_25g_nic"]:
        notes.append("≥ 25 GbE NIC present — vSAN ESA networking requirement met.")
        result["verdict"] = "ESA Ready"
        result["badge"]   = "success"
    else:
        notes.append(
            "No ≥ 25 GbE NIC detected in original config — "
            "vSAN ESA networking requires at least 1 × 25 GbE adapter. "
            "The server may still qualify as 'ESA Storage Met' pending a NIC upgrade."
        )
        result["verdict"] = "ESA Storage Met"
        result["badge"]   = "warning"

    return result


def _infer_from_model(system_description: str, result: dict, model_db: Optional[dict]) -> dict:
    """
    Fallback: infer ESA suitability from the system model description alone
    when no component data is available.

    This is a best-effort heuristic — actual as-configured PERC state is unknown.
    """
    result["data_source"] = "model_inference"
    desc_upper = system_description.upper()

    if not system_description:
        result["notes"].append(
            "No component data and no system description available. "
            "Cannot determine ESA readiness."
        )
        return result

    result["notes"].append(
        f"Component inventory not available. Assessment is based on model "
        f"description only: '{system_description}'"
    )

    # Models with NVMe-native chassis (16G+ PowerEdge with EDSFF or NVMe suffix)
    nvme_indicators = ["NVME", "EXPRESS FLASH", "EDSFF", "E3.S", "E1.L", "NVE"]
    if any(ind in desc_upper for ind in nvme_indicators):
        result["nvme_count"] = 2   # assume minimum met if NVMe chassis variant
        result["notes"].append(
            "Model description suggests NVMe-capable chassis variant. "
            "Verify actual drive configuration before deployment."
        )

    # 25G NIC indicators in system description
    if _NIC_25G_PATTERN.search(system_description):
        result["has_25g_nic"] = True

    result["notes"].append(
        "PERC/RAID controller presence cannot be determined from model name alone. "
        "Run a Redfish scan or check the original Dell order BOM to confirm."
    )
    result["verdict"] = "Unknown — Verify BOM"
    result["badge"]   = "info"
    return result


# ---------------------------------------------------------------------------
# Warranty summary helper (used by host_report.py)
# ---------------------------------------------------------------------------

def summarise_warranty(warranty_rec: dict) -> dict:
    """
    Distil a Dell TechDirect asset-entitlements record into a compact dict
    suitable for rendering in a host report warranty card.

    Returns:
      {
        "service_tag":       str,
        "model":             str,
        "ship_date":         str,
        "status":            "Active" | "Expired" | "Unknown",
        "badge":             "success" | "danger" | "info",
        "expiry_date":       str,   # latest entitlement end date
        "service_level":     str,   # most senior service level description
        "entitlements":      [...], # list of {service_level, start, end}
      }
    """
    out = {
        "service_tag":  str(warranty_rec.get("serviceTag", "")).upper(),
        "model":        str(warranty_rec.get("systemDescription", "")
                            or warranty_rec.get("brandName", "")),
        "ship_date":    _fmt_date(warranty_rec.get("shipDate", "")),
        "status":       "Unknown",
        "badge":        "info",
        "expiry_date":  "",
        "service_level": "",
        "entitlements": [],
    }

    entitlements = warranty_rec.get("entitlements", []) or []
    parsed = []
    for e in entitlements:
        end_raw   = str(e.get("endDate",   "") or "")
        start_raw = str(e.get("startDate", "") or "")
        level     = str(e.get("serviceLevelDescription", "") or
                        e.get("serviceLevelCode", ""))
        parsed.append({
            "service_level": level,
            "start":         _fmt_date(start_raw),
            "end":           _fmt_date(end_raw),
            "_end_raw":      end_raw,
        })

    if parsed:
        # Sort by end date descending to surface the longest-running entitlement
        parsed.sort(key=lambda x: x["_end_raw"], reverse=True)
        out["entitlements"]  = parsed
        latest = parsed[0]
        out["expiry_date"]   = latest["end"]
        out["service_level"] = latest["service_level"]

        from datetime import datetime, timezone
        try:
            expiry_dt = datetime.strptime(latest["_end_raw"][:10], "%Y-%m-%d")
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if expiry_dt >= now:
                out["status"] = "Active"
                out["badge"]  = "success"
            else:
                out["status"] = "Expired"
                out["badge"]  = "danger"
        except ValueError:
            out["status"] = "Unknown"

    return out


def _fmt_date(raw: str) -> str:
    """Normalise ISO date strings to 'YYYY-MM-DD'; return raw on failure."""
    if not raw:
        return ""
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(raw[:10])
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        return raw[:10] if len(raw) >= 10 else raw
