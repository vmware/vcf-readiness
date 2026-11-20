"""Pure cluster aggregation, qualification checklist, matrix export, and sizing projections."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Optional, Sequence, Union
from urllib.parse import urlsplit

from vcf_hci.plugins.mtat.constants import (
    HOST_HISTORY_HEADER,
    POLICY_MTAT_32,
    VM_HISTORY_HEADER,
)
from vcf_hci.plugins.mtat.csv_export import (
    csv_field,
    render_hosts_history,
    render_vms_history,
)
from vcf_hci.plugins.mtat.eligibility import MTAT_32_REASONS
from vcf_hci.plugins.mtat.models import Assessment, HostRow, VmRow
from vcf_hci.plugins.mtat.numbers import format_number, percent, quantize

MATRIX_CSV_HEADER = (
    "Target Cluster Scope,Analyzed Range Profile,CPU Avg/Peak,Active Memory %,Consumed Memory %"
)

_MTAT_32_REASON_LABELS = frozenset(label for _key, label in MTAT_32_REASONS)

_RATIO_SPECS: tuple[tuple[str, int, str], ...] = (
    ("25", 25, "25% (4:1 DRAM:NVMe)"),
    ("50", 50, "50% (2:1 DRAM:NVMe)"),
    ("100", 100, "100% (1:1 DRAM:NVMe)"),
)


def _to_decimal(value: object) -> Decimal:
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, str) and value.strip():
        try:
            return Decimal(value.strip())
        except InvalidOperation:
            return Decimal(0)
    return Decimal(0)


def _to_optional_decimal(value: object) -> Optional[Decimal]:
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    return _to_decimal(value)


def sanitize_endpoint_label(endpoint: str, source_kind: str = "") -> str:
    """Return a credential-free authority label for display in cluster_scope."""
    if source_kind == "operations-xlsx":
        return "workbook"
    raw = (endpoint or "").strip()
    if not raw or raw.startswith(("//", "\\\\")):
        return ""
    try:
        parsed = urlsplit(raw if "://" in raw else "https://" + raw)
        host = parsed.hostname or ""
        if not host or any(c.isspace() or c == "\\" for c in host):
            return ""
        port = parsed.port
        if port is not None and port not in (443, 80):
            return "%s:%d" % (host, port)
        return host
    except ValueError:
        return ""


def format_cluster_scope(cluster_name: str, endpoint_label: str = "") -> str:
    """Format '<cluster_name> (<endpoint_label>)' when an endpoint label is available."""
    base = (cluster_name or "").strip() or "Cluster"
    label = (endpoint_label or "").strip()
    if label and ("(%s)" % label) not in base:
        return "%s (%s)" % (base, label)
    return base


def _range_priority(range_name: str) -> int:
    lower = (range_name or "").strip().lower()
    if "30 day" in lower or "month" in lower or "30d" in lower:
        return 40
    if "7 day" in lower or "week" in lower or "7d" in lower:
        return 30
    if "24 hour" in lower or "1 day" in lower or "past day" in lower or lower == "day" or "24h" in lower:
        return 20
    if "real-time" in lower or "realtime" in lower or "snapshot" in lower:
        return 5
    return 25


def select_primary_assessment(assessments: Sequence[Assessment]) -> Assessment:
    """Select the longest historical rollup range or the last collected assessment."""
    if not assessments:
        raise ValueError("at least one assessment is required")
    best_index = 0
    best_key = (_range_priority(assessments[0].range_name), 0)
    for idx, item in enumerate(assessments):
        candidate_key = (_range_priority(item.range_name), idx)
        if candidate_key >= best_key:
            best_key = candidate_key
            best_index = idx
    return assessments[best_index]


def _is_connected_host(row: HostRow) -> bool:
    if row.tiering == "ERROR":
        return False
    return not (
        _to_decimal(row.physical_ram_gb) == 0
        and row.missing_metrics == "CPU, Active, Consumed"
    )


def _is_mtat_32_dram_only(row: VmRow) -> bool:
    if row.dram_only == "Unknown":
        return False
    if row.eligibility_policy == POLICY_MTAT_32:
        return bool(row.eligibility_reasons) or row.dram_only.startswith("Yes")
    if row.current_policy_reasons:
        return any(reason in _MTAT_32_REASON_LABELS for reason in row.current_policy_reasons)
    return any(reason in _MTAT_32_REASON_LABELS for reason in row.eligibility_reasons)


def _is_current_policy_dram_only(row: VmRow) -> bool:
    if row.dram_only == "Unknown":
        return False
    if row.current_policy_reasons:
        return True
    return _is_mtat_32_dram_only(row)


def _format_current_policy_cell(row: VmRow) -> str:
    if row.dram_only == "Unknown":
        return "Unknown"
    if row.current_policy_reasons:
        return "Yes (%s)" % ", ".join(row.current_policy_reasons)
    if _is_mtat_32_dram_only(row) and row.eligibility_reasons:
        return "Yes (%s)" % ", ".join(row.eligibility_reasons)
    return "No"


def summarize_vm_eligibility(vms: Sequence[VmRow]) -> dict[str, Union[int, float]]:
    total_vms = len(vms)
    mtat_count = 0
    mtat_prov = Decimal(0)
    mtat_active = Decimal(0)
    curr_count = 0
    curr_prov = Decimal(0)
    curr_active = Decimal(0)
    elig_count = 0
    elig_prov = Decimal(0)
    elig_active = Decimal(0)

    for row in vms:
        prov = _to_decimal(row.provisioned_gb)
        act = _to_decimal(row.active_gb)
        mtat_pinned = _is_mtat_32_dram_only(row)
        curr_pinned = _is_current_policy_dram_only(row)
        selected_pinned = row.dram_only.startswith("Yes") or bool(row.eligibility_reasons)
        if mtat_pinned:
            mtat_count += 1
            mtat_prov += prov
            mtat_active += act
        if curr_pinned:
            curr_count += 1
            curr_prov += prov
            curr_active += act
        if not selected_pinned:
            elig_count += 1
            elig_prov += prov
            elig_active += act

    return {
        "total_vms": total_vms,
        "mtat_32_dram_only_count": mtat_count,
        "mtat_32_dram_only_provisioned_gb": float(quantize(mtat_prov, 3)),
        "mtat_32_dram_only_active_gb": float(quantize(mtat_active, 3)),
        "current_policy_dram_only_count": curr_count,
        "current_policy_dram_only_provisioned_gb": float(quantize(curr_prov, 3)),
        "current_policy_dram_only_active_gb": float(quantize(curr_active, 3)),
        "eligible_vms_count": elig_count,
        "eligible_provisioned_gb": float(quantize(elig_prov, 3)),
        "eligible_active_gb": float(quantize(elig_active, 3)),
    }


def build_qualification_checklist(summary: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Evaluate the three MTAT hardware qualification rules for a summarized range."""
    cpu_pct = float(summary.get("cpu_pct", 0.0))
    active_pct = float(summary.get("active_pct", 0.0))
    consumed_pct = float(summary.get("consumed_pct", 0.0))

    cpu_pass = cpu_pct <= 50.0
    active_pass = active_pct <= 50.0
    consumed_pass = consumed_pct >= 80.0

    return [
        {
            "metric": "CPU Usage",
            "target": "<= 50%",
            "value_pct": cpu_pct,
            "value_label": "%.1f%%" % cpu_pct,
            "status": "PASS" if cpu_pass else "REVIEW",
            "badge_class": "badge-success" if cpu_pass else "badge-warning",
            "note": "" if cpu_pass else "(Host CPU utilization exceeds 50%; verify CPU headroom for NVMe tiering page management)",
        },
        {
            "metric": "Active Memory",
            "target": "<= 50%",
            "value_pct": active_pct,
            "value_label": "%.1f%%" % active_pct,
            "status": "PASS" if active_pass else "REVIEW",
            "badge_class": "badge-success" if active_pass else "badge-warning",
            "note": "" if active_pass else "(Active working set exceeds 50% of physical DRAM; reduces safe NVMe tiering headroom)",
        },
        {
            "metric": "Consumed Memory",
            "target": ">= 80%",
            "value_pct": consumed_pct,
            "value_label": "%.1f%%" % consumed_pct,
            "status": "PASS" if consumed_pass else "NOTE",
            "badge_class": "badge-success" if consumed_pass else "badge-info",
            "note": "" if consumed_pass else "(Memory Tiering will not trigger until there is memory pressure (80%))",
        },
    ]


def compute_sizing_projections(summary: Mapping[str, Any]) -> dict[str, Any]:
    """Compute NVMe tier sizing and DRAM reclamation across 25%, 50%, and 100% ratios."""
    physical_ram_gb = Decimal(str(summary.get("total_physical_ram_gb", 0.0)))
    active_gb = Decimal(str(summary.get("total_active_gb", 0.0)))
    cpu_pct = float(summary.get("cpu_pct", 0.0))
    active_pct = float(summary.get("active_pct", 0.0))

    vm_elig = summary.get("vm_eligibility") or {}
    pinned_gb = Decimal(str(vm_elig.get("mtat_32_dram_only_provisioned_gb", 0.0)))
    eligible_active_gb = Decimal(str(vm_elig.get("eligible_active_gb", 0.0)))

    min_dram_dec = quantize(max(active_gb * Decimal(2), pinned_gb + eligible_active_gb), 3)
    tierable_dram_dec = max(Decimal(0), physical_ram_gb - pinned_gb)
    headroom_dram_dec = max(Decimal(0), physical_ram_gb - min_dram_dec)

    ratios: dict[str, dict[str, Any]] = {}
    for key, ratio_pct, ratio_label in _RATIO_SPECS:
        ratio_dec = Decimal(ratio_pct) / Decimal(100)
        rec_nvme_dec = quantize(physical_ram_gb * ratio_dec, 3)
        effective_cap_dec = quantize(physical_ram_gb + rec_nvme_dec, 3)
        raw_reclaim_dec = tierable_dram_dec * (ratio_dec / (Decimal(1) + ratio_dec))
        reclaim_dec = quantize(min(raw_reclaim_dec, headroom_dram_dec), 3)
        savings_pct_dec = percent(reclaim_dec, physical_ram_gb, 1)

        if physical_ram_gb <= 0:
            viable = False
            guidance = "No connected host physical DRAM detected."
        elif cpu_pct > 50.0 or active_pct > 50.0:
            viable = False
            guidance = "Review baseline qualification: CPU usage or active memory exceeds the 50% threshold."
        elif ratio_pct == 100 and active_pct > 40.0:
            viable = False
            guidance = "100% (1:1) ratio requires active memory <= 40% to avoid NVMe tier contention; prefer 25% or 50%."
        else:
            viable = True
            if ratio_pct == 25:
                guidance = "Conservative 4:1 DRAM:NVMe tiering profile suitable for general production workloads."
            elif ratio_pct == 50:
                guidance = "Balanced 2:1 DRAM:NVMe default tiering profile recommended for qualified VCF clusters."
            else:
                guidance = "Aggressive 1:1 DRAM:NVMe tiering profile for low-activity workloads with ample headroom."

        ratios[key] = {
            "ratio_pct": ratio_pct,
            "ratio_label": ratio_label,
            "recommended_nvme_gb": float(rec_nvme_dec),
            "effective_tiered_capacity_gb": float(effective_cap_dec),
            "reclaimable_dram_gb": float(reclaim_dec),
            "dram_savings_pct": float(savings_pct_dec),
            "min_dram_required_gb": float(min_dram_dec),
            "viable": viable,
            "guidance": guidance,
        }

    return {"ratios": ratios}


def _serialize_host_row(row: HostRow) -> dict[str, str]:
    return {
        "cluster": str(row.cluster),
        "host_name": str(row.host_name),
        "tiering": str(row.tiering),
        "cpu_pct": format_number(_to_optional_decimal(row.cpu_pct), 2),
        "physical_ram_gb": format_number(_to_optional_decimal(row.physical_ram_gb), 3),
        "consumed_gb": format_number(_to_optional_decimal(row.consumed_gb), 3),
        "active_gb": format_number(_to_optional_decimal(row.active_gb), 3),
        "active_pct": format_number(_to_optional_decimal(row.active_pct), 1),
        "tier_ratio_pct": format_number(_to_optional_decimal(row.tier_ratio_pct), 3),
        "active_avg_gb": format_number(_to_optional_decimal(row.active_avg_gb), 3),
        "nvme_gb": format_number(_to_optional_decimal(row.nvme_gb), 3),
        "missing_metrics": str(row.missing_metrics),
    }


def _serialize_vm_row(row: VmRow) -> dict[str, str]:
    return {
        "host_name": str(row.host_name),
        "vm_name": str(row.vm_name),
        "provisioned_gb": format_number(_to_optional_decimal(row.provisioned_gb), 3),
        "active_gb": format_number(_to_optional_decimal(row.active_gb), 3),
        "active_pct": format_number(_to_optional_decimal(row.active_pct), 1),
        "dram_only": str(row.dram_only),
        "current_policy_dram_only": _format_current_policy_cell(row),
        "pages_1gb": str(row.pages_1gb),
        "pages_2mb": str(row.pages_2mb),
        "missing_metrics": str(row.missing_metrics),
    }


def summarize_assessment(assessment: Assessment, endpoint_label: str = "") -> dict[str, Any]:
    """Compute cluster range summary, qualification checklist, VM eligibility, and sizing."""
    connected_hosts = [row for row in assessment.hosts if _is_connected_host(row)]
    cpu_hosts = [row for row in connected_hosts if "CPU" not in row.missing_metrics] or connected_hosts

    if cpu_hosts:
        cpu_values = [_to_decimal(row.cpu_pct) for row in cpu_hosts]
        cpu_avg_dec = quantize(sum(cpu_values, Decimal(0)) / Decimal(len(cpu_values)), 1)
        cpu_peak_dec = quantize(max(cpu_values), 1)
    else:
        cpu_avg_dec = Decimal(0)
        cpu_peak_dec = Decimal(0)

    total_phys_dec = quantize(sum((_to_decimal(row.physical_ram_gb) for row in connected_hosts), Decimal(0)), 3)
    total_consumed_dec = quantize(sum((_to_decimal(row.consumed_gb) for row in connected_hosts), Decimal(0)), 3)
    total_active_dec = quantize(sum((_to_decimal(row.active_gb) for row in connected_hosts), Decimal(0)), 3)
    total_active_avg_dec = quantize(
        sum(
            (
                _to_decimal(row.active_avg_gb if row.active_avg_gb is not None else row.active_gb)
                for row in connected_hosts
            ),
            Decimal(0),
        ),
        3,
    )
    total_nvme_dec = quantize(
        sum((_to_decimal(row.nvme_gb) for row in connected_hosts if row.nvme_gb is not None), Decimal(0)),
        3,
    )

    active_pct_dec = percent(total_active_dec, total_phys_dec, 1)
    consumed_pct_dec = percent(total_consumed_dec, total_phys_dec, 1)

    cluster_name = next(
        (row.cluster for row in connected_hosts if row.cluster),
        next((row.cluster for row in assessment.hosts if row.cluster), "Cluster"),
    )
    cluster_scope = format_cluster_scope(cluster_name, endpoint_label)
    vm_eligibility = summarize_vm_eligibility(assessment.vms)

    summary: dict[str, Any] = {
        "range_name": assessment.range_name,
        "source_kind": assessment.source_kind,
        "source_label": assessment.source_label,
        "source_version": assessment.source_version,
        "cluster_name": cluster_name,
        "cluster_scope": cluster_scope,
        "host_count": len(assessment.hosts),
        "connected_host_count": len(connected_hosts),
        "vm_count": len(assessment.vms),
        "failed_vm_count": len(assessment.failed_vms),
        "cpu_pct": float(cpu_avg_dec),
        "cpu_peak_pct": float(cpu_peak_dec),
        "active_pct": float(active_pct_dec),
        "consumed_pct": float(consumed_pct_dec),
        "total_physical_ram_gb": float(total_phys_dec),
        "total_consumed_gb": float(total_consumed_dec),
        "total_active_gb": float(total_active_dec),
        "total_active_avg_gb": float(total_active_avg_dec),
        "total_nvme_gb": float(total_nvme_dec),
        "checklist": [],
        "vm_eligibility": vm_eligibility,
        "sizing": {},
        "hosts": [_serialize_host_row(row) for row in assessment.hosts],
        "vms": [_serialize_vm_row(row) for row in assessment.vms],
    }
    summary["checklist"] = build_qualification_checklist(summary)
    summary["sizing"] = compute_sizing_projections(summary)
    return summary


def build_matrix_rows(range_summaries: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    """Build Range Comparison Matrix rows from range summary dicts."""
    rows: list[dict[str, str]] = []
    for item in range_summaries:
        cpu_val = item.get("cpu_pct", 0.0)
        cpu_peak_val = item.get("cpu_peak_pct", cpu_val)
        active_val = item.get("active_pct", 0.0)
        consumed_val = item.get("consumed_pct", 0.0)
        rows.append(
            {
                "cluster_scope": str(item.get("cluster_scope") or ""),
                "range_name": str(item.get("range_name") or ""),
                "cpu_pct": cpu_val if isinstance(cpu_val, str) else ("%.1f%%" % float(cpu_val)),
                "cpu_peak_pct": cpu_peak_val if isinstance(cpu_peak_val, str) else ("%.1f%%" % float(cpu_peak_val)),
                "active_pct": active_val if isinstance(active_val, str) else ("%.1f%%" % float(active_val)),
                "consumed_pct": consumed_val if isinstance(consumed_val, str) else ("%.1f%%" % float(consumed_val)),
            }
        )
    return rows


def render_matrix_csv(
    items: Sequence[Union[Assessment, Mapping[str, Any]]],
    endpoint_label: str = "",
) -> str:
    """Render RFC 4180 CSV for the Range Comparison Matrix."""
    summaries: list[Mapping[str, Any]] = []
    for item in items:
        if isinstance(item, Assessment):
            summaries.append(summarize_assessment(item, endpoint_label=endpoint_label))
        else:
            summaries.append(item)
    matrix_rows = build_matrix_rows(summaries)
    lines: list[str] = []
    for row in matrix_rows:
        cpu_cell = row["cpu_pct"]
        if row.get("cpu_peak_pct") and row["cpu_peak_pct"] != row["cpu_pct"]:
            cpu_cell = "%s / %s" % (row["cpu_pct"], row["cpu_peak_pct"])
        lines.append(
            ",".join(
                [
                    csv_field(row["cluster_scope"]),
                    csv_field(row["range_name"]),
                    csv_field(cpu_cell),
                    csv_field(row["active_pct"]),
                    csv_field(row["consumed_pct"]),
                ]
            )
        )
    return MATRIX_CSV_HEADER + "\r\n" + "".join(line + "\r\n" for line in lines)


def render_multi_hosts_history(assessments: Sequence[Assessment]) -> str:
    """Render hosts_history.csv across one or more assessments under a single header."""
    if not assessments:
        return HOST_HISTORY_HEADER + "\r\n"
    if len(assessments) == 1:
        return render_hosts_history(assessments[0])
    chunks = [HOST_HISTORY_HEADER + "\r\n"]
    for assessment in assessments:
        rendered = render_hosts_history(assessment)
        parts = rendered.split("\r\n", 1)
        if len(parts) == 2 and parts[1]:
            chunks.append(parts[1])
    return "".join(chunks)


def render_multi_vms_history(assessments: Sequence[Assessment]) -> str:
    """Render vms_history.csv across one or more assessments under a single header."""
    if not assessments:
        return VM_HISTORY_HEADER + "\r\n"
    if len(assessments) == 1:
        return render_vms_history(assessments[0])
    chunks = [VM_HISTORY_HEADER + "\r\n"]
    for assessment in assessments:
        rendered = render_vms_history(assessment)
        parts = rendered.split("\r\n", 1)
        if len(parts) == 2 and parts[1]:
            chunks.append(parts[1])
    return "".join(chunks)


def build_report_payload(
    assessments: Sequence[Assessment],
    endpoint_label: str = "",
) -> dict[str, Any]:
    """Build the structured payload['report'] object for status_payload(job)."""
    if not assessments:
        return {
            "cluster_scope": format_cluster_scope("Cluster", endpoint_label),
            "primary_range": "",
            "matrix": [],
            "ranges": [],
        }
    primary = select_primary_assessment(assessments)
    range_summaries = [summarize_assessment(item, endpoint_label=endpoint_label) for item in assessments]
    primary_summary = next(
        (item for item in range_summaries if item["range_name"] == primary.range_name),
        range_summaries[-1],
    )
    return {
        "cluster_scope": str(primary_summary["cluster_scope"]),
        "primary_range": str(primary.range_name),
        "matrix": build_matrix_rows(range_summaries),
        "ranges": range_summaries,
    }
