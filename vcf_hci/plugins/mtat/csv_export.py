"""Exact MTAT 3.2 CSV rendering."""

from __future__ import annotations

from vcf_hci.plugins.mtat.constants import (
    COLLECTION_FAILED,
    HOST_CSV_HEADER,
    HOST_HISTORY_HEADER,
    MEMORY_UNIT,
    VM_CSV_HEADER,
    VM_HISTORY_HEADER,
)
from vcf_hci.plugins.mtat.models import Assessment, HostRow, VmRow
from vcf_hci.plugins.mtat.numbers import format_number


def csv_field(value: object) -> str:
    text = "" if value is None else str(value)
    if any(character in text for character in '",\r\n'):
        return '"%s"' % text.replace('"', '""')
    return text


def _host_cells(row: HostRow) -> list[str]:
    return [
        csv_field(row.tiering),
        format_number(row.cpu_pct, 2),
        format_number(row.physical_ram_gb, 3),
        format_number(row.consumed_gb, 3),
        format_number(row.active_gb, 3),
        format_number(row.active_pct, 1),
        format_number(row.tier_ratio_pct, 3),
        format_number(row.active_avg_gb, 3),
        format_number(row.nvme_gb, 3),
        csv_field(row.missing_metrics),
        format_number(row.cpu_mhz, 0),
        MEMORY_UNIT,
    ]


def _vm_cells(row: VmRow) -> list[str]:
    return [
        csv_field(row.host_name),
        csv_field(row.vm_name),
        format_number(row.provisioned_gb, 3),
        format_number(row.active_gb, 3),
        format_number(row.active_pct, 1),
        csv_field(row.dram_only),
        csv_field(row.pages_1gb),
        csv_field(row.pages_2mb),
        csv_field(row.missing_metrics),
        MEMORY_UNIT,
    ]


def _failed_vm_cells(name: str) -> list[str]:
    index = name.find("/")
    if index > 0:
        host, vm = name[:index], name[index + 1 :]
    else:
        host, vm = "", name
    return [csv_field(host), csv_field(vm), "", "", "", "Unknown", "", "", COLLECTION_FAILED, MEMORY_UNIT]


def _finish(header: str, lines: list[str]) -> str:
    return header + "\r\n" + "".join(line + "\r\n" for line in lines)


def render_hosts(assessment: Assessment) -> str:
    lines = []
    for row in assessment.hosts:
        lines.append(",".join([csv_field(row.cluster), csv_field(row.host_name), *_host_cells(row)]))
    return _finish(HOST_CSV_HEADER, lines)


def render_vms(assessment: Assessment) -> str:
    lines = [",".join(_vm_cells(row)) for row in assessment.vms]
    lines.extend(",".join(_failed_vm_cells(name)) for name in assessment.failed_vms)
    return _finish(VM_CSV_HEADER, lines)


def _context(cluster: str, range_name: str) -> str:
    return "%s (%s)" % (cluster, range_name)


def render_hosts_history(assessment: Assessment) -> str:
    lines = []
    for row in assessment.hosts:
        prefix = [csv_field(row.cluster), csv_field(assessment.range_name), csv_field(_context(row.cluster, assessment.range_name)), csv_field(row.host_name)]
        lines.append(",".join([*prefix, *_host_cells(row), csv_field(assessment.source_label)]))
    return _finish(HOST_HISTORY_HEADER, lines)


def render_vms_history(assessment: Assessment) -> str:
    lines = []
    for row in assessment.vms:
        cluster = _cluster_for(assessment, row.host_name)
        prefix = [csv_field(cluster), csv_field(assessment.range_name), csv_field(_context(cluster, assessment.range_name))]
        lines.append(",".join([*prefix, *_vm_cells(row), csv_field(assessment.source_label)]))
    for name in assessment.failed_vms:
        host = name[:name.find("/")] if name.find("/") > 0 else ""
        cluster = _cluster_for(assessment, host)
        prefix = [csv_field(cluster), csv_field(assessment.range_name), csv_field(_context(cluster, assessment.range_name))]
        lines.append(",".join([*prefix, *_failed_vm_cells(name), csv_field(assessment.source_label)]))
    return _finish(VM_HISTORY_HEADER, lines)


def _cluster_for(assessment: Assessment, host_name: str) -> str:
    for row in assessment.hosts:
        if row.host_name == host_name:
            return row.cluster
    return ""
