"""
VCF Readiness Tool — Post-collection hardware enrichment pipeline.

Applies VCF 9.1 compatibility rules (Layer B) and BCG deep-links (Layer C)
to a normalized hardware payload (Layer A) in a single post-collection pass.
"""
import logging
from typing import Any, Dict, List, Optional, Union

from vcf_hci.bios.advisories import evaluate_bios_advisories
from vcf_hci.bios.x2apic import refresh_x2apic_guidance
from vcf_hci.collector.collect_gpu import retain_collected_pcie
from vcf_hci.collector.oem.dell_storage import normalize_dell_backplanes
from vcf_hci.enrichment_steps.bios import enrich_bios_settings, enrich_oem_baseline
from vcf_hci.enrichment_steps.findings import enrich_event_blockers, enrich_job_queue
from vcf_hci.enrichment_steps.network import (
    enrich_fc_hbas as enrich_fc_hbas,
)
from vcf_hci.enrichment_steps.network import (
    enrich_io_link_health,
    enrich_network_adapters,
)
from vcf_hci.enrichment_steps.network import (
    evaluate_optical_link_health as evaluate_optical_link_health,
)
from vcf_hci.enrichment_steps.pcie import (
    correlate_direct_attached_nvme_pcie as correlate_direct_attached_nvme_pcie,
)
from vcf_hci.enrichment_steps.pcie import (
    enrich_pcie_topology,
)
from vcf_hci.enrichment_steps.pcie import (
    synthesize_pcie_slots as synthesize_pcie_slots,
)
from vcf_hci.enrichment_steps.security import enrich_security_posture
from vcf_hci.enrichment_steps.storage import (
    consolidate_direct_attached_nvme_controllers as consolidate_direct_attached_nvme_controllers,
)
from vcf_hci.enrichment_steps.storage import (
    enrich_storage,
)
from vcf_hci.enrichment_steps.storage import (
    is_vmd_active_in_bios as is_vmd_active_in_bios,
)
from vcf_hci.enrichment_steps.system import (
    detect_liquid_cooling as detect_liquid_cooling,
)
from vcf_hci.enrichment_steps.system import (
    enrich_memory_topology,
    enrich_system_identity_and_cpu,
)
from vcf_hci.storage_capacity import normalize_storage_capacities
from vcf_hci.storage_pcie import storage_pcie_view

logger = logging.getLogger("vcf_assess")


def enrich_host_result(
    data: Union[Dict[str, Any], List[Dict[str, Any]]],
    json_hcl: Optional[Dict[str, Any]] = None,
    csv_db: Optional[Any] = None,
    force: bool = False,
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """Enrich a normalized hardware payload with Layer B verdicts and Layer C links.

    Mutates and returns data with:
      - CPU compatibility verdict, architecture tier, and memory/PCIe limits
      - BIOS and BMC firmware baseline evaluations
      - Boot mode verdict and evaluation
      - Memory topology and channel display calculations
      - PCIe lane budget calculations
      - CNA dual-persona BCG URLs
      - Storage drive firmware evaluations
      - BMC security audit evaluation and redacted findings

    Args:
        data: Host dictionary (or list of host dicts for multi-blade chassis)
        json_hcl: Optional vSAN HCL JSON dictionary
        csv_db: Optional vSAN HCL CSV database
        force: If True, re-run enrichment even if payload is marked as already enriched

    Returns:
        The enriched host dictionary or list of dictionaries.
    """
    if not data:
        return data

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                _enrich_single_host(item, json_hcl=json_hcl, csv_db=csv_db, force=force)
        return data

    if isinstance(data, dict):
        _enrich_single_host(data, json_hcl=json_hcl, csv_db=csv_db, force=force)
        return data

    return data


def _enrich_single_host(
    host_data: Dict[str, Any],
    json_hcl: Optional[Dict[str, Any]] = None,
    csv_db: Optional[Any] = None,
    force: bool = False,
) -> None:
    """Enrich in dependency order, preserving each stage's existing error boundary."""
    # Saved summaries need these repairs even when the derived facts are cached.
    host_data.update(storage_pcie_view(host_data))
    normalize_dell_backplanes(host_data)
    refresh_x2apic_guidance(host_data)
    normalize_storage_capacities(host_data.get("storage_subsystem"))
    advisory_system = host_data.get("system")
    if isinstance(advisory_system, dict):
        if not isinstance(advisory_system.get("bios_eval"), dict):
            advisory_system["bios_eval"] = {}
        advisory_system["bios_eval"]["firmware_advisories"] = evaluate_bios_advisories(advisory_system)
    if not force and host_data.get("_enriched"):
        return

    retain_collected_pcie(host_data)
    _repair_saved_evidence(host_data)

    if json_hcl is None:
        try:
            from vcf_hci.hcl import load_vsan_hcl_json
            json_hcl = load_vsan_hcl_json()
        except Exception as exc:
            logger.debug("Failed loading vSAN HCL JSON: %s", exc)
            json_hcl = None

    # Keep actual references: an absent system's fallback must remain detached.
    system, vendor, cpu_summary = enrich_system_identity_and_cpu(host_data)
    cpu_count = enrich_memory_topology(host_data, cpu_summary)

    # FC identity is an input to PCIe synthesis; NIC/storage evaluation follows it.
    try:
        enrich_fc_hbas(host_data)
    except Exception as exc:
        logger.debug("Failed enriching FC HBAs: %s", exc)

    enrich_pcie_topology(host_data, cpu_summary, cpu_count, json_hcl)
    enrich_network_adapters(host_data, json_hcl)
    enrich_io_link_health(host_data)
    enrich_storage(host_data, system, json_hcl)

    enrich_security_posture(host_data, vendor)
    enrich_bios_settings(host_data)
    enrich_oem_baseline(host_data, system)

    enrich_job_queue(host_data)
    enrich_event_blockers(host_data, system)

    # A failed stage or final annotation must not newly mark the host complete.
    from vcf_hci.collector.hardware_findings import annotate_hardware_findings
    annotate_hardware_findings(host_data)
    host_data["_enriched"] = True


def _repair_saved_evidence(host_data: Dict[str, Any]) -> None:
    """Repair legacy PSU, memory and drive evidence before deriving compatibility facts."""
    # Old saved summaries must receive the same semantic fixes as new captures.
    psu = host_data.get("psu_status") or {}
    if psu and not psu.get("power_limit_evidence"):
        psu["power_limit_enforced"] = None
        psu["power_limit_evidence"] = "Unknown"
        watts = psu.get("power_limit_watts")
        threshold = f"configured ({watts} W)" if isinstance(watts, (int, float)) and watts > 0 else "threshold unknown"
        psu["power_cap_badge"] = f"<span class='badge info'>Power cap {threshold}; enforcement unknown</span>"
    memory_telemetry = host_data.get("memory_telemetry") or {}
    if memory_telemetry:
        memory_telemetry["current_utilization_gb"] = "N/A"
        memory_telemetry["historical_peak_gb"] = "N/A"
        memory_telemetry["metric_label"] = "Memory Bus/Bandwidth Utilization"
    for controller in host_data.get("storage_subsystem") or []:
        for drive in controller.get("drives") or []:
            oem_metrics = drive.get("oem_metrics") or {}
            for field in ("media_errors", "power_cycles", "unsafe_shutdowns", "thermal_throttled"):
                if drive.get(field) is None and oem_metrics.get(field) is not None:
                    drive[field] = oem_metrics[field]
            spare = drive.get("available_spare_pct")
            if spare is None:
                spare = oem_metrics.get("available_spare_pct")
            if spare is not None:
                drive.setdefault("available_spare_pct_raw", spare)
                drive["available_spare_pct"] = spare if isinstance(spare, (int, float)) and not isinstance(spare, bool) and 0 <= spare <= 100 else None
