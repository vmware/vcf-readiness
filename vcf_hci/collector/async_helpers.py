"""
VCF Readiness Tool — Asynchronous helper functions and safe defaults for Redfish collector.
"""
import html as _html_mod
import logging
import time
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any, Dict, Optional

from vcf_hci.security.contract import empty_security_evidence

logger = logging.getLogger("vcf_assess")


def _h(s: Any) -> str:
    """HTML-escape a BMC-sourced string; returns '' for None to avoid AttributeError."""
    return _html_mod.escape(str(s)) if s is not None else ""


# Safe defaults used when a section crashes so the rest of the report still renders.
_SECTION_DEFAULTS: Dict[str, Any] = {
    "bios_checks":       {"power_modes": [], "ras_modes": [], "side_channel": [], "attributes": {}},
    "sel_alarms":        [],
    "bmc_license":       {"license_name": "N/A", "badge": "", "vendor_note": ""},
    "bmc_sec_cfg":       {},
    "bmc_security_evidence": empty_security_evidence("generic"),
    "sw_inv_os":         {},
    "bmc_net_proto":     {"ntp_enabled": False, "ntp_servers": [], "ntp_configured": False, "has_ntp_servers": False, "dns_enabled": False, "dns_servers": [], "dns_configured": False, "protocols": {}, "virtual_media_inserted": False, "bmc_datetime": None, "datetime_local_offset": None, "is_utc": True, "timezone_name": None, "time_drift_seconds": None, "time_drift_detected": False, "badge": ""},
    "firmware_inventory": [],
    "pcie_devices":      [],
    "memory_subsystem":  {},
    "memory_telemetry":  {},
    "cpu_telemetry":     {},
    "io_telemetry":      {},
    "thermal_telemetry": {"sensors": [], "key_sensor": None},
    "network_adapters":  [],
    "storage_subsystem": [],
    "gpu_accelerators":  [],
    "fc_hbas":           [],
    "lldp_neighbors":    [],
    "psu_status":        {},
    "pcie_slots":        [],
    "pcie_switches":     [],
    "job_queue":         {},
}


def _safe_result(future: Any, label: str, host: str, timeout: float = 60.0, collector: Optional[Any] = None) -> Any:
    """Return the future's result, or a safe default on any exception or timeout.

    Logs the full traceback at DEBUG level so the debug log captures
    every section failure without aborting the host scan.
    """
    if future is None:
        if label == "bmc_security_evidence":
            return empty_security_evidence("generic")
        return _SECTION_DEFAULTS.get(label)
    try:
        return future.result(timeout=timeout)
    except (TimeoutError, FuturesTimeoutError, Exception) as exc:
        is_timeout = isinstance(exc, (TimeoutError, FuturesTimeoutError)) or "timed out" in str(exc).lower() or "timeout" in str(exc).lower()
        exc_str = str(exc).strip() or type(exc).__name__
        logger.debug(f"[SECTION ERROR] {host} / {label}: {exc_str}", exc_info=True)
        if is_timeout:
            logger.warning(f"  [⚠] {host} — section '{label}' timed out: {exc_str} (continuing)")
            if collector is not None:
                if label not in getattr(collector, "_timed_out_sections", []):
                    collector._timed_out_sections.append(label)
                if label not in getattr(collector, "_failed_sections", []):
                    collector._failed_sections.append(label)
        else:
            logger.warning(f"  [⚠] {host} — section '{label}' failed: {exc_str} (continuing)")
            if collector is not None:
                if label not in getattr(collector, "_failed_sections", []):
                    collector._failed_sections.append(label)
        if label == "bmc_security_evidence":
            return empty_security_evidence("generic")
        return _SECTION_DEFAULTS.get(label)


def _timed(label: str, fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Call fn(*args, **kwargs), logging elapsed time at DEBUG level."""
    t0 = time.time()
    result = fn(*args, **kwargs)
    logger.debug(f"[TIMING] {label}: {time.time() - t0:.2f}s")
    return result
