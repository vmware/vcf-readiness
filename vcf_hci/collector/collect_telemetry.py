"""
VCF Readiness Tool — telemetry (CPU, memory, I/O utilization) collection mixin.
"""
import logging
from typing import TYPE_CHECKING, Any, Optional, Tuple

if TYPE_CHECKING:
    class _CollectorBase:
        sys_uri: Optional[str]
        chassis_uri: Optional[str]
        mgr_uri: Optional[str]
        sys_sku: str
        host: str
        port: int
        username: str
        password: str
        session_token: Optional[str]
        verify_ssl: bool
        ca_bundle: Optional[str]
        timeout: float
        host_timeout: float
        scan_start_time: Optional[float]
        cancel_event: Any
        skip_host_set: Any
        skipped: bool
        timed_out: bool
        auth_failed: bool
        chassis_management_info: dict
        stage_callback: Any
        _PCIE_SWITCH_NAMES: tuple
        def _get(self, endpoint: str, _retry: bool = True, timeout: int = 15, critical: bool = True) -> Optional[dict]: ...
        def _get_members(self, endpoint_or_data: Any, limit: int = 0, max_pages: int = 100) -> list: ...
        def _get_oem_raw(self, uri: str, timeout: Optional[float] = None) -> Optional[dict]: ...
        def _is_cancelled_or_skipped(self) -> bool: ...
        @staticmethod
        def _is_license_blocked(data: Optional[dict]) -> Optional[str]: ...
        def _resolve_product_name(self, raw_obj: dict, pcie_cache: Optional[list] = None) -> str: ...
        def oem_bios_date(self, sys_data: dict) -> str: ...
        def oem_sku(self, sys_data: dict) -> str: ...
        def oem_storage_endpoints(self) -> list: ...
        def oem_drive_endurance(self, drive_json: dict) -> Optional[float]: ...
        def oem_drive_metrics(self, drive_json: dict) -> dict: ...
        def oem_nic_firmware(self, adapter_json: dict) -> str: ...
        def oem_cpu_cache(self, proc_json: dict) -> list: ...
        def oem_memory_usage(self, sys_data: dict) -> dict: ...
        def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict: ...
        def oem_handle_retry(self, data: dict, endpoint: str) -> bool: ...
        def oem_manager_paths(self) -> list: ...
        def oem_fastpath_roots(self) -> Optional[Tuple[list, list, list]]: ...
else:
    _CollectorBase = object

logger = logging.getLogger("vcf_assess")



def _percentage(value):
    """Accept finite percentages only; malformed BMC values remain unknown."""
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
        return int(number) if 0 <= number <= 100 else None
    except (TypeError, ValueError, OverflowError):
        return None


def _availability(value, report, endpoint, service_supported, fallback=False):
    """Record bounded endpoint evidence without storing error messages or secrets."""
    recorded = report.get("_collection_evidence") or {}
    error = report.get("error")
    error_dict = error if isinstance(error, dict) else {}
    extended = error_dict.get("@Message.ExtendedInfo") or report.get("@Message.ExtendedInfo") or []
    if isinstance(extended, dict):
        extended = [extended]
    ids = [str(item.get("MessageId") or "") for item in extended if isinstance(item, dict)] or recorded.get("message_ids") or []
    code = str(error_dict.get("code") or "")
    tokens = " ".join(ids + [code]).lower()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        status = "available"
    elif any(t in tokens for t in ("licensenotpassed", "licenserequired", "licensemissing", "licenseexpired")):
        status = "explicitly_license_blocked"
    elif "timeout" in str(error).lower() or "timed out" in str(error).lower():
        status = "timed_out"
    elif report.get("ServiceEnabled") is False:
        status = "disabled"
    elif recorded.get("status"):
        status = recorded["status"]
    elif service_supported is False:
        status = "not_collected"
    else:
        status = "unknown"
    return {"status": status, "source": "SystemUsage" if fallback else endpoint, "endpoint": endpoint,
            "assessed": status != "not_collected", "service_supported": service_supported,
            "http_status": recorded.get("http_status"), "endpoint_status": recorded.get("status") or status,
            "message_ids": ids[:8], "reason": status.replace("_", " ")}


class _TelemetryMixin(_CollectorBase):
    """Collection methods: CPU / memory / I/O telemetry from TelemetryService."""

    def _metric_report(self, endpoint):
        report = {}
        if getattr(self, "_telemetry_service_supported", None) is not False:
            report = self._get(endpoint, timeout=5, critical=False) or {}
        report = dict(report) if isinstance(report, dict) else {}
        evidence = (getattr(self, "_telemetry_endpoint_evidence", None) or {}).get(endpoint)
        if evidence:
            report["_collection_evidence"] = evidence
        return report

    def collect_memory_telemetry(self, installed_gb: int = 256) -> dict:
        current_pct = historical_peak_pct = None
        fallback = False
        peak_ts = "N/A"
        metric_report = {}
        endpoint = "/TelemetryService/MetricReports/SystemBoardMemoryUsage"
        metric_report = self._metric_report(endpoint)
        if not metric_report.get("error"):
            for metric in metric_report.get("MetricValues", []):
                m_id, val = str(metric.get("MetricId", "")), metric.get("MetricValue")
                if "Current" in m_id and val is not None:
                    current_pct = _percentage(val)
                elif "Peak" in m_id and val is not None:
                    historical_peak_pct = _percentage(val)
                    peak_ts = metric.get("Timestamp", "N/A")
        if current_pct is None and self.sys_uri:
            sys_data = self._get(self.sys_uri) or {}
            usage = self.oem_memory_usage(sys_data)
            if "MemoryBusUtil" in usage:
                current_pct = _percentage(usage["MemoryBusUtil"])
                fallback = current_pct is not None
        # These are bandwidth counters, not occupied RAM capacity.
        curr_gb = peak_gb = "N/A"
        return {
            "availability": {
                "current": _availability(current_pct, metric_report, endpoint, getattr(self, "_telemetry_service_supported", None), fallback),
                "historical_peak": _availability(historical_peak_pct, metric_report, endpoint, getattr(self, "_telemetry_service_supported", None)),
            },
            "current_utilization_pct": current_pct if current_pct is not None else "N/A",
            "current_utilization_gb": curr_gb,
            "historical_peak_pct": historical_peak_pct if historical_peak_pct is not None else "N/A",
            "historical_peak_gb": peak_gb,
            "peak_timestamp": peak_ts,
            "metric_label": "Memory Bus/Bandwidth Utilization",
        }


    def collect_cpu_telemetry(self) -> dict:
        current_pct = historical_peak_pct = None
        fallback = False
        peak_ts = "N/A"
        metric_report = {}
        endpoint = "/TelemetryService/MetricReports/CPUUsage"
        metric_report = self._metric_report(endpoint)
        if not metric_report.get("error"):
            for metric in metric_report.get("MetricValues", []):
                m_id, val = str(metric.get("MetricId", "")), metric.get("MetricValue")
                if "Current" in m_id and val is not None:
                    current_pct = _percentage(val)
                elif "Peak" in m_id and val is not None:
                    historical_peak_pct = _percentage(val)
                    peak_ts = metric.get("Timestamp", "N/A")
        if current_pct is None and self.sys_uri:
            sys_data = self._get(self.sys_uri) or {}
            usage = self.oem_memory_usage(sys_data)
            if "CPUUtil" in usage:
                current_pct = _percentage(usage["CPUUtil"])
                fallback = current_pct is not None
        return {
            "availability": {
                "current": _availability(current_pct, metric_report, endpoint, getattr(self, "_telemetry_service_supported", None), fallback),
                "historical_peak": _availability(historical_peak_pct, metric_report, endpoint, getattr(self, "_telemetry_service_supported", None)),
            },
            "current_utilization_pct": current_pct if current_pct is not None else "N/A",
            "historical_peak_pct": historical_peak_pct if historical_peak_pct is not None else "N/A",
            "peak_timestamp": peak_ts,
        }


    def collect_pcie_telemetry(self) -> dict:
        """Collect PCIe bus and switch port error telemetry from TelemetryService.

        Inspects MetricReports for PCIe error metrics including:
          - GPUPCIeCorrectableErrorCount
          - PCIeSwitchPortReceiverErrs
          - PCIeSwitchPortRecoveryDiagErrs (retraining counts)
          - PCIeSwitchPortBadDTLPErrs, PCIeSwitchPortBadDLLPErrs
          - LocalLinkIntegrityErrors
        """
        pcie_telem = {
            "pcie_switch_receiver_errors": 0,
            "pcie_switch_recovery_errors": 0,
            "pcie_switch_bad_tlp_errors": 0,
            "pcie_switch_bad_dllp_errors": 0,
            "gpu_pcie_correctable_errors": 0,
            "local_link_integrity_errors": 0,
            "has_pcie_metrics": False,
        }
        if getattr(self, "_telemetry_service_supported", None) is False:
            return pcie_telem

        report_names = [
            "/TelemetryService/MetricReports/GPUMetrics",
            "/TelemetryService/MetricReports/GPUStatistics",
            "/TelemetryService/MetricReports/AggregationMetrics",
        ]
        for r_name in report_names:
            report = self._get(r_name, timeout=5, critical=False) or {}
            if report.get("error"):
                continue
            for m in report.get("MetricValues", []):
                mid = str(m.get("MetricId", ""))
                val = m.get("MetricValue")
                if val is None:
                    continue
                try:
                    num_val = int(float(val))
                except (ValueError, TypeError):
                    continue

                if "GPUPCIeCorrectable" in mid:
                    pcie_telem["gpu_pcie_correctable_errors"] += num_val
                    pcie_telem["has_pcie_metrics"] = True
                elif "PCIeSwitchPortReceiverErrs" in mid:
                    pcie_telem["pcie_switch_receiver_errors"] += num_val
                    pcie_telem["has_pcie_metrics"] = True
                elif "PCIeSwitchPortRecoveryDiagErrs" in mid:
                    pcie_telem["pcie_switch_recovery_errors"] += num_val
                    pcie_telem["has_pcie_metrics"] = True
                elif "PCIeSwitchPortBadDTLPErrs" in mid:
                    pcie_telem["pcie_switch_bad_tlp_errors"] += num_val
                    pcie_telem["has_pcie_metrics"] = True
                elif "PCIeSwitchPortBadDLLPErrs" in mid:
                    pcie_telem["pcie_switch_bad_dllp_errors"] += num_val
                    pcie_telem["has_pcie_metrics"] = True
                elif "LocalLinkIntegrityErrors" in mid:
                    pcie_telem["local_link_integrity_errors"] += num_val
                    pcie_telem["has_pcie_metrics"] = True

        return pcie_telem

    def collect_io_telemetry(self) -> dict:
        """PCIe root complex I/O bandwidth utilization (IOUsage).

        Source priority:
          Dell iDRAC: /TelemetryService/MetricReports/SystemUsageAggregations
            - Average CollectionFunction → current proxy (1-min rolling avg)
            - Maximum CollectionFunction → 1-min interval peak
          HPE iLO:    Oem.Hpe.SystemUsage.IOBusUtil (inline in System resource)
        """
        io_avg = io_max = None
        fallback = False
        endpoint = "/TelemetryService/MetricReports/SystemUsageAggregations"
        report = {}
        report = self._metric_report(endpoint)
        if not report.get("error"):
            for m in report.get("MetricValues", []):
                mid = str(m.get("MetricId", ""))
                fn  = str(m.get("CollectionFunction", ""))
                val = m.get("MetricValue")
                if mid != "IOUsage" or val is None:
                    continue
                try:
                    v = _percentage(val)
                except (ValueError, TypeError):
                    continue
                if fn == "Average":
                    io_avg = v
                elif fn == "Maximum":
                    io_max = v
        if io_avg is None and self.sys_uri:
            sys_data = self._get(self.sys_uri) or {}
            usage = self.oem_memory_usage(sys_data)
            if "IOBusUtil" in usage:
                io_avg = _percentage(usage["IOBusUtil"])
                fallback = io_avg is not None
        res = {
            "availability": {
                "current": _availability(io_avg, report, endpoint, getattr(self, "_telemetry_service_supported", None), fallback),
                "historical_peak": _availability(io_max, report, endpoint, getattr(self, "_telemetry_service_supported", None)),
            },
            "io_current_pct": io_avg if io_avg is not None else "N/A",
            "io_peak_pct":    io_max if io_max is not None else "N/A",
        }
        pcie_telem = self.collect_pcie_telemetry()
        if pcie_telem.get("has_pcie_metrics"):
            res["pcie_telemetry"] = pcie_telem
        return res

