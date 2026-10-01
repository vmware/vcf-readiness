"""
VCF Readiness Tool — Prometheus Telemetry Exporter (vcf_hci.telemetry_exporter)

Generates standard Prometheus / OpenMetrics text exposition format metrics for
BMC power, thermal, hardware health, and VCF 9.1 readiness verdicts.

Enables chaining high-frequency telemetry (1m–5m intervals) directly into
VMware Cloud Foundation (VCF) Operations via Cloud Proxy Telegraf or the
Prometheus Management Pack, while reserving the VCF-R Management Pack for
24h deep inventory and topology mapping.

Output conforms to Prometheus exposition format 0.0.4.
Zero external dependencies (stdlib only).
"""

import logging
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("vcf_assess")


def escape_label_value(val: Any) -> str:
    """Escape label values according to Prometheus text exposition spec."""
    s = str(val or "")
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return s


def format_prometheus_metric(
    name: str,
    value: Union[int, float],
    labels: Optional[Dict[str, str]] = None,
    help_text: Optional[str] = None,
    metric_type: str = "gauge",
) -> str:
    """Format a single metric line or series in Prometheus text format."""
    lines = []
    if help_text:
        lines.append(f"# HELP {name} {help_text}")
    if metric_type:
        lines.append(f"# TYPE {name} {metric_type}")

    lbl_parts = []
    if labels:
        for k, v in sorted(labels.items()):
            lbl_parts.append(f'{k}="{escape_label_value(v)}"')
    lbl_str = f"{{{','.join(lbl_parts)}}}" if lbl_parts else ""

    # Ensure clean float or integer representation
    if isinstance(value, float):
        val_str = f"{value:.4f}".rstrip("0").rstrip(".") if not value.is_integer() else f"{int(value)}"
    else:
        val_str = str(int(value))

    lines.append(f"{name}{lbl_str} {val_str}")
    return "\n".join(lines)


def render_assessment_metrics(assessment: Dict[str, Any], target_ip: Optional[str] = None) -> str:
    """Convert an individual host assessment dictionary into Prometheus metrics."""
    if not isinstance(assessment, dict):
        return ""

    target = target_ip or str(assessment.get("ip") or assessment.get("host") or "unknown")
    vendor = str(assessment.get("system", {}).get("manufacturer") or assessment.get("vendor") or "Generic")
    model = str(assessment.get("system", {}).get("model") or "Unknown")

    common_labels = {
        "target": target,
        "vendor": vendor,
        "model": model,
    }

    out_lines = []

    # 1. Scrape Health (redfish_up: 1=OK, 0=Failed, 2=Lockout)
    auth_failed = bool(assessment.get("auth_failed"))
    timed_out = bool(assessment.get("timed_out"))
    if auth_failed:
        up_val = 2
    elif timed_out:
        up_val = 0
    else:
        up_val = 1

    out_lines.append(format_prometheus_metric(
        "redfish_up",
        up_val,
        common_labels,
        help_text="Redfish scrape status: 1=success, 0=failed, 2=auth_lockout",
    ))

    # 2. VCF 9.1 Readiness Verdict (1=COMPLIANT, 0=NON_COMPLIANT)
    verdict = str(assessment.get("vcf9_verdict") or assessment.get("overall_verdict") or "").upper()
    vcf_val = 1 if "COMPLIANT" in verdict and "NON" not in verdict else 0
    vcf_labels = dict(common_labels)
    vcf_labels["verdict"] = verdict or "UNKNOWN"
    out_lines.append(format_prometheus_metric(
        "vcf_readiness_status",
        vcf_val,
        vcf_labels,
        help_text="VCF 9.1 overall compatibility status (1=compliant, 0=non-compliant)",
    ))

    # 3. vSAN ESA Readiness (1=Ready, 0=Not Ready)
    esa_ready = bool(assessment.get("vsan_esa_ready") or assessment.get("esa_ready"))
    out_lines.append(format_prometheus_metric(
        "vcf_vsan_esa_ready",
        1 if esa_ready else 0,
        common_labels,
        help_text="vSAN Express Storage Architecture readiness (1=ready, 0=not ready)",
    ))

    # 4. Power Telemetry
    power_data = assessment.get("power") or assessment.get("power_subsystem") or {}
    if isinstance(power_data, dict):
        # Power consumed (W)
        consumed_w = power_data.get("power_consumed_watts") or power_data.get("consumed_watts")
        if isinstance(consumed_w, (int, float)):
            out_lines.append(format_prometheus_metric(
                "redfish_power_consumed_watts",
                consumed_w,
                common_labels,
                help_text="System total power consumption in Watts",
            ))

        # Power supplies
        psus = power_data.get("power_supplies") or []
        for idx, psu in enumerate(psus if isinstance(psus, list) else []):
            if not isinstance(psu, dict):
                continue
            psu_labels = dict(common_labels)
            psu_labels["bay"] = str(psu.get("bay") or psu.get("id") or idx + 1)
            psu_labels["serial"] = str(psu.get("serial_number") or psu.get("serial") or "")
            output_w = psu.get("last_power_output_watts") or psu.get("output_watts") or psu.get("power_output_watts")
            if isinstance(output_w, (int, float)):
                out_lines.append(format_prometheus_metric(
                    "redfish_power_supply_output_watts",
                    output_w,
                    psu_labels,
                    help_text="Power supply unit output in Watts",
                ))

    # 5. Thermal Telemetry (Temperatures and Fans)
    thermal_data = assessment.get("thermal") or assessment.get("thermal_subsystem") or {}
    if isinstance(thermal_data, dict):
        temps = thermal_data.get("temperatures") or []
        for t_item in temps if isinstance(temps, list) else []:
            if not isinstance(t_item, dict):
                continue
            t_name = str(t_item.get("name") or t_item.get("sensor") or "Unknown")
            celsius = t_item.get("reading_celsius") or t_item.get("reading") or t_item.get("temperature")
            if isinstance(celsius, (int, float)):
                t_labels = dict(common_labels)
                t_labels["sensor"] = t_name
                out_lines.append(format_prometheus_metric(
                    "redfish_thermal_sensor_temperature_celsius",
                    celsius,
                    t_labels,
                    help_text="Thermal sensor temperature reading in Celsius",
                ))

        fans = thermal_data.get("fans") or []
        for f_item in fans if isinstance(fans, list) else []:
            if not isinstance(f_item, dict):
                continue
            f_name = str(f_item.get("name") or f_item.get("fan") or "Unknown")
            speed_pct = f_item.get("speed_percent") or f_item.get("reading")
            if isinstance(speed_pct, (int, float)):
                f_labels = dict(common_labels)
                f_labels["fan"] = f_name
                out_lines.append(format_prometheus_metric(
                    "redfish_thermal_fan_speed_percent",
                    speed_pct,
                    f_labels,
                    help_text="Fan speed percentage (0-100%)",
                ))

    return "\n".join(out_lines) + "\n"


def render_fleet_metrics(assessments: List[Dict[str, Any]]) -> str:
    """Convert an entire fleet of host assessment dictionaries into Prometheus format."""
    chunks = []
    for ass in assessments or []:
        if isinstance(ass, dict):
            chunks.append(render_assessment_metrics(ass))
    return "".join(chunks)


__all__ = [
    "escape_label_value",
    "format_prometheus_metric",
    "render_assessment_metrics",
    "render_fleet_metrics",
]
