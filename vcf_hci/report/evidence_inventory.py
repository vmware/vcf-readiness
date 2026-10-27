"""Views of retained component evidence; no collection or compatibility inference."""

import re
from datetime import datetime, timezone
from html import escape

from vcf_hci.report.disclosures import supporting_evidence_html


def _known(value):
    return value is not None and str(value).strip().lower() not in ("", "n/a", "unknown", "none")


def service_inventory(data):
    """Merge assemblies and component detail by serial, or part plus location."""
    rows = []
    identities = {}
    sources = [
        ("assembly", data.get("assembly_inventory") or []),
        ("PSU", (data.get("psu_status") or {}).get("psus") or []),
        ("DIMM", (data.get("memory_subsystem") or {}).get("dimm_list") or []),
        ("fan", (data.get("thermal_telemetry") or {}).get("fans") or []),
    ]
    for source, items in sources:
        for item in items:
            if not isinstance(item, dict):
                continue
            serial = item.get("serial_number")
            part = item.get("part_number")
            location = item.get("physical_context") or item.get("slot") or item.get("device_locator") or item.get("name") or ""
            identity = ("serial", str(serial).strip().lower()) if _known(serial) else (
                ("part_location", str(part).strip().lower(), str(location).strip().lower())
                if _known(part) and _known(location) else None)
            row = {key: item.get(key) for key in (
                "name", "model", "part_number", "serial_number", "spare_part_number",
                "production_date", "health", "state")}
            row["location"] = location
            row["source"] = source
            if identity is not None and identity in identities:
                existing = identities[identity]
                for key, value in row.items():
                    if key != "source" and not _known(existing.get(key)) and _known(value):
                        existing[key] = value
                existing["source"] += ", " + source
            else:
                rows.append(row)
                if identity is not None:
                    identities[identity] = row
    return rows


def sensor_inventory(data):
    """Merge generic sensors with thermal detail without dropping real zeros."""
    rows = {}
    thermal = data.get("thermal_telemetry") or {}
    for source, kind, items in (
        ("Sensors", "", data.get("chassis_sensors") or []),
        ("Thermal", "fan", thermal.get("fans") or []),
        ("Thermal", "temperature", thermal.get("temperatures") or thermal.get("sensors") or []),
    ):
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or item.get("id") or "Unknown")
            item_kind = item.get("kind") or kind
            identity = (name.strip().lower(), item_kind)
            reading = next((item[k] for k in ("reading", "reading_rpm", "rpm", "reading_celsius", "temperature_c")
                            if item.get(k) is not None), None)
            row = {"name": name, "kind": item_kind, "reading": reading,
                   "units": item.get("units") or ("RPM" if item_kind == "fan" else "°C" if item_kind == "temperature" else ""),
                   "health": item.get("health"), "part_number": item.get("part_number"),
                   "serial_number": item.get("serial_number"), "source": source}
            if identity not in rows:
                rows[identity] = row
            else:
                for key, value in row.items():
                    if not _known(rows[identity].get(key)) and _known(value):
                        rows[identity][key] = value
    return list(rows.values())


def pcie_locality(data):
    """Positive CPU-affinity links only; never infer locality from a model name."""
    rows = []
    for device in data.get("pcie_devices") or []:
        if not isinstance(device, dict):
            continue
        raw = device.get("_raw") if isinstance(device.get("_raw"), dict) else {}
        affinity = (((raw.get("Links") or {}).get("Oem") or {}).get("Dell") or {}).get("CPUAffinity")
        if isinstance(affinity, dict):
            affinity = [affinity]
        if isinstance(affinity, str):
            affinity = [affinity]
        affinity = affinity if isinstance(affinity, (list, tuple)) else []
        sockets = []
        for link in affinity:
            value = link.get("@odata.id") if isinstance(link, dict) else link
            if isinstance(value, str) and value:
                sockets.append(value.rstrip("/").rsplit("/", 1)[-1])
        rows.append({"name": device.get("name") or device.get("id"),
                     "id": device.get("id"), "class": device.get("device_class"),
                     "cpu_affinity": ", ".join(sorted(set(sockets))) or "Unknown",
                     "source": "Links.Oem.Dell.CPUAffinity" if sockets else "Unknown"})
    return rows


def telemetry_inventory(data):
    rows = []
    partial = data.get("partial_sections") or []
    for key, label, current, peak in (
        ("cpu_telemetry", "CPU", "current_utilization_pct", "historical_peak_pct"),
        ("memory_telemetry", "Memory bandwidth", "current_utilization_pct", "historical_peak_pct"),
        ("io_telemetry", "PCIe I/O", "io_current_pct", "io_peak_pct"),
    ):
        telemetry = data.get(key) or {}
        for period, field in (("current", current), ("historical_peak", peak)):
            value = telemetry.get(field)
            evidence = (telemetry.get("availability") or {}).get(period) or {}
            available = isinstance(value, (int, float)) and not isinstance(value, bool)
            status = "available" if available else evidence.get("status") or ("not_collected" if key in partial or (not telemetry and "quick" in str(data.get("scan_profile") or "").lower()) else "unknown")
            rows.append({"name": label, "period": period, "value_pct": value if available else None,
                         "status": status, "source": evidence.get("source") or "Unknown",
                         "assessed": evidence.get("assessed", available),
                         "endpoint_status": evidence.get("endpoint_status"), "http_status": evidence.get("http_status"),
                         "endpoint": evidence.get("endpoint"),
                         "message_ids": ", ".join(evidence.get("message_ids") or [])})
    return rows


def power_context(data):
    psu = data.get("psu_status") or {}
    capacities = [p.get("wattage") for p in psu.get("psus") or [] if isinstance(p, dict)]
    complete = bool(capacities) and all(isinstance(c, (int, float)) and c > 0 for c in capacities)
    installed = sum(capacities) if complete else None
    after_loss = installed - max(capacities) if complete else None
    measured = psu.get("consumed_watts")
    metrics = psu.get("power_metrics") or {}
    return {"installed_capacity_w": installed, "capacity_after_largest_psu_loss_w": after_loss,
            "redundancy_verified": psu.get("redundant") if isinstance(psu.get("redundant"), bool) else None,
            "measured_w": measured, "average_w": metrics.get("avg_w"), "peak_w": metrics.get("max_w"),
            "measurement_interval_min": metrics.get("interval_min"),
            "allocated_w": psu.get("power_allocated_watts"),
            "headroom_after_loss_w": after_loss - measured if after_loss is not None and isinstance(measured, (int, float)) else None,
            "configured_limit_w": psu.get("power_limit_watts"),
            "limit_enforcement": "enabled" if psu.get("power_limit_enforced") is True else "disabled" if psu.get("power_limit_enforced") is False else "unknown"}


def firmware_context(data):
    rows = []
    # Age is relative to capture time, never an automatic health verdict.
    captured = data.get("timestamp") or data.get("scanned_at")
    try:
        reference = datetime.fromisoformat(str(captured).replace("Z", "+00:00"))
        reference = reference.replace(tzinfo=timezone.utc) if reference.tzinfo is None else reference.astimezone(timezone.utc)
    except (ValueError, TypeError):
        reference = None
    for item in data.get("firmware_inventory") or []:
        if not isinstance(item, dict):
            continue
        release = item.get("release_date") or item.get("release_date_time")
        age = None
        if reference and release:
            try:
                released = datetime.fromisoformat(str(release).replace("Z", "+00:00"))
                released = released.replace(tzinfo=timezone.utc) if released.tzinfo is None else released.astimezone(timezone.utc)
                age = (reference - released).days
                if age < 0:
                    age = None
            except (ValueError, TypeError):
                pass
        rows.append({"name": item.get("name"), "id": item.get("id"), "version": item.get("version"),
                     "release_date": release, "age_at_capture_days": age,
                     "updateable": item.get("updateable"), "source": "firmware_inventory"})
    return rows


def _table(title, rows, columns):
    if not rows:
        return ""
    def cell(value):
        return escape(str(value)) if value is not None and value != "" else "Unknown"
    header = "".join(f"<th>{cell(label)}</th>" for _, label in columns)
    body = "".join("<tr>" + "".join(f"<td>{cell(row.get(key))}</td>" for key, _ in columns) + "</tr>" for row in rows)
    table = f"<div style='overflow-x:auto'><table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table></div>"
    element_id = "component-evidence-" + re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return supporting_evidence_html(title, table, len(rows), element_id)


def render_evidence_inventory(data):
    """Compact drill-down placed in the health tab of standalone reports."""
    power = [{"name": key.replace("_", " "), "value": value} for key, value in power_context(data).items()]
    license_info = data.get("bmc_license") or {}
    licensing = [{"name": key, "value": license_info.get(key)} for key in ("license_name", "edition", "license_term", "expiry", "status", "source")]
    return (
        "<h2>Component Evidence &amp; Sizing Context</h2>"
        "<p>Unknown values require additional evidence. Memory bandwidth does not measure occupied RAM. "
        "PSU capacity after a failure is arithmetic capacity; verify wiring and redundancy mode. "
        "Firmware age is context, not a health verdict.</p>"
        + _table("Telemetry availability", telemetry_inventory(data), [(k, k.replace("_", " ")) for k in ("name", "period", "value_pct", "status", "source", "endpoint", "endpoint_status", "http_status", "message_ids")])
        + _table("BMC license evidence", licensing, [("name", "Field"), ("value", "Value")])
        + _table("PCIe CPU locality", pcie_locality(data), [("name", "Device"), ("id", "Identity"), ("class", "Class"), ("cpu_affinity", "CPU socket"), ("source", "Source")])
        + _table("Service inventory", service_inventory(data), [(k, k.replace("_", " ")) for k in ("name", "location", "part_number", "serial_number", "spare_part_number", "production_date", "health", "source")])
        + _table("Sensors", sensor_inventory(data), [(k, k.replace("_", " ")) for k in ("name", "kind", "reading", "units", "health", "part_number", "serial_number", "source")])
        + _table("Power sizing", power, [("name", "Metric"), ("value", "Value")])
        + _table("Firmware provenance", firmware_context(data), [(k, k.replace("_", " ")) for k in ("name", "id", "version", "release_date", "age_at_capture_days", "updateable", "source")])
    )
