"""
VCF Operations 9.1 — Lightweight Ops Collector & Telemetry Helpers.

Provides narrow fetchers and profile resolvers for high-frequency polling
tiers (T1 telemetry, T2 component health) and ops-inventory collection.
"""
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vcf_assess")


def usable_temperature(temp_c: Any, temp_max: Any = None) -> Optional[float]:
    """Return valid Celsius temperature reading or None for null/sentinels.

    Sentinel rule: 255 °C is treated as an invalid sensor reading (common on iLO)
    when temp_max is missing or 0.
    """
    if temp_c is None:
        return None
    try:
        val = float(temp_c)
    except (ValueError, TypeError):
        return None

    max_val = None
    if temp_max is not None:
        try:
            max_val = float(temp_max)
        except (ValueError, TypeError):
            max_val = None

    if val == 255.0 and (max_val is None or max_val <= 0.0):
        return None

    return val


def resolve_scan_profile(
    scan_profile: Optional[str] = None,
    quick_mode: bool = False,
    lean_mode: bool = False,
    crawl: bool = False,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Resolve scan profile string and flags into execution parameters.

    Returns dict with keys:
      name, lean_mode, quick_mode, collect_sel, collect_firmware,
      collect_util_telemetry, crawl.
    """
    caller_crawl = bool(crawl or kwargs.get("crawl_endpoints", False))

    if scan_profile == "ops-inventory":
        return {
            "name": "ops-inventory",
            "lean_mode": True,
            "quick_mode": False,
            "collect_sel": True,
            "collect_firmware": True,
            "collect_util_telemetry": False,
            "crawl": False,
        }
    elif scan_profile == "inventory-lite" or (scan_profile is None and quick_mode):
        return {
            "name": "inventory-lite",
            "lean_mode": True,
            "quick_mode": True,
            "collect_sel": False,
            "collect_firmware": False,
            "collect_util_telemetry": False,
            "crawl": False,
        }
    elif scan_profile == "readiness-lean" or (scan_profile is None and lean_mode):
        return {
            "name": "readiness-lean",
            "lean_mode": True,
            "quick_mode": False,
            "collect_sel": False,
            "collect_firmware": False,
            "collect_util_telemetry": False,
            "crawl": False,
        }
    else:
        # Default: readiness-full
        return {
            "name": "readiness-full",
            "lean_mode": False,
            "quick_mode": False,
            "collect_sel": True,
            "collect_firmware": True,
            "collect_util_telemetry": True,
            "crawl": caller_crawl,
        }


def telemetry_paths(cached_uris: Optional[Dict[str, Any]]) -> List[str]:
    """Return at most six telemetry paths for T1 polling.

    Includes cached system, chassis, power, and thermal, plus modern subsystem
    URIs (PowerSubsystem / ThermalSubsystem) when legacy endpoints are absent.
    Never includes MetricReport paths or crawler seeds.
    """
    if not cached_uris or not isinstance(cached_uris, dict):
        return []

    def _is_valid_path(p: str) -> bool:
        if not p or not isinstance(p, str):
            return False
        if "MetricReport" in p:
            return False
        return p not in ("/", "/redfish", "/redfish/v1", "/redfish/v1/")

    paths: List[str] = []
    seen = set()

    def _add(uri: Optional[str]) -> None:
        if uri and isinstance(uri, str):
            uri_clean = uri.strip()
            if _is_valid_path(uri_clean) and uri_clean not in seen:
                seen.add(uri_clean)
                paths.append(uri_clean)

    # 1. System URI
    sys_uri = (
        cached_uris.get("system")
        or cached_uris.get("sys")
        or cached_uris.get("system_uri")
        or cached_uris.get("sys_uri")
    )
    if not sys_uri:
        for k in cached_uris:
            if isinstance(k, str) and "/Systems/" in k:
                sys_uri = k
                break

    # 2. Chassis URI
    chassis_uri = cached_uris.get("chassis") or cached_uris.get("chassis_uri")
    if not chassis_uri:
        for k in cached_uris:
            if isinstance(k, str) and "/Chassis/" in k and not any(sub in k for sub in ("Power", "Thermal", "Sensors", "Network")):
                chassis_uri = k
                break

    # 3. Power endpoints (legacy vs modern)
    power_uri = cached_uris.get("power") or cached_uris.get("power_uri")
    if not power_uri:
        for k in cached_uris:
            if isinstance(k, str) and k.rstrip("/").endswith("/Power"):
                power_uri = k
                break

    power_subsys_uri = (
        cached_uris.get("power_subsystem")
        or cached_uris.get("power_subsystem_uri")
        or cached_uris.get("PowerSubsystem")
    )
    if not power_subsys_uri:
        for k in cached_uris:
            if isinstance(k, str) and "PowerSubsystem" in k:
                power_subsys_uri = k
                break

    # 4. Thermal endpoints (legacy vs modern)
    thermal_uri = cached_uris.get("thermal") or cached_uris.get("thermal_uri")
    if not thermal_uri:
        for k in cached_uris:
            if isinstance(k, str) and k.rstrip("/").endswith("/Thermal"):
                thermal_uri = k
                break

    thermal_subsys_uri = (
        cached_uris.get("thermal_subsystem")
        or cached_uris.get("thermal_subsystem_uri")
        or cached_uris.get("ThermalSubsystem")
    )
    if not thermal_subsys_uri:
        for k in cached_uris:
            if isinstance(k, str) and "ThermalSubsystem" in k:
                thermal_subsys_uri = k
                break

    _add(sys_uri)
    _add(chassis_uri)

    if power_uri:
        _add(power_uri)
    elif power_subsys_uri:
        _add(power_subsys_uri)
    elif chassis_uri:
        _add(f"{chassis_uri.rstrip('/')}/Power")

    if thermal_uri:
        _add(thermal_uri)
    elif thermal_subsys_uri:
        _add(thermal_subsys_uri)
    elif chassis_uri:
        _add(f"{chassis_uri.rstrip('/')}/Thermal")

    return paths[:6]


def collect_ops_telemetry(collector: Any, cached_uris: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Collect T1 narrow telemetry: watts, volts, thermal max, fan faults, redundancy, health.

    Reuses existing power and thermal collectors / normalizers on BaseRedfishCollector.
    Does not walk DIMMs or PCIe.
    """
    if cached_uris and isinstance(cached_uris, dict):
        chassis_uri = (
            cached_uris.get("chassis")
            or cached_uris.get("chassis_uri")
            or getattr(collector, "chassis_uri", None)
        )
        if chassis_uri and not getattr(collector, "chassis_uri", None):
            collector.chassis_uri = chassis_uri
    else:
        chassis_uri = getattr(collector, "chassis_uri", None)

    psu_status: Dict[str, Any] = {}
    if hasattr(collector, "collect_psu_status"):
        try:
            psu_status = collector.collect_psu_status() or {}
        except Exception as p_err:
            logger.debug("collect_psu_status non-fatal exception: %s", p_err)

    thermal_status: Dict[str, Any] = {}
    if hasattr(collector, "collect_thermal_telemetry"):
        try:
            thermal_status = collector.collect_thermal_telemetry() or {}
        except Exception as t_err:
            logger.debug("collect_thermal_telemetry non-fatal exception: %s", t_err)

    # If power/thermal mixins were not present or returned empty, perform minimal fallback GETs
    raw_power: Dict[str, Any] = {}
    if not psu_status and hasattr(collector, "_get") and chassis_uri:
        power_ep = f"{chassis_uri.rstrip('/')}/Power"
        raw_power = collector._get(power_ep) or {}
        if not raw_power or raw_power.get("error"):
            subsys_ep = f"{chassis_uri.rstrip('/')}/PowerSubsystem"
            raw_power = collector._get(subsys_ep) or {}

    raw_thermal: Dict[str, Any] = {}
    if not thermal_status and hasattr(collector, "_get") and chassis_uri:
        thermal_ep = f"{chassis_uri.rstrip('/')}/Thermal"
        raw_thermal = collector._get(thermal_ep) or {}
        if not raw_thermal or raw_thermal.get("error"):
            subsys_ep = f"{chassis_uri.rstrip('/')}/ThermalSubsystem"
            raw_thermal = collector._get(subsys_ep) or {}

    # Extract power metrics
    consumed_watts = psu_status.get("consumed_watts")
    if consumed_watts is None and raw_power:
        for pc in raw_power.get("PowerControl", []):
            if isinstance(pc, dict) and pc.get("PowerConsumedWatts") is not None:
                try:
                    consumed_watts = float(pc["PowerConsumedWatts"])
                    break
                except (ValueError, TypeError):
                    pass

    power_metrics = psu_status.get("power_metrics") or {}
    power_peak_watts = power_metrics.get("max_w") or consumed_watts
    energy_kwh = psu_status.get("consumed_energy_kwh")
    if energy_kwh is None and raw_power:
        for pc in raw_power.get("PowerControl", []):
            if isinstance(pc, dict):
                p_kwh = pc.get("ConsumedIntervalEnergykWh") or pc.get("EnergykWh")
                if p_kwh is not None:
                    try:
                        energy_kwh = round(float(p_kwh), 2)
                        break
                    except (ValueError, TypeError):
                        pass

    redundant = bool(psu_status.get("redundant", False))

    # Extract PSUs and line voltage / output watts
    psus: List[Dict[str, Any]] = []
    volts: Optional[float] = None

    # Inspect raw power supplies if available
    raw_psus = []
    if raw_power and isinstance(raw_power, dict):
        raw_psus = raw_power.get("PowerSupplies", [])
    elif hasattr(collector, "_get") and chassis_uri:
        p_doc = collector._get(f"{chassis_uri.rstrip('/')}/Power") or {}
        if isinstance(p_doc, dict):
            raw_psus = p_doc.get("PowerSupplies", [])

    psu_base_list = psu_status.get("psus", [])
    if psu_base_list:
        for idx, p in enumerate(psu_base_list):
            raw_match = raw_psus[idx] if idx < len(raw_psus) and isinstance(raw_psus[idx], dict) else {}
            line_v = raw_match.get("LineInputVoltage")
            out_w = raw_match.get("LastPowerOutputWatts") or raw_match.get("PowerOutputWatts")
            try:
                line_v_num = float(line_v) if line_v is not None else None
            except (ValueError, TypeError):
                line_v_num = None
            try:
                out_w_num = float(out_w) if out_w is not None else None
            except (ValueError, TypeError):
                out_w_num = None

            if volts is None and line_v_num is not None:
                volts = line_v_num

            psus.append({
                "name": p.get("name", f"PSU{idx+1}"),
                "model": p.get("model", "Unknown"),
                "wattage": p.get("wattage"),
                "output_watts": out_w_num if out_w_num is not None else p.get("wattage"),
                "input_voltage": line_v_num,
                "health": p.get("health", "Unknown"),
                "state": p.get("state", "Unknown"),
            })
    elif raw_psus:
        for idx, rp in enumerate(raw_psus):
            if not isinstance(rp, dict):
                continue
            status = rp.get("Status") or {}
            line_v = rp.get("LineInputVoltage")
            out_w = rp.get("LastPowerOutputWatts") or rp.get("PowerOutputWatts")
            try:
                line_v_num = float(line_v) if line_v is not None else None
            except (ValueError, TypeError):
                line_v_num = None
            try:
                out_w_num = float(out_w) if out_w is not None else None
            except (ValueError, TypeError):
                out_w_num = None

            if volts is None and line_v_num is not None:
                volts = line_v_num

            psus.append({
                "name": rp.get("Name", f"PSU{idx+1}"),
                "model": rp.get("Model") or rp.get("PartNumber", "Unknown"),
                "wattage": rp.get("PowerCapacityWatts"),
                "output_watts": out_w_num if out_w_num is not None else rp.get("PowerCapacityWatts"),
                "input_voltage": line_v_num,
                "health": status.get("Health", "Unknown"),
                "state": status.get("State", "Unknown"),
            })

    # Extract thermal readings and fan faults
    sensors = thermal_status.get("sensors") or []
    fan_faults = thermal_status.get("fan_faults") or []

    if not sensors and raw_thermal:
        for t in raw_thermal.get("Temperatures", []):
            if isinstance(t, dict):
                sensors.append({
                    "name": t.get("Name", "Sensor"),
                    "reading": t.get("ReadingCelsius"),
                    "health": (t.get("Status") or {}).get("Health", "OK"),
                })
        for f in raw_thermal.get("Fans", []):
            if isinstance(f, dict):
                f_h = (f.get("Status") or {}).get("Health", "OK")
                f_rpm = f.get("Reading") if f.get("Reading") is not None else f.get("ReadingRPM")
                if f_h not in ("OK", "Ok") or (f_rpm is not None and f_rpm == 0):
                    fan_faults.append(f)

    valid_temps: List[float] = []
    for s in sensors:
        r_val = s.get("reading")
        if isinstance(r_val, str):
            r_val = r_val.replace("°C", "").replace("C", "").strip()
        u_temp = usable_temperature(r_val)
        if u_temp is not None:
            valid_temps.append(u_temp)

    thermal_max_celsius = max(valid_temps) if valid_temps else None
    fan_fault_count = len(fan_faults)

    # Resolve overall health
    out_of_spec = thermal_status.get("out_of_spec", False)
    if out_of_spec or fan_fault_count > 0:
        overall_health = "Warning"
    else:
        overall_health = "OK"

    return {
        "power_watts": consumed_watts,
        "watts": consumed_watts,
        "power_peak_watts": power_peak_watts,
        "thermal_max_celsius": thermal_max_celsius,
        "thermal_max": thermal_max_celsius,
        "fan_fault_count": fan_fault_count,
        "fan_faults": fan_fault_count,
        "power_redundant": redundant,
        "redundant": redundant,
        "energy_kwh": energy_kwh,
        "volts": volts,
        "input_voltage": volts,
        "health": overall_health,
        "psus": psus,
    }


def collect_ops_component_health(
    collector: Any,
    drive_uris: Optional[List[str]] = None,
    port_uris: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Fetch health, temperature, failure prediction, and link status for drives and ports.

    Does not rediscover topology; queries only the specified URIs.
    """
    drive_uris = drive_uris or []
    port_uris = port_uris or []

    drives: Dict[str, Dict[str, Any]] = {}
    ports: Dict[str, Dict[str, Any]] = {}

    get_fn = getattr(collector, "_get", None)

    for d_uri in drive_uris:
        if not d_uri or not isinstance(d_uri, str):
            continue
        raw = get_fn(d_uri) if get_fn else {}
        if isinstance(raw, dict) and not raw.get("error"):
            status = raw.get("Status") or {}
            raw_health = status.get("Health") or status.get("HealthRollup") or "OK"
            raw_state = status.get("State") or "Enabled"

            oem = raw.get("Oem") or {}
            dell_oem = oem.get("Dell") or {}
            if isinstance(dell_oem, dict):
                dell_disk = dell_oem.get("DellPhysicalDisk") or {}
            else:
                dell_disk = {}

            pred_fail = bool(
                raw.get("FailurePredicted")
                or raw_health in ("Critical", "Warning")
                or dell_oem.get("PredictiveFailure")
                or dell_disk.get("PredictiveFailure")
            )

            raw_temp = (
                raw.get("TemperatureCelsius")
                or raw.get("CurrentTemperatureCelsius")
                or (raw.get("Metrics") or {}).get("TemperatureCelsius")
            )
            thresh = raw.get("Thresholds") or {}
            raw_max = (
                (thresh.get("UpperCritical") or {}).get("Reading")
                if isinstance(thresh.get("UpperCritical"), dict)
                else thresh.get("UpperCritical")
            ) or 0
            temp_c = usable_temperature(raw_temp, raw_max)

            drives[d_uri] = {
                "uri": d_uri,
                "health": str(raw_health),
                "health_status": str(raw_health),
                "state": str(raw_state),
                "failure_predicted": pred_fail,
                "temperature_celsius": temp_c,
            }

    for p_uri in port_uris:
        if not p_uri or not isinstance(p_uri, str):
            continue
        raw = get_fn(p_uri) if get_fn else {}
        if isinstance(raw, dict) and not raw.get("error"):
            status = raw.get("Status") or {}
            raw_health = status.get("Health") or status.get("HealthRollup") or "OK"
            raw_state = status.get("State") or "Enabled"
            link_raw = raw.get("LinkStatus") or raw.get("LinkState") or ""
            link_status = str(link_raw).strip() if link_raw else "Unknown"

            ports[p_uri] = {
                "uri": p_uri,
                "link_status": link_status,
                "health": str(raw_health),
                "state": str(raw_state),
            }

    res: Dict[str, Any] = {
        "drives": drives,
        "ports": ports,
    }
    # Provide direct URI key access as well for flexible caller retrieval
    res.update(drives)
    res.update(ports)
    return res
