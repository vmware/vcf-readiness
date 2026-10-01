"""
VCF Readiness Tool — power supply and thermal collection mixin.
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
        def oem_psu_capacity(self, psu_json: dict) -> Optional[int]: ...
else:
    _CollectorBase = object

logger = logging.getLogger("vcf_assess")


# Power cap sentinel values: 0, 32767 (0x7FFF / INT16_MAX), 65535 (0xFFFF / UINT16_MAX).
# Enterprise BMCs (e.g. Dell iDRAC, HPE iLO, Supermicro) return these when power capping is disabled or unconfigured.
# In rackmount enterprise servers, power limits exceeding 30,000 W are also non-physical sentinel values.
_POWER_CAP_SENTINEL_VALUES = {0, 32767, 65535}
_POWER_CAP_MAX_REALISTIC_WATTS = 30000


def _safe_num(val, cast=float):
    """Coerce Redfish numeric values that some BMCs (Cisco CIMC) return as
    strings ("11.900", "745") or sentinel text ("N/A"). Returns None on failure."""
    if val is None or isinstance(val, bool):
        return None
    if isinstance(val, (int, float)):
        try:
            return cast(val)
        except (ValueError, TypeError):
            return None
    if isinstance(val, str):
        s = val.strip()
        if not s or s.upper() in ("N/A", "NA", "NONE", "NULL", "UNKNOWN"):
            return None
        try:
            return cast(float(s))
        except (ValueError, TypeError):
            return None
    return None


class _PowerMixin(_CollectorBase):
    """Collection methods: PSUs, thermal sensors."""

    def collect_psu_status(self) -> dict:
        """Check power supply unit count, redundancy, capacity, and current draw."""
        result = {
            "psus": [], "redundant": False, "summary": "Unknown",
            "badge": "<span class='badge warning'>⚠️ PSU Status Unknown</span>",
            "consumed_watts": None, "total_capacity_watts": None,
            "power_metrics": {},
        }
        if not self.chassis_uri:
            return result
        power_data = self._get(f"{self.chassis_uri}/Power") or {}
        if isinstance(power_data, dict) and power_data.get("error"):
            power_data = {}

        psu_raw_list = power_data.get("PowerSupplies", [])
        power_control_list = power_data.get("PowerControl", [])
        if isinstance(power_control_list, dict):
            power_control_list = [power_control_list]  # Cisco CIMC returns a singular object

        # ── Fallback to Redfish 2020.4+ PowerSubsystem if legacy Power supplies empty ──
        if not psu_raw_list:
            subsys = self._get(f"{self.chassis_uri}/PowerSubsystem") or {}
            if isinstance(subsys, dict) and not subsys.get("error"):
                psu_link = subsys.get("PowerSupplies")
                if isinstance(psu_link, dict) and psu_link.get("@odata.id"):
                    psu_members = self._get_members(psu_link.get("@odata.id"))
                    for m in psu_members:
                        if isinstance(m, dict):
                            m_uri = m.get("@odata.id")
                            if m_uri:
                                psu_item = self._get(m_uri) or {}
                                if psu_item and not psu_item.get("error"):
                                    psu_raw_list.append(psu_item)
                            elif m.get("Name"):
                                psu_raw_list.append(m)
                elif isinstance(psu_link, list):
                    for p_entry in psu_link:
                        if isinstance(p_entry, dict):
                            p_uri = p_entry.get("@odata.id")
                            if p_uri:
                                psu_item = self._get(p_uri) or {}
                                if psu_item and not psu_item.get("error"):
                                    psu_raw_list.append(psu_item)
                            else:
                                psu_raw_list.append(p_entry)

        # ── Per-PSU data ────────────────────────────────────────────────────────
        for psu in psu_raw_list:
            if not isinstance(psu, dict):
                continue
            status = psu.get("Status")
            if not isinstance(status, dict):
                status = {}
            raw_health = status.get("Health") or status.get("health")
            raw_state = status.get("State") or status.get("state")
            health_str = str(raw_health) if raw_health is not None else "Unknown"
            state_str = str(raw_state) if raw_state is not None else "Unknown"

            wattage_val = _safe_num(psu.get("PowerCapacityWatts"), int)
            if wattage_val is None:
                wattage_val = _safe_num(psu.get("LastPowerOutputWatts"), int)
            if wattage_val is None and hasattr(self, "oem_psu_capacity"):
                try:
                    wattage_val = self.oem_psu_capacity(psu)
                except Exception:
                    pass
            result["psus"].append({
                "name":    psu.get("Name", "PSU"),
                "model":   psu.get("Model") or psu.get("PartNumber", "Unknown"),
                "wattage": wattage_val if wattage_val is not None else "N/A",
                "health":  health_str,
                "state":   state_str,
            })

        # ── System-level power consumption (PowerControl[] or EnvironmentMetrics) ─────
        power_limit_watts = None
        power_limit_enforced = False
        consumed_energy_kwh = None
        power_allocated_watts = None

        for pc in power_control_list:
            if not isinstance(pc, dict):
                continue
            consumed = pc.get("PowerConsumedWatts")
            if consumed is not None:
                c_val = _safe_num(consumed, int)
                if c_val is not None:
                    result["consumed_watts"] = c_val

            p_limit = pc.get("PowerLimit") or {}
            if isinstance(p_limit, dict) and p_limit.get("LimitInWatts") is not None:
                p_lim_val = _safe_num(p_limit.get("LimitInWatts"), int)
                if (
                    p_lim_val is not None
                    and p_lim_val > 0
                    and p_lim_val not in _POWER_CAP_SENTINEL_VALUES
                    and p_lim_val < _POWER_CAP_MAX_REALISTIC_WATTS
                ):
                    power_limit_watts = p_lim_val
                    power_limit_enforced = True

            p_alloc = pc.get("PowerAllocatedWatts")
            if p_alloc is not None:
                p_alloc_val = _safe_num(p_alloc, int)
                if p_alloc_val is not None:
                    power_allocated_watts = p_alloc_val

            p_kwh = pc.get("ConsumedIntervalEnergykWh") or pc.get("EnergykWh")
            if p_kwh is not None:
                p_kwh_val = _safe_num(p_kwh, float)
                if p_kwh_val is not None:
                    consumed_energy_kwh = round(p_kwh_val, 2)

            metrics = pc.get("PowerMetrics") or pc.get("PowerMetric") or {}
            if metrics:
                result["power_metrics"] = {
                    "min_w":  _safe_num(metrics.get("MinConsumedWatts"), int),
                    "max_w":  _safe_num(metrics.get("MaxConsumedWatts"), int),
                    "avg_w":  _safe_num(metrics.get("AverageConsumedWatts"), int),
                    "interval_min": _safe_num(metrics.get("IntervalInMin"), float),
                }
            # Take only the first populated entry
            if result["consumed_watts"] is not None:
                break

        # Fallback power consumption & energy metrics from EnvironmentMetrics
        if result["consumed_watts"] is None or consumed_energy_kwh is None:
            env_metrics = self._get(f"{self.chassis_uri}/EnvironmentMetrics") or {}
            if isinstance(env_metrics, dict) and not env_metrics.get("error"):
                pw = env_metrics.get("PowerWatts")
                if isinstance(pw, dict) and result["consumed_watts"] is None:
                    reading = pw.get("Reading") or pw.get("AverageConsumedWatts")
                    c_val = _safe_num(reading, int)
                    if c_val is not None:
                        result["consumed_watts"] = c_val
                    if not result["power_metrics"]:
                        result["power_metrics"] = {
                            "min_w": _safe_num(pw.get("MinConsumedWatts"), int),
                            "max_w": _safe_num(pw.get("MaxConsumedWatts"), int),
                            "avg_w": _safe_num(pw.get("AverageConsumedWatts"), int),
                            "interval_min": _safe_num(pw.get("IntervalInMin"), float),
                        }
                elif isinstance(pw, (int, float, str)) and result["consumed_watts"] is None:
                    c_val = _safe_num(pw, int)
                    if c_val is not None:
                        result["consumed_watts"] = c_val

                ek = env_metrics.get("EnergykWh")
                if consumed_energy_kwh is None:
                    if isinstance(ek, dict) and ek.get("Reading") is not None:
                        ek_val = _safe_num(ek.get("Reading"), float)
                        if ek_val is not None:
                            consumed_energy_kwh = round(ek_val, 2)
                    elif isinstance(ek, (int, float, str)):
                        ek_val = _safe_num(ek, float)
                        if ek_val is not None:
                            consumed_energy_kwh = round(ek_val, 2)
                    if isinstance(ek, dict) and ek.get("Reading") is not None:
                        try:
                            consumed_energy_kwh = round(float(ek["Reading"]), 2)
                        except (ValueError, TypeError):
                            pass
                    elif isinstance(ek, (int, float)):
                        consumed_energy_kwh = round(float(ek), 2)

        if power_limit_enforced and power_limit_watts:
            result["power_cap_badge"] = f"<span class='badge warning'>⚠️ Power Cap Enforced ({power_limit_watts} W) — Potential Throttle Risk</span>"
        else:
            result["power_cap_badge"] = "<span class='badge success'>🟢 Power Cap: Unlimited (Uncapped)</span>"

        result["power_limit_watts"] = power_limit_watts
        result["power_limit_enforced"] = power_limit_enforced
        result["consumed_energy_kwh"] = consumed_energy_kwh
        result["power_allocated_watts"] = power_allocated_watts

        # ── Aggregate installed PSU capacity ────────────────────────────────────
        cap_list = [
            p["wattage"] for p in result["psus"]
            if isinstance(p["wattage"], (int, float)) and p["wattage"] > 0
        ]
        if cap_list:
            result["total_capacity_watts"] = int(sum(cap_list))

        # ── Redundancy badge ────────────────────────────────────────────────────
        psu_count = len(result["psus"])
        redundancy = power_data.get("Redundancy", [])
        healthy = sum(1 for p in result["psus"] if p["health"] in ("OK", "Ok"))

        # Explicit Redfish Redundancy group → definitive
        explicit_redundant = bool(redundancy) and psu_count >= 2

        # Inferred: ≥2 healthy PSUs and draw fits within a single PSU's capacity.
        # Many BMCs (Dell iDRAC, Supermicro) never populate the Redundancy array
        # even in a true 1+1 config.  If we can see 2+ PSUs, assume N+1 redundancy
        # unless the draw actually exceeds what one PSU can handle.
        inferred_redundant = False
        if not explicit_redundant and psu_count >= 2 and healthy >= 2:
            cap   = result["total_capacity_watts"]      # total installed watts
            draw  = result["consumed_watts"]             # current draw or None
            per_psu = (cap / psu_count) if cap and psu_count else 0
            if draw is None or cap == 0:
                # No load or capacity data — 2+ healthy PSUs present, assume redundant
                inferred_redundant = True
            elif per_psu > 0 and draw < per_psu:
                # Current draw fits within a single PSU → N+1 redundant
                inferred_redundant = True

        result["redundant"] = explicit_redundant or inferred_redundant

        cap_str   = f" · {result['total_capacity_watts']} W total" if result["total_capacity_watts"] else ""
        draw_str  = f" · Draw: {result['consumed_watts']} W" if result["consumed_watts"] is not None else ""
        watt_note = f"{cap_str}{draw_str}"

        # Build a per-PSU detail line for the card summary (helps SEs spot the faulted unit)
        _psu_lines = []
        for _p in result["psus"]:
            _h = _p.get("health", "Unknown")
            _icon = "🟢" if _h in ("OK", "Ok") else ("🔴" if _h in ("Critical", "Warning") else "⚠️")
            _w_str = f" {_p['wattage']}W" if isinstance(_p.get("wattage"), (int, float)) else ""
            _psu_lines.append(f"{_icon} {_p.get('name','PSU')}: {_p.get('model','Unknown')}{_w_str} ({_h})")
        _psu_detail = " &nbsp;|&nbsp; ".join(_psu_lines)

        if healthy == 0 and psu_count > 0:
            result["badge"]   = (
                f"<span class='badge danger'>🔴 All PSUs Faulted / Critical "
                f"(0 of {psu_count} PSUs healthy)</span>"
            )
            result["summary"] = f"All {psu_count} PSUs faulted — verify cabling and power input{watt_note}"
            if _psu_detail:
                result["summary"] += f"<br><small style='color:var(--text-muted)'>{_psu_detail}</small>"
        elif psu_count >= 2 and healthy < 2:
            faulted = psu_count - healthy
            result["badge"]   = (
                f"<span class='badge danger'>🔴 PSU Fault — Redundancy Lost "
                f"({healthy} of {psu_count} PSUs healthy)</span>"
            )
            result["summary"] = f"{faulted} PSU fault(s) — verify cabling and replace faulted unit{watt_note}"
            if _psu_detail:
                result["summary"] += f"<br><small style='color:var(--text-muted)'>{_psu_detail}</small>"
        elif psu_count >= 2 and healthy < psu_count:
            faulted = psu_count - healthy
            result["badge"]   = (
                f"<span class='badge warning'>🟡 PSU Degraded "
                f"({healthy} of {psu_count} PSUs healthy)</span>"
            )
            result["summary"] = f"{faulted} degraded PSU(s) — redundancy degraded{watt_note}"
            if _psu_detail:
                result["summary"] += f"<br><small style='color:var(--text-muted)'>{_psu_detail}</small>"
        elif result["redundant"]:
            _redun_label = "Redundant" if explicit_redundant else "Redundant (inferred)"
            result["badge"]   = f"<span class='badge success'>🟢 {_redun_label} ({psu_count}× PSUs, {healthy} healthy)</span>"
            result["summary"] = f"{psu_count}× redundant PSUs{watt_note}"
            if _psu_detail:
                result["summary"] += f"<br><small style='color:var(--text-muted)'>{_psu_detail}</small>"
        elif psu_count == 1:
            result["badge"]   = "<span class='badge warning'>🟡 Single PSU (No Redundancy)</span>"
            result["summary"] = f"Single PSU — no redundancy{watt_note}"
            if _psu_detail:
                result["summary"] += f"<br><small style='color:var(--text-muted)'>{_psu_detail}</small>"
        elif psu_count == 0:
            result["badge"]   = "<span class='badge info'>ℹ️ PSU data unavailable</span>"
            result["summary"] = "PSU data not available"
        else:
            # healthy >= 2 but draw exceeds per-PSU capacity — N+1 failover would be insufficient
            _cap_val = result.get("total_capacity_watts")
            _cap = float(_cap_val) if isinstance(_cap_val, (int, float)) else 0.0
            _draw_val = result.get("consumed_watts")
            _draw = float(_draw_val) if isinstance(_draw_val, (int, float)) else 0.0
            _per_psu_w = int(_cap / psu_count) if _cap and psu_count else 0
            result["badge"] = (
                f"<span class='badge warning'>🟡 High Load — N+1 Failover at Risk "
                f"({psu_count}× PSUs · Draw: {int(_draw)} W ≥ {_per_psu_w} W/PSU capacity)</span>"
            )
            result["summary"] = f"{psu_count}× PSUs — load may exceed single-PSU headroom{watt_note}"
            if _psu_detail:
                result["summary"] += f"<br><small style='color:var(--text-muted)'>{_psu_detail}</small>"
        return result


    def collect_thermal_telemetry(self) -> dict:
        empty = {"out_of_spec": False, "overall_status_badge": "<span class='badge warning'>⚠️ Thermal Unknown</span>", "key_sensor": None, "sensors": [], "fan_faults": []}
        if not self.chassis_uri:
            return empty
        thermal = self._get(f"{self.chassis_uri}/Thermal") or {}
        if isinstance(thermal, dict) and thermal.get("error"):
            thermal = {}

        temperatures_raw = thermal.get("Temperatures", [])
        fans_raw = thermal.get("Fans", [])

        # ── Fallback to Redfish 2020.4+ ThermalSubsystem if legacy Thermal empty ────
        if not temperatures_raw and not fans_raw and not getattr(self, "lean_mode", False):
            tsub = self._get(f"{self.chassis_uri}/ThermalSubsystem") or {}
            if isinstance(tsub, dict) and not tsub.get("error"):
                # Fetch Fans
                fans_ref = tsub.get("Fans")
                if isinstance(fans_ref, dict) and fans_ref.get("@odata.id"):
                    fans_uri = fans_ref.get("@odata.id")
                    fetch_expand_fn = getattr(self, "_fetch_expanded_collection", None)
                    if callable(fetch_expand_fn) and getattr(self, "expand_supported", False):
                        fans_coll = fetch_expand_fn(fans_uri)
                        fan_members = self._get_members(fans_coll) if fans_coll else []
                    else:
                        fan_members = self._get_members(fans_uri)
                    for fm in fan_members:
                        if isinstance(fm, dict):
                            if fm.get("Name") and len(fm) > 2:
                                fans_raw.append(fm)
                            else:
                                f_uri = fm.get("@odata.id")
                                if f_uri:
                                    if hasattr(self, "_request_cache") and f_uri in self._request_cache:
                                        f_item = self._request_cache[f_uri]
                                    else:
                                        f_item = self._get(f_uri) or {}
                                    if f_item and not f_item.get("error"):
                                        fans_raw.append(f_item)
                                elif fm.get("Name"):
                                    fans_raw.append(fm)
                elif isinstance(fans_ref, list):
                    for f_entry in fans_ref:
                        if isinstance(f_entry, dict):
                            f_uri = f_entry.get("@odata.id")
                            if f_uri:
                                f_item = self._get(f_uri) or {}
                                if f_item and not f_item.get("error"):
                                    fans_raw.append(f_item)
                            else:
                                fans_raw.append(f_entry)

                # Fetch Temperatures / Sensors
                temps_ref = tsub.get("Temperatures") or tsub.get("ThermalMetrics")
                if isinstance(temps_ref, dict) and temps_ref.get("@odata.id"):
                    t_members = self._get_members(temps_ref.get("@odata.id"))
                    for tm in t_members:
                        if isinstance(tm, dict):
                            t_uri = tm.get("@odata.id")
                            if t_uri:
                                t_item = self._get(t_uri) or {}
                                if t_item and not t_item.get("error"):
                                    temperatures_raw.append(t_item)
                            elif tm.get("Name"):
                                temperatures_raw.append(tm)
                elif isinstance(temps_ref, list):
                    for t_entry in temps_ref:
                        if isinstance(t_entry, dict):
                            t_uri = t_entry.get("@odata.id")
                            if t_uri:
                                t_item = self._get(t_uri) or {}
                                if t_item and not t_item.get("error"):
                                    temperatures_raw.append(t_item)
                            else:
                                temperatures_raw.append(t_entry)

            # Check Sensors collection at Chassis level if still no temperatures
            if not temperatures_raw:
                sensors_coll = self._get(f"{self.chassis_uri}/Sensors") or {}
                if isinstance(sensors_coll, dict) and not sensors_coll.get("error"):
                    sensor_members = self._get_members(sensors_coll)
                    for sm in sensor_members:
                        if isinstance(sm, dict):
                            s_uri = sm.get("@odata.id")
                            if s_uri:
                                s_item = self._get(s_uri) or {}
                                if s_item and not s_item.get("error"):
                                    stype = str(s_item.get("ReadingType") or s_item.get("SensorType") or "").lower()
                                    if "temperature" in stype or s_item.get("ReadingCelsius") is not None:
                                        temperatures_raw.append(s_item)

            # Check EnvironmentMetrics for ambient temperature if still empty
            if not temperatures_raw:
                env_metrics = self._get(f"{self.chassis_uri}/EnvironmentMetrics") or {}
                if isinstance(env_metrics, dict) and not env_metrics.get("error"):
                    tc = env_metrics.get("TemperatureCelsius")
                    if isinstance(tc, dict) and tc.get("Reading") is not None:
                        temperatures_raw.append({
                            "Name": tc.get("Name", "Ambient Temperature"),
                            "ReadingCelsius": tc.get("Reading"),
                            "Status": {"Health": "OK", "State": "Enabled"},
                        })
                    elif isinstance(tc, (int, float)):
                        temperatures_raw.append({
                            "Name": "Ambient Temperature",
                            "ReadingCelsius": tc,
                            "Status": {"Health": "OK", "State": "Enabled"},
                        })

        sensors, out_of_spec, key_sensor = [], False, None
        _KEY_PRIORITY = 99  # current best priority (lower wins)

        def _sensor_priority(sname: str) -> int:
            n = sname.lower()
            if any(k in n for k in ("exhaust", "outlet")):
                return 1
            if "cpu" in n or "processor" in n:
                return 2
            if any(k in n for k in ("inlet", "front ambient", "ambient")):
                return 3
            return 10  # any sensor with a warn threshold

        for t in temperatures_raw:
            if not isinstance(t, dict):
                continue
            t_state = (t.get("Status") or {}).get("State") or "Enabled"
            if t_state in ("Absent", "Disabled"):
                continue
            name = t.get("Name", "Thermal Sensor")
            raw_reading = t.get("ReadingCelsius") if t.get("ReadingCelsius") is not None else t.get("Reading")
            health = (t.get("Status") or {}).get("Health", "OK")
            thresh = t.get("Thresholds") or {}
            raw_warn = (
                t.get("UpperThresholdNonCritical")
                or (thresh.get("UpperCaution") or {}).get("Reading")
                or (thresh.get("UpperNonCritical") or {}).get("Reading")
            )
            raw_crit = (
                t.get("UpperThresholdCritical")
                or (thresh.get("UpperCritical") or {}).get("Reading")
            )
            reading_num = _safe_num(raw_reading, float)
            warn_num = _safe_num(raw_warn, float)
            crit_num = _safe_num(raw_crit, float)

            # Consider sensor as key candidate when it has warn OR crit threshold
            _has_thresh = bool(warn_num is not None or crit_num is not None)
            if _has_thresh:
                _prio = _sensor_priority(name)
                if _prio < _KEY_PRIORITY or key_sensor is None:
                    _KEY_PRIORITY = _prio
                    key_sensor = {
                        "name": name,
                        "reading": f"{reading_num} °C" if reading_num is not None else "N/A",
                        "threshold_warn": f"{warn_num} °C" if warn_num is not None else "N/A",
                        "threshold_crit": f"{crit_num} °C" if crit_num is not None else "N/A",
                    }
            if health not in ["OK", "Ok"] or (crit_num is not None and reading_num is not None and reading_num >= crit_num):
                flag = "<span class='badge danger'>🔴 Critical Out of Spec</span>"
                out_of_spec = True
            elif warn_num is not None and reading_num is not None and reading_num >= warn_num:
                flag = "<span class='badge warning'>🟡 Warning High Temp</span>"
                out_of_spec = True
            else:
                flag = "<span class='badge success'>🟢 In Spec</span>"
            sensors.append({
                "name": name,
                "reading": f"{reading_num} °C" if reading_num is not None else "N/A",
                "threshold_warn": f"{warn_num} °C" if warn_num is not None else "N/A",
                "threshold_crit": f"{crit_num} °C" if crit_num is not None else "N/A",
                "status_flag": flag,
            })

        # Parse Fans[]
        fan_faults = []
        for fan in fans_raw:
            if not isinstance(fan, dict):
                continue
            fan_health = (fan.get("Status") or {}).get("Health", "OK")
            fan_state = (fan.get("Status") or {}).get("State", "Enabled")
            raw_rpm = fan.get("Reading") if fan.get("Reading") is not None else fan.get("ReadingRPM")
            if raw_rpm is None:
                raw_rpm = fan.get("SpeedRPM")
            rpm_num = _safe_num(raw_rpm, int)
            fan_name = fan.get("Name") or fan.get("MemberId", "Fan")
            if fan_state not in ("Enabled", ""):
                continue
            if fan_health not in ("OK", "Ok") or (rpm_num is not None and rpm_num == 0):
                fan_faults.append({
                    "name": fan_name,
                    "reading_rpm": rpm_num if rpm_num is not None else "N/A",
                    "health": fan_health,
                })
        return {
            "out_of_spec": out_of_spec,
            "overall_status_badge": "<span class='badge danger'>🔴 Thermal Warning</span>" if out_of_spec else "<span class='badge success'>🟢 All Sensors In Spec</span>",
            "key_sensor": key_sensor,
            "sensors": sensors,
            "fan_faults": fan_faults,
        }

