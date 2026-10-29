"""Processor acquisition and pure physical CPU/cache normalization."""
import re
from typing import Any, Dict, Iterator, Optional, Tuple

from vcf_hci.collector.contracts import SystemCollector
from vcf_hci.logging_utils import get_nested

_CPU_SUMMARY_PLACEHOLDERS = frozenset({
    "",
    "n/a",
    "na",
    "none",
    "unknown",
    "available for assignment",
    "not available",
    "not specified",
    "null",
})


KNOWN_XEON_E5_E7_CORES: Dict[str, Tuple[int, int]] = {
    # Xeon E5 v4 (Broadwell-EP) — (cores_per_socket, threads_per_socket)
    "E5-2603 V4": (6, 6),
    "E5-2609 V4": (8, 8),
    "E5-2620 V4": (8, 16),
    "E5-2623 V4": (4, 8),
    "E5-2630 V4": (10, 20),
    "E5-2630L V4": (10, 20),
    "E5-2637 V4": (4, 8),
    "E5-2640 V4": (10, 20),
    "E5-2643 V4": (6, 12),
    "E5-2650 V4": (12, 24),
    "E5-2650L V4": (14, 28),
    "E5-2660 V4": (14, 28),
    "E5-2667 V4": (8, 16),
    "E5-2680 V4": (14, 28),
    "E5-2683 V4": (16, 32),
    "E5-2687W V4": (12, 24),
    "E5-2690 V4": (14, 28),
    "E5-2695 V4": (18, 36),
    "E5-2697 V4": (18, 36),
    "E5-2697A V4": (16, 32),
    "E5-2698 V4": (20, 40),
    "E5-2699 V4": (22, 44),
    "E5-2699A V4": (22, 44),
    "E5-4610 V4": (10, 10),
    "E5-4620 V4": (10, 20),
    "E5-4627 V4": (10, 10),
    "E5-4640 V4": (12, 24),
    "E5-4650 V4": (14, 28),
    "E5-4660 V4": (16, 32),
    "E5-4669 V4": (22, 44),
    # Xeon E5 v3 (Haswell-EP)
    "E5-2603 V3": (6, 6),
    "E5-2609 V3": (6, 6),
    "E5-2620 V3": (6, 12),
    "E5-2623 V3": (4, 8),
    "E5-2630 V3": (8, 16),
    "E5-2630L V3": (8, 16),
    "E5-2637 V3": (4, 8),
    "E5-2640 V3": (8, 16),
    "E5-2643 V3": (6, 12),
    "E5-2650 V3": (10, 20),
    "E5-2650L V3": (12, 24),
    "E5-2660 V3": (10, 20),
    "E5-2667 V3": (8, 16),
    "E5-2670 V3": (12, 24),
    "E5-2680 V3": (12, 24),
    "E5-2683 V3": (14, 28),
    "E5-2687W V3": (10, 20),
    "E5-2690 V3": (12, 24),
    "E5-2695 V3": (14, 28),
    "E5-2697 V3": (14, 28),
    "E5-2698 V3": (16, 32),
    "E5-2699 V3": (18, 36),
    # Xeon E7 v3/v4 (Broadwell/Haswell-EX)
    "E7-4809 V3": (8, 16),
    "E7-4809 V4": (8, 16),
    "E7-4820 V3": (10, 20),
    "E7-4820 V4": (10, 20),
    "E7-4830 V3": (12, 24),
    "E7-4830 V4": (14, 28),
    "E7-4850 V3": (14, 28),
    "E7-4850 V4": (16, 32),
    "E7-8860 V3": (16, 32),
    "E7-8860 V4": (18, 36),
    "E7-8870 V3": (18, 36),
    "E7-8870 V4": (20, 40),
    "E7-8880 V3": (18, 36),
    "E7-8880 V4": (22, 44),
    "E7-8890 V3": (18, 36),
    "E7-8890 V4": (24, 48),
}


def _normalize_cpu_summary_model(raw: Optional[Any]) -> str:
    """Map BMC placeholder ProcessorSummary.Model strings to Unknown.

    AMI MegaRAC / some RackScale implementations send
    'Available for assignment' instead of a CPU name.
    """
    s = str(raw or "").strip()
    if not s or s.lower() in _CPU_SUMMARY_PLACEHOLDERS:
        return "Unknown"
    return s


def lookup_xeon_e5_e7_cores(model: str) -> Optional[Tuple[int, int]]:
    """Look up (cores_per_socket, threads_per_socket) for known Xeon E5/E7 v3/v4 CPUs."""
    if not model:
        return None
    m_clean = re.sub(r"\s+", " ", model.upper()).strip()
    for k, v in KNOWN_XEON_E5_E7_CORES.items():
        if k in m_clean:
            return v
    match = re.search(r"\b(E[57]-\d{4}[A-Z]?(?:\s*L)?)\s*(V[34])\b", m_clean)
    if match:
        key = f"{match.group(1)} {match.group(2)}"
        if key in KNOWN_XEON_E5_E7_CORES:
            return KNOWN_XEON_E5_E7_CORES[key]
    return None


def lookup_cpu_memory_channels(cpu_model: str) -> int:
    """Determine native memory channels per socket based on CPU architecture."""
    if not cpu_model:
        return 8
    s = str(cpu_model).upper()

    # 1. Embedded & Microserver CPUs (2 or 4 channels)
    if re.search(r"\b(V1\d{3}|V2\d{3}|V3\d{3}|R1\d{3}|V1500B|V1807B|V3C64|R1606G)\b", s) or "RYZEN EMBEDDED" in s:
        return 2
    if re.search(r"\bEPYC\s*3\d{3}\b|\b(3101|3201|3251|3301|3401|3451)\b", s) or "EPYC EMBEDDED 3" in s:
        return 4
    if re.search(r"\bXEON\s+D[-\s]?(17|27|28|18)\d\d", s) or re.search(r"\bD-(17|27|28|18)\d\d", s) or "ICE LAKE-D" in s:
        return 4
    if re.search(r"\bXEON\s+D[-\s]?(15|16|21)\d\d", s) or re.search(r"\bD-(15|16|21)\d\d", s) or "BROADWELL-DE" in s:
        return 2
    if re.search(r"\bE3-1\d{3}", s) or re.search(r"\bXEON\s+E[-\s]?2[123]\d\d", s):
        return 2
    if any(k in s for k in ["DENVERTON", "SNOW RIDGE"]) or re.search(r"\bATOM\b|\bC3[3579]\d\d\b|\bP59?\d\d\b", s):
        return 2

    # 2. 12-channel platforms (AMD Turin/Genoa/Bergamo, Intel Xeon 6 6900)
    if re.search(r"EPYC\s*9\d\d[45]|TURIN|GENOA|BERGAMOT|BERGAMO", s) or any(k in s for k in ["9004", "9005"]):
        return 12
    if re.search(r"\b69\d\d[PE]\b", s) or re.search(r"\bXEON\s*6\s*69\d\d\b", s) or any(k in s for k in ["6900P", "6900E", "XEON 6900", "GRANITE RAPIDS-AP"]):
        return 12

    # 3. 6-channel platforms (AMD Siena, Intel Cooper Lake, Cascade Lake, Skylake-SP)
    if re.search(r"EPYC\s*8\d\d4|SIENA", s) or "8004" in s:
        return 6
    if re.search(r"\b[345689]2\d\d[+UYTRLSM]*\b", s) or "CASCADE" in s or "CASCADE LAKE" in s:
        return 6
    if re.search(r"\b[34568]1\d\d[+TFMP]*\b", s) or "SKYLAKE" in s:
        return 6
    if re.search(r"\b[568]3\d\dH\b", s) or "COOPER LAKE" in s:
        return 6

    # 4. 8-channel platforms (AMD Milan/Rome/Naples, Intel Xeon 6 6700/6500, Emerald, Sapphire, Ice Lake-SP)
    if re.search(r"EPYC\s*7\d\d[123]|ROME|MILAN|NAPLES", s) or any(k in s for k in ["7001", "7002", "7003"]):
        return 8
    if re.search(r"\b6[57]\d\d[PE]\b", s) or re.search(r"\bXEON\s*6\s*6[57]\d\d\b", s) or any(k in s for k in ["6700P", "6700E", "6500P", "6500E", "XEON 6700", "XEON 6500", "GRANITE RAPIDS", "SIERRA FOREST"]):
        return 8
    if "EMERALD RAPIDS" in s or "EMERALD" in s or re.search(r"\b[34568]5\d\d[+VNYPUQFLS]*\b", s):
        return 8
    if any(k in s for k in ["SAPPHIRE RAPIDS", "SAPPHIRE"]) or re.search(r"\b[34568]4\d\d[+HMNPUVYQS]*\b", s):
        return 8
    if any(k in s for k in ["ICE LAKE"]) or re.search(r"\b[34568]3\d\d[+NSTUYPVQ]*\b", s):
        return 8

    # 5. 4-channel platforms (Pre-Skylake Xeon E5/E7 v1-v4)
    if any(k in s for k in ["HASWELL", "BROADWELL", " V3 ", " V4 ", "E5-", "E7-"]):
        return 4

    # 6. Consumer fallbacks
    if re.search(r"\b(CORE|CELERON|PENTIUM|RYZEN|ATHLON)\b", s):
        return 2

    return 8


def processor_summary_seed(data: dict) -> tuple:
    """Capture summary values before processor acquisition/OEM cache hooks."""
    proc_summary = data.get("ProcessorSummary") or {}
    cpu_model = _normalize_cpu_summary_model(proc_summary.get("Model"))
    if cpu_model == "Unknown" and isinstance(data.get("Processors"), dict):
        p_fam = data["Processors"].get("ProcessorFamily") or data["Processors"].get("Model")
        if p_fam:
            cpu_model = _normalize_cpu_summary_model(p_fam)
    cpu_count = proc_summary.get("Count") or (data.get("Processors", {}).get("Count") if isinstance(data.get("Processors"), dict) else None) or 1
    channels_per_socket = lookup_cpu_memory_channels(cpu_model)

    return cpu_model, cpu_count, channels_per_socket, proc_summary.get("CoreCount"), proc_summary.get("LogicalProcessorCount")


def normalize_processor(proc: dict) -> dict:
    """Decode one CPU observation before invoking its optional cache hook."""
    p_model = str(proc.get("Model") or "").strip()
    p_max_speed = proc.get("MaxSpeedMHz")
    p_op_speed = (
        proc.get("OperatingSpeedMHz")
        or get_nested(proc, "Oem", "Lenovo", "CurrentClockSpeedMHz")
        or get_nested(proc, "Oem", "Dell", "DellProcessor", "CurrentClockSpeedMhz")
        or get_nested(proc, "Oem", "Hpe", "CurrentSpeedMHz")
    )
    p_cores = proc.get("TotalCores")
    p_threads = proc.get("TotalThreads")
    p_socket = str(proc.get("Socket", "") or "").strip()
    p_status = proc.get("Status") or {}
    p_state = str(p_status.get("State", "") or "").strip()
    p_health = str(p_status.get("Health", "") or "").strip()

    # ProcessorId — VCG/BCG CPU search helper + microcode revision
    _pid = proc.get("ProcessorId", {}) or {}
    _id_reg = _pid.get("IdentificationRegisters", "")
    _eff_fam = _pid.get("EffectiveFamily", "")
    _eff_mod = _pid.get("EffectiveModel", "")
    _step    = _pid.get("Step", "")
    _ucode   = _pid.get("MicrocodeInfo")
    p_microcode = None
    if _ucode is not None and str(_ucode).strip() not in ("", "None", "null", "N/A"):
        p_microcode = str(_ucode).strip()
        if p_microcode.isdigit() or (
            p_microcode.lower().startswith("0x") is False and re.fullmatch(r"[0-9A-Fa-f]+", p_microcode)
        ):
            # Normalize bare hex / int to 0x-prefixed form when numeric.
            try:
                p_microcode = hex(int(_ucode)) if isinstance(_ucode, int) else (
                    hex(int(p_microcode, 16)) if re.fullmatch(r"[0-9A-Fa-f]+", p_microcode) else p_microcode
                )
            except (TypeError, ValueError):
                pass
    # Supermicro OEM fallback on processor object
    if not p_microcode:
        _smc_proc = ((proc.get("Oem") or {}).get("Supermicro") or {})
        if isinstance(_smc_proc, dict):
            _alt = _smc_proc.get("MicrocodeVersion") or _smc_proc.get("MicrocodeInfo")
            if _alt is not None and str(_alt).strip():
                p_microcode = str(_alt).strip()
    p_proc_id_str = None
    if _id_reg:
        p_proc_id_str = _id_reg.strip()
    elif _eff_fam or _eff_mod:
        _parts = []
        if _eff_fam:
            _parts.append(f"Fam {_eff_fam}")
        if _eff_mod:
            _parts.append(f"Mod {_eff_mod}")
        if _step:
            _parts.append(f"Step {_step}")
        p_proc_id_str = " · ".join(_parts)

    return {'socket': p_socket, 'model': p_model, 'cores': p_cores, 'threads': p_threads, 'max_speed_mhz': p_max_speed, 'operating_speed_mhz': p_op_speed, 'health': p_health, 'state': p_state, 'processor_id': p_proc_id_str, 'microcode': p_microcode}


def normalize_processor_cache(_cache_raw: Any) -> list:
    """Normalize already-acquired cache evidence without losing zero sizes."""
    p_cache_list = []
    for _c in _cache_raw:
        if not isinstance(_c, dict):
            continue
        _raw_kb = _c.get("CacheSize") or _c.get("MaximumSizeKB") or 0
        try:
            _raw_kb = int(_raw_kb)
        except (TypeError, ValueError):
            _raw_kb = 0
        _size_mib = (
            _c.get("CacheSizeMiB")
            or _c.get("MaxCacheSizeMiB")
            or (round(_raw_kb / 1024, 2) if _raw_kb else 0)
        )
        try:
            _size_mib = float(_size_mib or 0)
            if _size_mib.is_integer():
                _size_mib = int(_size_mib)
        except (TypeError, ValueError):
            _size_mib = 0
        p_cache_list.append({
            "level": str(_c.get("CacheMemoryType") or _c.get("Name") or _c.get("Level") or "").strip(),
            "size_mib": _size_mib,
            "associativity": str(_c.get("Associativity") or "").strip(),
        })

    return p_cache_list


def collect_processor_evidence(self: SystemCollector) -> Iterator[Optional[dict]]:
    """Yield CPU records; None signals a GPU at its original discovery point."""
    if self.sys_uri:
        members = self._get_members(f"{self.sys_uri}/Processors")
        for _m in members:
            _mid = str(_m.get("@odata.id", ""))
            if re.search(r'/Video\.|/Accelerator\.|/GPU\.|\.GPU\.|\.Video\.', _mid, re.I):
                yield None
                continue
            proc = self._get(_mid) or {}
            if not proc:
                continue
            _ptype = str(proc.get("ProcessorType") or "").upper()
            if _ptype and _ptype not in ("CPU", "DSP", "OEM", ""):
                if _ptype in ("GPU", "ACCELERATOR"):
                    yield None
                continue

            record = normalize_processor(proc)
            cache = proc.get("Cache") or self.oem_cpu_cache(proc) or []
            record["cache_list"] = normalize_processor_cache(cache)
            yield record


def normalize_processor_summary(
    cpu_model: str, cpu_count: Any, channels_per_socket: int, total_cores: Any,
    total_threads: Any, processors_list: list, has_collection: bool,
) -> dict:
    """Summarize physical sockets using the existing count/frequency/asymmetry rules."""
    cpu_verdict, arch_label = "", ""
    max_ram_speed_mhz, max_pcie_lanes_per_socket = None, 0
    # ── Per-socket CPU specs from Processors collection ─────────────────────
    max_speed_mhz = None
    operating_speed_mhz = None
    per_socket_cores = None
    per_socket_threads = None
    processor_id_str = None
    cache_list: list = []
    socket_label: str = ""
    asymmetry_detected = False
    asymmetry_note = None

    if has_collection:
        populated_procs = [
            p for p in processors_list
            if p.get("state", "").lower() != "absent" and (p.get("model") or p.get("cores") is not None)
        ]
        first_proc = populated_procs[0] if populated_procs else (processors_list[0] if processors_list else None)

        if first_proc:
            _fp_model = first_proc["model"]
            if _fp_model and _fp_model != cpu_model:
                if (
                    cpu_model == "Unknown"
                    or re.search(r"\bprocessor\b", cpu_model, re.I)
                    or len(_fp_model) > len(cpu_model)
                ):
                    cpu_model = _fp_model
            channels_per_socket = lookup_cpu_memory_channels(cpu_model)

            max_speed_mhz       = first_proc["max_speed_mhz"]
            operating_speed_mhz = first_proc["operating_speed_mhz"]
            per_socket_cores    = first_proc["cores"]
            per_socket_threads  = first_proc["threads"]
            socket_label        = first_proc["socket"]
            processor_id_str    = first_proc["processor_id"]
            cache_list          = first_proc["cache_list"]

        # If some sockets are absent and populated_procs reflects the actual installed CPUs,
        # align cpu_count to the populated count.
        if populated_procs and len(populated_procs) < (cpu_count or 1):
            cpu_count = len(populated_procs)

        if len(populated_procs) > 1:
            models_set = {p["model"].lower() for p in populated_procs if p.get("model")}
            cores_set = {p["cores"] for p in populated_procs if p.get("cores") is not None}
            max_speeds_set = {p["max_speed_mhz"] for p in populated_procs if p.get("max_speed_mhz") is not None}
            op_speeds_set = {p["operating_speed_mhz"] for p in populated_procs if p.get("operating_speed_mhz") is not None}
            states_set = {p["state"].lower() for p in populated_procs if p.get("state")}

            if (
                len(models_set) > 1
                or len(cores_set) > 1
                or len(max_speeds_set) > 1
                or len(op_speeds_set) > 1
                or ("disabled" in states_set)
            ):
                asymmetry_detected = True
                asymmetry_note = "CPU socket asymmetry detected: mismatched processor model, core count, speed, or socket state."
                if "Asymmetry" not in cpu_verdict:
                    cpu_verdict += " (⚠️ Socket Asymmetry Detected)"

    # Prefer per-socket values from Processors; fall back to dividing summary totals
    _safe_count = max(cpu_count or 1, 1)
    if not total_cores and not per_socket_cores:
        known_cores = lookup_xeon_e5_e7_cores(cpu_model)
        if known_cores:
            per_socket_cores, per_socket_threads = known_cores
            total_cores = per_socket_cores * _safe_count
            total_threads = per_socket_threads * _safe_count

    if not total_cores and per_socket_cores:
        total_cores = per_socket_cores * _safe_count
    if not total_threads and per_socket_threads:
        total_threads = per_socket_threads * _safe_count

    cores_ps   = per_socket_cores   or (total_cores   // _safe_count if total_cores   else None)
    threads_ps = per_socket_threads or (total_threads // _safe_count if total_threads else None)
    ht_enabled = (threads_ps // cores_ps >= 2) if (cores_ps and threads_ps) else None

    # Base frequency: prefer string in model name, then OperatingSpeedMHz
    _freq_m = re.search(r'@\s*([\d.]+)\s*GHz', cpu_model, re.I)
    base_freq_ghz = float(_freq_m.group(1)) if _freq_m else (
        round(operating_speed_mhz / 1000, 2) if operating_speed_mhz else None
    )
    max_freq_ghz = round(max_speed_mhz / 1000, 2) if max_speed_mhz else None

    return {'count': cpu_count, 'core_count': total_cores if total_cores is not None else 0, 'logical_count': total_threads if total_threads is not None else 0, 'cores_per_socket': cores_ps if cores_ps is not None else 0, 'threads_per_socket': threads_ps if threads_ps is not None else 0, 'ht_enabled': ht_enabled, 'base_freq_ghz': base_freq_ghz, 'max_freq_ghz': max_freq_ghz, 'model': cpu_model, 'architecture': arch_label, 'channels_per_socket': channels_per_socket, 'max_ram_speed_mhz': max_ram_speed_mhz, 'max_pcie_lanes_per_socket': max_pcie_lanes_per_socket, 'verdict': cpu_verdict, 'processor_id': processor_id_str, 'cache_list': cache_list, 'socket_label': socket_label, 'processors': processors_list, 'asymmetry_detected': asymmetry_detected, 'asymmetry_note': asymmetry_note}
