"""
VCF Readiness Tool — Dynamic System Resource Monitor and Auto-Stepdown Controller.

Monitors CPU load average and available system RAM using Python standard library only
(no external dependencies like psutil). Dynamically throttles outer fleet concurrency
when system saturation or memory pressure is detected.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from typing import Any, Dict, Tuple

logger = logging.getLogger("vcf_assess")

# Default resource thresholds
DEFAULT_LOAD_FACTOR_STEPDOWN = 1.5   # 1-min loadavg > 1.5x CPU cores triggers stepdown
DEFAULT_LOAD_FACTOR_RECOVERY = 1.0   # 1-min loadavg < 1.0x CPU cores allows recovery
DEFAULT_MIN_RAM_AVAIL_PCT = 10.0     # < 10% available RAM triggers stepdown
DEFAULT_RECOVERY_RAM_AVAIL_PCT = 20.0 # > 20% available RAM allows recovery
MINIMUM_CONCURRENCY_FLOOR = 2


def get_system_cpu_load() -> Tuple[float, int]:
    """Return (1-minute load average, logical CPU count) using stdlib.

    Returns:
        Tuple of (load_1m, cpu_count).
    """
    cpu_cores = os.cpu_count() or 4
    if hasattr(os, "getloadavg"):
        try:
            load_1m, _, _ = os.getloadavg()
            return float(load_1m), cpu_cores
        except (OSError, AttributeError):
            pass
    return 0.0, cpu_cores


def get_system_ram_metrics() -> Dict[str, float]:
    """Return available and total RAM metrics in bytes and percentage.

    Returns:
        Dict with keys: 'total_bytes', 'available_bytes', 'available_pct'.
    """
    total_b = 0.0
    avail_b = 0.0

    # Linux /proc/meminfo inspection
    if sys.platform.startswith("linux") and os.path.exists("/proc/meminfo"):
        try:
            mem_info: Dict[str, float] = {}
            with open("/proc/meminfo", encoding="utf-8") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        k = parts[0].strip()
                        v_str = parts[1].strip().split()[0]
                        try:
                            mem_info[k] = float(v_str) * 1024.0  # kB to bytes
                        except ValueError:
                            pass
            total_b = mem_info.get("MemTotal", 0.0)
            avail_b = mem_info.get("MemAvailable", mem_info.get("MemFree", 0.0) + mem_info.get("Buffers", 0.0) + mem_info.get("Cached", 0.0))
        except Exception as exc:
            logger.debug(f"Failed parsing /proc/meminfo: {exc}")

    # Fallback for macOS / BSD
    if total_b <= 0.0 and hasattr(os, "sysconf"):
        try:
            page_size = float(os.sysconf("SC_PAGE_SIZE"))
            phys_pages = float(os.sysconf("SC_PHYS_PAGES"))
            total_b = page_size * phys_pages
            # Assume 50% available on non-Linux if detailed kernel counters unavailable
            avail_b = total_b * 0.5
        except (ValueError, OSError, AttributeError):
            pass

    # Generic fallback
    if total_b <= 0.0:
        total_b = 8.0 * (1024.0**3)  # Assume 8GB
        avail_b = 4.0 * (1024.0**3)

    avail_pct = (avail_b / total_b * 100.0) if total_b > 0.0 else 50.0
    return {
        "total_bytes": total_b,
        "available_bytes": avail_b,
        "available_pct": round(avail_pct, 1),
    }


class SystemThrottleMonitor:
    """Monitors system load and dynamically controls active concurrency permits.

    Guarantees that a 96-thread outer fleet scan automatically steps down
    concurrency by 25% if host CPU load or memory pressure spikes, and
    re-expands when the system normalizes.
    """

    def __init__(
        self,
        initial_threads: int = 16,
        max_threads: int = 96,
        auto_throttle: bool = True,
        load_stepdown_factor: float = DEFAULT_LOAD_FACTOR_STEPDOWN,
        load_recovery_factor: float = DEFAULT_LOAD_FACTOR_RECOVERY,
        min_ram_pct: float = DEFAULT_MIN_RAM_AVAIL_PCT,
        recovery_ram_pct: float = DEFAULT_RECOVERY_RAM_AVAIL_PCT,
        stepdown_cooldown_sec: float = 30.0,
    ):
        self.max_threads = max(MINIMUM_CONCURRENCY_FLOOR, max_threads)
        self.current_threads = min(max(MINIMUM_CONCURRENCY_FLOOR, initial_threads), self.max_threads)
        self.initial_threads = self.current_threads
        self.auto_throttle = auto_throttle
        self.load_stepdown_factor = load_stepdown_factor
        self.load_recovery_factor = load_recovery_factor
        self.min_ram_pct = min_ram_pct
        self.recovery_ram_pct = recovery_ram_pct
        self.stepdown_cooldown_sec = stepdown_cooldown_sec

        self._lock = threading.Lock()
        self._last_check_time = 0.0
        self._last_stepdown_time = 0.0
        self._check_interval_sec = 3.0
        self._stepdown_count = 0
        self._recovery_count = 0
        self._throttle_active = False
        self._throttle_reason = ""

    def check_and_adjust_concurrency(self) -> int:
        """Evaluate system load and adjust current thread target.

        Returns:
            Effective adjusted thread count.
        """
        if not self.auto_throttle:
            return self.current_threads

        now = time.time()
        with self._lock:
            if (now - self._last_check_time) < self._check_interval_sec:
                return self.current_threads
            self._last_check_time = now

            load_1m, cpu_cores = get_system_cpu_load()
            ram_info = get_system_ram_metrics()
            avail_ram_pct = ram_info.get("available_pct", 50.0)

            high_load_threshold = cpu_cores * self.load_stepdown_factor
            recovery_load_threshold = cpu_cores * self.load_recovery_factor

            # Trigger Step-Down (enforce cooldown to prevent cascading drops on 1m smoothed load)
            if (
                (load_1m > high_load_threshold or avail_ram_pct < self.min_ram_pct)
                and self.current_threads > MINIMUM_CONCURRENCY_FLOOR
                and (now - self._last_stepdown_time) >= self.stepdown_cooldown_sec
            ):
                new_threads = max(MINIMUM_CONCURRENCY_FLOOR, int(self.current_threads * 0.75))
                if new_threads < self.current_threads:
                    reason = []
                    if load_1m > high_load_threshold:
                        reason.append(f"CPU loadavg {load_1m:.2f} > {high_load_threshold:.1f}")
                    if avail_ram_pct < self.min_ram_pct:
                        reason.append(f"Avail RAM {avail_ram_pct:.1f}% < {self.min_ram_pct:.1f}%")
                    self._throttle_reason = " & ".join(reason)
                    self._throttle_active = True
                    self._stepdown_count += 1
                    self._last_stepdown_time = now
                    logger.warning(
                        f"[⚡ Auto-Stepdown] System contention detected ({self._throttle_reason}). "
                        f"Reducing outer concurrency: {self.current_threads} -> {new_threads} threads."
                    )
                    self.current_threads = new_threads

            # Trigger Recovery
            elif (
                load_1m < recovery_load_threshold
                and avail_ram_pct > self.recovery_ram_pct
                and self.current_threads < self.initial_threads
            ):
                new_threads = min(self.initial_threads, int(self.current_threads * 1.25) + 1)
                if new_threads > self.current_threads:
                    self._recovery_count += 1
                    logger.info(
                        f"[⚡ Auto-Stepup] System resources normalized (Load: {load_1m:.2f}, RAM: {avail_ram_pct:.1f}%). "
                        f"Restoring outer concurrency: {self.current_threads} -> {new_threads} threads."
                    )
                    self.current_threads = new_threads
                    if self.current_threads >= self.initial_threads:
                        self._throttle_active = False
                        self._throttle_reason = ""

            return self.current_threads

    def get_status(self) -> Dict[str, Any]:
        """Return diagnostic metrics snapshot."""
        with self._lock:
            load_1m, cpu_cores = get_system_cpu_load()
            ram_info = get_system_ram_metrics()
            return {
                "current_threads": self.current_threads,
                "initial_threads": self.initial_threads,
                "max_threads": self.max_threads,
                "throttle_active": self._throttle_active,
                "throttle_reason": self._throttle_reason,
                "stepdown_count": self._stepdown_count,
                "recovery_count": self._recovery_count,
                "cpu_load_1m": load_1m,
                "cpu_cores": cpu_cores,
                "available_ram_pct": ram_info.get("available_pct", 50.0),
            }
