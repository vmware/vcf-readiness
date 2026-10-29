"""Reserve synchronous fleet changes against scans and other artifact writers."""

from functools import wraps
from typing import Any, Callable

from vcf_hci.web.scan_worker import _state, _state_lock


def exclusive_fleet_change(function: Callable[..., Any]) -> Callable[..., Any]:
    """Reserve before reading state; scan launchers must set running before return.

    The state lock protects acquisition only. Keeping the reservation during IO
    avoids blocking progress/SSE readers while preventing stale artifact writes.
    """
    @wraps(function)
    def reserved(self: Any, *args: Any, **kwargs: Any) -> Any:
        operation = str(getattr(function, "__name__", "fleet update"))
        with _state_lock:
            if _state.get("running") or _state.get("_fleet_worker_active") or _state.get("_fleet_operation"):
                self._send_json({"error": "Scan already running" if _state.get("running") else "Wait for the current scan/import or fleet update to finish"}, 409)
                return None
            _state["_fleet_operation"] = operation
        try:
            return function(self, *args, **kwargs)
        finally:
            with _state_lock:
                if _state.get("_fleet_operation") == operation:
                    _state.pop("_fleet_operation", None)
    return reserved


def fleet_worker(function: Callable[..., Any]) -> Callable[..., Any]:
    """Release a launcher's worker reservation only when its thread has exited."""
    @wraps(function)
    def finished(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        finally:
            with _state_lock:
                _state.pop("_fleet_worker_active", None)
    return finished
