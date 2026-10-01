"""NDJSON progress lines on stdout for a collector started with --progress-ndjson."""

import json
import sys
from typing import Any, Callable, Dict

__all__ = ["emit_progress", "ndjson_scan_callbacks"]


def emit_progress(event: str, payload: Dict[str, Any]) -> None:
    body = {"event": event}
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key == "event":
                continue
            body[key] = value
    sys.stdout.write(json.dumps(body, separators=(",", ":"), default=str) + "\n")
    sys.stdout.flush()


def ndjson_scan_callbacks() -> Dict[str, Callable]:
    """Callbacks accepted by scan_hosts. Human text stays off stdout."""

    def log_callback(event: str, msg: str) -> None:
        emit_progress("log", {"channel": event, "msg": msg})

    def host_start_callback(info: dict) -> None:
        emit_progress("host_start", info if isinstance(info, dict) else {"info": info})

    def host_stage_callback(info: dict) -> None:
        emit_progress("host_stage", info if isinstance(info, dict) else {"info": info})

    def host_done_callback(info: dict) -> None:
        emit_progress("host_done", info if isinstance(info, dict) else {"info": info})

    def progress_callback(completed: int, total: int) -> None:
        emit_progress("progress", {"completed": completed, "total": total})

    return {
        "log_callback": log_callback,
        "host_start_callback": host_start_callback,
        "host_stage_callback": host_stage_callback,
        "host_done_callback": host_done_callback,
        "progress_callback": progress_callback,
    }
