"""Emit the Redfish Explorer only when a raw capture is on the host dict."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any, Dict, Optional


def explorer_allowed(data: Optional[Dict[str, Any]]) -> bool:
    return bool(data and data.get("_explorer_written"))


def try_write_explorer(data: Dict[str, Any], output_filepath: str) -> bool:
    """Write redfish_explorer_<ip>.html beside the host report when a capture exists."""
    if data.get("_explorer_written"):
        return True
    data["_explorer_written"] = False
    capture = data.get("raw_redfish_capture")
    if not capture or not output_filepath:
        return False
    tool = Path(__file__).resolve().parents[2] / "tools" / "generate_redfish_explorer.py"
    if not tool.is_file():
        return False
    spec = importlib.util.spec_from_file_location("generate_redfish_explorer", tool)
    if spec is None or spec.loader is None:
        return False
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ip = str((data.get("system") or {}).get("ip") or "").strip() or "host"
    dest = os.path.join(os.path.dirname(os.path.abspath(output_filepath)), f"redfish_explorer_{ip}.html")
    module.generate_redfish_explorer_html(data, dest)
    data["_explorer_written"] = True
    return True
