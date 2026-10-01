"""Read BMC credentials from stdin for a remote collector process.

The JSON document is::

    {"targets": ["192.0.2.10"], "creds": {"192.0.2.10": ["root", "secret"], "default": ["root", "secret"]}}

Passwords never appear in argv. This module does not write them to disk.
"""

import json
from typing import BinaryIO, Dict, List, Tuple, Union

__all__ = ["dump_creds_document", "load_creds_document"]

CredsMap = Dict[str, Tuple[str, str]]


def dump_creds_document(creds: Union[CredsMap, Dict[str, List[str]], tuple], targets: List[str]) -> bytes:
    """Serialize credentials for ``--creds-stdin``. Tuple creds become the default pair."""
    payload_creds: Dict[str, List[str]] = {}
    if isinstance(creds, tuple):
        if len(creds) != 2:
            raise ValueError("credential tuple must be (username, password)")
        payload_creds["default"] = [str(creds[0]), str(creds[1])]
    elif isinstance(creds, dict):
        for key, value in creds.items():
            if not isinstance(key, str) or not key:
                raise ValueError("credential key must be a non-empty string")
            if isinstance(value, (list, tuple)) and len(value) == 2:
                payload_creds[key] = [str(value[0]), str(value[1])]
            else:
                raise ValueError("credential value for %s must be (username, password)" % key)
    else:
        raise ValueError("creds must be a dict or a (username, password) tuple")
    clean_targets = [str(item) for item in targets if str(item)]
    body = {"targets": clean_targets, "creds": payload_creds}
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def load_creds_document(source: Union[BinaryIO, bytes, str]) -> Dict[str, object]:
    """Parse a creds document. Returns ``{"creds": {host: (user, password)}, "targets": [...]}``."""
    if hasattr(source, "read"):
        raw = source.read()
    else:
        raw = source
    if isinstance(raw, str):
        text = raw
    else:
        try:
            text = raw.decode("utf-8")
        except Exception:
            raise ValueError("credential stdin is not UTF-8") from None
    if not text.strip():
        raise ValueError("credential stdin is empty")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        raise ValueError("credential stdin is not JSON") from None
    if not isinstance(data, dict):
        raise ValueError("credential document must be a JSON object")
    raw_creds = data.get("creds")
    if not isinstance(raw_creds, dict) or not raw_creds:
        raise ValueError("credential document needs a non-empty creds object")
    creds: CredsMap = {}
    for key, value in raw_creds.items():
        if not isinstance(key, str) or not key or any(ch.isspace() for ch in key):
            raise ValueError("invalid credential target")
        if not isinstance(value, (list, tuple)) or len(value) != 2:
            raise ValueError("credential entry must be [username, password]")
        username = value[0] if isinstance(value[0], str) else ""
        password = value[1] if isinstance(value[1], str) else ""
        if not username or password == "":
            raise ValueError("credential entry is missing a username or password")
        creds[key] = (username, password)
    targets: List[str] = []
    raw_targets = data.get("targets")
    if raw_targets is None:
        targets = [key for key in creds if key != "default"]
    elif isinstance(raw_targets, list):
        for item in raw_targets:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("targets must be strings")
            targets.append(item.strip())
    else:
        raise ValueError("targets must be a list")
    return {"creds": creds, "targets": targets}
