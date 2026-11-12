"""Typed service accounts stored inside the existing encrypted vault payload."""

import re
import uuid
from typing import Any, Dict, List
from urllib.parse import urlsplit

SERVICE_KINDS = ("vcenter", "operations")


def normalize_service(raw: Dict[str, Any]) -> Dict[str, str]:
    kind = raw.get("kind")
    if kind not in SERVICE_KINDS:
        raise ValueError("Choose vCenter or VCF Operations.")
    result = {}
    for key, limit in (("label", 120), ("endpoint", 2048), ("username", 256), ("password", 4096), ("auth_source", 256)):
        value = raw.get(key, "")
        if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
            raise ValueError("Invalid service credential field.")
        result[key] = value if key == "password" else value.strip()
    if not all(result[k] for k in ("label", "endpoint", "username", "password")):
        raise ValueError("Enter an instance name, endpoint, username and password.")
    url = urlsplit(result["endpoint"] if "://" in result["endpoint"] else "https://" + result["endpoint"])
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username is not None
        or url.password is not None
        or url.query
        or url.fragment
        or url.path.rstrip("/") not in ("", "/ui", "/suite-api", "/suite-api/api")
    ):
        raise ValueError("Enter an HTTPS instance hostname or URL without embedded credentials.")
    host = url.hostname.encode("idna").decode("ascii").lower()
    if not re.fullmatch(r"[a-z0-9_.:-]+", host):
        raise ValueError("Invalid instance hostname.")
    port = url.port if url.port is not None else 443
    if not 1 <= port <= 65535:
        raise ValueError("Invalid HTTPS port.")
    host = "[" + host + "]" if ":" in host else host
    result["endpoint"] = "https://" + host + (":" + str(port) if port != 443 else "")
    entry_id = raw.get("id") or uuid.uuid4().hex
    if not isinstance(entry_id, str) or not re.fullmatch(r"[a-f0-9]{32}", entry_id):
        raise ValueError("Invalid service credential ID.")
    result.update(id=entry_id, kind=kind)
    if kind != "operations":
        result["auth_source"] = ""
    return result


class ServiceCredentialStore:
    """Separate service identity from BMC exact/subnet/default credential matching."""

    _service_credentials: Dict[str, Dict[str, str]]

    def _require_unlocked(self) -> None:
        raise NotImplementedError

    def set_service_credential(self, raw: Dict[str, Any]) -> str:
        self._require_unlocked()
        record = normalize_service(raw)
        self._service_credentials[record["id"]] = record
        return record["id"]

    def list_service_credentials(self) -> List[Dict[str, str]]:
        self._require_unlocked()
        return [
            {k: v for k, v in row.items() if k != "password"}
            for row in sorted(
                self._service_credentials.values(), key=lambda r: (r["kind"], r["label"].lower(), r["id"])
            )
        ]

    def get_service_credential(self, entry_id: str, kind: str) -> Dict[str, str]:
        self._require_unlocked()
        record = self._service_credentials.get(entry_id)
        if record is None or record["kind"] != kind:
            raise ValueError("Saved credentials are unavailable for this source. Select an instance again.")
        return dict(record)

    def remove_service_credential(self, entry_id: str) -> bool:
        self._require_unlocked()
        return self._service_credentials.pop(entry_id, None) is not None
