"""Bounded follow of Drive.Metrics and Memory.Metrics links, plus chassis sensors.

Link follows run only for full (non-quick) profiles, reuse the collector cache,
and stop at a hard per-host request cap. Missing or denied metrics degrade to
an empty payload. Chassis sensor normalization is a separate member-capped walk.
"""

from typing import Any, Dict, List, Optional

METRICS_LINK_CAP = 24
SENSOR_MEMBER_CAP = 32

_SENSOR_KINDS = (
    ("intrusion", ("intrusion", "physicalsecurity")),
    ("temperature", ("temperature", "temp")),
    ("fan", ("fan", "rotational")),
    ("voltage", ("voltage", "volt")),
)


class MetricsLinkBudget:
    """Counts Metrics link GETs for one host. Cache hits do not consume it."""

    def __init__(self, cap: int = METRICS_LINK_CAP) -> None:
        self.cap = int(cap)
        self.used = 0

    @property
    def exhausted(self) -> bool:
        return self.used >= self.cap


def metrics_are_inline(value: Any) -> bool:
    """True when Metrics already carries readings and is not only an odata link."""
    if not isinstance(value, dict):
        return False
    return any(not str(key).startswith("@odata") for key in value)


def metrics_link(value: Any) -> str:
    if isinstance(value, str):
        text = value.strip()
        return text if text.startswith("/") else ""
    if isinstance(value, dict) and not metrics_are_inline(value):
        link = value.get("@odata.id")
        if isinstance(link, str) and link.strip().startswith("/"):
            return link.strip()
    return ""


def resolve_metrics_link(collector: Any, raw: Any) -> Dict[str, Any]:
    """Return inline metrics, or follow one link when the profile and cap allow it."""
    if metrics_are_inline(raw):
        return dict(raw)
    if collector is None or not getattr(collector, "_metrics_follow_enabled", False):
        return {}
    link = metrics_link(raw)
    if not link:
        return {}
    cache = getattr(collector, "_request_cache", None)
    if isinstance(cache, dict) and isinstance(cache.get(link), dict):
        cached = cache[link]
        if cached.get("error"):
            return {}
        return dict(cached)
    budget = getattr(collector, "_metrics_link_budget", None)
    if not isinstance(budget, MetricsLinkBudget):
        budget = MetricsLinkBudget()
        try:
            collector._metrics_link_budget = budget
        except Exception:
            return {}
    if budget.exhausted:
        return {}
    budget.used += 1
    try:
        fetched = collector._get(link, critical=False)
    except Exception:
        return {}
    if not isinstance(fetched, dict) or fetched.get("error"):
        return {}
    if isinstance(cache, dict):
        cache[link] = fetched
    return dict(fetched)


def sensor_kind(payload: Dict[str, Any]) -> str:
    reading_type = str(payload.get("ReadingType") or payload.get("SensorType") or "").lower()
    name = str(payload.get("Name") or "").lower()
    blob = f"{reading_type} {name}"
    for kind, tokens in _SENSOR_KINDS:
        if any(token in blob for token in tokens):
            return kind
    return ""


def normalize_sensor(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return None
    kind = sensor_kind(payload)
    if not kind:
        return None
    status = payload.get("Status") if isinstance(payload.get("Status"), dict) else {}
    health = status.get("Health")
    reading = payload.get("Reading")
    if reading is None:
        reading = payload.get("ReadingCelsius")
    return {
        "name": str(payload.get("Name") or payload.get("Id") or kind).strip(),
        "kind": kind,
        "reading": reading,
        "units": str(payload.get("ReadingUnits") or "").strip(),
        "health": str(health).strip() if health not in (None, "") else "",
        "state": str(status.get("State") or "").strip(),
    }


def fetch_chassis_sensors(collector: Any, cap: int = SENSOR_MEMBER_CAP) -> List[Dict[str, Any]]:
    """Normalize temperature, fan, voltage, and intrusion sensors with a member cap."""
    chassis_uri = getattr(collector, "chassis_uri", None)
    if not chassis_uri or collector is None:
        return []
    collection_uri = f"{chassis_uri}/Sensors"
    try:
        page = collector._get(collection_uri, critical=False)
    except Exception:
        return []
    if not isinstance(page, dict) or page.get("error"):
        return []
    try:
        members = collector._get_members(page)
    except Exception:
        members = page.get("Members") if isinstance(page.get("Members"), list) else []
    normalized: List[Dict[str, Any]] = []
    seen = 0
    for member in members or []:
        if seen >= cap:
            break
        seen += 1
        payload = member if isinstance(member, dict) else {}
        link = ""
        if isinstance(member, dict) and not metrics_are_inline(member):
            link = metrics_link(member)
        elif isinstance(member, str):
            link = member if member.startswith("/") else ""
        if link:
            try:
                fetched = collector._get(link, critical=False)
            except Exception:
                continue
            payload = fetched if isinstance(fetched, dict) else {}
        record = normalize_sensor(payload)
        if record:
            normalized.append(record)
    return normalized
