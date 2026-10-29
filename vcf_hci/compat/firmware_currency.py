"""Currency comparison for BIOS and BMC catalogs.

A version newer than the local snapshot stays healthy. An older version is
described by age when the catalog records a release date and the host reports one.
ROM and controller family codes are compared on their own so a new family is not
scored against a retired one.
"""
import re
from datetime import date
from typing import Any, Dict, Optional, Tuple

_HUU_RE = re.compile(r"(\d+)\.(\d+)\((\d+)\.(\d+)\)")
_CISCO_BIOS_RE = re.compile(
    r"([BC]\d+M\d+[A-Z]?)\.(\d+)\.(\d+)\.(\d+)([a-z]*)"
    r"(?:\.(\d+)\.(\d{10}))?", re.IGNORECASE,
)
_HPE_RE = re.compile(
    r"(?<![A-Z])([A-Z]\d{2})\s*v?\s*(\d+(?:\.\d+)+)",
    re.IGNORECASE,
)
_LENOVO_RE = re.compile(
    r"(?<![A-Z])([A-Z]{3})\d*[A-Z]*-(\d+(?:\.\d+)+)",
    re.IGNORECASE,
)
_LENOVO_BUILD_RE = re.compile(
    r"^([A-Z]{3})(\d{3})([A-Z]*)$",
    re.IGNORECASE,
)
_X_BMC_RE = re.compile(r"^X(\d+(?:\.\d+)+)", re.IGNORECASE)
_DOTTED_RE = re.compile(r"\d+(?:\.\d+)+")
_DATE_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
_GEN_RE = {gen: re.compile(rf"(?<![A-Z0-9]){gen}(?![A-Z0-9])") for gen in ("17G", "16G", "15G", "14G", "13G")}

# Longer tokens first is unnecessary for generation (R760XA and R760 are the same
# generation) but (?!\d) keeps R640 from swallowing R6415.
_DELL_MODEL_GEN = (
    ("R7725", "17G"), ("R7715", "17G"), ("R6725", "17G"), ("R6715", "17G"),
    ("R770", "17G"), ("R670", "17G"),
    ("R7625", "16G"), ("R760", "16G"), ("R6625", "16G"), ("R660", "16G"), ("R960", "16G"),
    ("R7525", "15G"), ("R750", "15G"), ("R6525", "15G"), ("R650", "15G"),
    ("R550", "15G"), ("R450", "15G"),
    ("R7425", "14G"), ("R7415", "14G"), ("R740", "14G"),
    ("R6415", "14G"), ("R640", "14G"), ("R940", "14G"), ("R540", "14G"), ("R440", "14G"),
    ("T640", "14G"), ("C6420", "14G"), ("FC640", "14G"), ("M640", "14G"), ("C4140", "14G"),
)


def match_baseline(table: Dict[str, Any], text: str) -> Tuple[Optional[str], Optional[dict]]:
    """Return the longest catalog key contained in text."""
    hay = str(text or "").upper()
    best_key = None
    best_len = -1
    for key, value in table.items():
        if key and key in hay and len(key) > best_len:
            best_key = key
            best_len = len(key)
    if best_key is None:
        return None, None
    return best_key, table[best_key]


def _nums(dotted: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in str(dotted).split(".") if part.isdigit() or part.isdecimal())


def parse_version(value: str) -> Tuple[Optional[str], Tuple[int, ...], str]:
    """Return (family, numeric components, kind).

    kind is ``huu``, ``cisco_bios``, ``x_bmc``, ``family``, or ``dotted``.
    """
    text = str(value or "").strip()
    if not text:
        return None, (), "empty"
    huu = _HUU_RE.search(text)
    if huu:
        return None, tuple(int(g) for g in huu.groups()), "huu"
    cisco = _CISCO_BIOS_RE.search(text)
    if cisco:
        platform, major, minor, patch, suffix, revision, stamp = cisco.groups()
        nums = (int(major), int(minor), int(patch))
        nums += tuple(ord(c) - ord("a") + 1 for c in suffix.lower()) or (0,)
        if stamp:
            # BIOS stamps are MMDDYYHHMM; compare chronologically across years.
            nums += (int(revision), int(stamp[4:6] + stamp[:4] + stamp[6:]))
        return platform.upper(), nums, "cisco_bios"
    x_bmc = _X_BMC_RE.match(text.upper())
    if x_bmc:
        return "X", _nums(x_bmc.group(1)), "x_bmc"
    hpe = _HPE_RE.search(text.upper())
    if hpe:
        return hpe.group(1).upper(), _nums(hpe.group(2)), "family"
    lenovo = _LENOVO_RE.search(text.upper())
    if lenovo:
        return lenovo.group(1).upper(), _nums(lenovo.group(2)), "family"
    lenovo_bld = _LENOVO_BUILD_RE.match(text.upper())
    if lenovo_bld:
        rev_num = int(lenovo_bld.group(2))
        return lenovo_bld.group(1).upper(), (rev_num,), "family"
    dotted = _DOTTED_RE.search(text)
    if dotted:
        nums = _nums(dotted.group(0))
        suffix = re.match(r"([a-z]+)(?:$|\s)", text[dotted.end():], re.IGNORECASE)
        if suffix:
            nums += tuple(ord(c) - ord("a") + 1 for c in suffix.group(1).lower())
        return None, nums, "dotted"
    return None, (), "empty"


def _cmp(left: Tuple[int, ...], right: Tuple[int, ...]) -> int:
    width = max(len(left), len(right), 1)
    a = left + (0,) * (width - len(left))
    b = right + (0,) * (width - len(right))
    return (a > b) - (a < b)


def _parse_date(value: str) -> Optional[date]:
    if not value:
        return None
    match = _DATE_RE.search(str(value))
    if not match:
        return None
    try:
        return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None


def age_note(installed_date: str, released: str, latest: str) -> str:
    """Describe how far an older install sits behind the catalog snapshot."""
    phrase = f"behind catalog latest {latest}"
    installed = _parse_date(installed_date)
    catalog = _parse_date(released)
    if not installed or not catalog or installed >= catalog:
        return phrase
    months = (catalog.year - installed.year) * 12 + (catalog.month - installed.month)
    if catalog.day < installed.day:
        months -= 1
    if months <= 0:
        return phrase
    unit = "month" if months == 1 else "months"
    return f"{months} {unit} behind catalog latest {latest} (released {catalog.isoformat()})"


def _dell_gen(text: str) -> Optional[str]:
    hay = str(text or "").upper()
    for token, gen in _DELL_MODEL_GEN:
        if re.search(rf"(?<![A-Z0-9]){token}(?!\d)", hay):
            return gen
    return None


def _specialize(baseline: dict, firmware: str) -> dict:
    """Pick a firmware-family row when the catalog stores more than one train."""
    families = baseline.get("by_prefix") or {}
    flat = {k: v for k, v in baseline.items() if k != "by_prefix"}
    if not families:
        return flat
    fw = re.sub(r"^[^A-Z0-9]+", "", str(firmware or "").upper())
    best_prefix = ""
    best_row = None
    for prefix, row in families.items():
        token = str(prefix).upper()
        if fw.startswith(token) and len(token) > len(best_prefix):
            best_prefix = token
            best_row = row
    if best_row:
        flat.update(best_row)
        flat.pop("unverified_family", None)
        return flat
    # XCC has no single number. A build id with no CDI/AFBT/ESX prefix is not
    # scored against another generation. Other catalogs keep their default train.
    if baseline.get("prefix_required"):
        flat["unverified_family"] = True
    return flat


def resolve_bmc_baseline(model: str, firmware: str = "", server_model: str = "") -> Tuple[Optional[str], Optional[dict]]:
    """Pick a BMC catalog row, preferring Dell generation over a shared iDRAC9 key."""
    from ..constants import BMC_FW_BASELINES

    bmc_up = str(model or "").upper()
    srv_up = str(server_model or "").upper()
    combined = f"{bmc_up} {srv_up}"

    def _row(key: str):
        base = BMC_FW_BASELINES.get(key)
        if not base:
            return None, None
        return key, _specialize(base, firmware)

    looks_dell = any(token in combined for token in ("IDRAC", "MONOLITHIC", "POWEREDGE", "DELL"))
    if looks_dell and "C4140" in combined:
        found = _row("14G C4140")
        if found[0]:
            return found

    for gen in ("17G", "16G", "15G", "14G", "13G"):
        if _GEN_RE[gen].search(bmc_up):
            return _row(gen)

    if "IDRAC" in bmc_up:
        gen = _dell_gen(srv_up) or _dell_gen(bmc_up)
        if gen == "14G" and "C4140" in combined:
            return _row("14G C4140")
        if gen:
            return _row(gen)

    key, base = match_baseline(BMC_FW_BASELINES, bmc_up)
    if not base:
        return None, None
    return key, _specialize(base, firmware)


def classify_currency(installed: str, baseline: dict, installed_date: str = "") -> dict:
    """Classify installed firmware against one catalog row.

    ``ahead`` and ``current`` are healthy. ``behind`` is a yellow age note.
    ``below_minimum`` is the only failure.
    """
    latest = str(baseline.get("latest") or "")
    minimum = str(baseline.get("min_recommended", latest) or "")
    if baseline.get("unverified_family") or baseline.get("currency_unverified"):
        return {
            "currency": "unverified",
            "age_note": "",
            "latest_version": latest or "N/A",
            "update_recommended": False,
            "is_outdated": False,
        }
    raw = str(installed or "").strip()
    if not raw or raw.upper() in ("N/A", "UNKNOWN", "NONE"):
        return {
            "currency": "unverified",
            "age_note": "",
            "latest_version": latest or "N/A",
            "update_recommended": False,
            "is_outdated": False,
        }
    if raw.upper().replace(" ", "") == latest.upper().replace(" ", ""):
        return _result("current", "", latest)

    inst_fam, inst_nums, inst_kind = parse_version(raw)
    lat_fam, lat_nums, lat_kind = parse_version(latest)
    _min_fam, min_nums, _min_kind = parse_version(minimum)
    note = age_note(installed_date, str(baseline.get("released") or ""), latest)
    if inst_fam in baseline.get("unverified_installed_families", ()):
        return _result("unverified", "Resolve the reported platform/ROM identity before selecting an update", latest)

    # A bare Lenovo build ID and its full build-version form must compare in
    # build space, rather than comparing IVE184 to the semantic version 4.30.
    build_pattern = r"^([A-Z]{3})(\d{3})([A-Z]*)(?:-|$)"
    ib = re.match(build_pattern, raw.upper())
    lb = re.match(build_pattern, latest.upper())
    if ib and lb and ib.group(1) == lb.group(1) and (
        _LENOVO_BUILD_RE.fullmatch(raw) or _LENOVO_BUILD_RE.fullmatch(latest)
    ):
        def build_nums(match):
            return (int(match.group(2)),) + tuple(ord(c) - ord("A") + 1 for c in match.group(3))
        inst_nums, lat_nums = build_nums(ib), build_nums(lb)
        # A catalog floor like IVE186P-3.00 records a semantic floor with a
        # release build prefix. It does not establish the build ID for 3.00.
        mb = _LENOVO_BUILD_RE.fullmatch(minimum.upper())
        min_nums = build_nums(mb) if mb and mb.group(1) == ib.group(1) else ()

    if lat_kind == "cisco_bios" and inst_kind == "huu":
        return _result("unverified", "HUU bundle version is not an installed BIOS component version", latest)
    if inst_kind == lat_kind == "cisco_bios" and inst_fam != lat_fam:
        return _result("unverified", "Cisco BIOS platform does not match the catalog component", latest)

    if inst_kind == "cisco_bios" and lat_kind == "huu" and inst_nums and lat_nums:
        inst_nums = inst_nums[:3]
        train = lat_nums[:3]
        train_cmp = _cmp(inst_nums, train)
        if train_cmp == 0:
            return _result("current", "", latest)
        if train_cmp > 0:
            return _result("ahead", f"ahead of catalog snapshot {latest}", latest)
        if min_nums and _cmp(inst_nums, min_nums[:3] if len(min_nums) > 3 else min_nums) < 0:
            return _result("below_minimum", note, latest)
        return _result("behind", note, latest)

    previous = {str(item).upper() for item in (baseline.get("previous_families") or [])}
    if inst_fam and lat_fam and inst_fam != lat_fam:
        if inst_fam in previous:
            family_note = f"ROM family {inst_fam}; catalog latest is {latest}"
            if installed_date and baseline.get("released"):
                family_note = f"{family_note}; {note}"
            return _result("behind", family_note, latest)
        return _result("ahead", f"ahead of catalog snapshot {latest}", latest)

    if not inst_nums or not lat_nums:
        return {
            "currency": "unverified",
            "age_note": "",
            "latest_version": latest or "N/A",
            "update_recommended": False,
            "is_outdated": False,
        }

    vs_latest = _cmp(inst_nums, lat_nums)
    if vs_latest > 0:
        return _result("ahead", f"ahead of catalog snapshot {latest}", latest)
    if vs_latest == 0:
        return _result("current", "", latest)
    if min_nums and _cmp(inst_nums, min_nums) < 0:
        return _result("below_minimum", note, latest)
    return _result("behind", note, latest)


def _result(currency: str, age: str, latest: str) -> dict:
    return {
        "currency": currency,
        "age_note": age,
        "latest_version": latest,
        "update_recommended": currency in ("behind", "below_minimum"),
        "is_outdated": currency == "below_minimum",
    }


def currency_badge(installed: str, verdict: dict, *, bios: bool) -> str:
    """HTML badge. Newer than the catalog is never warning or danger."""
    shown = str(installed or "N/A")
    latest = verdict.get("latest_version") or "N/A"
    currency = verdict.get("currency")
    age = str(verdict.get("age_note") or "").strip()
    tail = f" — {age}" if age else ""
    if currency in ("ahead", "current"):
        if bios:
            label = f"Up-to-Date (v{shown}){tail}"
        else:
            label = f"Up-to-Date ({shown}){tail}"
        return f"<span class='badge success'>\U0001f7e2 {label}</span>"
    if currency == "behind":
        if bios:
            label = f"Update Available (v{shown} | Latest: v{latest}){tail}"
        else:
            label = f"Update Available ({shown} | Latest: {latest}){tail}"
        return f"<span class='badge warning'>\U0001f7e1 {label}</span>"
    if currency == "below_minimum":
        if bios:
            label = f"Outdated BIOS (v{shown} | Latest: v{latest}){tail}"
        else:
            label = f"Outdated ({shown} | Latest: {latest}){tail}"
        return f"<span class='badge danger'>\U0001f534 {label}</span>"
    if bios:
        return f"<span class='badge info'>ℹ️ v{shown}</span>"
    return f"<span class='badge info'>ℹ️ {shown}</span>"
