"""
VCF Readiness Tool — Credential CSV parser (vcf_hci.vault.csv_import)

Pure text parsing for bulk credential import into the encrypted vault.
Performs no file I/O; callers pass the CSV text and receive rows plus
per-line error strings.  Target syntax is validated later by
``CredentialVault.import_rows`` / ``set_entry``.

Accepted header names (case-insensitive):
    target   | ip | host | hostname | address
    username | user
    password | pass
    note     (optional)

Blank lines and lines beginning with ``#`` are ignored.  A UTF-8 BOM is
stripped.  Duplicate targets: the last row wins (a warning is recorded).
"""

import csv
import io
from typing import Dict, List, Tuple

CSV_TEMPLATE = (
    "target,username,password,note\n"
    "192.0.2.10,root,CHANGE_ME,exact host\n"
    "idrac-r740-01.rainpole.net,root,CHANGE_ME,hostname entry\n"
    "192.0.2.0/24,admin,CHANGE_ME,whole rack (CIDR)\n"
    "198.51.100.10-20,root,CHANGE_ME,IPv4 range (expanded on import)\n"
    "default,root,CHANGE_ME,fallback for everything else\n"
)

_TARGET_ALIASES = ("target", "ip", "host", "hostname", "address")
_USER_ALIASES = ("username", "user")
_PASS_ALIASES = ("password", "pass")
_NOTE_ALIASES = ("note", "notes", "comment", "description")

__all__ = ["CSV_TEMPLATE", "parse_credentials_csv"]


def _pick(header_map: Dict[str, str], aliases: Tuple[str, ...]) -> str:
    for a in aliases:
        if a in header_map:
            return header_map[a]
    return ""


def parse_credentials_csv(text: str) -> Tuple[List[Dict[str, str]], List[str], List[str]]:
    """Parse credential CSV text.

    Returns ``(rows, errors, warnings)`` where each row is
    ``{"target", "username", "password", "note", "line"}`` (``line`` is the
    1-based physical line number as a string), ``errors`` are human-readable
    strings prefixed with the offending line number, and ``warnings`` are
    non-fatal notices (duplicate targets).  A structural problem (missing
    required column, empty file) yields no rows and one error.
    """
    if text is None:
        return [], ["empty CSV"], []
    if text.startswith("\ufeff"):
        text = text[1:]
    physical_lines = text.splitlines()
    # Keep a map from logical (non-comment) line index -> physical line number
    kept: List[Tuple[int, str]] = []
    for idx, line in enumerate(physical_lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        kept.append((idx, line))
    if not kept:
        return [], ["empty CSV: no header row found"], []

    header_line = kept[0][1]
    try:
        header_cells = next(csv.reader(io.StringIO(header_line)))
    except (csv.Error, StopIteration):
        return [], ["line %d: cannot parse header" % kept[0][0]], []
    header_map: Dict[str, str] = {}
    for cell in header_cells:
        key = (cell or "").strip().lower()
        if key and key not in header_map:
            header_map[key] = cell
    col_target = _pick(header_map, _TARGET_ALIASES)
    col_user = _pick(header_map, _USER_ALIASES)
    col_pass = _pick(header_map, _PASS_ALIASES)
    col_note = _pick(header_map, _NOTE_ALIASES)
    missing = []
    if not col_target:
        missing.append("target")
    if not col_user:
        missing.append("username")
    if not col_pass:
        missing.append("password")
    if missing:
        return [], ["line %d: missing required column(s): %s" % (kept[0][0], ", ".join(missing))], []

    rows: List[Dict[str, str]] = []
    errors: List[str] = []
    warnings: List[str] = []
    seen: Dict[str, str] = {}
    for phys_no, line in kept[1:]:
        try:
            cells = next(csv.reader(io.StringIO(line)))
        except (csv.Error, StopIteration):
            errors.append("line %d: malformed CSV" % phys_no)
            continue
        record = dict(zip(header_cells, cells))
        target = (record.get(col_target) or "").strip()
        username = (record.get(col_user) or "").strip()
        password = record.get(col_pass) or ""
        note = (record.get(col_note) or "").strip() if col_note else ""
        if not target:
            errors.append("line %d: empty target" % phys_no)
            continue
        if not username:
            errors.append("line %d: empty username" % phys_no)
            continue
        if password == "":
            errors.append("line %d: empty password" % phys_no)
            continue
        key = target.lower()
        if key in seen:
            warnings.append("line %d: duplicate target '%s' overrides line %s" % (phys_no, target, seen[key]))
            rows = [r for r in rows if r["target"].lower() != key]
        seen[key] = str(phys_no)
        rows.append({"target": target, "username": username, "password": password,
                     "note": note, "line": str(phys_no)})
    return rows, errors, warnings
