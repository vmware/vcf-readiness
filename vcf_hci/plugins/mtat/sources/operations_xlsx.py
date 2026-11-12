"""Offline Operations OOXML import with bounded ZIP/XML parsing and no SDK/network."""
from __future__ import annotations

import json
import re
import time
import zipfile
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import Callable, Optional, TypedDict
from xml.etree import ElementTree as ET

from vcf_hci.plugins.mtat import limits
from vcf_hci.plugins.mtat.assess import assess
from vcf_hci.plugins.mtat.lifecycle import experimental_enabled
from vcf_hci.plugins.mtat.models import Assessment, HostEvidence, Provenance, SampleSeries
from vcf_hci.plugins.mtat.operations_columns import header_name, header_unit, map_headers
from vcf_hci.plugins.mtat.operations_ranges import TimedHost, partition_ranges
from vcf_hci.plugins.mtat.sources.base import CollectionRequest, PreflightReport, ProgressSink

_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PACKAGE = "http://schemas.openxmlformats.org/package/2006/relationships"
_FACTORS = {"B": 1, "BYTE": 1, "BYTES": 1, "KB": 1000, "KIB": 1024, "MB": 1000 ** 2,
            "MIB": 1024 ** 2, "GB": 1000 ** 3, "GIB": 1024 ** 3, "TB": 1000 ** 4, "TIB": 1024 ** 4}
_NUMBER = re.compile(r"^\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)\s*([A-Za-z]+)?\s*$")
_CELL = re.compile(r"^([A-Z]+)([1-9][0-9]*)$")


class _Table(TypedDict):
    source: int
    sheet: str
    headers: list[str]
    mapping: dict
    rows: list[dict[str, str]]


def _xml(data: bytes) -> ET.Element:
    # XML parsers accept UTF-16; prohibit declarations before parsing any encoding.
    probe = data.replace(b"\x00", b"").lower()
    if b"<!doctype" in probe or b"<!entity" in probe:
        raise ValueError("workbook XML declarations are prohibited")
    try:
        return ET.fromstring(data)
    except ET.ParseError:
        raise ValueError("malformed workbook XML") from None


def _number(value: str) -> Decimal:
    try:
        number = Decimal(value.strip().replace(",", ""))
    except InvalidOperation:
        raise ValueError("workbook metric is not numeric") from None
    if not number.is_finite() or number < 0 or number.adjusted() > 18:
        raise ValueError("workbook metric is out of bounds")
    return number


def _timestamp(value: str, date1904: bool) -> Optional[int]:
    if not value:
        return None
    try:
        if re.fullmatch(r"\d+(?:\.\d+)?", value):
            number = Decimal(value)
            if number < 1000000:
                base = datetime(1904, 1, 1, tzinfo=timezone.utc) if date1904 else datetime(1899, 12, 30, tzinfo=timezone.utc)
                return int((base + timedelta(days=float(number))).timestamp() * 1000)
            return int(number * 1000) if number < 100000000000 else int(number)
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1000)
    except (ValueError, OverflowError):
        raise ValueError("invalid workbook timestamp") from None


class OperationsXlsxAdapter:
    kind = "operations-xlsx"

    def __init__(self, *, enabled: Optional[bool] = None, memory_unit: str = "auto", range_base: str = "Workbook",
                 cancelled: Callable[[], bool] = lambda: False) -> None:
        if memory_unit != "auto" and memory_unit.upper() not in _FACTORS:
            raise ValueError("unsupported workbook memory unit")
        self.enabled, self.memory_unit, self.range_base, self.cancelled = enabled, memory_unit, range_base, cancelled
        self._deadline = 0.0

    def close(self) -> None:
        """No network or persistent workbook handle is retained."""

    def _check(self) -> None:
        if self.cancelled():
            raise RuntimeError("MTAT workbook import cancelled")
        if time.monotonic() > self._deadline:
            raise RuntimeError("MTAT workbook deadline exceeded")

    def _start(self, request: CollectionRequest) -> Path:
        enabled = experimental_enabled() if self.enabled is None else self.enabled
        if not enabled or not request.acknowledged:
            raise PermissionError("Experimental enablement and per-run acknowledgement are required")
        if request.source_kind != self.kind:
            raise ValueError("incorrect source kind")
        self._deadline = time.monotonic() + limits.JOB_TIMEOUT_SECONDS
        self._check()
        if request.endpoint.startswith(("//", "\\\\")) or "://" in request.endpoint:
            raise ValueError("workbook endpoint must be a local file path")
        path = Path(request.endpoint)
        if path.suffix.lower() != ".xlsx" or path.stat().st_size > limits.MAX_UPLOAD_BYTES:
            raise ValueError("workbook type or upload size is invalid")
        return path

    def _sheets(self, path: Path) -> tuple[list[tuple[str, list[list[str]]]], bool]:
        try:
            with zipfile.ZipFile(path) as archive:
                names = set()
                expanded = 0
                if len(archive.infolist()) > limits.MAX_XLSX_SHEETS * 16 + 256:
                    raise ValueError("workbook ZIP member limit exceeded")
                for item in archive.infolist():
                    self._check()
                    name = item.filename
                    parts = PurePosixPath(name).parts
                    if name in names or name.startswith("/") or "\\" in name or ".." in parts or ":" in name or item.flag_bits & 1 or (item.external_attr >> 16) & 0o170000 == 0o120000:
                        raise ValueError("unsafe workbook archive path or member")
                    if "externallinks" in name.lower() or name.lower().endswith(".bin") or "vbaproject" in name.lower():
                        raise ValueError("macros and external links are prohibited")
                    names.add(name)
                    expanded += item.file_size
                    if expanded > limits.MAX_XLSX_UNCOMPRESSED_BYTES or item.file_size > max(item.compress_size, 1) * limits.MAX_XLSX_COMPRESSION_RATIO:
                        raise ValueError("workbook expansion limit exceeded")
                required = {"[Content_Types].xml", "xl/workbook.xml", "xl/_rels/workbook.xml.rels"}
                if not required <= names:
                    raise ValueError("workbook structure is incomplete")
                content = archive.read("[Content_Types].xml")
                if b"macroenabled" in content.lower() or b"vbaproject" in content.lower():
                    raise ValueError("macro workbook content is prohibited")
                content_types = _xml(content)
                if any("macroenabled" in value.lower() or "vbaproject" in value.lower() for node in content_types.iter() for value in node.attrib.values()):
                    raise ValueError("macro workbook content is prohibited")
                relations = {}
                for name in sorted(names):
                    if not name.endswith(".rels"):
                        continue
                    root = _xml(archive.read(name))
                    if root.tag != "{" + _PACKAGE + "}Relationships":
                        raise ValueError("malformed workbook relationships")
                    seen_ids = set()
                    for rel in root:
                        key, target = rel.get("Id"), rel.get("Target", "")
                        if rel.tag != "{" + _PACKAGE + "}Relationship" or not key or key in seen_ids or not target or rel.get("TargetMode", "Internal") != "Internal" or ".." in PurePosixPath(target).parts or "\\" in target or ":" in target:
                            raise ValueError("unsafe workbook relationship")
                        seen_ids.add(key)
                        # Absolute package paths are legal OOXML, never filesystem paths.
                        parent = PurePosixPath(name).parent.parent
                        resolved = target.lstrip("/") if target.startswith("/") else str(parent / target)
                        if resolved.startswith("./"):
                            resolved = resolved[2:]
                        if resolved not in names:
                            raise ValueError("workbook relationship target is missing")
                        if name == "xl/_rels/workbook.xml.rels":
                            relations[key] = (resolved, rel.get("Type"))
                shared: list[str] = []
                if "xl/sharedStrings.xml" in names:
                    for cell in _xml(archive.read("xl/sharedStrings.xml")).findall("{%s}si" % _MAIN):
                        value = "".join(t.text or "" for t in cell.iter("{%s}t" % _MAIN))
                        if len(value) > limits.MAX_XLSX_CELL_CHARS or len(shared) >= limits.MAX_XLSX_ROWS * limits.MAX_XLSX_COLUMNS:
                            raise ValueError("workbook shared string limit exceeded")
                        shared.append(value)
                if sum(name.startswith("xl/worksheets/") and name.endswith(".xml") for name in names) > limits.MAX_XLSX_SHEETS:
                    raise ValueError("workbook sheet limit exceeded")
                workbook = _xml(archive.read("xl/workbook.xml"))
                settings = workbook.find("{%s}workbookPr" % _MAIN)
                date1904 = settings is not None and settings.get("date1904") in ("1", "true")
                sheets = workbook.findall("{%s}sheets/{%s}sheet" % (_MAIN, _MAIN))
                if not sheets or len(sheets) > limits.MAX_XLSX_SHEETS:
                    raise ValueError("workbook sheet limit exceeded")
                result = []
                row_count = 0
                used = set()
                for sheet in sheets:
                    self._check()
                    key = sheet.get("{%s}id" % _REL)
                    target, kind = relations.get(key, ("", ""))
                    if kind != _REL + "/worksheet" or target in used:
                        raise ValueError("malformed worksheet relationship")
                    used.add(target)
                    root = _xml(archive.read(target))
                    if root.tag != "{%s}worksheet" % _MAIN:
                        raise ValueError("malformed worksheet")
                    rows = []
                    last_row = 0
                    for row in root.findall("{%s}sheetData/{%s}row" % (_MAIN, _MAIN)):
                        self._check()
                        row_count += 1
                        row_number = int(row.get("r", str(last_row + 1)))
                        if row_number <= last_row or row_number > limits.MAX_XLSX_ROWS or row_count > limits.MAX_XLSX_ROWS:
                            raise ValueError("workbook row limit or ordering is invalid")
                        last_row = row_number
                        values: dict[int, str] = {}
                        for cell in row:
                            if cell.tag != "{%s}c" % _MAIN:
                                continue
                            match = _CELL.fullmatch(cell.get("r", ""))
                            if not match or int(match[2]) != row_number:
                                raise ValueError("invalid worksheet cell reference")
                            column = 0
                            for letter in match[1]:
                                column = column * 26 + ord(letter) - ord('A') + 1
                            if column > limits.MAX_XLSX_COLUMNS or column in values:
                                raise ValueError("workbook column limit or duplicate cell")
                            cached = cell.find("{%s}v" % _MAIN)
                            formula = cell.find("{%s}f" % _MAIN)
                            if formula is not None and re.search(r"\[[^\]]+\].*!|(?:https?|file):|(?:WEBSERVICE|HYPERLINK)\(|\|", formula.text or "", re.IGNORECASE):
                                raise ValueError("external workbook formula links are prohibited")
                            if formula is not None and (cached is None or cached.text is None):
                                raise ValueError("formula cell has no cached value")
                            value = cached.text or "" if cached is not None else ""
                            kind = cell.get("t", "n")
                            if kind == "s":
                                index = int(value)
                                if not 0 <= index < len(shared):
                                    raise ValueError("invalid shared string reference")
                                value = shared[index]
                            elif kind == "inlineStr":
                                value = "".join(t.text or "" for t in cell.iter("{%s}t" % _MAIN)) if cell.find("{%s}is" % _MAIN) is not None else ""
                            elif kind == "e":
                                raise ValueError("worksheet contains an error cell")
                            if len(value) > limits.MAX_XLSX_CELL_CHARS:
                                raise ValueError("workbook cell limit exceeded")
                            values[column] = value
                        rows.append([values.get(i, "") for i in range(1, max(values, default=0) + 1)])
                    result.append((sheet.get("name", "Sheet"), rows))
                return result, date1904
        except (zipfile.BadZipFile, KeyError, ET.ParseError):
            raise ValueError("invalid workbook archive") from None

    def _tables(self, sheets: list[tuple[str, list[list[str]]]]) -> list[_Table]:
        tables: list[_Table] = []
        for sheet, rows in sheets:
            table: Optional[_Table] = None
            for raw_cells in rows:
                self._check()
                cells = list(raw_cells)
                while cells and not cells[-1].strip():
                    cells.pop()
                mapping = map_headers(tuple(cells))
                if "host" in mapping and ((table is None and "cluster" in mapping) or any(key in mapping for key in ("cpu", "active", "consumed", "alloc", "prov", "cap"))):
                    non_empty = [c.strip() for c in cells if c.strip()]
                    if len(set(non_empty)) != len(non_empty):
                        raise ValueError("duplicate workbook headers")
                    table = {"source": len(tables), "sheet": sheet, "headers": cells, "mapping": mapping, "rows": []}
                    tables.append(table)
                elif table is not None and any(cells):
                    if len(cells) > len(table["headers"]):
                        raise ValueError("workbook row exceeds header width")
                    table["rows"].append(dict(zip(table["headers"], cells + [""] * (len(table["headers"]) - len(cells)))))
        return tables

    def _groups(self, request: CollectionRequest) -> tuple[list[dict], tuple[str, ...]]:
        sheets, date1904 = self._sheets(self._start(request))
        tables = self._tables(sheets)
        groups: dict = {}
        clusters: dict[str, set[str]] = {}
        contexts: dict[tuple[str, str], dict[str, str]] = {}
        sample_count = 0
        for table in tables:
            mapping = table["mapping"]
            for row in table["rows"]:
                self._check()
                host = row.get(mapping["host"], "").strip()
                cluster = row.get(mapping.get("cluster"), "").strip() or "(no cluster)"
                if host and cluster != "(no cluster)":
                    clusters.setdefault(host, set()).add(cluster)
                context = {header_name(k): v for k, v in row.items() if header_name(k) in {"tenant", "bom", "datacenter", "fabric"} and v}
                if context:
                    contexts.setdefault((cluster, host), {}).update(context)
                if not any(k in mapping for k in ("cpu", "active", "consumed", "alloc", "prov", "cap")) or not host:
                    continue
                key = (table["source"], cluster, host)
                if key not in groups:
                    if len(groups) >= limits.MAX_HOSTS:
                        raise ValueError("workbook host limit exceeded")
                    groups[key] = {"source": table["source"], "cluster": cluster, "host": host, "values": {}, "timestamps": [], "seen_timestamps": set(), "missing": set()}
                group = groups[key]
                timestamp = _timestamp(row.get(mapping.get("ts"), ""), date1904)
                if "ts" in mapping and timestamp is None:
                    raise ValueError("workbook history row is missing its timestamp")
                if timestamp is None and group["values"]:
                    raise ValueError("duplicate untimed host snapshots are ambiguous")
                if timestamp is not None:
                    if timestamp in group["seen_timestamps"]:
                        raise ValueError("duplicate host timestamp within one workbook history")
                    group["seen_timestamps"].add(timestamp)
                    group["timestamps"].append(timestamp)
                for alias in ("cpu", "active", "consumed", "alloc", "prov", "cap", "mhz"):
                    header = mapping.get(alias)
                    if not header or not row.get(header, "").strip():
                        group["missing"].add(alias)
                    if header and row.get(header, "").strip():
                        sample_count += 1
                        if sample_count > limits.MAX_SAMPLES:
                            raise ValueError("workbook sample limit exceeded")
                        group["values"].setdefault(alias, []).append((row[header], header))
        output = list(groups.values())
        for group in output:
            known = clusters.get(group["host"], set())
            if group["cluster"] == "(no cluster)" and len(known) == 1:
                group["cluster"] = next(iter(known))
            unambiguous = group["cluster"] == "(no cluster)" or known == {group["cluster"]}
            merged_context = dict(contexts.get(("(no cluster)", group["host"]), {})) if unambiguous else {}
            merged_context.update(contexts.get((group["cluster"], group["host"]), {}))
            group["context"] = merged_context
        if request.cluster:
            output = [g for g in output if g["cluster"] == request.cluster]
        if not output:
            raise ValueError("workbook contains no selected host metric rows")
        timed = tuple(TimedHost(g["source"], g["cluster"], g["host"], min(g["timestamps"]) if g["timestamps"] else None,
                               max(g["timestamps"]) if g["timestamps"] else None) for g in output)
        return output, partition_ranges(self.range_base, timed)

    def ranges(self, request: CollectionRequest) -> tuple[str, ...]:
        """List independently selectable histories without revealing credentials."""
        return self._groups(request)[1]

    def preflight(self, request: CollectionRequest) -> PreflightReport:
        labels = self.ranges(request)
        return PreflightReport(True, "Operations workbook", False, {"host_metrics": True, "vm_eligibility": False}, labels)

    def _metric(self, group: dict, alias: str) -> Optional[SampleSeries]:
        if alias in group.get("missing", set()):
            return None
        entries = group["values"].get(alias, [])
        if not entries:
            return None
        values: list = []
        for text, header in entries:
            if alias == "cpu":
                values.append(_number(text.rstrip("%")))
                continue
            if alias == "mhz":
                cleaned = re.sub(r"\s*mhz\s*$", "", text.strip(), flags=re.IGNORECASE)
                values.append(_number(cleaned))
                continue
            match = _NUMBER.fullmatch(text.replace(",", ""))
            if not match:
                raise ValueError("workbook memory cell is not numeric")
            unit = self.memory_unit.upper() if self.memory_unit != "auto" else (match[2] or header_unit(header) or ("KiB" if header_name(header).startswith("mem|") else "GB")).upper()
            if unit not in _FACTORS:
                raise ValueError("unsupported embedded workbook memory unit")
            values.append(int(_number(match[1]) * _FACTORS[unit]))
        return SampleSeries(tuple(values), "percent" if alias in ("cpu", "mhz") else "bytes", entries[0][1])

    def collect(self, request: CollectionRequest, progress: ProgressSink) -> Assessment:
        try:
            groups, labels = self._groups(request)
            label = request.range_name or labels[0]
            if len(labels) > 1:
                if label not in labels:
                    raise ValueError("select one of the separate overlapping workbook ranges")
                timed_sources = sorted({g["source"] for g in groups if g["timestamps"]})
                index = labels.index(label)
                if index < len(timed_sources):
                    groups = [g for g in groups if g["source"] == timed_sources[index]]
                else:
                    timed_hosts = {(g["cluster"], g["host"]) for g in groups if g["timestamps"]}
                    groups = [g for g in groups if not g["timestamps"] and (g["cluster"], g["host"]) not in timed_hosts]
            # Non-overlapping, timestamped histories can safely contribute to one range.
            merged: dict = {}
            for group in groups:
                key = (group["cluster"], group["host"])
                if key not in merged:
                    merged[key] = group
                elif group["timestamps"] and merged[key]["timestamps"]:
                    target = merged[key]
                    target["timestamps"].extend(group["timestamps"])
                    target["missing"].update(group["missing"])
                    for metric, values in group["values"].items():
                        target["values"].setdefault(metric, []).extend(values)
                else:
                    raise ValueError("duplicate host snapshots require separate workbook ranges")
            groups = list(merged.values())
            evidence = []
            provenance = []
            identities = set()
            for index, group in enumerate(groups):
                self._check()
                key = (group["cluster"], group["host"])
                if key in identities:
                    raise ValueError("duplicate host snapshots require separate workbook ranges")
                identities.add(key)
                physical = self._metric(group, "prov") or self._metric(group, "cap")
                measured = self._metric(group, "consumed")
                consumed = measured or self._metric(group, "alloc")
                active = self._metric(group, "active")
                mhz = self._metric(group, "mhz")
                evidence.append(HostEvidence(group["cluster"], group["host"], "/".join(key), "historical",
                    memory_size_bytes=max(physical.values) if physical else None, tier_properties_supported=False,
                    cpu=self._metric(group, "cpu"), consumed=consumed, active=active,
                    cpu_mhz=int(max(mhz.values)) if mhz else None))
                marks = [Provenance(metric, series.source_key, series.encoding, authority) for metric, series, authority in (
                    ("Consumed", consumed, "measured" if measured else "proxy"), ("Active", active, "measured"),
                    ("Physical_RAM", physical, "measured")) if series is not None]
                marks.extend(Provenance("Context: " + k, v, "label", "mapping") for k, v in sorted(group["context"].items()))
                provenance.append(tuple(marks))
                progress.update("hosts", index + 1, len(groups), "Importing workbook host evidence")
            result = assess(label, self.kind, "Operations workbook", "OOXML", tuple(evidence), (), request.policy, acknowledged=request.acknowledged)
            result = replace(result, hosts=tuple(replace(row, provenance=row.provenance + marks) for row, marks in zip(result.hosts, provenance)))
            if len(json.dumps(asdict(result), default=str).encode()) > limits.MAX_RESULT_BYTES:
                raise ValueError("assessment result byte limit exceeded")
            self._check()
            return result
        finally:
            self.close()
