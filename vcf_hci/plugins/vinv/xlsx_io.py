"""Stdlib .xlsx writer, safe .xlsx reader, and JSON serializer for VinvSnapshot."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Tuple, Union
from xml.parsers import expat

from vcf_hci.plugins.vinv import limits
from vcf_hci.plugins.vinv.constants import (
    ALL_TAB_NAMES,
    CORE_TAB_NAMES,
    OPTIONAL_FILEINFO_TAB,
    TAB_HEADERS,
    UNIFIED_TAB_NAME_MAP,
)
from vcf_hci.plugins.vinv.models import VinvSnapshot, VinvTab
from vcf_hci.plugins.vinv.parity import HEADER_ALIASES, with_aliases
from vcf_hci.plugins.vinv.schema import snapshot_to_excel_sheet_dicts
from vcf_hci.report.excel_export import _write_xlsx

_MAIN_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_REL_NS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
_PKG_REL_NS = "{http://schemas.openxmlformats.org/package/2006/relationships}"
_CELL_REF_RE = re.compile(r"^([A-Z]+)(\d+)$")
_REVERSE_UNIFIED_MAP = {v: k for k, v in UNIFIED_TAB_NAME_MAP.items()}


def _col_index(letters: str) -> int:
    idx = 0
    for ch in letters:
        idx = idx * 26 + (ord(ch) - ord("A") + 1)
    return idx - 1


def _check_safe_xml(raw_bytes: bytes) -> None:
    parser = expat.ParserCreate()

    def reject(*args: object) -> None:
        raise ValueError("XML DTD / entity declarations are forbidden in workbooks")

    def reject_external(context: str, base: Union[str, None], system_id: Union[str, None], public_id: Union[str, None]) -> int:
        raise ValueError("XML DTD / entity declarations are forbidden in workbooks")

    parser.StartDoctypeDeclHandler = reject
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject_external
    try:
        parser.Parse(raw_bytes, True)
    except expat.ExpatError:
        raise ValueError("invalid workbook XML") from None


def render_vinv_xlsx(snapshot: VinvSnapshot) -> bytes:
    """Render a standalone 26-tab (or 27-tab) vSphere Inventory .xlsx workbook."""
    sheets = snapshot_to_excel_sheet_dicts(snapshot, unified_mode=False)
    return _write_xlsx(sheets)


def parse_vinv_xlsx(source: Union[bytes, str, Path]) -> VinvSnapshot:
    """Parse a vSphere inventory .xlsx workbook using Python stdlib only."""
    if isinstance(source, (str, Path)):
        p = Path(source)
        if p.suffix.lower() != ".xlsx" or p.stat().st_size > limits.MAX_UPLOAD_BYTES:
            raise ValueError("workbook must be a .xlsx file within upload size limits")
        raw_zip = p.read_bytes()
    else:
        if len(source) > limits.MAX_UPLOAD_BYTES:
            raise ValueError("workbook exceeds upload size limit")
        raw_zip = source

    try:
        zf = zipfile.ZipFile(BytesIO(raw_zip), "r")
    except Exception:
        raise ValueError("invalid .xlsx zip archive") from None

    with zf:
        total_uncompressed = 0
        for info in zf.infolist():
            total_uncompressed += info.file_size
            if total_uncompressed > limits.MAX_XLSX_UNCOMPRESSED_BYTES:
                raise ValueError("workbook uncompressed size limit exceeded")
            if info.compress_size > 0 and (info.file_size / info.compress_size) > limits.MAX_XLSX_COMPRESSION_RATIO:
                raise ValueError("workbook compression ratio limit exceeded")

        if "xl/workbook.xml" not in zf.namelist():
            raise ValueError("missing xl/workbook.xml")

        # Shared strings table (optional when inlineStr is used)
        shared_strings: List[str] = []
        if "xl/sharedStrings.xml" in zf.namelist():
            ss_bytes = zf.read("xl/sharedStrings.xml")
            _check_safe_xml(ss_bytes)
            ss_root = ET.fromstring(ss_bytes)
            for si in ss_root.findall(f"{_MAIN_NS}si"):
                texts = [t.text or "" for t in si.iter(f"{_MAIN_NS}t")]
                shared_strings.append("".join(texts)[: limits.MAX_XLSX_CELL_CHARS])

        # Relationships from xl/_rels/workbook.xml.rels
        rels_map: Dict[str, str] = {}
        rels_path = "xl/_rels/workbook.xml.rels"
        if rels_path in zf.namelist():
            rels_bytes = zf.read(rels_path)
            _check_safe_xml(rels_bytes)
            rels_root = ET.fromstring(rels_bytes)
            for rel in rels_root.findall(f"{_PKG_REL_NS}Relationship"):
                rid = rel.attrib.get("Id", "")
                target = rel.attrib.get("Target", "").lstrip("/")
                if not target.startswith("xl/"):
                    target = "xl/" + target
                rels_map[rid] = target

        wb_bytes = zf.read("xl/workbook.xml")
        _check_safe_xml(wb_bytes)
        wb_root = ET.fromstring(wb_bytes)
        sheet_elems = wb_root.findall(f".//{_MAIN_NS}sheet")
        if not sheet_elems or len(sheet_elems) > limits.MAX_XLSX_SHEETS:
            raise ValueError("workbook sheet count out of bounds")

        parsed_sheets: Dict[str, Tuple[Tuple[str, ...], Tuple[Tuple[str, ...], ...]]] = {}
        total_rows = 0

        for idx, sh in enumerate(sheet_elems, 1):
            raw_name = sh.attrib.get("name", f"Sheet{idx}").strip()
            canonical_name = _REVERSE_UNIFIED_MAP.get(raw_name, raw_name)
            if canonical_name not in ALL_TAB_NAMES:
                continue
            rid = sh.attrib.get(f"{_REL_NS}id", "")
            target_path = rels_map.get(rid, f"xl/worksheets/sheet{idx}.xml")
            if target_path not in zf.namelist():
                continue
            sh_bytes = zf.read(target_path)
            _check_safe_xml(sh_bytes)
            sh_root = ET.fromstring(sh_bytes)

            rows_list: List[List[str]] = []
            for row_elem in sh_root.findall(f".//{_MAIN_NS}sheetData/{_MAIN_NS}row"):
                total_rows += 1
                if total_rows > limits.MAX_XLSX_ROWS:
                    raise ValueError("workbook row limit exceeded")
                cells_dict: Dict[int, str] = {}
                max_col = -1
                for c_idx, cell_elem in enumerate(row_elem.findall(f"{_MAIN_NS}c")):
                    ref = cell_elem.attrib.get("r", "")
                    m = _CELL_REF_RE.match(ref)
                    col_i = _col_index(m.group(1)) if m else c_idx
                    if col_i >= limits.MAX_XLSX_COLUMNS:
                        raise ValueError("workbook column limit exceeded")
                    max_col = max(max_col, col_i)
                    c_type = cell_elem.attrib.get("t", "")
                    val_str = ""
                    if c_type == "inlineStr":
                        t_nodes = [t.text or "" for t in cell_elem.iter(f"{_MAIN_NS}t")]
                        val_str = "".join(t_nodes)
                    elif c_type == "s":
                        v_elem = cell_elem.find(f"{_MAIN_NS}v")
                        if v_elem is not None and v_elem.text is not None:
                            try:
                                ss_i = int(v_elem.text)
                                if 0 <= ss_i < len(shared_strings):
                                    val_str = shared_strings[ss_i]
                            except ValueError:
                                val_str = ""
                    else:
                        v_elem = cell_elem.find(f"{_MAIN_NS}v")
                        if v_elem is not None and v_elem.text is not None:
                            val_str = v_elem.text
                    cells_dict[col_i] = val_str[: limits.MAX_XLSX_CELL_CHARS].strip()
                if max_col >= 0:
                    row_vals = [cells_dict.get(i, "") for i in range(max_col + 1)]
                    rows_list.append(row_vals)

            if not rows_list:
                continue
            header = tuple(rows_list[0])
            width = len(header)
            data_rows = tuple(
                tuple((r[i] if i < len(r) else "") for i in range(width))
                for r in rows_list[1:]
                if any(cell != "" for cell in r)
            )
            parsed_sheets[canonical_name] = (header, data_rows)

    if "vInfo" not in parsed_sheets and "vHost" not in parsed_sheets:
        raise ValueError("workbook does not contain vInfo or vHost inventory sheets")

    # Extract metadata from vMetaData or vSource if present
    vc_server = ""
    vc_version = ""
    vc_build = ""
    vc_uuid = ""
    vc_fullname = ""
    gen_utc = ""
    scope_cluster = ""
    tls_verified = False
    warnings: Tuple[str, ...] = ()

    if "vMetaData" in parsed_sheets and parsed_sheets["vMetaData"][1]:
        m_hdr, m_rows = parsed_sheets["vMetaData"]
        m_dict = dict(zip(m_hdr, m_rows[0]))
        vc_server = m_dict.get("vCenter Server", "") or m_dict.get("Server", "")
        vc_version = m_dict.get("vCenter Version", "")
        vc_build = m_dict.get("vCenter Build", "")
        vc_uuid = m_dict.get("vCenter UUID", "")
        gen_utc = m_dict.get("Generated UTC", "") or m_dict.get("xlsx creation datetime", "")
        scope_cluster = m_dict.get("Scope Cluster", "")
        tls_verified = m_dict.get("TLS Verified", "").strip().lower() == "true"
        warnings = tuple(part.strip() for part in m_dict.get("Collection Warnings", "").split(";") if part.strip())

    if "vSource" in parsed_sheets and parsed_sheets["vSource"][1]:
        s_hdr, s_rows = parsed_sheets["vSource"]
        s_dict = dict(zip(s_hdr, s_rows[0]))
        vc_server = vc_server or s_dict.get("VI SDK Server", "") or s_dict.get("Name", "")
        vc_version = vc_version or s_dict.get("Version", "")
        vc_build = vc_build or s_dict.get("Build", "")
        vc_uuid = vc_uuid or s_dict.get("VI SDK UUID", "")
        vc_fullname = s_dict.get("Fullname", "")

    if not vc_server and "vHost" in parsed_sheets and parsed_sheets["vHost"][1]:
        h_hdr, h_rows = parsed_sheets["vHost"]
        h_dict = dict(zip(h_hdr, h_rows[0]))
        vc_server = h_dict.get("VI SDK Server", "imported-vcenter.rainpole.net")
        vc_uuid = vc_uuid or h_dict.get("VI SDK UUID", "")

    tabs: List[VinvTab] = []
    for tab_name in CORE_TAB_NAMES:
        expected_headers = TAB_HEADERS[tab_name]
        if tab_name in parsed_sheets:
            hdr, r_tuples = parsed_sheets[tab_name]
            tabs.append(_align_tab(tab_name, hdr, r_tuples))
        else:
            tabs.append(VinvTab(name=tab_name, headers=expected_headers, rows=()))

    include_file_info = OPTIONAL_FILEINFO_TAB in parsed_sheets
    if include_file_info:
        f_hdr, f_rows = parsed_sheets[OPTIONAL_FILEINFO_TAB]
        tabs.append(_align_tab(OPTIONAL_FILEINFO_TAB, f_hdr, f_rows))

    return VinvSnapshot(
        vcenter_server=vc_server or "imported-vcenter.rainpole.net",
        vcenter_version=vc_version,
        vcenter_build=vc_build,
        vcenter_uuid=vc_uuid,
        vcenter_fullname=vc_fullname,
        generated_utc=gen_utc or "imported",
        scope_cluster=scope_cluster or "All Clusters",
        include_file_info=include_file_info,
        tls_verified=tls_verified,
        acknowledged=True,
        tabs=tuple(tabs),
        warnings=warnings,
    )


def snapshot_to_json(snapshot: VinvSnapshot) -> str:
    payload = {
        "vcenter_server": snapshot.vcenter_server,
        "vcenter_version": snapshot.vcenter_version,
        "vcenter_build": snapshot.vcenter_build,
        "vcenter_uuid": snapshot.vcenter_uuid,
        "vcenter_fullname": snapshot.vcenter_fullname,
        "generated_utc": snapshot.generated_utc,
        "scope_cluster": snapshot.scope_cluster,
        "include_file_info": snapshot.include_file_info,
        "tls_verified": snapshot.tls_verified,
        "acknowledged": snapshot.acknowledged,
        "warnings": list(snapshot.warnings),
        "tabs": [
            {"name": tab.name, "headers": list(tab.headers), "rows": [list(r) for r in tab.rows]}
            for tab in snapshot.tabs
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def snapshot_from_json(raw: str) -> VinvSnapshot:
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("tabs"), list):
        raise ValueError("not a vSphere inventory snapshot")
    if len(data["tabs"]) > limits.MAX_XLSX_SHEETS:
        raise ValueError("snapshot has too many tabs")
    by_name: Dict[str, VinvTab] = {}
    total_rows = 0
    for item in data["tabs"]:
        if not isinstance(item, dict):
            raise ValueError("invalid snapshot tab")
        name = str(item.get("name", ""))
        if name not in TAB_HEADERS or name in by_name:
            raise ValueError("unknown or duplicate snapshot tab")
        headers = [str(h) for h in item.get("headers") or ()]
        rows = item.get("rows", [])
        if len(headers) > limits.MAX_XLSX_COLUMNS or not isinstance(rows, list):
            raise ValueError("invalid snapshot tab shape")
        total_rows += len(rows)
        if total_rows > limits.MAX_XLSX_ROWS:
            raise ValueError("snapshot row limit exceeded")
        for row in rows:
            if not isinstance(row, list):
                raise ValueError("invalid snapshot row")
            if any(len(str(c)) > limits.MAX_XLSX_CELL_CHARS for c in row):
                raise ValueError("snapshot cell size limit exceeded")
        by_name[name] = _align_tab(name, tuple(headers), tuple(tuple(str(c) for c in row) for row in rows))
    if "vInfo" not in by_name and "vHost" not in by_name:
        raise ValueError("snapshot requires a vInfo or vHost tab")
    order = list(CORE_TAB_NAMES) + [OPTIONAL_FILEINFO_TAB]
    tabs = tuple(by_name.get(n) or VinvTab(name=n, headers=TAB_HEADERS[n], rows=()) for n in order
                 if n in by_name or n in CORE_TAB_NAMES)
    return VinvSnapshot(
        vcenter_server=str(data.get("vcenter_server", "")),
        vcenter_version=str(data.get("vcenter_version", "")),
        vcenter_build=str(data.get("vcenter_build", "")),
        vcenter_uuid=str(data.get("vcenter_uuid", "")),
        vcenter_fullname=str(data.get("vcenter_fullname", "")),
        generated_utc=str(data.get("generated_utc", "")),
        scope_cluster=str(data.get("scope_cluster", "")),
        include_file_info=bool(data.get("include_file_info", False)),
        tls_verified=bool(data.get("tls_verified", True)),
        acknowledged=bool(data.get("acknowledged", True)),
        tabs=tabs,
        warnings=tuple(str(w) for w in data.get("warnings", ())),
    )


def _align_tab(name: str, headers: Tuple[str, ...], rows: Tuple[Tuple[str, ...], ...]) -> VinvTab:
    if len(set(headers)) != len(headers):
        raise ValueError("duplicate inventory headers")
    expected = TAB_HEADERS[name]
    output = expected + tuple(h for h in headers if h not in expected and h not in HEADER_ALIASES.get(name, {}).values())
    if len(output) > limits.MAX_XLSX_COLUMNS:
        raise ValueError("inventory column limit exceeded")
    aligned = []
    for row in rows:
        record = with_aliases(name, dict(zip(headers, row)))
        aligned.append(tuple(str(record.get(h, "")) for h in output))
    return VinvTab(name=name, headers=output, rows=tuple(aligned))
