"""Workbook firmware evidence for 9.1; vendor currency is not certification."""

import re
from datetime import date
from typing import Any, Optional
from urllib.parse import quote, urlsplit

from vcf_hci.bcg_links import BCGLinkGenerator
from vcf_hci.collector.pci_utils import normalize_pci_id
from vcf_hci.compat.firmware import _compare_fw_versions, is_zero_or_null_firmware
from vcf_hci.compat.firmware_currency import resolve_bmc_baseline
from vcf_hci.fc_inventory import fc_adapter_key, normalize_fc_ports
from vcf_hci.hcl import lookup_unique_hcl_device

KINDS = ("BIOS", "BMC", "NIC", "NVMe", "HBA/RAID")
UPGRADE_HEADERS = (
    "Needs BIOS upgrade",
    "Needs BMC upgrade (age advisory)",
    "Needs NIC firmware upgrade",
    "Needs NVMe firmware upgrade",
    "Needs HBA/RAID firmware upgrade",
)
FIRMWARE_HEADERS = (
    "Host IP",
    "Hostname",
    "Component",
    "Name",
    "Device ID",
    "Installed Firmware",
    "Assessment Target",
    "Supported Firmware",
    "Needs Upgrade",
    "Evidence / Reason",
    "Assessment Reason",
    "BCG Reference",
)


def safe_bcg_url(value: Any) -> str:
    """Only emit public HTTPS BCG destinations, including catalog-provided URLs."""
    url = str(value or "").strip()
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme == "https"
            and parsed.hostname == "compatibilityguide.broadcom.com"
            and not parsed.username
            and not parsed.password
            and parsed.port in (None, 443)
            and not any(ord(c) < 32 for c in url)
        ):
            return url
    except ValueError:
        pass
    return ""


def server_bcg_reference(data: dict) -> tuple[str, str]:
    """BIOS versions are checked on the server listing, not a BIOS-only program."""
    si = data.get("system") or {}
    model = str(si.get("model") or "").strip()
    if model.lower() in ("", "n/a", "unknown", "not reported", "system", "server"):
        return "", ""
    cpu = si.get("cpu_summary") or {}
    url = BCGLinkGenerator.server(
        vendor=str(si.get("manufacturer") or si.get("vendor") or ""),
        model=model,
        cpu_model=cpu.get("model") or "",
        processor_id=str(cpu.get("processor_id") or ""),
    )
    return url, "BCG server listing" if urlsplit(url).path == "/detail" else "BCG server search"


def _device_bcg_reference(row: dict, device: dict, ids: list[str], entry: Optional[dict], osa: bool) -> None:
    program = "ssd" if row["kind"] == "NVMe" else "vsanio" if osa else "io"
    entry = entry or {}
    # Prefer retained catalog identities; a BCG destination does not prove support.
    url = safe_bcg_url(entry.get("io_vcglink") if program == "io" else "")
    if not url and program == "io" and entry.get("io_product_id"):
        url = BCGLinkGenerator.device_detail(str(entry["io_product_id"]), "io")
    url = url or safe_bcg_url(entry.get("vcglink"))
    pid = entry.get("io_product_id") if program == "io" else ""
    pid = str(pid or entry.get("product_id") or "")
    if not url and pid:
        product_program = (
            "io" if program == "io" and entry.get("io_product_id") else str(entry.get("hcl_program") or program)
        )
        url = BCGLinkGenerator.device_detail(pid, product_program)
    if not url:
        if ids[0] and ids[1] and row["kind"] != "NVMe":
            url = BCGLinkGenerator.pci_exact(*ids, program=program)
        elif row["name"].lower() not in ("", "unknown", "n/a", row["kind"].lower()):
            if row["kind"] == "NVMe":
                url = BCGLinkGenerator.storage(row["name"], str(device.get("part_number") or ""))
            elif osa:
                url = BCGLinkGenerator.pci_exact("", "", program=program) + "&keyword=" + quote(row["name"])
            else:
                url = BCGLinkGenerator.io_device(row["name"])
    row["bcg_url"] = safe_bcg_url(url)
    row["bcg_label"] = (
        ("BCG listing" if urlsplit(url).path == "/detail" else "BCG device search") if row["bcg_url"] else ""
    )


def upgrade_cell(status: str) -> tuple:
    return status, {"Yes": "red", "No": "green"}.get(status, "yellow")


def _date(value: Any) -> Optional[date]:
    try:
        return date.fromisoformat(str(value)[:10])
    except (ValueError, TypeError):
        return None


def _row(kind: str, device: dict, installed: Any, target: str) -> dict:
    return {
        "kind": kind,
        "name": str(
            device.get("model") or device.get("ctrl_model") or device.get("adapter_name") or device.get("name") or kind
        ),
        "device_id": str(
            device.get("id")
            or device.get("physical_adapter_id")
            or device.get("adapter_id")
            or device.get("pci_quad")
            or ""
        ),
        "installed": str(installed or ""),
        "target": target,
        "supported": "",
        "upgrade": "Incomplete",
        "ready": None,
        "reason": "No release-specific firmware evidence available.",
        "bcg_url": "",
        "bcg_label": "",
    }


def _device_row(kind: str, device: dict, hcl: dict, osa: bool = False) -> dict:
    installed = device.get("ctrl_firmware") or device.get("firmware_version") or device.get("firmware")
    row = _row(kind, device, installed, "vSAN OSA 9.1" if osa else "ESXi 9.1")
    ids = [
        normalize_pci_id(str(device.get(k) or ""))
        for k in ("vendor_id", "device_id", "subsystem_vendor_id", "subsystem_id")
    ]
    if not all(ids):
        quad = str(device.get("pci_quad") or "").split(":")
        if len(quad) == 4:
            ids = [normalize_pci_id(x) for x in quad]
    entry = lookup_unique_hcl_device(*ids, json_hcl=hcl, model_name=row["name"])
    # NICs/controllers need exact OEM identity, not a shared chipset/model fallback.
    if kind != "NVMe":
        quad_key = ":".join(ids)
        quads = hcl.get("quads") or hcl.get("_pci_quads") or {}
        exact = (quads.get(quad_key) or hcl.get(quad_key)) if all(ids) else None
        entry = exact if isinstance(exact, dict) else None
    _device_bcg_reference(row, device, ids, entry, osa)
    if not entry:
        row["reason"] = "Exact device identity / 9.1 firmware evidence unavailable; verify BCG."
        return row
    matrix = entry.get("release_matrix") or entry.get("releaseMatrix") or {}
    # OSA must use vSAN evidence; ESXi alone does not certify a vSAN controller.
    releases = ("vSAN OSA 9.1", "vSAN 9.1") if osa else ("ESXi 9.1", "vSAN 9.1") if kind == "NVMe" else ("ESXi 9.1",)
    rel = next((matrix[k] for k in releases if isinstance(matrix.get(k), dict)), None)
    if not rel:
        row["reason"] = f"No {row['target']} firmware matrix for this device; verify BCG."
        if entry.get("releases") and not any("9.1" in str(r) for r in entry["releases"]):
            row["ready"] = False
            row["reason"] += (
                " Device is listed only for other releases; firmware upgrade alone is not a confirmed remedy."
            )
        return row
    if osa and not any(x in str(entry.get("tier") or "").lower() for x in ("osa", "all flash", "hybrid")):
        row["reason"] = "vSAN OSA controller qualification not confirmed; verify controller mode and BCG."
        return row
    versions = [str(v).strip() for v in rel.get("firmwares") or [] if not is_zero_or_null_firmware(v)]
    minimum = str(rel.get("min_firmware") or "")
    certified = str(rel.get("firmware") or rel.get("recommended_firmware") or "")
    row["supported"] = ", ".join(versions) or certified or minimum
    if is_zero_or_null_firmware(installed) or not row["supported"]:
        row["reason"] = "Installed firmware or release-specific supported version missing."
        return row
    fw = str(installed).strip()
    allowed = versions or ([certified] if certified else [])
    if fw.casefold() in [v.casefold() for v in allowed]:
        row.update(
            upgrade="No",
            ready=True,
            reason="Installed firmware is listed for the assessment target; verify required driver pairing in BCG.",
        )
        return row
    # A list is a set of certified builds, not permission to use every newer build.
    # Only compare numeric versions; unrelated OEM alphanumeric trains stay unknown.
    floor = minimum or (
        min(versions, key=lambda v: tuple(int(n) for n in v.split(".")))
        if versions and all(re.fullmatch(r"\d+(?:\.\d+)*", v) for v in versions)
        else ""
    )
    if re.fullmatch(r"\d+(?:\.\d+)*", fw) and re.fullmatch(r"\d+(?:\.\d+)*", floor):
        cmp = _compare_fw_versions(fw, floor)
        if cmp < 0:
            row.update(upgrade="Yes", ready=False, reason=f"Installed firmware is below the target minimum {floor}.")
        elif not versions and minimum:
            row.update(
                upgrade="No",
                ready=True,
                reason=f"Installed firmware meets the explicit target minimum {floor}; verify driver pairing.",
            )
        else:
            row.update(
                ready=False,
                reason="Installed build is not in the target's certified firmware list; verify supported update path.",
            )
    else:
        row["reason"] = (
            "Installed build not confirmed by target firmware evidence; verify OEM firmware train / update path."
        )
    return row


def _bmc_row(data: dict) -> dict:
    bm = data.get("bmc_firmware") or {}
    installed = str(bm.get("bmc_fw_version") or "")
    model = str(bm.get("bmc_model") or "BMC")
    row = _row("BMC", {"name": model}, installed, "Age advisory only (>365 days at capture)")
    # Only the installed build's date is useful, never the latest build's date
    # unless that version exactly matches. Reject ambiguous inventory matches.
    dates = set()
    for fw in data.get("firmware_inventory") or []:
        name = str(fw.get("name") or "").lower()
        if str(fw.get("version") or "") == installed and any(
            t in name for t in ("bmc", "idrac", "ilo", "xcc", "integrated management controller")
        ):
            released = _date(fw.get("release_date"))
            if released:
                dates.add(released)
    direct = _date(bm.get("release_date"))
    if direct:
        dates.add(direct)
    if not dates:
        _, baseline = resolve_bmc_baseline(model, installed, str((data.get("system") or {}).get("model") or ""))
        if baseline and installed == str(baseline.get("latest") or ""):
            released = _date(baseline.get("released"))
            if released:
                dates.add(released)
    captured = _date(data.get("timestamp") or data.get("scanned_at"))
    released = next(iter(dates)) if len(dates) == 1 else None
    age = (captured - released).days if captured and released else None
    if is_zero_or_null_firmware(installed) or age is None or age < 0:
        row["reason"] = (
            "Installed BMC build date / capture date missing or ambiguous. Age is not a vSphere certification check."
        )
    else:
        row.update(
            upgrade="Yes" if age > 365 else "No",
            reason=f"Installed BMC build is {age} days old at capture ({released}); age advisory, not a vSphere support requirement.",
        )
    return row


def classify_assessment_reason(row: dict) -> str:
    """Stable sort key. Prose stays in Evidence / Reason; this does not change Incomplete."""
    kind = str(row.get("kind") or "")
    if kind == "BIOS":
        return "Currency"
    if kind == "BMC":
        return "Age advisory"
    text = str(row.get("reason") or "").lower()
    if "driver pairing" in text:
        return "Driver pairing"
    if (
        "exact device identity" in text
        or "firmware evidence unavailable" in text
        or "no applicable component inventory" in text
    ):
        return "Missing HCL"
    return "9.1 certification"


def firmware_rows(data: dict, hcl: dict) -> list[dict[str, Any]]:
    """One assessment per relevant component; never mutate captured evidence."""
    si = data.get("system") or {}
    bios = _row("BIOS", {"name": si.get("model") or "BIOS"}, si.get("bios_version"), "ESXi 9.1")
    bios["reason"] = (
        "OEM BIOS currency/security baseline does not establish ESXi 9.1 firmware support; verify server BCG / OEM support matrix."
    )
    bios["bcg_url"], bios["bcg_label"] = server_bcg_reference(data)
    rows = [bios, _bmc_row(data)]
    rows.extend(_device_row("NIC", nic, hcl) for nic in data.get("network_adapters") or [])
    for ctrl in data.get("storage_subsystem") or []:
        name = str(ctrl.get("name") or ctrl.get("ctrl_model") or "").lower()
        if not (
            ctrl.get("is_boot_ctrl") or ctrl.get("is_software_raid") or ctrl.get("is_vmd") or "direct attached" in name
        ):
            rows.append(_device_row("HBA/RAID", ctrl, hcl, osa=True))
        for drive in ctrl.get("drives") or []:
            protocol = str(drive.get("protocol") or drive.get("bus_protocol") or drive.get("interface") or "").upper()
            if "NVME" in protocol or "NVME" in str(drive.get("media_type") or "").upper():
                rows.append(_device_row("NVMe", drive, hcl))
    adapters: dict[str, Any] = {}
    for hba in normalize_fc_ports(data.get("fc_hbas") or []):
        # Preserve distinct adapters; collapse ports only with physical identity.
        identity = fc_adapter_key(hba)
        row = _device_row("HBA/RAID", hba, hcl)
        if identity and identity in adapters:
            previous = adapters[identity]
            if previous["installed"] != row["installed"]:
                previous.update(
                    installed=" / ".join((previous["installed"], row["installed"])),
                    upgrade="Incomplete",
                    ready=None,
                    reason="Conflicting firmware reported across ports of this adapter; verify installed build.",
                )
            continue
        if identity:
            adapters[identity] = row
        rows.append(row)
    for kind in ("NIC", "NVMe", "HBA/RAID"):
        if not any(r["kind"] == kind for r in rows):
            row = _row(kind, {"name": "Not reported"}, "", "vSAN OSA 9.1" if kind == "HBA/RAID" else "ESXi 9.1")
            row["reason"] = "No applicable component inventory reported; confirm presence / applicability."
            rows.append(row)
    for row in rows:
        row["reason_class"] = classify_assessment_reason(row)
    return rows


def upgrade_summary(rows: list[dict[str, Any]]) -> list[tuple]:
    result = []
    for kind in KINDS:
        statuses = [r["upgrade"] for r in rows if r["kind"] == kind]
        status = "Yes" if "Yes" in statuses else "No" if statuses and all(s == "No" for s in statuses) else "Incomplete"
        cell = upgrade_cell(status)
        result.append((status, "yellow") if kind == "BMC" and status == "Yes" else cell)
    return result


def nic_readiness(rows: list[dict[str, Any]]) -> tuple:
    states = [r["ready"] for r in rows if r["kind"] == "NIC"]
    if not states or None in states:
        return "Incomplete", "yellow"
    if all(states):
        return "Yes", "green"
    return ("Some", "yellow") if any(states) else ("No", "red")


def firmware_cells(data: dict, rows: list[dict[str, Any]]) -> list[list]:
    si = data.get("system") or {}
    host = str(si.get("ip") or si.get("bmc_ip") or data.get("host") or "")
    return [
        [
            host,
            str(si.get("hostname") or ""),
            r["kind"],
            r["name"],
            r["device_id"],
            r["installed"],
            r["target"],
            r["supported"],
            (r["upgrade"], "yellow") if r["kind"] == "BMC" and r["upgrade"] == "Yes" else upgrade_cell(r["upgrade"]),
            r["reason"],
            r.get("reason_class") or classify_assessment_reason(r),
            r["bcg_label"],
        ]
        for r in rows
    ]
