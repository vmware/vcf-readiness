"""Public BIOS advisory evidence, separate from firmware currency and CPU floors."""


import datetime
import re
from typing import Optional

_SOURCE_FIX_DATE = datetime.date(2026, 10, 15)


def _network_boot_kind(option: dict) -> str:
    text = " ".join(str(option.get(key) or "") for key in ("name", "raw_name", "uefi_path"))
    if re.search(r"\bipxe(?:\w*\.efi)?\b|\b(?:snponly|snp)(?:64)?\.efi\b", text, re.I):
        return "ipxe"
    if re.search(r"\bpxe\b", text, re.I):
        return "pxe"
    # Common BootOption labels/device paths omit the word PXE. HTTP/iSCSI
    # paths can also contain IP nodes, so do not treat those as PXE evidence.
    if not re.search(r"https?[:(/ ]|\b(?:iscsi|nvme)\b|\buri\(", text, re.I):
        if re.search(r"\bipv[46]\b", text, re.I):
            return "pxe"
    return ""


def _bios_date_context(value: object) -> dict:
    parsed = None
    if isinstance(value, str):
        raw = value.strip()
        try:
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:T\S+)?", raw):
                parsed = datetime.date.fromisoformat(raw[:10])
            elif re.fullmatch(r"\d{1,2}/\d{1,2}/\d{4}", raw):
                month, day, year = map(int, raw.split("/"))
                parsed = datetime.date(year, month, day)
        except ValueError:
            parsed = None
    if parsed and parsed > datetime.datetime.now(datetime.timezone.utc).date():
        parsed = None
    predates = parsed < _SOURCE_FIX_DATE if parsed else None
    note = (
        "BIOS predates the 2026-10-15 upstream source fix; prioritize vendor review."
        if predates else
        "BIOS date is on or after the upstream source fix; this does not verify an OEM patch."
        if parsed else
        "BIOS release date unavailable or invalid; patch coverage cannot be inferred."
    )
    return {"bios_predates_source_fix": predates, "date_note": note,
            "source_fix_date": _SOURCE_FIX_DATE.isoformat()}


def _pxe_exposure(system: dict) -> dict:
    evidence = []
    options = system.get("boot_order_details")
    if not isinstance(options, list):
        options = []
    if not options and isinstance(system.get("boot_order"), list):
        options = [{"name": str(name)} for name in system["boot_order"]]
    for index, option in enumerate(options):
        if not isinstance(option, dict):
            continue
        kind = _network_boot_kind(option)
        if kind:
            enabled = option.get("enabled")
            evidence.append({
                "source": "boot_order_details", "position": index + 1,
                "name": str(option.get("name") or option.get("raw_name") or option.get("uefi_path") or ""),
                "kind": kind, "enabled": enabled if isinstance(enabled, bool) else None,
                "mode": str(system.get("raw_boot_mode") or system.get("boot_mode") or ""),
            })
    override = system.get("boot_override")
    if isinstance(override, dict):
        enabled = str(override.get("enabled") or "").lower()
        active = (override.get("is_active") is not False and enabled in ("once", "continuous")) or (
            override.get("is_active") is True and not enabled
        )
        kind = _network_boot_kind({"name": override.get("target")})
        if active and kind:
            evidence.append({"source": "boot_override", "name": str(override.get("target")),
                             "kind": kind, "enabled": True,
                             "mode": str(override.get("mode") or system.get("boot_mode") or "")})

    enabled_pxe = [item for item in evidence if item["kind"] == "pxe" and item["enabled"] is True]
    # Explicit legacy-only evidence cannot establish execution of the UEFI driver.
    uefi_possible = [item for item in enabled_pxe if str(item["mode"]).strip().upper() not in ("LEGACY", "BIOS", "CSM")]
    if uefi_possible:
        exposure, label, badge = "potential", "Potential PXE firmware exposure", "warning"
        note = "Enabled PXE boot option or active PXE override detected, including any fallback entry."
        if not any("UEFI" in str(item["mode"]).upper() for item in uefi_possible):
            note += " Boot mode is unverified; confirm which firmware PXE implementation executes."
    elif any(item["kind"] == "ipxe" and item["enabled"] is True for item in evidence):
        exposure, label, badge = "ipxe_path_unverified", "iPXE boot path unverified", "warning"
        note = "iPXE may be chainloaded through firmware PXE; the label alone does not prove the affected driver is bypassed."
    elif enabled_pxe:
        exposure, label, badge = "legacy_pxe", "Legacy PXE observed; UEFI exposure unverified", "info"
        note = "Reported legacy PXE does not establish use of the affected UEFI driver; other boot paths remain unverified."
    elif evidence and all(item["enabled"] is False for item in evidence):
        exposure, label, badge = "listed_entries_disabled", "Listed network boot entries disabled", "info"
        note = "These listed entries are disabled; this does not prove all PXE paths or firmware network stacks are disabled."
    else:
        exposure, label, badge = "unknown", "PXE exposure unknown", "info"
        note = "Network boot enablement is unreported or incomplete; disk-first boot and absent entries do not prove PXE disabled."
    return {"exposure_status": exposure, "exposure_label": label, "badge": badge,
            "exposure_note": note, "boot_evidence": evidence}


def evaluate_bios_advisories(system_info: Optional[dict] = None) -> list:
    """Return tracked advisories without inventing OEM affected/fixed ranges.

    Until a model/ROM-family-specific OEM bulletin supplies a fixed release,
    every platform remains unverified. A newer BIOS or disabled PXE does not
    establish that the vulnerable firmware code has been patched.
    """
    system = system_info if isinstance(system_info, dict) else {}
    exposure = _pxe_exposure(system)
    date_context = _bios_date_context(system.get("bios_release_date"))
    return [{
        "cve": "CVE-2026-97631",
        "title": "EDK II PXE pre-boot code execution",
        "status": "unverified",
        "label": "OEM fix not verified",
        **exposure,
        **date_context,
        "review_priority": "elevated" if exposure["exposure_status"] == "potential" and date_context["bios_predates_source_fix"] else "standard",
        "affected_status": "unknown",
        "fixed_version": None,
        "patch_verified": False,
        "checked_on": "2026-10-29",
        "source_url": "https://github.com/tianocore/edk2/security/advisories/GHSA-99cj-7hg9-mp4m",
        "patch_url": "https://github.com/tianocore/edk2/pull/13302",
        "note": (
            "An upstream source fix exists; an OEM BIOS containing this fix has not been verified "
            "for this platform in this tool's advisory data. Confirm the exact model and ROM family "
            "with the server vendor. Exposure requires PXE boot over IPv4 or IPv6 and delivery of "
            "ICMP error traffic during boot. Review PXE settings and disable unused network boot; "
            "isolate required provisioning networks. Local-disk boot order alone does not prove "
            "PXE is disabled. TPM, Secure Boot and historical BIOS security floors do not establish "
            "protection against this flaw."
        ),
    }]
