"""Bounded boot-option acquisition and pure persistent/override evidence resolution."""
import re
from typing import Any, Dict, Optional

from vcf_hci.collector.contracts import SystemCollector


def _clean_boot_name(raw_name: str) -> str:
    cleaned = re.sub(r"^(?:Unavailable:\s*)+", "", str(raw_name or "").strip(), flags=re.I).strip()
    return cleaned or str(raw_name or "").strip()


def parse_boot_override(data: dict) -> dict:
    """Keep active/dormant overrides separate from persistent configuration."""
    # Boot mode & boot target extraction
    boot_obj = data.get("Boot") or {}
    override_target = str(boot_obj.get("BootSourceOverrideTarget") or "").strip()
    override_enabled = str(boot_obj.get("BootSourceOverrideEnabled") or "Disabled").strip()
    override_mode = str(boot_obj.get("BootSourceOverrideMode") or "").strip()

    is_override_active = (
        override_enabled.lower() not in ("disabled", "", "none", "null")
        and override_target.lower() not in ("none", "n/a", "", "null", "nonespecified")
    )
    boot_override = {
        "is_active": is_override_active,
        "target": override_target if is_override_active else "None",
        "enabled": override_enabled,
        "mode": override_mode,
    }

    # Determine persistent boot_mode (do not assume dormant override_mode=Legacy is persistent)
    system_boot_mode = str(boot_obj.get("BootMode") or "").strip()
    if is_override_active and override_mode:
        boot_mode = override_mode
    elif system_boot_mode:
        boot_mode = system_boot_mode
    elif not is_override_active and override_mode.upper() == "UEFI":
        boot_mode = "UEFI"
    else:
        boot_mode = ""  # Defer to BIOS attributes and boot order details below

    return {"boot_mode": boot_mode, "boot_order": boot_obj.get("BootOrder") or [],
            "boot_override": boot_override, "override_target": override_target,
            "override_mode": override_mode, "is_override_active": is_override_active,
            "_boot_object": boot_obj}


def normalize_boot_option(opt_data: dict, b_opt_id: str, target_cand: Optional[str]) -> tuple:
    """Decode explicit enabled state and retain first enabled/unknown priority."""
    reported_enabled = opt_data.get("BootOptionEnabled")
    is_enabled = reported_enabled if isinstance(reported_enabled, bool) else None
    raw_dname = opt_data.get("DisplayName") or opt_data.get("Name") or opt_data.get("Description") or b_opt_id
    clean_dname = _clean_boot_name(raw_dname)
    uefi_path = opt_data.get("UefiDevicePath") or ""
    opt_ref = opt_data.get("BootOptionReference") or opt_data.get("Id") or b_opt_id

    is_current = False
    if is_enabled is not False and not target_cand:
        target_cand = clean_dname
        is_current = True

    return {'id': str(opt_ref), 'name': clean_dname, 'raw_name': str(raw_dname), 'enabled': is_enabled, 'uefi_path': str(uefi_path), 'is_current': is_current}, target_cand


def collect_boot_options(self: SystemCollector, data: dict, boot_order: Any) -> tuple:
    """Preserve inline/linked acquisition, alias indexing and 50/30 endpoint bounds."""
    boot_obj = data.get("Boot") or {}
    boot_order_details = []
    persistent_boot_target = ""
    boot_opts_ref = boot_obj.get("BootOptions") or {}
    opts_uri = (
        boot_opts_ref.get("@odata.id")
        if isinstance(boot_opts_ref, dict) and boot_opts_ref.get("@odata.id")
        else f"{self.sys_uri}/BootOptions" if getattr(self, "sys_uri", None) else None
    )

    if opts_uri:
        clean_opts_uri = opts_uri.rstrip("/")
        members = self._get_members(opts_uri, limit=50)

        # Pre-index collection members by BootOptionReference, Id, and URI tail
        # so servers indexing BootOptions by number (e.g. /BootOptions/1 -> BootOptionReference: Boot0005)
        # resolve EFI BootOrder entries correctly.
        boot_opts_by_ref: Dict[str, Dict[str, Any]] = {}
        for m in members:
            m_uri = m.get("@odata.id") if isinstance(m, dict) else (m if isinstance(m, str) else None)
            if not m_uri:
                continue
            if isinstance(m, dict) and len(m) > 2 and (m.get("DisplayName") or m.get("Name") or m.get("BootOptionReference")):
                opt_data = m
            else:
                opt_data = self._get(m_uri, critical=False)
            if not isinstance(opt_data, dict):
                continue

            for k in [
                str(opt_data.get("BootOptionReference") or "").strip(),
                str(opt_data.get("Id") or "").strip(),
                str(m_uri).rstrip("/").split("/")[-1].strip(),
            ]:
                if k:
                    boot_opts_by_ref[k] = opt_data
                    boot_opts_by_ref[k.lower()] = opt_data
                    boot_opts_by_ref[k.upper()] = opt_data

        opt_ids_to_fetch = [str(x).strip() for x in boot_order if str(x).strip()] if isinstance(boot_order, list) else []
        if not opt_ids_to_fetch:
            for m in members:
                if isinstance(m, dict):
                    m_uri = m.get("@odata.id") or ""
                    m_id = m.get("Id") or (m_uri.rstrip("/").split("/")[-1] if m_uri else None)
                    if m_id:
                        opt_ids_to_fetch.append(str(m_id))
                elif isinstance(m, str) and m:
                    opt_ids_to_fetch.append(m.rstrip("/").split("/")[-1])

        target_cand = None
        for b_opt_id in opt_ids_to_fetch[:30]:
            opt_data = (
                boot_opts_by_ref.get(b_opt_id)
                or boot_opts_by_ref.get(b_opt_id.lower())
                or boot_opts_by_ref.get(b_opt_id.upper())
            )
            if not opt_data:
                item_uri = b_opt_id if b_opt_id.startswith("/") else f"{clean_opts_uri}/{b_opt_id}"
                opt_data = self._get(item_uri, critical=False)
            if not isinstance(opt_data, dict):
                continue
            record, target_cand = normalize_boot_option(opt_data, b_opt_id, target_cand)
            boot_order_details.append(record)

        if target_cand:
            persistent_boot_target = target_cand

    return boot_order_details, persistent_boot_target


def normalize_boot_evidence(boot_obj: dict, seed: dict, boot_order_details: list, persistent_boot_target: str) -> dict:
    """Resolve effective and persistent targets over supplied option observations."""
    override_target, is_override_active = seed["override_target"], seed["is_override_active"]
    if not persistent_boot_target:
        if override_target and override_target.lower() not in ("none", "n/a", "null", "nonespecified"):
            persistent_boot_target = _clean_boot_name(override_target)

    if is_override_active:
        boot_target = _clean_boot_name(override_target)
    elif persistent_boot_target:
        boot_target = persistent_boot_target
    else:
        raw_target = str(boot_obj.get("BootSourceOverrideTarget") or "N/A").strip()
        boot_target = _clean_boot_name(raw_target) if raw_target.lower() not in ("none", "n/a", "null", "nonespecified") else "None"

    return {"boot_mode": seed["boot_mode"], "boot_target": boot_target, "persistent_boot_target": persistent_boot_target, "boot_order": seed["boot_order"], "boot_order_details": boot_order_details, "boot_override": seed["boot_override"]}


def infer_boot_mode(data: dict, boot_order_details: list, bios_attrs: dict, override_mode: str) -> str:
    """Infer mode only when explicit/current evidence left it unknown."""
    boot_mode_attr = str(bios_attrs.get("BootModeSelect") or bios_attrs.get("BootMode") or bios_attrs.get("SystemBootMode") or "").strip().upper()
    csm_attr = str(bios_attrs.get("CSMSupport") or "").strip().upper()

    has_uefi_entry = any(
        ("uefi" in str(b.get("uefi_path", "")).lower())
        or ("uefi" in str(b.get("name", "")).lower())
        or ("uefi" in str(b.get("raw_name", "")).lower())
        or ("esxi" in str(b.get("name", "")).lower())
        for b in boot_order_details
    )
    has_secure_boot = bool(data.get("SecureBoot")) or str(bios_attrs.get("SecureBootEnable", "")).lower() in ("true", "enabled", "1")

    if (
        boot_mode_attr in ("UEFI", "PURE_UEFI")
        or (boot_mode_attr and "UEFI" in boot_mode_attr)
        or has_uefi_entry
        or has_secure_boot
    ):
        boot_mode = "UEFI"
    elif boot_mode_attr in ("LEGACY", "BIOS", "DUAL"):
        boot_mode = "Legacy"
    elif override_mode:
        boot_mode = override_mode
    else:
        boot_mode = "Unknown"

    return boot_mode


def collect_system_boot(self: SystemCollector, data: dict) -> dict:
    """Acquire options, resolve targets, then perform only the original conditional BIOS read."""
    seed = parse_boot_override(data)
    details, persistent = collect_boot_options(self, data, seed["boot_order"])
    result = normalize_boot_evidence(seed["_boot_object"], seed, details, persistent)
    if not result["boot_mode"] or result["boot_mode"].lower() in ("unknown", "none", "n/a"):
        bios_ref = data.get("Bios") or {}
        bios_uri = bios_ref.get("@odata.id") if isinstance(bios_ref, dict) else (f"{self.sys_uri}/Bios" if self.sys_uri else None)
        bios_attrs = {}
        if bios_uri:
            bios_json = self._get(bios_uri, critical=False) or {}
            bios_attrs = bios_json.get("Attributes") or {}
            if not isinstance(bios_attrs, dict):
                bios_attrs = {}

        result["boot_mode"] = infer_boot_mode(data, details, bios_attrs, seed["override_mode"])
    return result
