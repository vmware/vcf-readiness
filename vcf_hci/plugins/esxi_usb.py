"""Adapter for the ESXi SSH to USB BMC scanner.

The scanner itself lands from another branch. This module is the only call
site the wizard uses. When that branch is merged, point ``scan_via_esxi`` at
its public function if the import path differs.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Mapping, Optional, Sequence


class EsxiUsbUnavailable(RuntimeError):
    """The USB BMC scanner branch is not in this checkout."""


def targets_from_property_rows(rows: Sequence[Mapping[str, Any]]) -> list:
    """Turn vCenter HostSystem property rows into wizard target rows."""
    targets = []
    for row in rows:
        name = str(row.get("name") or "").strip()
        def attr(obj, key, default=None):
            return obj.get(key, default) if isinstance(obj, Mapping) else getattr(obj, key, default)
        vnics = row.get("config.network.vnic") or ()
        selected = set()
        for config in row.get("config.virtualNicManagerInfo.netConfig") or ():
            if str(attr(config, "nicType", "")).lower() == "management":
                selected.update(attr(config, "selectedVnic", ()) or ())
        candidates = []
        for vnic in vnics:
            address = _vnic_address(vnic)
            try:
                valid = ipaddress.ip_address(address)
            except ValueError:
                continue
            if valid.is_link_local or valid.is_loopback or valid.is_unspecified:
                continue
            if selected and attr(vnic, "key", "") not in selected:
                continue
            candidates.append(address)
        address = candidates[0] if len(set(candidates)) == 1 else ""
        target = {"name": name, "management_ip": address, "key": str(row.get("key") or "")}
        identity = row.get("hardware.systemInfo")
        if identity is not None:
            def value(field, source=identity):
                return source.get(field, "") if isinstance(source, Mapping) else getattr(source, field, "")
            target.update(uuid=str(value("uuid") or ""), serial=str(value("serialNumber") or ""))
        ipmi = row.get("config.ipmi")
        if ipmi is not None:
            candidate = ipmi.get("bmcIpAddress", "") if isinstance(ipmi, Mapping) else getattr(ipmi, "bmcIpAddress", "")
            target["bmc_ip_candidate"] = str(candidate or "").strip("\x00 ")
        targets.append(target)
    return targets


def _vnic_address(vnic: Any) -> str:
    if isinstance(vnic, Mapping):
        spec = vnic.get("spec") or {}
        ip = spec.get("ip") if isinstance(spec, Mapping) else {}
        if isinstance(ip, Mapping):
            return str(ip.get("ipAddress") or "").strip()
        return ""
    spec = getattr(vnic, "spec", None)
    ip = getattr(spec, "ip", None) if spec is not None else None
    return str(getattr(ip, "ipAddress", "") or "").strip()


def scan_via_esxi(
    host: str,
    ssh_user: str,
    ssh_password: str,
    host_key_pin: str,
    options: Optional[Mapping[str, Any]] = None,
) -> Any:
    """Run one host through the merged scanner, or fail closed if it is absent."""
    if not host or not ssh_user or not ssh_password:
        raise ValueError("ESXi SSH needs a host, username, and password.")
    if not host_key_pin:
        raise ValueError("Pin the ESXi SSH host key before scanning.")
    try:
        from vcf_hci.remote.esxi_usb_scanner import scan_host
    except ImportError as exc:
        raise EsxiUsbUnavailable(
            "ESXi SSH to USB BMC is not in this build. Merge that branch, then rerun this wizard step."
        ) from exc
    return scan_host(host, ssh_user, ssh_password, host_key_pin, options or {})
