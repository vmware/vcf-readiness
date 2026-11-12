"""Deterministic salted obfuscation for vSphere Inventory snapshots."""

from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from typing import Dict, List, Optional, Tuple

from vcf_hci.plugins.vinv.constants import TAB_HEADERS
from vcf_hci.plugins.vinv.models import VinvSnapshot, VinvTab

_SENSITIVE_COLUMN_KINDS: Dict[str, str] = {
    "VM": "VM",
    "DNS Name": "DNS",
    "Primary IP Address": "IP",
    "IPv4 Address": "IP",
    "IP Address": "IP",
    "IP 6 Address": "IP6",
    "IPv6 Address": "IP6",
    "NetFlow Collector IP": "IP",
    "Console": "IP",
    "Gateway": "IP",
    "IP 6 Gateway": "IP6",
    "DNS Servers": "IP",
    "Host": "Host",
    "Hosts": "Host",
    "ESXi Host": "Host",
    "VI SDK Server": "vCenter",
    "vCenter Server": "vCenter",
    "Mac Address": "MAC",
    "MAC": "MAC",
    "Service tag": "SN",
    "Serial": "SN",
    "OEM specific string": "SN",
    "SMBIOS UUID": "UUID",
    "VM UUID": "UUID",
    "UUID": "UUID",
    "Disk UUID": "UUID",
    "VI SDK UUID": "UUID",
    "vCenter UUID": "UUID",
    "Raw LUN ID": "UUID",
    "WWN / IQN / NQN": "WWN",
    "Key": "LIC",
    "Annotation": "NOTE",
    "Description": "NOTE",
    "Contact": "USER",
    "Admin Name": "USER",
    "Owner": "USER",
    "Domain": "DOM",
    "Search domains": "DOM",
    "NTP Server(s)": "NTP",
    "CDP Switch": "SW",
    "LLDP Chassis ID": "SW",
    "LLDP System Name": "SW",
    "Datacenter": "DC",
    "Cluster": "CL",
    "Cluster name": "CL",
    "Scope Cluster": "CL",
    "Datastore": "DS",
    "Folder": "FOLDER",
    "Resource pool": "RP",
    "vApp": "RP",
    "Network #1": "PG",
    "Network #2": "PG",
    "Network #3": "PG",
    "Cluster rule name(s)": "NOTE",
    "Collection Warnings": "NOTE",
    "Network #4": "PG",
    "Network #5": "PG", "Network #6": "PG", "Network #7": "PG", "Network #8": "PG",
    "Serial number": "SN", "Serial #": "SN", "WWN": "WWN",
    "DNS Search Order": "DOM", "Domain List": "DOM",
    "Certificate Issuer": "CERT", "Certificate Subject": "CERT",
    "Guest Detailed Data": "NOTE", "Customization Info": "NOTE",
    "Assigned License(s)": "LIC", "Host members": "Host", "Server": "vCenter",
    "Disk": "LUN",
    "Network": "PG",
    "Port Group": "PG",
    "Address": "PATH",
    "URL": "PATH",
    "vSAN Fault Domain Name": "SITE",
    "LACP Name": "DVS",
    "Object ID": "ID",
    "VM ID": "ID",
    "VMRef": "ID",
    "Folder ID": "ID",
    "Disk Key": "ID",
    "Device": "DEVICE",
    "Device Node": "DEVICE",
    "Network Device": "DEVICE",
    "Uplink port": "PORT",
    "PCI": "PCI",
    "Pci": "PCI",
    "Bus": "BUS",
    "Label": "LABEL",
    "Path 1": "PATH", "Path 2": "PATH", "Path 3": "PATH", "Path 4": "PATH",
    "Path 5": "PATH", "Path 6": "PATH", "Path 7": "PATH", "Path 8": "PATH",
    "CDP Port": "PORT", "LLDP Port ID": "PORT",
    "NIC label": "DEVICE", "Controller": "DEVICE", "NetStack": "NET",
    "Active Uplink": "PORT", "Active Uplinks": "PORT",
    "Standby Uplink": "PORT", "Standby Uplinks": "PORT", "Uplinks": "PORT",
    "Labels": "NOTE", "Cluster Settings": "NOTE",
    "Subnet mask": "NET", "VLAN": "NET", "CDP VLAN": "NET",
}

_TAB_COLUMN_KINDS: Dict[str, Dict[str, str]] = {
    "vCluster": {"Name": "CL"},
    "vSource": {"Name": "vCenter"},
    "vDatastore": {"Name": "DS"},
    "vRP": {"Resource Pool name": "RP", "Resource Pool path": "PATH"},
    "vNetwork": {"Switch": "DVS"},
    "vNIC": {"Switch": "DVS"},
    "vSwitch": {"Switch": "DVS"},
    "vPort": {"Switch": "DVS"},
    "dvSwitch": {"Switch": "DVS", "Name": "DVS"},
    "dvPort": {"Port": "PG", "Switch": "DVS"},
    "vSnapshot": {"Name": "SNAP"},
    "vHealth": {"Name": "OBJ"},
    "vMultiPath": {"Display name": "LUN", "Object ID": "ID"},
}

_PATH_COLUMNS = frozenset({
    "Path", "Disk Path", "Filename", "Log directory", "Snapshot directory", "Suspend directory",
    "Friendly Path Name", "File Name", "Internal Sort Column",
})
_LIST_KINDS = frozenset({"Host", "IP", "IP6", "DOM", "NTP", "CL", "DS"})
_QUOTED = re.compile(r"'([^']*)'")
_STATUS_WORD = re.compile(r"^[a-z][A-Za-z]*$|^CD/DVD drive \d+$")


def _token(salt: str, prefix: str, value: str) -> str:
    clean = value.strip()
    if not clean or clean in ("—", "-", "N/A", "Unknown", "All Clusters"):
        return clean
    digest = hashlib.sha256(f"{salt}:{prefix}:{clean}".encode()).hexdigest()[:8].upper()
    if prefix == "IP":
        b1 = (int(digest[:2], 16) % 250) + 1
        b2 = (int(digest[2:4], 16) % 250) + 1
        return f"192.0.2.{b1}" if b1 != b2 else f"198.51.100.{b1}"
    if prefix == "IP6":
        return f"2001:db8::{digest[:4].lower()}:{digest[4:].lower()}"
    if prefix == "MAC":
        return f"02:00:{digest[0:2]}:{digest[2:4]}:{digest[4:6]}:{digest[6:8]}".lower()
    if prefix == "LIC":
        return "00000-00000-00000-00000-00000"
    if prefix == "DOM":
        return "rainpole.net"
    return f"{prefix}-{digest}"


def _scrub(salt: str, kind: str, value: str, aliases: Dict[str, str]) -> str:
    if kind in _LIST_KINDS and "," in value:
        return ", ".join(_scrub(salt, kind, part.strip(), aliases) for part in value.split(",") if part.strip())
    if kind == "Host" and value in aliases:
        return aliases[value]
    return _token(salt, kind, value)


def _scrub_message(salt: str, message: str) -> str:
    def repl(match: re.Match[str]) -> str:
        inner = match.group(1)
        return match.group(0) if _STATUS_WORD.match(inner) else f"'{_token(salt, 'OBJ', inner)}'"
    return _QUOTED.sub(repl, message)


def obfuscate_vinv_snapshot(
    snapshot: VinvSnapshot,
    salt: str,
    host_alias_map: Optional[Dict[str, str]] = None,
) -> VinvSnapshot:
    """Return a copy of VinvSnapshot with sensitive identifiers deterministically tokenized."""
    aliases = dict(host_alias_map or {})
    vc_token = _token(salt, "vCenter", snapshot.vcenter_server)
    vc_uuid_token = _token(salt, "UUID", snapshot.vcenter_uuid) if snapshot.vcenter_uuid else ""

    new_tabs: List[VinvTab] = []
    for tab in snapshot.tabs:
        overrides = _TAB_COLUMN_KINDS.get(tab.name, {})
        new_rows: List[Tuple[str, ...]] = []
        for row in tab.rows:
            out_cells: List[str] = []
            for idx, col in enumerate(tab.headers):
                val = row[idx] if idx < len(row) else ""
                kind = overrides.get(col) or _SENSITIVE_COLUMN_KINDS.get(col)
                if not val:
                    out_cells.append("")
                elif tab.name == "vHealth" and col == "Message":
                    out_cells.append(_token(salt, "NOTE", val))
                elif tab.name == "vHealth" and col == "Name" and val in aliases:
                    out_cells.append(aliases[val])
                elif col not in TAB_HEADERS.get(tab.name, ()):
                    out_cells.append(_token(salt, "CUSTOM", val))
                elif kind:
                    out_cells.append(_scrub(salt, kind, val, aliases))
                elif col in _PATH_COLUMNS:
                    out_cells.append(_token(salt, "PATH", val))
                else:
                    out_cells.append(val)
            new_rows.append(tuple(out_cells))
        new_headers = tuple(h if h in TAB_HEADERS.get(tab.name, ()) else _token(salt, "CUSTOM", h) for h in tab.headers)
        new_tabs.append(VinvTab(name=tab.name, headers=new_headers, rows=tuple(new_rows)))

    return replace(
        snapshot,
        vcenter_server=vc_token,
        vcenter_uuid=vc_uuid_token,
        scope_cluster=_scrub(salt, "CL", snapshot.scope_cluster, aliases),
        warnings=tuple(_token(salt, "NOTE", w) for w in snapshot.warnings),
        tabs=tuple(new_tabs),
    )
