"""
VCF Readiness Tool — PII obfuscation helpers.

Replaces IPs, MACs, serial numbers, and WWNs with deterministic hash tokens
so reports can be shared externally without exposing customer data.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import html
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from vcf_hci.constants import TOOL_VERSION
from vcf_hci.security.redaction import (
    obfuscate_security_data,
    redact_security_findings,
)


class ObfuscationKey:
    """Collects real→token pairs while obfuscating a fleet (for private key export)."""

    def __init__(self, salt: str):
        self.salt = salt
        self.host_aliases: Dict[str, dict] = {}
        self.mapping: Dict[str, dict] = {}
        self.forward: Dict[str, str] = {}

    def record(self, kind: str, real: Any, token: Any) -> None:
        if not real or real in ("N/A", "Unknown", "", "REDACTED", "—"):
            return
        real_s = str(real)
        token_s = str(token)
        self.forward[real_s] = token_s
        self.mapping[token_s] = {"real": real_s, "kind": kind}

    def to_dict(self) -> dict:
        return {
            "version": 1,
            "tool_version": TOOL_VERSION,
            "salt": self.salt,
            "host_aliases": self.host_aliases,
            "forward": self.forward,
            "mapping": self.mapping,
            "note": "KEEP PRIVATE. Maps obfuscated tokens back to real customer values.",
        }


def _obf_hash(salt: str, value: str, length: int = 8) -> str:
    """Deterministic short hex token: same salt+value → same output."""
    raw = f"{salt}:{value}".encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:length].upper()


def _obf_mac(salt: str, value: str) -> str:
    """Hash a MAC address to a locally-administered MAC (02: prefix)."""
    h = _obf_hash(salt, value, 10)
    return f"02:{h[0:2]}:{h[2:4]}:{h[4:6]}:{h[6:8]}:{h[8:10]}"


def _obf_wwn(salt: str, value: str) -> str:
    """Hash a WWN/WWPN to an 8-byte colon-separated token."""
    if not value or str(value).strip() in ("", "N/A", "Unknown", "—", "REDACTED"):
        return str(value or "")
    h = _obf_hash(salt, value, 16)
    return ":".join(h[i:i+2] for i in range(0, 16, 2))


def _obf_ip(salt: str, value: str) -> str:
    """Hash an IP to an RFC 5737 TEST-NET-1 address (192.0.2.x) — obviously fake."""
    n = int(_obf_hash(salt, value, 4), 16) % 254 + 1
    return f"192.0.2.{n}"


def _obf_label(salt: str, prefix: str, value: str) -> str:
    """Hash a string to a prefixed token, e.g. 'SN-D04C1E' or 'switch-A3F9B2'."""
    return f"{prefix}-{_obf_hash(salt, value, 6)}"


def _obf_nqn(salt: str, value: str) -> str:
    """Hash an NVMe Qualified Name (NQN) to a deterministic fictitious Rainpole token."""
    h = _obf_hash(salt, value, 12).lower()
    val_low = str(value).lower()
    if "host" in val_low:
        return f"nqn.2014-08.io.rainpole:host-{h}"
    return f"nqn.2014-08.io.rainpole:subsys-{h}"


def _obf_iqn(salt: str, value: str) -> str:
    """Hash an iSCSI Qualified Name (IQN) to a deterministic fictitious Rainpole token."""
    h = _obf_hash(salt, value, 12).lower()
    return f"iqn.1998-01.io.rainpole:target-{h}"


def _obf_eui(salt: str, value: str) -> str:
    """Hash an EUI-64 identifier to a deterministic token."""
    h = _obf_hash(salt, value, 16).lower()
    return f"eui.{h}"


def _pii_span(page_salt: str, real_val: Optional[str], prefix: str = "") -> str:
    """Wrap a sensitive value in a <span class='pii'> for the in-browser mask toggle.

    The data-mask attribute holds the hash token (computed server-side using a
    per-page random salt so the token cannot be reverse-engineered from the HTML).
    Same real_val within the same page always maps to the same token, so a viewer
    checking the box can still spot that two entries share the same underlying value.
    """
    if not real_val or real_val in ("N/A", "Unknown", "REDACTED", "—", ""):
        return html.escape(str(real_val), quote=True).replace("'", "&#39;") if real_val is not None else ""
    p_low = prefix.lower()
    if p_low == "nqn":
        mask = _obf_nqn(page_salt, real_val)
    elif p_low == "iqn":
        mask = _obf_iqn(page_salt, real_val)
    elif p_low == "eui":
        mask = _obf_eui(page_salt, real_val)
    elif p_low in ("wwn", "wwpn", "wwnn"):
        mask = _obf_wwn(page_salt, real_val)
    elif p_low in ("mac", "mac_address"):
        mask = _obf_mac(page_salt, real_val)
    elif prefix:
        mask = _obf_label(page_salt, prefix, real_val)
    else:
        mask = _obf_hash(page_salt, real_val, 10)
    safe_real = html.escape(str(real_val), quote=True).replace("'", "&#39;")
    return (f"<span class='pii' data-real='{safe_real}' data-mask='{mask}'>"
            f"{safe_real}</span>")


_NQN_RE = re.compile(r"\bnqn\.2014-08\.[a-zA-Z0-9.\-_:]+\b", re.IGNORECASE)
_IQN_RE = re.compile(r"\biqn\.\d{4}-\d{2}\.[a-zA-Z0-9.\-_:]+\b", re.IGNORECASE)
_EUI_RE = re.compile(r"\beui\.[0-9a-fA-F]{16}\b", re.IGNORECASE)


def obfuscate_host_data(
    data: dict,
    host_alias: str,
    salt: str,
    key: Optional[ObfuscationKey] = None,
    strip_raw: bool = False,
) -> dict:
    """Return a deep copy of *data* with all customer-identifying fields replaced.

    Using the same *salt* across multiple hosts ensures identical real values
    (e.g. the same network switch chassis ID) produce the same token in every
    report file, so a reviewer can detect cross-host relationships without
    seeing the actual infrastructure details.

    When *key* is provided, real→token pairs are recorded for private key export.
    """
    def label(s: str, prefix: str, value: str) -> str:
        tok = _obf_label(s, prefix, value)
        if key is not None:
            key.record(prefix.lower(), value, tok)
        return tok

    def mac(s: str, value: str) -> str:
        tok = _obf_mac(s, value)
        if key is not None:
            key.record("mac", value, tok)
        return tok

    def wwn(s: str, value: str) -> str:
        if not value or str(value).strip() in ("", "N/A", "Unknown", "—"):
            return value
        tok = _obf_wwn(s, value)
        if key is not None:
            key.record("wwn", value, tok)
        return tok

    def wwpn(s: str, value: str) -> str:
        if not value or str(value).strip() in ("", "N/A", "Unknown", "—"):
            return value
        tok = _obf_wwn(s, value)
        if key is not None:
            key.record("wwpn", value, tok)
        return tok

    def wwnn(s: str, value: str) -> str:
        if not value or str(value).strip() in ("", "N/A", "Unknown", "—"):
            return value
        tok = _obf_wwn(s, value)
        if key is not None:
            key.record("wwnn", value, tok)
        return tok

    def ip_tok(s: str, value: str) -> str:
        tok = _obf_ip(s, value)
        if key is not None:
            key.record("ip", value, tok)
        return tok

    def nqn(s: str, value: str) -> str:
        tok = _obf_nqn(s, value)
        if key is not None:
            key.record("nqn", value, tok)
        return tok

    def iqn(s: str, value: str) -> str:
        tok = _obf_iqn(s, value)
        if key is not None:
            key.record("iqn", value, tok)
        return tok

    def eui(s: str, value: str) -> str:
        tok = _obf_eui(s, value)
        if key is not None:
            key.record("eui", value, tok)
        return tok

    raw_cap = None if strip_raw else data.get("raw_redfish_capture")
    if "raw_redfish_capture" in data:
        data_to_copy = dict(data)
        data_to_copy.pop("raw_redfish_capture", None)
        d = copy.deepcopy(data_to_copy)
    else:
        d = copy.deepcopy(data)
    si = d.get("system", {})
    real_ip_for_alias = (
        si.get("ip")
        or si.get("bmc_ip")
        or d.get("host")
        or d.get("ip")
        or d.get("bmc_ip")
        or ""
    )
    real_host_for_alias = si.get("hostname") or ""
    if key is not None:
        key.host_aliases[host_alias] = {
            "ip": real_ip_for_alias,
            "hostname": real_host_for_alias,
        }
        if real_ip_for_alias:
            key.record("host_ip", real_ip_for_alias, host_alias)
        if real_host_for_alias:
            key.record("hostname", real_host_for_alias, host_alias)

    si["ip"]            = host_alias
    si["hostname"]      = host_alias
    si["dns_name"]      = None
    if "bmc_ip" in si:
        si["bmc_ip"] = host_alias
    if "host" in d:
        d["host"] = host_alias
    if "ip" in d:
        d["ip"] = host_alias
    if "bmc_ip" in d:
        d["bmc_ip"] = host_alias
    si["serial_number"] = label(salt, "SN",  si.get("serial_number", ""))
    si["asset_tag"]     = label(salt, "TAG", si.get("asset_tag", ""))
    if "system_uuid" in si:
        raw_uuid = si["system_uuid"]
        if raw_uuid and str(raw_uuid).strip() not in ("N/A", "Unknown", "REDACTED", "—", ""):
            si["system_uuid"] = label(salt, "UUID", str(raw_uuid))
    real_sn_orig  = (data.get("system") or {}).get("serial_number", "")
    real_sku_orig = (data.get("system") or {}).get("sku", "")
    real_dns_orig = (data.get("system") or {}).get("dns_name", "")
    if si.get("sku"):
        if real_sku_orig and real_sn_orig and real_sku_orig.strip().upper() == real_sn_orig.strip().upper():
            si["sku"] = ""
        else:
            si["sku"] = label(salt, "SKU", si["sku"])
    for n in d.get("lldp_neighbors", []):
        if n.get("local_mac"):
            n["local_mac"] = mac(salt, n["local_mac"])
        if n.get("switch_name"):
            n["switch_name"] = label(salt, "SW", n["switch_name"])
        if n.get("switch_port"):
            n["switch_port"] = label(salt, "port", n["switch_port"])
        if n.get("chassis_id"):
            n["chassis_id"] = mac(salt, n["chassis_id"])
        if n.get("mgmt_ipv4"):
            n["mgmt_ipv4"] = ip_tok(salt, n["mgmt_ipv4"])
        if n.get("system_desc"):
            desc = str(n["system_desc"])
            desc = re.sub(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}', lambda m: mac(salt, m.group(0)), desc)
            desc = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', lambda m: ip_tok(salt, m.group(0)), desc)
            n["system_desc"] = desc
    for hba in d.get("fc_hbas", []):
        hba["wwpn"] = wwpn(salt, hba.get("wwpn", ""))
        hba["wwnn"] = wwnn(salt, hba.get("wwnn", ""))
        for bt in (hba.get("boot_targets") or []):
            if bt.get("target_wwpn"):
                bt["target_wwpn"] = wwpn(salt, bt["target_wwpn"])
            if bt.get("target_iqn"):
                bt["target_iqn"] = iqn(salt, bt["target_iqn"])
            if bt.get("target_nqn"):
                bt["target_nqn"] = nqn(salt, bt["target_nqn"])
    for ctrl in d.get("storage_subsystem", []):
        if ctrl.get("serial_number"):
            ctrl["serial_number"] = label(salt, "SN", ctrl["serial_number"])
        if ctrl.get("nvme_subsystem_nqn"):
            ctrl["nvme_subsystem_nqn"] = nqn(salt, ctrl["nvme_subsystem_nqn"])
        for drv in ctrl.get("drives", []):
            if drv.get("serial"):
                drv["serial"] = label(salt, "SN", drv["serial"])
            if drv.get("serial_number"):
                drv["serial_number"] = label(salt, "SN", drv["serial_number"])
            if drv.get("part_number"):
                drv["part_number"] = label(salt, "PN", drv["part_number"])
            for id_key in ("eui", "eui_64", "nguid", "nqn", "identifiers"):
                if drv.get(id_key):
                    if isinstance(drv[id_key], str):
                        v_str = drv[id_key]
                        if _NQN_RE.search(v_str):
                            drv[id_key] = _NQN_RE.sub(lambda m: nqn(salt, m.group(0)), v_str)
                        elif _EUI_RE.search(v_str):
                            drv[id_key] = _EUI_RE.sub(lambda m: eui(salt, m.group(0)), v_str)
                        else:
                            drv[id_key] = label(salt, "ID", v_str)
        for enc in ctrl.get("enclosures", []):
            if enc.get("serial_number"):
                enc["serial_number"] = label(salt, "SN", enc["serial_number"])
    # WS-Man path & MAC in NICs
    _mac_re = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
    for nic in d.get("network_adapters", []):
        pn = nic.get("part_number", "")
        if pn and _mac_re.match(pn):
            nic["part_number"] = mac(salt, pn)
        if nic.get("mac_address"):
            nic["mac_address"] = mac(salt, nic["mac_address"])
        if nic.get("permanent_mac_address"):
            nic["permanent_mac_address"] = mac(salt, nic["permanent_mac_address"])
        for port in nic.get("ports", []):
            if port.get("mac_address"):
                port["mac_address"] = mac(salt, port["mac_address"])
            if port.get("permanent_mac_address"):
                port["permanent_mac_address"] = mac(salt, port["permanent_mac_address"])
        for part in nic.get("npar_partitions", []) or []:
            if part.get("mac_address"):
                part["mac_address"] = mac(salt, part["mac_address"])
            if part.get("wwpn"):
                part["wwpn"] = wwpn(salt, part["wwpn"])
            if part.get("wwnn"):
                part["wwnn"] = wwnn(salt, part["wwnn"])
        for vic_vif in nic.get("vic_virtual_interfaces", []) or []:
            if vic_vif.get("mac_address"):
                vic_vif["mac_address"] = mac(salt, vic_vif["mac_address"])
            if vic_vif.get("permanent_mac"):
                vic_vif["permanent_mac"] = mac(salt, vic_vif["permanent_mac"])
            if vic_vif.get("wwpn"):
                vic_vif["wwpn"] = wwpn(salt, vic_vif["wwpn"])
            if vic_vif.get("wwnn"):
                vic_vif["wwnn"] = wwnn(salt, vic_vif["wwnn"])
        if nic.get("name"):
            def _replace_mac_in_name(m):
                return f" - {mac(salt, m.group(1))}"
            nic["name"] = re.sub(r'\s*-\s*(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})$', _replace_mac_in_name, nic["name"])

    for fw in d.get("firmware_inventory", []):
        if fw.get("name"):
            def _replace_mac_in_fw_name(m):
                return f" - {mac(salt, m.group(1))}"
            fw["name"] = re.sub(r'\s*-\s*(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})$', _replace_mac_in_fw_name, fw["name"])

    for gpu in d.get("gpu_accelerators", []):
        if gpu.get("serial_number"):
            gpu["serial_number"] = label(salt, "SN", gpu["serial_number"])
        if gpu.get("part_number"):
            gpu["part_number"] = label(salt, "PN", gpu["part_number"])

    for slot in d.get("pcie_slots", []):
        if slot.get("device_serial"):
            slot["device_serial"] = label(salt, "SN", slot["device_serial"])

    # Memory subsystem & topology DIMM serial numbers
    mem_sub = d.get("memory_subsystem") or {}
    if isinstance(mem_sub, dict):
        for dimm in mem_sub.get("dimm_list", []) or []:
            if isinstance(dimm, dict) and dimm.get("serial_number"):
                dimm["serial_number"] = label(salt, "SN", dimm["serial_number"])
        for dimm in mem_sub.get("failed_dimms", []) or []:
            if isinstance(dimm, dict) and dimm.get("serial_number"):
                dimm["serial_number"] = label(salt, "SN", dimm["serial_number"])
        for dimm in mem_sub.get("dimm_details", []) or []:
            if isinstance(dimm, dict):
                if dimm.get("serial_number"):
                    dimm["serial_number"] = label(salt, "SN", dimm["serial_number"])
                if dimm.get("serial"):
                    dimm["serial"] = label(salt, "SN", dimm["serial"])
                if dimm.get("SerialNumber"):
                    dimm["SerialNumber"] = label(salt, "SN", dimm["SerialNumber"])

    mem_topo = d.get("memory_topology") or {}
    if isinstance(mem_topo, dict):
        for sock_val in mem_topo.values():
            if isinstance(sock_val, dict):
                for chan_val in sock_val.values():
                    if isinstance(chan_val, dict):
                        for dimm in chan_val.get("dimms", []) or []:
                            if isinstance(dimm, dict):
                                if dimm.get("serial_number"):
                                    dimm["serial_number"] = label(salt, "SN", dimm["serial_number"])
                                if dimm.get("serial"):
                                    dimm["serial"] = label(salt, "SN", dimm["serial"])

    # SEL alarms message scrubbing
    real_host_orig = (data.get("system") or {}).get("hostname", "")
    real_ip_orig   = (
        (data.get("system") or {}).get("bmc_ip")
        or (data.get("system") or {}).get("ip", "")
        or data.get("host", "")
        or data.get("ip", "")
        or data.get("bmc_ip", "")
    )
    real_tag_orig  = (data.get("system") or {}).get("asset_tag", "")
    for sel in d.get("sel_alarms", []) or []:
        if isinstance(sel, dict) and sel.get("message"):
            msg = str(sel["message"])
            if real_sn_orig and len(real_sn_orig) > 3:
                msg = msg.replace(real_sn_orig, si["serial_number"])
            if real_host_orig and len(real_host_orig) > 3:
                msg = msg.replace(real_host_orig, host_alias)
            if real_dns_orig and len(real_dns_orig) > 3:
                msg = msg.replace(real_dns_orig, f"{host_alias}.example.com")
            if real_ip_orig and len(real_ip_orig) > 6:
                msg = msg.replace(real_ip_orig, ip_tok(salt, real_ip_orig))
            if real_tag_orig and len(real_tag_orig) > 3:
                msg = msg.replace(real_tag_orig, si["asset_tag"])
            mac_pattern = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b')
            for mac_val in set(mac_pattern.findall(msg)):
                msg = msg.replace(mac_val, mac(salt, mac_val))
            msg = re.sub(r'[a-zA-Z0-9.-]+\.broadcom\.net', 'host.example.com', msg)
            sel["message"] = msg

    # Hostname replacements in NIC names & descriptions and firmware inventory
    for nic in d.get("network_adapters", []) or []:
        if isinstance(nic, dict):
            if nic.get("name") and real_host_orig and len(real_host_orig) > 3:
                nic["name"] = nic["name"].replace(real_host_orig, host_alias)
            if nic.get("description") and real_host_orig and len(real_host_orig) > 3:
                nic["description"] = nic["description"].replace(real_host_orig, host_alias)

    for fw in d.get("firmware_inventory", []) or []:
        if isinstance(fw, dict):
            if fw.get("name") and real_host_orig and len(real_host_orig) > 3:
                fw["name"] = fw["name"].replace(real_host_orig, host_alias)
            if fw.get("description") and real_host_orig and len(real_host_orig) > 3:
                fw["description"] = fw["description"].replace(real_host_orig, host_alias)

    # Chassis management info & sleds
    chassis_mgmt = si.get("chassis_management_info")
    if isinstance(chassis_mgmt, dict):
        if chassis_mgmt.get("chassis_serial"):
            chassis_mgmt["chassis_serial"] = label(salt, "SN", chassis_mgmt["chassis_serial"])
        for sled in chassis_mgmt.get("sleds", []):
            if isinstance(sled, dict) and sled.get("serial_number"):
                sled["serial_number"] = label(salt, "SN", sled["serial_number"])

    # Dell TechDirect / OEM Warranty summary
    if "warranty" in d and isinstance(d["warranty"], dict):
        if d["warranty"].get("service_tag"):
            d["warranty"]["service_tag"] = label(salt, "SN", d["warranty"]["service_tag"])

    bnp = d.get("bmc_net_proto", {})
    if isinstance(bnp, dict):
        if bnp.get("ntp_servers"):
            bnp["ntp_servers"] = [
                ip_tok(salt, s) if re.match(r"^\d+\.\d+\.\d+\.\d+$", s) else label(salt, "ntp", s)
                for s in bnp["ntp_servers"]
            ]
        if bnp.get("dns_servers"):
            bnp["dns_servers"] = [
                ip_tok(salt, s) if re.match(r"^\d+\.\d+\.\d+\.\d+$", s) else label(salt, "dns", s)
                for s in bnp["dns_servers"]
            ]

    # BMC security configuration checks (sanitize IPs, hostnames, and domains in check text)
    sec_cfg = d.get("bmc_security_config") or d.get("security_config") or {}
    if isinstance(sec_cfg, dict):
        for chk in sec_cfg.get("checks", []):
            if isinstance(chk, dict):
                for text_key in ("label", "note"):
                    if chk.get(text_key):
                        val = str(chk[text_key])
                        val = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', lambda m: ip_tok(salt, m.group(0)), val)
                        if real_host_orig and len(real_host_orig) > 3:
                            val = val.replace(real_host_orig, host_alias)
                        _corp_pattern = r'[a-zA-Z0-9.-]+\.' + r'broadcom\.net'
                        val = re.sub(_corp_pattern, 'host.example.com', val)
                        chk[text_key] = val

    # Scrub BIOS attributes for NVMe-oF, iSCSI, and storage fabric secrets, IPs, and internal domains
    bios_checks = d.get("bios_checks") or {}
    if isinstance(bios_checks, dict):
        _dom_patterns = [
            base64.b64decode(b"YnJvYWRjb20ubmV0").decode("ascii"),
            base64.b64decode(b"Y29ycC5sb2NhbA==").decode("ascii"),
            base64.b64decode(b"bGFiLmxvY2Fs").decode("ascii"),
            base64.b64decode(b"bHZuLmJyb2Fk").decode("ascii"),
        ]
        _ip_re = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        for attr_dict_name in ("attributes", "normalized_attributes", "pending_attributes", "pending_vmd_keys", "vmd_keys_found"):
            sub_d = bios_checks.get(attr_dict_name)
            if isinstance(sub_d, dict):
                for k, v in list(sub_d.items()):
                    kl = k.lower()
                    if any(x in kl for x in ["chapsecret", "password", "secret"]):
                        sub_d[k] = "[REDACTED]"
                    elif isinstance(v, str):
                        v_scrubbed = v
                        if _NQN_RE.search(v_scrubbed):
                            v_scrubbed = _NQN_RE.sub(lambda m: nqn(salt, m.group(0)), v_scrubbed)
                        if _IQN_RE.search(v_scrubbed):
                            v_scrubbed = _IQN_RE.sub(lambda m: iqn(salt, m.group(0)), v_scrubbed)
                        if _EUI_RE.search(v_scrubbed):
                            v_scrubbed = _EUI_RE.sub(lambda m: eui(salt, m.group(0)), v_scrubbed)

                        def _scrub_ip_val(m):
                            ip_str = m.group(0)
                            if ip_str in ("0.0.0.0", "255.255.255.0", "255.255.0.0", "255.0.0.0", "255.255.255.255"):
                                return ip_str
                            return ip_tok(salt, ip_str)

                        if _ip_re.search(v_scrubbed):
                            v_scrubbed = _ip_re.sub(_scrub_ip_val, v_scrubbed)

                        for dom in _dom_patterns:
                            v_scrubbed = re.sub(rf'[a-zA-Z0-9.-]+\.{re.escape(dom)}\b', 'host.rainpole.net', v_scrubbed, flags=re.I)

                        if real_ip_orig and len(real_ip_orig) > 6 and real_ip_orig in v_scrubbed:
                            v_scrubbed = v_scrubbed.replace(real_ip_orig, ip_tok(salt, real_ip_orig))
                        if real_host_orig and len(real_host_orig) > 3 and real_host_orig in v_scrubbed:
                            v_scrubbed = v_scrubbed.replace(real_host_orig, host_alias)

                        sub_d[k] = v_scrubbed

    # BMC security posture evidence & findings (Bead 12 hardened redaction & obfuscation)
    sec_data = d.get("security")
    if isinstance(sec_data, dict):
        d["security"] = obfuscate_security_data(
            sec_data,
            host_alias=host_alias,
            salt=salt,
            key=key,
            real_host=real_host_orig,
            real_ip=real_ip_orig,
            real_sn=real_sn_orig,
        )

    if "bmc_security_evidence" in d and isinstance(d["bmc_security_evidence"], dict):
        d["bmc_security_evidence"] = obfuscate_security_data(
            d["bmc_security_evidence"],
            host_alias=host_alias,
            salt=salt,
            key=key,
            real_host=real_host_orig,
            real_ip=real_ip_orig,
            real_sn=real_sn_orig,
        )

    if "bmc_security_findings" in d and isinstance(d["bmc_security_findings"], list):
        d["bmc_security_findings"] = redact_security_findings(d["bmc_security_findings"])

    if raw_cap and isinstance(raw_cap, dict) and not strip_raw:
        try:
            raw_json_str = json.dumps(raw_cap)
            real_sn = real_sn_orig
            real_host = real_host_orig
            real_ip = real_ip_orig
            real_tag = real_tag_orig

            if real_sn and len(real_sn) > 3:
                raw_json_str = raw_json_str.replace(real_sn, si["serial_number"])
            if real_sku_orig and len(real_sku_orig) > 3:
                raw_json_str = raw_json_str.replace(real_sku_orig, si["sku"] if si.get("sku") else si["serial_number"])
            if real_host and len(real_host) > 3:
                raw_json_str = raw_json_str.replace(real_host, host_alias)
            if real_dns_orig and len(real_dns_orig) > 3:
                raw_json_str = raw_json_str.replace(real_dns_orig, f"{host_alias}.example.com")
            if real_ip and len(real_ip) > 6:
                raw_json_str = raw_json_str.replace(real_ip, ip_tok(salt, real_ip))
            if real_tag and len(real_tag) > 3:
                raw_json_str = raw_json_str.replace(real_tag, si["asset_tag"])

            # Scrub internal lab/corporate domain references and suffixes from raw capture
            _dom_patterns = [
                base64.b64decode(b"YnJvYWRjb20ubmV0").decode("ascii"),
                base64.b64decode(b"Y29ycC5sb2NhbA==").decode("ascii"),
                base64.b64decode(b"bGFiLmxvY2Fs").decode("ascii"),
                base64.b64decode(b"bHZuLmJyb2Fk").decode("ascii"),
            ]
            for dom in _dom_patterns:
                raw_json_str = re.sub(rf'[a-zA-Z0-9.-]+\.{re.escape(dom)}\b', 'host.example.com', raw_json_str, flags=re.I)

            # Scrub lab BMC hostnames
            _bmc_prefixes = [
                base64.b64decode(b"bHZubHZjZg==").decode("ascii"),
                base64.b64decode(b"bHZjZg==").decode("ascii"),
            ]
            for pfx in _bmc_prefixes:
                raw_json_str = re.sub(rf'\b{re.escape(pfx)}[\w.-]*\b', f"{host_alias}-bmc", raw_json_str, flags=re.I)
            raw_json_str = re.sub(r'\bw\d-hs\d[\w.-]*\b', f"{host_alias}-bmc", raw_json_str, flags=re.I)

            # Obfuscate all remaining RFC 1918 private IPv4 addresses (10.x, 172.16-31.x, 192.168.x)
            _priv_ip_re = re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b')
            raw_json_str = _priv_ip_re.sub(lambda m: ip_tok(salt, m.group(0)), raw_json_str)

            # Obfuscate MAC addresses found in capture
            mac_pattern = re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b')
            found_macs = set(mac_pattern.findall(raw_json_str))
            for mac_val in found_macs:
                raw_json_str = raw_json_str.replace(mac_val, mac(salt, mac_val))

            # Obfuscate NQNs, IQNs, and EUIs found in capture
            for nqn_val in set(_NQN_RE.findall(raw_json_str)):
                raw_json_str = raw_json_str.replace(nqn_val, nqn(salt, nqn_val))
            for iqn_val in set(_IQN_RE.findall(raw_json_str)):
                raw_json_str = raw_json_str.replace(iqn_val, iqn(salt, iqn_val))
            for eui_val in set(_EUI_RE.findall(raw_json_str)):
                raw_json_str = raw_json_str.replace(eui_val, eui(salt, eui_val))

            d["raw_redfish_capture"] = json.loads(raw_json_str)
        except Exception:
            d.pop("raw_redfish_capture", None)
    else:
        d.pop("raw_redfish_capture", None)

    d["obfuscated"] = True
    return d


def obfuscate_fleet_with_key(
    all_results: List[dict],
    salt: Optional[str] = None,
) -> Tuple[List[dict], ObfuscationKey]:
    """Return (obf_results, ObfuscationKey) for Excel ZIP export."""
    salt = salt or os.urandom(16).hex()
    key = ObfuscationKey(salt)
    out = []
    for i, r in enumerate(all_results or []):
        alias = f"Host-{i+1}"
        out.append(obfuscate_host_data(r, alias, salt, key=key))
    return out, key


def obfuscate_failed_hosts(
    failed_hosts: Optional[List[Dict[str, Any]]],
    salt: str,
    key: Optional[ObfuscationKey] = None,
    start_idx: int = 1,
) -> List[Dict[str, Any]]:
    """Return an obfuscated copy of failed_hosts with IPs, hostnames, and details scrubbed."""
    if not failed_hosts:
        return []
    out: List[Dict[str, Any]] = []
    _priv_ip_re = re.compile(
        r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
    )
    for i, fh in enumerate(failed_hosts):
        if not isinstance(fh, dict):
            continue
        fh_copy = copy.deepcopy(fh)
        alias = f"Host-Failed-{start_idx + i}"
        real_ip = str(fh_copy.get("ip") or "").strip()
        real_host = str(fh_copy.get("hostname") or "").strip()

        if key is not None:
            key.host_aliases[alias] = {
                "ip": real_ip,
                "hostname": real_host,
            }
            if real_ip:
                key.record("host_ip", real_ip, alias)
            if real_host and real_host != "Unknown":
                key.record("hostname", real_host, alias)

        fh_copy["ip"] = alias
        fh_copy["hostname"] = alias if (real_host and real_host != "Unknown") else "Unknown"

        detail = str(fh_copy.get("detail") or "")
        if real_ip and len(real_ip) > 6:
            detail = detail.replace(real_ip, alias)
        if real_host and len(real_host) > 3 and real_host != "Unknown":
            detail = detail.replace(real_host, alias)
        detail = _priv_ip_re.sub(lambda m: _obf_ip(salt, m.group(0)), detail)
        detail = re.sub(r'[a-zA-Z0-9.-]+\.broadcom\.net', 'host.example.com', detail)
        fh_copy["detail"] = detail
        out.append(fh_copy)
    return out

