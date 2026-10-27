"""Reconcile FC port observations without treating node WWNs as extra ports."""

import copy
import re
from typing import Optional


def wwn_key(value) -> str:
    """Compare valid WWNs independently of case and punctuation."""
    value = re.sub(r'[:.\-\s]', '', str(value or '')).lower()
    return value if re.fullmatch(r'[0-9a-f]{16}', value) and value not in ('0' * 16, 'f' * 16) else ''


def _known(value) -> bool:
    return value is not None and str(value).strip().lower() not in ('', 'n/a', 'unknown', 'none', 'not available')


def fc_adapter_key(port: dict) -> str:
    """Use physical location/adapter IDs, never a model or PCI vendor/device ID."""
    for field in ('physical_adapter_id', 'adapter_id', 'port_id'):
        value = str(port.get(field) or '')
        slot = re.search(r'(FC\.(?:Slot|Embedded|Integrated)\.\d+)(?:[-/]|$)', value, re.I)
        if slot:
            return slot.group(1).lower()
    for field in ('physical_adapter_id', 'adapter_id', 'adapter_uri', 'pcie_device_uri', 'pci_slot', 'slot'):
        if _known(port.get(field)):
            return str(port[field]).strip().lower()
    return ''


def fc_adapter_count(ports: list) -> Optional[int]:
    """Return an evidenced physical card count, or None when location is missing."""
    keys = [fc_adapter_key(port) for port in ports]
    return len(set(keys)) if all(keys) else None


def _same_port(left: dict, right: dict) -> bool:
    adapter = fc_adapter_key(left)
    if not adapter or adapter != fc_adapter_key(right):
        return False
    for field in ('physical_port_id', 'port_id'):
        if _known(left.get(field)) and str(left[field]).lower() == str(right.get(field) or '').lower():
            return True
    return False


def _node_alias(alias: dict, canonical: dict) -> bool:
    # CNA/vHBA personalities may legitimately share a physical uplink and WWNN.
    if any(port.get('is_cna') or port.get('cna_family') for port in (alias, canonical)):
        return False
    return bool(
        _same_port(alias, canonical)
        and not wwn_key(alias.get('wwnn'))
        and wwn_key(alias.get('wwpn'))
        and wwn_key(alias.get('wwpn')) == wwn_key(canonical.get('wwnn'))
        and wwn_key(canonical.get('wwpn'))
        and wwn_key(canonical.get('wwpn')) != wwn_key(canonical.get('wwnn'))
    )


def _merge(primary: dict, extra: dict) -> dict:
    result = copy.deepcopy(primary)
    for key, value in extra.items():
        if not _known(result.get(key)) and _known(value):
            result[key] = copy.deepcopy(value)
    for key in ('speed_gbps', 'port_speed_gbps'):
        try:
            speed = float(result.get(key) or 0)
        except (ValueError, TypeError):
            speed = 0
        if speed <= 0 and _known(extra.get(key)):
            result[key] = extra[key]
    targets = result.get('boot_targets') or []
    for target in extra.get('boot_targets') or []:
        if target not in targets:
            targets.append(copy.deepcopy(target))
    if targets:
        result['boot_targets'] = targets
    return result


def normalize_fc_ports(ports: list) -> list:
    """Merge proven duplicate observations; retain uncertain/virtual identities.

    Historical summaries can contain a NetworkPort node WWN mislabeled as WWPN,
    followed by a NetworkDeviceFunction with the actual WWPN and matching WWNN.
    Repair that pair only with matching adapter and port location evidence.
    """
    result = []
    for port in ports or []:
        if not isinstance(port, dict):
            continue
        for index, old in enumerate(result):
            key = wwn_key(port.get('wwpn'))
            same_wwpn = key and key == wwn_key(old.get('wwpn'))
            conflicting_cards = fc_adapter_key(old) and fc_adapter_key(port) and fc_adapter_key(old) != fc_adapter_key(port)
            if same_wwpn and not conflicting_cards:
                result[index] = _merge(old, port)
                break
            if _node_alias(old, port):
                result[index] = _merge(port, old)
                break
            if _node_alias(port, old):
                result[index] = _merge(old, port)
                break
        else:
            result.append(copy.deepcopy(port))
    return result
