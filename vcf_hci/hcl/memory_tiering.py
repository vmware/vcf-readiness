"""Offline Memory Tiering listing evidence, separate from vSAN readiness."""
import os
import re
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

from vcf_hci.hcl.memory_tiering_data import active_catalog

PREVIEW_ENV = 'VCF_READINESS_NVME_NAMESPACE_PREVIEW'
BCG_SEARCH = 'https://compatibilityguide.broadcom.com/search?program=memorytier&persona=live&column=partnerName&order=asc'


def namespace_preview_enabled() -> bool:
    return os.environ.get(PREVIEW_ENV) == '1'


def _key(value: str) -> str:
    return re.sub(r'[^A-Z0-9]', '', value.upper())


CatalogEntry = Tuple[str, str, str, tuple]
@lru_cache(maxsize=4)
def _catalog_indexes(entries: tuple) -> tuple:
    by_model: Dict[str, List[CatalogEntry]] = {}
    by_token: Dict[str, List[CatalogEntry]] = {}
    by_id: Dict[str, List[CatalogEntry]] = {}
    for entry in entries:
        by_model.setdefault(_key(entry[0]), []).append(entry)
        # Some Dell BCG descriptions append a five-character orderable part
        # number after '/', while Redfish reports the same full model without it.
        if entry[1] == 'Dell' and re.search(r'/[A-Z0-9]{5}$', entry[0]):
            description = entry[0].rsplit('/', 1)[0]
            by_model.setdefault(_key(description), []).append(entry)
        by_id.setdefault(entry[2], []).append(entry)
        for token in set(re.findall(r'[A-Z0-9-]+', entry[0].upper())):
            if len(token) >= 9 and re.search(r'\d', token) and re.search(r'[A-Z]', token):
                by_token.setdefault(token, []).append(entry)
    return by_model, by_token, by_id


def memory_tiering_matches(drive: dict, json_hcl: Optional[dict] = None) -> List[Tuple[str, str, str, tuple]]:
    """Require an exact model or a complete SKU token, never a family substring.

    Capacity-bearing BCG names also require observed capacity alignment. A listing
    does not validate firmware, topology, release or an individual deployment.
    """
    model = str(drive.get('model') or '').strip().upper()
    if not model:
        return []
    entries = tuple((name, partner, pid, tuple(releases))
                    for name, partner, pid, releases in active_catalog(json_hcl)['entries'])
    by_model, by_token, by_id = _catalog_indexes(entries)
    tokens = [t for t in re.findall(r'[A-Z0-9-]+', model)
              if len(t) >= 9 and re.search(r'\d', t) and re.search(r'[A-Z]', t)]
    result = []
    # vSAN and memorytier share product IDs. Resolve only an exact local alias,
    # never the fuzzy family/PCI matching used for broader vSAN investigation.
    item = (json_hcl or {}).get('models', {}).get(model, {})
    exact_id = str(item.get('product_id') or '') if isinstance(item, dict) else ''
    candidates = list(by_model.get(_key(model), [])) + list(by_id.get(exact_id, []))
    for token in tokens:
        candidates.extend(by_token.get(token, []))
    oem = str(drive.get('manufacturer') or '')
    # Explicit OEM branding narrows SKU matches; an ODM's bare SKU does not
    # authorize choosing a different OEM's qualified variant.
    partner_hint = next((partner for token, partner in (
        ('DELL', 'Dell'), ('HPE', 'Hewlett Packard Enterprise'),
        ('HEWLETT', 'Hewlett Packard Enterprise'), ('LENOVO', 'Lenovo'),
        ('CISCO', 'Cisco'), ('HITACHI', 'Hitachi'),
    ) if token in (model + ' ' + oem).upper()), '')
    for name, partner, product_id, releases in sorted(set(candidates)):
        if partner_hint and partner != partner_hint:
            continue
        capacities = re.findall(r'(\d+(?:\.\d+)?)\s*(TB|GB)\b', name.upper())
        if capacities:
            try:
                observed = float(drive.get('capacity_gb') or 0)
            except (ValueError, TypeError):
                continue
            # Historical summaries stored GiB in capacity_gb. Compare that
            # representation as well as decimal GB without rewriting evidence.
            # An explicit unit/byte count remains authoritative.
            unit_hint = str(drive.get('capacity_unit') or drive.get('capacity_units') or '').upper()
            values = [observed]
            if unit_hint == 'GIB':
                values = [observed * (1024 ** 3) / 1e9]
            elif not unit_hint:
                values.append(observed * (1024 ** 3) / 1e9)
            if drive.get('capacity_bytes') is not None:
                try:
                    values = [float(drive['capacity_bytes']) / 1e9]
                except (ValueError, TypeError):
                    continue
            if not any(abs(value - float(n) * (1000 if unit == 'TB' else 1))
                       <= float(n) * (1000 if unit == 'TB' else 1) * .025
                       for value in values for n, unit in capacities):
                continue
        result.append((name, partner, product_id, releases))
    return result


# Reviewed TLC / 1 DWPD read-intensive product briefs; no family-only inference
# across PRO/MAX, R/V, RI/MU or QLC variants. Keep model-specific evidence here.
RI_SOURCES = (
    (r'\bDell Ent NVMe P5500 RI U\.2 3\.84TB\b',
     'https://compatibilityguide.broadcom.com/detail?program=ssd&productId=48200&persona=live'),
    (r'\bDell NVMe PM1743 RI E3\.S 3\.84TB\b',
     'https://compatibilityguide.broadcom.com/detail?program=ssd&productId=55068&persona=live'),
    (r'\b(?:CM6-R|KCM6[1XDF]RUL[A-Z0-9]+)\b',
     'https://www.kioxia.com/content/dam/kioxia/shared/business/ssd/enterprise-ssd/asset/productbrief/eSSD-CM6-R-product-brief.pdf'),
    (r'\b(?:CD6-R|KCD6[1XDF]LUL[A-Z0-9]+)\b',
     'https://www.kioxia.com/content/dam/kioxia/shared/business/ssd/data-center-ssd/asset/productbrief/dSSD-CD6-R-product-brief.pdf'),
    (r'\b(?:CM7-R|KCMY[1XDF]RUG[A-Z0-9]+)\b',
     'https://europe.kioxia.com/content/dam/kioxia/shared/business/ssd/enterprise-ssd/asset/productbrief/eSSD-CM7-R-product-brief.pdf'),
    (r'\bKCM7[1XDF]RJE[A-Z0-9]+\b',
     'https://www.kioxia.com/content/dam/kioxia/shared/business/ssd/enterprise-ssd/asset/productbrief/eSSD-CM7-R-E3.S-product-brief.pdf'),
    (r'\b(?:CD8-R|KCD8[1XD]RUG[A-Z0-9]+)\b',
     'https://www.kioxia.com/content/dam/kioxia/shared/business/ssd/data-center-ssd/asset/productbrief/dSSD-CD8-R-U2-product-brief.pdf'),
    (r'\b7450[ _-]*PRO\b',
     'https://www.micron.com/content/dam/micron/global/public/products/product-flyer/7450-nvme-ssd-product-brief.pdf'),
    (r'\b(?:D7-)?P5520\b',
     'https://www.solidigm.com/products/data-center/product-briefs/d7-p5520-p5620-product-brief.html'),
    (r'\b(?:PM9A3|MZQL2960HCJR(?:-[A-Z0-9]+)?|MZQL21T9HCJR(?:-[A-Z0-9]+)?|MZQL23T8HCLS(?:-[A-Z0-9]+)?|MZQL27T6HBLA(?:-[A-Z0-9]+)?)\b',
     'https://images.samsung.com/is/content/samsung/assets/si/memory-storage/ssd-ji-data-center/samsung_ssd_pm9a3_data_sheet_rev1_0.pdf'),
)


def namespace_candidate_source(drive: dict, evaluation: dict, json_hcl: Optional[dict] = None) -> Optional[str]:
    """Return evidence only for explicitly identified TLC 1 DWPD ESA candidates."""
    from vcf_hci.hcl.cross_reference import detect_qlc_nvme

    model = str(drive.get('model') or '')
    evidence = str(evaluation.get('hcl_matched_info') or '')
    if (evaluation.get('category') != 'vSAN ESA/OSA NVMe'
            or not evaluation.get('vsan_eligible') or 'esa' not in evidence.lower()
            or 'cyber' in evidence.lower() or drive.get('is_qlc')
            or detect_qlc_nvme(model) or drive.get('is_boot')
            or any(drive.get(k) for k in ('behind_vmd', 'behind_trimode', 'behind_software_raid'))):
        return None
    nand = str(drive.get('nand_type') or drive.get('flash_type') or '').upper()
    if 'QLC' in nand:
        return None
    # Operator/import metadata can cover additional products without guessing TLC
    # from absence in the QLC list or interpreting wear remaining as rated DWPD.
    try:
        dwpd = float(drive.get('rated_dwpd', 0))
    except (TypeError, ValueError):
        dwpd = 0
    if drive.get('rated_dwpd') is not None and dwpd != 1:
        return None
    if 'TLC' in nand and dwpd == 1:
        return 'Collected TLC / rated 1 DWPD evidence'
    # An exact HCL alias can resolve an opaque OEM SKU to a reviewed product.
    item = (json_hcl or {}).get('models', {}).get(model.strip().upper(), {})
    if isinstance(item, dict):
        model += ' ' + str(item.get('model') or '')
    for pattern, source in RI_SOURCES:
        if re.search(pattern, model, re.IGNORECASE):
            return source
    return None
