# Broadcom HCL Subpackage (`vcf_hci.hcl`)

> Hardware Compatibility List (HCL) loader, dark-site bundle manager, and component cross-referencing engine.

---

## Overview

The `hcl` subpackage manages Broadcom vSAN HCL certification datasets. It supports:
1. **Live Online Fetching:** Auto-downloads `all.json` from Broadcom servers with a 30-day cache stored in `~/.vcf-readiness/hcl/`.
2. **Offline Dark-Site Bundles:** Creates and extracts standalone `.zip` HCL datasets (`vcf_hcl_bundle_*.zip`) for air-gapped datacenters.
3. **CSV Fallback:** Parses local legacy CSV exports in `hcl/`.
4. **Cross-Referencing:** Matches collected drive models, firmware versions, and PCI IDs against certified HCL entries.

---

## Files & Modules Index

- **`loader.py`**: `HCLLoader` managing local disk caches, fetching live vSAN HCL datasets from Broadcom (`https://vvs.broadcom.com/service/vsan/all.json`), and loading CSV fallback datasets.
- **`bundle_manager.py`**: `HCLBundleManager` handling creation (`--bundle-hcl`) and importation (`--import-hcl`) of offline air-gapped dark-site zip bundles.
- **`cross_reference.py`**: `cross_reference_hcl()` comparing host drive inventory and PCI network/storage devices against HCL entries to verify certification status.

---

## Dataset Storage Paths

- **User Cache Directory:** `~/.vcf-readiness/hcl/all.json`
- **Fallback CSV Directory:** `hcl/` (project root)
- **Dark-Site Bundle Output:** `~/.vcf-readiness/hcl/vcf_hcl_bundle_<date>.zip`
