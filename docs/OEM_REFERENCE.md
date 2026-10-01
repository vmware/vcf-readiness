# OEM Reference Guide — VCF Readiness Assessment Tool

This document catalogues every OEM-keyed data structure in `vcf_hci/` (and `vcfr_collector.py`)
and provides a step-by-step checklist for onboarding a new OEM.

---

## Table of Contents

- [1. OEM Detection](#1-oem-detection)
- [2. Chassis Bay Count Tables](#2-chassis-bay-count-tables)
- [3. BIOS Baselines — `BIOS_BASELINES`](#3-bios-baselines--bios_baselines)
- [4. BMC Firmware Baselines — `BMC_FW_BASELINES`](#4-bmc-firmware-baselines--bmc_fw_baselines)
- [5. Side-Channel Advisory Links — `_VENDOR_SIDE_CHANNEL_LINKS`](#5-side-channel-advisory-links--_vendor_side_channel_links)
- [6. CVE Tier Thresholds — `_CVE_TIERS`](#6-cve-tier-thresholds--_cve_tiers)
- [7. NVMe Firmware Baselines — `NVME_FW_BASELINES`](#7-nvme-firmware-baselines--nvme_fw_baselines)
- [8. BCG URL Patterns — `BCGLinkGenerator`](#8-bcg-url-patterns--bcglinkgenerator)
- [9. OEM-Specific Redfish Endpoint Quirks](#9-oem-specific-redfish-endpoint-quirks)
- [9.1 Redfish $expand & OEM Bulk Telemetry Profiles](#91-redfish-expand--oem-bulk-telemetry-profiles)
- [10. Onboarding Checklist — Adding a New OEM](#10-onboarding-checklist--adding-a-new-oem)
- [11. Multi-Vendor SEL / IML Deep-Linking Engine](#11-multi-vendor-sel--iml-deep-linking-engine)

---

## 1. OEM Detection

### Vendor String Normalisation

The raw `Manufacturer` field returned by `GET /Systems/{id}` is stored as
`sys_info["vendor"]`. It is **not** normalised at collection time; callers
uppercase it for comparisons:

```python
vendor_up = str(sys_info.get("vendor", "")).upper()
```

Common values seen in the field:

| OEM | Typical Manufacturer string |
|---|---|
| Dell | `Dell Inc.` |
| HPE | `HPE` or `Hewlett Packard Enterprise` |
| Lenovo | `LENOVO` |
| Supermicro | `Supermicro` |
| Cisco | `Cisco Systems Inc` |
| Quanta / QCT | `Quanta Cloud Technology Inc.` |
| GIGABYTE | `GIGABYTE` or `GIGA-BYTE` |

### `_KNOWN_VSPHERE_OEMS`

Not a dictionary but a tuple constant (search for it in the code) listing OEM name
fragments used in UI display decisions.

### BCG Model Keyword Cleanup per OEM

`BCGLinkGenerator.server()` strips vendor-prefix noise from the model string before
building the Broadcom Compatibility Guide URL. When adding a new OEM, ensure the
regex substitution handles the OEM's standard prefix format (e.g. `ProLiant`, `PowerEdge`, `ThinkSystem`).

---

## 2. Chassis Bay Count Tables

### `HPE_SKU_CHASSIS_DB`

Keyed on HPE product SKU string (uppercase), returned from
`Oem.Hpe.ProductId` or `System.SKU`. Value: `(bay_count, chassis_label)`.

**Example:**

```python
HPE_SKU_CHASSIS_DB = {
    "P19766-B21": (8, "DL380 Gen10 8SFF NVMe"),
    ...
}
```

**To add an entry:** Look up the HPE QuickSpecs for the target model and note the
SKU and its drive bay configuration.

### `DELL_MODEL_CHASSIS_DB`

Keyed on the model suffix stripped of `PowerEdge ` prefix and normalised to
uppercase (e.g. `R740XD` not `PowerEdge R740xd`). Value: `(bay_count, chassis_label)`.

**To add an entry:** Use Dell's EMC server configurator to confirm bay count and
chassis description.

### Encouraging OEM Contributions for Chassis Maps and Front Panel Layouts

We actively invite server OEMs and hardware vendors to provide official chassis mapping specifications, front-panel SVG diagrams, and SKU databases to make hardware assessment in VCF Readiness reports as robust as possible.

**How OEMs Can Contribute:**
1. **Order SKU & Model Database Additions**: Supply table entries for `DELL_SKU_CHASSIS_DB`, `HPE_SKU_CHASSIS_DB`, `DELL_MODEL_CHASSIS_DB`, or new vendor-specific tables mapping order numbers/SKUs to max front drive bays and exact chassis descriptions.
2. **Drive Bay Grid & Layout Definitions**: Share physical slot numbering conventions (e.g., vertical 2x5 pairing vs horizontal row-major numbering) and form-factor capabilities (EDSFF E1.S / E3.S, U.2/U.3 SFF, 3.5" LFF).
3. **High-Resolution Front Panel Vector Graphics / SVGs**: Provide clean SVG outline assets or layout coordinates for server chassis families.
4. **Sanitized Redfish Payloads**: Share Redfish response trees from BMC controllers (`GET /redfish/v1/Systems/{id}/Storage`, `/Systems/{id}/Storage/{id}/Drives/{id}`) so drive bay locations (`Location.Placement.Bay`, `Oem` slot properties) are parsed with 100% precision.

---

## 3. BIOS Baselines — `BIOS_BASELINES`

### Location

`vcf_hci/constants.py` (after license constants).

### Key Format

Uppercase substring of the server model string. The lookup uses `if k in model_key`
(substring match) so keys must be **unique enough** to avoid cross-OEM collisions.

| OEM | Key format | Example |
|---|---|---|
| Dell | `POWEREDGE R<nnn>` | `POWEREDGE R640` |
| HPE | `PROLIANT DL<nnn> GEN<n>` | `PROLIANT DL380 GEN10` |
| Lenovo | `THINKSYSTEM SR<nnn>` or `THINKAGILE HX<nnn>` | `THINKSYSTEM SR630` |
| Supermicro | `SYS-<code>` | `SYS-1029U` |
| Cisco | `UCSC-C<nnn>-M<n>` or `HX<nnn>` | `UCSC-C220-M5` |
| Quanta / QCT | `QUANTAGRID D<nnn>` | `QUANTAGRID D42A-2U` |
| GIGABYTE | Platform model / `GIGABYTE` | `GIGABYTE SERVER` |

### Value Format

```python
"POWEREDGE R640": {
    "latest":          "2.24.0",   # newest known-good BIOS (update regularly)
    "min_recommended": "2.23.0",   # minimum field-safe version
    "min_spectre":     "1.3.7",    # minimum version containing Spectre/Meltdown microcode
}
```

### Version Format Differences per OEM

| OEM | BiosVersion format | parse_version_tuple() result |
|---|---|---|
| Dell | `2.24.0` | `(2, 24, 0)` |
| HPE | `U30 v3.00` | extracts `(3, 0)` from trailing number |
| Lenovo | `[IVE-2.93]` | extracts `(2, 93)` from bracketed string |
| Supermicro | `4.4` | `(4, 4)` |
| Cisco | `C220M5.4.1.2b.0.032...` | extracts `(4, 1, 2)` |

For Lenovo, `BIOS_BASELINES` keys use the `IVE-X.XX` / `TEE-X.XX` / `AFE-X.XX`
prefix format because `parse_version_tuple()` strips the leading non-numeric
characters and compares the numeric portion only.

### `min_spectre` Rationale

`min_spectre` is the oldest BIOS version that first shipped CPU microcode patches
for the January 2018 Spectre/Meltdown (CVE-2017-5715) disclosure.

Sources by OEM:
- **Dell**: KB 000178106 (initial microcode bundles, Feb 2018)
- **HPE**: Customer Advisory a00039267en_us (Feb 2018; U30 v1.22 for Gen10)
- **Lenovo**: LEN-22133 (IVE116Y ≈ IVE-1.16 for Gen1 ThinkSystem)
- **Supermicro**: Intel-SA-00088 advisory (stable BIOS from 2.0x range)
- **Cisco**: cisco-sa-20180104-cpusidechannel (IMC 3.1(2g) bundle)

For platforms shipped **after** Jan 2018, `min_spectre` is set to the first release
version (`1.0.0` / `1.0` / `4.1.0`) since all shipped versions include the patches.

---

## 4. BMC Firmware Baselines — `BMC_FW_BASELINES`

### Location

Adjacent to `BIOS_BASELINES` (~line 405).

### Key Format

Uppercase substring of the manager `Model` or `Name` Redfish field, or a
distinctive portion of `FirmwareVersion`. The lookup in `collect_bmc_firmware()`
iterates `BMC_FW_BASELINES` and tests `if key in mgr_model or key in fw_ver.upper()`.

| BMC | Key | Example version |
|---|---|---|
| Dell iDRAC 9 | `IDRAC9` | `7.00.00.181` |
| Dell iDRAC 8 | `IDRAC8` | `2.82.82.82` |
| HPE iLO 5 | `ILO 5` | `3.10` |
| HPE iLO 6 | `ILO 6` | `1.70` |
| Lenovo XCC/XCC2 | `XCC` | `8.90` |
| Cisco IMC | `CIMC` | `4.3.2` |
| Supermicro BMC | `SUPERMICRO BMC` | `3.76` |
| Quanta BMC | `AST2500` | `3.14.19` |
| GIGABYTE BMC | `MEGARAC` or `410810600` | `12.60.10` |

### Value Format

Identical to `BIOS_BASELINES`:

```python
"IDRAC9": {
    "latest":          "7.20.10.50",
    "min_recommended": "7.00.00.181",   # fixes CVE-2025-26482
    "min_spectre":     "3.30.30",       # first iDRAC9 version with BMC-side mitigations
}
```

---

## 5. Side-Channel Advisory Links — `_VENDOR_SIDE_CHANNEL_LINKS`

### Location

Adjacent to `BMC_FW_BASELINES` (~line 420).

### Key Format

Uppercase vendor name fragment matched against `sys_info["vendor"].upper()` with
`if k in vendor_up`. Keys must not overlap — `HEWLETT` covers HPE's full-name
string `HEWLETT PACKARD ENTERPRISE` separately from the `HPE` short-name key.

### Value Format

```python
"DELL": ("https://www.dell.com/support/kbdoc/en-us/000178106",
         "Dell KB 000178106 — Spectre/Meltdown Impact on PowerEdge")
```

Both are displayed in the BIOS card as a hyperlink and in the BIOS accordion footer.

Configured vendor advisory mappings:
- **DELL**: KB 000178106 (`Dell KB 000178106 — Spectre/Meltdown Impact on PowerEdge`)
- **HPE / HEWLETT**: Advisory a00039267en_us (`HPE Advisory a00039267en_us — Side-Channel Analysis Mitigations`)
- **LENOVO**: Advisory LEN-22133 (`Lenovo Advisory LEN-22133 — Speculative Execution Side-Channel Vulnerabilities`)
- **SUPERMICRO**: Intel-SA-00088 (`Intel-SA-00088 / Supermicro Advisory — Speculative Execution Side-Channel`)
- **CISCO**: cisco-sa-20180104-cpusidechannel (`Cisco Security Advisory — CPU Side-Channel Information Disclosure`)
- **QUANTA**: Intel-SA-00088 (`Intel-SA-00088 — Spectre/Meltdown (Quanta platforms)`)
- **GIGABYTE**: Intel-SA-00088 (`Intel-SA-00088 — Spectre/Meltdown (GIGABYTE platforms)`)

---

## 6. CVE Tier Thresholds — `_CVE_TIERS`

### Location

Adjacent to `_VENDOR_SIDE_CHANNEL_LINKS` (~line 440).

### Format

```python
_CVE_TIERS = [
    (cutoff_date_str_or_None, tier_int, tier_label, badge_class, description),
    ...
]
```

A BIOS is assigned the **highest tier** whose `cutoff_date <= bios_release_date`.
The final entry has `cutoff_date = None` (no upper bound — current tier).

### Tier Summary

| Tier | Date cutoff | Covered CVEs |
|---|---|---|
| 0 | < 2018-01-05 | None (pre-disclosure) |
| 1 | < 2018-08-14 | Spectre V1/V2, Meltdown |
| 2 | < 2019-05-14 | + L1TF / Foreshadow |
| 3 | < 2020-06-09 | + MDS / TAA / RIDL |
| 4 | < 2024-03-12 | + SRBDS / CrossTalk |
| 5 | ≥ 2024-03-12 | + RFDS (Intel 4th Gen+) |

CVE tiering only fires when `bios_release_date` is a parseable date:
- **Dell iDRAC**: `Oem.Dell.DellSystem.BIOSReleaseDate`
- **HPE iLO**: `Oem.Hpe.Bios.Current.Date`
- **Lenovo XCC**: Sourced via `oem_bios_date()` querying `/redfish/v1/UpdateService/FirmwareInventory` for the UEFI/BIOS component.
- **Cisco IMC**: Sourced via `oem_bios_date()` querying `/redfish/v1/UpdateService/FirmwareInventory` for the BIOS component.

For Supermicro and other unconfigured BMCs where the release date is not exposed, the date defaults to "N/A" and the version-based `spectre_status` badge provides the primary baseline evaluation.

---

## 7. NVMe Firmware Baselines — `NVME_FW_BASELINES`

### Location

`vcf_hci/constants.py`.

### Key Format

Uppercase **model-number prefix** (not a full model string). The lookup in
`evaluate_drive_fw()` uses `model_up.startswith(k)`.

```python
"MZQL2": {"latest": "GXA8302Q", "min_recommended": "GXA7302Q"},  # Samsung PM9A3
```

### QLC Detection — `QLC_NVME_PREFIXES`

Separate tuple of model-number prefixes for QLC NAND drives (< 1 DWPD endurance).
Prefix must be **specific enough** to avoid matching TLC variants — see inline
comments for each entry.

### NVMe SMART Telemetry & OEM Extensions

Drive health details are parsed in `_parse_drive_details()` in `vcf_hci/collector/collect_storage.py` and extracted from standard Redfish properties, `Metrics` sub-objects, and OEM-specific structures:

| OEM Vendor | Primary OEM Key | Extracted SMART Fields |
|---|---|---|
| **Dell iDRAC** | `Oem.Dell.DellPhysicalDisk` | `RemainingRatedWriteEndurancePercent`, `AbruptPowerOffCount`, `MediaAndDataIntegrityErrors`, `ThermalThrottled`, `PowerLossProtectionStatus`, `PCIeErrors`, `BadNANDBlockCount`, `SecurityStatus`, `UsageAttribute`, `ComponentStagingState` |
| **HPE iLO** | `Oem.Hpe` under `/SmartStorage` | `SSDEnduranceUtilizationPercentage`, `UnsafeShutdowns`, `UncorrectableReadErrors` / `MediaErrors`, `CurrentTemperatureCelsius`, `PowerLossProtection`, `TotalBytesWritten`, `EncrypStatus`, `PendingFirmwareVersion` |
| **Lenovo XCC** | `Oem.Lenovo.Drive` | `RemainingDriveLife`, `DriveErrorCount` / `SMARTStatus`, `WriteEndurancePercentage`, `UnsafeShutdowns`, `Temperature`, `PowerOnHours` |
| **Supermicro** | `Oem.Supermicro` or `StorageMetrics` | `LifeLeft` / `RemainingLife`, `TemperatureCelsius`, `MediaErrors`, DCMS license gate handling (`OemLicenseNotPassed`) |
| **Cisco IMC** | `Oem.Cisco` or `CIMC` | `Operability`, `Presence`, `UnsafeShutdowns`, `MediaErrors`, `LinkSpeed` / `LinkWidth` |
| **Quanta** | `Oem.Quanta_RackScale` (aliases `Oem.Quanta`, `Oem.QCT`) | `PowerOnHours` / `OperationHours`, `PartNumber` / `FRU` |
| **GIGABYTE** | `Oem.GBT` (alias `Oem.Gigabyte`) | `SlotNumber`, `PowerOnHours` / `OperationHours`, `PartNumber` / `FRU` |

---

## 8. BCG URL Patterns — `BCGLinkGenerator`

### Location

Class defined in `vcf_hci/bcg_links.py`.

### Per-OEM URL Construction

```
server: .../search?program=server&keyword={vendor}+{model_cleaned}
cpu:    .../search?program=cpu&keyword={cpu_family}
ssd:    .../search?program=ssd&keyword={model_first_token}
io:     .../search?program=io&keyword={nic_name}
gpu:    .../search?program=sptg&keyword={gpu_model}
```

`BCGLinkGenerator.server()` strips vendor-specific noise:
- Dell: strips `PowerEdge `, normalises spaces
- HPE: strips `ProLiant `, strips Gen-suffix for generic searches
- Lenovo: strips `ThinkSystem `
- Others: passed through as-is

When adding a new OEM, verify BCG accepts the resulting keyword by testing a manual
search at [compatibilityguide.broadcom.com](https://compatibilityguide.broadcom.com).

---

## 9. OEM-Specific Redfish Endpoint Quirks

These are derived from the code comments and known BMC behaviour:

| OEM | Quirk | Handling |
|---|---|---|
| **HPE iLO** | SmartStorage at `/Systems/{id}/SmartStorage/ArrayControllers` | Dedicated HPE storage path |
| **HPE iLO** | System usage metrics at `Oem.Hpe.SystemUsage` | OEM key extraction |
| **HPE iLO** | BIOS date at `Oem.Hpe.Bios.Current.Date` | Used for CVE tier |
| **HPE iLO** | License at `Oem.Hpe.License` | `collect_bmc_license()` |
| **HPE iLO** | `ResourceNotReadyRetry` extended info → retry once after 3 s | Built into `_get()` |
| **Dell iDRAC** | BIOS date at `Oem.Dell.DellSystem.BIOSReleaseDate` | Used for CVE tier |
| **Dell iDRAC** | Drive endurance at `Oem.Dell.DellPhysicalDisk.RemainingRatedWriteEndurancePercent` | Per-drive OEM key |
| **Dell iDRAC** | `System.SKU` populated with Service Tag (e.g. `7SBKS13`) | `DellCollector.oem_sku()` returns `""` if SKU equals Service Tag |
| **Supermicro** | Drives under `/Systems/{id}/SimpleStorage` (not `/Storage`) | Fallback path tried |
| **Supermicro** | HTML 404 pages on missing endpoints | `JSONDecodeError` trap in `_get()` |
| **Supermicro** | `/Storage` may be blocked by DCMS license → `OemLicenseNotPassed` | `_is_license_blocked()` |
| **Cisco IMC** | Singular `PowerControl` object (not a list) & singular `PowerMetric` | `collect_power` normalizes dict to list, supports `PowerMetric` |
| **Cisco IMC** | String numeric values (`"152"`, `"11.900"`, `"71"`) and `"N/A"` string sentinels | Handled via `collect_power._safe_num` coercion helper |
| **Cisco IMC** | Manager at `/Managers/CIMC` (not `/Managers/1`) | Handled via `oem_manager_paths` and `oem_fastpath_roots` |
| **Cisco IMC** | System path is serial number e.g. `/Systems/FCH2005V1EN` | Handled via `oem_fastpath_roots` / dynamic discovery |
| **Cisco IMC** | SEL at `/Chassis/1/LogServices/SEL` (Chassis level) | `collect_system_event_log()` probes Chassis log services |
| **Cisco IMC** | BIOS date in FirmwareInventory | Sourced via `oem_bios_date` from `/UpdateService/FirmwareInventory` |
| **Lenovo XCC** | Storage controller ID has underscore: `RAID_Slot1` | Replay harness and endpoints indexed via `@odata.id` |
| **Lenovo XCC** | BIOS date in FirmwareInventory | Sourced via `oem_bios_date` from `/UpdateService/FirmwareInventory` |
| **Lenovo XCC** | Gen-1 Features-on-Demand (FoD) licensing | `oem_license_info()` checks `/Managers/1/Oem/Lenovo/FoD/Keys` |
| **Lenovo XCC** | Fast-path roots at `/Systems/1`, `/Chassis/1`, `/Managers/1` | Handled via `oem_fastpath_roots` |
| **Dell iDRAC** | Fast-path roots at `/Systems/System.Embedded.1` | Handled via `oem_fastpath_roots` |
| **Quanta / QCT** | Self roots (`/Systems/Self`, `/Chassis/Self`, `/Managers/Self`), drive telemetry under `Oem.Quanta_RackScale` (not `Oem.Quanta`), shallow crawl leaves | `QuantaCollector.oem_fastpath_roots()`, multi-key `oem_drive_metrics()`, SimpleStorage fallback |
| **GIGABYTE** | Self roots (`/Systems/Self`), drive telemetry under `Oem.GBT` (e.g. `SlotNumber`, not `Oem.Gigabyte`), AMI MegaRAC | `GigabyteCollector.oem_fastpath_roots()`, multi-key `oem_drive_metrics()`, SimpleStorage fallback |
| **All vendors** | `/Systems` root `Members[0]` may be a full path like `/Systems/System.Embedded.1` | `_discover_roots()` uses Members[0] |
| **All vendors** | `/Systems/{id}/SecureBoot` — DMTF standard; older BMCs return 404 | `collect_secure_boot_redfish()` falls back to "Not Exposed" |

---

## 9.1 Redfish $expand & OEM Bulk Telemetry Profiles

For full architectural details, see [ADR-002: Multi-OEM Redfish $expand Architecture and Bulk Telemetry Retrieval Strategies](decisions/ADR-002-oem-redfish-expand-and-fastpath-telemetry.md).

| OEM Platform | $expand Support | Max Levels | Syntax | Target Collections, Pacing & Concurrency Strategy |
|---|:---:|:---:|:---:|---|
| **Dell PowerEdge** (iDRAC9/10) | **Yes** (Full) | 1 | `*` or `.` | `FirmwareInventory`, `EthernetInterfaces`, `ThermalSubsystem/Fans`, `Memory`, `Storage`. 17G Arbel scales to **5 inner workers**; 14G–16G to **3–4 workers**; 13G Pilot-3 clamped to **2 workers**. |
| **Lenovo ThinkSystem** (XCC/XCC2/XCC3) | **Yes** (Full) | **2** | `*` or `.` | Multi-level expand on `Chassis/1/NetworkAdapters` (pre-expands ports and NDFs), `Memory`, `FirmwareInventory`. V3/V4 AST2600 engages **pipelined zero-pacing (0.0s)** and **4 inner workers**. |
| **HPE ProLiant** (iLO 7, Gen12) | **Yes** (Full) | **5** | `*` or `.` | Full hierarchy expansion. Engages **pipelined zero-pacing (0.0s)** and **4–5 inner workers** with ultra-low latency (<103ms). |
| **HPE ProLiant** (iLO 5/6, Gen10/11) | **Partial** | 1 | **`.` ONLY** | `Systems/1/Memory`, `Chassis/1/Thermal`, `SmartStorage` inline disk arrays. Rejects `*` with HTTP 400. **3 inner workers**. |
| **HPE ProLiant** (iLO 4, Gen9) | **No** | N/A | None | Bypasses expand; standard member pagination. Clamped to **2 inner workers**. |
| **Cisco UCS** (CIMC M6+) | **Yes** (Full) | **2** | `*` or `.` | Multi-level expand on `NetworkAdapters` with **VIC subordinate pre-caching**, `EthernetInterfaces` (bulk vNICs), `Memory`. Scales to **4 inner workers**. |
| **Cisco UCS** (CIMC M4/M5) | **Bypass** | N/A | None | Standard enumeration; inline ports on `NetworkAdapters`; native XML API (`/nuova`). Clamped to **2–3 inner workers** with 0.10s pacing floor. |
| **Supermicro** (X10–X14) | **Bypass** | N/A | None | Single-GET `/Systems/1/SimpleStorage` (bypasses DCMS license) & monolithic `/Chassis/1/Thermal`. Pacing floor >=0.10s; **2 workers** on X10 (AST2400) to **3–4 workers** on X12–X14 (AST2600). |
| **GIGABYTE / MegaRAC** (AMI SP-X) | **Yes** (Full) | **5** | `*` or `.` | Multi-level expand on `/Systems/Self/Storage` and `/Memory`. **4 inner workers**. |
| **Quanta / QCT** | **Bypass** | N/A | None | Canonical `/Systems/Self` fast-path roots; shallow crawl tolerance. **2–3 inner workers**. |

---

## 10. Onboarding Checklist — Adding a New OEM

Follow these steps in order when adding support for a new OEM (or a new model generation from an existing OEM):

### Step 1: Vendor Detection

- [ ] Identify the `Manufacturer` string returned by `/Systems/{id}` for this OEM.
- [ ] If the OEM brand string is new, add it to `_KNOWN_VSPHERE_OEMS` (if applicable).
- [ ] Test that `sys_info["vendor"].upper()` produces a stable, matchable fragment.

### Step 2: `BIOS_BASELINES`

- [ ] Research the latest and minimum-recommended BIOS versions from the OEM support portal.
- [ ] Research `min_spectre` from the OEM's Spectre/Meltdown advisory (see §3 for sources).
- [ ] Choose a model key that is a unique uppercase substring of the Redfish `Model` string.
- [ ] Add entries for all relevant model variants (1-socket, 2-socket, AMD, Intel).

### Step 3: `BMC_FW_BASELINES`

- [ ] Identify the manager `Model` / `Name` Redfish field format for this OEM's BMC.
- [ ] Identify the latest and min-recommended BMC firmware versions.
- [ ] Add an entry with a key that will substring-match the manager model field.

### Step 4: `_VENDOR_SIDE_CHANNEL_LINKS`

- [ ] Locate the OEM's official Spectre/Meltdown security advisory URL.
- [ ] Add the vendor name fragment and `(url, display_label)` tuple.

### Step 5: `BCGLinkGenerator`

- [ ] Test the BCG server URL by searching for one of the new models on the BCG site.
- [ ] If vendor prefix noise causes a "no results" search, add a strip rule to `BCGLinkGenerator.server()`.

### Step 6: OEM-Specific Endpoint Quirks

- [ ] Test `/Systems/{id}/Bios` attributes on a real device (or firmware simulator).
- [ ] Note any non-standard paths for Storage, Managers, SEL, etc.
- [ ] Add code comments and, if needed, fallback logic to `collect_storage_subsystem()`,
  `collect_system_event_log()`, or `collect_bmc_license()`.

### Step 7: `DELL_MODEL_CHASSIS_DB` / `HPE_SKU_CHASSIS_DB` (if chassis bay count needed)

- [ ] For Dell: add model-suffix → `(bay_count, label)` entries for new storage variants.
- [ ] For HPE: add SKU → `(bay_count, label)` entries from QuickSpecs.

### Step 8: Test

- [ ] Run the tool against a real or simulated host.
- [ ] Confirm read-only BMC credentials function without write permission errors (see [Security Architecture](SECURITY_ARCHITECTURE.md) for vendor-specific least-privilege role setups).
- [ ] Verify `bios_eval.badge`, `bios_eval.spectre_badge`, `secure_boot.badge`, and `bmc_firmware.badge` render correctly in the HTML report.

---

## 11. Multi-Vendor SEL / IML Deep-Linking Engine

The deep-linking engine in `vcf_hci/report/sel_links.py` decodes vendor-proprietary System Event Log (SEL), Integrated Management Log (IML), and fault codes directly into verified official vendor documentation chapters:

### Dell PowerEdge EEMS Architecture
- **Canonical Architecture:** Uses canonical multi-generation reference URLs (`https://www.dell.com/support/manuals/en-us/poweredge-r740xd/error_event_message_guide_c/`) bound to verified DITA chapter GUIDs for 20+ hardware categories (`SEC`, `PSU`, `RDU`, `PDR`, `HWC`, `MEM`, `PST`, `BOOT`, `CTL`, `PCI`, `TMP`, `TMPS`, `VLT`, `OSE`, `CUMP`, `FLDC`, `NINT`, `NNOD`, `NVCH`, `SEL`, `SRV`, `TST`).
- **Raw IPMI Hex Translation:** Maps 76 distinct raw IPMI hexadecimal sensor event codes to their canonical EEMS chapters (e.g. CPU machine check `07a60140`, memory self-healing `07a3c001`, multi-bit ECC `6fa1c001`, PCIe fatal bus errors `6fa91800`–`6fac283c`, cooling threshold `01520004`, and dynamic drive bay removal `efa00100` &rarr; `PDR1016`).
- **Safe Fallback Routing:** Unknown or unindexed event prefixes route safely to the Master Reference Guide Root Index to avoid 404 / topic errors.

### HPE ProLiant IML Resolution
- **Format:** Decodes `<class_decimal>.<code_decimal>` conventions (e.g. `19.22` for storage predictive failure, `2.35` for fan redundancy, `10.5920` for SMART drive replacement, `51.7` for backplane management, `50.1122` for uncorrectable memory threshold).
- **Target URL:** Maps class and code to the official *HPE Gen12 IML Troubleshooting Guide*:
  `https://support.hpe.com/hpesc/public/docDisplay?docId=ilogen12-msg-en_us&page=class0x{c:04x}code0x{code:04x}-gen12.html`

### Cisco UCS IMC Faults Mapping
- **Catalog:** Maps all 114 standard `F\d{4}` fault codes (e.g. `F0409`, `F0462`, `F0510`, `F0744`, `F1008`, `F1744`), 116 named `flt*` symbols (`fltEquipmentFanDegraded`, `fltBiosUnitFD0FailedSecurityVerification`), and component prefixes directly to corresponding chapters in the *Cisco UCS Integrated Management Controller Faults Reference Guide*.

- [ ] Confirm `build_fleet_tiles_html()` Tile 2 and Tile 14 reflect the new host's spectre status.

### Step 9: Update This Document

- [ ] Add a row to the appropriate section above (BIOS Baselines, BMC Baselines, endpoint quirks).
- [ ] Note the OEM's version format if it differs from existing patterns.
