# Redfish Collector Subpackage (`vcf_hci.collector`)

> Layer A Redfish collection engine, domain mixins, and vendor-specific OEM adapter subclasses.

---

## Architecture & Class Hierarchy

`BaseRedfishCollector` is an Abstract Base Class inheriting domain mixin classes. Vendor subclasses inherit from `GenericCollector` (which inherits `BaseRedfishCollector`) and override specific OEM hooks:

```
                  BaseRedfishCollector (base.py)
   ┌────────────────────┴────────────────────────────────┐
   │ Domain Mixins:                                     │
   │   • _SystemMixin (collect_system.py)              │
   │   • _StorageMixin (collect_storage.py)            │
   │   • _NetworkMixin (collect_network.py)            │
   │   • _PowerMixin (collect_power.py)                │
   │   • _LogsMixin (collect_logs.py)                  │
   │   • _TelemetryMixin (collect_telemetry.py)        │
   │   • _GPUMixin (collect_gpu.py)                    │
   └────────────────────┬────────────────────────────────┘
                        │
                 GenericCollector (oem/generic.py)
   ┌────────────────────┼───────────────────┬───────────────────┐
   │                    │                   │                   │
DellCollector      HPECollector    SupermicroCollector    CiscoCollector ...
(oem/dell.py)      (oem/hpe.py)    (oem/supermicro.py)    (oem/cisco.py)
```

### Assessment Collector vs. Hypermedia Crawler

- **Assessment Engine (`BaseRedfishCollector` & Mixins)**: Targeted, concurrent query execution across known hardware endpoints (`/Systems`, `/Storage`, `/NetworkAdapters`, `/Chassis`, `/SessionService`) optimized for fast sub-minute readiness scans.
- **Diagnostic Crawler (`crawler.py` / `RedfishCrawler`)**: Full-tree hypermedia discovery engine that traverses arbitrary BMC implementations via `@odata.id` links without prior schema assumptions. Safely skips mutation actions (`/actions/`), bounds recursion depth, caps high-volume collection logs, and exports DMTF-compliant offline mockups.

---

## Files & Modules Index

- **`SCANNING_OPTIMIZATIONS.md`**: Comprehensive architectural reference for scanning optimizations, two-tier concurrency, phase task isolation, adaptive throttling, and OEM hardware quirks.
- **`base.py`**: `BaseRedfishCollector` ABC. Provides HTTP Basic Auth, SSL bypass (`ssl.CERT_NONE`), negative endpoint caching, assessment orchestrator (`run_assessment`, `rescan_partial_sections`), and default OEM hook definitions.
- **`crawler.py`**: `RedfishCrawler` hypermedia crawler. Discovers and catalogs all reachable Redfish endpoints via recursive `@odata.id` link traversal with cycle detection, mutation action exclusion, log collection capping, and DMTF mockup ZIP export.
- **`http_session.py`**: `RedfishSessionManager` managing Redfish session creation, pinned TLS openers, guaranteed session teardown (`DELETE`), persistent Keep-Alive connection pooling (`StdlibHTTPConnectionPool`) with 1:1 worker alignment, and dynamic inter-request pacing (`compute_request_pacing`).
- **`discovery.py`**: `DiscoveryMixin` providing dynamic URI root discovery (`/Systems`, `/Chassis`, `/Managers`), BMC silicon architecture classification (`classify_bmc_silicon` across 5 silicon eras), inner worker ceiling sizing (`determine_inner_worker_ceiling`), and PCIe NIC product name resolution.
- **`os_eval.py`**: `_evaluate_os_info` helper evaluating OS name, build numbers, lifecycle/EOL status, and ESXi update badges.
- **`async_helpers.py`**: Asynchronous execution helpers (`_safe_result`, `_timed`, `_h`, `_SECTION_DEFAULTS`).
- **`collect_system.py`**: `_SystemMixin` collecting host SKU, serial, CPU inventory, memory DIMMs, and BIOS release date.
- **`collect_storage.py`**: `_StorageMixin` enumerating storage controllers, physical drives, NVMe SSDs, RAID volumes, and drive endurance/wear metrics.
- **`collect_network.py`**: `_NetworkMixin` collecting Ethernet NIC adapters, port speeds, Fibre Channel (FC) HBAs with WWPNs, and Cisco VIC subordinate port/device function pre-caching.
- **`collect_power.py`**: `_PowerMixin` checking PSU count, redundancy status, and voltage ranges.
- **`collect_logs.py`**: `_LogsMixin` retrieving System Event Log (SEL) and Integrated Management Log (IML) alarms.
- **`collect_telemetry.py`**: `_TelemetryMixin` reading thermal sensors, fan speeds, and CPU/memory utilization metrics.
- **`collect_gpu.py`**: `_GPUMixin` enumerating discrete NVIDIA, AMD, and Intel GPUs.
- **`pci_utils.py`**: Utilities for parsing PCI Vendor/Device ID quads (`Vendor:Device:SubVendor:SubDevice`), matching cached PCIe devices, and short-circuit PCI extraction for expanded Redfish collections.
- **`oem/`**: Vendor-specific collector factory and subclasses:
  - **`oem/__init__.py`**: `create_collector()` factory matching vendor string to OEM subclass via `_REGISTRY`.
  - **`oem/generic.py`**: Default DMTF Redfish collector implementation.
  - **`oem/dell.py`**: Dell iDRAC collector (`Oem.Dell` physical disk endurance, BIOS date, warranty tag).
  - **`oem/hpe.py`**: HPE iLO collector (`SmartStorage` controllers, `Oem.Hpe.SystemUsage`, 3s retry handler).
  - **`oem/supermicro.py`**: Supermicro BMC collector (`SimpleStorage` fallback, DCMS license gate detection).
  - **`oem/cisco.py`**: Cisco IMC collector (`/Managers/CIMC` path, chassis-level SEL).
  - **`oem/lenovo.py`**: Lenovo XCC collector (`LicenseService` tiering).
  - **`oem/intel.py`**: Intel BMC collector.

---

## OEM Hook API Reference

To add or modify vendor-specific Redfish behaviors, override these hook methods on a `GenericCollector` subclass in `vcf_hci/collector/oem/`:

| Method Hook | Default Return | Purpose |
|-------------|----------------|---------|
| `oem_bios_date(sys_data)` | `""` | Extract vendor BIOS release date string |
| `oem_sku(sys_data)` | `""` | Extract host part number / SKU |
| `oem_storage_endpoints()` | `[]` | Return extra OEM storage URIs (e.g. SmartStorage) |
| `oem_drive_endurance(drive)` | `None` | Extract remaining drive write endurance % |
| `oem_cpu_cache(proc_data)` | `[]` | Extract L1/L2/L3 CPU cache hierarchy |
| `oem_memory_usage(sys_data)`| `{}` | Extract memory bus utilization telemetry |
| `oem_nic_firmware(adapter)` | `""` | Extract NIC firmware version string |
| `oem_license_info(mgr, sys)`| `{}` | Extract BMC license state and tier badge |
| `oem_handle_retry(data, uri)`| `False` | Handle transient 503/Busy errors (e.g. iLO ResourceNotReady) |
| `oem_manager_paths()` | `[]` | Return non-standard Manager URIs (e.g. `/Managers/CIMC`) |
