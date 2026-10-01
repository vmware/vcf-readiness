# Adding OEM Support — Full ABC Interface Reference

This guide is the authoritative reference for implementing a new OEM Redfish adapter in the VCF Readiness Tool.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Full OEM Hook Interface](#full-oem-hook-interface)
- [Step-by-Step: Adding a New Vendor](#step-by-step-adding-a-new-vendor)
- [Tips for Tricky BMCs](#tips-for-tricky-bmcs)
- [Contributing Chassis Maps \& Front Panel Layouts](#contributing-chassis-maps--front-panel-layouts)

---

```
vcf_hci/collector/
├── base.py                  ← BaseRedfishCollector ABC (core scan pipeline)
├── http_session.py          ← RedfishSessionManager (session lifecycle)
├── discovery.py             ← DiscoveryMixin (dynamic URI root discovery)
├── os_eval.py               ← _evaluate_os_info (OS build & lifecycle evaluation)
├── async_helpers.py         ← Asynchronous execution helpers & timers
├── collect_system.py        ← _SystemMixin  (CPU, memory, BIOS, TPM)
├── collect_storage.py       ← _StorageMixin (NVMe, SAS, RAID detection)
├── collect_network.py       ← _NetworkMixin (NICs, FC HBAs, LLDP)
├── collect_power.py         ← _PowerMixin   (PSUs, thermal)
├── collect_telemetry.py     ← _TelemetryMixin (CPU/memory utilization)
├── collect_gpu.py           ← _GPUMixin      (PCIe, accelerators)
├── collect_logs.py          ← _LogsMixin     (SEL/IML)
├── pci_utils.py             ← PCI vendor/device ID resolution
└── oem/
    ├── __init__.py          ← _REGISTRY + create_collector() factory
    ├── generic.py           ← GenericCollector (pure DMTF, your starting point)
    ├── dell.py              ← DellCollector
    ├── hpe.py               ← HPECollector
    ├── supermicro.py        ← SupermicroCollector
    ├── cisco.py             ← CiscoCollector
    ├── lenovo.py            ← LenovoCollector
    ├── intel.py             ← IntelBMCCollector
    ├── quanta.py            ← QuantaCollector
    └── gigabyte.py          ← GigabyteCollector
```

`UniversalRedfishCollector` (the name exposed in the public API for backward compatibility) is assembled by combining `BaseRedfishCollector` with all the mixin classes. OEM subclasses override **hook methods** only — the core scan loop in `base.py` is shared by everyone.

---

## Full OEM Hook Interface

```python
class BaseRedfishCollector:

    # ── Identification ────────────────────────────────────────────────────
    VENDOR_MATCH: tuple[str, ...] = ()
    # Tuple of uppercase vendor string fragments. create_collector() matches
    # the Manufacturer field from /Systems/{id} against these. Case-insensitive.
    # Example: ("DELL", "IDRAC") matches "Dell Inc." and "iDRAC Embedded"

    # ── BIOS / Firmware ───────────────────────────────────────────────────
    def oem_bios_date(self, sys_data: dict) -> str:
        """
        Extract the BIOS release date string from /Systems/{id} data.

        Args:
            sys_data: Full /Systems/{id} response dict.
        Returns:
            Date string (any format is accepted — displayed verbatim) or "N/A".

        OEM paths:
            Dell:  sys_data["Oem"]["Dell"]["DellSystem"]["BIOSReleaseDate"]
            HPE:   sys_data["Oem"]["Hpe"]["Bios"]["Current"]["Date"]
            Generic default: "N/A"
        """

    # ── SKU / Product ID ──────────────────────────────────────────────────
    def oem_sku(self, sys_data: dict) -> str:
        """
        Return the marketing SKU or part number.

        Args:
            sys_data: Full /Systems/{id} response dict.
        Returns:
            SKU string or "N/A".

        OEM paths:
            HPE: sys_data["Oem"]["Hpe"]["ProductId"]
            Generic default: sys_data.get("SKU", "N/A")
        """

    # ── Storage ───────────────────────────────────────────────────────────
    def oem_storage_endpoints(self) -> list[str]:
        """
        Return a list of additional storage endpoint URIs to scan beyond
        the standard /Systems/{id}/Storage path.

        Returns:
            List of absolute Redfish URIs (strings).

        OEM examples:
            HPE:        ["{sys_uri}/SmartStorage/ArrayControllers"]
            Supermicro: ["{sys_uri}/SimpleStorage"]
            Generic:    []

        Note: self.sys_uri is available and populated before this is called.
        """

    # ── Drive Wear ────────────────────────────────────────────────────────
    def oem_drive_endurance(self, drive_data: dict) -> float | None:
        """
        Extract the remaining write endurance percentage for SSDs.

        Args:
            drive_data: A single drive member dict from the Storage collection.
        Returns:
            Float 0–100 representing % remaining endurance, or None if unavailable.

        OEM paths:
            Dell: drive_data["Oem"]["Dell"]["DellPhysicalDisk"]
                           ["RemainingRatedWriteEndurancePercent"]
            Generic: None
        """

    # ── Drive Metrics ─────────────────────────────────────────────────────
    def oem_drive_metrics(self, drive_json: dict) -> dict:
        """
        Vendor-specific drive telemetry (power_on_hours, part_number, predictive_failure, …).

        Args:
            drive_json: A single drive member dict from the Storage collection.
        Returns:
            Dict of OEM drive telemetry metrics. Default: {}

        OEM examples:
            Dell Oem.Dell.DellPhysicalDisk; Lenovo Oem.Lenovo.Drive; Cisco Oem.Cisco / Oem.CIMC
        """

    # ── CPU Cache ─────────────────────────────────────────────────────────
    def oem_cpu_cache(self, proc_data: dict) -> list[dict]:
        """
        Extract cache level detail from a processor member dict.

        Args:
            proc_data: A single processor member dict.
        Returns:
            List of dicts with keys: Level (str), SizeKiB (int).
            Empty list if unavailable.

        OEM paths:
            Dell: proc_data["Oem"]["Dell"]["DellProcessor"]["Cache"]
            HPE:  proc_data["Oem"]["Hpe"]["Cache"]
            Generic: []
        """

    # ── Memory Utilization ────────────────────────────────────────────────
    def oem_memory_usage(self, sys_data: dict) -> dict:
        """
        Return vendor-specific memory bus / DRAM utilization metrics.

        Args:
            sys_data: Full /Systems/{id} response dict.
        Returns:
            Dict with at minimum {"MemoryBusUtilization": float} or empty dict.

        OEM paths:
            HPE: sys_data["Oem"]["Hpe"]["SystemUsage"]
            Generic: {}
        """

    # ── NIC Firmware ─────────────────────────────────────────────────────
    def oem_nic_firmware(self, adapter: dict) -> str:
        """
        Extract firmware version for a NIC adapter.

        Args:
            adapter: A single NetworkAdapter member dict.
        Returns:
            Firmware version string or "N/A".

        Generic default: adapter.get("FirmwarePackageVersion", "N/A")
        """

    # ── License ───────────────────────────────────────────────────────────
    def oem_license_info(self, mgr_data: dict, sys_data: dict) -> dict:
        """
        Return BMC license information.

        Args:
            mgr_data: Full /Managers/{id} response dict.
            sys_data: Full /Systems/{id} response dict (some vendors put
                      license info on the system resource).
        Returns:
            Dict with keys:
                license_name (str): Human-readable license tier name.
                badge (str):        HTML badge fragment or "".

        OEM paths:
            HPE: mgr_data["Oem"]["Hpe"]["License"]["Name"]
            Generic: {"license_name": "N/A", "badge": ""}
        """

    # ── Retry Logic ───────────────────────────────────────────────────────
    def oem_handle_retry(self, data: dict, endpoint: str) -> bool:
        """
        Return True if the response indicates a transient "not ready" state
        that should trigger a single automatic retry after a short delay.

        Args:
            data: Parsed JSON response dict (may be an error body).
            endpoint: The Redfish URI that was just queried.
        Returns:
            True  → caller will wait 3 seconds and retry once.
            False → treat data as the final result.

        OEM example:
            HPE: checks for MessageId "HpeCommon.1.1.ResourceNotReadyRetry"
                 in data["@Message.ExtendedInfo"][0]["MessageId"]
            Generic: False
        """

    # ── Manager Paths ─────────────────────────────────────────────────────
    def oem_manager_paths(self) -> list[str]:
        """
        Return a prioritized list of /Managers/{id} URIs to try when the
        standard /Managers/1 path is not present.

        Returns:
            Ordered list of absolute URIs to probe (first reachable wins).

        OEM example:
            Cisco: ["/redfish/v1/Managers/CIMC"]
            Generic: []
        """

    # ── Fast-Path Root Discovery ──────────────────────────────────────────
    def oem_fastpath_roots(self) -> Optional[Tuple[List[str], List[str], List[str]]]:
        """
        Return pre-resolved (system_uris, chassis_uris, manager_uris) tuples
        to bypass full collection iteration when standard paths are known.

        Returns:
            Tuple of ([sys_uris], [chassis_uris], [mgr_uris]) if reachable,
            or None to fall back to dynamic Redfish root enumeration.

        OEM examples:
            Dell:   (["/redfish/v1/Systems/System.Embedded.1"], ["/redfish/v1/Chassis/System.Embedded.1"], ["/redfish/v1/Managers/iDRAC.Embedded.1"])
            Lenovo: (["/redfish/v1/Systems/1"], ["/redfish/v1/Chassis/1"], ["/redfish/v1/Managers/1"])
            Cisco:  probes /Managers/CIMC, returns serial-keyed system and chassis paths
            Generic default: None
        """
```

---

## Step-by-Step: Adding a New Vendor

### 1. Capture Redfish Data

Use the bundled pure-standard-library capture tool to capture a full Redfish tree and endpoint manifest from the target BMC (zero pip dependencies):

```bash
python tools/crawl_oem_host.py -r <BMC_IP> -u <USER> -p <PASSWORD> -D samples/<vendor> --zip
```

The output directory contains DMTF-compliant JSON files for every endpoint along with `endpoints_manifest.json` and `endpoints_manifest.csv`. Save them in `samples/<vendor>/`.

### 2. Identify Non-Standard Paths

Look at the captured data and note any OEM-specific response fields. Common patterns:

| What to look for | Usually in |
|-----------------|-----------|
| BIOS date | `/Systems/{id}` → `Oem.<Vendor>.<BiosSection>.Date` |
| Part number | `/Systems/{id}` → `Oem.<Vendor>.ProductId` or `SKU` |
| Storage tree | A non-standard subtree off `/Systems/{id}/` |
| Drive wear | Per-drive `Oem.<Vendor>.<DiskSection>.WearPercent` |
| License | `/Managers/{id}` → `Oem.<Vendor>.License` |

### 3. Create the Collector

```python
# vcf_hci/collector/oem/myvendor.py
from .generic import GenericCollector


class MyVendorCollector(GenericCollector):
    """Collector for MyVendor servers."""

    VENDOR_MATCH = ("MYVENDOR",)

    def oem_bios_date(self, sys_data: dict) -> str:
        return (
            sys_data.get("Oem", {})
                    .get("MyVendor", {})
                    .get("BiosDate", "N/A")
        )
```

### 4. Register in the Factory

```python
# vcf_hci/collector/oem/__init__.py
from .myvendor import MyVendorCollector

_REGISTRY: list = [
    # ... existing entries ...
    (MyVendorCollector.VENDOR_MATCH, MyVendorCollector),
]
```

Note: first match wins; put more specific vendors before generic ones. Intel is last among named vendors; Generic is the fallback outside the list.

### 5. Add Tests

Create `tests/test_collector_myvendor.py` (or add a class to `test_collector_oem.py`):

```python
from vcf_hci.collector.oem.myvendor import MyVendorCollector

class TestMyVendorCollector:
    def test_oem_bios_date(self):
        c = MyVendorCollector("10.0.0.1", "admin", "admin")
        data = {"Oem": {"MyVendor": {"BiosDate": "2024-06-01"}}}
        assert c.oem_bios_date(data) == "2024-06-01"

    def test_oem_bios_date_fallback(self):
        c = MyVendorCollector("10.0.0.1", "admin", "admin")
        assert c.oem_bios_date({}) == "N/A"
```

### 6. Run Tests

```bash
python -m pytest tests/ -v
```

All existing tests must still pass.

---

## Tips for Tricky BMCs

### HTML 404 Responses (Supermicro-style)

Some BMCs return an HTML page instead of a JSON error when an endpoint doesn't exist. The `_get()` method in `base.py` already traps `json.JSONDecodeError` globally, so this is handled automatically. You don't need to add extra error handling.

### Transient Not-Ready Errors

If a BMC temporarily returns a "scan in progress" or "not ready" JSON body (as HPE iLO does during boot), override `oem_handle_retry()`. The caller will automatically wait 3 seconds and retry once.

---

## Contributing Chassis Maps & Front Panel Layouts

In addition to Redfish collector hooks, OEMs and partners are encouraged to contribute chassis mapping data to enhance visual report fidelity:
- **Order SKUs & Model Databases**: Add entries to `DELL_SKU_CHASSIS_DB`, `HPE_SKU_CHASSIS_DB`, or `DELL_MODEL_CHASSIS_DB` in `vcf_hci/constants.py`.
- **Chassis SVG Overlays**: Submit slot numbering patterns and vector front-panel graphics for standalone HTML report diagrams.
- **Redfish Dump Mockups**: Submit sanitized BMC JSON dumps via `tools/crawl_oem_host.py` to populate `samples/<vendor>/`.

### Non-Standard Manager URI

If the BMC's Manager resource is not at `/Managers/1`, override `oem_manager_paths()` to return the correct URI(s). The discovery code tries each in order and uses the first that responds.

### License-Gated Endpoints (Supermicro DCMS)

Some vendors gate certain Redfish endpoints behind a license. The base `_get()` method calls `_is_license_blocked()` which checks for `OemLicenseNotPassed` in the error response. The resulting badge is surfaced in the HTML report automatically.
