# Contributing to VCF Readiness Tool

Thank you for your interest in contributing! This guide covers everything you need to get started.

## Table of Contents

- [Quick Start](#quick-start)
- [Adding OEM Support](#adding-oem-support)
- [Changing Compatibility Rules](#changing-compatibility-rules)
- [Code Style](#code-style)
- [Running Tests](#running-tests)
- [Opening a Pull Request](#opening-a-pull-request)

---

## Quick Start

```bash
git clone https://github.com/vmware/vcf-readiness.git
cd Distribution-Redfish-Scraper

# Python 3.9+ required, no pip install needed (zero external runtime deps)
python3 vcf_hci/cli.py --help

# Run tests (requires pytest — only dev dependency)
pip install pytest
python -m pytest tests/ -v
```

---

## Adding OEM Support

The tool uses an **OEM ABC pattern**: each vendor gets a single file in `vcf_hci/collector/oem/` that subclasses `GenericCollector` and overrides only the methods that differ from DMTF-standard Redfish.

### 5-Step Recipe

**1. Create the file**

```bash
touch vcf_hci/collector/oem/myvendor.py
```

**2. Subclass `GenericCollector`**

```python
# vcf_hci/collector/oem/myvendor.py
from .generic import GenericCollector


class MyVendorCollector(GenericCollector):
    """Collector for MyVendor servers (MyBMC firmware)."""

    VENDOR_MATCH = ("MYVENDOR", "MY VENDOR INC")  # matched case-insensitively

    # Override only the hooks that behave differently
    def oem_bios_date(self, sys_data: dict) -> str:
        return (
            sys_data.get("Oem", {})
                    .get("MyVendor", {})
                    .get("BiosReleaseDate", "N/A")
        )
```

**3. Register it**

```python
# vcf_hci/collector/oem/__init__.py
from .myvendor import MyVendorCollector

_REGISTRY = [
    ...
    (("MYVENDOR",), MyVendorCollector),
]
```

**4. Write a test**

```python
# tests/test_collector_oem.py — add a new class
class TestMyVendorCollector:
    def test_oem_bios_date(self):
        c = MyVendorCollector("10.0.0.1", "admin", "admin")
        data = {"Oem": {"MyVendor": {"BiosReleaseDate": "2024-01-15"}}}
        assert c.oem_bios_date(data) == "2024-01-15"
```

**5. Open a PR** — see [Opening a Pull Request](#opening-a-pull-request)

### Available OEM Hook Methods

| Method | Default Behavior | Override When |
|--------|-----------------|---------------|
| `oem_bios_date(sys_data)` | Returns `"N/A"` | Vendor stores BIOS date in an OEM key |
| `oem_sku(sys_data)` | Returns `sys_data.get("SKU", "N/A")` | Vendor stores part number in OEM section |
| `oem_storage_endpoints()` | Returns `[]` | Vendor has additional storage trees (e.g., HPE SmartStorage) |
| `oem_drive_endurance(drive)` | Returns `None` | Vendor exposes drive wear % in OEM fields |
| `oem_drive_metrics(drive_json)` | Returns `{}` | Vendor-specific drive telemetry (power_on_hours, part_number, predictive_failure, …) |
| `oem_cpu_cache(proc_data)` | Returns `[]` | Vendor exposes L1/L2/L3 details in OEM fields |
| `oem_memory_usage(sys_data)` | Returns `{}` | Vendor exposes memory bus utilization outside TelemetryService |
| `oem_nic_firmware(adapter)` | Returns `FirmwarePackageVersion` field | Vendor uses a different field name |
| `oem_license_info(mgr, sys)` | Returns `{"license_name": "N/A", "badge": ""}` | Vendor has a meaningful license tier |
| `oem_handle_retry(data, ep)` | Returns `False` | BMC returns a retry-later JSON message (e.g., HPE ResourceNotReadyRetry) |
| `oem_manager_paths()` | Returns `[]` | BMC Manager URI does not follow `Managers/1` standard (e.g., Cisco CIMC) |

For the complete interface reference, see [`docs/adding-oem-support.md`](docs/adding-oem-support.md).

### OEM & Hardware Vendor Collaboration (Chassis Maps, Diagrams & Redfish Payloads)

Server OEMs, hardware vendors, and solution partners are strongly encouraged to collaborate with us to ensure their hardware platforms are accurately represented and assessed:

- **Chassis Drive Bay Maps & SKUs**: Provide mappings for order SKUs or part numbers to physical drive bay configurations (e.g. 10 SFF, 16 SFF, 24 SFF, 16 EDSFF, 4 LFF, 12 LFF) for addition to `DELL_SKU_CHASSIS_DB`, `HPE_SKU_CHASSIS_DB`, `DELL_MODEL_CHASSIS_DB`, or new vendor-specific chassis lookup tables.
- **Chassis Diagrams & Front Panel Vector Graphics**: Provide SVG layouts, slot numbering conventions (vertical 2x5 pairing vs horizontal row-major), or front panel graphics to enhance standalone HTML report chassis visualizations.
- **Redfish Payloads & OEM Schema Extension**: Provide sanitized Redfish JSON dumps (captured via `tools/redfishMockupCreate.py`) to help test storage controller enumeration, drive slot placement (`Location.Placement.Bay`), wear reporting, and health status without requiring physical hardware in test labs.

---

## Changing Compatibility Rules

### CPU Verdicts

Edit `vcf_hci/compat/cpu.py` → `evaluate_cpu()` (re-exported by `VCF9CompatibilityEngine.evaluate_cpu()` in `vcf_hci/compat_engine.py`).

The matching logic uses regex patterns on the CPU model string to return the VCF 9.1 support status, microarchitecture label, memory channels, memory speed, and PCIe lane ceiling:

```python
# In vcf_hci/compat/cpu.py evaluate_cpu():
if re.search(r"\bNEW_FAMILY\b", s):
    return "🟢 Fully Supported", "New Microarchitecture (8 Channel DDR5)", 8, 5600, 128
```

### BIOS Baselines

Add rows to `BIOS_BASELINES` in `vcf_hci/constants.py`:

```python
"ProLiant DL360 Gen11": {
    "baseline": "U46",
    "date": "2024-09-15",
    "cve_tier": 3,
},
```

### vSAN HCL

Drop a new `vSAN SSD_MM-DD-YYYY.csv` into the `hcl/` directory. The tool auto-selects the newest file at startup.

---

## Code Style

- **Zero external dependencies** — use only Python 3.9+ stdlib. Forbidden: `requests`, `pandas`, `jinja2`.
- **Python 3.9 compatible** — use `Optional[X]` / `Union[X, Y]`, not `X | Y` in type hints.
- **f-strings** for all string formatting.
- **`.get()` with defaults** for all dict access — never assume Redfish keys exist.
- **No `print()`** outside the CLI block — use `logger.debug/info/warning`.
- **`sanitize_filename()`** on any string used as a filename.
- **No comments** that just narrate what the code does; comment non-obvious OEM behavior only.

---

## Running Tests

```bash
# Install the only dev dependency
pip install pytest

# Run all tests
python -m pytest tests/ -q

# Run vendor or test-category filtered tests
python -m pytest -m dell
python -m pytest -m replay
python -m pytest -m "not replay"   # optional

# Run a specific test file
python -m pytest tests/test_compat_engine.py -v

# Run a specific test
python -m pytest tests/test_bcg_links.py::TestServerURLs::test_dell_poweredge_strips_prefix -v
```

Tests never touch a real BMC — they use pre-canned fixture dicts in `tests/fixtures/`.

---

## Opening a Pull Request

1. Fork and create a branch: `git checkout -b oem/myvendor`
2. Make your changes with tests.
3. Run `python -m pytest tests/ -v` and confirm all tests pass.
4. Push and open a PR against `main`.
5. Fill in the PR template (auto-loaded from `.github/pull_request_template.md`).

CI will run pytest automatically on every PR. PRs with failing tests will not be merged.

---

## Working with the Web UI

### Running the web UI in dev mode

No build step needed. From the project root:

```bash
python vcfr_web.py
# Opens http://127.0.0.1:7182 in your default browser
```

Press `Ctrl-C` in the terminal or click **Quit** in the browser to stop the server. Any changes to `vcf_hci/web/server.py` or `vcf_hci/web/app_html.py` take effect on the next `python vcfr_web.py` run (the server is not a live-reload dev server).

### `vcf_hci/web/assets.py` is auto-generated

`vcf_hci/web/assets.py` is **auto-generated** by `tools/bundle_assets.py`. It contains Clarity Design System CSS compressed with gzip and encoded in base64 so the web UI can embed it without an internet connection.

**Never include `vcf_hci/web/assets.py` in a pull request.** It is a large, machine-generated file. If your PR changes the Clarity CSS version, run `tools/bundle_assets.py` locally and verify the UI looks correct — but omit the file from the PR diff.

> The `.gitattributes` file marks `vcf_hci/web/assets.py` as `linguist-generated=true` so GitHub collapses it in diffs automatically.

### Refreshing the bundled Clarity CSS

If a new Clarity CSS release is available and you want to update it:

```bash
# Requires internet access — dev only
python tools/bundle_assets.py
```

This fetches the latest Clarity CSS, compresses it, and overwrites `vcf_hci/web/assets.py`. Re-run the web UI to verify everything still looks correct before committing.

---

## Reporting Bugs / Requesting New OEM Support

Use the GitHub Issue templates:

- **Bug report** — for crashes, incorrect data, or wrong compatibility verdicts.
- **OEM Support Request** — for BMC controllers not yet supported. Include a Redfish capture from `tools/redfishMockupCreate.py`.
- **Feature Request** — for new hardware checks, report sections, or CLI flags.

---

## License

CA, Inc. License — see [LICENSE.md](LICENSE.md)

