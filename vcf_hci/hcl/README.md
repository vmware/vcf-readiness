# Broadcom HCL Subpackage (`vcf_hci.hcl`)

The HCL package loads local compatibility datasets, imports and exports dark-site bundles, and correlates collected component evidence. Ordinary loads never download data. Missing or stale data does not establish hardware certification.

## APIs and data flow

- `loader.py`: `load_vsan_hcl_json(local_path=None, refresh_live=False, max_age_days=30)` reads local JSON and builds model/PCI indexes. Only `refresh_live=True` permits a public Broadcom download; a stale file can still be read locally. `load_optional_vsan_csv()` loads CSV data, `load_io_nics_catalog()` loads the packaged Network I/O catalog, and `get_hcl_cache_status()` reports freshness and provenance.
- `bundle_manager.py`: `get_hcl_dir()` selects storage. `ensure_auto_hcl_bundle()` looks for existing local bundles without downloading. `create_hcl_bundle()` implements explicit `--bundle-hcl` creation; `import_hcl_bundle()` implements `--import-hcl` import. `HCLBundleManager` provides static wrappers for those bundle operations.
- `cross_reference.py`: `cross_reference_device()` and `lookup_unique_hcl_device()` match PCI evidence; `cross_reference_drive()` matches drive evidence; `evaluate_drive_hcl_tier()` interprets drive certification tiers. Match confidence, release, driver, firmware, and ESA/OSA qualification remain distinct.
- `export_bundle.py`: exports the active local datasets with provenance through the browser dark-site transfer workflow, without a live refresh.

## Storage and operator controls

`get_hcl_dir()` uses `~/.vcf-readiness/hcl/`, falling back to the current directory if that location cannot be created. The local vSAN dataset is `all.json`; packaged `vcf_hci/hcl/io_nics.json` is the separate Network I/O catalog. Created bundles default to `vcf_hcl_bundle_<date>.zip` in the selected HCL directory. CSV discovery checks an explicit path, the HCL directory, and supported current-directory patterns; see `load_optional_vsan_csv()`.

Use `--refresh-hcl`, `--bundle-hcl`, or the browser refresh action when a public download is intended. `--import-hcl` and browser export of active local data support transfer into isolated environments. A 30-day age threshold is a freshness indicator, not an automatic refresh schedule. Baseline or unverified data must remain labeled as such in readiness workflows.

See [installation and dark-site operation](../../docs/INSTALL.md#offline-and-air-gapped-operation) and [architecture](../../ARCHITECTURE.md).

## Memory Tiering drive listings

`memory_tiering_catalog.py` is the packaged public BCG `memorytier` fallback with
model, partner, product ID, listed releases and retrieval date. The active local
cache is `memory_tiering.json`. Online Web UI launch refreshes vSAN and Memory
Tiering data once in the background and rebuilds the local bundle; suppress this
with `--no-hcl-auto-refresh` or preload `--import-hcl`. The Refresh Live HCL action
and CLI `--refresh-hcl` / `--bundle-hcl` also refresh Memory Tiering. Failed/partial downloads retain
the last valid cache or packaged fallback. No network request runs during report
generation or ordinary HCL loading.

CLI bundle creation and browser ZIP export include `memory_tiering.json`. Import
uses that ZIP's catalog ahead of local data, including its own retrieval date;
older ZIPs fall back to the packaged snapshot. Export preserves the selected
bundle's catalog and includes it in the manifest and SHA-256 inventory. The
developer fallback generator remains `python tools/sync_memory_tiering.py`;
`--input` supports a previously retrieved viewResults response.

`memory_tiering.py` uses exact model names, complete SKU tokens or exact local HCL
aliases with capacity checks. A Mem Tier badge establishes a catalog listing;
firmware/release/deployment validation remains separate. Family-only or unknown
matches stay untagged. The web `--nvme-namespace-preview` flag additionally enables
TLC RI 1 DWPD ESA drives and their namespace-sizing Help. Identification requires
explicit rated NAND/endurance metadata or a reviewed product brief (including exact
HCL aliases for OEM SKUs); absence from the QLC list never proves TLC. Extend the
reviewed evidence registry for additional opaque models rather than guessing.
