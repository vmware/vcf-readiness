# Architecture

VCF Readiness is a Python 3.9+ application. Native collection and the local UI use the standard library. Two local entry points share that runtime:

- `vcfr_web.py` and `python -m vcf_hci.web` call `vcf_hci.web.main`: loopback browser UI.
- `vcfr_collector.py` and `python -m vcf_hci` call `vcf_hci.cli.main`: command-line collector and offline renderer.

`redfish_web.py` and `redfish_collector.py` are backward-compatible shims for those same entry points.

Both native paths use the same scan, enrichment, and report modules. The browser UI is an adapter around the core workflow, not a separate assessment engine. Experimental MTAT, described below, is a separate access boundary. The running UI mounts it.

## Local runtime flow

```text
operator
  |
  +-- CLI parser -----------------------------+
  |   vcf_hci/cli.py                          |
  |                                           v
  +-- loopback browser UI --> vcf_hci/web/* --> vcf_hci/scan.py
                                                   |
                      protocol probe + target policy
                        vcf_hci/protocol.py
                        vcf_hci/tls_utils.py
                                                   |
                        Redfish or read-only WS-Man collection
                        vcf_hci/collector/*
                        vcf_hci/wsman.py
                                                   |
                        normalized host dictionaries
                                                   |
                        enrichment and evaluations
                        enrich_host_result()
                        vcf_hci/enrichment.py
                        vcf_hci/enrichment_steps/*
                        vcf_hci/compat/*
                        vcf_hci/security/*
                        vcf_hci/hcl/*
                                                   |
                        local deliverables
                        vcf_hci/report/*
                        vcf_hci/summary_io.py
                        vcf_hci/scan_complete.py
                        vcf_hci/fleet_library.py
                        vcf_hci/server_groups.py
```

`vcf_hci/scan.py` owns multi-host orchestration. `vcf_hci/scan_host.py` owns one target's lifecycle. The collector factory in `vcf_hci/collector/oem/__init__.py` selects an OEM adapter and falls back to generic DMTF Redfish behavior. `enrich_host_result()` in `vcf_hci/enrichment.py` is the facade over `vcf_hci/enrichment_steps/`. When a host returns data, `_handle_completed_host()` calls `hydrate_groups()` from `vcf_hci/server_groups.py`. After a scan that was not cancelled and has at least one result, `write_scan_manifest()` in `vcf_hci/fleet_library.py` records the fleet-library manifest.

Collectors normalize inconsistent vendor payloads into dictionaries consumed by enrichment and reports. Compatibility and security evaluators should not perform network I/O.

## Read-only security boundary

For native BMC collection, read-only means no managed hardware configuration or data changes. Local reports and normal authentication/session records still occur. Optional jump-host execution writes its own collector scratch; optional managed VDT collection additionally uploads and executes privileged code on a vCenter appliance and writes owned temporary files. Experimental MTAT reads vCenter or Operations after acknowledgement and returns local CSV. It uses manual service credentials or an explicitly selected typed local-vault service entry for that run, not BMC credentials, and its adapters do not update that source's inventory or configuration. These workflows have separate access and write boundaries. The native scanner's managed-system boundary covers native BMC collection. Jump-host scratch, managed VDT, and MTAT are described below.

The transport allowlist permits:

- `GET`, `HEAD`, and `OPTIONS` inventory requests.
- `POST` only to create an ephemeral Redfish session. The BMC connection pool enforces that boundary.
- `DELETE` only when the session manager closes that same session.
- SOAP/XML `POST` only for WS-Man read actions, Cisco XML inventory reads, and the fixed anonymous vCenter `RetrieveServiceContent` request to `/sdk`. The WS-Man collector allowlists its read actions; the vCenter probe accepts no caller-supplied operation or credentials.

Configuration `PATCH`/`PUT`, Redfish action POSTs, power operations, reset operations, firmware updates, account changes, and BIOS changes are outside the product contract.

The crawler may discover and report action metadata but does not invoke discovered actions.

Typed vCenter and Operations accounts in the encrypted vault can be explicitly selected by plugins. The server resolves their opaque IDs and stored endpoints; passwords never return to the browser. BMC matching and jump-host profiles remain separate. Appliance SSH credentials and trust gates are not inferred from vCenter SSO.

Authentication data is passed to a collector for the duration of a scan. The optional local vault is off by default. Raw payload retention, debug logging, JSON export, crawl output, and obfuscation are also explicit options because their outputs can contain sensitive inventory.

## Network model

### Default local and offline behavior

The web server binds to `127.0.0.1` by default and protects startup with a one-time launch token followed by a session cookie. Normal collection connects only to targets supplied by the operator. Reports and evaluations are generated locally.

HCL loading uses packaged or existing local data by default. Missing or stale local data does not trigger an automatic public download.

The Web UI separately refreshes public vSAN and Memory Tiering BCG data in a
background task once per launch and rebuilds the local dark-site bundle. Use
`--no-hcl-auto-refresh` to suppress this task; `--import-hcl` also keeps HCL startup
offline. Failed downloads retain existing local or packaged evidence. Ordinary
library loads and CLI scans remain offline.

The project has no analytics, usage telemetry, or crash reporting. The browser server starts one bounded background request to GitHub's public release API per launch (`vcf_hci/web/update_check.py`), using normal certificate verification. It sends the tool version in its User-Agent, not scan results or credentials, and displays a link for a newer stable release without downloading or installing it. Set `VCF_READINESS_CHECK_UPDATES=0` before starting the UI to disable this request. CLI collection does not start this checker.

### Explicit egress

The following paths can contact services other than the selected BMCs:

- `--refresh-hcl`, `--bundle-hcl`, and the equivalent web action contact the public Broadcom HCL endpoint.
- Dell warranty enrichment contacts TechDirect after the operator supplies credentials and enables it.
- Configured external credential providers contact their configured endpoints when selected.
- Remote jump-host execution opens SSH connections to vault-configured jump hosts when the operator selects remote execution in the local web UI.

These paths are operator-triggered features. The release notice and HCL background
refresh described above are separate default-on startup requests. Disable both
for a UI launch with no public egress.

### TLS and target controls

BMC TLS verification is disabled by default for self-signed controllers. `--verify-ssl` enables validation, and `--ca-bundle` supplies an enterprise trust bundle. Hostname resolution and legacy TLS are separate explicit options.

Target parsing and metadata-address protections live in `vcf_hci/logging_utils.py`, `vcf_hci/protocol.py`, and `vcf_hci/tls_utils.py`. `--restrict-private-targets` narrows accepted scan targets. It is not a substitute for network authorization.

## Browser UI flow

`vcf_hci/web/server.py` serves a local single-page application and JSON/SSE endpoints. API mixins validate sessions and translate requests into core scan operations. `vcf_hci/web/scan_worker.py` runs scans outside the request handler and broadcasts progress.

The local web process writes to the chosen output directory. Browser code does not contact BMCs directly.

A network-exposed UI listener is an advanced server mode, separate from remote jump-host execution. The default `--bind` is `127.0.0.1`. `listener_requires_tls()` requires TLS material when `--allow-remote` is set or the bind host is outside `127.0.0.1`, `::1`, and `localhost`. A wildcard bind (`0.0.0.0`, `::`, or empty) is refused unless `--allow-remote` is set. The preferred headless design is still loopback plus an SSH local port forward.

## Remote jump-host flow

Remote execution is experimental and exposed through the local browser UI, not as a standalone scan CLI.

```text
local loopback UI
  -> unlock opt-in local vault
  -> select configured jump host
  -> build ephemeral stdlib zipapp
  -> SSH with pinned host key
  -> create marker-guarded /tmp/vcfr_remote_<run-id>
  -> execute collector as the remote unprivileged user
  -> stream progress and pull artifacts
  -> validate cleanup path and marker
  -> delete the ephemeral sandbox after successful retrieval
```

Routing and fan-out live in `vcf_hci/remote/orchestrator.py`. SSH execution and artifact retrieval live in `vcf_hci/remote/executor.py`. Path, marker, process, and cleanup safeguards live in `vcf_hci/remote/guardrails.py`. `vcf_hci/web/remote_scan.py` bridges this workflow into browser scan state.

The jump host needs Python 3.9+, SSH access, writable `/tmp`, free space, and network reachability to its assigned BMCs. It does not need the repository installed. Remote jump execution is refused when `_is_remote_server()` is true: `--allow-remote` is set, or the bind address is `0.0.0.0`, `::`, or empty. A specific non-loopback address still requires TLS from `listener_requires_tls()`.

## Data and output flow

Each successful collector returns a normalized host dictionary. Enrichment adds:

- VCF and vSAN evaluations.
- HCL correlations and BCG links.
- security findings and posture.
- topology, firmware, and inventory-derived observations.

The report layer consumes enriched dictionaries and writes local HTML and optional spreadsheet, CSV, JSON, crawl, and obfuscated artifacts. `vcf_hci/summary_io.py` loads and writes supported summary forms for offline re-rendering and fleet assembly.

Reports are snapshots. They can contain infrastructure identifiers and findings. Obfuscation creates share-oriented copies but does not make every free-form or raw field safe; review artifacts before distribution.

## Assessment limits in the current implementation

Storage/network readiness (`vcf_hci/compat/vsan.py`) and inventory profile fit (`vcf_hci/report/inventory_tables.py`) are separate heuristics. Profile sizing requires positive finite RAM/core/network evidence; absent evidence produces **Sizing Not Assessed**, retaining storage-only evidence. The Edge minimum is 64 GB RAM and 16 cores; Small/Medium/Large use their recorded sizing thresholds. The helper does not enforce a 1.6 TB per-drive minimum or establish complete ReadyNode certification.

Legacy `cve_*` fields now carry informational **BIOS Date Estimate** labels, refreshed from the actual release date during offline HTML/Excel rendering. Missing, invalid and future dates remain unassessed. The historical date cutoffs do not measure installed microcode or prove current mitigation coverage. Version-based BIOS security-floor checks remain separate and require installed-version evidence. Catalog verdicts and offline reports retain their capture/evaluation context; regenerating presentation is not a new live assessment.

A **Mem Tier** badge comes from `memory_tiering_matches()`. A match is an exact model, a complete SKU token, or an exact local HCL alias, and capacity-bearing listings are checked against observed capacity. Family-only matches stay untagged. The badge establishes a catalog listing. Firmware, release, topology, and deployment validation remain separate, as `memory_tiering_matches()` states.

The web flag `--nvme-namespace-preview` is off by default. `namespace_preview_enabled()` is true only when `VCF_READINESS_NVME_NAMESPACE_PREVIEW` is `1`, which the web entry point sets from that flag. When the flag is on, `namespace_candidate_source()` can mark an evidence-backed TLC read-intensive 1 DWPD vSAN ESA drive, and the report can include namespace-sizing Help. Identification uses explicit rated NAND and endurance metadata or a reviewed product brief in `RI_SOURCES`. Absence from the QLC list does not establish TLC. The candidate tag is separate from a Memory Tiering BCG listing.

## Extension boundaries

- Add standard collection behavior to the relevant `vcf_hci/collector/collect_*.py` mixin.
- Add vendor deviations to a subclass in `vcf_hci/collector/oem/`.
- Add readiness rules to `vcf_hci/compat/`.
- Add BMC security controls to `vcf_hci/security/`.
- Add presentation behavior to `vcf_hci/report/` or `vcf_hci/web/`.
- Keep network I/O out of evaluation and rendering modules.

All parsing must tolerate missing, malformed, and vendor-specific data. A missing field should produce an unknown or not-assessed result, not an invented pass.

## Optional appliance diagnostic plugins

Upstream VDT is operator-supplied through ZIP upload or an approved extracted installation; it is not bundled with the scanner. The scanner-owned adapters live under `vcf_hci/plugins/`, while the root `Plugins/` holds local operator payloads. Private working/reference material and upstream payloads are excluded from shipment. Release tooling applies the separate private-experiment exclusions to staged copies.

The VDT tab is always visible and offers ZIP installation when no payload is present. The externally supplied `Plugins` directory is created on installation if needed and inspected without importing dropped Python. A local, authenticated installer bounds and validates ZIP contents, atomically installs each recognized payload without overwriting existing packages, and refreshes the catalog immediately. Discovery recognizes modern and legacy layouts independently of archive/directory names. Anonymous HTTPS ServiceContent retrieval identifies actual vCenter version/build before credential entry and selects a documented compatible installed branch; appliance certificates are accepted without identity verification, so this is not HTTPS pinning. Managed preflight/execution separately require the verified pinned SSH host key and recheck compatibility; matching a release does not bypass the runtime or source-hash gate.

Manual JSON imports remain local/session-owned. The optional local-listener collection job uses system OpenSSH with a pinned host key to deploy a reviewed VDT copy into a marker-owned appliance scratch directory. Appliance SSH/root access and vCenter SSO credentials are separate, transient inputs. The appliance adapter uses installed native libraries, selects audited checks, records reduced coverage, validates native exports and checksums, pulls private local artifacts, and cleans only its own completed directory. Failed/cancelled jobs retain evidence. Credentials do not enter persistent preferences, URLs, arguments or job/report metadata.

This explicit deployment workflow writes its own temporary files and outputs. It is separate from the native scanner's managed-system read-only collection contract. It does not enable appliance services, change account/shell settings, register support manifests, or silently run arbitrary discovered plugin code. Initial execution support is the pinned VDT 2.3.2 for vCenter profile; legacy 1.1.4 execution remains manual because of its older runtime and text output; other VDT products remain import-only. `select_vdt()` sets `remote_supported` only when the installed vCenter payload version is `2.3.2`, and `_selected_payload()` accepts that same version for managed execution. Root appliance access, separate SSO authentication, installed native dependencies, temporary writes and cleanup/retention requirements are summarized in the [security review boundary](docs/SECURITY_ARCHITECTURE.md#35-optional-vdt-plugin-security-boundary). Its application-level allowlist is not a general root-code security sandbox.

## Experimental MTAT workload assessment

Experimental MTAT is a separate access boundary from native BMC collection, jump-host scratch, and managed VDT. `MTAT_PANEL` in `vcf_hci/web/mtat_html.py` and `MtatApiMixin` in `vcf_hci/web/mtat_api.py` exist. The mixin refuses preflight and job creation unless `acknowledged` is true. `VcenterAdapter._open()`, `OperationsRestAdapter._open()`, and `OperationsXlsxAdapter._start()` each raise `PermissionError` without that acknowledgement. `experimental_enabled()` returns true with no startup flag, so the running UI mounts the panel. Collection still requires the acknowledgement.

The run reads one source: vCenter (`VcenterAdapter`), Operations REST (`OperationsRestAdapter`), or a local Operations workbook (`OperationsXlsxAdapter`). vCenter and Operations REST use the username and password on that `CollectionRequest` and clear the password after the connection handoff. `_password_for()` supplies a non-secret placeholder for the workbook, and `_start()` reads that local `.xlsx`.

`load_pyvmomi()` imports pyVmomi only when the vCenter adapter opens. It accepts the wheel only when the filename, SHA-256, and version match `PYVMOMI_FILENAME`, `PYVMOMI_SHA256`, and `PYVMOMI_VERSION`. Importing `vcf_hci/plugins/mtat/vendor.py` does not import pyVmomi. The Operations adapters do not call the loader. Native collection still has no required third-party runtime package.

The vCenter and Operations adapters do not update inventory or configuration. vCenter reads use `RetrieveContent`, `RetrievePropertiesEx`, and `QueryPerf`. `_properties()` creates a container view for that read and then destroys it. Operations REST, whose module describes read-only collection, acquires and releases an authentication token, reads inventory with GET, and posts a stats query to `/resources/stats/query` under the `/suite-api/api` prefix. A finished job returns local CSV from `render_hosts()`, `render_vms()`, `render_hosts_history()`, and `render_vms_history()`, including the session zip built by `export_zip()`. Operator detail is in [MTAT workload assessment (experimental)](docs/MTAT_WORKLOAD_ASSESSMENT_EXPERIMENTAL.md).

`build_app_html()` inserts `MTAT_PANEL`. `AppHandler` includes `MtatApiMixin`. `do_GET` and `do_POST` dispatch `/api/plugins/mtat`. `APP_JS` includes `JS_MTAT`. The plugins catalog returns the MTAT entry from `catalog_entry()`. After the phased-wizard pack, the mounted panel is three steps: Source and Connection, Baseline Assessment, and Sizing and Savings. vSphere Inventory is available by default alongside MTAT in the Plugins catalog. Both require acknowledgement before collection.

## Generated documentation

`tools/bundle_docs.py` converts an explicit source whitelist into `vcf_hci/web/docs_data.py`. The output is deterministic and tracked so the help portal works offline.

Edit source Markdown, run the generator, and commit both source and generated output:

```bash
python tools/bundle_docs.py
python tools/bundle_docs.py --check
```

`vcf_hci/web/assets.py` is also generated and must not be hand-edited.

## Architectural invariants

1. Python 3.9+ with no required third-party runtime packages for native collection and the local UI; the vault optionally uses installed AES support. Experimental vCenter MTAT calls `load_pyvmomi()` only when that adapter opens.
2. Native BMC collection does not change managed-system configuration. Optional appliance diagnostics explicitly write owned temporary files. Experimental MTAT returns local CSV and does not update vCenter or Operations inventory or configuration.
3. Ordinary scans evaluate locally using existing HCL data; remote execution is an explicit option.
4. Web startup HCL refresh and the UI release notice are default-on and can each be disabled before launch; other public data refreshes are explicit.
5. Browser UI is loopback by default.
6. Credentials and raw inventory are sensitive. Plugin service credentials are manual or explicitly resolved from typed local-vault entries for that run, separate from BMC credentials.
7. Readiness labels remain evidence-limited; the profile-fit, date-based, Memory Tiering badge, and namespace-preview limits above require explicit review.
8. Generated files are reproducible from tracked inputs.