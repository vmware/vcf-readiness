# Architecture

VCF Readiness is a Python 3.9+ standard-library application with two local entry points:

- `vcfr_web.py` / `python -m vcf_hci.web`: loopback browser UI.
- `vcfr_collector.py` / `python -m vcf_hci`: command-line collector and offline renderer.

Both paths use the same scan, enrichment, and report modules. The browser UI is an adapter around the core workflow, not a separate assessment engine.

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
                        vcf_hci/enrichment.py
                        vcf_hci/compat/*
                        vcf_hci/security/*
                        vcf_hci/hcl/*
                                                   |
                        local deliverables
                        vcf_hci/report/*
                        vcf_hci/summary_io.py
                        vcf_hci/scan_complete.py
```

`vcf_hci/scan.py` owns multi-host orchestration. `vcf_hci/scan_host.py` owns one target's lifecycle. The collector factory in `vcf_hci/collector/oem/__init__.py` selects an OEM adapter and falls back to generic DMTF Redfish behavior.

Collectors normalize inconsistent vendor payloads into dictionaries consumed by enrichment and reports. Compatibility and security evaluators should not perform network I/O.

## Read-only security boundary

Read-only means the application does not change managed-system state.

The transport allowlist permits:

- `GET`, `HEAD`, and `OPTIONS` inventory requests.
- `POST` only to create an ephemeral Redfish session. The BMC connection pool enforces that boundary.
- `DELETE` only when the session manager closes that same session.
- SOAP/XML `POST` only for WS-Man read actions and Cisco XML inventory reads. The WS-Man collector allowlists those read actions.

Configuration `PATCH`/`PUT`, Redfish action POSTs, power operations, reset operations, firmware updates, account changes, and BIOS changes are outside the product contract.

The crawler may discover and report action metadata but does not invoke discovered actions.

Authentication data is passed to a collector for the duration of a scan. The optional local vault is off by default. Raw payload retention, debug logging, JSON export, crawl output, and obfuscation are also explicit options because their outputs can contain sensitive inventory.

## Network model

### Default local and offline behavior

The web server binds to `127.0.0.1` by default and protects startup with a one-time launch token followed by a session cookie. Normal collection connects only to targets supplied by the operator. Reports and evaluations are generated locally.

HCL loading uses packaged or existing local data by default. Missing or stale local data does not trigger an automatic public download.

The project has no analytics, usage telemetry, crash reporting, or background update check.

### Explicit egress

The following paths can contact services other than the selected BMCs:

- `--refresh-hcl`, `--bundle-hcl`, and the equivalent web action contact the public Broadcom HCL endpoint.
- Dell warranty enrichment contacts TechDirect after the operator supplies credentials and enables it.
- Configured external credential providers contact their configured endpoints when selected.
- Remote jump-host execution opens SSH connections to vault-configured jump hosts when the operator selects remote execution in the local web UI.

These are operator-triggered features. They must remain visible in UI or CLI wording and must not become startup behavior.

### TLS and target controls

BMC TLS verification is disabled by default for self-signed controllers. `--verify-ssl` enables validation, and `--ca-bundle` supplies an enterprise trust bundle. Hostname resolution and legacy TLS are separate explicit options.

Target parsing and metadata-address protections live in `vcf_hci/logging_utils.py`, `vcf_hci/protocol.py`, and `vcf_hci/tls_utils.py`. `--restrict-private-targets` narrows accepted scan targets. It is not a substitute for network authorization.

## Browser UI flow

`vcf_hci/web/server.py` serves a local single-page application and JSON/SSE endpoints. API mixins validate sessions and translate requests into core scan operations. `vcf_hci/web/scan_worker.py` runs scans outside the request handler and broadcasts progress.

The local web process writes to the chosen output directory. Browser code does not contact BMCs directly.

A network-exposed UI listener is an advanced server mode, separate from remote jump-host execution. Non-loopback binding requires an explicit allow flag and TLS material. The preferred headless design is still loopback plus an SSH local port forward.

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

The jump host needs Python 3.9+, SSH access, writable `/tmp`, free space, and network reachability to its assigned BMCs. It does not need the repository installed. Remote execution is disabled when the browser server itself is in remote-listener mode.

## Data and output flow

Each successful collector returns a normalized host dictionary. Enrichment adds:

- VCF and vSAN evaluations.
- HCL correlations and BCG links.
- security findings and posture.
- topology, firmware, and inventory-derived observations.

The report layer consumes enriched dictionaries and writes local HTML and optional spreadsheet, CSV, JSON, crawl, and obfuscated artifacts. `vcf_hci/summary_io.py` loads and writes supported summary forms for offline re-rendering and fleet assembly.

Reports are snapshots. They can contain infrastructure identifiers and findings. Obfuscation creates share-oriented copies but does not make every free-form or raw field safe; review artifacts before distribution.

## Extension boundaries

- Add standard collection behavior to the relevant `vcf_hci/collector/collect_*.py` mixin.
- Add vendor deviations to a subclass in `vcf_hci/collector/oem/`.
- Add readiness rules to `vcf_hci/compat/`.
- Add BMC security controls to `vcf_hci/security/`.
- Add presentation behavior to `vcf_hci/report/` or `vcf_hci/web/`.
- Keep network I/O out of evaluation and rendering modules.

All parsing must tolerate missing, malformed, and vendor-specific data. A missing field should produce an unknown or not-assessed result, not an invented pass.

## Generated documentation

`tools/bundle_docs.py` converts an explicit source whitelist into `vcf_hci/web/docs_data.py`. The output is deterministic and tracked so the help portal works offline.

Edit source Markdown, run the generator, and commit both source and generated output:

```bash
python tools/bundle_docs.py
python tools/bundle_docs.py --check
```

`vcf_hci/web/assets.py` is also generated and must not be hand-edited.

## Architectural invariants

1. Python 3.9+ and standard-library runtime.
2. Strict read-only managed-system behavior.
3. Ordinary scans are local and default-offline.
4. Optional egress requires an explicit operator action.
5. Browser UI is loopback by default.
6. Credentials and raw inventory are sensitive.
7. Compatibility claims degrade to unknown when evidence is absent.
8. Generated files are reproducible from tracked inputs.