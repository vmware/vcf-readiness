# `vcf_hci` Package Overview

> Core Python package for the VCF / vSphere 9.1 HCI Readiness Assessment Tool.

---

## Package Entry Points

- **`python -m vcf_hci`** — CLI runner invoking `vcf_hci.cli.main()`.
- **`vcfr_web.py`** — Root launch script starting `vcf_hci.web.server` and opening the browser UI.
- **`vcfr_collector.py`** — Root CLI entry point delegating to `vcf_hci.cli.main()`.
- **`redfish_web.py` / `redfish_collector.py`** — Root backward-compatibility shims.

---

## Module Index

### Core Utilities & Business Rules
- **`bcg_links.py`**: `BCGLinkGenerator` constructing deep-links into the Broadcom Compatibility Guide for Servers, CPUs, SSDs, IO adapters, and GPUs.
- **`compat_engine.py`**: `VCF9CompatibilityEngine` evaluating CPU support tiers (KB 428874), vSAN ESA readiness, TPM 2.0 security baseline, Intel VMD settings, and BIOS/BMC firmware baselines.
- **`enrichment.py`**: `enrich_host_result()` post-collection pipeline applying Layer B compatibility verdicts, memory topology, lane budgets, Layer C BCG deep links, and BMC Hardware Security Audit findings.
- **`constants.py`**: Hardware lookup tables, ESXi build matrices, tool version metadata, and URL constants.
- **`logging_utils.py`**: Log formatting configuration, `sanitize_filename()` file safety utility, and IP target parser (`parse_ip_targets()`).
- **`obfuscation.py`**: `obfuscate_host_data()` scrubbing IP addresses, MAC addresses, serial numbers, and hostnames for anonymized reporting. Supports both server-side pre-obfuscated report generation (`obfuscated=True` / `OBFUSCATED_*.html`) and dynamic DOM PII masking via JS on standard reports.
- **`protocol.py`**: Out-of-band protocol detection probing HTTPS Redfish, WS-Man, and Intel AMT/DASH endpoints.
- **`scan.py`**: Multi-host multi-threaded scan orchestrator (`scan_hosts()`).
- **`wsman.py`**: `WsManCollector` handling legacy WS-Man / AMT out-of-band management protocols.

### Subpackages
- **[`collector/`](collector/README.md)**: Layer A Redfish API query engine, hardware collection mixins, diagnostic hypermedia crawler (`crawler.py`), and vendor-specific OEM hook subclasses (`dell.py`, `hpe.py`, `supermicro.py`, `cisco.py`, `lenovo.py`, `intel.py`, `quanta.py`, `gigabyte.py`).
- **`security/`**: BMC Hardware Security Audit engine evaluating 84 canonical controls, standard DMTF Redfish + Dell iDRAC9 / HPE iLO OEM evaluators, recursive secret redaction, host/fleet posture scoring, and zero-dependency IPMI 2.0 RMCP+ Cipher Suite 0 network probing (`ipmi_probe.py`).
- **[`report/`](report/README.md)**: Layer D standalone HTML report generator (`host_report.py`, `fleet/`), multi-vendor SEL deep-link resolver (`sel_links.py`), SE Decision Matrix and inventory tables (`inventory_tables.py`), 10-tab Excel exporter (`excel_export.py`), standardized CSV exporter (`csv_export.py`), centralized Schema v2.0 domain registry (`schema_registry.py`), and switch buffer taxonomy / ASIC intelligence (`switch_topology.py`).
- **[`hcl/`](hcl/README.md)**: Broadcom vSAN HCL dataset loader, offline bundle manager, PCI component cross-referencing, and offline certified Network I/O catalog (`io_nics.json`).
- **`bios/`**: BIOS feature evaluators (`power_modes.py`, `ras_modes.py`, `security.py`).
- **`servicetag/`**: Dell TechDirect API integration and warranty lookup (`dell_api.py`, `esa_evaluator.py`).
- **`web/`**: Single-page browser application, embedded Clarity CSS assets (`assets.py`), SSE API server (`server.py`), modular endpoints (`fleet_api.py`, `scan_api.py`, `import_api.py`, `export_api.py`, `security_api.py`, `session_api.py`), modular assets (`app_*.py`, `docs_*.py`), and the opt-in in-memory vault holder (`vault_session.py`).
- **`vault/`**: Optional, off-by-default encrypted local credential vault (`crypto.py`, `store.py`, `csv_io.py`, `cli.py`, `session.py`, `python -m vcf_hci.vault`). Stdlib-only PBKDF2 + HMAC-SHA256 Encrypt-then-MAC; exact → CIDR → default resolution. Must never import `vcf_hci.web`, `compat_engine`, or `bcg_links`. See [docs/CREDENTIAL_VAULT.md](../docs/CREDENTIAL_VAULT.md).
- **Core Orchestration & Infrastructure Modules**:
  - `fleet_library.py`: Multi-scan fleet library crawler, universal drop ingest, `MANIFEST.json` validation, and deterministic host deduplication (`assemble_fleet()`).
  - `fleet_discovery.py`: Two-pass fast discovery and Longest-Job-First (LJF) priority scheduling.
  - `system_throttle.py`: Dynamic system auto-stepdown resource monitor (CPU load average & available RAM).
  - `tls_utils.py`: `StdlibHTTPConnectionPool` (keep-alive pooling) and SSL/TLS context configuration.
  - `scan.py`, `scan_host.py`, `scan_complete.py`: Multi-host scan lifecycle orchestration, worker execution, and post-scan report/export generation.

---

## Architectural Constraints

1. **Zero External Runtime Dependencies:** Standard library imports only.
2. **Python 3.9+ Compatibility:** `Union[X, Y]` / `Optional[X]` annotations only.
3. **Defensive Parsing:** All JSON decoding must handle non-JSON HTML error responses.
