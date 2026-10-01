# Software Bill of Materials (SBOM) — Customer Deliverables

> **Product:** VCF / vSphere 9.1 HCI Readiness Assessment Tool (`vcf-readiness`)  
> **Release Version:** v9.7.1  
> **Generated Date:** 2026-09-27  
> **Standards Compliance:** CycloneDX 1.5 JSON (`docs/sbom/cyclonedx-customer-v9.7.1.json`), SPDX 2.3 JSON (`docs/sbom/spdx-customer-v9.7.1.json`)  
> **License:** CA, Inc. Software License Agreement (Broadcom)  

---

## 1. Executive Summary & Zero-Dependency Architectural Guarantee

This document provides a comprehensive, transparent Software Bill of Materials (SBOM) for the standalone customer offline distribution (`Distribution-VCF-Readiness.zip`) and compiled multi-platform binaries.

### Key Compliance Highlights:
1. **Zero Runtime External Dependencies:**
   - The core Python application (`vcf_hci/`) imports **strictly from the Python standard library** (Python 3.9+).
   - **Forbidden third-party runtime libraries:** Zero usage of `requests`, `urllib3`, `aiohttp`, `jinja2`, `pandas`, `beautifulsoup4`, or `lxml`.
   - Customers can execute the tool directly using any stock Python 3.9–3.12 interpreter without installing external pip packages or connecting to public/private package indexes.
2. **Zero External CDN / Web Dependencies:**
   - The embedded Web UI and all generated HTML reports operate **100% offline in air-gapped environments**.
   - All stylesheet assets (VMware Clarity Design System) and icons are pre-compiled and embedded directly as in-memory data constants.
3. **Zero Cryptographic Non-Standard Ciphers:**
   - The Credential Vault utilizes standard library primitives only (`hashlib`, `hmac`, PBKDF2-HMAC-SHA256 Encrypt-then-MAC) with zero proprietary or third-party binary encryption drivers.
4. **Strict Isolation & Air-Gapped Safe:**
   - The tool initiates outbound HTTPS connections **only** to the explicitly targeted BMC IP addresses provided by the operator (port 443). No outbound telemetry, update checks, or external analytics calls are made.

---

## 2. Software Component Inventory

The following table enumerates all first-party and bundled open-source components comprising the customer deliverables:

| Component Name | Version | Type | License | Supplier | Delivery / Inclusion Mechanism | Required / Optional |
|---|---|---|---|---|---|---|
| `vcf_hci` | `9.7.1` | application | LicenseRef-CA-Inc | Broadcom / CA, Inc. | Source package & compiled binaries | **Required** |
| `@cds/core` | `5.7.0` | library | Apache-2.0 | VMware by Broadcom | In-memory CSS served by local Web UI (127.0.0.1:7182) and embedded in offline HTML reports | **Required** |
| `vsan-hcl-dataset` | `9.1.0` | data | LicenseRef-Proprietary-Broadcom | Broadcom | Embedded JSON file and offline bundle archive in hcl/ | **Required** |
| `pyinstaller-bootloader` | `6.11.0` | framework | GPL-2.0-only WITH Bootloader-exception | PyInstaller Development Team | Embedded in standalone platform executables (Mac/Win/Linux). Not used when running via Python source. | Optional |
| `cpython-embedded-runtime` | `3.11.9` | operating-system-component | PSF-2.0 | Python Software Foundation | Self-extracting binary payload | Optional |
| `openssl-c-library` | `3.0.13` | library | Apache-2.0 | OpenSSL Project | Binary runtime dependency of compiled executables | Optional |
| `sqlite3-engine` | `3.45.1` | library | blessing | SQLite Consortium | Standard library module in Python and compiled binaries | Optional |
| `zlib-compression` | `1.3.1` | library | Zlib | Jean-loup Gailly and Mark Adler | Standard library module in Python and compiled binaries | Optional |
| `libffi` | `3.4.4` | library | MIT | Anthony Green and contributors | Embedded inside compiled binaries in bin/ | Optional |
| `vcf-readiness-adapter` | `9.7.1` | application | MIT | Broadcom / VMware Community | Packaged .pak archive in integrations/vcf-ops/ | Optional |

---

## 3. Component Details & Licensing Analysis

### 3.1. Core Application Engine (`vcf_hci`)
- **License:** CA, Inc. Software License Agreement (`LICENSE.md`)
- **Purpose:** Enterprise BMC querying (Dell iDRAC, HPE iLO, Supermicro, Cisco IMC, Lenovo XCC, Intel BMC), hardware specification extraction, vSAN ESA readiness evaluation, and standalone HTML report generation.
- **Dependencies:** Strictly standard library (`urllib.request`, `ssl`, `json`, `sqlite3`, `concurrent.futures`, `hashlib`, `hmac`).

### 3.2. VMware Clarity Design System (`@cds/core`)
- **Version:** 5.7.0
- **License:** Apache-2.0
- **Purpose:** Professional enterprise UI design system for the local browser interface (127.0.0.1:7182) and generated interactive fleet reports.
- **Embedding Method:** Pre-bundled via `tools/bundle_assets.py` into `vcf_hci/web/assets.py` as a base64-encoded, gzip-compressed string constant. No Node.js or internet access is required.

### 3.3. Broadcom vSAN Hardware Compatibility Dataset (`vsan-hcl-dataset`)
- **Version:** 9.1.0
- **License:** Broadcom Community / Proprietary Dataset
- **Purpose:** Maps PCI Vendor ID, Device ID, Sub-Vendor ID, and Sub-Device ID to VMware Compatibility Guide (VCG / BCG) records for network interfaces, NVMe drives, and storage controllers.
- **Delivery:** Packaged offline inside `vcf_hci/io_nics.json` and `hcl/vcf_hcl_bundle_latest.zip`.

### 3.4. PyInstaller Bootloader & Bundled Binaries (`bin/`)
- **License:** GPL-2.0-only WITH Bootloader-exception
- **Exception Clause:** The PyInstaller Bootloader exception explicitly permits the creation and distribution of standalone executables containing proprietary, commercial, or non-GPL software without triggering copyleft requirements on the packaged application code.
- **Purpose:** Optional convenience executables (`VCF-Readiness-Web-mac`, `VCF-Readiness-Web.exe`, `vcf-assess`) for operators without a local Python runtime.
- **Contained Runtimes:** Statically bundles CPython 3.11+, OpenSSL 3.0+ (Apache-2.0), SQLite3 (Public Domain), zlib (Zlib), and libffi (MIT).

### 3.5. VMware VCF Operations Management Pack (`integrations/vcf-ops/`)
- **Version:** 9.7.1
- **License:** Community Tooling License (`management_pack/eula.txt`)
- **Purpose:** Optional adapter for VMware Aria Operations / VCF Operations 9.1 integration. Deploys via `.pak` archive to ingest readiness metrics directly into enterprise dashboards.

---

## 4. Master Offline Distribution Zip Contents (`Distribution-VCF-Readiness.zip`)

When built using `./build_offline_package.sh`, the master distribution package contains strictly the following vetted assets:

| Directory / File | Description & Purpose |
|---|---|
| `00_HOWTOLAUNCH.TXT` | Quick-start guide with zero-dependency launch commands for Mac, Linux, and Windows. |
| `README.md` | Comprehensive user guide covering Web UI, CLI, BMC security baseline, and ESA requirements. |
| `INSTALL.md` | Deployment prerequisites, Python installation instructions, and network firewall requirements. |
| `ARCHITECTURE.md` | Four-layer architectural blueprint (Collector, Enrichment, BCG Links, UI/Reporting). |
| `CHANGELOG.md` | Complete version history, feature release notes, and compatibility updates. |
| `LICENSE.md` | Software License Agreement (Broadcom / CA, Inc.). |
| `NOTICE` | Official Broadcom subcomponents and third-party license notice. |
| `THIRD_PARTY_LICENSES.md` | Notices and license texts for bundled third-party open-source components (Clarity Apache-2.0, OpenSSL, CPython, libffi, zlib). |
| `CONTRIBUTING.md` | Guidelines for testing, code formatting, and OEM extension development. |
| `pyproject.toml` | Project metadata, PEP 517 build configuration, and zero-dependency declarations. |
| `vcfr_web.py / redfish_web.py` | Local Web Browser UI launcher (starts lightweight HTTP server on 127.0.0.1:7182). |
| `vcfr_collector.py / redfish_collector.py` | Command-line interface entry points for multi-host batch assessments. |
| `build-web.sh / build-web.bat` | Local platform binary compilation scripts for Mac/Linux and Windows. |
| `bin/` | Staged single latest compiled standalone platform executables (no Python installation required). |
| `vcf_hci/` | Core application Python package (100% standard library, zero external pip dependencies). |
| `docs/` | Customer-facing documentation whitelist (guides, OEM reference, security architecture, SBOM). |
| `scripts/` | Customer-facing helper and execution wrapper scripts. |
| `tools/` | Customer-facing build utilities (build_management_pack.py, clean_build_artifacts.py, etc.). |
| `hcl/` | Offline Broadcom vSAN HCL database extracts and bundle archives. |
| `integrations/vcf-ops/` | VMware VCF Operations 9.1 Management Pack (.pak) and installation documentation. |

---

## 5. Vulnerability & Risk Management Statements

- **CVE Risk Surface:** Because runtime Python dependencies are zero, this application is immune to dependency confusion attacks, malicious PyPI package takeovers, or unvetted transitive wheel vulnerabilities.
- **Network Exposure:** The Web UI listens strictly on `127.0.0.1` (loopback only) by default, preventing unauthorized LAN access.
- **SSL Verification:** Uses `ssl.CERT_NONE` by default for BMC HTTPS queries because enterprise BMCs frequently utilize self-signed internal certificates. Operator credentials remain encrypted in transit over TLS.
- **Reporting:** Standalone reports are self-contained single HTML files with zero external tracking pixels, external scripts, or external font stylesheets.

---

*Document generated automatically by `tools/generate_sboms.py` on 2026-09-27.*
