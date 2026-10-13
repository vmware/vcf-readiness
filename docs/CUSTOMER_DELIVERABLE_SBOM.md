# Software Bill of Materials (SBOM) — Customer Deliverables

> **Product:** VCF / vSphere 9.1 HCI Readiness Assessment Tool (`vcf-readiness`)
> **Runtime version in this checkout:** 9.9.2 (`vcf_hci/constants.py`)
> **Historical inventory date:** 2026-09-27
> **Companion JSON:** `docs/sbom/cyclonedx-customer-v9.7.1.json`, `docs/sbom/spdx-customer-v9.7.1.json`
> **License:** CA, Inc. Software License Agreement (Broadcom)  

This source checkout does not include prebuilt executables, a platform build script, an offline-package script, a `bin/` directory, a VCF Operations management pack, or a tracked SBOM generator. The JSON companions still identify v9.7.1 and are not rebuilt by a command in this tree. Run the application from source, as described in `README.md` and `docs/INSTALL.md`.

---

## 1. Executive Summary & Zero-Dependency Architectural Guarantee

This document describes the source application in this checkout. It is not a manifest of downloadable release assets.

### Key Compliance Highlights:
1. **Zero Runtime External Dependencies:**
   - The core Python application (`vcf_hci/`) imports **strictly from the Python standard library** (Python 3.9+).
   - **Forbidden third-party runtime libraries:** Zero usage of `requests`, `urllib3`, `aiohttp`, `jinja2`, `pandas`, `beautifulsoup4`, or `lxml`.
   - Customers can execute the tool directly using any stock Python 3.9–3.12 interpreter without installing external pip packages or connecting to public/private package indexes.
2. **Zero External CDN / Web Dependencies:**
   - The embedded Web UI and all generated HTML reports operate **100% offline in air-gapped environments**.
   - All stylesheet assets (VMware Clarity Design System) and icons are pre-compiled and embedded directly as in-memory data constants.
3. **Credential vault cryptography:**
   - The default vault mode uses standard-library primitives (`hashlib`, `hmac`, PBKDF2-HMAC-SHA256). An optional `crypto` extra can use `pycryptodomex` when that package is installed. It is not required to run a scan.
4. **Default-offline operation:**
   - Ordinary scans contact the BMC targets the operator selects and write reports locally. They do not send telemetry, update checks, or analytics.
   - Public HCL download, Dell warranty lookup, external credential providers, and experimental jump-host SSH happen only after an explicit operator action. BMC HTTP on port 80 is accepted with a warning; it is not an HTTPS-only product.

---

## 2. Software Component Inventory

The following table enumerates all first-party and bundled open-source components comprising the customer deliverables:

| Component Name | Version | Type | License | Supplier | Delivery / Inclusion Mechanism | Required / Optional |
|---|---|---|---|---|---|---|
| `vcf_hci` | `9.9.2` | application | LicenseRef-CA-Inc | Broadcom / CA, Inc. | Python source in this checkout | **Required** |
| `@cds/core` | `5.7.0` | library | Apache-2.0 | VMware by Broadcom | In-memory CSS in `vcf_hci/web/assets.py`, served by the local Web UI and embedded in offline HTML reports | **Required** |
| `vsan-hcl-dataset` | packaged local data | data | LicenseRef-Proprietary-Broadcom | Broadcom | `vcf_hci/hcl/io_nics.json` plus any local HCL data the operator already has. A public download requires `--refresh-hcl` or `--bundle-hcl`. | **Required for HCL correlation** |

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
- **Embedding Method:** Already present in `vcf_hci/web/assets.py` as an in-memory stylesheet constant. This checkout does not include a script that rebuilds that module. No Node.js access is required to run the UI.

### 3.3. Broadcom vSAN Hardware Compatibility Dataset (`vsan-hcl-dataset`)
- **Version:** 9.1.0
- **License:** Broadcom Community / Proprietary Dataset
- **Purpose:** Maps PCI Vendor ID, Device ID, Sub-Vendor ID, and Sub-Device ID to VMware Compatibility Guide (VCG / BCG) records for network interfaces, NVMe drives, and storage controllers.
- **Delivery:** Local catalog data in `vcf_hci/hcl/io_nics.json`. Operators can import an approved offline bundle with `--import-hcl`. This checkout does not contain a prebuilt HCL zip.

### 3.4. What this checkout does not ship

There is no compiled executable, PyInstaller payload, management-pack archive, or helper script directory in this tree. The only supported launch path is the Python source documented in `README.md`.

---

## 4. Source tree you can run

Use the files that are actually in the checkout:

| Path | Role |
|---|---|
| `00_HOWTOLAUNCH.TXT` | Short source launch card |
| `README.md` | Beginner guide |
| `docs/INSTALL.md` | Source install, headless use, and explicit offline HCL workflow |
| `ARCHITECTURE.md` | Runtime, remote, and security flows |
| `vcfr_web.py` | Local web UI launcher |
| `vcfr_collector.py` | Command-line collector |
| `vcf_hci/` | Application package |
| `docs/` | Longer guides |
| `tools/check_data_hygiene.py` | Contributor data-hygiene check |
| `tools/bundle_docs.py` | Deterministic help-bundle generator |

---

## 5. Vulnerability & Risk Management Statements

- **CVE Risk Surface:** Because runtime Python dependencies are zero, this application is immune to dependency confusion attacks, malicious PyPI package takeovers, or unvetted transitive wheel vulnerabilities.
- **Network Exposure:** The Web UI binds to loopback by default. A non-loopback listener requires an explicit allow flag and TLS material, and it disables vault and jump-host features.
- **SSL Verification:** Uses `ssl.CERT_NONE` by default for BMC HTTPS queries because enterprise BMCs frequently utilize self-signed internal certificates. Operator credentials remain encrypted in transit over TLS.
- **Reporting:** Standalone reports are self-contained single HTML files with zero external tracking pixels, external scripts, or external font stylesheets.

---

*Maintained with the source tree. The JSON files under `docs/sbom/` are historical companions and are not rebuilt by a command in this checkout.*
