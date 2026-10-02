# VCF Readiness Assessment Tool

> Zero-dependency Python tool for VMware Sales Engineers and Solution Architects to assess legacy server hardware for VMware Cloud Foundation 9.1 repurposing.

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-green.svg)](#)
[![Latest Release](https://img.shields.io/github/v/release/vmware/vcf-readiness?label=Download)](https://github.com/vmware/vcf-readiness/releases/latest)

---

## Table of Contents

- [Download](#download)
- [5-Minute Quick Start](#5-minute-quick-start)
- [Run from Source (no binary needed)](#run-from-source-no-binary-needed)
- [What It Does](#what-it-does)
- [Key Features](#key-features)
- [Interface Options](#interface-options)
  - [Option A — Browser UI (recommended)](#option-a--browser-ui-recommended)
  - [Option B — Command-Line Interface](#option-b--command-line-interface)
  - [Scan Modes (Quick, Lean, Full)](#scan-modes-quick-lean-full)
- [Command-Line Options](#command-line-options)
- [Output Files](#output-files)
- [Report Sections](#report-sections)
- [Security Architecture](#security-architecture)
- [Data Obfuscation & PII Anonymization](#data-obfuscation--pii-anonymization)
- [Architecture](#architecture)
- [OEM \& Hardware Vendor Collaboration](#oem--hardware-vendor-collaboration)
- [Broadcom References](#broadcom-references)
- [Credits & Acknowledgements](#credits--acknowledgements)
- [License](#license)

---

## Download

**No Python required** — grab the pre-built binary for your platform from the [**Latest Release page →**](https://github.com/vmware/vcf-readiness/releases/latest)

| Platform | File | Notes |
|----------|------|-------|
| Windows | `VCF-Readiness-Web-v<version>-win.exe` / `.zip` | Double-click; opens browser automatically |
| macOS | `VCF-Readiness-Web-v<version>-mac.zip` | Unzip → double-click `Launch-VCF-Readiness-Web.command` (Right-click Open on first launch) |
| Linux | `VCF-Readiness-Web-v<version>-linux.zip` | Extract → run executable |

> Already have Python 3.9+? Skip the binary and [run from source](#run-from-source-no-binary-needed) — it's one command.

---

## 5-Minute Quick Start

> **What you need:** network access to your BMC management IPs (iDRAC / iLO / BMC). That's it.

### Step 1 — Download and launch

**Windows:**
1. Download `VCF-Readiness-Web-v<version>-win.exe` from the [release page](https://github.com/vmware/vcf-readiness/releases/latest)
2. Double-click it. If Windows SmartScreen appears, click **More info → Run anyway**
3. Your browser opens automatically at `http://127.0.0.1:7182`

**macOS:**
1. Download `VCF-Readiness-Web-v<version>-mac.zip` from the [release page](https://github.com/vmware/vcf-readiness/releases/latest)
2. Double-click the zip to unzip it
3. Double-click **`Launch-VCF-Readiness-Web.command`** (If Gatekeeper warns: right-click → **Open** → **Open**)
4. Your browser opens automatically at `http://127.0.0.1:7182`

**Linux / headless server:** See [Run from source](#run-from-source-no-binary-needed) below.

### Step 2 — Fill in the form

1. **Targets** — enter one or more BMC IPs, a range (`10.0.0.1-20`), or a CIDR block (`192.168.1.0/24`)
2. **Credentials** — username and password for your iDRAC / iLO / BMC
3. Click **Run Assessment**

### Step 3 — Get your reports

The tool scans each host and generates a standalone HTML report per server. No internet connection required for scanning. Reports open directly in the browser, or you can find them in your chosen output folder.

---

## Run from Source (no binary needed)

The tool has **zero external dependencies** — if you have Python 3.9+ installed, one command is all it takes.

```bash
# Clone or download the repository, then:
python vcfr_web.py
# Browser opens automatically at http://127.0.0.1:7182
```

### Don't have Python yet?

<details>
<summary><strong>Windows — install Python from python.org</strong></summary>

1. Go to [https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/) and download the **Windows installer (64-bit)** for the latest Python 3.x release.
2. Run the installer. **Critical:** on the first screen, check **"Add python.exe to PATH"** before clicking Install Now.
3. Open **Command Prompt** (Start → type `cmd` → Enter).
4. Verify: `python --version` — should print `Python 3.x.x`
5. Navigate to the project and launch:
   ```cmd
   cd C:\Users\YourName\Documents\Distribution-Redfish-Scraper
   python vcfr_web.py
   ```

</details>

<details>
<summary><strong>macOS — install Python via Homebrew</strong></summary>

1. Open **Terminal** (Spotlight → type `Terminal` → Enter).
2. Install Homebrew (if you don't have it):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```
3. Install Python:
   ```bash
   brew install python
   ```
4. Verify: `python3 --version` — should print `Python 3.x.x`
5. Navigate to the project and launch:
   ```bash
   cd ~/Documents/Distribution-Redfish-Scraper
   python3 vcfr_web.py
   ```

> **No external dependencies needed.** The web UI runs in your browser using only Python standard library.

</details>

<details>
<summary><strong>Linux — install Python via package manager</strong></summary>

Most Linux distributions include Python 3 by default. If not:

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install python3

# RHEL / CentOS / Fedora
sudo dnf install python3

# Verify
python3 --version
```

Then launch the tool:
```bash
cd ~/Documents/Distribution-Redfish-Scraper
python3 vcfr_web.py
```

**Headless / SSH server?** Forward port 7182 to your local machine and open the browser there:
```bash
# Run this on your local machine (replace user@server with your server)
ssh -L 7182:127.0.0.1:7182 user@server

# Then on the server, start the tool:
python3 vcfr_web.py

# Open http://127.0.0.1:7182 in your local browser
```

</details>

---

## What It Does

Connects to enterprise server BMCs over Redfish APIs and produces a standalone HTML report per host answering one question: **can this server be repurposed for VCF 9.1?**

**BMC coverage**

| BMC | Adapter | Assessment depth | Automated fixture |
|-----|---------|------------------|-------------------|
| Dell iDRAC | `DellCollector` | Full OEM hooks (SKU, BIOS date, endurance, SMART, license) | Yes (R640 / R6525 / R750 / R740+GPU) |
| HPE iLO | `HPECollector` | Full OEM hooks (SmartStorage, retry, SystemUsage, license) | Yes (DL360 Gen10) |
| Supermicro BMC | `SupermicroCollector` | SimpleStorage + DCMS license gate | Yes (SYS-E200-8D) |
| Cisco IMC | `CiscoCollector` | Manager path `/Managers/CIMC`, drive metrics, license note | Yes (C220 M5 fixture + `samples/cisco-c220-m5` replay; optional skip if dump absent) |
| Lenovo XCC | `LenovoCollector` | Drive metrics + LicenseService tier | Yes (SR630 fixture + `samples/lenovo-sr630v2` replay; optional skip if dump absent) |
| Intel BMC | `IntelBMCCollector` | DMTF / Generic behavior (no OEM field mapping yet) | No successful dump yet (`GenericCollector` hooks only) |
| Quanta BMC | `QuantaCollector` | Self roots, RackScale drive Oem, SimpleStorage | Yes (`samples/quanta-d42a-2u`, shallow) |
| GIGABYTE BMC | `GigabyteCollector` | Self roots, `Oem.GBT` slot, SimpleStorage | Yes (`samples/gigabyte-server`) |
| Other Redfish BMCs | `GenericCollector` | Standard DMTF resources only | Fallback |

Unknown vendors still scan; OEM-only fields (wear, SmartStorage, CIMC manager path) may be missing.

---

## Key Features

| Feature | Details |
|---------|---------|
| **Browser UI (new)** | Full HTML5 interface — no Tkinter, works on any OS with a browser. `python vcfr_web.py` |
| **Dark Mode** | Reports respect your OS dark/light preference; toggle persists across sessions |
| **Real-Time Progress** | Server-Sent Events stream scan progress live to the browser |
| **Zero External Dependencies** | Runs on any Python 3.9+ installation. No `pip install` needed. Works on locked-down SE laptops. |
| **Multi-vendor OEM Support** | Dynamic Redfish root discovery (`/Systems`, `/Chassis`, `/Managers`) — no hardcoded paths. |
| **VCF 9.1 Rules Engine** | Evaluates CPU support (KB 428874), vSAN ESA/OSA readiness, TPM 2.0 state, Intel VMD BIOS settings. |
| **NVMe SMART Telemetry** | Polling of 20 SMART metrics (OCP v2.6 Spec compliant) with vendor OEM extensions (Dell, HPE, Supermicro, Lenovo, Cisco) under the Health tab. |
| **LLDP & Cisco CDP Discovery** | Multi-vendor ToR switch neighbor mapping across DMTF Redfish, Cisco IMC (CDP/LLDP), Dell iDRAC, HPE iLO, and Lenovo XCC. |
| **Multi-Pass Auto-Retry** | 3-pass automated recovery engine with adaptive thread clamping and targeted differential rescan for degraded or slow BMCs. |
| **GPU Discovery** | Detects NVIDIA / AMD accelerators for Private AI Foundation workload assessment. |
| **FC HBA Detection** | Finds Fibre Channel HBAs and extracts WWPNs for SAN zoning readiness. |
| **PSU Redundancy Check** | Validates power supply count and redundancy state. |
| **Dynamic BCG Deep-Links** | Single-click Broadcom Compatibility Guide URLs for Servers, CPUs, SSDs, NICs/HBAs, GPUs. |
| **Multi-host Fleet Summary** | Scan a subnet and get one `fleet_summary.html` plus per-host detail reports. |
| **Fleet Hub & Multi-Scan Library** | Browser UI and CLI generate a single `fleet_combined.html` Fleet Hub. Small scans (&le;64 hosts) embed reports inline; larger scans (&gt;64 hosts up to 3,000+ hosts) produce a sidecar pack with lazy on-demand frames, searchable host picker, and paginated inventory without the 256-host cliff. Pointing at a multi-scan library directory assembles consolidated fleet deliverables. |
| **Live HCL Cross-Reference** | Auto-fetches `all.json` from Broadcom vSAN HCL (30-day cache in `~/.vcf-readiness/hcl/`). Fallback to local dark-site bundle or CSV. |
| **Saved Profiles** | Named host+credential presets. Passwords go to macOS Keychain / Windows DPAPI / libsecret — never plaintext on disk. |
| **Encrypted Credential Vault (optional)** | Off by default. Per-host / per-subnet / default BMC passwords in a passphrase-encrypted local file, CSV import, CLI + Web UI. See [Credential Vault Guide](docs/CREDENTIAL_VAULT.md). |
| **VCF Operations Integration** | *(In Incubation)* Containerized VMware Integration SDK Management Pack for VCF Operations 9.x and Aria Operations is in developer incubation and will be released in an upcoming update. |
| **Enterprise Security & TLS** | Configurable BMC TLS verification with custom CA bundles, FCrDNS validation, RFC1918 private-target restrictions, and HttpOnly session cookie auth. |
| **Debug Mode** | `--debug` flag writes detailed HTTP traces to `vcf_assess_debug.log`. |
| **PyInstaller Compatible** | Bundle into a double-click `.exe` or macOS binary for field use. |

---

## Interface Options

### Option A — Browser UI (recommended)

The web interface (`vcfr_web.py`) runs a lightweight local server and opens your default browser automatically. No Tkinter, no desktop GUI framework — works anywhere Python runs.

**From source:**
```bash
python vcfr_web.py
# Opens http://127.0.0.1:7182 automatically
```


**Features exclusive to the browser UI:**
- Real-time scan progress via Server-Sent Events
- Fleet Hub report (`00_fleet_combined.html` / `fleet_combined.html`) with adaptive inline or sidecar embedding, searchable host picker, and paginated inventory tables
- "Open Fleet Library" modal to discover and assemble multiple independent scan drops from remote workers or edge collectors into consolidated fleet deliverables
- Auto-export CSV and multi-tab Excel workbooks upon scan completion
- One-click downloads for HTML, Summary JSON, multi-tab Excel (`.xlsx`), and CSV spreadsheets
- Profile and session persistence
- Dark mode toggle that persists to `localStorage`

---

### Option B — Command-Line Interface

#### Prerequisites

- Python 3.9+ (macOS, Linux, or Windows)
- Network access to BMC management IPs

#### Scan a Single Host

```bash
python vcfr_collector.py --targets 10.0.0.1
```

#### Scan a Range or Subnet

```bash
python vcfr_collector.py --targets "10.0.0.1-20"
python vcfr_collector.py --targets "192.168.1.0/24" --threads 8
```

#### Force Refresh Broadcom HCL

```bash
python vcfr_collector.py --targets 10.0.0.1 --refresh-hcl
```

#### Debug Mode & Summary JSON Export

```bash
python vcfr_collector.py --targets 10.0.0.1 --debug --save-json
# Writes vcf_assess_debug.log, vcf_summary_<IP>.json, and fleet_summary.json
# with full HTTP traces and maximized raw Redfish data capture
```

#### Offline Summary Import & Fleet Library Assemble Mode (Skip Scan)

```bash
# Single-Artifact Summary Import
python vcfr_collector.py --from-summary fleet_summary.json
# Instantly renders HTML reports from saved summary JSON without live BMC access

# Multi-Scan Fleet Library Assemble
python vcfr_collector.py --from-summary ~/Desktop/VCF-Scans
# Discovers all dropped scan directories and zip archives in library folder,
# deduplicates hosts by UUID/serial/IP, and assembles consolidated fleet deliverables

# Assemble-Only (Skip re-rendering individual host reports)
python vcfr_collector.py --from-summary ~/Desktop/VCF-Scans --assemble-only
```

---

### Scan Modes (Quick, Lean, Full)

The assessment tool provides three scan modes to balance scan speed vs data depth:

- **Quick mode** (`quick_mode=True` / `--quick`): Ultra-fast overview scan (~5s per host). Queries CPU details, BIOS settings, SEL alarms, license, and BMC firmware only. Storage, network adapter, GPU, PSU, thermal, and telemetry sections are skipped and will appear empty in generated reports by design.
- **Lean mode** (`lean_mode=True` / `--lean`): Fast hardware inventory scan (~15–30s per host). Collects all hardware inventories including Drive and NIC PCI IDs, storage controllers, network adapters, and vSAN ESA readiness while skipping heavy performance telemetry, firmware inventory member GETs, and extra thermal GETs.
- **Full mode** (default, recommended for complete VCF/vSAN readiness): Comprehensive hardware assessment (~60–90s per host). Queries all Redfish endpoints including performance telemetry, SMART drive wear/endurance metrics, thermal sensors, and GPU accelerators.

#### Scan Mode Feature Comparison

| Feature | Quick Scan (`--quick`) | Lean Scan (`--lean`) | Full Scan (Default) |
| :--- | :--- | :--- | :--- |
| **Average Duration** | **~5 seconds / host** | **~15–30 seconds / host** | **~60–90 seconds / host** |
| **CPU, RAM & BIOS Check** | Yes | Yes | Yes |
| **SEL Alarms & BMC FW** | Yes | Yes | Yes |
| **Drive & Controller PCI IDs** | No | **Yes** | Yes |
| **NIC & Adapter PCI IDs** | No | **Yes** | Yes |
| **vSAN ESA Compatibility** | CPU/RAM only | **Yes** | Yes |
| **Broadcom BCG Deep-Links** | Server/CPU only | **Server, CPU, SSD, IO** | Server, CPU, SSD, IO, GPU |
| **SMART Wear & Performance Telemetry** | No | No | Yes |

* **Dell iDRAC pre-boot note:** Even in full or lean mode, Dell iDRAC Redfish endpoints may return empty NIC and storage inventories while the host is powered off or in POST/pre-boot. Always run assessments with the host powered on and OS active.

---

## Security Architecture

> 🛡️ **For Security Teams:** See the dedicated [**Security Architecture Whitepaper (Infosec One-Pager)**](docs/SECURITY_ARCHITECTURE.md) for full details on least privilege, out-of-band architecture, air-gapped operations, and source audit rights.

### Key Security & Trust Guarantees
- **Principle of Least Privilege:** Requires only read-only OOB BMC accounts over HTTPS (port 443). Zero write, reboot, or firmware flashing capabilities; zero in-band host/OS credentials.
- **Zero Third-Party Dependencies:** 100% Python 3.9+ standard library (`urllib.request`, `ssl`, `json`, `hashlib`). No unvetted `pip` packages.
- **Zero "Phone-Home" / No Egress:** No analytics, telemetry beacons, or external reporting pings.
- **Auditable & Non-Opaque:** Run purely as standard Python source code (`python3 vcfr_web.py`) without pre-compiled binaries.
- **Permissive License for Security Reviews:** Explicit rights under `LICENSE.md` to ingest and audit source code using enterprise SAST or LLM security platforms (e.g. Mythos, Fable, CodeQL).

### Security & TLS Enforcement

The VCF Readiness Assessment Tool includes enterprise security controls for BMC connectivity, credential isolation, and web interface protection:

- **BMC TLS Verification (`--verify-ssl`)**: By default, the tool operates in `CERT_NONE` mode to handle unmanaged/self-signed enterprise BMC certificates without crashing. Passing `--verify-ssl` enforces strict TLS certificate validation against the OS trust store.
- **Custom Enterprise CA Bundles (`--ca-bundle <path>`)**: For enterprise environments using internal PKI (e.g. Microsoft CA, HashiCorp Vault, Active Directory Certificate Services), point `--ca-bundle` to your root/intermediate CA bundle (`.pem` or `.crt`).
- **Forward-Confirmed Reverse DNS (`--dns-lookup`)**: When verifying certificates by hostname or scanning subnets, `--dns-lookup` performs automated FCrDNS (PTR query followed by forward A/AAAA confirmation) to validate BMC Subject Alternative Names (SANs) and mitigate DNS spoofing.
- **Private IP Range Enforcement (`--restrict-private-targets`)**: Enforces scanning strictly within RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), or link-local (`169.254.0.0/16`), rejecting public WAN/internet IPs.
- **Web UI & API Hardening**:
  - Session cookies are `HttpOnly` and `SameSite=Strict`. On an HTTPS listener they are also `Secure`.
  - The startup URL carries a one-time launch token. The browser exchanges it for that cookie; the token then stops working and is not accepted as an API credential.
  - Strict exact-origin CORS and Host header validation preventing cross-site request forgery (CSRF) and DNS rebinding.
  - `--allow-remote`, or a `--bind` other than loopback, requires `--tls-cert` and `--tls-key`. The UI does not listen in cleartext on a reachable interface.
  - Windows DPAPI credential files hardened with restrictive `icacls` user ACLs (or macOS Keychain / Linux Secret Service).
  - Strict 32 MB payload caps and Zip Slip path traversal defenses on all file imports.
- **Optional Encrypted Credential Vault (off by default)**: For fleets with different BMC passwords per rack or generation, `python -m vcf_hci.vault` manages a passphrase-encrypted local file (`~/.vcf-readiness/credentials.vault`) of exact-host / CIDR / default entries. Stdlib-only PBKDF2-HMAC-SHA256 (600k iterations) + HMAC-SHA256 Encrypt-then-MAC — not AES, since the Python standard library has none. Passwords are never printed, never sent to the browser, and the Web UI vault is disabled under `--allow-remote`. Enable per scan with `--vault` or the *Use encrypted credential vault* checkbox. See the [Credential Vault Guide](docs/CREDENTIAL_VAULT.md).

### BMC Hardware Security Audit (84 Controls & CISA/NSA Alignment)

The assessment engine includes an out-of-band **BMC Hardware Security Audit** evaluating 84 canonical controls to verify enterprise server nodes meet hardening standards prior to VCF 9.1 commissioning:

- **84 Canonical Controls:** Evaluates 59 configuration controls (`C01`–`C59`), 16 operational lifecycle recommendations (`O01`–`O16`), and 9 platform assurance capabilities (`I01`–`I09`).
- **Catalog Provenance & Governance:** Numbering originated from a formal normalization of the *Dell iDRAC9 Security Configuration Guide* (the initial setting-by-setting baseline). The security intent of these controls is governed by authoritative vendor-neutral benchmarks: the [**CISA & NSA Joint Cybersecurity Information Sheet: Harden Baseboard Management Controllers (PDF)**](https://media.defense.gov/2023/Jun/14/2003241405/-1/-1/0/CSI_HARDEN_BMCS.PDF), the **VMware Cloud Foundation Security Configuration Guide (SCG 9.1)**, and **NIST SP 800-193**.
- **Three-Tier Multi-OEM Portability:**
  - **Tier 1 (8 Universal DMTF Standards):** Evaluated identically via standard Redfish on all platforms (`C09, C21, C23, C24, C29, C37, C43, C53`), including Intel and Supermicro.
  - **Tier 2 (40 Portable Concepts):** Vendor-neutral hardening outcomes evaluated via dedicated OEM adapters for Dell iDRAC, HPE iLO, Lenovo XCC, and Cisco CIMC.
  - **Tier 3 (11 Dell-Specific Controls):** Dell-proprietary features (`C18, C19, C30–C32, C48, C55–C59`) held strictly as `not_applicable` on non-Dell BMCs.
  - **OEM Gap Stubs (`G-*`):** Non-Dell native security modes (e.g. HPE iLO `SecurityState: HighSecurity/FIPS/CNSA`) are tracked as distinct gap stubs without altering the canonical catalog.

For the exhaustive control catalog, evidence schemas, and remediation procedures, see:
- [**User Guide & Reference Manual — 84-Control Security Audit Catalog**](docs/USER_GUIDE_REFERENCE.md#bmc-84-control-catalog)
- [**Security Architecture Whitepaper — Regulatory & Hardening Compliance Baselines**](docs/SECURITY_ARCHITECTURE.md#12-regulatory--hardening-compliance-baselines-cisa-nsa-nist-vcf-scg)

---

## Command-Line Options

| Argument | Default | Description |
|----------|---------|-------------|
| `--targets` | Prompted | IP, hostname/FQDN, range (`10.0.0.1-20`), or CIDR (`10.0.0.0/24`) |
| `--username`, `-u` | Prompted | BMC username |
| `--password-env` | `None` | Environment variable name containing the BMC password |
| `--no-input` | `False` | Disable interactive prompts for non-interactive scripting |
| `--vault [PATH]` | off | **Opt-in.** Resolve per-host credentials from the encrypted local vault (default `~/.vcf-readiness/credentials.vault`). Manage with `python -m vcf_hci.vault`. |
| `--vault-passphrase-env` | `None` | Environment variable holding the vault passphrase (required with `--vault --no-input`) |
| `--from-summary` | `None` | Path to summary JSON/zip, scan directory, or parent library directory to assemble |
| `--site` | `""` | Assign site/datacenter tag to scan (recorded in MANIFEST.json and provenance) |
| `--assemble-only` | `False` | Assemble fleet summary, Fleet Hub HTML, Excel, and CSVs without rendering host reports |
| `--csv` | auto-detected | Path to offline Broadcom vSAN SSD CSV |
| `--refresh-hcl` | `False` | Force re-download of `all.json` from Broadcom |
| `--bundle-hcl` | `None` | Package live Broadcom vSAN HCL dataset into a dark-site zip bundle |
| `--import-hcl` | `None` | Path to offline air-gapped dark-site HCL zip bundle |
| `--verify-ssl` | `False` | Enforce TLS certificate verification for BMC HTTPS connections |
| `--ca-bundle` | `None` | Path to custom enterprise CA certificate bundle (`.pem`/`.crt`) for TLS |
| `--dns-lookup` | `False` | Perform Forward-Confirmed Reverse DNS (FCrDNS) lookups for BMC hostnames |
| `--restrict-private-targets` | `False` | Restrict targets to RFC1918 private / local / loopback IP addresses only |
| `--threads` | `8` | Concurrent scan threads for multi-host runs (max: 96) |
| `--force-threads` | `False` | Bypass automatic VPN / high-latency network concurrency throttling |
| `--two-pass` | `False` | Run Pass 1 fast discovery probe and Longest-Job-First (LJF) priority scheduling |
| `--discover-only` | `False` | Run Pass 1 discovery sweep, write `data/discovery_cache.json`, and exit |
| `--discovery-cache` | `None` | Path to prior discovery cache JSON file to skip dark/unresponsive IPs |
| `--prune-inactive` | `False` | Automatically filter out dark/unreachable IPs discovered in Pass 1 |
| `--no-auto-throttle` | `False` | Disable dynamic concurrency stepdown on high CPU load or low memory |
| `--legacy-tls` | `False` | Allow legacy TLS 1.0/1.1 and ciphers (`DEFAULT:@SECLEVEL=1`) for older BMCs (Dell 13G, Supermicro X10) |
| `--tls-min-version` | `None` | Set minimum TLS version (`1.0`, `1.1`, `1.2`, `1.3`) |
| `--host-timeout` | `300` | Maximum scan duration per host in seconds (default: 300s / 5m) |
| `--allow-partial` | `False` | Harvest valid subsystems even if non-critical endpoints time out |
| `--output-dir` | `.` | Directory where HTML reports are written (default: `~/Desktop/VCF-Scans`) |
| `--save-json` | `False` | Save structured host and fleet summary JSONs for offline import/analysis |
| `--include-raw` | `False` | Include raw Redfish API response payloads in summary JSONs |
| `--no-combined` | `False` | Skip generating Fleet Hub HTML report |
| `--profile` | `readiness-full` | Scan depth profile: `readiness-full`, `readiness-lean`, `inventory-lite` |
| `--lean` | `False` | Lean scan mode (skip telemetry, firmware inventory, and extra thermal GETs) |
| `--oem` | `False` | Activate deep OEM discovery preset (crawl, raw retention, full profile, 15m timeout) |
| `--crawl` | `False` | Run Redfish hypermedia crawler, catalog write actions, and export mockup ZIP |
| `--excel` | `True` | Export assessment results to multi-tab Excel workbook (`.xlsx`) [default: enabled] |
| `--no-excel` | `False` | Disable automatic Excel workbook export |
| `--csv-export` | `False` | Export assessment results to standardized CSV files (`00_fleet_summary.csv`, etc.) |
| `--obfuscate` | `False` | Generate obfuscated report copies (IPs→Host-N, MACs/S/Ns→hashes) |
| `--force` | `False` | Bypass target expansion caps and allow large CIDR scans (`/8`, `/16`) |
| `--debug` | `False` | Enable verbose debug logging and raw Redfish JSON capture |

---

## Output Files

| File | Description |
|------|-------------|
| `vsphere_vsan_report_<IP>.html` | Per-host assessment with all hardware details and BCG links |
| `vcf_summary_<IP>.json` | Machine-readable host summary JSON (with `--save-json` or `--debug`) |
| `fleet_summary.json` / `.json.gz` | Fleet summary JSON/v2 compressed manifest payload for offline import |
| `MANIFEST.json` | Scan execution metadata manifest (`tool_version`, `scanned_at`, `host_count`, `collector_id`, `site`, `scan_profile`, `obfuscated`) for library discovery and remote drop ingestion |
| `fleet_summary.html` | One-page fleet overview dashboard |
| `fleet_combined.html` / `00_fleet_combined.html` | Fleet Hub HTML dashboard embedding all host reports (single inline file for &le; 64 hosts, sidecar pack with lazy on-demand frames for &gt; 64 hosts up to 3,000+ hosts without 256-host cliff) |
| `vcf_readiness_<timestamp>.xlsx` | Multi-sheet Excel export (Summary, Storage, NICs, GPUs, Security, Failed Hosts) |
| `00_fleet_summary.csv` | Standardized tabular fleet summary with 40+ Schema v2.0 domain fields |
| `00_drives_inventory.csv` | Physical storage drive inventory across all assessed hosts |
| `00_nics_inventory.csv` | Network interface adapter, port, and ToR switch neighbor inventory |
| `00_gpus_inventory.csv` | Hardware accelerator and GPU inventory across all hosts |
| `00_failed_hosts.csv` | Preflight and connection failure diagnostics for unreachable hosts |
| `00_OBFUSCATED_*` | Obfuscated mirrors of HTML, Excel (`.xlsx`), and CSV deliverables (with `--obfuscate`) |
| `vcf_assess_debug.log` | HTTP-level debug trace (with `--debug` flag) |

State kept in your home directory:

| File / Directory | Description |
|------------------|-------------|
| `~/.vcf-readiness/hcl/` | HCL dataset cache (`all.json`) and auto-built dark-site bundles (`vcf_hcl_bundle_*.zip`) |
| `~/.vcf-readiness-session.json` | Last-used range, username, output folder, mode |
| `~/.vcf-readiness-profiles.json` | Saved profiles — **no passwords** |
| `~/.vcf-readiness-secrets.json` | Windows only: DPAPI-encrypted passwords |
| `~/.vcf-readiness/credentials.vault` | **Only if you opt in.** Passphrase-encrypted per-host/subnet/default BMC credentials (`0600`), see [Credential Vault Guide](docs/CREDENTIAL_VAULT.md) |

---

## Report Sections

> 📚 **Comprehensive Reference Guide:** For an exhaustive tab-by-tab and field-by-field reference explaining every metric, evaluation rule, official VMware KB, and the 84-control BMC security audit, see the [**User Guide & Reference Manual (docs/USER_GUIDE_REFERENCE.md)**](docs/USER_GUIDE_REFERENCE.md).

Each per-host HTML report includes:

- **Executive Summary Cards** — CPU support tier, BIOS version status, TPM 2.0 state, memory topology, vSAN ESA/OSA readiness, Intel VMD state, PSU redundancy, CPU/memory utilization
- **System Event Log** — Last 3 unique Warning/Critical SEL or IML alarms
- **Performance Telemetry** — Current and historical peak CPU and memory bus utilization
- **Thermal Matrix** — Expandable sensor table with warning and critical thresholds
- **Network Interfaces** — Per-port link speed with ESA/OSA qualification badges, LLDP & Cisco CDP Top-of-Rack switch neighbor discovery, and BCG links
- **Fibre Channel HBAs** — FC adapters, port WWPNs, speeds, BCG links
- **GPU Accelerators** — Hardware accelerator inventory + BCG links
- **Storage Subsystem** — Per-controller drive inventory with vSAN classification, endurance %, and BCG search links

---

## Data Obfuscation & PII Anonymization

The VCF Readiness Assessment Tool includes built-in, server-side data obfuscation capabilities to allow VMware Sales Engineers, Solution Architects, and customer IT teams to share hardware readiness reports externally (e.g., with Broadcom engineering or hardware OEMs) without exposing sensitive infrastructure metadata or personally identifiable information (PII).

### Obfuscation Coverage Catalog

When obfuscation is enabled, all customer-identifying fields across the entire report dataset are replaced with deterministic hash tokens:

- **Host & Network Identifiers:** BMC IP addresses, hostnames, FQDNs, DNS names, management network IP addresses, NTP server IPs/hostnames, LLDP / Cisco CDP switch names, switch ports, chassis IDs, and network adapter MAC addresses.
- **Hardware Serial Numbers:** Server chassis serial numbers, service tags, asset tags, hardware SKUs, physical drive serial numbers, storage enclosure serials, Fibre Channel HBA WWPNs and WWNNs, GPU accelerator serial and part numbers, PCIe expansion slot device serials, and DIMM memory serial numbers.
- **Logs & Raw API Captures:** System Event Log (SEL/IML) messages and raw Redfish JSON payloads are scrubbed using regular expressions to strip hostnames, domain names (such as internal network domains), IP addresses, MAC addresses, and serial numbers.

### Non-Recoverable Anonymization Mechanism

- **Irreversible SHA-256 Hashing:** Real PII values are combined with a per-scan random salt and hashed using SHA-256 before being truncated to short hexadecimal tokens (e.g. `SN-A9030E`, `Host-86`, or `switch-B4C12E`). Real values are discarded server-side during report processing and are never written to the output HTML or JSON files.
- **RFC 5737 TEST-NET IP Mapping:** All IP addresses are mapped to non-routable RFC 5737 TEST-NET addresses (`192.0.2.x`), ensuring fake IPs are immediately recognizable.
- **Locally Administered MAC Addresses:** All MAC addresses are transformed to IEEE 802 locally-administered MAC addresses starting with `02:xx:xx:xx:xx:xx`.
- **Deterministic Cross-Host Correlation:** When scanning a fleet, the same salt is applied across all hosts in the scan run. Identical real values (such as shared top-of-rack switches or identical SAN boot targets) produce identical tokens in every report file. Reviewers can analyze topology relationships and component groupings across the fleet without seeing underlying customer infrastructure details.

### Hardware Spec & Verdict Integrity

Obfuscation **only** sanitizes sensitive identifiers. All technical hardware specifications and compatibility evaluation logic remain 100% intact:
- CPU model, socket count, core count, instruction set architecture, and VCF 9.1 support tiers
- Total RAM capacity, speed, DIMM health, and channel interleaving efficiency %
- Drive model, capacity, bus type (NVMe/SAS/SATA), endurance remaining %, OCP SMART metrics, and vSAN ESA/OSA eligibility
- NIC port speed, link status, and ESA qualification badges
- TPM 2.0 status, BIOS baseline compliance, Intel VMD state, and Secure Boot settings
- All clickable Broadcom Compatibility Guide (BCG) deep-links

### How to Use Obfuscation

1. **Web UI:** Check the **"Generate obfuscated copies"** checkbox on the assessment form before running a scan. The tool generates standard reports alongside dedicated `OBFUSCATED_*.html` reports in the `VCF-Scans` directory.
2. **Command-Line Interface:** Pass the `--obfuscate` flag during scan execution:
   ```bash
   python vcfr_collector.py --targets 10.0.0.1-10 --obfuscate
   ```
3. **Interactive Client-Side Toggle:** On standard (un-obfuscated) HTML reports, viewers can check the **"Obfuscate report"** checkbox in the top header to mask sensitive fields dynamically in the browser and download a standalone obfuscated HTML file. Pre-obfuscated reports display a static **🔒 Obfuscated Report** badge.

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│          Layer A: OEM-Agnostic Redfish Adapter         │
│   UniversalRedfishCollector (dynamic root discovery)   │
└──────────────────────────┬─────────────────────────────┘
                           │ Raw Hardware Payload
                           ▼
┌────────────────────────────────────────────────────────┐
│        Post-Collection Enrichment Pipeline             │
│   vcf_hci/enrichment.py — enrich_host_result()         │
└──────────────────────────┬─────────────────────────────┘
                           │ Enriched Hardware Payload
                           ▼
┌────────────────────────────────────────────────────────┐
│          Layer B: VCF 9.1 Compatibility Engine         │
│   vcf_hci/compat/ + VCF9CompatibilityEngine facade     │
└──────────────────────────┬─────────────────────────────┘
                           │ Status Verdicts & Badges
                           ▼
┌────────────────────────────────────────────────────────┐
│          Layer C: BCG Deep-Link Generator              │
│   BCGLinkGenerator (Servers, CPUs, SSDs, IO, GPUs)     │
└──────────────────────────┬─────────────────────────────┘
                           │ Component URLs
                           ▼
┌────────────────────────────────────────────────────────┐
│    Layer D: Aggregator + Reports + UI                  │
│   HTML Reports · Browser UI (vcf_hci/web/)             │
└────────────────────────────────────────────────────────┘
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full engineering specification.

---

## OEM & Hardware Vendor Collaboration

Are you a server OEM, hardware vendor, or solution partner? We actively invite direct collaboration!

To make hardware visualization, chassis drive bay diagrams, and compatibility assessment as accurate and robust as possible, OEMs are encouraged to reach out or contribute:
- **Chassis Drive Bay Maps & Order SKUs**: Provide mappings for server part numbers/SKUs to physical drive bay configurations (e.g. 10 SFF, 24 SFF, 16 EDSFF, 4 LFF) for addition to our chassis databases.
- **Chassis Diagrams & Front Panel Vector Graphics**: Provide SVG layouts or chassis maps to enhance standalone HTML report visualizations.
- **Redfish Telemetry & Mockup Payloads**: Provide sanitized Redfish JSON dumps (using `tools/crawl_oem_host.py`) to help test storage controller enumeration, NVMe drive slot detection, and health reporting without requiring physical hardware in test labs.

Please open a [GitHub Issue](https://github.com/vmware/vcf-readiness/issues/new?template=oem_support_request.md) or submit a Pull Request. See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/OEM_REFERENCE.md](docs/OEM_REFERENCE.md) for details.

---

## Broadcom References

- **[KB 428874](https://knowledge.broadcom.com/external/article/428874)** — vSphere/VCF 9.x CPU Deprecated Mode Support Policy
- **[Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/)** — Live hardware search matrix
- **[vSAN HCL JSON](https://vvs.broadcom.com/service/vsan/all.json)** — Live vSAN drive certification data

## Switch Buffer & Silicon References

- **[Michael Buraglio's Packet Buffer Reference](https://port-buffers.forwardingplane.net/)** ([GitHub: buraglio/port-buffers](https://github.com/buraglio/port-buffers)) — Static catalog of switch/router packet buffer sizes, queue architectures, and silicon specifications across enterprise and data center networking hardware.
- **[Jim Warner's UCSC Packet Buffer Research](https://people.ucsc.edu/~warner/buffer-wuz.html)** ([ASIC Buffer History](https://people.ucsc.edu/~warner/Bufs/buf-hist.html)) — Pioneering research by Jim Warner (formerly UCSC) documenting packet buffer depths, memory segmentation, and shared memory architectures across switch ASICs.

---

## Credits & Acknowledgements

### Project Thanks & Acknowledgements

- **Phong Le** — For answering 40,000 hardware HCL questions.
- **Onur Yuzseven & Brock Peterson** — For the great vCommunity plugins ([GitHub: prydin/VCF-Operations-vCommunity](https://github.com/prydin/VCF-Operations-vCommunity), [Brock Peterson's vCommunity Management Pack Guide](https://www.brockpeterson.com/post/vcommunity-management-pack-for-vcf-operations)).
- **Everyone at Spiceworks** — For making me realize the power of a good inventory, and the [Spiceworks Community](https://community.spiceworks.com/) forums for teaching me the evils of fake RAID.

### Third-Party Software & Research

- Browser UI styled with [Clarity Design System](https://clarity.design/) tokens (VMware/Broadcom, Apache-2.0 license). CSS is pre-bundled in `vcf_hci/web/assets.py` — no internet required at runtime. See [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
- Switch buffer intelligence, ASIC mapping, and VOQ classification derived from the open research of **Michael Buraglio** and **Jim Warner**.

---

## License

CA, Inc. License — see [LICENSE.md](LICENSE.md) and [NOTICE](NOTICE). For third-party components included in standalone distributions, see [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).