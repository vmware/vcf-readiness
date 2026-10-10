# VCF Readiness Assessment Tool

> Zero-dependency Python tool for VMware Sales Engineers, Solution Architects, and IT teams to assess server hardware for VMware Cloud Foundation 9.1 and vSAN Express Storage Architecture (ESA) repurposing.

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-green.svg)](#)
[![Latest Release](https://img.shields.io/github/v/release/vmware/vcf-readiness?label=Download)](https://github.com/vmware/vcf-readiness/releases/latest)

---

<p align="center">
  <a href="#-visual-report-showcase">
    <img src="docs/assets/vcf_readiness_showcase.gif" alt="VCF Readiness Assessment Tool Rotating Feature Showcase" width="100%">
  </a>
  <br>
  <em>Automated enterprise fleet telemetry, memory topology visualizer, ToR fabric mapping, vSAN ESA HCL validation &amp; 84-point BMC security audit.</em>
</p>

---

## 🎬 Video Walkthroughs & Demos

Watch short step-by-step video guides to get up and running, launch on macOS, and interpret generated assessment reports.

> 📺 **[Watch Full YouTube Playlist (3 Videos) →](https://www.youtube.com/playlist?list=PLIyQp4kTfTYU)**

| [Scanner Quick Start (1:19)](https://www.youtube.com/watch?v=nfKTH5aG76s) | [Report Overview (8:20)](https://www.youtube.com/watch?v=tQkxyRHZu4M) | [Launch for Mac from Python (0:55)](https://www.youtube.com/watch?v=L5_IyTcHiMo) |
|:---:|:---:|:---:|
| [![Scanner Quick Start](docs/assets/screenshots/video-scanner-quickstart.jpg)](https://www.youtube.com/watch?v=nfKTH5aG76s) | [![Report Overview](docs/assets/screenshots/video-report-overview.jpg)](https://www.youtube.com/watch?v=tQkxyRHZu4M) | [![Launch for Mac from Python](docs/assets/screenshots/video-mac-launch.jpg)](https://www.youtube.com/watch?v=L5_IyTcHiMo) |
| Target entry, credentials, TLS certificates, and initiating a fleet assessment | Detailed walkthrough of fleet summary badges, tabs, BIOS drift, and host sub-reports | Terminal launch with Python standard library on macOS workstations |

---

## Table of Contents

- [Video Walkthroughs & Demos](#-video-walkthroughs--demos)
- [Quick Start: Run from Source (Recommended)](#-quick-start-run-from-source-recommended)
- [Alternative: Pre-Compiled Executables (Unsigned)](#-alternative-pre-compiled-executables-unsigned)
- [What It Does & Platform Support](#-what-it-does)
- [Visual Report Showcase](#-visual-report-showcase)
- [Command-Line Interface (CLI)](#-command-line-interface-cli)
- [OEM & Hardware Vendor Collaboration](#-oem--hardware-vendor-collaboration)
- [Advanced Documentation](#-advanced-documentation--architectural-deep-dives)
- [References & Credits](#-references--credits)

---

## 🚀 Quick Start: Run from Source (Recommended)

The assessment tool is built with **zero external dependencies** — it runs on standard Python 3.9+ using only the Python standard library. No `pip install` is needed, making it ideal for restricted SE laptops and air-gapped environments.

> 🎥 **Prefer video?** Watch the 1-minute [**Scanner Quick Start Video (1:19) →**](https://www.youtube.com/watch?v=nfKTH5aG76s) for a walkthrough of targets, credentials, and running a scan.

### macOS & Linux

```bash
# 1. Clone the repository
git clone https://github.com/vmware/vcf-readiness.git
cd vcf-readiness

# 2. Make executable and launch the Web UI
chmod +x vcfr_web.py
./vcfr_web.py
# Or launch directly via Python: python3 vcfr_web.py
```
> *Your web browser will open automatically at **`http://127.0.0.1:7182`**.*

### Windows

```cmd
git clone https://github.com/vmware/vcf-readiness.git
cd vcf-readiness
python vcfr_web.py
```
> *Your web browser will open automatically at **`http://127.0.0.1:7182`**.*

<details>
<summary><strong>Need to install Python 3.9+? (Windows, macOS, Linux setup guide)</strong></summary>

### Windows
1. Download the **Windows installer (64-bit)** from [python.org](https://www.python.org/downloads/windows/).
2. **Critical:** On the first installer screen, check **"Add python.exe to PATH"** before clicking Install Now.
3. Open Command Prompt (`cmd`) and verify: `python --version`

### macOS
> 🎥 **Video Guide:** Watch [**Launch for Mac from Python (0:55) →**](https://www.youtube.com/watch?v=L5_IyTcHiMo) for a quick demonstration of launching the web interface from Terminal.

1. Open Terminal and install Python via Homebrew:
   ```bash
   brew install python
   ```
2. Verify: `python3 --version`

### Linux (Ubuntu, Debian, RHEL, Fedora)
```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y python3

# RHEL / CentOS / Fedora
sudo dnf install -y python3

# Verify
python3 --version
```

### Remote / Headless Linux Server
Forward the web interface over SSH to your local machine:
```bash
# Run on your local machine:
ssh -L 7182:127.0.0.1:7182 user@remote-server

# On the remote server, start the web server:
python3 vcfr_web.py
# Then open http://127.0.0.1:7182 in your local browser
```

</details>

---

## 📦 Alternative: Pre-Compiled Executables (Unsigned)

If Python is not available on your system, standalone binaries are packaged on the [**Latest Release page →**](https://github.com/vmware/vcf-readiness/releases/latest)

| Platform | Download Package | Launch Instructions |
|:---------|:-----------------|:--------------------|
| **Windows** | `VCF-Readiness-Web-v9.9.1-win.exe` | Double-click binary; browser opens automatically |
| **macOS** | `VCF-Readiness-Web-v9.9.1-mac.zip` | Unzip → double-click `Launch-VCF-Readiness-Web.command` |
| **Linux** | `VCF-Readiness-Web-v9.9.1-linux.zip` | Extract archive → run executable |

> ⚠️ **Important Notice Regarding Unsigned Executables:**
> 
> Release binaries are **unsigned developer builds**. Because they are not signed with enterprise certificates, your operating system will flag them on first execution:
> - **macOS Gatekeeper:** macOS will block execution by default. To allow it, **right-click** `Launch-VCF-Readiness-Web.command` (or binary) → select **Open** → click **Open** in the confirmation dialog.
> - **Windows SmartScreen:** Windows may show a blue warning banner. Click **"More info"** → then click **"Run anyway"**.
> 
> **To avoid OS security prompts completely, we strongly recommend [running from source](#-quick-start-run-from-source-recommended).**

---

## 🔍 What It Does

The tool queries enterprise server BMC controllers over out-of-band Redfish REST APIs and evaluates hardware against VCF 9.1 and vSAN Express Storage Architecture (ESA) standards. It answers the critical architectural question: **can this server fleet be repurposed for VCF 9.1?**

### Multi-Vendor BMC Platform Support

| BMC Platform | Architecture & Adapters | Assessment Depth | Automated Test Fixture |
|:-------------|:------------------------|:-----------------|:-----------------------|
| **Dell iDRAC** | `DellCollector` (iDRAC7/8/9/10) | Full OEM telemetry (SKU, BIOS date, NVMe SMART wear, EEMS alerts, license) | Yes (R640, R6525, R750, R740+GPU) |
| **HPE iLO** | `HPECollector` (iLO 4/5/6) | Full OEM hooks (SmartStorage, system usage, IML event logs, license) | Yes (DL360 Gen10, DL380 Gen10) |
| **Supermicro BMC** | `SupermicroCollector` | SimpleStorage, drive inventory, DCMS license detection | Yes (SYS-E200-8D, SuperServer) |
| **Cisco IMC** | `CiscoCollector` (CIMC) | `/Managers/CIMC`, physical drive metrics, Cisco CDP neighbor discovery | Yes (C220 M5) |
| **Lenovo XCC** | `LenovoCollector` (XCC/XCC2) | Drive metrics, LicenseService tiers, ThinkSystem inventory | Yes (SR630, SR650) |
| **Quanta / QCT** | `QuantaCollector` | Dynamic root discovery, RackScale drive OEM inventory | Yes (QuantaGrid D42A) |
| **GIGABYTE BMC** | `GigabyteCollector` | Self-roots, `Oem.GBT` slot detection, SimpleStorage | Yes (GIGABYTE Server) |
| **Generic Redfish** | `GenericCollector` | Universal DMTF Redfish fallback for standard platforms | Universal fallback |

---

## 📊 Visual Report Showcase

Every assessment run generates rich, standalone HTML deliverables (an aggregated **Fleet Summary** and individual **Host Reports**) with zero runtime external asset dependencies.

> 🎥 **Video Tour:** Watch the [**Report Overview Video (8:20) →**](https://www.youtube.com/watch?v=tQkxyRHZu4M) for a guided walkthrough of the fleet summary, status badges, BIOS drift scorecard, and per-host sub-reports.

### 1. Fleet Dashboard & Resource Headroom
Aggregates compute vCPU, RAM, and direct-attached NVMe storage across your entire server inventory, modeling resource headroom against VCF 9.1 management domain sizing profiles.

![Fleet Health and Management Headroom Tiles](docs/images/01-fleet-health-tiles.png)

Fleet-wide power redundancy tracking, chassis power cap warnings, vSAN readiness distribution, and aggregate kilowatt telemetry:

![Fleet Power, vSAN Distribution, and Alarms](docs/images/02-fleet-power-sel-tor.png)

- **Detailed Telemetry:** [Fleet Metric Health Tiles (`docs/assets/screenshots/fleet-metric-tiles.png`)](docs/assets/screenshots/fleet-metric-tiles.png)

---

### 2. Interactive Per-Host Assessment Matrix
Sort, search, and filter servers by OEM vendor, CPU support tier, TPM 2.0 status, and vSAN ESA readiness with direct links into individual host sub-reports.

![Per-Host Assessment Table](docs/images/03-per-host-table.png)

- **Detailed Telemetry:** [Multi-Host Fleet Status Grid (`docs/assets/screenshots/fleet-multi-host-capture.png`)](docs/assets/screenshots/fleet-multi-host-capture.png)

---

### 3. Executive Hardware Scorecards & Subsystem Audits
Color-coded executive summary scorecards highlighting CPU compatibility, BIOS currency, TPM 2.0 status, and vSAN driver/firmware alignment against the Broadcom Compatibility Guide (BCG).

![Executive Host Summary Scorecards](docs/images/08-host-scorecards.png)

- **Detailed Telemetry:** [Single-Host Assessment Tiles (`docs/assets/screenshots/single-host-server-tiles.png`)](docs/assets/screenshots/single-host-server-tiles.png) • [Sub-Category Health Breakdown (`docs/assets/screenshots/sub-category-system-overview.png`)](docs/assets/screenshots/sub-category-system-overview.png)

---

### 4. Physical Motherboard DIMM Slot & Channel Layout
Visualizer mapping installed DIMM modules to physical CPU sockets and memory channels, detecting unbalanced memory interleaving, unpopulated channels, and memory operating below peak rated speeds.

![Motherboard DIMM Slot and Channel Visualizer](docs/images/04-dimm-slot-visualizer.png)

- **Detailed Telemetry:** [Motherboard Channel Topology (`docs/assets/screenshots/memory-channel-topology.png`)](docs/assets/screenshots/memory-channel-topology.png)

---

### 5. Storage Subsystem & vSAN ESA Qualification
Evaluates storage controllers, RAID pass-through modes, and NVMe SSDs. Performs exact PCI Quad matching (`VID:DID:SVID:SSID`) against the Broadcom vSAN HCL dataset, calculates SMART drive wear/endurance remaining %, and generates one-click BCG search links.

![Storage Subsystem and vSAN ESA Qualification](docs/images/05-storage-vsan-esa.png)

- **Detailed Telemetry:** [vSAN ESA Drive Compliance (`docs/assets/screenshots/vsan-esa-drive-compliance.png`)](docs/assets/screenshots/vsan-esa-drive-compliance.png) • [Drive SMART Telemetry (`docs/assets/screenshots/nvme-smart-health-telemetry.png`)](docs/assets/screenshots/nvme-smart-health-telemetry.png) • [PCIe Lane Inventory (`docs/assets/screenshots/pcie-lane-inventory.png`)](docs/assets/screenshots/pcie-lane-inventory.png)

---

### 6. Network Interfaces & Top-of-Rack (ToR) Switch Fabric
Identifies network adapters and port speeds (verifying ≥25 GbE ESA requirements), queries LLDP and Cisco CDP neighbor data to discover connected Top-of-Rack switches, and correlates leaf switch pairs to highlight single-homed hosts and cabling miswires.

![NIC Inventory and Dedicated BMC Management Port](docs/images/06-nic-tor-mapping.png)

![Top-of-Rack Switch Fabric and Topology Matrix](docs/images/10-tor-switch-fabric.png)

- **Detailed Telemetry:** [NIC Optics & LLDP Detection (`docs/assets/screenshots/nic-optics-lldp-detection.png`)](docs/assets/screenshots/nic-optics-lldp-detection.png) • [LLDP / CDP Switch Neighbors (`docs/assets/screenshots/lldp-cdp-switch-neighbors.png`)](docs/assets/screenshots/lldp-cdp-switch-neighbors.png)

---

### 7. System Event Log (SEL / IML) & Diagnostic Decoders
Extracts the latest Warning and Critical hardware alarms from the server's event log, integrating direct links to Dell EEMS diagnostic guides and HPE IML documentation.

![System Assessment Summary and Event Log](docs/images/09-system-assessment-sel.png)

- **Detailed Telemetry:** [System Event Log Monitoring (`docs/assets/screenshots/system-event-log-monitoring.png`)](docs/assets/screenshots/system-event-log-monitoring.png)

---

### 8. 84-Control BMC Hardware Security Audit & Golden BIOS Baseline
Out-of-band security compliance audit evaluating 84 canonical controls aligned with the **CISA & NSA Joint BMC Hardening Guide**, **VMware Cloud Foundation Security Configuration Guide (SCG 9.1)**, and **NIST SP 800-193**. Evaluates BIOS performance drift against Broadcom VCF 9.1 Golden Baselines.

![BMC Hardware Security Audit Findings](docs/images/07-bmc-security-audit.png)

- **Detailed Telemetry:** [BMC Hardware Security Audit (`docs/assets/screenshots/bmc-hardware-security-audit.png`)](docs/assets/screenshots/bmc-hardware-security-audit.png) • [Hardware Security Baseline (`docs/assets/screenshots/hardware-security-baseline.png`)](docs/assets/screenshots/hardware-security-baseline.png) • [BIOS Golden Baseline Drift (`docs/assets/screenshots/bios-golden-baseline-drift.png`)](docs/assets/screenshots/bios-golden-baseline-drift.png) • [BIOS Performance Settings (`docs/assets/screenshots/bios-performance-settings.png`)](docs/assets/screenshots/bios-performance-settings.png)

> 📖 **Comprehensive Reference Guide:** For an exhaustive tab-by-tab and field-by-field reference explaining every metric, evaluation rule, official VMware KB, and the 84-control BMC security audit, see the [**User Guide & Reference Manual (docs/USER_GUIDE_REFERENCE.md)**](docs/USER_GUIDE_REFERENCE.md).

---

## 💻 Command-Line Interface (CLI)

Prefer running from the terminal, scheduling automated cron sweeps, or integrating into automation pipelines?

```bash
# Scan a single host
python vcfr_collector.py --targets 192.0.2.10

# Scan an IP range or CIDR block with 8 parallel worker threads
python vcfr_collector.py --targets "192.0.2.1-24" --threads 8
python vcfr_collector.py --targets "192.0.2.0/24" --threads 16

# Offline summary import: Re-render HTML reports & Excel from prior scan JSON
python vcfr_collector.py --from-summary fleet_summary.json
```

> **Scan Modes:** By default, assessments execute in **Full Mode** (deep hardware queries, SMART metrics, and security audit). For quick sweeps across large subnets, pass `--lean` (~15–30s per host) or `--quick` (~5s per host).

<details>
<summary><strong>Full Command-Line Options Reference (36 Flags — Click to expand)</strong></summary>

| Argument | Default | Description |
|:---------|:--------|:------------|
| `--targets` | Prompted | Target IP, hostname/FQDN, range (`192.0.2.1-20`), or CIDR (`192.0.2.0/24`) |
| `--username`, `-u` | Prompted | BMC username |
| `--password-env` | `None` | Environment variable name containing the BMC password |
| `--no-input` | `False` | Disable interactive prompts for non-interactive scripting |
| `--vault [PATH]` | off | **Opt-in.** Resolve per-host credentials from encrypted local vault (`~/.vcf-readiness/credentials.vault`) |
| `--vault-passphrase-env` | `None` | Environment variable holding vault passphrase (required with `--vault --no-input`) |
| `--from-summary` | `None` | Path to summary JSON/zip, scan directory, or parent library directory to assemble |
| `--site` | `""` | Assign site/datacenter tag to scan (recorded in MANIFEST.json and provenance) |
| `--assemble-only` | `False` | Assemble fleet summary, Fleet Hub HTML, Excel, and CSVs without re-rendering host reports |
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
| `--legacy-tls` | `False` | Allow legacy TLS 1.0/1.1 and ciphers for older BMCs (Dell 13G, Supermicro X10) |
| `--tls-min-version` | `None` | Set minimum TLS version (`1.0`, `1.1`, `1.2`, `1.3`) |
| `--host-timeout` | `300` | Maximum scan duration per host in seconds (default: 300s / 5m) |
| `--allow-partial` | `False` | Harvest valid subsystems even if non-critical endpoints time out |
| `--output-dir` | `~/Desktop/VCF-Scans` | Directory where HTML reports, JSON, and spreadsheets are written |
| `--save-json` | `False` | Save structured host and fleet summary JSONs for offline analysis |
| `--include-raw` | `False` | Include raw Redfish API response payloads in summary JSONs |
| `--no-combined` | `False` | Skip generating Fleet Hub HTML report |
| `--profile` | `readiness-full` | Scan depth profile: `readiness-full`, `readiness-lean`, `inventory-lite` |
| `--lean` | `False` | Fast hardware scan (skips performance telemetry and extra thermal GETs) |
| `--quick` | `False` | Ultra-fast overview scan (~5s/host: CPU, BIOS, SEL alarms only) |
| `--oem` | `False` | Deep OEM discovery preset (crawler, raw retention, full profile, 15m timeout) |
| `--crawl` | `False` | Run Redfish hypermedia crawler and export mockup ZIP |
| `--excel` | `True` | Export assessment results to multi-tab Excel workbook (`.xlsx`) |
| `--no-excel` | `False` | Disable automatic Excel workbook export |
| `--csv-export` | `False` | Export assessment results to standardized CSV files (`00_fleet_summary.csv`, etc.) |
| `--obfuscate` | `False` | Generate obfuscated report copies (IPs→Host-N, MACs/serials→hashes) |
| `--debug` | `False` | Enable verbose debug logging and raw Redfish JSON capture |

</details>

---

## 🤝 OEM & Hardware Vendor Collaboration

> **Do you have access to hardware? Have a feature you want implemented? Reach out!**

We actively invite server OEMs, hardware vendors, and lab owners to collaborate. Whether you have new hardware platforms to test, want drive bay diagrams mapped, or have feature ideas, please open a [GitHub Issue](https://github.com/vmware/vcf-readiness/issues/new) or submit a Pull Request. See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/OEM_REFERENCE.md](docs/OEM_REFERENCE.md).

---

## 📚 Advanced Documentation & Architectural Deep Dives

<details>
<summary><strong>Enterprise Security, TLS, & Air-Gapped Privacy</strong></summary>

For security architecture teams, the assessment engine provides strict isolation guarantees:
- **Zero Third-Party Dependencies:** 100% Python standard library (`urllib.request`, `ssl`, `json`, `hashlib`). No external `pip` packages.
- **Principle of Least Privilege:** Requires read-only BMC accounts over HTTPS (port 443). Zero write, reboot, or firmware update actions.
- **Zero In-Band Footprint:** Zero agents, daemons, or root credentials on the hypervisor or guest operating system.
- **Air-Gapped & Zero Egress:** Zero telemetry beacons, analytics, or outbound communication.
- **Optional Local Credential Vault:** Passphrase-protected local storage (`~/.vcf-readiness/credentials.vault`) using PBKDF2-HMAC-SHA256 (600,000 rounds) + HMAC-SHA256 Encrypt-then-MAC fallback. See the [Credential Vault Guide](docs/CREDENTIAL_VAULT.md).

See the dedicated [**Security Architecture Whitepaper (docs/SECURITY_ARCHITECTURE.md)**](docs/SECURITY_ARCHITECTURE.md).

</details>

<details>
<summary><strong>Client & Server-Side Data Obfuscation (Safe External Sharing)</strong></summary>

Need to share reports externally without exposing sensitive corporate infrastructure?
- **Irreversible SHA-256 Hashing:** Real hostnames, serial numbers, and MAC addresses are salted and hashed into short tokens (e.g. `Host-13`, `SN-3DF62A`, `SW-53356D`).
- **RFC 5737 TEST-NET Mapping:** All IP addresses are mapped to non-routable documentation subnets (`192.0.2.x`).
- **Hardware Spec Integrity:** CPU models, memory channel configurations, drive endurance %, and clickable BCG links remain 100% functional.
- **Usage:** Check **"Generate obfuscated copies"** in the Web UI, supply `--obfuscate` in CLI, or click the **"Obfuscate report"** dynamic toggle in any standard HTML report header.

</details>

<details>
<summary><strong>Report Deliverables & Output Files</strong></summary>

Reports are saved to `~/Desktop/VCF-Scans/` (or your chosen `--output-dir`):

| File | Format | Description |
|:-----|:-------|:------------|
| `00_fleet_summary.html` | HTML | Consolidated fleet dashboard with health tiles, ToR matrix, and host table |
| `00_fleet_combined.html` | HTML | Fleet Hub combining fleet summary and all single-host sub-reports |
| `vsphere_vsan_report_<IP>.html` | HTML | Standalone individual server report with deep hardware telemetry |
| `00_fleet_summary.xlsx` | Excel | Multi-tab spreadsheet with formatted executive tables and raw data |
| `00_fleet_summary.csv` | CSV | Standardized flat CSV export for ingestion into data warehouses |
| `vcf_summary_<IP>.json` | JSON | Machine-readable structured hardware payload |
| `vcf_readiness_deliverables.zip` | ZIP | Self-contained, portable archive containing all reports and spreadsheets |

</details>



---

## 🔗 References & Credits

### Broadcom & VMware References
- **[KB 428874](https://knowledge.broadcom.com/external/article/428874)** — vSphere/VCF 9.x CPU Deprecated Mode Support Policy
- **[Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/)** — Live hardware search matrix
- **[vSAN HCL JSON](https://vvs.broadcom.com/service/vsan/all.json)** — Live vSAN drive certification dataset

### Switch Buffer & Silicon Research
- **[Michael Buraglio's Packet Buffer Reference](https://port-buffers.forwardingplane.net/)** ([GitHub: buraglio/port-buffers](https://github.com/buraglio/port-buffers))
- **[Jim Warner's UCSC Packet Buffer Research](https://people.ucsc.edu/~warner/buffer-wuz.html)** ([ASIC Buffer History](https://people.ucsc.edu/~warner/Bufs/buf-hist.html))

### Project Acknowledgements
- **Phong Le** — For answering 40,000 hardware HCL questions.
- **Onur Yuzseven & Brock Peterson** — For the vCommunity plugins and VMware Aria/VCF Operations guidance.
- **Spiceworks Community** — For community hardware discussions and insights on server repurposing.
- Built with [Clarity Design System](https://clarity.design/) design tokens (VMware/Broadcom, Apache-2.0 license).

---

## License

CA, Inc. License — see [LICENSE.md](LICENSE.md) and [NOTICE](NOTICE). For third-party components included in standalone distributions, see [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).