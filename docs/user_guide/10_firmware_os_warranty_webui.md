## 10. Firmware Alignment, Host OS, Warranty & Web UI Operations {#firmware-and-operations}

Provides operational reference documentation for driver/firmware alignment tracking, host operating system telemetry, server warranty lifecycle management, and Web UI / CLI operational usage.

---

### 10.1 Driver & Firmware Alignment Baselines {#firmware-driver-alignment}

The driver/firmware alignment engine cross-references installed peripheral firmware and hypervisor drivers against certified pairs published on the Broadcom Compatibility Guide (BCG):

| Alignment Column | Technical Definition & Evaluation Logic | Operational Impact | External Documentation |
|---|---|---|---|
| **Component Name** | Physical peripheral device (e.g. `Intel E810 25GbE 2P SFP28 Adapter`, `Broadcom BCM57414`, `Dell HBA355i`). | Identifies the physical I/O controller requiring firmware/driver coordination. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |
| **Installed Firmware** | Firmware / NVM image release currently running on the adapter. | Must align with certified releases; uncertified revisions cause kernel driver unload panics. | [vSphere Lifecycle Manager (vLCM)](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-lifecycle-manager/index.html) |
| **ESXi Driver Version** | Driver module version active in the hypervisor kernel (e.g. `icen v1.13.2.0`, `bnxtnet v228.0.134.0`). | Validates that hypervisor drivers match firmware registers. | [Broadcom VCG — IO Devices](https://compatibilityguide.broadcom.com/search?program=io) |
| **Certified HCL Baseline**| Official certified firmware and driver combination approved for VMware vSphere 9.1. | Required baseline for enterprise Broadcom support and vSphere Lifecycle Manager (vLCM) baselines. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |
| **Alignment Verdict** | Status: `🟢 Compliant`, `▲ Update Recommended`, or `🔴 Incompatible Driver/FW`. | Highlights devices requiring firmware flashing or asynchronous driver VIB injection. | [vSphere ESXi Upgrade Guide](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-esxi-installation/index.html) |

---

### 10.2 Host Operating System Telemetry {#host-operating-system}

When servers run active hypervisors or staging operating systems, the tool extracts host telemetry via BMC agentless management:

| Operating System Metric | Discovered Telemetry & Evaluation Logic | Operational Purpose |
|---|---|---|
| **Operating System** | Operating system release string (e.g. `VMware ESXi 8.0.3`, `Red Hat Enterprise Linux 9.2`, `Windows Server 2022`). | Identifies the existing operating environment prior to VCF 9.1 hypervisor reimaging. |
| **Kernel Release** | Hypervisor or OS kernel version string (e.g. `24022510` for ESXi 8.0 Update 3). | Informs in-place upgrade pathways vs clean greenfield reimaging requirements. |
| **Host FQDN & Domain** | Fully qualified domain name and DNS search domain configured in the host OS. | Facilitates automated host DNS record validation and vCenter inventory reconciliation. |

---

### 10.3 Hardware Warranty & OEM Lifecycle Tracking {#hardware-warranty-lifecycle}

Server chassis serial numbers are cross-referenced with OEM contract databases to forecast hardware end-of-support (EOSL):

| Lifecycle Metric | Definition & Evaluation Logic | Cluster Planning Value |
|---|---|---|
| **Serial / Service Tag** | Hardware chassis serial number (e.g. `SN-A9030E`, `CZ2938190A`). | Master identifier for OEM hardware maintenance contracts and warranty lookups. |
| **Asset Tag** | Internal enterprise asset management tag. | Reconciles assessed server nodes with enterprise financial depreciation ledgers. |
| **Warranty Start Date** | Original factory ship and warranty inception date. | Establishes the physical hardware operational age. |
| **Warranty Expiration** | Current contract expiration date. Highlights if expired (`🔴 Expired`) or expiring within 90 days (`▲ Expiring Soon`). | Servers with expired maintenance contracts risk extended downtime during hardware failures. |
| **Service Level Agreement** | Active maintenance SLA (e.g. `ProSupport Plus 4-Hour Onsite Mission Critical`, `HPE Pointnext Complete Care`). | Confirms whether replacement parts can be dispatched within 4 hours for production clusters. |

---

### 10.4 Web UI & CLI Operational Reference {#web-ui-and-cli-operations}

The assessment tool provides both an interactive local browser interface and a scripted command-line interface.

#### 1. Launching the Interfaces
```bash
# Launch interactive local Web UI (default: http://127.0.0.1:7182)
python3 vcfr_web.py

# Or run non-interactive CLI scan
python3 vcfr_collector.py --targets "192.0.2.10-20" --username readonly_audit
```

#### 2. Target Specification Formats
The tool supports flexible IP and hostname inputs:
- **Single Host:** `192.0.2.10` or `esxi-01.rainpole.net`
- **IP Range:** `192.0.2.10-30`
- **CIDR Subnet:** `192.0.2.0/24`
- **Target File:** Plain-text file containing one target per line (`--targets targets.txt`).

#### 3. Scan Modes Comparison
| Scan Profile | Average Duration | Telemetry Depth | When to Use |
|---|---|---|---|
| **Quick Scan (`--quick`)** | **~5 seconds / host** | CPU, RAM, BIOS settings, SEL alarms, and BMC firmware only. | Fast preliminary inventory; skips storage drives, NICs, and telemetry. |
| **Lean Scan (`--lean`)** | **~15–30 seconds / host** | Complete hardware inventory: drive models, NIC ports, and vSAN ESA readiness. | High-speed complete assessment; skips heavy SMART wear counters and thermal telemetry. |
| **Full Scan (Default)** | **~60–90 seconds / host** | Exhaustive hardware audit: 20 OCP NVMe SMART wear metrics, thermal sensors, and GPU topology. | **Recommended:** Complete assessment for production VCF 9.1 and vSAN ESA qualification. |

#### 4. Enterprise Security, Discovery & Execution Flags
- **Encrypted Credential Vault (`--vault [PATH]`, `--vault-passphrase-env VAR`)**: Resolves per-host and per-subnet BMC credentials from an encrypted local vault file (`~/.vcf-readiness/credentials.vault`). Protects environments with heterogeneous BMC credentials without plaintext CSVs.
- **High-Speed Discovery & LJF Scheduling (`--two-pass`)**: Executes Pass 1 lightweight probe (3s timeout) to pre-qualify CPU architectures and count storage drives, then dispatches heavy 24-drive storage nodes at $t=0$ using Longest-Job-First (LJF) scheduling to eliminate tail stragglers.
- **Fast Discovery Sweep (`--discover-only`)**: Performs only Pass 1 network discovery across candidate subnets, prints an active target summary table, writes `data/discovery_cache.json`, and exits without running full deep audits.
- **Discovery Cache Ingestion (`--discovery-cache <path>`)**: Loads active BMC targets directly from a prior discovery cache JSON file, skipping network scanning across dark/unoccupied IP ranges.
- **Inactive Target Pruning (`--prune-inactive`)**: Automatically filters out dark or unreachable IPs discovered during Pass 1 before launching Phase 2 deep audits.
- **Dynamic Resource Throttle Override (`--no-auto-throttle`)**: Disables automatic outer worker stepdown triggered by host CPU load average (>1.5× cores) or memory pressure (<10% available RAM).
- **Legacy BMC TLS Handshakes (`--legacy-tls`, `--tls-min-version {1.0,1.1,1.2,1.3}`)**: Relaxes OpenSSL security level to `DEFAULT:@SECLEVEL=1` and allows older TLS protocols for legacy BMCs (Dell 13G iDRAC 8, Supermicro X10) that fail OpenSSL 3 handshakes.
- **Deep OEM Hypermedia Crawl (`--oem`, `--crawl`)**: Activates deep read-only Redfish crawling, catalogs non-GET action endpoints across 11 functional domains without executing them, and exports DMTF-compliant mockup ZIP archives (`redfish_mockup_<HOST>.zip`).
- **Resilient Scanning (`--allow-partial`)**: Harvests valid subsystem telemetry even if non-critical endpoints time out, avoiding completely aborted host audits.
- **Excel & Tabular Exporters (`--excel`, `--no-excel`, `--csv-export`)**: Multi-tab Excel workbook export is enabled by default (`--excel`). Pass `--no-excel` to disable. Pass `--csv-export` to generate standardized CSV tables (`00_fleet_summary.csv`, `00_drives_inventory.csv`, etc.).
- **BMC TLS Certificate Verification (`--verify-ssl`)**: Enforces strict TLS validation against the OS certificate store.
- **Custom Enterprise CA Bundle (`--ca-bundle <path>`)**: Supplies internal enterprise root/intermediate CA bundles for TLS authentication.
- **Forward-Confirmed Reverse DNS (`--dns-lookup`)**: Validates BMC Subject Alternative Names (SANs) against DNS PTR/A records to prevent spoofing.
- **Private Subnet Restriction (`--restrict-private-targets`)**: Restricts scanning strictly to RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or loopback.
- **Dark-Site HCL Bundle Creation (`--bundle-hcl <path>`)**: Packages live Broadcom vSAN HCL datasets into an offline dark-site zip bundle.
- **Dark-Site HCL Import (`--import-hcl <path>`)**: Imports pre-packaged HCL datasets into air-gapped datacenter workstations.
- **Offline Summary Rendering & Multi-Scan Fleet Assemble (`--from-summary <path>`)**: Re-renders HTML reports instantly from saved JSON summaries or assembles entire library directories containing multiple dropped scan folders/zips without live BMC connectivity. Supports `--site <name>` tagging and `--assemble-only` execution.

#### 5. Data Obfuscation & PII Anonymization (`--obfuscate`)
When sharing reports with external hardware vendors or Broadcom support, passing `--obfuscate` activates irreversible cryptographic sanitization:
- **Salted SHA-256 Hashing:** All hostnames, serial numbers, service tags, asset tags, MAC addresses, and WWPNs are replaced with deterministic hash tokens (e.g. `SN-A9030E`, `Host-12`).
- **RFC 5737 TEST-NET Mapping:** Real IP addresses are remapped to non-routable documentation subnets (`192.0.2.x`).
- **Log Scrubbing:** Raw Redfish JSON responses and System Event Log entries are sanitized to scrub private domain names and internal host references.

#### 6. Export Deliverables Catalog
| Generated File | Format & Contents | Target Audience |
|---|---|---|
| `vsphere_vsan_report_<IP>.html` | Self-contained single-host assessment report with BCG deep links. | Field Technicians & Systems Engineers. |
| `fleet_summary.html` | Fleet-wide overview dashboard with health tiles and host summary table. | Infrastructure Managers & Architects. |
| `fleet_combined.html` / `00_fleet_combined.html` | Fleet Hub HTML dashboard embedding all host reports (single inline file for &le; 64 hosts, sidecar pack with lazy on-demand frames for &gt; 64 hosts up to 3,000+ hosts without 256-host cliff). | Enterprise Architects & IT Leadership. |
| `MANIFEST.json` | Scan execution metadata manifest (`tool_version`, `scanned_at`, `host_count`, `collector_id`, `site`, `scan_profile`, `obfuscated`) for library discovery and remote drop ingestion. | Automation Engineers & Orchestrators. |
| `vcf_readiness_<timestamp>.xlsx` | Multi-tab Excel workbook: Summary, Storage, NICs, GPUs, Security, Failed Hosts. | IT Procurement & Capacity Planners. |
| `00_fleet_summary.csv` | Standardized tabular CSV with 40+ schema fields for automated pipeline ingestion. | Infrastructure Automation & CMDB Leads. |
| `00_drives_inventory.csv` | Granular physical storage drive inventory across all assessed nodes. | Storage Engineers & Hardware Vendors. |
| `00_nics_inventory.csv` | Network adapter, port, link speed, and ToR switch neighbor inventory. | Network Architects & Fabric Engineers. |
| `00_gpus_inventory.csv` | Hardware accelerator and GPU inventory across all nodes. | AI Infrastructure & Data Science Leads. |
| `00_failed_hosts.csv` | Preflight diagnostics, unreachable BMC IPs, and authentication errors. | Operations & Network Support Teams. |

---

### 10.5 Multi-Scan Fleet Library & Universal Drop Ingestion {#fleet-library-assembly}

The Multi-Scan Fleet Library architecture (`vcf_hci/fleet_library.py`) enables distributed data collection across enterprise datacenter fabrics without requiring direct central-to-BMC network connectivity:

```
┌────────────────────────────────────────────────────────────────────────┐
│ Remote Collector Workers (edge nodes, automation agents, cron runners) │
│ • Worker A (Denver DC): scans 250 BMCs → writes Denver_20260921.zip    │
│ • Worker B (Dallas DC): scans 500 BMCs → writes Dallas_20260921.zip    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Drop or HTTP POST /api/fleet/ingest
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Central Fleet Library Directory (e.g. ~/Desktop/VCF-Scans/)           │
│ • Reads MANIFEST.json metadata from each scan directory/zip archive    │
│ • Zero credentials or plaintext secrets stored in manifests            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Multi-Scan Assembly (assemble_fleet)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Consolidated Fleet Deliverables (Single Fleet Hub + Single Workbook)   │
│ • Deterministic Deduplication: System UUID → Serial+Model → BMC IP     │
│ • Provenance Stamping: source_scan, site tag, collector_id retained    │
│ • Unified Excel workbook, CSV suite, Fleet Summary & Fleet Hub HTML    │
└────────────────────────────────────────────────────────────────────────┘
```

#### Universal Drop Manifest (`MANIFEST.json`)
Every scan directory and exported ZIP archive automatically generates a structured `MANIFEST.json` containing execution provenance:
```json
{
  "manifest_version": "1.0.0",
  "tool_version": "9.6.0",
  "scanned_at": "2026-09-21T14:30:00Z",
  "host_count": 214,
  "collector_id": "denver-jump-01",
  "site": "Denver-DC1",
  "scan_profile": "readiness-full",
  "obfuscated": false
}
```

#### Assembly & Deduplication Logic
When invoking `--from-summary` against a directory containing multiple scan folders or ZIP archives, `assemble_fleet()` resolves overlapping host records using a strict deterministic priority:
1. **Redfish System UUID:** Primary immutable physical machine identifier.
2. **Serial Number + Chassis Model:** Secondary hardware identity for platforms omitting UUID.
3. **BMC IP Address / Hostname:** Tertiary network identifier.
4. **Timestamp Winner:** When duplicate host identities are encountered across scans, the record with the most recent `scanned_at` timestamp wins, while earlier scan IDs are appended to `previous_scan_ids`.

#### CLI & Web UI Operational Usage
```bash
# Point CLI at a library parent folder containing multiple dropped scans:
python3 vcfr_collector.py --from-summary ~/Desktop/VCF-Scans

# Assemble consolidated fleet deliverables without re-rendering individual host reports:
python3 vcfr_collector.py --from-summary ~/Desktop/VCF-Scans --assemble-only --site "Consolidated-Cluster"
```
In the Web UI:
- Click **"Open Fleet Library"** in the top navigation or Discovery card.
- Inspect discovered scan drops, host counts, execution dates, and site tags.
- Select scans to assemble and click **"Assemble Fleet Deliverables"**.
- Single-host reports are rendered lazily on demand, and an optional **"Pre-render All Reports"** action bakes all HTML files for offline portability.

---

### 10.6 Optional Encrypted Local Credential Vault {#credential-vault-operations}

For enterprise environments where servers utilize different BMC passwords across server generations, clusters, or physical racks, the tool provides an optional, off-by-default credential vault (`vcf_hci/vault/`):

- **Pure Python Standard Library Cryptography:** Uses PBKDF2-HMAC-SHA256 (600,000 iterations, 16-byte random salt), HMAC-SHA256 counter-mode keystream, and HMAC-SHA256 Encrypt-then-MAC with constant-time verification. Zero external cryptography packages required.
- **File Security:** Saved at `~/.vcf-readiness/credentials.vault` with owner-only permissions (`0600`; Windows ACL restricted to user SID).
- **Matching Precedence:** `exact` host/IP/FQDN &rarr; `cidr` subnet (longest prefix wins, `/28` beats `/24`) &rarr; `default` fallback.
- **Zero Browser Exposure:** Credentials are resolved strictly inside the backend server process; passwords are never sent to the browser or returned in API responses.

#### CLI Vault Management (`python -m vcf_hci.vault`)
```bash
# 1. Initialize vault with a passphrase (minimum 12 characters)
python -m vcf_hci.vault init

# 2. Bulk import from CSV (then safely delete the plaintext CSV file)
python -m vcf_hci.vault import-csv credentials.csv
rm credentials.csv

# 3. Add or update individual entries
python -m vcf_hci.vault add --target 192.0.2.0/24 --username admin

# 4. List stored entries (passwords are NEVER displayed)
python -m vcf_hci.vault list

# 5. Execute assessment scan using the vault
python3 vcfr_collector.py --targets 192.0.2.0/24 --vault
```

#### Web UI Credential Vault Integration
- Expand the **🔐 Encrypted Credential Vault** accordion under the Credentials card.
- Enter your passphrase to **Unlock Vault** (or **Create Vault** if first time).
- Add individual targets or use **Import CSV** (paste text or choose file with *Skip invalid rows* protection).
- Check the **"Use encrypted credential vault for this scan"** box.
- The vault coverage indicator previews how many target hosts match `exact`, `cidr`, or `default` credentials, highlighting unmatched IPs.
- Vault auto-locks after 60 minutes of inactivity and upon server shutdown.

