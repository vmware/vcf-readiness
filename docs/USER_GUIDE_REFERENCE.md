# VCF / vSphere 9.1 HCI Readiness Assessment Tool — User Guide & Reference

> **Target Audience:** VMware Sales Engineers (SEs), Solution Architects, Infrastructure Leads, and Cybersecurity Auditors evaluating server hardware for VMware Cloud Foundation (VCF) 9.1 and vSAN Express Storage Architecture (ESA).

---

## Master Table of Contents

- [1. Fleet Dashboard & Summary Tab](#fleet-summary-tab)
  - [1.1 Fleet Health Tiles](#fleet-health-tiles)
  - [1.2 Degraded Redfish BMC Service / Slow Response Alert](#slow-bmc-alert)
  - [1.3 Per-Host Assessment Table](#fleet-per-host-table)
  - [1.4 Top-of-Rack (ToR) Switch & Fabric Matrix](#tor-switch-matrix)
  - [1.5 Fleet Hub Architecture & Adaptive Scale Modes](#fleet-hub-scale-modes)
- [2. Detailed Inventory Panel](#detailed-inventory-panel)
  - [2.1 Hosts Subtab (SE Decision Matrix)](#inv-hosts)
  - [2.2 Drives Subtab (Storage Telemetry)](#inv-drives)
  - [2.3 NICs Subtab (Network Interface Inventory)](#inv-nics)
  - [2.4 BIOS Settings Subtab (Firmware & Execution Baseline)](#inv-bios)
  - [2.5 Health Alarms Subtab (Subsystem Telemetry)](#inv-alarms)
  - [2.6 Security Subtab (Out-of-Band & Platform Hardening)](#inv-security)
- [3. Single-Host Assessment Report Overview](#single-host-report)
  - [3.1 Host Identity Header & Status Banners](#host-header-and-banners)
  - [3.2 Executive Summary Cards](#executive-summary-cards)
  - [3.3 Actionable Alert Rollup Engine](#alert-rollup)
- [4. Compute & CPU Architecture Deep-Dive](#compute-and-cpu-deep-dive)
  - [4.1 Processor Architecture & Cache Hierarchy](#processor-architecture)
  - [4.2 Spectre / Meltdown CVE Microcode Tiers](#cve-microcode-tiers)
  - [4.3 Memory Subsystem & Interleaving Topology](#memory-channel-interleaving)
- [5. Storage Subsystem & vSAN Qualification](#storage-subsystem)
  - [5.1 vSAN ESA ReadyNode Profile Baselines](#vsan-esa-readynode-profiles)
  - [5.2 Storage Controllers & RAID Passthrough Blocker Logic](#storage-controllers)
  - [5.3 Physical Drive Inventory & Flash Wear Life](#physical-drives-table)
  - [5.4 Granular OCP NVMe SMART Telemetry](#nvme-smart-telemetry)
- [6. Network Interfaces & Top-of-Rack Discovery](#network-interfaces)
  - [6.1 Network Adapters & ESA 25 GbE Baseline](#network-adapters)
  - [6.2 Physical Ports & Link Speed Ratings](#network-ports-table)
  - [6.3 LLDP & Cisco CDP Switch Neighbor Discovery](#tor-switch-discovery)
  - [6.4 Fibre Channel Host Bus Adapters (FC HBAs)](#fibre-channel-hbas)
- [7. Expansion, Accelerators & System Health](#expansion-and-health)
  - [7.1 PCIe Expansion Slots & Lane Budget](#pcie-expansion-slots)
  - [7.2 GPU Accelerators & Private AI Readiness](#gpu-accelerators-private-ai)
  - [7.3 Power Supply Units & Redundancy](#power-supply-units)
  - [7.4 Thermal Sensor Matrix & Fan Telemetry](#thermal-sensor-matrix)
  - [7.5 System Event Log (SEL / IML Alarms)](#system-event-log)
- [8. BIOS & Platform Configuration](#bios-and-platform-configuration)
  - [8.1 BIOS Version Baselines & UEFI Boot Mode](#uefi-boot-mode)
  - [8.2 CPU Power Management Profiles](#cpu-power-management)
  - [8.3 Memory RAS Modes & OEM Population Guides](#memory-ras-modes)
  - [8.4 Intel Volume Management Device (Intel VMD) Pass-Through](#intel-vmd-passthrough)
  - [8.5 Virtualization & Platform Processor Flags](#platform-processor-flags)
- [9. Key Anchor: BMC Hardware Security Audit Findings](#bmc-hardware-security-audit-findings)
  - [9.1 Platform Cryptographic Security (TPM 2.0 & Secure Boot)](#platform-cryptographic-security)
  - [9.2 BMC Security Posture Rollup & Risk Ratings](#bmc-security-posture-rollup)
  - [9.3 Comprehensive 84-Control Security Audit Catalog](#bmc-84-control-catalog)
  - [9.4 OEM Security Hardening Guides & VCF Security Guidelines](#oem-security-hardening-guides)
  - [9.5 Practical Security Remediation Scripts & CLI Commands](#security-remediation-scripts)
- [10. Firmware Alignment, Host OS, Warranty & Web UI Operations](#firmware-and-operations)
  - [10.1 Driver & Firmware Alignment Baselines](#firmware-driver-alignment)
  - [10.2 Host Operating System Telemetry](#host-operating-system)
  - [10.3 Hardware Warranty & OEM Lifecycle Tracking](#hardware-warranty-lifecycle)
  - [10.4 Web UI & CLI Operational Reference](#web-ui-and-cli-operations)
  - [10.5 Multi-Scan Fleet Library & Universal Drop Ingestion](#fleet-library-assembly)
  - [10.6 Optional Encrypted Local Credential Vault](#credential-vault-operations)

---

## 1. Fleet Dashboard & Summary Tab {#fleet-summary-tab}

The **Fleet Summary** tab provides a consolidated executive dashboard summarizing hardware qualification, platform security, and network fabric discovery across all scanned servers in the datacenter.

---

### 1.1 Fleet Health Tiles {#fleet-health-tiles}

The high-level status tiles at the top of the Fleet Summary dashboard provide instant visibility into overall cluster repurposing potential and hardware health:

| Metric Tile | Description & Evaluation Logic | VCF 9.1 Readiness Significance | Documentation Link |
|---|---|---|---|
| **Total Hosts Assessed** | Total count of physical server nodes queried during the assessment run. | Establishes the baseline server pool available for cluster sizing and workload domain planning. | [VMware Cloud Foundation Architecture](https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html) |
| **vSAN ESA Ready Nodes** | Count of hosts satisfying all hardware criteria for vSAN Express Storage Architecture: &ge;2 direct-attached NVMe SSDs, no RAID or VMD blockers, and &ge;25 GbE networking. | Identifies servers capable of participating in high-performance vSAN ESA storage pools. | [vSAN ESA ReadyNode Guidance](https://core.vmware.com/resource/vmware-vsan-esa-readynode-hardware-guidance) |
| **vSAN OSA Compatible Nodes** | Count of hosts equipped with SAS/SATA SSDs attached to certified HBA controllers, suitable for legacy vSAN Original Storage Architecture. | Identifies nodes suitable for traditional vSAN OSA disk group configurations (1 cache SSD + capacity drives). | [vSAN OSA Planning Guide](https://docs.vmware.com/en/VMware-vSphere/8.0/vsan-planning/GUID-10C4D04C-7682-4E57-B2E2-817DC7D57C5A.html) |
| **Unsupported / Override Required CPUs** | Count of hosts with legacy processors (Intel Haswell/Broadwell or older marked Unsupported) or Intel Skylake-SP (marked Override Required). | Intel Skylake-SP requires CPU support override during install or upgrade ([KB 428874](https://knowledge.broadcom.com/external/article/428874)); older processors block ESXi 9.1 installation. | [Broadcom KB 428874](https://knowledge.broadcom.com/external/article/428874) |
| **TPM 2.0 Inactive / Missing** | Count of hosts lacking an activated TPM 2.0 cryptoprocessor in BIOS/UEFI. | TPM 2.0 is mandatory for VCF 9.1 ESXi Secure Boot, Host Attestation, and vSphere Native Key Provider. | [vSphere Security Guide — TPM 2.0](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-security/GUID-10F7022C-DBE0-4E80-9285-EB02CEF513A1.html) |
| **BMC Security Action Req** | Count of hosts where high-priority out-of-band management vulnerabilities were detected (e.g. default password, active Telnet, unencrypted IPMI over LAN). | Non-compliant BMC configurations violate enterprise security baselines and expose management networks to attack. | [VCF Security & Compliance Guidelines](https://github.com/vmware/vcf-security-and-compliance-guidelines) |
| **Hardware Faults / Alarms** | Count of hosts reporting active Critical or Warning events in System Event Logs (SEL), failing drive S.M.A.R.T. metrics, or degraded memory/thermal sensors. | Physical faults must be remediated or components replaced prior to commissioning nodes into production. | [vSphere Monitoring and Health](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-monitoring-and-performance/GUID-074EFB79-1C52-4742-89BE-44585B17B493.html) |
| **PSU Redundancy Degraded** | Count of hosts operating with a single power supply or where AC grid/power redundancy is degraded. | High availability clusters require full N+1 power supply redundancy to guarantee node uptime during rack power events. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |

---

### 1.2 Degraded Redfish BMC Service / Slow Response Alert {#slow-bmc-alert}

When an enterprise BMC experiences socket timeouts, response delays, or throttles Redfish worker threads during inventory collection, the dashboard displays a collapsible amber alert:

- **Trigger Condition:** Scan duration &ge;60 seconds, HTTP response latency spikes, or adaptive thread clamping triggered during Redfish GET requests.
- **Root Causes:**
  - Outdated BMC firmware containing known Redfish daemon memory leaks or resource deadlocks.
  - Transient web server thread exhaustion inside the BMC embedded management subsystem.
  - Network latency, packet loss, or firewall inspection overhead between the scanning workstation and the BMC IP.
- **Recommended Remediation:**
  - **Dell iDRAC:** Upgrade iDRAC9 firmware to current baseline and execute a soft reset: `racadm racreset`.
  - **HPE iLO:** Upgrade iLO 5/6 firmware and reset the management processor: `ilorest reset`.
  - **Lenovo XCC:** Perform an out-of-band reset using OneCLI: `onecli misc reset`.
  - **Supermicro / Generic BMC:** Execute a cold reset over IPMI: `ipmitool bmc reset cold`.
  - **Quanta / QCT BMC:** Execute a cold reset over IPMI: `ipmitool -I lanplus -H <bmc_ip> -U <user> -P <pass> mc reset cold`.
  - **GIGABYTE BMC (AMI MegaRAC):** Execute a cold reset over IPMI: `ipmitool -I lanplus -H <bmc_ip> -U <user> -P <pass> mc reset cold`.

---

### 1.3 Per-Host Assessment Table {#fleet-per-host-table}

The central assessment table presents a dense multi-node compatibility matrix. Solution architects use this table to triage server repurposing eligibility at a glance.

#### Table Controls & Filtering
- **OEM Filter:** Filters the fleet table dynamically by hardware manufacturer (Dell, HPE, Lenovo, Cisco, Supermicro, Quanta, GIGABYTE, Intel).
- **Hide Unsupported Hosts:** Dynamically hides legacy systems containing pre-Skylake processors to focus cluster planning exclusively on viable hardware candidates.
- **Table Pagination Controls:** Client-side pager with configurable page sizes (25, 50, 100, or All rows per page) ensures responsive rendering even when auditing thousands of physical servers.
- **Initial Paint Row Capping:** For fleets exceeding 500 hosts, the initial HTML render caps rendered table rows to 500 to guarantee sub-second browser paint times, while the full fleet dataset is preserved in the compact `#fleet-inv-data` JSON island and filterable without page reloads.
- **Searchable Host Picker:** In large-scale fleet reports (Sidecar mode), static host navigation buttons are replaced by a fast filterable dropdown picker (`<input>` + `<select>`) to jump instantly to any server by IP, hostname, or model.

#### Field-by-Field Reference
| Column Header | Description & Evaluation Logic | VCF 9.1 Readiness Verdict | External Reference |
|---|---|---|---|
| **Host / IP** | Host system hostname and out-of-band management BMC IP address. Clicking navigates directly to that server's detailed single-host report. | Identifies the physical node in the management network. | [vSphere Networking Basics](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-networking/GUID-A9648937-2E89-4DF5-BF7D-F3C6DDAE3C98.html) |
| **Model** | Server manufacturer and chassis model. Displays a warning badge if slow BMC response times were encountered. | Hardware model must be listed as certified on the Broadcom Compatibility Guide (BCG) for vSphere 9.x. | [Broadcom Compatibility Guide (Systems)](https://compatibilityguide.broadcom.com/search?program=server) |
| **CPU Support** | Processor family and compatibility tier: Green (`Supported`), Yellow (`Override Required`), or Red (`Unsupported`). | Intel Cascade Lake/Ice Lake/Sapphire Rapids/Emerald Rapids and AMD EPYC 7002/7003/8004/9004 are supported; Skylake-SP requires CPU support override. | [Broadcom KB 428874](https://knowledge.broadcom.com/external/article/428874) |
| **TPM 2.0** | Cryptographic security status: Green (`Configured`), Amber (`TPM 1.2`), or Red (`Missing/Disabled`). | TPM 2.0 chip enabled in UEFI mode is required for host attestation and credential security. | [vSphere TPM 2.0 Requirements](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-security/GUID-10F7022C-DBE0-4E80-9285-EB02CEF513A1.html) |
| **BMC Security** | Out-of-band security compliance score: Green (`Met`), Amber (`Partial`), or Red (`Action Req`). Clicking navigates to the host security tab. | BMC security audit evaluates 84 controls against the VCF Security Configuration Guide baseline. | [VCF Security Guidelines](https://github.com/vmware/vcf-security-and-compliance-guidelines) |
| **vSAN Tier** | Storage tier readiness: Green (`ESA Ready`), Yellow (`OSA Compatible`), or Red (`None/Ineligible`). | Indicates whether the physical storage configuration qualifies for vSAN ESA, vSAN OSA, or requires hardware changes. | [vSAN Hardware Guidance](https://core.vmware.com/resource/vmware-vsan-esa-readynode-hardware-guidance) |
| **PSU** | Power supply operational status: Green (`Redundant`) or Yellow (`Single/Degraded`). | Dual redundant power supplies connected to independent feeds are required for enterprise production clusters. | [vSphere Resiliency Best Practices](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-availability/GUID-D812833E-67A2-4D30-B147-380F7BE98E9B.html) |
| **FC HBAs** | Count and models of installed Fibre Channel Host Bus Adapters (e.g. `2 HBA`), or `—` if none installed. | Identifies nodes capable of attaching to existing SAN storage arrays via Fibre Channel VMFS datastores. | [Broadcom Compatibility Guide (IO)](https://compatibilityguide.broadcom.com/search?program=io) |
| **GPUs** | Count and models of detected PCIe GPU accelerators (e.g. `2 GPU`), or `—` if none installed. | Identifies hardware accelerators capable of supporting VMware Private AI Foundation workloads. | [VMware Private AI Foundation](https://docs.vmware.com/en/VMware-Cloud-Foundation/services/vcf-private-ai-deployment/GUID-A934E26F-D2E4-42B1-8C1A-2C3C58B3A829.html) |

---

### 1.4 Top-of-Rack (ToR) Switch & Fabric Matrix {#tor-switch-matrix}

The ToR Switch & Fabric Matrix automatically correlates Layer 2 network switch adjacency across all physical host ports using Link Layer Discovery Protocol (LLDP) and Cisco Discovery Protocol (CDP).

| Matrix Field | Description & Evaluation Logic | Network Planning Significance | Documentation Link |
|---|---|---|---|
| **Switch Hostname** | Upstream physical switch system name or FQDN discovered from the switch management plane. | Identifies which Top-of-Rack switch pair services each host in the rack. | [vSphere VDS LLDP Configuration](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-networking/GUID-A9648937-2E89-4DF5-BF7D-F3C6DDAE3C98.html) |
| **Switch Port** | Interface identifier on the upstream switch (e.g. `Ethernet1/12`, `TenGigE0/0/1`). | Verifies physical patch cable wiring against datacenter port interconnect schedules. | [VMware vSphere Networking Guide](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-networking/index.html) |
| **Protocol** | Layer 2 discovery protocol utilized (`LLDP`, `Cisco CDP`, or OEM vendor MIB). | Confirms standard discovery protocol operation across multi-vendor switch environments. | [IEEE 802.1AB LLDP Standard](https://standards.ieee.org/) |
| **Host Port** | Physical NIC port identifier on the server (e.g. `vmnic0`, `Port 1`, `Slot 1 Port 2`). | Maps ESXi uplink adapters to corresponding switch port connections. | [vSAN ESA Network Requirements](https://core.vmware.com/resource/vsan-esa-networking) |
| **Speed** | Current negotiated link bandwidth (e.g. `25 Gbps`, `100 Gbps`, `10 Gbps`). | vSAN ESA requires minimum 25 GbE dedicated or shared bandwidth per host uplink. | [vSAN ESA ReadyNode Networking](https://core.vmware.com/resource/vsan-esa-networking) |
| **Port VLAN** | Native VLAN ID untagged or tagged on the switch interface. | Validates that host uplinks are connected to trunk ports permitting VCF management, vSAN, and overlay VLANs. | [VCF Network Architecture](https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html) |
| **MTU Size** | Configured maximum transmission unit size (bytes). Highlights if set to standard `1500` vs jumbo `9000`. | Jumbo frames (MTU 9000) are strongly recommended for vSAN ESA and Geneve overlay traffic to reduce CPU overhead. | [vSAN Jumbo Frames Best Practices](https://kb.vmware.com/s/article/1007654) |

---

### 1.5 Fleet Hub Architecture & Adaptive Scale Modes {#fleet-hub-scale-modes}

The Combined Fleet Report (`fleet_combined.html` / `00_fleet_combined.html`) acts as the consolidated Fleet Hub, integrating the executive dashboard, Top-of-Rack switch matrix, SE Decision Matrix, granular inventory tabs, and full single-host assessment reports into a unified deliverable.

To eliminate historical browser memory crashes and the legacy 256-host ceiling (`COMBINED_HTML_MAX_HOSTS = 4096`), the reporting engine dynamically adapts its rendering architecture based on fleet size:

| Scale Mode | Fleet Threshold | Host Report Embedding Strategy | Excel & Asset Storage | Packaging & Distribution Requirement |
|---|---|---|---|---|
| **`inline` Mode** | **&le; 64 hosts** | Single consolidated `.html` file. Host reports are embedded within lazy `data-srcdoc` iframes (not parsed by the browser at load time, conserving RAM). | Multi-tab `.xlsx` workbook is embedded directly as Base64 for instant offline downloads. | **Single-file portable:** Entire report is self-contained. The single HTML file can be moved or emailed independently. |
| **`sidecar` Mode** | **&gt; 64 hosts up to 3,000+ hosts** | Sibling report directory pack. Single-host reports are rendered to `reports/vsphere_vsan_report_<IP>.html` on disk and mounted dynamically via `data-src` iframes only when navigated to. | Sibling file links (`./vcf_readiness_<timestamp>.xlsx`) replace Base64 embedding to prevent DOM bloat. | **Directory pack portable:** `00_fleet_combined.html` relies on the companion `reports/` folder and `.xlsx` file. Distribute as a ZIP archive. |

#### Architectural Pillars for 3,000+ Host Scale
1. **Dynamic Iframe LRU Caching:** In Sidecar mode, the browser UI maintains an in-memory Least Recently Used (LRU) cache capping active mounted iframes to **3 concurrent live frames**. When opening a 4th host, the oldest inactive iframe DOM subtree is unmounted, keeping browser memory flat (~150–250 MB) even across thousands of nodes.
2. **Compact `#fleet-inv-data` JSON Island:** Rather than injecting tens of thousands of duplicate HTML nodes into the DOM, detailed inventory, drive telemetry, and network port metrics are stored in a compact JSON island.
3. **Searchable Host Picker:** Replaces thousands of static tab buttons with a responsive searchable dropdown input, enabling instant keyboard filtering by hostname, IP address, serial number, or server model.
4. **Critical Distribution Rule for Field SEs:**
   > ⚠️ **IMPORTANT PACKAGING RULE:** When delivering reports generated in **Sidecar mode** (&gt;64 hosts), **do not email `00_fleet_combined.html` by itself**. The iframes dynamically load `reports/vsphere_vsan_report_<IP>.html` relative to the hub. Always zip the entire output folder (or use the Web UI "Download ZIP" action) so that `00_fleet_combined.html`, `reports/`, and the `.xlsx` workbook remain co-located.

---

## 2. Detailed Inventory Panel {#detailed-inventory-panel}

The **Detailed Inventory** panel in combined fleet reports provides a dense, multi-dimensional view of all assessed server hardware across your datacenter. It aggregates physical hardware inventory, compatibility verdicts against VMware Cloud Foundation 9.1 standards, Broadcom Compatibility Guide (BCG) certified baselines, and out-of-band security posture.

The Detailed Inventory is divided into six specialized subpanes:
1. **Hosts:** SE Decision Matrix summarizing host compute, storage qualification, network readiness, memory interleaving, and platform security.
2. **Drives:** Granular storage drive inventory with controller topology, endurance life percentage, protocol classification, and certified firmware tracking.
3. **NICs:** Network interface controller port inventory with speed capabilities, link connection states, MAC addresses, and certified firmware levels.
4. **BIOS Settings:** System firmware configurations including CPU power profiles, memory RAS modes, Intel VMD settings, boot modes, and Spectre/CVE microcode tiers.
5. **Health Alarms:** Active hardware alarms aggregated from System Event Logs (SEL), drive S.M.A.R.T. telemetry, power supply redundancy, thermal sensors, and memory ECC counters.
6. **Security:** Out-of-band management and host platform hardening including TPM 2.0, Secure Boot, BMC firmware baselines, CVE microcode tiers, Hyperthreading posture, NTP/time drift, DNS configuration, and BMC hardening.

---

### 2.1 Hosts Subtab (SE Decision Matrix) {#inv-hosts}

The Hosts subtab provides the primary decision matrix utilized by Solution Architects to determine cluster repurposing qualification, hardware upgrade requirements, and ReadyNode sizing.

| Column Header | Description & Evaluation Logic | VCF 9.1 Readiness Criteria | External Documentation |
|---|---|---|---|
| **Host** | Host system hostname and out-of-band management BMC IP address. Clicking any row navigates directly to that host's comprehensive single-host report. | Identifies the physical node in the datacenter fabric. | [vSphere Documentation](https://docs.vmware.com/en/VMware-vSphere/index.html) |
| **Model** | Server hardware manufacturer (Dell, HPE, Supermicro, Cisco, Lenovo, Intel) and normalized chassis model name. | Hardware platform must be certified on the Broadcom Compatibility Guide for vSphere 9.x. | [Broadcom VCG — Systems](https://compatibilityguide.broadcom.com/search?program=server) |
| **CPU** | Processor model name, socket count, and VCF 9.1 architectural tier.<br>• **Supported (Green):** Intel Cascade Lake/Ice Lake/Sapphire Rapids/Emerald Rapids/Granite Rapids, AMD EPYC 7002/7003/8004/9004.<br>• **Supported (Override Required) (Yellow):** Intel Skylake-SP (supported in VCF 9.x per KB 428874; installation or upgrade requires CPU override).<br>• **Unsupported (Red):** Intel Haswell/Broadwell (v3/v4) or older architectures. | Supported CPU architecture required for VCF 9.1 cluster deployment. | [Broadcom KB 428874](https://knowledge.broadcom.com/external/article/428874) |
| **Host OS** | Installed operating system or VMware ESXi hypervisor release version and vendor build number.<br>• **Supported (Standard):** Active supported release.<br>• **EOL (Red):** End of General Support reached (e.g. ESXi 7.0 reached EOL in April 2025; upgrade to vSphere 8.x/9.x required).<br>• **— Not Reported:** OS agent (Dell iSM or HPE AMS) not running. | Identifies operating system lifecycle and migration requirements for VCF 9.1 repurposing. | [Broadcom Product Lifecycle](https://support.broadcom.com) |
| **ESA Disks** | Direct-attached NVMe storage capacity bucket breakdown and self-contained storage qualification status (independent of network speed).<br>• **✓ Storage Qualified (Green):** &ge;2 direct-attached NVMe SSDs without RAID or VMD blockers.<br>• **✓ Storage Qualified (SW RAID) (Green):** &ge;2 direct-attached NVMe SSDs with host software RAID detected (requires BIOS bypass to AHCI / Non-RAID).<br>• **✗ Behind RAID (Red):** NVMe drives attached to HW RAID or Tri-Mode controller (direct PCIe pass-through required).<br>• **✗ VMD Enabled (Red):** Intel VMD enabled in BIOS (must be disabled for native NVMe pass-through).<br>• **▲ OSA (SAS/SATA) (Amber):** SAS/SATA drives detected without direct NVMe SSDs.<br>• **— Insufficient (Muted):** &lt;2 direct NVMe SSDs detected. | &ge;2 direct NVMe SSDs required for vSAN ESA storage tier. | [Broadcom KB 89498](https://kb.vmware.com/s/article/89498) |
| **ESA Tier** | Dedicated vSAN ESA ReadyNode profile qualification evaluating holistic hardware criteria (NVMe drive count & capacity, RAM, CPU cores, and NIC speeds).<br>• **✓ ESA-L (Large) (Green):** &ge;4 Direct NVMe SSDs, &ge;512 GB RAM, &ge;48 CPU cores, &ge;25 GbE NIC.<br>• **✓ ESA-M (Medium) (Green):** &ge;2 Direct NVMe SSDs, &ge;256 GB RAM, &ge;32 CPU cores, &ge;25 GbE NIC.<br>• **✓ ESA-S (Small) (Green):** &ge;2 Direct NVMe SSDs, &ge;128 GB RAM, &ge;16 CPU cores, &ge;25 GbE NIC.<br>• **✓ ESA-XS (Edge) (Green):** &ge;2 Direct NVMe SSDs, &ge;64 GB RAM, &ge;16 CPU cores, &ge;10/25 GbE NIC.<br>• **▲ Needs 25G NIC (Amber):** Meets ESA storage and compute criteria, but NIC is &lt;25 GbE (upgrade required).<br>• **✗ Blocked (Red):** Ineligible due to HW RAID, Tri-Mode, or Intel VMD.<br>• **— Ineligible (Muted):** Insufficient drives. | Holistic profile qualification matching VMware vSAN ESA ReadyNode specifications. | [vSAN ESA ReadyNode Profiles](https://core.vmware.com/resource/vmware-vsan-esa-readynode-hardware-guidance) |
| **NICs** | Network adapter summary with selective down-port highlighting and 25 GbE baseline compliance. Active &ge;25 GbE links are highlighted in green (`2×25G↑`), while down ports are selectively highlighted in red (`2×25G↓`). Hover tooltips detail aggregate port count and link states. | Minimum 25 GbE network interfaces required for vSAN ESA clusters. | [vSAN ESA Networking Guide](https://core.vmware.com/resource/vsan-esa-networking) |
| **FC HBA** | Optional column displayed when Fibre Channel Host Bus Adapters are detected in the fleet. Displays detected HBA model and port count. | Identifies external SAN / VMFS storage integration readiness. | [Broadcom VCG — IO Devices](https://compatibilityguide.broadcom.com/search?program=io) |
| **RAM** | Total installed system RAM in GB, populated DIMM slot count, and memory channel interleaving efficiency rating. | Memory must meet workload domain capacity sizing and balanced channel interleaving rules. | [vSphere Performance Best Practices](https://core.vmware.com/resource/vsphere-performance-best-practices) |
| **TPM** | Trusted Platform Module presence and activation status.<br>• **✓ (Green):** TPM 2.0 enabled and active.<br>• **✗ (Red):** TPM absent, disabled, or legacy TPM 1.2. | TPM 2.0 required for ESXi 9.1 Secure Boot, host attestation, and vSphere Native Key Provider. | [vSphere TPM 2.0 Guide](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-security/GUID-10F7022C-DBE0-4E80-9285-EB02CEF513A1.html) |
| **BMC Sec** | Out-of-band management security posture baseline compliance.<br>• **✓ Met (Green):** All evaluated security controls passed.<br>• **▲ Partial (Amber):** Security controls partially assessed (unknowns present; honesty rule enforces that unknown does not pass).<br>• **✗ Action Req (Red):** High-priority hardening failures detected (e.g. Telnet, default password, IPMI-over-LAN). | BMC security posture evaluation against VCF Security Configuration Guide (SCG) baseline. | [VCF Security Guidelines](https://github.com/vmware/vcf-security-and-compliance-guidelines) |
| **VMD** | Intel Volume Management Device status.<br>• **✓ Off (Green):** VMD disabled (native NVMe pass-through enabled).<br>• **✗ On (Red):** VMD enabled (blocks native vSAN ESA NVMe driver). | Must be Disabled for direct-attached NVMe pass-through in vSAN ESA. | [Broadcom KB 88602](https://kb.vmware.com/s/article/88602) |
| **GPU** | Count and models of detected PCIe GPU accelerators. | Identifies hardware accelerators for VMware Private AI Foundation workloads. | [VMware Private AI Deployment](https://docs.vmware.com/en/VMware-Cloud-Foundation/services/vcf-private-ai-deployment/GUID-A934E26F-D2E4-42B1-8C1A-2C3C58B3A829.html) |

---

### 2.2 Drives Subtab (Storage Telemetry) {#inv-drives}

The Drives subtab details every physical storage drive detected across all storage controllers in the assessed fleet.

| Column Header | Description & Evaluation Logic | VCF 9.1 / vSAN Significance | External Documentation |
|---|---|---|---|
| **Host** | Host server hostname and BMC IP address. | Links physical drive asset to specific cluster node. | [vSphere Storage Overview](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-storage/index.html) |
| **Controller** | Storage controller model (e.g. Dell HBA355i, HPE Smart HBA, PERC H740P, Direct NVMe PCIe). Highlighted in red if controller is Dell PERC 7xx (HW RAID). | vSAN ESA requires direct PCIe or certified pass-through HBA; HW RAID controllers are ineligible. | [Broadcom KB 89498](https://kb.vmware.com/s/article/89498) |
| **Model** | Drive manufacturer part number and model with direct Broadcom Compatibility Guide (BCG) deep link. | Clicking opens certified device listing on Broadcom VCG for storage drives. | [Broadcom VCG — Storage SSDs](https://compatibilityguide.broadcom.com/search?program=ssd) |
| **Media** | Storage media technology: `NVMe SSD`, `SAS SSD`, `SATA SSD`, `HDD`. | vSAN ESA requires all-NVMe media; vSAN OSA supports SAS/SATA SSDs. | [vSAN ESA Architecture](https://core.vmware.com/resource/vmware-vsan-esa-readynode-hardware-guidance) |
| **Cap GB** | Raw drive capacity in gigabytes (e.g. 1920 GB, 3840 GB, 7680 GB, 15360 GB). | Used for storage capacity sizing calculations and pool planning. | [vSAN Sizing Guide](https://core.vmware.com/resource/vsan-sizing-guide) |
| **Protocol** | Bus transport protocol: `NVMe`, `SAS`, `SATA`. | NVMe protocol required for ESA flash devices. | [vSAN ESA Technical Details](https://core.vmware.com/vsan-esa) |
| **Category** | Classification: `vSAN ESA/OSA NVMe`, `vSAN OSA Compatible (HBA)`, `Unsupported NVMe RAID`, `Unsupported NVMe Tri-Mode`. | Directly impacts vSAN storage qualification status. | [vSAN Planning & Deployment](https://docs.vmware.com/en/VMware-vSphere/8.0/vsan-planning/GUID-10C4D04C-7682-4E57-B2E2-817DC7D57C5A.html) |
| **Health** | Hardware diagnostic health and S.M.A.R.T. operational state (`OK`, `Warning`, `Critical`, `Degraded`). | Failing or degraded drives must be replaced before node commissioning. | [vSphere Health Monitoring](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-monitoring-and-performance/index.html) |
| **Life%** | Remaining silicon flash endurance percentage (wear gauge). Reported directly from BMC OEM storage telemetry and NVMe log pages. | Drives with &lt;20% remaining life trigger critical replacement warnings. | [vSAN Drive Wear Monitoring](https://kb.vmware.com/s/article/2144888) |
| **Firmware** | Installed drive firmware version compared against certified Broadcom HCL baselines.<br>• **✓ (Green):** Certified and current.<br>• **▲ (Amber):** Certified update available or outdated. | Drive firmware must match VMware certified HCL releases to prevent I/O timeouts. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |

---

### 2.3 NICs Subtab (Network Interface Inventory) {#inv-nics}

The NICs subtab details every physical network interface adapter port across the fleet.

| Column Header | Description & Evaluation Logic | VCF 9.1 / vSAN Significance | External Documentation |
|---|---|---|---|
| **Host** | Host server hostname and BMC IP address. | Links network port to physical node. | [vSphere Networking](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-networking/index.html) |
| **Adapter** | Network controller adapter model (e.g. Intel E810-XXVDA2, Broadcom BCM57414, Mellanox ConnectX-6 Dx) with BCG deep link. | Clicking opens certified controller entry on Broadcom VCG for I/O devices. | [Broadcom VCG — IO Devices](https://compatibilityguide.broadcom.com/search?program=io) |
| **Port** | Physical network interface port identifier (e.g. `Port 1`, `NIC.Embedded.1-1-1`, `Slot 2 Port 1`). | Identifies physical uplink wiring and adapter port index. | [vSphere Uplink Configuration](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-networking/GUID-A9648937-2E89-4DF5-BF7D-F3C6DDAE3C98.html) |
| **Speed** | Current negotiated link speed or maximum rated bandwidth (e.g. `25 Gbps`, `100 Gbps`, `10 Gbps`). | &ge;25 Gbps required for vSAN ESA traffic; &ge;10 Gbps for management/vMotion. | [vSAN ESA Networking Requirements](https://core.vmware.com/resource/vsan-esa-networking) |
| **Link** | Physical connection state (`✓ Up` in green or `✗ Down` in red). | All intended cluster uplinks must be connected and negotiated Up. | [vSphere Link State Troubleshooting](https://kb.vmware.com/s/article/1003780) |
| **MAC** | Permanent hardware MAC address of the network interface port. | Used for vSphere Distributed Switch (VDS) uplink mapping and switch port security. | [vSphere Networking MAC Assignment](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-networking/index.html) |
| **Firmware** | Installed network controller firmware version compared against Broadcom certified baselines. | Firmware and driver combination must be aligned with vSphere 9.1 certified versions. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |

---

### 2.4 BIOS Settings Subtab (Firmware & Execution Baseline) {#inv-bios}

The BIOS Settings subtab displays key platform firmware configurations affecting CPU execution, memory reliability, storage pass-through, and microcode security.

| Column Header | Description & Evaluation Logic | VCF 9.1 Readiness Criteria | External Documentation |
|---|---|---|---|
| **Host** | Host server hostname and BMC IP address. | Links BIOS configuration to physical node. | [vSphere Documentation](https://docs.vmware.com/en/VMware-vSphere/index.html) |
| **Model** | Server hardware manufacturer and chassis model. | Identifies OEM configuration template. | [Broadcom VCG — Systems](https://compatibilityguide.broadcom.com/search?program=server) |
| **BIOS Version** | Installed system BIOS/UEFI firmware release version. | Must meet OEM minimum firmware release matrix for ESXi 9.1. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |
| **Release Date** | OEM release date of the installed BIOS build. | Identifies aging firmware builds requiring lifecycle updates. | [vSphere Lifecycle Manager (vLCM)](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-lifecycle-manager/index.html) |
| **CPU Power Profile** | Processor power management policy.<br>• **✓ Performance (Green):** Maximum Performance / Custom OS Control.<br>• **▲ Power Saving / Balanced (Amber/Red):** Energy Efficient or Dynamic saving modes. | ESXi and vSAN ESA require **Maximum Performance** profile in BIOS to prevent latency spikes and CPU throttling under heavy I/O. | [Broadcom KB 1018206](https://kb.vmware.com/s/article/1018206) |
| **Memory RAS** | Reliability, Availability, and Serviceability memory mode (`Optimized`, `Advanced ECC`, `Mirroring`, `Spare`). | `Optimized` / `Advanced ECC` provides maximum capacity and channel throughput. | [Memory RAS & OEM Guides](#oem-memory-population-guides) • [vSphere Performance Best Practices](https://core.vmware.com/resource/vsphere-performance-best-practices) |
| **Intel VMD** | Intel Volume Management Device status.<br>• **✓ Disabled (Pass-thru) (Green):** Pass-through ready.<br>• **✗ Enabled (VMD) (Red):** VMD enabled. | Must be **Disabled** so ESXi directly controls NVMe PCIe lanes and telemetry. | [Broadcom KB 88602](https://kb.vmware.com/s/article/88602) |
| **Boot Mode** | Firmware boot architecture.<br>• **✓ UEFI (Green):** Modern UEFI firmware boot.<br>• **✗ Legacy BIOS (Red):** Legacy BIOS boot mode. | **UEFI** boot mode is strictly required for VCF 9.1; Legacy BIOS is unsupported. | [vSphere UEFI Boot Requirements](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-esxi-installation/GUID-69D2C4D3-7ED1-4CD8-87FA-5CF13106DCF8.html) |
| **Spectre / CVE Tier** | Processor microcode security mitigation baseline covering Spectre, Meltdown, L1TF, MDS, and SRBDS.<br>• **✓ Tier 4 (Green):** Current certified microcode.<br>• **✗ Tier &lt;4 (Red):** Outdated microcode requiring BIOS update. | Tier 4 microcode ensures protection against speculative execution side-channels. | [Broadcom KB 330041](https://kb.vmware.com/s/article/330041) |

---

### 2.5 Health Alarms Subtab (Subsystem Telemetry) {#inv-alarms}

The Health Alarms subtab consolidates active hardware faults, degraded components, and telemetry threshold breaches from BMC subsystems.

| Column Header | Description & Evaluation Logic | Action Required | External Documentation |
|---|---|---|---|
| **Host** | Host server hostname and BMC IP address. | Identifies faulted physical node. | [vSphere Monitoring Guide](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-monitoring-and-performance/index.html) |
| **Severity** | Alarm urgency level (`✗ Critical`, `▲ Warning`, `ℹ Info`, or `✓ Healthy`). | Critical alarms block cluster commissioning until hardware remediation. | [vSphere Alarm Definitions](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-monitoring-and-performance/GUID-074EFB79-1C52-4742-89BE-44585B17B493.html) |
| **Subsystem** | Reporting hardware domain: `SEL Event Log`, `Drive SMART`, `Drive Wear`, `Drive Thermal`, `Power Supply`, `Thermal`, `Memory`, `Scan Status`. | Identifies responsible hardware subsystem. | [vSphere Hardware Health](https://kb.vmware.com/s/article/1003780) |
| **Health Alarm / Telemetry** | Detailed fault message, sensor threshold violation, or event description (e.g. `Predictive Failure on Slot 3`, `Power supply non-redundant`, `Uncorrectable multi-bit ECC error count: 1`). Clickable internal tab-jump link navigates directly to the corresponding host diagnostic subtab (`Overview`, `Storage`, `Health & Sensors`, `Memory`). | Provides diagnostic details for field technician dispatch or RMA replacement. | [vSphere Event Troubleshooting](https://kb.vmware.com/s/article/2006336) |
| **Component / Target** | Specific physical component identifier, drive bay slot, DIMM slot, or sensor name. For SEL entries, provides external deep links to vendor documentation guides (e.g. Dell PowerEdge EEMS Reference Guide chapters with exact topic GUIDs). For other components, provides internal tab-jump links to relevant host subtabs. | Pinpoints physical hardware part needing service or replacement. | [OEM Service Manuals](https://www.dell.com/support) |
| **Timestamp / Status** | Event timestamp or active condition status (`Active Alarm`, `Active State`, `Normal`). | Distinguishes transient historical events from active continuous faults. | [vSphere Logging Architecture](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-monitoring-and-performance/index.html) |

---

### 2.6 Security Subtab (Out-of-Band & Platform Hardening) {#inv-security}

The Security subtab provides a comprehensive audit of out-of-band management controller hardening, host cryptographic security, and baseline compliance.

| Column Header | Description & Evaluation Logic | VCF 9.1 Hardening Guideline | External Documentation |
|---|---|---|---|
| **Host** | Host server hostname and BMC IP address. | Links security audit to physical node. | [vSphere Security Guide](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-security/index.html) |
| **Model** | Server hardware manufacturer and chassis model. | Identifies vendor security framework and OEM hardening profile. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |
| **TPM 2.0** | Trusted Platform Module 2.0 presence and activation.<br>• **✓ (Green):** TPM 2.0 enabled and active.<br>• **✗ (Red):** TPM disabled, absent, or legacy TPM 1.2. | **Required for VCF 9.1:** Provides cryptographic identity, secure boot verification, and vSphere Native Key Provider integration. | [vSphere TPM 2.0 Hardening](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-security/GUID-10F7022C-DBE0-4E80-9285-EB02CEF513A1.html) |
| **Secure Boot** | UEFI Secure Boot signature validation status.<br>• **✓ (Green):** Enabled and active.<br>• **✗ (Red):** Disabled. | **Recommended:** Ensures only cryptographically signed ESXi hypervisor binaries, kernel drivers, and VIBs are executed at boot. | [Broadcom KB 2147606](https://kb.vmware.com/s/article/2147606) |
| **BMC Firmware** | Out-of-band management controller firmware baseline status.<br>• **✓ (Green):** Firmware meets or exceeds certified security baseline.<br>• **▲ (Amber):** Certified firmware update available.<br>• **✗ (Red):** Outdated firmware with known vulnerabilities. | BMC firmware should be kept current to remediate known remote code execution (RCE) and privilege escalation vulnerabilities. | [OEM Security Advisory Baselines](docs/OEM_REFERENCE.md) |
| **BMC License** | Out-of-band management controller license tier (e.g. iDRAC Enterprise/Datacenter, HPE iLO Advanced, Perpetual).<br>• **✓ (Green):** Enterprise or Perpetual license active.<br>• **✗ (Red):** License expired or required features blocked.<br>• **— (Muted):** Standard or default license. | Enterprise license tier required for full out-of-band remote telemetry and virtual media deployment. | [OEM License Guidelines](docs/OEM_REFERENCE.md) |
| **CVE Tier** | CPU microcode speculative execution side-channel mitigation level (Tier 1–Tier 4). | **Tier 4 Required:** Guarantees platform hardware mitigations for Spectre, Meltdown, L1TF, MDS, and SRBDS. | [Broadcom KB 330041](https://kb.vmware.com/s/article/330041) |
| **HT** | Intel Hyper-Threading / AMD SMT processor logical core status (`Enabled` or `Disabled`). | Displayed as informational plain text. Standard VCF deployments operate with Hyperthreading **Enabled** for maximum compute density. | [Broadcom KB 55806](https://kb.vmware.com/s/article/55806) |
| **NTP / Time Drift** | BMC Network Time Protocol synchronization and clock skew detection.<br>• **✓ In Sync (Green):** NTP active and BMC clock is synchronized within 300s (5 min) threshold.<br>• **▲ No Servers (Amber):** NTP protocol enabled but no NTP servers configured.<br>• **✗ Drift (Red):** Clock skew &gt;300s detected against assessment workstation.<br>• **✗ Disabled (Red):** NTP disabled on BMC. | **Critical for VCF Operations:** Consistent time across all BMCs and ESXi hosts is mandatory to prevent TLS certificate validation failures, SSO token expiration errors, and log correlation skew. | [Broadcom KB 1003734](https://kb.vmware.com/s/article/1003734) |
| **DNS** | BMC Domain Name System server configuration.<br>• **✓ Configured (Green):** DNS name servers configured on BMC or forward/reverse DNS resolves.<br>• **▲ No Servers (Amber):** DNS enabled without configured servers.<br>• **✗ Not Configured (Red):** No DNS servers configured. | BMCs should have reachable DNS servers configured for forward and reverse hostname resolution. | [VCF DNS Requirements](https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html) |
| **BMC Hardening** | Comprehensive out-of-band management security posture rollup and prioritized issue badges:<br>• **Posture Rollup:** `✓ Baseline Met` (Green), `▲ Partial (XU)` (Amber), or `✗ Action Req (XF)` (Red).<br>• **Critical Issues (Red):** `✗ Telnet` (unencrypted remote shell), `✗ Default Pwd` (unrotated root password), `✗ TLS < 1.2` (legacy cryptographic protocol).<br>• **High-Priority Concerns (Amber):** `▲ HTTP` (plaintext web management), `▲ IPMI LAN On` (unencrypted IPMI-over-LAN), `▲ No Lockout` (brute-force vulnerability), `▲ Host Pass-Through` (boundary escape risk), `▲ Weak Ciphers` (ciphers &lt;256-bit or weak algorithms), `▲ No Syslog` (missing remote audit logging), `▲ USB Mgmt` (unrestricted USB provisioning).<br>• **Baseline Tokens:** `TLS 1.2+`, `✓ Pwd Changed`, `✓ IPMI Disabled`, `✓ Hardened`. | Follow VCF Security Configuration Guide (SCG) and OEM hardening guides (Dell iDRAC, HPE iLO) to lock down management interfaces. | [VCF Security & Compliance Guidelines](https://github.com/vmware/vcf-security-and-compliance-guidelines) |

---

## 3. Single-Host Assessment Report Overview {#single-host-report}

The **Single-Host Assessment Report** provides a granular, component-level hardware and compatibility breakdown for an individual physical server node. It offers solution architects and deployment engineers definitive compatibility verdicts against VMware Cloud Foundation 9.1 and vSAN Express Storage Architecture requirements.

---

### 3.1 Host Identity Header & Status Banners {#host-header-and-banners}

The top section of the single-host report establishes the physical identity of the server, out-of-band management connectivity, hypervisor discovery, and data collection parameters.

| Header Element | Description & Evaluation Logic | Operational Significance | External Documentation |
|---|---|---|---|
| **Hostname & BMC IP** | Server hostname registered in BMC DNS or fallback IP address. Clicking the IP opens the BMC web management console (iDRAC, iLO, XCC, IMC). | Establishes node identity and out-of-band administration address. | [vSphere Host Management](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-host-administration/index.html) |
| **Vendor & Model** | Physical chassis manufacturer and normalized model name (e.g. `Dell PowerEdge R750`, `HPE ProLiant DL380 Gen10 Plus`). Includes BCG deep link. | Clicking opens the certified server model entry on the Broadcom Compatibility Guide. | [Broadcom VCG — Systems](https://compatibilityguide.broadcom.com/search?program=server) |
| **Serial / Service Tag** | Hardware chassis serial number, service tag, or asset identifier extracted from BMC SMBIOS data. | Used for hardware warranty verification, vendor support cases, and asset tracking. | [OEM Service Tags](https://www.dell.com/support) |
| **Asset Tag** | Customer-assigned physical datacenter asset tag programmed in BMC NVRAM. | Facilitates reconciliation with enterprise Configuration Management Databases (CMDB). | [ITIL Asset Management](https://docs.vmware.com/) |
| **Power State & LED** | Current server chassis power state (`On`, `Off`, `PoweringOn`) and front panel chassis locator LED status (`Blinking`, `Off`). | Confirms node operational state and provides physical chassis identification during datacenter walk-throughs. | [DMTF Redfish ComputerSystem](https://www.dmtf.org/standards/redfish) |
| **System Type** | Server physical form factor: `Physical (Rackmount)`, `Blade System`, or `Modular Chassis`. | Informs datacenter rack density and power planning. | [vSphere Hardware Sizing](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-host-administration/index.html) |
| **BIOS Date** | OEM release date of the installed system BIOS / UEFI build. | Quickly highlights stale system firmware requiring lifecycle updates. | [vSphere Lifecycle Manager](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-lifecycle-manager/index.html) |
| **Data Source Protocol** | Protocol utilized for collection: `DMTF Redfish v1.x (HTTPS)` or legacy `Dell WS-Man (WinRM)`. | Verifies out-of-band communication transport. | [DMTF Redfish Standards](https://www.dmtf.org/standards/redfish) |
| **Scan Mode Badge** | Collection profile executed: `Quick Scan` (~5s), `Lean Scan` (~15–30s), or `Full Scan` (~60–90s). | Clarifies why certain sections (e.g. SMART drive wear or thermal telemetry) may be omitted in fast scans. | [User Guide Reference](#web-ui-and-cli-operations) |
| **Host OS Detection** | In-band operating system telemetry queried from BMC agentless interfaces: hypervisor build (e.g. `VMware ESXi 8.0.3 build-24022510`), Linux kernel, or Windows Server. | Identifies current operating environment prior to VCF 9.1 hypervisor reimaging. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |
| **BCG Deep Links** | Single-click links dynamically generated for the Server Platform and CPU Processor family. | Direct access to official Broadcom certified compatibility listings. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |
| **PII Obfuscation Badge** | Indicator displayed when data obfuscation is active (`🔒 Obfuscated Report`). Real hostnames, IPs, MACs, and serials are replaced with deterministic SHA-256 tokens. | Guarantees compliance when sharing readiness reports with external partners or Broadcom support. | [Security Architecture](docs/SECURITY_ARCHITECTURE.md) |

---

### 3.2 Executive Summary Cards {#executive-summary-cards}

Eight high-contrast visual cards immediately communicate qualification status across core hardware subsystems:

#### 1. CPU Support Tier Card
- **Evaluation Logic:** Evaluates processor model against VCF 9.1 CPU compatibility baselines.
- **Statuses:**
  - `🟢 Supported`: Intel Cascade Lake, Ice Lake, Sapphire Rapids, Emerald Rapids, Granite Rapids; AMD EPYC 7002, 7003, 8004, 9004.
  - `🟡 Supported (Override Required)`: Intel Skylake-SP ([Broadcom KB 428874](https://knowledge.broadcom.com/external/article/428874)). Supported in VCF 9.x with CPU support override during install or upgrade.
  - `🔴 Unsupported`: Intel Haswell, Broadwell (v3/v4), or older architectures; blocks ESXi 9.1 installation.
- **External Reference:** [Broadcom KB 428874](https://kb.vmware.com/s/article/428874).

#### 2. BIOS & Microcode Card
- **Evaluation Logic:** Compares installed BIOS firmware against OEM minimum release matrices and evaluates processor microcode side-channel security tiers.
- **Statuses:**
  - `🟢 Baseline Met`: Installed BIOS meets or exceeds recommended OEM firmware release with Tier 4 microcode.
  - `🟡 Update Recommended`: BIOS is below recommended baseline or aging release date detected.
  - `🔴 Action Required`: Vulnerable microcode level (Tier <4) requiring mandatory BIOS flashing.
- **External Reference:** [Broadcom KB 330041](https://kb.vmware.com/s/article/330041).

#### 3. TPM 2.0 Security Card
- **Evaluation Logic:** Validates the presence, activation status, and firmware level of the hardware Trusted Platform Module.
- **Statuses:**
  - `🟢 TPM Configured`: TPM 2.0 enabled, activated, and communicating via UEFI interface.
  - `⚠️ TPM 1.2 Upgrade Required`: Legacy TPM 1.2 detected; must be upgraded to TPM 2.0 for VCF 9.1.
  - `🔴 TPM Missing / Disabled`: TPM chip absent or disabled in BIOS; blocks host attestation and Key Provider.
- **External Reference:** [vSphere TPM 2.0 Guide](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-security/GUID-10F7022C-DBE0-4E80-9285-EB02CEF513A1.html).

#### 4. Memory Interleaving Card
- **Evaluation Logic:** Assesses total system RAM, populated DIMM slot symmetry, and channel interleaving efficiency across CPU sockets.
- **Statuses:**
  - `🟢 Balanced (100% Throughput)`: Symmetrical channel population delivering maximum memory bandwidth.
  - `🟡 Suboptimal Interleaving`: Unbalanced channel configuration causing memory throttling.
  - `🔴 Degraded / Single-Channel`: Unpopulated memory channels significantly degrading VM performance.
- **External Reference:** [VMware Performance Best Practices](https://core.vmware.com/resource/vsphere-performance-best-practices).

#### 5. vSAN ESA/OSA Readiness Card
- **Evaluation Logic:** Evaluates direct-attached NVMe flash count, total usable capacity, and uplink network speed.
- **Statuses:**
  - `🟢 vSAN ESA Ready`: &ge;2 direct NVMe SSDs, no RAID/VMD blockers, and &ge;25 GbE network interfaces.
  - `🟡 vSAN ESA Storage Met`: Storage requirements satisfied, but network NIC is <25 GbE (requires 25G NIC upgrade).
  - `🟡 vSAN OSA Compatible`: SAS/SATA SSDs attached via certified pass-through HBA controller.
  - `🔴 vSAN Ineligible`: NVMe behind HW RAID, Intel VMD enabled, or insufficient drive count.
- **External Reference:** [vSAN ESA ReadyNode Hardware Guidance](https://core.vmware.com/resource/vmware-vsan-esa-readynode-hardware-guidance).

#### 6. Intel VMD Pass-Through Card
- **Evaluation Logic:** Checks whether Intel Volume Management Device (VMD) is enabled in BIOS.
- **Statuses:**
  - `🟢 VMD Off (Pass-thru Ready)`: Intel VMD disabled; native ESXi NVMe driver has direct PCIe lane access.
  - `🔴 VMD On (Driver Blocker)`: Intel VMD enabled; blocks direct-attached NVMe devices in vSAN ESA.
- **External Reference:** [Broadcom KB 88602](https://kb.vmware.com/s/article/88602).

#### 7. Power Supply Redundancy Card
- **Evaluation Logic:** Evaluates physical PSU count, input line status, and operational redundancy mode.
- **Statuses:**
  - `🟢 Redundant`: 2+ healthy power supplies operating in active/standby or load-sharing redundant mode.
  - `🟡 Non-Redundant / Degraded`: Single power supply installed or AC power feed failed on redundant PSU.
- **External Reference:** [vSphere Availability Best Practices](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-availability/index.html).

#### 8. Telemetry & Utilization Card
- **Evaluation Logic:** Captures current and historical peak CPU utilization and memory bus throughput percentages.
- **Statuses:**
  - `🟢 Healthy Headroom`: Peak resource utilization within normal operational limits (<75%).
  - `🟡 High Utilization`: Historical peak utilization exceeding 80%, indicating compute/memory saturation.
- **External Reference:** [vSphere Performance Monitoring](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-monitoring-and-performance/index.html).

---

### 3.3 Actionable Alert Rollup Engine {#alert-rollup}

Directly beneath the executive cards, the Alert Rollup Engine categorizes findings into prioritized action tiers to streamline field remediation:

| Alert Severity | Visual Treatment | Definition & Criteria | Example Scenarios |
|---|---|---|---|
| **Critical Blockers** | Red Box (`alert-danger`) | Hardware configurations or missing components that strictly prevent VCF 9.1 deployment or vSAN ESA commissioning. | • Intel VMD Enabled in BIOS.<br>• NVMe SSDs attached behind PERC HW RAID.<br>• Unsupported CPU architecture (Broadwell/Haswell).<br>• TPM absent or TPM 1.2.<br>• Legacy BIOS boot mode. |
| **Configuration Warnings** | Yellow Box (`alert-warning`) | Suboptimal configurations that permit installation but degrade performance, reduce redundancy, or require lifecycle upgrades. | • Intel Skylake-SP Override Required (KB 428874).<br>• Suboptimal memory channel interleaving.<br>• Single power supply / lost AC grid feed.<br>• Drive flash wear life &lt;20% remaining.<br>• Network adapter links down or &lt;25 GbE. |
| **Operational Notes** | Blue Box (`alert-info`) | Best-practice recommendations and informational telemetry items for ongoing datacenter governance. | • BMC clock skew &gt;300s relative to NTP.<br>• Remote syslog not configured on BMC.<br>• Virtual Media ISO currently mounted.<br>• Drive firmware certified update available on HCL. |

---

### 3.4 System Event Log (SEL) & Vendor Reference Integration {#host-sel}

The System Event Log pane captures out-of-band hardware events, critical faults, and sensor threshold alerts from the BMC. 

- **Vendor SEL Reference Button:** Prominently links to authoritative vendor error and event guides based on the detected host manufacturer:
  - **Dell PowerEdge:** [Dell PowerEdge Servers Error and Event Messages Reference Guide (EEMs)](https://www.dell.com/support/manuals/en-us/poweredge-r740xd/error_event_message_guide_c/poweredge-servers-error-and-event-messages-eems?guid=guid-96cc49ee-fa46-4249-adb6-e0c9a3cbdb1f&lang=en-us)
  - **HPE ProLiant:** [HPE Integrated Management Log (IML) Messages and Troubleshooting Guide](https://support.hpe.com/hpesc/public/docDisplay?docId=ilogen12-msg-en_us&docLocale=en_US)
  - **Cisco UCS:** [Cisco UCS IMC Faults Reference Guide](https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/fault/reference/guide/b_Cisco_UCS_IMC_Faults_Reference_Guide/b_Cisco_UCS_IMC_Faults_Reference_Guide_chapter_0100.html)
  - **Lenovo ThinkSystem:** [Lenovo ThinkSystem XCC Events Reference Guide](https://pubs.lenovo.com/sr650-v4/xcc_error_messages)
  - **Supermicro:** [Supermicro BMC IPMI User's Guide (SEL Reference)](https://www.supermicro.com/manuals/other/IPMI_Users_Guide.pdf)
- **Deep-Linked Message IDs & Hex Sensor Codes:**
  - For Dell PowerEdge hosts, both alphanumeric EEMS codes (e.g., `PSU0001`, `PDR1016`) and raw IPMI hex sensor codes (e.g., `0b01ffff` -> `RDU0012`, `6f03ffff` -> `PSU0003`, `efa00113` -> `PDR1016`, `6f8002ff` -> `SEC0033`, `6fa41100` -> `HWC8010`) are mapped directly to their exact chapter and topic GUID in Dell's official EEMS Reference Guide.
  - Clicking any message ID or alert title navigates directly to Dell's documentation with zero search redirects.

---

## 4. Compute & CPU Architecture Deep-Dive {#compute-and-cpu-deep-dive}

The compute evaluation examines CPU socket architecture, core topology, clock frequencies, instruction set capabilities, microcode mitigations for side-channel speculative execution vulnerabilities, and memory interleaving efficiency.

---

### 4.1 Processor Architecture & Cache Hierarchy {#processor-architecture}

Processor selection directly dictates hypervisor scheduling efficiency, per-core licensing economics, and advanced virtualization capabilities.

| Processor Metric | Technical Definition & Evaluation Logic | VCF 9.1 / vSAN Impact | External Reference |
|---|---|---|---|
| **Processor Model** | Full manufacturer processor string (e.g. `Intel(R) Xeon(R) Platinum 8380 CPU @ 2.30GHz`, `AMD EPYC 9654 96-Core Processor`). | Determines core architectural generation and VMware Compatibility Guide listing. | [Broadcom VCG — Processors](https://compatibilityguide.broadcom.com/search?program=cpu) |
| **Socket Count** | Total physical CPU sockets populated on the server motherboard (typically 1P or 2P). | Direct multiplier for per-socket VMware Cloud Foundation core licensing metrics. | [VCF Licensing Overview](https://docs.vmware.com/en/VMware-Cloud-Foundation/index.html) |
| **Physical Cores** | Total physical execution cores across all installed processor sockets (e.g. 32, 64, 128 cores). | vSAN ESA requires minimum 16 cores (ESA-XS/S), 32 cores (ESA-M), or 48 cores (ESA-L). | [vSAN ESA ReadyNode Guidance](https://core.vmware.com/resource/vmware-vsan-esa-readynode-hardware-guidance) |
| **Logical Threads** | Total virtual execution threads enabled via Intel Hyper-Threading (HT) or AMD Simultaneous Multithreading (SMT). | Multiplies virtual CPU (vCPU) capacity available to hypervisor scheduling queues. | [Broadcom KB 55806](https://kb.vmware.com/s/article/55806) |
| **Base & Turbo Clocks** | Rated fundamental frequency (GHz) and maximum single-core turbo frequency. | High base clock (>2.6 GHz) prevents CPU wait states under intense I/O transactions. | [VMware Performance Best Practices](https://core.vmware.com/resource/vsphere-performance-best-practices) |
| **Microarchitecture** | Processor generation (e.g. `Cascade Lake`, `Ice Lake`, `Sapphire Rapids`, `Emerald Rapids`, `Zen 3`, `Zen 4`). | Governs instruction set support and EVC (Enhanced vMotion Compatibility) baselines. | [Broadcom KB 1003212](https://kb.vmware.com/s/article/1003212) |
| **Instruction Extensions** | Detected hardware acceleration flags: `AVX-512`, `Intel AMX`, `VMX`, `SVM`, `SHA`, `AES-NI`. | Hardware cryptography and matrix acceleration for encryption, vSAN compression, and AI. | [Intel Architecture Instruction Extensions](https://www.intel.com/) |
| **L1/L2/L3 Cache** | Granular cache hierarchy: per-core L1 instruction/data, per-core L2, and shared L3 Smart Cache. | Large L3 cache buffers reduce RAM bus accesses, directly improving storage I/O throughput. | [vSphere CPU Sizing](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-host-administration/index.html) |
| **CPU Utilization Telemetry**| Real-time and historical peak CPU utilization percentage collected via BMC telemetry registers. | Sizing validation: servers showing sustained >80% utilization require workload re-balancing. | [vSphere Performance Monitoring](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-monitoring-and-performance/index.html) |

---

### 4.2 Spectre / Meltdown CVE Microcode Tiers {#cve-microcode-tiers}

The assessment engine evaluates installed processor microcode against Broadcom security advisories to protect against speculative execution side-channel vulnerabilities:

| CVE Microcode Tier | Security Baseline & Mitigation Coverage | Platform Vulnerability Posture | Required Action |
|---|---|---|---|
| **Tier 1 (Legacy / Insecure)** | Original unmitigated silicon microcode; vulnerable to Spectre v1 (CVE-2017-5753), Spectre v2 (CVE-2017-5715), and Meltdown (CVE-2017-5754). | **Critical Security Vulnerability:** Allows malicious VM guest workloads to read host hypervisor memory. | Mandatory BIOS/microcode update prior to cluster joining. |
| **Tier 2 (Basic Mitigations)** | Includes basic Speculative Store Bypass Disable (SSBD / Spectre v4, CVE-2018-3639) and Rogue System Register Read (Spectre v3a). | **Elevated Risk:** Vulnerable to advanced microprocessor cache and buffer side-channels. | Update BIOS to Tier 4 certified microcode. |
| **Tier 3 (Intermediate Mitigations)** | Adds Microarchitectural Data Sampling (MDS / ZombieLoad, RIDL, Fallon, CVE-2019-11091) and L1 Terminal Fault (L1TF, CVE-2018-3620). | **Moderate Risk:** Missing Special Register Buffer Data Sampling (SRBDS) and modern transient execution mitigations. | Upgrade to latest vendor BIOS release. |
| **Tier 4 (Current Certified Baseline)** | Comprehensive microcode coverage: incorporates SRBDS (CVE-2020-0543), Processor MMIO Stale Data, and Retbleed mitigations. | **Compliant Security Posture:** Full hardware and microcode defense against all published transient execution side-channels. | No action required; certified for VCF 9.1 production deployment. |

> 📖 **Broadcom Reference:** For full details on hypervisor mitigations, see [Broadcom KB 330041 — VMware ESXi Speculative Execution Mitigations](https://kb.vmware.com/s/article/330041).

---

### 4.3 Memory Subsystem & Interleaving Topology {#memory-channel-interleaving}

Memory bandwidth and symmetrical channel population represent critical performance factors in high-throughput vSAN ESA and compute-dense clusters.

#### Memory Topology Fields
| Memory Field | Technical Definition & Evaluation Logic | Performance Significance | External Documentation |
|---|---|---|---|
| **Total Installed Capacity** | Aggregated RAM across all populated DIMMs (GB). | vSAN ESA requires minimum 64 GB (ESA-XS), 128 GB (ESA-S), 256 GB (ESA-M), or 512 GB (ESA-L). | [vSAN ESA ReadyNode Profiles](https://core.vmware.com/resource/vmware-vsan-esa-readynode-hardware-guidance) |
| **Populated / Total Slots** | Ratio of installed DIMMs to available physical motherboard memory slots (e.g. `16 / 32 Slots`). | Identifies available memory expansion headroom for future workload domain growth. | [vSphere Hardware Sizing](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-host-administration/index.html) |
| **Configured Clock Speed** | Actual operating transfer rate in MT/s or MHz (e.g. `3200 MT/s`, `4800 MT/s`). | Operating speed drops if unbalanced DIMM ranks or excessive DIMMs per channel (2 DPC) are installed. | [vSphere Performance Best Practices](https://core.vmware.com/resource/vsphere-performance-best-practices) |
| **Operating Voltage** | Memory module electrical voltage (e.g. `1.2V` for DDR4, `1.1V` for DDR5). | Ensures DIMMs are operating within factory JEDEC low-voltage energy standards. | [JEDEC Standards](https://www.jedec.org/) |
| **Generation & Form Factor** | Memory generation (`DDR4`, `DDR5`) and module type (`RDIMM`, `LRDIMM`, `3DS RDIMM`). | Mixing RDIMMs and LRDIMMs within the same server is strictly unsupported by server OEMs and causes POST failures. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |
| **Memory RAS Mode** | System reliability setting: `Optimized`, `Advanced ECC`, `Memory Mirroring`, or `Rank Sparing`. | `Optimized` / `Advanced ECC` provides 100% throughput; `Mirroring` cuts usable capacity by 50%. | [Memory RAS & OEM Guides](#oem-memory-population-guides) • [vSphere Resource Management](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-resource-management/index.html) |
| **Memory Bus Utilization** | Real-time and historical peak memory bus bandwidth utilization percentage. | Identifies memory-bound applications and validates NUMA node distribution. | [vSphere Performance Monitoring](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-monitoring-and-performance/index.html) |
| **Uncorrectable ECC Errors** | Count of multi-bit parity errors logged by the memory controller (detected via BMC SEL). | **Critical Blocker:** Any count &gt;0 indicates defective silicon requiring immediate DIMM replacement. | [vSphere Hardware Health](https://kb.vmware.com/s/article/1003780) |
| **Correctable ECC Errors** | Cumulative count of single-bit parity errors corrected by memory controller ECC logic. | High rates (>1000/day) indicate impending silicon failure and predict uncorrectable crashes. | [OEM Service Diagnostics](https://www.dell.com/support) |

#### Memory Interleaving Efficiency Rating Engine
Modern processors (e.g. Intel Ice Lake/Sapphire Rapids with 8 channels, AMD EPYC with 8 or 12 channels) divide memory access across multiple independent memory controllers:

- **Balanced / Fully Interleaved (`🟢 Balanced (100% Bandwidth)`):**
  - All memory channels on each CPU socket are populated with identical DIMM capacities and speeds (e.g. 16 identical DIMMs on an 8-channel dual-socket server).
  - Maximizes memory throughput by interleaving sequential memory addresses across all channels simultaneously.
- **Suboptimal Interleaving (`🟡 Suboptimal Interleaving (Reduced Throughput)`):**
  - Memory channels are populated asymmetrically (e.g. 12 DIMMs populated on an 8-channel dual-socket server).
  - Memory controller is forced into partial interleave mode, reducing effective memory bus bandwidth by 15% to 35% and penalizing storage cache throughput.
- **Degraded / Single-Channel (`🔴 Degraded / Single-Channel`):**
  - Missing memory channels cause severe NUMA imbalance, severely restricting vSphere VM execution efficiency.

> 📖 **OEM Memory Population Rules Reference**: For official physical DIMM slot population tables, channel balancing rules, and mode-specific configuration guidelines across the last three server generations (Dell PowerEdge 14G/15G/16G and HPE ProLiant Gen10/Gen10 Plus/Gen11), see [Section 8.3: OEM Memory Population & Channel Architecture Guides](#oem-memory-population-guides).

---

## 5. Storage Subsystem & vSAN Qualification {#storage-subsystem}

The storage evaluation analyzes physical storage controllers, bus attachments, direct PCIe pass-through topology, drive media classification, certified firmware baselines, and silicon endurance metrics to determine vSAN Express Storage Architecture (ESA) and Original Storage Architecture (OSA) readiness.

---

### 5.1 vSAN ESA ReadyNode Profile Baselines {#vsan-esa-readynode-profiles}

VMware vSAN Express Storage Architecture (ESA) is optimized for high-performance direct-attached NVMe flash devices without traditional disk groups (no dedicated cache drives). The assessment engine qualifies servers against official VMware ReadyNode profiles:

| Profile Level | Storage Drives | Memory (RAM) | Compute Cores | Network Uplink | Target Workload Profile |
|---|---|---|---|---|---|
| **ESA-L (Large)** | &ge;4 Direct NVMe SSDs (&ge;1.6 TB each) | &ge;512 GB | &ge;48 Cores | &ge;25 GbE | High-density databases, mission-critical applications, large enterprise clusters. |
| **ESA-M (Medium)**| &ge;2 Direct NVMe SSDs (&ge;1.6 TB each) | &ge;256 GB | &ge;32 Cores | &ge;25 GbE | Standard enterprise compute clusters, moderate I/O workloads, virtual desktops. |
| **ESA-S (Small)** | &ge;2 Direct NVMe SSDs (&ge;1.6 TB each) | &ge;128 GB | &ge;16 Cores | &ge;25 GbE | Entry enterprise datacenter clusters, test/development environments. |
| **ESA-XS (Edge)** | &ge;2 Direct NVMe SSDs (&ge;1.6 TB each) | &ge;64 GB | &ge;16 Cores | &ge;10/25 GbE | Remote Office / Branch Office (ROBO), edge appliances, distributed retail sites. |

#### Storage Qualification Verdicts
- **✓ vSAN ESA Ready (`🟢 Ready`):** Server meets all hardware requirements: &ge;2 direct NVMe SSDs, direct PCIe pass-through (no HW RAID or VMD blockers), and &ge;25 GbE networking.
- **▲ vSAN ESA Storage Met (`🟡 Storage Met (Needs 25G NIC)`):** Storage and compute qualify for ESA, but network adapter is <25 GbE. Requires NIC upgrade to 25 GbE before commissioning.
- **▲ vSAN OSA Compatible (`🟡 OSA Compatible`):** Server contains SAS/SATA SSDs attached to a certified HBA controller; qualified for traditional vSAN OSA (1 cache drive + capacity drives).
- **✗ Blocked / Ineligible (`🔴 Blocked`):** Disqualified due to hardware RAID controllers, Tri-Mode controllers, Intel VMD enabled in BIOS, or insufficient qualifying drives (<2 NVMe).

> 📖 **VMware Reference:** See [VMware vSAN ESA ReadyNode Hardware Guidance](https://core.vmware.com/resource/vmware-vsan-esa-readynode-hardware-guidance) for complete profile sizing tables.

---

### 5.2 Storage Controllers & RAID Passthrough Blocker Logic {#storage-controllers}

vSAN ESA introduces a specialized high-performance log-structured filesystem that interacts directly with NVMe PCIe controller registers. Intermediate hardware abstraction layers severely degrade latency and are strictly unsupported.

| Storage Controller Field | Technical Definition & Evaluation Logic | Compatibility Impact | External Documentation |
|---|---|---|---|
| **Controller Model** | Full controller model name (e.g. `Dell HBA355i`, `HPE Smart Array P408i-a`, `Direct NVMe PCIe Pass-thru`). | Determines bus topology and hardware compatibility. | [Broadcom VCG — Storage](https://compatibilityguide.broadcom.com/search?program=io) |
| **Controller Type** | Architectural category: `Direct PCIe Pass-thru`, `Pass-through HBA`, `Hardware RAID`, `Tri-Mode`. | Directly dictates storage qualification tier. | [Broadcom KB 89498](https://kb.vmware.com/s/article/89498) |
| **Firmware Version** | Installed storage controller firmware build compared against certified VMware HCL baselines. | Outdated firmware causes bus resets and SCSI/NVMe command timeouts. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |
| **Driver Version** | Installed ESXi kernel driver matching the controller firmware build. | Driver/firmware alignment is strictly required for ESXi cluster support. | [vSphere Lifecycle Manager](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-lifecycle-manager/index.html) |

#### Passthrough Blocker Logic
1. **Hardware RAID Controllers (e.g. Dell PERC H740P, PERC H750, HPE Smart Array in RAID mode):**
   - **Status: Blocked (Red).** Hardware RAID controllers abstract physical NVMe PCIe registers behind proprietary RAID firmware caches, blocking native vSAN ESA NVMe drivers ([Broadcom KB 89498](https://kb.vmware.com/s/article/89498)).
   - **Remediation:** Replace HW RAID controllers with direct PCIe pass-through cables or certified pass-through HBAs (e.g. Dell HBA355i).
2. **Tri-Mode Controllers (e.g. Broadcom MegaRAID 9560 / PERC H755N Tri-Mode):**
   - **Status: Blocked (Red).** Multiplexing NVMe over SAS/SATA Tri-Mode backplanes violates vSAN ESA direct-attached pass-through specifications.
3. **Intel Volume Management Device (Intel VMD):**
   - **Status: Blocked (Red).** When enabled in system BIOS, Intel VMD aggregates NVMe drives under an Intel VMD endpoint, preventing ESXi from managing drives natively ([Broadcom KB 88602](https://kb.vmware.com/s/article/88602)).
   - **Remediation:** Disable Intel VMD in BIOS to restore native PCIe pass-through.

---

### 5.3 Physical Drive Inventory & Flash Wear Life {#physical-drives-table}

The physical drives table inventories every drive attached to storage backplanes and PCIe slots across the server:

| Drive Column | Description & Evaluation Logic | vSAN ESA / OSA Significance | External Documentation |
|---|---|---|---|
| **Bay / Slot** | Physical enclosure drive bay or slot number (e.g. `Bay 0`, `Slot 1`, `Disk.Bay.2`). | Pinpoints physical drive location for hot-swap operations or replacement dispatches. | [OEM Service Manuals](https://www.dell.com/support) |
| **Model** | Manufacturer drive model number with direct Broadcom Compatibility Guide (BCG) link. | Clicking opens certified device listing on Broadcom VCG for storage SSDs. | [Broadcom VCG — Storage SSDs](https://compatibilityguide.broadcom.com/search?program=ssd) |
| **Serial Number** | Unique physical drive serial number extracted from drive controller NVRAM. | Required for tracking RMA replacements and verifying hardware warranty. | [OEM Drive Replacement](https://www.dell.com/support) |
| **Capacity GB** | Formatted drive capacity in gigabytes (e.g. 1920 GB, 3840 GB, 7680 GB, 15360 GB). | Sizing baseline used for calculating raw and usable datastore storage pools. | [vSAN Sizing Calculator](https://core.vmware.com/resource/vsan-sizing-guide) |
| **Media Type** | Flash technology: `NVMe SSD`, `SAS SSD`, `SATA SSD`, or `HDD`. | vSAN ESA requires all-NVMe media; SAS/SATA SSDs are restricted to vSAN OSA. | [vSAN Architecture Overview](https://core.vmware.com/vsan-esa) |
| **Protocol** | Bus protocol: `NVMe (PCIe)`, `SAS`, `SATA`. | NVMe protocol delivers direct CPU register mapping with microsecond latency. | [NVM Express Standards](https://nvmexpress.org/) |
| **Category** | Classification: `vSAN ESA/OSA NVMe`, `vSAN OSA Compatible (HBA)`, `Unsupported NVMe RAID`. | Determines eligibility in the vSAN storage pool. | [vSAN Planning Guide](https://docs.vmware.com/en/VMware-vSphere/8.0/vsan-planning/index.html) |
| **Operational Health** | Real-time diagnostic state: `OK`, `Warning`, `Critical`, or `Degraded`. | Drives reporting degraded health must be decommissioned before cluster installation. | [vSphere Health Monitoring](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-monitoring-and-performance/index.html) |
| **Remaining Life%** | Flash silicon endurance wear gauge (percentage of life remaining). | **Wear Alert:** Drives with &lt;20% remaining life trigger a critical replacement warning. | [Broadcom KB 2144888](https://kb.vmware.com/s/article/2144888) |
| **Firmware** | Installed drive firmware revision compared against certified HCL baselines. | Firmware updates resolve drive controller lockups, command timeouts, and bad-block bugs. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |

---

### 5.4 Granular OCP NVMe SMART Telemetry {#nvme-smart-telemetry}

For enterprise NVMe drives, the assessment tool queries all 20 standardized SMART telemetry metrics defined by the **Open Compute Project (OCP) Datacenter NVMe SSD Specification (v2.6)**:

| SMART Attribute | Technical Definition & Measurement Unit | Health & Degradation Threshold |
|---|---|---|
| **Critical Warning** | Bitmask of internal controller alerts (spare capacity, temperature, reliability, read-only mode). | **0 (None):** Any non-zero value indicates immediate silicon or hardware failure. |
| **Composite Temperature** | Internal silicon controller and NAND flash composite operating temperature (°C). | **<70°C:** Temperatures exceeding 75°C cause thermal throttling; >80°C risks drive shutdown. |
| **Available Spare** | Percentage of remaining factory over-provisioned spare flash blocks (0–100%). | **>20%:** Decreasing spare capacity indicates bad-block retirement. |
| **Available Spare Threshold** | Vendor-configured threshold at which the Available Spare alert bit is triggered. | Factory threshold (typically 10%); breaching triggers critical drive replacement. |
| **Percentage Used** | Estimated percentage of drive silicon endurance consumed based on write endurance (TBW). | **<80% Used:** Values &ge;100% indicate flash warranty expiration and high failure probability. |
| **Data Units Read** | Cumulative data read from the drive in 512-byte units (represented as Millions of 512B blocks). | Telemetry metric tracking total read volume over the drive operational lifecycle. |
| **Data Units Written** | Cumulative data written to the drive in 512-byte units. | Used to compute Write Amplification Factor (WAF) when compared against host writes. |
| **Host Read Commands** | Cumulative number of read I/O commands processed by the drive controller. | Workload analysis metric measuring read I/O intensity. |
| **Host Write Commands** | Cumulative number of write I/O commands processed by the drive controller. | Workload analysis metric measuring write I/O intensity. |
| **Controller Busy Time** | Cumulative time (minutes) during which the controller was busy processing active I/O commands. | Identifies I/O queue saturation and storage bus bottlenecks. |
| **Power Cycles** | Number of power-on cycles experienced by the drive. | Operational lifecycle tracking; high power cycles indicate rack power instability. |
| **Power On Hours** | Cumulative operating hours the drive has been energized. | Silicon aging metric used to forecast Mean Time Between Failures (MTBF). |
| **Unsafe Shutdowns** | Number of unexpected power loss events without prior host shutdown notification. | High counts risk metadata corruption and indicate emergency power-off events. |
| **Media & Data Integrity Errors**| Cumulative count of uncorrectable read/write errors, ECC failures, or CRC mismatches. | **0:** Any value &gt;0 indicates physical media decay requiring immediate drive RMA. |
| **Error Information Log Entries**| Cumulative count of error information log events recorded in the drive controller memory. | High error log frequency indicates bus transfer instability or interface errors. |
| **Warning Composite Temp Time** | Cumulative time (minutes) the drive operated above warning thermal thresholds. | Extended duration indicates inadequate server chassis airflow or cooling fan failure. |
| **Critical Composite Temp Time**| Cumulative time (minutes) the drive operated above critical thermal shutdown thresholds. | Indicates severe thermal events that accelerate silicon wear and cause I/O aborts. |
| **Thermal Mgmt Transitions** | Count of times the drive throttled performance to control operating temperature. | Confirms thermal throttling events that directly penalize cluster I/O latency. |
| **Thermal Mgmt Time** | Cumulative time (seconds) spent in active thermal throttling states. | Validates chassis thermal optimization effectiveness. |
| **End-to-End Data Path Errors** | Cumulative count of parity/CRC transfer errors detected between PCIe bus and flash memory. | **0:** Any non-zero count indicates hardware interface decay or controller corruption. |

---

## 6. Network Interfaces & Top-of-Rack Discovery {#network-interfaces}

The network assessment verifies physical network controller models, certified driver/firmware baselines, per-port link capabilities, 25 GbE qualification criteria for vSAN ESA, ToR switch fabric adjacency via LLDP and Cisco CDP, and Fibre Channel Host Bus Adapter (FC HBA) connectivity.

---

### 6.1 Network Adapters & ESA 25 GbE Baseline {#network-adapters}

High-performance software-defined storage in vSAN ESA relies on high-speed network transports with minimal latency and high frame processing efficiency.

| Network Adapter Attribute | Description & Evaluation Logic | VCF 9.1 / vSAN Impact | External Documentation |
|---|---|---|---|
| **Controller Model** | Hardware network interface card (e.g. `Intel Ethernet Controller E810-XXVDA2`, `Broadcom NetXtreme-E BCM57414`, `Mellanox ConnectX-6 Dx`). Includes BCG link. | Clicking opens certified controller entry on Broadcom VCG for I/O devices. | [Broadcom VCG — IO Devices](https://compatibilityguide.broadcom.com/search?program=io) |
| **Vendor / Manufacturer** | OEM network silicon manufacturer (Intel, Broadcom, NVIDIA/Mellanox, Marvell/QLogic). | Determines driver architecture (`native` vs `vmkusb`) and hardware offload engines. | [vSphere Networking Guide](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-networking/index.html) |
| **Installed Firmware** | Current controller firmware/NVM release installed on the adapter. | Must match certified releases on the VMware Compatibility Guide to prevent link dropouts. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |
| **Driver / FW Alignment** | Evaluates whether installed firmware matches certified driver pairing in the Broadcom HCL database. | Mismatched combinations risk kernel panics, packet drops, or link negotiation failures. | [vSphere Lifecycle Manager](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-lifecycle-manager/index.html) |
| **vSAN ESA 25 GbE Baseline**| Network bandwidth assessment: flags whether server has &ge;2 dedicated or shared 25 GbE ports. | **Mandatory Requirement:** vSAN ESA requires minimum 25 GbE interfaces; 10 GbE is restricted to vSAN OSA. | [vSAN ESA Networking Guide](https://core.vmware.com/resource/vsan-esa-networking) |

---

### 6.2 Physical Ports & Link Speed Ratings {#network-ports-table}

The physical ports table details every network uplink available on the server:

| Port Column | Description & Evaluation Logic | Deployment Planning Significance | External Documentation |
|---|---|---|---|
| **Port Identifier** | Physical interface name (e.g. `NIC.Embedded.1-1-1`, `Slot 1 Port 1`, `vmnic0`). | Maps physical cabling to ESXi uplink adapters during switch configuration. | [vSphere Uplink Mapping](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-networking/GUID-A9648937-2E89-4DF5-BF7D-F3C6DDAE3C98.html) |
| **Negotiated Speed** | Current physical link bandwidth: `100 Gbps`, `25 Gbps`, `10 Gbps`, `1 Gbps`. Active &ge;25G links highlighted green (`2x25G^`). | Confirms that uplinks are negotiated at rated speed and not degraded to lower link rates. | [vSAN ESA Performance Best Practices](https://core.vmware.com/resource/vsan-esa-networking) |
| **Link Status** | Physical carrier state: `✓ Up` (Green) or `✗ Down` (Red). Selective red highlighting isolates disconnected uplinks. | Unconnected down ports alert technicians to unplugged patch cables or inactive switch ports. | [Broadcom KB 1003780](https://kb.vmware.com/s/article/1003780) |
| **Hardware MAC** | Permanent hardware MAC address programmed in physical NIC EEPROM. | Used for switch port security, static DHCP leases, and vSphere Distributed Switch port binding. | [vSphere VDS Configuration](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-networking/index.html) |
| **Form Factor / Media** | Physical transceiver type: `SFP28` (25G), `QSFP28` (100G), `SFP+` (10G), or `10GBASE-T` (RJ45). | Validates physical optics compatibility with Top-of-Rack switch transceivers and DAC cables. | [IEEE 802.3by 25GbE Standard](https://standards.ieee.org/) |
| **RDMA Support** | Detects hardware RoCE v2 (RDMA over Converged Ethernet) or iWARP capabilities. | RoCE offloads CPU packet processing, significantly reducing latency in high-throughput vSAN clusters. | [vSAN over RDMA Guide](https://docs.vmware.com/en/VMware-vSphere/8.0/vsan-administration/GUID-3E6B4A38-95C4-4B2E-8B57-C18260197E63.html) |

---

### 6.3 LLDP & Cisco CDP Switch Neighbor Discovery {#tor-switch-discovery}

The assessment engine polls Layer 2 discovery protocols to reveal physical network topology without requiring in-band hypervisor access:

| Topology Field | Discovered Information & Evaluation Logic | Network Verification Significance |
|---|---|---|
| **Discovery Protocol** | Discovery protocol active on port: `LLDP` (IEEE 802.1AB standard) or `Cisco CDP`. | Verifies Layer 2 discovery broadcast propagation across server and switch ports. |
| **Switch Hostname / FQDN** | Hostname or fully qualified domain name reported by the upstream physical Top-of-Rack switch. | Validates rack cable wiring and confirms that dual-homed servers attach to redundant ToR switch pairs. |
| **Switch Port ID** | Physical switch interface description (e.g. `Ethernet1/1`, `TenGigabitEthernet0/1/2`). | Ensures cables connect to the designated switch ports allocated in datacenter port schedules. |
| **Switch Management IP** | Management IP address broadcast by the switch management plane. | Facilitates automated network switch auditing and configuration validation. |
| **Port Native VLAN** | VLAN ID configured as the native untagged VLAN on the switch trunk port. | Prevents VLAN hopping risks and validates that management VLANs align with network templates. |
| **MTU Size (Jumbo Frames)** | Maximum Transmission Unit configured on the switch port. Highlights standard `1500` vs jumbo `9000`. | **Best Practice:** vSAN ESA and Geneve overlay traffic require MTU 9000 to eliminate frame fragmentation. |

> 📖 **VMware Reference:** See [vSphere Distributed Switch LLDP Configuration](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-networking/GUID-A9648937-2E89-4DF5-BF7D-F3C6DDAE3C98.html).

---

### 6.4 Fibre Channel Host Bus Adapters (FC HBAs) {#fibre-channel-hbas}

When servers include Fibre Channel Host Bus Adapters, the tool captures SAN identity metrics for external storage integration:

| FC HBA Attribute | Description & Evaluation Logic | Storage Area Network (SAN) Significance | External Documentation |
|---|---|---|---|
| **Adapter Model** | Physical FC controller model (e.g. `Emulex LPe35002-M2 32Gb 2-Port`, `QLogic QLE2772 32Gb Dual Port`). Includes BCG link. | Clicking opens certified HBA entry on Broadcom VCG for storage controllers. | [Broadcom VCG — IO Devices](https://compatibilityguide.broadcom.com/search?program=io) |
| **Port WWPN** | World Wide Port Name: 64-bit unique optical port address (e.g. `10:00:00:10:9b:3a:4c:12`). | Mandatory identifier used by SAN storage administrators for Fibre Channel fabric switch zoning. | [vSphere Fibre Channel Storage](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-storage/GUID-A8333333-85D4-49E0-BCF5-29F7DC26D8B4.html) |
| **Node WWNN** | World Wide Node Name: 64-bit unique controller address common to all ports on the adapter. | Identifies the physical host endpoint across the storage fabric topology. | [vSphere SAN Configuration](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-storage/index.html) |
| **Port Speed** | Current optical link negotiation rate: `32 Gbps`, `16 Gbps`, `8 Gbps`. | Ensures Fibre Channel optics negotiate at full rated speeds with SAN switch directors. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |
| **Connection State** | Physical optical connection state (`Point-to-Point`, `Fabric`, `Down`). | Verifies that optical transceivers have established light and fabric login (FLOGI) with the SAN. | [vSphere Storage Troubleshooting](https://kb.vmware.com/s/article/1003683) |
| **SAN Zoning Readiness** | Validates that dual-port HBAs are present for multi-pathing (NMP) to external VMFS arrays. | Ensures enterprise storage high availability when attaching external SAN storage arrays. | [vSphere Multipathing Best Practices](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-storage/GUID-37CA5109-009A-40F9-9E6D-3E838F5F2B57.html) |

---

## 7. Expansion, Accelerators & System Health {#expansion-and-health}

Evaluates PCIe bus topologies, accelerator qualification for VMware Private AI Foundation workloads, power supply redundancy, thermal telemetry matrices, and BMC System Event Logs (SEL).

---

### 7.1 PCIe Expansion Slots & Lane Budget {#pcie-expansion-slots}

The PCIe expansion audit examines physical slot availability, bus generation, electrical lane width, and CPU socket lane allocation:

| PCIe Slot Metric | Technical Definition & Evaluation Logic | Infrastructure Sizing Significance | External Documentation |
|---|---|---|---|
| **Slot Identifier** | Physical motherboard or riser slot designation (e.g. `Slot 1`, `Slot 2 (CPU1)`, `OCP Slot 1`). | Guides physical card placement according to OEM riser card population rules. | [OEM Service Manuals](https://www.dell.com/support) |
| **Form Factor** | Mechanical slot length and profile: `Full-Height / Full-Length (FHFL)`, `Low-Profile (LP)`, `OCP 3.0 NIC`. | Ensures physical expansion cards fit within chassis riser clearances without obstructions. | [PCI-SIG Standards](https://pcisig.com/) |
| **PCIe Generation** | Bus signaling generation: `Gen 5 (32 GT/s)`, `Gen 4 (16 GT/s)`, `Gen 3 (8 GT/s)`. | High-throughput 100G/200G NICs and NVMe drives require Gen 4 or Gen 5 to prevent bus saturation. | [vSphere Hardware Sizing](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-host-administration/index.html) |
| **Slot Width (Max / Current)**| Electrical lane routing: physical mechanical width vs negotiated electrical lane count (e.g. `x16 / x8`). | Alerts if a high-speed card is operating in a degraded lane mode due to faulty riser seating. | [PCIe Troubleshooting](https://kb.vmware.com/s/article/1003780) |
| **Bifurcation Support** | Motherboard support for splitting PCIe lanes (e.g. splitting a x16 slot into `x4/x4/x4/x4`). | Mandatory when attaching multi-drive M.2/U.2 NVMe carrier cards to a single PCIe slot. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |
| **Populated Device** | Hardware device detected in the slot (e.g. `NVIDIA A100-PCIE-80GB`, `Broadcom BCM57414`). | Inventories all peripheral controller cards installed across the server expansion fabric. | [Broadcom VCG — IO Devices](https://compatibilityguide.broadcom.com/search?program=io) |
| **PCIe Lane Budget** | Aggregated lane consumption tracked against CPU root complex lane limits (e.g. 64 or 128 lanes/CPU). | Prevents oversubscribing CPU I/O lanes when adding multiple NVMe risers and GPU accelerators. | [Intel/AMD Platform Architecture](https://www.intel.com/) |

---

### 7.2 GPU Accelerators & Private AI Readiness {#gpu-accelerators-private-ai}

Hardware accelerators are audited to qualify the server node for enterprise artificial intelligence, machine learning, and high-performance computing workloads:

| GPU Attribute | Description & Evaluation Logic | VMware Private AI Readiness | External Documentation |
|---|---|---|---|
| **GPU Model** | Physical accelerator model (e.g. `NVIDIA A100-PCIE-80GB`, `NVIDIA H100 NVL`, `NVIDIA L40S`, `AMD Instinct MI300X`). Includes BCG link. | Clicking opens certified accelerator listing on Broadcom VCG for shared and direct-attached PCIe devices. | [Broadcom VCG — Shared PCIe](https://compatibilityguide.broadcom.com/search?program=gpu) |
| **Manufacturer** | Silicon vendor: `NVIDIA`, `AMD`, or `Intel`. | Dictates hypervisor driver package (NVIDIA AI Enterprise VIB vs standard kernel driver). | [VMware Private AI Foundation](https://docs.vmware.com/en/VMware-Cloud-Foundation/services/vcf-private-ai-deployment/GUID-A934E26F-D2E4-42B1-8C1A-2C3C58B3A829.html) |
| **VRAM Capacity** | Total onboard GPU memory (e.g. `80 GB HBM2e`, `48 GB GDDR6`). | Determines maximum parameter size of Large Language Models (LLMs) runnable on the physical host. | [vSphere vGPU Sizing Guide](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-host-administration/index.html) |
| **Bus Location (BDF)** | PCI Bus / Device / Function address (e.g. `0000:3b:00.0`). | Used for DirectPath I/O PCI pass-through mapping and NVIDIA vGPU profile allocation. | [vSphere DirectPath I/O](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-networking/GUID-A845C227-2C36-4700-B212-076AEF9B310A.html) |
| **Private AI Qualification** | Evaluates whether GPU model is certified for VMware Private AI Foundation with NVIDIA. | Confirms support for hardware-accelerated inferencing, model fine-tuning, and vector databases. | [VMware Private AI Deployment](https://docs.vmware.com/en/VMware-Cloud-Foundation/services/vcf-private-ai-deployment/index.html) |

---

### 7.3 Power Supply Units & Redundancy {#power-supply-units}

Power subsystem telemetry validates physical power redundancy, electrical load sharing, and energy efficiency across the server chassis:

| PSU Attribute | Technical Definition & Evaluation Logic | Datacenter Resiliency Impact | External Documentation |
|---|---|---|---|
| **Installed PSU Count** | Number of physical power supplies installed in chassis bays (typically 2 or 4). | Enterprise clusters require minimum 2 power supplies to provide electrical redundancy. | [vSphere Resiliency Guide](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-availability/index.html) |
| **Redundancy State** | Power operational mode: `🟢 Redundant` (N+1 healthy) or `🟡 Single / Degraded`. | **High Availability Risk:** Non-redundant power exposes the node to unexpected power outages. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |
| **Rated Capacity (W)** | Maximum rated output power per unit (e.g. `1100 Watts`, `1600 Watts`, `2400 Watts`). | High-power dual-socket nodes equipped with high-TDP CPUs and GPUs require 1600W+ supplies. | [OEM Power Sizing Calculators](https://www.dell.com/support) |
| **Input Line Voltage** | Operating electrical input feed: `High Line (200–240 VAC)` or `Low Line (100–120 VAC)`. | Low-line 120V feeds derate maximum PSU wattage output by up to 50% on large supplies. | [Datacenter Power Standards](https://www.ashrae.org/) |
| **Current Power Draw** | Real-time electrical power consumed by the system chassis (Watts). | Used for rack power budget planning, phase balancing, and cooling load calculations. | [vSphere Power Management](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-monitoring-and-performance/index.html) |
| **PSU Firmware & Serial** | Individual power supply firmware version and hardware serial number. | Needed for vendor power supply recall verification and firmware vulnerability patching. | [OEM Firmware Updates](https://www.dell.com/support) |

---

### 7.4 Thermal Sensor Matrix & Fan Telemetry {#thermal-sensor-matrix}

Thermal telemetry tracks temperature sensors and cooling fan assemblies to detect airflow bottlenecks and cooling failures:

| Thermal Metric | Description & Evaluation Logic | Operational Thresholds & Action |
|---|---|---|
| **Ambient Intake Temp** | Front chassis intake temperature sensor measuring incoming room airflow. | **<27°C:** Normal ASHRAE Class A2 datacenter standard; >35°C indicates rack cooling failure. |
| **Exhaust Temperature** | Rear chassis exhaust sensor measuring heat expelled from server components. | High exhaust temp (>50°C) with low intake indicates internal component overheating. |
| **CPU Core Temperatures** | Internal digital thermal sensors (DTS) embedded in physical CPU dies. | **<75°C:** Normal operating range; >85°C causes thermal throttling; >100°C triggers emergency shutdown. |
| **GPU Temperatures** | Core and HBM memory temperatures reported by physical GPU accelerators. | High temperatures trigger GPU clock throttling, drastically reducing AI inferencing throughput. |
| **Storage Temperatures** | Highest temperature reported across all drive bay NVMe/SAS storage devices. | **<70°C:** Drives exceeding 75°C trigger OCP warning composite alerts. |
| **Fan Speeds & PWM Duty** | Cooling fan rotational speeds in RPM and pulse-width modulation (PWM) percentage. | Fans running sustained 100% PWM indicate thermal stress, blocked chassis filters, or fan failure. |
| **Fan Redundancy State** | Status of cooling fan matrix: `Redundant` or `Degraded`. | Lost fan redundancy risks rapid thermal runaway under heavy cluster workloads. |

---

### 7.5 System Event Log (SEL / IML Alarms) {#system-event-log}

The assessment engine aggregates active and historical events from the BMC System Event Log (SEL) or Integrated Management Log (IML):

| Log Dimension | Description & Evaluation Logic | Hardware Triage Value | External Documentation |
|---|---|---|---|
| **Event Severity** | Event urgency level: `✗ Critical`, `▲ Warning`, or `ℹ Informational`. | Critical events highlight uncorrectable hardware failures that block node commissioning. | [vSphere Monitoring and Health](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-monitoring-and-performance/GUID-074EFB79-1C52-4742-89BE-44585B17B493.html) |
| **Reporting Subsystem** | Hardware domain: `Processor`, `Memory ECC`, `Power Supply`, `Storage`, `Thermal`, `BIOS`. | Pinpoints the exact hardware subsystem responsible for the event. | [OEM Service Diagnostics](https://www.dell.com/support) |
| **Sensor Target ID** | Specific physical part or sensor name (e.g. `DIMM_A1`, `PSU 2`, `Drive 3`, `Temp Sensor 1`). | Identifies the physical field-replaceable unit (FRU) requiring technician replacement. | [OEM Part Replacement](https://www.dell.com/support) |
| **Diagnostic Description** | Full vendor fault message (e.g. `Uncorrectable multi-bit ECC error`, `Predictive drive failure`, `Power supply input lost`). | Provides diagnostic error strings for rapid vendor support ticket logging and warranty RMA. | [Broadcom KB 2006336](https://kb.vmware.com/s/article/2006336) |
| **Event Timestamp** | Precise UTC timestamp of the logged event. | Correlates hardware anomalies with hypervisor crash dumps, network events, or power maintenance. | [vSphere Logging Architecture](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-monitoring-and-performance/index.html) |

#### Multi-Vendor Event Resolution & Deep-Linking Engine (`sel_links.py`)

Rather than presenting cryptic hexadecimal codes or static text, the assessment engine integrates an offline multi-vendor reference catalog that transforms raw BMC events into actionable, clickable links to authoritative OEM troubleshooting manuals:

1. **Dell PowerEdge EEMS & Raw IPMI Hex Mapping:**
   - **Canonical Multi-Generation URLs:** Uses canonical multi-generation reference URLs (`poweredge-r740xd/error_event_message_guide_c/`) bound to verified DITA chapter GUIDs for 20+ hardware categories (`SEC`, `PSU`, `RDU`, `PDR`, `HWC`, `MEM`, `PST`, `BOOT`, `CTL`, `PCI`, `TMP`, `TMPS`, `VLT`, `OSE`, `CUMP`, `FLDC`, `NINT`, `NNOD`, `NVCH`, `SEL`, `SRV`, `TST`).
   - **Raw IPMI Hex Code Translation:** Automatically translates 76 distinct raw IPMI sensor hexadecimal event strings into canonical EEMS topics (e.g. CPU machine check `07a60140`, memory self-healing `07a3c001`/`07a7c140`, multi-bit ECC `6fa1c001`, PCIe fatal bus errors `6fa91800`–`6fac283c`, BIOS halting `6f0fd0ff`, cooling threshold `01520004`, and dynamic drive bay removal `efa00100` &rarr; `PDR1016`).
   - **Safe Fallback Routing:** Unknown or unindexed event prefixes route safely to the Master Reference Guide Root Index, eliminating "Topic not found" errors.

2. **HPE ProLiant IML Direct Deep-Linking:**
   - Decodes HPE Redfish Integrated Management Log (IML) message conventions where events are structured as `<class_decimal>.<code_decimal>` (e.g. `19.22` for storage predictive failure, `2.35` for fan redundancy, `10.5920` for SMART drive replacement, `51.7` for backplane management, `50.1122` for uncorrectable memory threshold).
   - Generates direct topic URLs into the official *HPE Gen12 IML Troubleshooting Guide* (`https://support.hpe.com/hpesc/public/docDisplay?docId=ilogen12-msg-en_us&page=class0x{c:04x}code0x{code:04x}-gen12.html`) with contextual display badges.

3. **Cisco UCS IMC Faults Catalog:**
   - Built-in catalog maps all 114 standard `F\d{4}` fault codes (e.g. `F0409`, `F0462`, `F0510`, `F0744`, `F1008`, `F1744`), 116 named `flt*` symbols (`fltEquipmentFanDegraded`, `fltBiosUnitFD0FailedSecurityVerification`), and component prefixes directly to corresponding chapters in the *Cisco UCS Integrated Management Controller Faults Reference Guide*.

4. **Authoritative Guide Catalog Badges:**
   - Single-host and fleet inventory SEL tables render direct clickable links on Message ID cells.
   - Header badges provide one-click access to authoritative vendor documentation:
     - **Dell:** PowerEdge Error and Event Messages Guide (EEMS)
     - **HPE:** IML Messages and Troubleshooting Guide (Gen10 / Gen11 / Gen12)
     - **Cisco:** UCS Integrated Management Controller Faults Reference Guide
     - **Lenovo:** ThinkSystem XClarity Controller Events Guide
     - **Supermicro:** BMC IPMI User's Guide

---

## 8. BIOS & Platform Configuration {#bios-and-platform-configuration}

Audits system firmware release versions, boot mode architecture, CPU power management policies, memory RAS modes, Intel Volume Management Device (Intel VMD) configuration, and hardware virtualization flags.

---

### 8.1 BIOS Version Baselines & UEFI Boot Mode {#uefi-boot-mode}

System firmware provides the foundational hardware abstraction layer between server silicon and the VMware ESXi 9.1 hypervisor kernel:

| BIOS / Platform Setting | Technical Definition & Evaluation Logic | VCF 9.1 Deployment Impact | External Documentation |
|---|---|---|---|
| **BIOS Firmware Version** | Installed system BIOS/UEFI firmware build version string. | Must meet or exceed OEM certified minimum release matrix for VMware ESXi 9.1 compatibility. | [Broadcom Compatibility Guide](https://compatibilityguide.broadcom.com/) |
| **Firmware Release Date** | OEM release date of the installed BIOS build. | Highlights aging firmware; builds older than 18 months lack critical CPU microcode errata fixes. | [vSphere Lifecycle Manager](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-lifecycle-manager/index.html) |
| **Boot Mode Architecture**| System firmware boot mode: `✓ UEFI` (Green) or `✗ Legacy BIOS` (Red). | **Strict Blocker:** VMware Cloud Foundation 9.1 strictly mandates **UEFI** boot mode; Legacy BIOS is completely unsupported. | [vSphere ESXi Boot Mode Requirements](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-esxi-installation/GUID-69D2C4D3-7ED1-4CD8-87FA-5CF13106DCF8.html) |
| **Secure Boot Enforcement**| UEFI Secure Boot cryptographic signature validation status. | Ensures that only cryptographically signed hypervisor kernels, drivers, and VIBs execute during host initialization. | [Broadcom KB 2147606](https://kb.vmware.com/s/article/2147606) |

---

### 8.2 CPU Power Management Profiles {#cpu-power-management}

Power management policies configured in system BIOS directly impact compute latency, CPU frequency scaling, and storage I/O throughput:

| BIOS Power Setting | Operational Configuration | Performance & vSAN ESA Impact | External Documentation |
|---|---|---|---|
| **Maximum Performance (`✓ Performance`)** | Sets System Profile to **Maximum Performance** or **Custom OS Control**; disables C-states (C1E, C6) and PCIe Active State Power Management (ASPM). | **Required for vSAN ESA:** Prevents processor down-clocking during idle-to-burst transitions, eliminating storage I/O latency spikes. | [Broadcom KB 1018206](https://kb.vmware.com/s/article/1018206) |
| **Energy Efficient (`▲ Power Saving`)** | Enables aggressive hardware dynamic power throttling and CPU deep sleep states. | **Suboptimal / Warning:** Causes CPU core wake-up latencies of 50–200 µs, significantly degrading vSAN ESA NVMe sub-millisecond I/O. | [vSphere Performance Best Practices](https://core.vmware.com/resource/vsphere-performance-best-practices) |
| **OS Control Mode** | Permits the VMware ESXi Host Power Management (HPM) governor (DPM / Balanced) to regulate CPU P-states dynamically. | Acceptable alternative when corporate green datacenter policies mandate power savings under low utilization. | [vSphere Host Power Management](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-resource-management/GUID-4D0E2393-855E-4952-B488-82E9DF2652E2.html) |

---

### 8.3 Memory RAS Modes {#memory-ras-modes}

Reliability, Availability, and Serviceability (RAS) settings dictate how physical DIMMs are mapped into host memory address spaces:

| Memory RAS Policy | Architecture & Operating Mode | Usable Capacity & Throughput Impact | Recommended Workload |
|---|---|---|---|
| **Optimized / Advanced ECC** | Standard independent channel mode; provides 100% of physical DIMM capacity and maximum multi-channel interleaving bandwidth. | **Recommended Baseline:** Delivers full memory bandwidth and maximum VM density for VCF workload domains. | General VCF Workload Domains, vSAN ESA, High-Performance Compute |
| **Memory Mirroring** | Replicates memory contents in real time across paired memory channels to survive catastrophic physical DIMM failures. | **Capacity Penalty:** Sacrifices **50% of total installed RAM**; triggers a capacity sizing alert during cluster assessment. | Mission-critical financial/healthcare systems with zero tolerance for uncorrectable ECC crashes |
| **Memory Rank Sparing** | Reserves one memory rank per channel as a hot standby to replace failing ranks upon reaching ECC error thresholds. | **Capacity Penalty:** Reduces total usable RAM by 12.5% to 25%; useful only in remote sites with delayed technician RMA access. | Edge or ROBO clusters where onsite hardware dispatch requires multiple days |
| **Fault Tolerant Memory (FTM) / ADDDC** | Adaptive Double Device Data Correction (ADDDC) dynamically maps out failing DRAM chips without taking the host offline. | Negligible capacity impact (~0%); slight latency increase when virtual lockstep engages. | Enterprise database clusters requiring high uptime with full usable RAM capacity |

#### OEM Memory Population & Channel Architecture Guides {#oem-memory-population-guides}

Memory RAS modes operate in strict conjunction with physical DIMM slot population topologies. Installing DIMMs in unbalanced configurations or violating vendor channel population rules forces memory controllers into degraded single-channel or asymmetric interleaving modes, reducing memory bus throughput by 15% to 35% and preventing advanced RAS protection modes from initializing.

The tables below provide architectural baselines and direct links to official memory population guides across the last three enterprise server generations for Dell PowerEdge and HPE ProLiant:

##### Dell PowerEdge Memory Population Guides (Last 3 Generations)

| Server Generation | Representative Platforms & Processors | Memory Architecture & Channels | RAS Population Rules & Constraints | Official OEM Documentation Links |
|---|---|---|---|---|
| **16th Generation (16G)** | PowerEdge R760, R660, R7625, R7615<br>(4th/5th Gen Intel Xeon Scalable Sapphire Rapids / Emerald Rapids; AMD EPYC 9004 Genoa/Bergamo) | **DDR5 Registered DIMMs (RDIMM)**<br>• 8 memory channels per CPU (16 DIMMs per CPU, 32 total on 2S)<br>• Up to 4800 / 5600 MT/s (1 DPC) | • Populate white release tab slots first (1 DPC).<br>• Populating 2 DPC (32 DIMMs) throttles clock speed from 4800/5600 MT/s down to 4400 MT/s.<br>• Performance Optimized mode requires symmetrical DIMM capacities and ranks across all 8 channels per socket.<br>• Mixing DRAM types (e.g. standard RDIMM with 3DS RDIMM) is unsupported. | • [Dell PowerEdge R760 System Memory Guidelines](https://www.dell.com/support/manuals/en-us/poweredge-r760/per760_ism_pub/system-memory-guidelines)<br>• [Dell PowerEdge R760 Technical Guide](https://www.delltechnologies.com/asset/en-us/products/servers/technical-support/poweredge-r760-technical-guide.pdf)<br>• [Dell PowerEdge Memory RAS Features Overview](https://www.dell.com/support/kbdoc/en-us/000116150/dell-poweredge-memory-ras-features) |
| **15th Generation (15G)** | PowerEdge R750, R650, R7525, R7515<br>(3rd Gen Intel Xeon Scalable Ice Lake; AMD EPYC 7003 Milan) | **DDR4 RDIMM / LRDIMM**<br>• 8 memory channels per CPU (16 DIMMs per CPU, 32 total on 2S)<br>• Up to 3200 MT/s | • Channels A–H organized in dual-slot pairs.<br>• Always populate primary slots (A1–A8, B1–B8) before secondary slots (A9–A16, B9–B16).<br>• Fault Resilient Mode (ADDDC) requires x4 DRAM organization and homogeneous rank layout.<br>• Mirroring mode requires identical paired configurations across channel pairs. | • [Dell PowerEdge R750 System Memory Guidelines](https://www.dell.com/support/manuals/en-us/poweredge-r750/per750_ism_pub/system-memory-guidelines)<br>• [Dell PowerEdge R750 BIOS Memory Settings Reference](https://www.dell.com/support/manuals/en-us/poweredge-r750/per750_bios_pub_ism/memory-settings)<br>• [Dell PowerEdge R750 Technical Guide](https://i.dell.com/sites/csdocuments/product_docs/en/poweredge-r750-technical-guide.pdf) |
| **14th Generation (14G)** | PowerEdge R740, R640, R7425, R7415<br>(1st/2nd Gen Intel Xeon Scalable Skylake-SP / Cascade Lake; AMD EPYC 7001 Naples) | **DDR4 RDIMM / LRDIMM**<br>• 6 memory channels per CPU (12 DIMMs per CPU, 24 total on 2S)<br>• Up to 2666 / 2933 MT/s | • Full interleaving (100% bandwidth) requires 6 or 12 DIMMs per processor socket.<br>• 4 and 8 DIMM configurations use non-traditional population sequences (slots 1, 2, 4, 5 for 4 DIMMs; slots 1, 2, 4, 5, 7, 8, 10, 11 for 8 DIMMs).<br>• Mirroring supported only with 6 or 12 DIMMs per CPU.<br>• Single/Multi-Rank Sparing requires minimum 2 or 3 ranks per populated channel. | • [Dell PowerEdge R740 Mode-Specific Memory Guidelines](https://www.dell.com/support/manuals/en-us/poweredge-r740/per740_ism_pub/mode-specific-guidelines)<br>• [Dell PowerEdge R740 General Installation Guidelines](https://www.dell.com/support/manuals/en-us/poweredge-r740/per740_ism_pub/general-memory-module-installation-guidelines) |

##### HPE ProLiant Memory Population Guides (Last 3 Generations)

| Server Generation | Representative Platforms & Processors | Memory Architecture & Channels | RAS Population Rules & Constraints | Official OEM Documentation Links |
|---|---|---|---|---|
| **Gen11** | ProLiant DL380 Gen11, DL360 Gen11, ML350 Gen11, DL560 Gen11<br>(4th/5th Gen Intel Xeon Scalable Sapphire Rapids / Emerald Rapids; AMD EPYC 9004) | **DDR5 SmartMemory RDIMM**<br>• 8 memory channels per CPU (16 DIMMs per CPU, 32 total on 2S)<br>• Up to 4800 / 5600 MT/s | • White DIMM slots denote first slot in each channel (1 DPC priority).<br>• Slot population order is strictly mandated (e.g. single DIMM must use slot 10; 2 DIMMs use slots 3 & 10; balanced configurations require populating all 8 white slots: 1, 3, 6, 8, 10, 12, 14, 16).<br>• Fast Fault Tolerance (ADDDC) and Advanced ECC require balanced socket loading.<br>• Mixing x4 and x8 DRAM organizations across a socket is disallowed. | • [HPE Gen11 Server Memory Population Rules (a50007437enw)](https://www.hpe.com/psnow/doc/a50007437enw)<br>• [HPE ProLiant DL380 Gen11 QuickSpecs & Memory Rules](https://www.hpe.com/us/en/collaterals/collateral.a50004307enw.html)<br>• [HPE Server Memory Population Rules Portal](https://www.hpe.com/docs/memory-population-rules) |
| **Gen10 Plus** | ProLiant DL380 Gen10 Plus, DL360 Gen10 Plus<br>(3rd Gen Intel Xeon Scalable Ice Lake; AMD EPYC 7002/7003 Rome / Milan) | **DDR4 SmartMemory RDIMM / LRDIMM**<br>• 8 memory channels per CPU (16 DIMMs per CPU, 32 total on 2S)<br>• Up to 3200 MT/s | • Requires even quantities of DIMMs per socket; odd DIMM counts generate UEFI POST warnings and create asymmetric bus penalties.<br>• Mixing RDIMM and LRDIMM is strictly prohibited.<br>• Memory Mirroring requires paired channel configuration with identical DIMMs.<br>• AMD EPYC models require population in multiples of 4 or 8 DIMMs for optimal NUMA NPS1/NPS4 interleaving. | • [HPE Gen10 Plus Intel Xeon Memory Population Rules (a50003886enw)](https://www.hpe.com/psnow/doc/a50003886enw)<br>• [HPE ProLiant DL380 Gen10 Plus QuickSpecs](https://www.hpe.com/us/en/collaterals/collateral.a50002553enw.html)<br>• [HPE Gen10 / Gen10 Plus AMD EPYC Population Whitepaper (a00038346enw)](https://www.hpe.com/psnow/doc/a00038346enw.pdf) |
| **Gen10** | ProLiant DL380 Gen10, DL360 Gen10, ML350 Gen10, DL560 Gen10<br>(1st/2nd Gen Intel Xeon Scalable Skylake-SP / Cascade Lake) | **DDR4 SmartMemory RDIMM / LRDIMM**<br>• 6 memory channels per CPU (12 DIMMs per CPU, 24 total on 2S)<br>• Up to 2666 / 2933 MT/s | • 6-channel architecture requires 6 identical DIMMs (1 DPC) or 12 identical DIMMs (2 DPC) per socket for 100% memory bandwidth.<br>• Population sequence begins at slot 8 (single DIMM), then slots 8 & 10 (2 DIMMs), slots 8, 10, 1 (3 DIMMs), etc.<br>• Online Sparing requires minimum dual-rank DIMMs; Mirrored Memory requires 12 DIMMs per socket (dual-rank or quad-rank). | • [HPE Gen10 Intel Xeon Memory Population Rules (a00017079enw)](https://www.hpe.com/psnow/doc/a00017079enw)<br>• [HPE ProLiant Gen10 DDR4 Standard Memory Rules (a00058337enw)](https://www.hpe.com/psnow/doc/a00058337enw)<br>• [HPE Gen10 Advanced Memory Protection Tech Brief (a00018421en_us)](https://www.hpe.com/psnow/doc/a00018421en_us) |

> 💡 **VCF Sizing & Readiness Recommendation**: For both VCF Management and Workload Domains, configure memory in **Performance Optimized** (Dell) or **Advanced ECC / Fast Fault Tolerance** (HPE) mode with 100% symmetrical channel population (1 DPC or 2 DPC across all channels). Avoid Memory Mirroring unless mandated by specialized regulatory compliance, as the 50% capacity reduction directly impacts cluster host counts and vSAN ESA cost-per-gigabyte metrics. If the assessment tool reports `🟡 Suboptimal Interleaving` or `🔴 Degraded / Single-Channel`, cross-reference the installed DIMM slot map in the Detailed Inventory panel against the OEM population tables above to rebalance physical DIMMs prior to ESXi installation.

---

### 8.4 Intel Volume Management Device (Intel VMD) Pass-Through {#intel-vmd-passthrough}

Intel Volume Management Device (VMD) is an integrated processor hardware logic block that manages NVMe PCIe root ports:

| Intel VMD Configuration | Technical Operation | vSAN ESA Compatibility Status | External Documentation |
|---|---|---|---|
| **VMD Disabled (`✓ Off - Pass-thru Ready`)** | PCIe lanes are routed directly from CPU root complexes to NVMe drive backplanes. | **Fully Supported & Required:** The VMware ESXi native NVMe driver (`vmknvme`) takes direct ownership of drive PCIe registers. | [Broadcom KB 88602](https://kb.vmware.com/s/article/88602) |
| **VMD Enabled (`✗ On - Driver Blocker`)** | Intel VMD aggregates NVMe drives under an Intel VMD endpoint controller (`8086:201d`). | **Strict Blocker:** Intercepts PCIe interrupts and masks drive telemetry, completely disqualifying drives from vSAN ESA. | [Broadcom KB 88602](https://kb.vmware.com/s/article/88602) |

---

### 8.5 Virtualization & Platform Processor Flags

The assessment engine verifies that mandatory silicon virtualization extensions and hardware security primitives are activated in BIOS:

| Hardware Processor Flag | Technical Feature | Hypervisor Functionality Enabled |
|---|---|---|
| **Intel VT-x / AMD-V** | Silicon hardware-assisted CPU virtualization. | Mandatory for VMware ESXi hypervisor execution and virtual machine guest execution. |
| **Intel VT-d / AMD IOMMU** | Direct I/O memory management unit virtualization. | Required for DirectPath I/O PCI pass-through (SR-IOV, GPU passthrough, and vSAN NVMe controllers). |
| **SR-IOV** | Single Root I/O Virtualization. | Allows physical PCIe network adapters to partition virtual functions (VFs) directly into VM guest workloads. |
| **NX / XD (No-Execute Bit)**| Hardware memory execution prevention. | Protects the hypervisor and guest operating systems against buffer overflow exploits and code injection attacks. |

---

## 9. Key Anchor: BMC Hardware Security Audit Findings {#bmc-hardware-security-audit-findings}

This section serves as the definitive architectural reference for the out-of-band management controller security audit, baseline compliance frameworks, OEM hardening guidelines, and automated remediation procedures.

Out-of-band Baseboard Management Controllers (Dell iDRAC, HPE iLO, Lenovo XCC, Cisco IMC, Supermicro BMC, Intel BMC) operate with persistent access to server motherboards, PCIe buses, physical memory, and system firmware. Securing these interfaces is a non-negotiable prerequisite for enterprise VMware Cloud Foundation (VCF) 9.1 deployments.

---

### 9.1 Platform Cryptographic Security (TPM 2.0 & Secure Boot) {#platform-cryptographic-security}

Platform security combines hardware-rooted cryptographic identity with firmware boot integrity validation:

| Platform Security Feature | Evaluation Logic & Technical Standard | VCF 9.1 Mandate & Compliance Role | External Documentation |
|---|---|---|---|
| **TPM 2.0 Cryptoprocessor** | Validates presence of physical Trusted Platform Module (TPM) 2.0 chip enabled in UEFI mode. | **Mandatory Requirement:** Required for ESXi 9.1 Secure Boot attestation, cryptographic core isolation, and vSphere Native Key Provider. | [vSphere Security Guide — TPM 2.0](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-security/GUID-10F7022C-DBE0-4E80-9285-EB02CEF513A1.html) |
| **UEFI Secure Boot** | Audits UEFI signature verification for bootloaders, hypervisor kernel, and VIB kernel modules. | Ensures only cryptographically signed VMware binaries execute during POST; blocks bootkits and unauthorized rootkits. | [Broadcom KB 2147606](https://kb.vmware.com/s/article/2147606) |
| **Side-Channel Mitigations**| Evaluates processor microcode against Broadcom security baselines (Tier 1–Tier 4). | **Tier 4 Required:** Protects hypervisor and guest VM boundaries against Spectre, Meltdown, L1TF, MDS, and SRBDS. | [Broadcom KB 330041](https://kb.vmware.com/s/article/330041) |
| **BMC Firmware Baseline** | Compares BMC firmware build against certified OEM security maintenance baselines. | Mitigates published remote code execution (RCE) and memory corruption vulnerabilities in BMC daemons. | [OEM Reference Guide](docs/OEM_REFERENCE.md) |

---

### 9.2 BMC Security Posture Rollup & Risk Ratings {#bmc-security-posture-rollup}

The assessment engine aggregates individual control findings into a deterministic host security posture score:

#### Posture Classifications
1. **🟢 Baseline Met (`posture: "Baseline Met"`):**
   - All evaluated security controls passed the hardening standard.
   - Zero critical or high-priority vulnerabilities detected.
2. **🟡 Partially Assessed (`posture: "Partially Assessed"`):**
   - **Honesty Rule:** Unknown controls never count as a pass. If certain OEM attributes could not be queried via Redfish, the posture is classified as partially assessed rather than claiming compliance.
3. **🔴 Action Required (`posture: "Action Required"`):**
   - High-priority security failures detected (e.g. active Telnet, default root password, unencrypted IPMI-over-LAN).
   - Remediation is strictly required prior to commissioning nodes into enterprise clusters.

#### Prioritized Issue Badges
- **Critical Issues (Red Badges):**
  - `✗ Telnet`: Legacy unencrypted remote shell active on TCP port 23.
  - `✗ Default Pwd`: Unrotated factory default administrative password detected on root account.
  - `✗ TLS < 1.2`: Insecure cryptographic protocols (SSL 3.0, TLS 1.0, TLS 1.1) permitted on BMC web interfaces.
- **High-Priority Concerns (Amber Badges):**
  - `▲ HTTP`: Unencrypted plaintext web management interface exposed on TCP port 80.
  - `▲ IPMI LAN On`: Legacy IPMI-over-LAN active; vulnerable to RMCP+ Cipher 0 authentication bypass ([Broadcom KB 2046632](https://kb.vmware.com/s/article/2046632)).
  - `▲ No Lockout`: Account lockout threshold disabled, leaving the BMC exposed to automated brute-force attacks.
  - `▲ Host Pass-Through`: Virtual USB / Host-to-BMC network pass-through enabled; creates a hypervisor-to-BMC boundary escape path ([Broadcom KB 82435](https://kb.vmware.com/s/article/82435)).
  - `▲ Weak Ciphers`: Insecure symmetric ciphers (<256-bit) or obsolete hashing algorithms permitted.
  - `▲ No Syslog`: Out-of-band audit logging not forwarded to a central SIEM/syslog collector.
  - `▲ USB Mgmt`: Unrestricted local physical USB direct management port left enabled on server bezel.

---

### 9.3 Comprehensive 84-Control Security Audit Catalog {#bmc-84-control-catalog}

The tool evaluates out-of-band management controllers against an 84-control security catalog organized into five architectural tiers:

#### Control Provenance and Architectural Lineage
Users and security auditors frequently ask where the `C01`–`C59` numbering and controls originate:
- **Origin of the C01–C59 Taxonomy (Dell iDRAC9 Normalization):** When the audit engine was established, Dell was the only server OEM with an exhaustive, setting-by-setting published hardening manual: the *Dell iDRAC9 Security Configuration Guide* (revision A01). This guide was normalized into 84 canonical controls: 59 configuration controls (`C01`–`C59`), 16 operational lifecycle recommendations (`O01`–`O16`), and 9 platform assurance capabilities (`I01`–`I09`).
- **Vendor-Neutral Governance:** The security intent of these controls is governed by authoritative non-OEM frameworks: the **CISA & NSA Joint CSI** (*Harden Baseboard Management Controllers*), **VMware Cloud Foundation Security Configuration Guide (SCG 9.1)**, and **NIST SP 800-193**. Exactly 36 of the 59 configuration controls represent universal baseline hardening standards.
- **Three-Tier Multi-OEM Portability Model:**
  - **Tier 1: 8 Universal DMTF Standards (`C09, C21, C23, C24, C29, C37, C43, C53`):** Implemented purely via standard DMTF Redfish schemas (`ManagerNetworkProtocol`, `AccountService`, `CertificateService`, `SecureBoot`) and evaluated identically across all server manufacturers (including Intel Server Systems and Supermicro).
  - **Tier 2: 40 Portable Concepts (`C01–C08, C10–C17, C20, C22, C25–C28, C33–C36, C38–C42, C44–C47, C49–C52, C54`):** Vendor-neutral hardening concepts where underlying attributes differ by OEM. Resolved through dedicated OEM adapters (Dell `DellAttributes`, HPE iLO `SecurityService`, Lenovo XCC Security Mode, Cisco CIMC).
  - **Tier 3: 11 Dell-Specific Controls (`C18, C19, C30, C31, C32, C48, C55, C56, C57, C58, C59`):** Proprietary Dell features (e.g. Dell System Lockdown, SEKM, Group Manager, Lifecycle Controller import/export, Field Service Debug). Evaluated strictly as **`not_applicable`** on HPE, Lenovo, Cisco, Supermicro, and Intel platforms.
  - **OEM Feature Gap Stubs (`G-*`):** Unique vendor capabilities not present in Dell's baseline (e.g. HPE iLO `SecurityState` and Cisco `CNSA`) are maintained as separate architectural gap stubs without altering the canonical `C01`–`C59` taxonomy.

#### Group 1: Baseline Hardening Controls (VCF SCG Alignment) (36 Controls)
| Control ID | Control Title | Hardening Criteria & Objective | Transport | Confidence |
|---|---|---|---|---|
| **C01** | HTTP-to-HTTPS Redirection | Force web clients onto HTTPS via iDRAC redirection. | Dell OEM Redfish | High |
| **C02** | Minimum TLS Version | Require TLS 1.2+ (prefer 1.3 where available). | Dell OEM Redfish | High |
| **C03** | TLS Encryption Strength | Prefer 256-bit or higher SSL encryption bit length. | Dell OEM Redfish | High |
| **C04** | TLS Cipher-Suite Restriction | Retain only strongest compatible suites; remove weak/DHE where applicable. | Dell OEM Redfish | High |
| **C05** | Trusted iDRAC Web Certificate | Replace unique self-signed default with CA-signed cert; unique key per controller. | Dell OEM Redfish | Medium |
| **C07** | Remote Syslog over TLS | Prefer secure remote syslog (e.g. TCP/6514) with CA validation. | Dell OEM Redfish | High |
| **C09** | SSH Service Exposure | Enable SSH only when required; prefer over Telnet. | Standard Redfish | High |
| **C11** | SSH Cryptographic Policy | No DSA; strong ciphers/KEX/MACs; no SHA-1/CBC weak sets. | Dell OEM Redfish | High |
| **C12** | Dedicated Management NIC | Prefer Dedicated NIC for BMC management. | Dell OEM Redfish | High |
| **C13** | Management VLAN | Enable management VLAN on BMC NIC. | Dell OEM Redfish | High |
| **C14** | USB Management & USB SCP | Disable unused USB management and USB XML/SCP configuration. | Dell OEM Redfish | High |
| **C15** | OS-to-iDRAC Pass-Through | Disable OS-BMC pass-through unless required; prefer USB-NIC mode if needed. | Dell OEM Redfish | High |
| **C16** | IP Login Blocking | Enable source-IP blocking after failed logins (window/penalty). | Dell OEM Redfish | High |
| **C17** | IP Allow-Range Filtering | Restrict BMC access to authorized management address ranges. | Dell OEM Redfish | High |
| **C18** | Auto-Discovery | Disable auto-discovery after provisioning. | Dell OEM Redfish | High |
| **C19** | Auto Config / SCP Provisioning | Disable unused Auto Config; require HTTPS if used. | Dell OEM Redfish | Medium |
| **C20** | Disable Unused Interfaces & Services | Disable unused Local Config, Web, SEKM, SSH, remote RACADM, SNMP, ASR, USB, pass-through, etc. | Dell OEM Redfish | Medium |
| **C21** | IPMI over LAN Disablement | IPMI-over-LAN disabled by default/recommendation. | Standard Redfish | High |
| **C22** | Serial over LAN Hardening | Disable Serial-over-LAN when unused (guide default enabled). | Dell OEM Redfish | High |
| **C23** | Telnet Service Disablement | Telnet disabled (removed in FW 4.40+). | Standard Redfish | High |
| **C24** | SNMP Service Exposure & SNMPv3 | Disable SNMP unless needed; if needed SNMPv3 only. | Standard Redfish | High |
| **C26** | SNMP Credentials & Cryptography | No default communities; SNMPv3 SHA/AES with separate auth/privacy passphrases. | Dell OEM Redfish | Medium |
| **C28** | Authenticated NTP | Use authenticated NTP; do not mix auth and unauth sources. | Dell OEM Redfish | High |
| **C29** | Redfish Session Authentication | Clients should use session token auth (POST session, X-Auth-Token, DELETE) not per-request Basic. | Standard Redfish | High |
| **C37** | Least-Privilege Roles & Session Timeout | Grant only required privileges; restrict Configure Users. | Standard Redfish | High |
| **C38** | Per-User IPMI Privilege | IPMI LAN/Serial privilege No Access for every user by default. | Dell OEM Redfish | High |
| **C39** | Per-User SNMPv3 Protection | SHA/AES, separate passphrases, protocol disabled when unused. | Dell OEM Redfish | Medium |
| **C40** | Password Quality Policy | Strong password policy (score/length/classes). | Dell OEM Redfish | High |
| **C41** | Default Password & Force Change | Change unique shipped password; enable FCP where required. | Dell OEM Redfish | Medium |
| **C42** | Two-Factor Authentication | Enable supported 2FA (Simple 2FA / RSA SecurID where licensed). | Dell OEM Redfish | Medium |
| **C43** | Central Directory Authentication & Lockout | Use AD or LDAP for centralized identities when required. | Standard Redfish | High |
| **C44** | Active Directory Certificate Validation | Enable AD cert validation and upload issuing CA. | Dell OEM Redfish | High |
| **C45** | LDAP Certificate Validation | Enable LDAP cert validation and upload issuing CA. | Dell OEM Redfish | High |
| **C46** | Disable Host-Local Reconfiguration | Disable Local RACADM and/or preboot iDRAC Settings when not required. | Dell OEM Redfish | High |
| **C48** | System Lockdown | Enable System Lockdown after provisioning. | Dell OEM Redfish | High |
| **C53** | UEFI Secure Boot | Secure Boot enabled with UEFI boot. | Standard Redfish | High |

#### Group 2: Conditional Hardening Controls (Environment Dependent) (16 Controls)
| Control ID | Control Title | Hardening Criteria & Objective | Transport | Confidence |
|---|---|---|---|---|
| **C06** | SCEP / Automated Certificate Enrollment | Enable SCEP only where automated enrollment is used; default disabled. | Dell OEM Redfish | Medium |
| **C08** | FIPS Mode | Enable FIPS where required; know that enabling resets config. | Dell OEM Redfish | High |
| **C10** | SSH Public-Key Authentication | Prefer PKI SSH auth with strong keys where used. | Dell OEM Redfish | Medium |
| **C25** | SNMP Network Isolation | Isolate SNMP with VLAN/ACL/physical separation from general networks. | External Process | High |
| **C27** | IPMI Fallback Hardening / Cipher 0 | If IPMI unavoidable: segment, IPMI 2.0, disable Cipher 0. | Vendor Tool | Low |
| **C33** | Virtual Console Client & Video Encryption | eHTML5 + video encryption enabled. | Dell OEM Redfish | High |
| **C34** | Virtual Console TLS & Web Redirection | TLS 1.2+, 256-bit, HTTPS web redirect for virtual console. | Dell OEM Redfish | High |
| **C35** | Virtual Media Encryption | Virtual media encryption enabled. | Dell OEM Redfish | Low |
| **C36** | VNC Server Hardening | Disable VNC unless needed; if enabled use 256-bit SSL + timeout; password write-only. | Dell OEM Redfish | High |
| **C47** | Security Login Banner | Custom authorized-use / monitoring banner. | Dell OEM Redfish | High |
| **C49** | BIOS Setup/System Passwords & Lock Status | Setup password + Password Status Locked where required. | Dell OEM Redfish | Medium |
| **C50** | BIOS Power-Button Control | Disable power button where local shutdown risk warrants. | Standard Redfish | Medium |
| **C51** | UEFI Variable Access | Prefer Controlled UEFI variable access. | Standard Redfish | Medium |
| **C52** | In-Band Manageability Interface | Disable host-side manageability when unused; enable during HECI/IPMI update workflows. | Standard Redfish | Medium |
| **C54** | Secure Boot Policy & Mode | Standard policy + Deployed Mode for normal operation. | Standard Redfish | Medium |
| **C55** | LCD / Control-Panel Restriction | View Only or Disabled LCD; optional disable ID-button reset. | Vendor Tool | Low |

#### Group 3: OEM Runbook & Procedural Controls (Dell-Specific) (7 Controls)
| Control ID | Control Title | Hardening Criteria & Objective | Transport | Confidence |
|---|---|---|---|---|
| **C30** | Secure Enterprise Key Manager (SEKM) | Use SEKM where centralized keys required; TLS/cert identity match KMS. | Dell OEM Redfish | Medium |
| **C31** | Group Manager Enablement | Disable Group Manager when unused. | Dell OEM Redfish | High |
| **C32** | Group Manager Network & Passcode | Dedicated mgmt network + strong shared passcode + rotation. | Dell OEM Redfish | Medium |
| **C56** | BIOS Live Scanning | Boot-time integrity checking + licensed live scans. | Vendor Tool | Low |
| **C57** | Secure Imports & Exports | Use HTTPS for inventory/LCL/SCP/license/update transfers. | Dell OEM Redfish | Medium |
| **C58** | Outbound HTTPS & Proxy Validation | Do not ignore cert warnings; validate outbound HTTPS; distinct proxy creds. | Dell OEM Redfish | Medium |
| **C59** | Field Service Debug (FSD) | FSD disabled except authorized Dell support engagement. | External Process | High |

#### Group 4: Operational Recommendations (Lifecycle & Governance) (16 Controls)
| Control ID | Control Title | Hardening Criteria & Objective | Transport | Confidence |
|---|---|---|---|---|
| **O01** | Isolated Management Network | Never expose BMC to Internet; dedicated mgmt network. | External Process | Varies |
| **O02** | Firmware Currency | Keep BMC/platform firmware current. | Standard Redfish | Varies |
| **O03** | Signed Update & Rollback | Use signed packages; investigate signature failures. | Standard Redfish | Varies |
| **O04** | Certificate Lifecycle | Inventory expiry; renew trust stores. | Vendor Tool | Varies |
| **O05** | FIPS Change Control | Export SCP before FIPS; verify after FW maintenance. | Dell OEM Redfish | Varies |
| **O06** | Credential & Passcode Rotation | Rotate passwords and Group Manager passcode. | Vendor Tool | Varies |
| **O07** | Account & Privilege Review | Periodic review of local slots/roles/keys. | Standard Redfish | Varies |
| **O08** | Auto Config Credential Containment | Least-privilege non-reused share creds (DHCP plaintext). | External Process | Varies |
| **O09** | Java Console Verification | User verifies publisher/cert/FQDN before launch. | External Process | Varies |
| **O10** | SEKM Lifecycle Governance | Verify PERC/KMS/certs before enable/rekey. | Vendor Tool | Varies |
| **O11** | Secure Boot Certificate Governance | Test PK/KEK/db changes only in controlled deployment. | Vendor Tool | Varies |
| **O12** | Secure Disposal & Repurposing | System Erase before ownership transition. | Dell OEM Redfish | Varies |
| **O13** | Security-Event Monitoring | Alert on security Lifecycle Log events. | Standard Redfish | Varies |
| **O14** | Vulnerability Scanning Disposition | Harden before scan; document Dell false positives. | External Process | Varies |
| **O15** | Superroot Governance | Contractual reclaim/reprovision authority. | External Process | Varies |
| **O16** | Applicability & Exception Review | Threat-model exceptions documented. | External Process | Varies |

#### Hardware & Platform Assurance Capabilities (9 Controls)
| Control ID | Control Title | Hardening Criteria & Objective | Transport | Confidence |
|---|---|---|---|---|
| **I01** | Silicon Root of Trust | Built-in silicon RoT. | Vendor Tool | Varies |
| **I02** | Cryptographically Verified Trusted Boot | Built-in trusted boot + Secure Boot. | Standard Redfish | Varies |
| **I03** | SELinux inside BMC | Built-in non-disableable SELinux. | External Process | Varies |
| **I04** | Signed Firmware Enforcement | Built-in signed updates. | Standard Redfish | Varies |
| **I05** | Non-Root Internal Services | Built-in least privilege. | External Process | Varies |
| **I06** | BMC Credential Vault | Chip-bound credential encryption. | External Process | Varies |
| **I07** | BIOS Recovery & Hardware RoT | Automatic integrity/recovery. | Dell OEM Redfish | Varies |
| **I08** | Built-In SNMP Safeguards | Lockout/restricted MIB behavior. | Vendor Tool | Varies |
| **I09** | Lifecycle Security Auditing | Built-in security event generation. | Standard Redfish | Varies |

---

### 9.4 OEM Security Hardening Guides & VCF Security Guidelines {#oem-security-hardening-guides}

Consult the official security configuration baselines published by VMware, national cybersecurity authorities, and hardware server manufacturers:

- 🛡️ **[VMware Cloud Foundation Security and Compliance Guidelines (GitHub)](https://github.com/vmware/vcf-security-and-compliance-guidelines):**
  The authoritative repository of security configuration guides (SCG) for VCF, ESXi, and vSAN deployments.
- 🛡️ **[CISA & NSA Joint Cybersecurity Information Sheet: Harden Baseboard Management Controllers (PDF)](https://media.defense.gov/2023/Jun/14/2003241405/-1/-1/0/CSI_HARDEN_BMCS.PDF):**
  Authoritative joint federal guidance published by CISA and NSA establishing 8 essential defensive baselines for enterprise BMC operations and hardware security.
- 🔧 **[Dell iDRAC9 Security Configuration Guide](https://www.dell.com/support/manuals/en-us/idrac9-lifecycle-controller-v5.x-series/idrac9_security_configuration_guide/):**
  Hardening standards for Dell PowerEdge 14G, 15G, and 16G servers (System Lockdown, TLS, ports, IP filtering, SSH crypto, FIPS, BIOS security).
  - Direct PDF: [iDRAC9 Security Configuration Guide (PDF)](https://dl.dell.com/content/manual30213951-idrac9-security-configuration-guide.pdf)
- 🔧 **[HPE iLO Security Documentation Hub](https://www.hpe.com/info/iLO):**
  Official security documentation and administration resources for HPE ProLiant iLO 5 and iLO 6 controllers.
  - Redfish Security Service: [HPE iLO Redfish Security Service (Security States & TLS)](https://servermanagementportal.ext.hpe.com/docs/redfishservices/ilos/supplementdocuments/securityservice)
  - Security Bulletin Reference: *Implementing Security Best Practices to Protect the iLO Management Interface* (Doc ID: `a00046959en_us`)
  - Platform Security States: Gen10/Gen11 iLO 5/6 security modes (Production, High Security, FIPS, CNSA).
- 🔧 **[Lenovo ThinkSystem Server & XCC Hardening Guide](https://lenovopress.lenovo.com/lp1260-how-to-harden-the-security-of-your-thinksystem-server):**
  Hardening paper for Lenovo XClarity Controller (XCC / XCC2 / XCC3) covering TLS, IPMI/KCS disablement, physical lockdown, security modes, and OneCLI automation.
  - Direct PDF: [How to Harden the Security of your ThinkSystem Server (PDF)](https://lenovopress.lenovo.com/lp1260.pdf)
- 🔧 **[Cisco Compute Security Hardening Guide (Standalone / CIMC)](https://www.cisco.com/c/en/us/products/collateral/servers-unified-computing/compute-security-hardening-guide-standalone-wp.pdf):**
  Authoritative hardening whitepaper for Cisco UCS C-Series rack servers and standalone Cisco Integrated Management Controllers (CIMC).
  - GUI Configuration Guide: [Cisco UCS C-Series IMC GUI Configuration Guide, Release 6.0](https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/gui/config/guide/6_0/b_cisco_ucs_c-series_gui_configuration_guide_6-0.html)
- 🔧 **[Supermicro BMC Security Best Practices (PDF)](https://www.supermicro.com/products/nfo/files/IPMI/Best_Practices_BMC_Security.pdf):**
  Official best practices paper for securing Supermicro Baseboard Management Controllers, IPMI interfaces, and management networks.
  - Feature Guide PDF: [Supermicro BMC Server Management Feature Guide (PDF)](https://www.supermicro.com/products/nfo/files/IPMI/BMC_Server_Management_Feature_Guide.pdf)
  - Security Hub: [Supermicro Security Center](https://www.supermicro.com/en/support/security_center)
- 🔧 **[Intel Server Systems BMC & BIOS Security Configuration Guide](https://www.intel.com/content/www/us/en/support/articles/000055785/server-products.html):**
  Security configuration guidelines and best practices for Intel server platforms and integrated Baseboard Management Controllers.
  - Direct PDF: [Intel Server Systems BMC & BIOS Security Good Practices (PDF)](https://cdrdv2-public.intel.com/840799/BMC_BIOS_Security_GoodPractices.pdf)

#### CISA / NSA "Harden Baseboard Management Controllers" Alignment & Control Mapping

In June 2023, the Cybersecurity and Infrastructure Security Agency (CISA) and the National Security Agency (NSA) jointly published the Cybersecurity Information Sheet (CSI): **[Harden Baseboard Management Controllers (PDF)](https://media.defense.gov/2023/Jun/14/2003241405/-1/-1/0/CSI_HARDEN_BMCS.PDF)**. Unhardened BMCs represent highly privileged attack vectors that operate independently of the host operating system, maintain separate network identities, and persist even when the physical server is powered down.

The VCF HCI Readiness Tool's BMC Hardware Security Audit engine directly evaluates and automates verification of all 8 core recommendations defined in the joint CSI:

| CISA / NSA CSI Recommendation | Security Objective | VCF Readiness Tool Audit Controls | Confidence |
|---|---|---|---|
| **1. Protect BMC credentials** | Eliminate default passwords, enforce strong authentication, and thwart brute-force password guessing. | **C41** (Default Password & Force Change), **C40** (Password Quality Policy), **C43** (Central Directory Authentication & Account Lockout), **C16** (IP Login Blocking), Least-Privilege ReadOnly Audit Role. | High |
| **2. Enforce VLAN separation** | Isolate OOB management on dedicated VLANs with restricted network routing and access controls. | **C12** (Dedicated Management NIC), **C13** (Management VLAN), **C16** (IP Login Blocking), **C17** (IP Allow-Range Filtering). | High |
| **3. Harden configurations** | Minimize attack surface by disabling plaintext services, insecure protocols, and boundary-escape paths. | **C01** (HTTP-to-HTTPS Redirection), **C02** (Minimum TLS 1.2+), **C03** (TLS Encryption Strength), **C04** (TLS Cipher-Suite Restriction), **C07** (Remote Syslog TLS), **C09** (SSH Hardening), **C11** (SSH Cryptographic Policy), **C14** (USB Port Management), **C15** (OS-to-iDRAC Pass-Through), **C18/C19** (Auto-Discovery & SCP Zero-Touch), **C20** (Unused Services), **C21** (IPMI over LAN Disablement), **C22** (Serial-over-LAN), **C23** (Telnet Disablement), **C24** (SNMPv3 Only), **C28** (Authenticated NTP), **C37** (Session Timeout ≤ 1800s), **C48** (System Lockdown). | High / Medium |
| **4. Perform routine BMC update checks** | Maintain firmware patch currency to eliminate known CVEs, remote code execution (RCE), and privilege escalation flaws. | BMC Firmware Version Audit against certified baseline lines; **O01–O04** (Firmware Update Checks & CVE Microcode Baselines). | High |
| **5. Monitor BMC integrity** | Verify immutable hardware-anchored trust chains, secure boot validation, and cryptographically attested component integrity. | **I01–I05** (Hardware Silicon Root of Trust — Dell RoT, HPE Silicon Root of Trust), **I06–I09** (Secure Component Verification factory ledger), Host UEFI Secure Boot & TPM 2.0. | High |
| **6. Move sensitive workloads to hardened devices** | Restrict critical applications and sensitive data to server nodes with verified hardware and BMC security compliance. | Automated BMC Security Posture Rollup (`✓ Baseline Met`, `▲ Partial`, `✗ Action Req`), host compliance scorecards, and fleet triage views. | High |
| **7. Use firmware scanning tools periodically** | Conduct routine out-of-band auditing to detect configuration drift, unpatched vulnerabilities, or unauthorized changes. | **Automated by Tool:** Read-only Redfish compliance scanning engine auditing 84 canonical controls without OS interruption. | High |
| **8. Do not ignore BMCs** | Prevent forgotten, unconfigured, or legacy BMCs from serving as unmonitored footholds in datacenter fabrics. | Fleet-wide BMC network discovery, subnet sweeps, automated OEM identification, and multi-host inventory auditing. | High |

#### Key Broadcom Security Knowledge Base Articles
- [Broadcom KB 2147606 — Verifying Secure Boot on ESXi Hosts](https://kb.vmware.com/s/article/2147606)
- [Broadcom KB 1003734 — Time Synchronization and NTP Best Practices](https://kb.vmware.com/s/article/1003734)
- [Broadcom KB 82435 — Security Risks of Host-to-BMC Virtual USB NIC Pass-Through](https://kb.vmware.com/s/article/82435)
- [Broadcom KB 2046632 — Disabling Insecure IPMI Protocols (VMSA-2013-0007)](https://kb.vmware.com/s/article/2046632)
- [Broadcom KB 330041 — VMware ESXi Speculative Execution Mitigations](https://kb.vmware.com/s/article/330041)

---

### 9.5 Practical Security Remediation Scripts & CLI Commands {#security-remediation-scripts}

Use these verified command snippets to remediate out-of-band management findings across vendor environments.

*(Note: Network IP addresses used below adhere strictly to RFC 5737 documentation ranges `192.0.2.x` / `198.51.100.x`).*

#### 1. VMware ESXi Host Verification (In-Band)
Run these commands from an administrative ESXi SSH shell to verify Secure Boot and TPM attestation:

```bash
# Verify ESXi UEFI Secure Boot validation status
/usr/lib/vmware/secureboot/bin/secureBoot.py -c

# Check ESXi security configuration and TPM encryption status
esxcli system security get

# Verify TPM 2.0 device presence and driver registration
esxcli hardware tpm get
```

#### 2. Dell iDRAC (RACADM / Remote SSH CLI)
Remediate IPMI-over-LAN, default passwords, Telnet, NTP, and pass-through interfaces:

```bash
# Disable insecure legacy IPMI-over-LAN (RMCP+ Cipher 0 mitigation)
racadm set iDRAC.IPMILan.Enable 0

# Disable plaintext Telnet daemon
racadm set iDRAC.Telnet.Enable 0

# Enforce TLS 1.2 or TLS 1.3 as minimum cryptographic protocol
racadm set iDRAC.WebServer.TLSProtocol 2

# Disable Host-to-iDRAC virtual USB pass-through (boundary isolation)
racadm set iDRAC.USB.HostPassThrough 0

# Configure authenticated NTP synchronization
racadm set iDRAC.NTPConfigGroup.NTPEnable 1
racadm set iDRAC.NTPConfigGroup.NTP1 192.0.2.123
racadm set iDRAC.NTPConfigGroup.NTP2 192.0.2.124

# Enforce Account Lockout (5 attempts, 1800 second lockout)
racadm set iDRAC.Security.AccountLockoutThreshold 5
racadm set iDRAC.Security.AccountLockoutDuration 1800

# Enable System Lockdown mode (blocks unauthorized firmware/BIOS changes)
racadm set System.Lockdown.SystemLockdownMode 1
```

#### 3. HPE iLO (RESTful Interface Tool / ilorest CLI)
Apply hardening baselines to HPE iLO 5 and iLO 6 controllers:

```bash
# Login to HPE iLO
ilorest login 192.0.2.10 -u Administrator -p <CurrentPassword>

# Disable legacy IPMI-over-LAN
ilorest set Service.IpmiEnabled=False --commit

# Enforce High Security mode (disables TLS 1.0/1.1 and insecure ciphers)
ilorest set Security.SecurityState=HighSecurity --commit

# Configure static enterprise NTP servers
ilorest set DateTime.StaticNTP=192.0.2.123,192.0.2.124 --commit

# Enable UEFI Secure Boot in system BIOS
ilorest set Bios.SecureBoot=Enabled --commit

# Logout
ilorest logout
```

#### 4. Lenovo XClarity Controller (OneCLI)
Configure security policies across Lenovo ThinkSystem servers:

```bash
# Disable IPMI-over-LAN channel
onecli config set IPMI.EnableLANChannel Disabled --host 192.0.2.20 --user USERID --password <Password>

# Enforce TLS 1.2 minimum on web services
onecli config set Network.MinTLSVersion TLS1.2 --host 192.0.2.20 --user USERID --password <Password>

# Enable UEFI Secure Boot
onecli config set SystemConfiguration.SecureBootConfiguration.SecureBoot Enable --host 192.0.2.20 --user USERID --password <Password>

# Configure NTP servers
onecli config set NTP.NTPEnable Enabled --host 192.0.2.20 --user USERID --password <Password>
onecli config set NTP.NTP1 192.0.2.123 --host 192.0.2.20 --user USERID --password <Password>
```

---

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
