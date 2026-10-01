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

