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

