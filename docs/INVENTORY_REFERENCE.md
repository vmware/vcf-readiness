# Detailed Inventory & Fleet Reference Guide
## VCF / vSphere 9.1 HCI Readiness Assessment Tool (`vcf_hci`)

> **Target Audience:** VMware Sales Engineers (SEs), Solution Architects, Cloud Infrastructure Engineers, and Security Auditors evaluating server hardware for VMware Cloud Foundation (VCF) 9.1 and vSAN Express Storage Architecture (ESA).

---

## 1. Overview & SE Decision Matrix

The **Detailed Inventory** panel in combined fleet reports provides a dense, multi-dimensional view of all assessed server hardware across your datacenter. It aggregates hardware configuration data, compatibility verdicts against VMware Cloud Foundation 9.1 standards, Broadcom Compatibility Guide (BCG) certified baselines, and out-of-band security posture.

The Detailed Inventory is divided into six subpanes:
1. **Hosts:** SE Decision Matrix summarizing host compute, storage qualification, network readiness, memory interleaving, and platform security.
2. **Drives:** Granular storage drive inventory with controller topology, endurance life percentage, protocol classification, and certified firmware tracking.
3. **NICs:** Network interface controller port inventory with speed capabilities, link connection states, MAC addresses, and certified firmware levels.
4. **BIOS Settings:** System firmware configurations including CPU power profiles, memory RAS modes, Intel VMD settings, boot modes, and Spectre/CVE microcode tiers.
5. **Health Alarms:** Active hardware alarms aggregated from System Event Logs (SEL), drive S.M.A.R.T. telemetry, power supply redundancy, thermal sensors, and memory ECC counters.
6. **Security:** Out-of-band management and host platform hardening including TPM 2.0, Secure Boot, BMC firmware baselines, CVE microcode tiers, Hyperthreading posture, NTP/time drift, DNS configuration, and BMC hardening.

---

## 2. Hosts Tab (SE Decision Matrix)

The Hosts tab provides the core decision matrix used by Solution Architects to determine cluster qualification and repurposing readiness.

| Column Header | Description & Evaluation Logic | VCF 9.1 Readiness Criteria |
|---|---|---|
| **Host** | Host system hostname and out-of-band management BMC IP address. Clicking any row navigates directly to that host's comprehensive single-host assessment report. | Identifies unique physical node. |
| **Model** | Server hardware manufacturer (Dell, HPE, Supermicro, Cisco, Lenovo, Intel) and normalized chassis model name. | Hardware platform must be certified on VMware Compatibility Guide for vSphere 9.x. |
| **CPU** | Processor model name, socket count, and VCF 9.1 architectural tier. Model names are compactly formatted with word-wrapping after `Intel(R) Xeon(R)` and `AMD EPYC`.<br>• **Supported (Green):** Intel Cascade Lake/Ice Lake/Sapphire Rapids/Emerald Rapids/Granite Rapids, AMD EPYC 7002/7003/8004/9004.<br>• **Supported (Override Required) (Yellow):** Intel Skylake-SP (supported in VCF 9.x per KB 428874; installation or upgrade requires CPU override).<br>• **Unsupported (Red):** Intel Haswell/Broadwell (v3/v4) or older architectures. | Supported CPU architecture required for VCF 9.1 cluster deployment. |
| **ESA Disks** | Direct-attached NVMe storage capacity bucket breakdown and self-contained storage qualification status (independent of network speed).<br>• **✓ Storage Qualified (Green):** &ge;2 direct-attached NVMe SSDs without RAID or VMD blockers (Software RAID controllers require BIOS bypass to AHCI/Non-RAID).<br>• **✗ Behind RAID (Red):** NVMe drives attached to HW RAID or Tri-Mode controller (direct PCIe pass-through required).<br>• **✗ VMD Enabled (Red):** Intel VMD enabled in BIOS (must be disabled for native NVMe pass-through).<br>• **▲ OSA (SAS/SATA) (Amber):** SAS/SATA drives detected without direct NVMe SSDs.<br>• **— Insufficient (Muted):** &lt;2 direct NVMe SSDs. | &ge;2 direct NVMe SSDs required for vSAN ESA storage tier. |
| **ESA Tier** | Dedicated vSAN ESA ReadyNode profile qualification evaluating holistic hardware criteria (NVMe drive count & capacity, RAM, CPU cores, and NIC speeds).<br>• **✓ ESA-L (Large) (Green):** &ge;4 Direct NVMe SSDs, &ge;512 GB RAM, &ge;48 CPU cores, &ge;25 GbE NIC. Meets high-performance cluster criteria.<br>• **✓ ESA-M (Medium) (Green):** &ge;2 Direct NVMe SSDs, &ge;256 GB RAM, &ge;32 CPU cores, &ge;25 GbE NIC. Meets standard enterprise cluster criteria.<br>• **✓ ESA-S (Small) (Green):** &ge;2 Direct NVMe SSDs, &ge;128 GB RAM, &ge;16 CPU cores, &ge;25 GbE NIC. Meets entry datacenter cluster criteria.<br>• **✓ ESA-XS (Edge) (Green):** &ge;2 Direct NVMe SSDs, &ge;64 GB RAM, &ge;16 CPU cores, &ge;10/25 GbE NIC. Suitable for ROBO / Edge deployments.<br>• **▲ Needs 25G NIC (Amber):** Meets ESA storage and compute criteria, but NIC is &lt;25 GbE (upgrade required).<br>• **✗ Blocked (Red):** Ineligible due to HW RAID, Tri-Mode, or Intel VMD.<br>• **— Ineligible (Muted):** Insufficient drives. | Holistic profile qualification matching VMware vSAN ESA ReadyNode specifications. |
| **NICs** | Network adapter summary with selective down-port highlighting and 25 GbE baseline compliance. Active &ge;25 GbE links are highlighted in green (`2×25G↑`), while down ports are selectively highlighted in red (`2×25G↓`) without turning the entire cell red. Hover tooltips detail aggregate port count, active links, and ESA &ge;2x 25 GbE network readiness. | Minimum 25 GbE network interfaces required for vSAN ESA clusters. |
| **FC HBA** | Optional column displayed when Fibre Channel Host Bus Adapters are detected in the fleet. Displays detected HBA model and port count. | Informational for external SAN / VMFS storage integration. |
| **RAM** | Total installed system RAM in GB, populated DIMM slot count, and memory channel interleaving efficiency rating. | Memory must meet workload sizing and channel interleaving requirements. |
| **TPM** | Trusted Platform Module presence and activation status.<br>• **✓ (Green):** TPM 2.0 enabled and active.<br>• **✗ (Red):** TPM absent, disabled, or legacy TPM 1.2. | TPM 2.0 required for ESXi 9.1 secure boot, host attestation, and vSphere Key Provider. |
| **BMC Sec** | Out-of-band management security posture baseline compliance.<br>• **✓ Met (Green):** All evaluated security controls passed.<br>• **▲ Partial (Amber):** Security controls partially assessed (honesty rule: unknowns do not pass).<br>• **✗ Action Req (Red):** High-priority hardening failures detected (e.g. Telnet, default password, IPMI-over-LAN). | BMC security posture evaluation against VCF Security Configuration Guide (SCG) baseline. |
| **VMD** | Intel Volume Management Device status.<br>• **✓ Off (Green):** VMD disabled (native pass-through enabled).<br>• **✗ On (Red):** VMD enabled (blocks native vSAN ESA NVMe driver). | Must be Disabled for direct-attached NVMe pass-through in vSAN ESA. |
| **GPU** | Count and models of detected PCIe GPU accelerators. | Identifies hardware accelerators for VCF Private AI Foundation workloads. |

---

## 3. Drives Tab

The Drives tab details every physical storage drive detected across all storage controllers.

| Column Header | Description & Evaluation Logic | VCF 9.1 / vSAN Significance |
|---|---|---|
| **Host** | Host server hostname and BMC IP address. | Links drive to physical node. |
| **Controller** | Storage controller model (e.g. Dell HBA355i, HPE Smart HBA, PERC H740P, Direct NVMe PCIe). Highlighted in red if controller is Dell PERC 7xx (HW RAID). | vSAN ESA requires direct PCIe / HBA passthrough; HW RAID controllers are ineligible. |
| **Model** | Drive manufacturer part number and model with direct Broadcom Compatibility Guide (BCG) deep link. | Clicking opens certified device listing on Broadcom VCG. |
| **Media** | Storage media technology: `NVMe SSD`, `SAS SSD`, `SATA SSD`, `HDD`. | vSAN ESA requires all-NVMe media; vSAN OSA supports SAS/SATA SSDs. |
| **Cap GB** | Raw drive capacity in gigabytes (e.g. 1920 GB, 3840 GB, 7680 GB, 15360 GB). | Used for storage capacity sizing calculations. |
| **Protocol** | Bus transport protocol: `NVMe`, `SAS`, `SATA`. | NVMe required for ESA. |
| **Category** | Classification: `vSAN ESA/OSA NVMe`, `vSAN OSA Compatible (HBA)`, `Unsupported NVMe RAID`, `Unsupported NVMe Tri-Mode`. | Directly impacts vSAN storage qualification. |
| **Health** | Hardware diagnostic health and S.M.A.R.T. operational state (`OK`, `Warning`, `Critical`, `Degraded`). | Failing or degraded drives must be replaced before deployment. |
| **Life%** | Remaining silicon flash endurance percentage (wear gauge). Reported directly from BMC OEM storage telemetry and NVMe log pages. | Drives with &lt;20% remaining life trigger critical replacement warnings. |
| **Firmware** | Installed drive firmware version compared against certified Broadcom HCL baselines.<br>• **✓ (Green):** Certified and current.<br>• **▲ (Amber):** Certified update available or outdated. | Drive firmware must match VMware certified HCL releases to prevent I/O lockups. |

---

## 4. NICs Tab

The NICs tab details every physical network interface adapter port across the fleet.

| Column Header | Description & Evaluation Logic | VCF 9.1 / vSAN Significance |
|---|---|---|
| **Host** | Host server hostname and BMC IP address. | Links port to physical node. |
| **Adapter** | Network controller adapter model (e.g. Intel E810-XXVDA2, Broadcom BCM57414, Mellanox ConnectX-6 Dx) with BCG deep link. | Clicking opens certified controller entry on Broadcom VCG. |
| **Port** | Physical network interface port identifier (e.g. `Port 1`, `NIC.Embedded.1-1-1`, `Slot 2 Port 1`). | Identifies physical uplink wiring. |
| **Speed** | Current negotiated link speed or maximum rated bandwidth (e.g. `25 Gbps`, `100 Gbps`, `10 Gbps`). | &ge;25 Gbps required for vSAN ESA traffic; &ge;10 Gbps for management/vMotion. |
| **Link** | Physical connection state (`✓ Up` in green or `✗ Down` in red). | All intended cluster uplinks must be connected and negotiated Up. |
| **MAC** | Permanent hardware MAC address of the network interface port. | Used for vSphere Distributed Switch (VDS) uplink mapping. |
| **Firmware** | Installed network controller firmware version compared against Broadcom certified baselines. | Firmware and driver combination must be aligned with vSphere 9.1 certified versions. |

---

## 5. BIOS Settings Tab

The BIOS Settings tab displays key platform settings affecting CPU execution performance, memory reliability, storage passthrough, and security.

| Column Header | Description & Evaluation Logic | VCF 9.1 Readiness Criteria |
|---|---|---|
| **Host** | Host server hostname and BMC IP address. | Links BIOS configuration to physical node. |
| **Model** | Server hardware manufacturer and chassis model. | Identifies OEM configuration template. |
| **BIOS Version** | Installed system BIOS/UEFI firmware release version. | Must meet OEM minimum firmware release matrix for ESXi 9.1. |
| **Release Date** | OEM release date of the installed BIOS build. | Identifies aging firmware builds requiring lifecycle updates. |
| **CPU Power Profile** | Processor power management policy.<br>• **✓ Performance (Green):** Maximum Performance / Custom OS Control.<br>• **▲ Power Saving / Balanced (Amber/Red):** Energy Efficient or Dynamic saving modes. | ESXi and vSAN ESA require **Maximum Performance** profile in BIOS to prevent latency spikes and CPU throttling under heavy I/O. |
| **Memory RAS** | Reliability, Availability, and Serviceability memory mode (`Optimized`, `Advanced ECC`, `Mirroring`, `Spare`). | `Optimized` / `Advanced ECC` provides maximum capacity and channel throughput. |
| **Intel VMD** | Intel Volume Management Device status.<br>• **✓ Disabled (Pass-thru) (Green):** Pass-through ready.<br>• **✗ Enabled (VMD) (Red):** VMD enabled. | Must be **Disabled** so ESXi directly controls NVMe PCIe lanes and telemetry. |
| **Boot Mode** | Firmware boot architecture.<br>• **✓ UEFI (Green):** Modern UEFI firmware boot.<br>• **✗ Legacy BIOS (Red):** Legacy BIOS boot mode. | **UEFI** boot mode is strictly required for VCF 9.1; Legacy BIOS is unsupported. |
| **Spectre / CVE Tier** | Processor microcode security mitigation baseline covering Spectre, Meltdown, L1TF, MDS, and SRBDS.<br>• **✓ Tier 4 (Green):** Current certified microcode.<br>• **✗ Tier &lt;4 (Red):** Outdated microcode requiring BIOS update. | Tier 4 microcode ensures protection against speculative execution side-channels. |

---

## 6. Health Alarms Tab

The Health Alarms tab consolidates active faults, degraded components, and telemetry breaches from BMC subsystems.

| Column Header | Description & Evaluation Logic | Action Required |
|---|---|---|
| **Host** | Host server hostname and BMC IP address. | Identifies faulted node. |
| **Severity** | Alarm urgency level (`✗ Critical`, `▲ Warning`, `ℹ Info`, or `✓ Healthy`). | Critical alarms block commissioning until hardware remediation. |
| **Subsystem** | Reporting hardware domain: `SEL Event Log`, `Drive SMART`, `Drive Wear`, `Drive Thermal`, `Power Supply`, `Thermal`, `Memory`, `Scan Status`. | Identifies responsible hardware subsystem. |
| **Health Alarm / Telemetry** | Detailed fault message, sensor threshold violation, or event description (e.g. `Predictive Failure on Slot 3`, `Power supply non-redundant`, `Uncorrectable multi-bit ECC error count: 1`). | Provides diagnostic details for field technician dispatch. |
| **Component / Target** | Specific physical component identifier, drive bay slot, DIMM slot, or sensor name. | Pinpoints physical hardware part needing service or replacement. |
| **Timestamp / Status** | Event timestamp or active condition status (`Active Alarm`, `Active State`, `Normal`). | Distinguishes transient historical events from active continuous faults. |

---

## 7. Security Tab

The Security tab provides a comprehensive audit of out-of-band management controller hardening, host cryptographic security, and baseline compliance.

| Column Header | Description & Evaluation Logic | VCF 9.1 Hardening Guideline |
|---|---|---|
| **Host** | Host server hostname and BMC IP address. | Links security audit to physical node. |
| **Model** | Server hardware manufacturer and chassis model. | Identifies vendor security framework. |
| **TPM 2.0** | Trusted Platform Module 2.0 presence and activation.<br>• **✓ (Green):** TPM 2.0 enabled and active.<br>• **✗ (Red):** TPM disabled, absent, or legacy TPM 1.2. | **Required for VCF 9.1:** Provides cryptographic identity, secure boot verification, and vSphere Key Provider integration. |
| **Secure Boot** | UEFI Secure Boot signature validation status.<br>• **✓ (Green):** Enabled and active.<br>• **✗ (Red):** Disabled. | **Recommended:** Ensures only cryptographically signed ESXi hypervisor binaries, kernel drivers, and VIBs are executed at boot. |
| **BMC Model & FW** | Out-of-band management controller model (iDRAC, iLO, XCC, IMC) and firmware release version with certified baseline check. | Firmware updates protect against out-of-band management vulnerabilities (e.g. CVE-2023-38545). |
| **CVE Coverage Tier** | BIOS processor microcode security tier.<br>• **✓ Tier 4 (Green):** Full speculative execution microcode coverage.<br>• **✗ Tier &lt;4 (Red):** Missing recent hardware microcode patches. | Update system BIOS to current release to protect VM-to-VM and VM-to-Hypervisor boundaries. |
| **HT** | Intel Hyper-Threading / AMD SMT processor logical core status (`Enabled` or `Disabled`). | Displayed as informational plain text. Standard VCF deployments operate with Hyperthreading **Enabled** for maximum compute density. |
| **NTP / Time Drift** | BMC Network Time Protocol synchronization and clock skew detection.<br>• **✓ In Sync (Green):** NTP active and BMC clock is synchronized within 300s (5 min) threshold.<br>• **▲ No Servers (Amber):** NTP protocol enabled but no NTP servers configured.<br>• **✗ Drift (Red):** Clock skew &gt;300s detected against assessment workstation.<br>• **✗ Disabled (Red):** NTP disabled on BMC. | **Critical for VCF Operations:** Consistent time across all BMCs and ESXi hosts is mandatory to prevent TLS certificate validation failures, SSO token expiration errors, and log correlation skew. |
| **DNS** | BMC Domain Name System server configuration.<br>• **✓ Configured (Green):** DNS name servers configured on BMC or forward/reverse DNS resolves.<br>• **▲ No Servers (Amber):** DNS enabled without configured servers.<br>• **✗ Not Configured (Red):** No DNS servers configured. | BMCs should have reachable DNS servers configured for forward and reverse hostname resolution. |
| **BMC Hardening** | Comprehensive out-of-band management security posture rollup and prioritized issue badges (aligned with CISA/NSA *Harden Baseboard Management Controllers* guidance and VCF SCG):<br>• **Posture Rollup:** `✓ Baseline Met` (Green), `▲ Partial (XU)` (Amber), or `✗ Action Req (XF)` (Red).<br>• **Critical Issues (Red):** `✗ Telnet` (unencrypted remote shell), `✗ Default Pwd` (unrotated root password), `✗ TLS < 1.2` (legacy cryptographic protocol).<br>• **High-Priority Concerns (Amber):** `▲ HTTP` (plaintext web management), `▲ IPMI LAN On` (unencrypted IPMI-over-LAN), `▲ No Lockout` (brute-force vulnerability), `▲ Host Pass-Through` (boundary escape risk), `▲ Weak Ciphers` (ciphers &lt;256-bit or weak algorithms), `▲ No Syslog` (missing remote audit logging), `▲ USB Mgmt` (unrestricted USB provisioning).<br>• **Baseline Tokens:** `TLS 1.2+`, `✓ Pwd Changed`, `✓ IPMI Disabled`, `✓ Hardened`. | Follow VCF Security Configuration Guide (SCG) and OEM hardening guides (Dell iDRAC, HPE iLO) to lock down management interfaces. |

---

## 8. Excel & Obfuscated Export Reference

The Detailed Inventory toolbar includes two one-click export actions:

1. **Export Excel (`inventory.xlsx`):** Generates a multi-sheet spreadsheet containing:
   - `SE Decision Matrix`: Master host qualification summary.
   - `CPUs`: Multi-socket processor frequency, core, thread, and microcode inventory.
   - `Memory`: Complete DIMM slot inventory with speed, manufacturer, part numbers, serials, and interleaving efficiency scores.
   - `Storage`: Storage controller topology, drive models, capacities, endurance percentages, and certified firmware status.
   - `Networking`: NIC adapter ports, speeds, link states, MAC addresses, and LLDP neighbor switch details.
   - `GPUs`: Accelerator models, PCIe bandwidth, VRAM capacities, and AI readiness.
   - `Firmware Inventory`: Complete component firmware inventory.
   - `Fibre Channel`: Detected FC HBAs and WWPNs.

2. **Export Obfuscated + Key (`inventory_obfuscated.zip`):** Generates a cryptographically sanitized version of the Excel spreadsheet and JSON payloads.
   - All IP addresses are deterministically mapped to documentation ranges (`192.0.2.x`, `198.51.100.x`).
   - Hostnames are anonymized (`host-01.rainpole.net`, `esxi-02.rainpole.net`).
   - Hardware serial numbers, MAC addresses, and WWPNs are hashed with a cryptographically secure random salt.
   - Includes private `obfuscation_key.json` mapping real identifiers to tokens for internal reference and an audit instructions readme.
