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
