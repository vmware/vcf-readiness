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
