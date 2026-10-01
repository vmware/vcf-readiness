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
