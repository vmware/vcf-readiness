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

