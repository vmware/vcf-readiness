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
