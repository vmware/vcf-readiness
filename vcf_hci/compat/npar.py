"""
NIC Partitioning (NPAR) compatibility evaluation for VCF 9.1.
"""


def evaluate_npar(network_adapters: list) -> dict:
    """Evaluate NIC Partitioning (NPAR) status across discovered network adapters.

    VMware Cloud Foundation 9.1 and vSAN ESA / OSA architectures strongly discourage
    NPAR because partitioned virtual functions share a single hardware ASIC FIFO queue
    and transmit buffer pool. Under heavy vSAN storage or NSX overlay traffic, queue
    congestion on one partition can cause packet drops across all other partitions on the
    physical port (head-of-line blocking).

    Note: Cisco Virtual Interface Cards (VIC) use hardware ASIC virtualization providing
    dedicated PCIe endpoints, dedicated queues, interrupt vectors, and ASIC-scheduled
    Class of Service (CoS). Cisco VIC is fully certified with native nenic/fnic drivers
    and is not treated as generic NPAR.
    """
    npar_adapters = []
    vic_adapters = []
    for nic in (network_adapters or []):
        if nic.get("is_vic_virtual") or nic.get("cna_family") == "cisco_vic" or "VIC" in str(nic.get("name", "")).upper():
            if nic.get("vic_virtual_interfaces") or nic.get("npar_partitions") or nic.get("is_vic_virtual"):
                vic_adapters.append(nic)
        elif nic.get("is_npar"):
            npar_adapters.append(nic)

    vic_detected = bool(vic_adapters)
    vic_info = ""
    if vic_detected:
        vic_names = ", ".join(n.get("name", "Cisco VIC") for n in vic_adapters)
        vic_info = (
            f"Cisco Virtual Interface Card (VIC) hardware virtualization active on {vic_names}. "
            "Hardware vNICs/vHBAs present independent PCIe endpoints with dedicated ASIC queues "
            "and native ESXi nenic/fnic drivers (fully supported for VCF 9.1 / vSAN ESA)."
        )

    if not npar_adapters:
        return {
            "npar_detected": False,
            "verdict": "PASSED",
            "badge": (
                "<span class='badge info' style='background:#0284c7;color:#fff;'>🔵 Cisco VIC Virtual Interfaces</span>"
                if vic_detected
                else "<span class='badge success'>\U0001f7e2 Native Unpartitioned Ports</span>"
            ),
            "advisory": "",
            "recommendation": "",
            "partitioned_adapters": [],
            "vic_virtual_detected": vic_detected,
            "vic_adapters": vic_adapters,
            "vic_info": vic_info,
        }

    nic_names = ", ".join(n.get("name", "NIC") for n in npar_adapters)
    return {
        "npar_detected": True,
        "verdict": "WARNING",
        "badge": "<span class='badge warning'>\U0001f7e1 NPAR Active (Partitioned NIC)</span>",
        "advisory": (
            f"NIC Partitioning (NPAR) is active on {len(npar_adapters)} adapter(s): {nic_names}. "
            "VMware Cloud Foundation 9.1 and vSAN ESA/OSA architectures strongly discourage NPAR "
            "because all virtual partitions share a single physical ASIC queue and hardware buffer pool. "
            "Under high vSAN replication or NSX encapsulation traffic, hardware buffer saturation on one partition "
            "causes head-of-line blocking, dropped packets, and latency spikes across all partitions sharing the physical port."
        ),
        "recommendation": (
            "Disable NPAR in BIOS / BMC Device Settings. For traffic isolation and bandwidth guarantees in VCF 9.1, "
            "use native vSphere Distributed Switch (vDS) Network I/O Control (NIOC) with dedicated VLANs."
        ),
        "partitioned_adapters": npar_adapters,
        "vic_virtual_detected": vic_detected,
        "vic_adapters": vic_adapters,
        "vic_info": vic_info,
    }
