"""
vSAN ESA / OSA readiness and storage architecture evaluation for VCF 9.1.
"""


from typing import Optional, Tuple


def evaluate_vsan(
    nvme_direct_count: int,
    sas_sata_count: int,
    nic_max_gbps: float,
    vmd_enabled: bool = False,
    trimode_nvme_count: int = 0,
    raid_nvme_count: int = 0,
    software_raid_nvme_count: int = 0,
    osa_nvme_count: int = 0,
    total_nvme_tb: Optional[float] = None,
) -> Tuple[str, str]:
    if trimode_nvme_count > 0 and nvme_direct_count == 0:
        return (
            "\U0001f534 NOT Supported — NVMe Behind Tri-Mode RAID",
            f"{trimode_nvme_count} NVMe drive(s) attached to a Tri-Mode RAID controller are ineligible for vSAN ESA",
        )
    if raid_nvme_count > 0 and nvme_direct_count == 0:
        return (
            "\U0001f534 NOT Supported — NVMe Behind RAID",
            f"{raid_nvme_count} NVMe drive(s) attached to a RAID controller are ineligible for vSAN ESA",
        )
    if vmd_enabled and nvme_direct_count > 0:
        return (
            "\U0001f534 NOT Supported — Intel VMD Enabled",
            "NVMe drives detected, but Intel VMD is enabled in BIOS (must be disabled for native NVMe pass-through vSAN ESA)",
        )
    if nvme_direct_count >= 2 and nic_max_gbps >= 25:
        sub_note = f"{nvme_direct_count} Direct NVMe + {int(nic_max_gbps)} GbE NIC"
        if software_raid_nvme_count > 0:
            sub_note += " (SW RAID: bypass in BIOS)"
        return "\U0001f7e2 vSAN ESA Ready", sub_note
    elif nvme_direct_count >= 2 and nic_max_gbps >= 10:
        sub_note = f"{nvme_direct_count} Direct NVMe + {int(nic_max_gbps)} GbE NIC (Small Profile)"
        if total_nvme_tb is not None and total_nvme_tb >= 20.0:
            sub_note += " (25Gbps upgrade recommended for ≥20TB capacity)"
        if software_raid_nvme_count > 0:
            sub_note += " (SW RAID: bypass in BIOS)"
        return "\U0001f7e2 vSAN ESA Ready", sub_note
    elif nvme_direct_count >= 2:
        sub_note = f"{nvme_direct_count} NVMe drives but max NIC is {nic_max_gbps} GbE"
        if software_raid_nvme_count > 0:
            sub_note += " (SW RAID: bypass in BIOS)"
        return "\U0001f7e1 ESA Storage Met (Needs ≥10GbE NIC)", sub_note
    elif sas_sata_count >= 2 or (nvme_direct_count + sas_sata_count >= 2) or (nvme_direct_count + sas_sata_count + osa_nvme_count >= 2):
        total_osa = sas_sata_count + osa_nvme_count
        if nvme_direct_count > 0:
            return "\U0001f7e1 vSAN OSA Eligible", f"{nvme_direct_count} ESA NVMe + {total_osa} OSA drive(s) (needs ≥2 ESA NVMe for ESA)"
        if osa_nvme_count > 0:
            return "\U0001f7e1 vSAN OSA Eligible", f"{osa_nvme_count} NVMe drive(s) on vSAN OSA HCL (All-Flash OSA — not certified for vSAN ESA Storage Tier on BCG)"
        return "\U0001f7e1 vSAN OSA Eligible", f"{sas_sata_count} SAS/SATA drives"
    return "\U0001f534 Not vSAN Eligible", "Insufficient direct-attached drives"
