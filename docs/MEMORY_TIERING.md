# Memory Tiering

Memory Tiering evidence is separate from vSAN readiness. This Help article is always available. The optional namespace preview is off unless `python vcfr_web.py --nvme-namespace-preview` is used. The **Mem Tier — TLC RI 1 DWPD** tag and the namespace procedure stay in [NVMe namespace sizing](NVME_NAMESPACE_PREVIEW.md).

## How a drive matches

A drive matches the active Memory Tiering catalog by exact model, complete SKU, or exact local HCL alias. Capacity-bearing listings are checked against observed capacity. Family-only names are not matches. Explicit OEM branding keeps the match on that vendor's entry.

A **Mem Tier** badge is a catalog link to the matched Broadcom Compatibility Guide entry. On a host drive row the same link can read **Memory Tiering**. The badge is not firmware, release, or deployment validation. Its tooltip shows the listing name, partner, listed releases, and the catalog snapshot date. Confirm those requirements on the listing before treating the drive as ready to deploy.

## Fleet and host counts

The fleet column **Memory Tier Drives** is a count of identified NVMe drives. The count is availability only. It includes populated drives that match the catalog, and it leaves out absent drives, boot devices, unsupported NVMe, VMD attachments, RAID, tri-mode, software RAID, and devices identified as non-NVMe. Each physical drive is counted once.

The host Overview **Memory** card can show a compact **NVMe Tiering** check when eligible drives exist. The Memory tab then shows how many of those drives were identified. Both are omitted when none are identified.

A listed drive is not also counted as vSAN capacity. The badge does not change the vSAN verdict. A drive assigned to Memory Tiering is dedicated to that role.

With the preview off, the count is catalog matches only. [NVMe namespace sizing](NVME_NAMESPACE_PREVIEW.md) describes the additional TLC read-intensive candidates the preview can include.
