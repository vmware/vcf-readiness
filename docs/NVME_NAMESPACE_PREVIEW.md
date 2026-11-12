# NVMe namespace sizing

## Enable the preview

Launch `python3 vcfr_web.py --nvme-namespace-preview` to show this Help article and
**Mem Tier — TLC RI 1 DWPD** tags on identified TLC read-intensive vSAN
ESA capacity drives. The feature is off by default. QLC/cyber recovery drives are
excluded. Unknown NAND or rated endurance is not assumed to qualify. The scanner
only presents evidence and instructions; it never changes namespaces.

## How drive detection works

The regular **Mem Tier** badge is catalog evidence. Detection uses an exact
normalized model name, a complete SKU token, or an exact local HCL model alias;
it does not infer a match from a product-family substring. For listings that
specify capacity, observed drive capacity must also align. Explicit OEM branding
narrows matches to that vendor's entry. A match links to the specific Memory
Tiering BCG product and shows its listed releases and the data snapshot date.
This badge does not check whether the installed firmware or deployment meets
those listing requirements.

The separate **Mem Tier — TLC RI 1 DWPD** badge appears only with the optional
preview flag and only for a vSAN ESA eligible capacity drive. Candidate evidence
must come from collected TLC and rated 1 DWPD fields or an exact model/SKU in the
reviewed read-intensive product evidence list. Unknown NAND or endurance is not
treated as qualifying; QLC, cyber-recovery, boot, RAID and VMD-attached drives
are excluded. This identifies a candidate for review, not a supported or
certified configuration.

Host Memory tabs and fleet summaries count identified Memory Tiering drives
once per physical drive. They exclude absent, boot, unsupported NVMe, VMD,
RAID/Tri-Mode/software RAID, and explicitly non-NVMe devices. A listed drive
and a TLC read-intensive candidate may appear in the drive details, but each
physical drive contributes only once to availability totals. Review the exact
deployment requirements and dedicate the drive to one role; a drive assigned to
Memory Tiering is not simultaneously a vSAN capacity device.

The regular **Mem Tier** badge links to a model-specific entry in the
[Memory Tiering BCG](https://compatibilityguide.broadcom.com/search?program=memorytier&persona=live&column=partnerName&order=asc).
Its tooltip identifies listed releases and the snapshot date. Verify the exact OEM
model, capacity, firmware, ESXi release and deployment requirements in that entry.
An RI tag does not establish BCG listing or production support. The
support statement for resized read-intensive drives is pending; do not interpret
this preview as approval. A drive dedicated to memory tiering is not simultaneously
a vSAN capacity device.

## Why smaller namespaces can help

[Dell's R7525 / KIOXIA CM6 study (H19337)](https://infohub.delltechnologies.com/en-au/p/using-nvme-namespaces-to-increase-performance-in-a-dell-poweredge-r7525-server/)
tested a 3.84 TB, 1 DWPD SSD at 3.84 TB and 3.20 TB, alongside a 3.20 TB,
3 DWPD SSD. Unallocated flash became overprovisioning through CM6 firmware,
reducing garbage-collection pressure and improving write performance. Extra spare
area can reduce write amplification and extend useful life. The study did not
recertify the resized device as a 3 DWPD product or measure a universal endurance
multiplier. Results were synthetic FIO 3.19 on CentOS 8.4, not ESXi memory-tiering
benchmarks; other models and firmware can behave differently.

Columns below are original RI / resized RI / factory MU. Sequential tests used
128 KB, QD16; random tests used 4 KB, QD32.

| Workload | RI 3.84 TB | RI 3.20 TB | MU 3.20 TB |
| --- | --- | --- | --- |
| Sequential read MB/s | 6,971 | 6,952 | 6,972 |
| Sequential write MB/s | 4,246 | 4,246 | 4,245 |
| Random read IOPS | 1,549,202 | 1,548,940 | 1,549,470 |
| Random write IOPS | 173,067 | 337,920 | 354,666 |
| Mixed 70R/30W total IOPS | 552,572 | 794,035 | 801,880 |
| Mixed 50R/50W total IOPS | 340,963 | 643,469 | 651,980 |
| Mixed 30R/70W total IOPS | 245,315 | 474,846 | 499,764 |

## Prepare an isolated test device

**Deleting a namespace destroys access to its data. Back up and evacuate the
device before proceeding.** Use an approved maintenance window and a spare test
drive. Remove all vSAN, VMFS, boot, scratch, swap and memory-tiering consumers
through their supported procedures. Verify the adapter, serial number and every
attached namespace/controller. Never use a boot drive or an in-use datastore.

Confirm with the OEM that this exact firmware supports namespace management and
returns unallocated capacity to the spare pool. Creating a smaller partition or
datastore is not the same operation. Leave the freed capacity unallocated across
all namespaces. Confirm support and warranty implications before production use.

## ESXi operator procedure

These are templates based on the
[Broadcom ESXCLI NVMe reference](https://developer.broadcom.com/xapis/esxcli-command-reference/latest/namespace/esxcli_nvme.html).
Dell's article uses Linux `nvme-cli`; those commands cannot be pasted into ESXi.
Check the installed ESXi build's `--help` before using the templates. Replace all
angle-bracket placeholders with verified values; do not assume controller or
namespace ID 1, or that LBA format index 0 means 512 bytes.

### Step 1: Inventory

Record the device configuration using read commands:

```shell
esxcli nvme adapter list
esxcli nvme device get -A <adapter>
esxcli nvme device controller list -A <adapter>
esxcli nvme device namespace list -A <adapter>
esxcli nvme device namespace get -A <adapter> -n <old-nsid>
esxcli nvme device namespace create --help
```

### Step 2: Calculate the size

Select the supported LBA format and calculate the new namespace size and
capacity in logical blocks: `floor(target_bytes / logical_block_bytes)`. For an
illustrative decimal 3.20 TB target with 512-byte LBAs this is 6,250,000,000 blocks;
with 4096-byte LBAs it is 781,250,000 blocks. These are arithmetic examples, not
approved sizes for every SSD. Use the OEM-approved target and format index, retain
required metadata/protection settings, and check available capacity and alignment.

### Step 3: Recreate the namespace

After confirming evacuation and device identity, detach the old namespace from
each attached controller. Delete only that namespace, create a smaller one, record
the returned namespace ID, and attach it to the intended controller(s):

```shell
esxcli nvme device namespace detach -A <adapter> -c <controller-id> -n <old-nsid>
esxcli nvme device namespace delete -A <adapter> -n <old-nsid>
esxcli nvme device namespace create -A <adapter> -s <blocks> -c <blocks> -f <flbas>
esxcli nvme device namespace attach -A <adapter> -c <controller-id> -n <new-nsid>
```

### Step 4: Verify

Rescan and verify the returned size, format, namespace attachment and identity:

```shell
esxcli storage core adapter rescan -A <adapter>
esxcli nvme device namespace list -A <adapter>
esxcli nvme device namespace get -A <adapter> -n <new-nsid>
```

If namespace management is unsupported, the controller stays offline, or the new
device is missing, stop and use OEM/Broadcom guidance. Do not substitute a format
or secure erase command. Recreating the original size later does not restore data.
Validate workloads, latency, SMART wear and write amplification in the isolated
test before seeking a supported deployment configuration.
