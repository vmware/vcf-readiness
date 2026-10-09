# Redfish Monitoring Guide

> How the collector finishes a host quickly, still returns the inventory a VCF decision needs, and leaves the BMC able to answer the next host. This page is the customer-safe summary of the accepted expand-and-fast-path decision. The full decision record stays in the engineering tree and is not part of the public Help bundle.

A complete Redfish inventory is 40 to 120 member GETs. Each one costs 80 ms to 2.5 seconds, because the answer often waits on I2C, SPI, or PLDM behind the BMC. Sequential collection takes one to two minutes. Opening more sessions to go faster is how iDRAC, iLO, XCC, and CIMC end up returning HTTP 503, `BAD_HANDSHAKE_LENGTH`, or a watchdog reset. Speed comes from fewer requests on one session.

---

## 1. One session, then fewer requests

No OEM has raised the session cap so a fleet scraper can poll harder.

| BMC | What the cap actually is | What a leak does |
|---|---|---|
| Dell iDRAC9 | About 6–8 Redfish sessions | HTTP 401 until the 1800-second timeout, or until the controller is reset |
| Dell iDRAC10 | About 20 sessions | Firmware 1.30.x stopped iSM temporary accounts from evicting the scraper session |
| HPE iLO 5 / 6 | A shared socket table | A leaked session locks the REST engine |
| HPE iLO 7 | Same idea, plus pipelining | `MultipleHTTPRequests` reuses the session. It does not add sessions |
| Lenovo XCC / XCC2 / XCC3 | `PerUserSessionLimit` of 16 | Operators can lower it. The hardware will not raise it |
| Supermicro | 16 sessions | Newer firmware uses KeepAlive so the session does not idle out mid-scan. The cap stays 16 |

Four rules follow from that table.

1. Mint one `X-Auth-Token` per host and reuse it for every phase.
2. Delete that session in a `finally` block, including when the scan times out.
3. Size the inner workers to the silicon, and give the Keep-Alive pool the same number of sockets. The outer fleet thread count does not raise the inner ceiling.
4. Batch with `$expand`, `SimpleStorage`, or the HPE resource directory. Do not open a second session to parallelize the same host.

---

## 2. Negotiate expand once

Read `ProtocolFeaturesSupported.ExpandQuery` on the service root before the first collection GET.

- `ExpandAll` is true: use star syntax, `$expand=*($levels=N)`.
- `ExpandAll` is false and `NoLinks` is true: use period syntax, `$expand=.($levels=N)`. HPE iLO 5 and iLO 6 are this case. Star returns HTTP 400 `QueryNotSupportedOnResource`. Guessing star first wastes a round trip on every collection.
- Neither flag, or the whole object is missing: set expand off for the host. iLO 4 has no `ProtocolFeaturesSupported`. Cisco M4 and M5 return HTTP 501 or stall if you send the query anyway.

Clamp `N` to the advertised `MaxLevels`. If one collection rejects expand, remember that endpoint for the rest of the host and fall back to member GETs. Do not turn expand off for collections that accepted it.

When an expanded body comes back, store every child in the request cache under its `@odata.id`. Later port, function, DIMM, and firmware reads hit that cache and do not open another GET. An expand that is not cached is not a win. On a Cisco M6, expand alone cut the host from 165 GETs to 149. Caching the VIC ports and device functions, and skipping PCI walks that were already inline, cut it to 88 GETs and 28.6 seconds, with the same NIC fields.

Dell replay on five models (R750, R770, R7725, R650, R740xd) cut requests by 60 to 76 percent with the same inventory counts. HPE firmware and memory collections fell from about 35–38 GETs to one. A Lenovo adapter tree fell from five GETs to one.

Dell firmware inventory lists both `Current-*` and `Installed-*` URIs for the same component. Drop `Installed-*` only when the matching `Current-*` object is already in the expanded payload. That cut is safe. A PCIe walk that stops after the priority slots is not the same kind of cut: it is a named completeness tradeoff, and a host with a large backplane can omit a lower-priority device.

---

## 3. Silicon ceilings

Inner workers used to be a fixed three on every BMC. That was safe for old controllers and left the new ones idle. The ceiling now follows the controller silicon. The numbers below are from read-only saturation runs: one token, no dropped connections.

| Silicon | Where it shows up | Safe inner workers | What breaks the rule |
|---|---|---|---|
| Pilot-3 / AST2400 | Dell 13G iDRAC8, Cisco M4, HPE Gen9 iLO 4, Supermicro X10 | 2 | Three workers took a 13G iDRAC from 481 ms to 2,111 ms |
| AST2500 / Pilot-4 | Dell 14G–16G iDRAC9, Cisco M5, Lenovo V1/V2 XCC, Supermicro X11/X12 | 3, sometimes 4 | Cisco M5 latency jumped at 5 workers. Dell 14G/15G AMD models (R7525, R6525, R7515, R7415, R7425, R6415, R6515) are clamped to 2 in code, under the 3–4 band for other iDRAC9 hosts |
| AST2600 | Lenovo V3/V4, Supermicro X13/X14, Cisco M6/M7 | 4 | Five workers on an SR650 V3 went to 366 ms, about 2.9 times the single-worker baseline |
| Nuvoton Arbel | Dell 17G iDRAC10 | 5 | Latency stayed flat from 1 through 5 workers |
| HPE Gen12 | iLO 7 | 4–5 | A 2.5× ratio appears at 3 workers only because the baseline is 25 ms. Absolute latency stayed under 103 ms |

Pacing sits on top of that ceiling.

- Default gap between requests is 0.05 seconds.
- Legacy and unpipelined platforms (Cisco M4/M5, Supermicro, anything throttled) keep a floor of at least 0.10 seconds.
- Zero pacing is only for a host that advertises `MultipleHTTPRequests` and is not currently throttled. That is iLO 7 and ThinkSystem V3/V4. It removes about 5–10 seconds of idle time. It was not proven on the sensitive Cisco M6, SR650 V1/V2, and iLO 6 cohort. That comparison was planned and never run. Measure one host at a time, with two outer threads and a cool-down, if you run it later.

HTTP 429 or 503, or two timeouts in a row, drops the host to one worker and raises pacing, with backoff up to 2 seconds. Four successful GETs restore the silicon ceiling. A TLS handshake failure waits before the retry.

---

## 4. Do not let a fast phase hide a missing one

Phase 1 is system, BIOS, event log, firmware, and PCIe, with a time cap. Phase 2 is storage, network, memory, GPU, HBA, power, and thermal, with its own cap. If Phase 1 is still holding the only worker when the cap hits, Phase 2 never starts and the report looks like a host with no disks. Phase 1 threads are marked, and after the cap they return immediately so the worker is free.

Nested walks (ports, drives, DIMMs) do not open a new pool larger than the silicon ceiling. Inside a phase they run one at a time.

Negative cache remembers HTTP 404 paths so a second walk does not ask again. HPE can skip that probing when `/redfish/v1/ResourceDirectory` already lists the URIs. iLO 5 and iLO 6 also return `ResourceNotReadyRetry` during a background inventory refresh; pause and retry that GET once.

Scan depth is a choice, not a silent drop.

- Full is the default. It includes telemetry, SMART, thermal, and GPU.
- Lean keeps CPU, memory, storage, and NIC identity and skips historical telemetry and the extra firmware member GETs.
- Quick is a pre-screen. Storage and NIC tables are empty on purpose.

A Dell host that is powered off or still in POST returns empty NIC and storage inventories even in a full scan. That is the controller, not a collector skip. Scan with the host on and the OS up.

Fleet scheduling is the same idea at rack scale. A first pass counts drives with a short timeout and starts the heavy hosts first, so a 24-drive node does not become the tail that every other thread waits on. A discovery cache keeps the next run off addresses that never answered.

---

## 5. OEM families

Green is expand that is safe at the listed depth. Amber is a partial fast path. Red is member GETs. A dashed card is a decision the code does not finish yet.

<!-- OEM-MAP -->

The September 2026 multi-OEM pass treated every Cisco as expand-incapable. That is true for M4 and M5. CIMC 4.3(6) and later on M6, M7, and M8 advertise star expansion at two levels. Quanta still has no expand query.

### Fast paths when expand is the wrong tool

- HPE SmartStorage returns array controllers and physical drives inline. Cache those objects. Do not GET each drive stub.
- HPE `Oem.Hpe.SystemUsage` on the system resource is the CPU and memory utilization. It avoids a telemetry-sensor walk.
- Supermicro `/Storage` often returns `OemLicenseNotPassed` unless a DCMS license is installed. `/Systems/1/SimpleStorage` is license-free and returns the drive list in one body. Thermal and power are two more GETs, on the chassis, not a sensor walk.
- Cisco M4 and M5 already embed port objects on the network adapter. Read them there. The manager path is `/Managers/CIMC`, and the system event log is under the chassis.
- GIGABYTE, Quanta, and ASRock Rack MegaRAC boards publish `/Systems/Self`, `/Chassis/Self`, and `/Managers/Self`. Probe those before walking collection members. GIGABYTE drive slots are under `Oem.GBT`. Quanta drive fields are under `Oem.Quanta_RackScale`.
- ASRock Rack ROMED8 is that MegaRAC family. The public export has no ASRock collector. BIOS string `P4.30` belongs to that board. Do not store it as a Dell BIOS.

### Lessons already in the collector

- Lenovo `EthernetInterfaces` adds host-side and partition stubs next to the real adapters. A four-adapter host was being counted as nineteen. Orphaned generic Ethernet interfaces are dropped when a physical NIC with a PCI identity is already present.
- XCC often omits `MemoryLocation.Channel`. Slot locators such as `CPU1_DIMM_A1`, and numeric slots on a dual-socket system, are mapped across channels. Channel A is only the last resort, not the default for every DIMM.
- A redundancy flag of true with zero healthy supplies used to render as a healthy pair. The badge now follows the healthy count. Zero healthy supplies is a fault.

### Still open

- `BMC_FW_BASELINES` has one `XCC` row. XCC2 and XCC3 are not a separate train, so a V3 or V4 controller is compared with the Gen-1 version string.
- A calendar date embedded in the firmware string, including a 2019 XCC build, does not raise a five-year age alert.
- A ThinkSystem RAID 940-16i is recognized as tri-mode. The eight lanes it reports are the PCIe slot uplink, not a lane per drive. NVMe behind that RAID volume is not vSAN ESA pass-through. Volumes that are not raw or passthrough are treated as logical RAID. There is no separate finding tag for this yet.
- Do not claim zero pacing is safe on Cisco M6, first-generation XCC, or iLO 6. Those hosts were listed for an A/B run that did not happen.

HPE AMD platforms (`A40`, `A55`, `A43` BIOS families on DL385 and DL325) need baseline rows. They do not need a second collector.

---

## 6. Library and code plan merge

This section is the apply order for the library packs. It does not apply them. Run them against the lab scraper tree, one folder at a time. The public checkout is not the target: it has no replay harness and no ASRock collector.

Apply `01-library-harness`, then `02-oem-generations`, then `03-ui-report-gaps`. The patches do not depend on each other's text, so a later pack still applies if an earlier one was skipped. Each pack owns a different set of files.

### Library side (pack 01)

Point replay and crawled-sample tests at `REDFISH_LIBRARY`.

- Tier B: one golden host per OEM generation, through assessment and enrichment. Assert vendor, model, CPU, and that the collector class is not the generic collector when an adapter exists.
- Tier C: one golden host per archetype, marked nightly. Compare structure with the saved host JSON. Leave raw Redfish capture out of that compare.
- Rebind catalog paths that still point at an old workstation copy of the library. Fill the replay-fixture flag from the archetype's best host.
- Quarantine invalid rows: scans with no drives and no NICs, and Dell rows whose BIOS string is `P4.30`.
- Do not copy captures into git.

### Code side (packs 02 and 03)

Pack 02 writes these fields. Pack 03 renders them and tolerates a missing key. Do not invent a second name.

- `network_adapters[].ports[]`: `speed_gbps`, `speed_source`, `is_management`
- `hardware_findings[]` entries with tags `NVME_BEHIND_RAID`, `UNKNOWN_BOOT_DEVICE`, `UNLINKED_PCIE_DRIVE`, `ZERO_CAPACITY_DRIVE`, `UNKNOWN_NIC_SPEED`
- `bmc_security_audit.matrix_id`: `dell-c01-c59`, `hpe-c01-c59`, `cisco-sudi`, `lenovo-xcc`, or `dmtf-8`
- `system.asset_tag` and `system.hci_appliance`
- `pcie_switches` on the host result

Pack 02 also adds the BIOS and BMC baseline rows the map calls for: Dell 13G and the missing 14G–16G AMD and 16G/17G rows, HPE Gen9 and the AMD and Gen12 rows, and separate XCC, XCC2, and XCC3 BMC rows. Cisco M4, M7, and M8 do not need new collector code. An M6 replay test should skip until a Cisco M6 sample directory exists.

Pack 02 does not edit report templates. Pack 03 does not edit OEM collectors, baselines, or replay tests. Neither pack edits the public-export script or the catalog tool, and neither retargets itself at the public checkout.

### What the report should show after pack 03

- Per-port speed, where the speed came from, and a management-port mark. If those keys are absent, keep the single speed cell.
- The storage and boot finding tags on the overview and storage sections.
- Multi-socket CPU telemetry as its own block. Leave the verdict string alone.
- The HCI banner reads `system.hci_appliance`. Asset tag comes from Redfish `AssetTag`.
- Security section prints `matrix_id`, and uses `dmtf-8` when the key is absent, so a short matrix is not read as a clean audit.
- Diagnostics include silicon generation, phase timings, and whether the TLS socket was reused.
- Do not link a Redfish explorer page unless that file was actually written for the host.
