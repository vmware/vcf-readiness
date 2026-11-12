# MTAT Workload Assessment (Experimental)

MTAT Workload Assessment (Experimental) is available from Plugins without a startup flag. Collection still requires acknowledgement.

Experimental workload assessment. Validate against MTAT 3.2 before sizing or deployment decisions.

This label applies to the MTAT inbox feature only. It does not change Redfish or BCG memory-tiering drive evidence.

The pinned contract is MTAT 3.2, schema 1.0.0, revision 2026-11-10. The public baseline commit is `3094eb3075ff3887db3e61406bf2210c064a1798`. The only accepted pyVmomi artifact is `pyvmomi-9.0.0.0-py3-none-any.whl`, SHA-256 `7812642a62b6ce2b439d7e4856d27101ad102734bce41daf77bedfb3e2d9cbf2`.

vCenter 6.5, 6.7, 7.0, 8.0 U3, 9.0, and 9.1 are validation lanes, not claims of support. 6.5 stays unvalidated until its live lane passes. Operations 8.x and 9.x are separate unvalidated lanes.

Deferred sources are Linux SSH, Windows WinRM, KVM, Hyper-V, AHV, oVirt, Kubernetes, and Telegraf.

Live collection requires a per-run acknowledgement. The feature does not send analytics, crash uploads, usage telemetry, or Telegraf configuration, and it does not write to vCenter or Operations.

On a dark site, also start with `--no-hcl-auto-refresh` and set `VCF_READINESS_CHECK_UPDATES=0` before launch. `--import-hcl` remains the offline HCL bundle switch.

## Source limitations

Operations host exports cannot prove VM eligibility or physical tier composition.
Live lanes remain unvalidated pending operator evidence in tests/fixtures/mtat/live-lanes.md.

A disconnected or not-responding host exports zeros and `CPU, Active, Consumed`.
A host collection failure stays a row with `Tiering=ERROR`. A failed VM stays
in the VMs CSV with `Missing_Metrics=Collection failed`.

Live history defaults to the past seven days in UTC, with editable dates. For
vCenter, the default `auto` interval selects the finest enabled Level 2 or higher
interval of at least 30 minutes that retains the requested duration (about 336
samples per metric per entity for a week at 30 minutes). It trims incomplete edge
buckets and the expired retention boundary. If no suitable interval exists, the
request is rejected. An explicit interval key still requires an aligned retained
window. Operations REST uses its explicit
window. Workbook preflight lists separate overlapping export ranges: use the
complete listed range label when running that import. Discovery and Preflight retain the
password in the current form for Run. Workbook imports need no
credentials. Choose an explicit memory unit when automatic units are unsuitable.

For vCenter, enter the endpoint and credentials, acknowledge experimental collection, then choose **Discover clusters and history**. The dropdown lists accessible clusters with their inventory IDs; a single cluster is selected automatically. Discovery retains the password in the current form for Preflight and Run. Changing the endpoint, username, TLS choice or source clears the discovered selection. Operations sources retain their cluster entry field.

The vCenter endpoint accepts a hostname or a full HTTPS browser URL, such as `https://vc-01.rainpole.net/ui/app/admin/sso-users/groups`. Surrounding whitespace, the UI path, query and fragment are discarded for connection; explicit ports are preserved. Enter credentials in their separate fields.


Discovery also reads vCenter historical interval settings. The history table shows
sampling fidelity, configured retention, statistics level and enabled state.
**Past 7 Days** and **Past 30 Days** are offered when an enabled Level 2 or higher
interval retains that duration at a sampling interval of at least 30 minutes.
Unsupported presets are disabled; choose **Custom history** for editable UTC
dates and an explicit interval key, or **Realtime** for current observations.
Realtime sends no historical window. Discovery does not change statistics settings
or silently switch to Realtime. A blocked preflight retains the settings table and
reports the history validation reason. Configured retention does not prove that
every required metric has been collected throughout that period; missing evidence
remains unverified. See the [vCenter historical interval API](https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/vim.HistoricalInterval.html).


**Verify TLS** and **I acknowledge this experimental collection** are in
**Source and connection**, below the credentials. Discovery requires an endpoint,
username, password and the acknowledgement; its nearby status explains any missing
requirement. Verify TLS is checked by default and does not determine whether the
discovery button is enabled. The password remains in the current form through
discovery, Preflight and Run, including retries. Reloading the page clears the
form; MTAT does not save this password to browser storage. Server-side request
secrets are still cleared after each operation.


Connection failures now distinguish certificate verification, authentication,
permissions, DNS, timeouts, network access and a missing/unloadable pinned SDK.
The page shows an error code and diagnostic reference for failed server requests.
The Web UI process logs a matching warning with the operation, stage and exception
type; it does not log credentials, endpoint URLs or raw upstream exception text.
Check the terminal or service log used to launch the Web UI. Discovery and
Preflight show progress immediately; a request exceeding two minutes is reported
as timed out. A client timeout does not prove server-side work has stopped.
Configured history and actual historical metric completeness remain distinct.


For a vCenter with a self-signed/untrusted certificate, choose **Review certificate /
TOFU** beside Verify TLS. Inspection reuses Redfish's credential-free certificate
inspection and displays subject, issuer, expiry and SHA-256 fingerprint. Confirm
that fingerprint through a trusted channel, then choose **Trust this SHA-256
fingerprint**. This replaces CA-chain trust with exact certificate identity
verification for every TLS connection, before sending API credentials. A changed
certificate blocks access; it is never automatically accepted. Pins apply only to
this vCenter endpoint in the current page and clear when the endpoint/source
changes or the page reloads. Remove pin restores the Verify TLS choice. Review
currently accepts DNS/IPv4 endpoints; IPv6 literals use system CA verification.
This vCenter trust option does not change Operations or Redfish TLS policies.

## Phased Clarity assessment workflow

The MTAT web view is organized as a 3-step Clarity workflow (`1. Source & Connection`, `2. Baseline Assessment`, and `3. Sizing & Savings`):

1. **1. Source & Connection** — Select the data source (`vCenter`, `Operations REST`, or `Operations workbook`), configure endpoint credentials and TLS/TOFU certificate pinning (or choose an `.xlsx` workbook up to 32 MiB), check **I acknowledge this experimental collection**, and run **Discover clusters and history** for vCenter.
2. **2. Baseline Assessment** — Select the **Target Cluster Scope**, choose one or more **Evaluation Metrics Range** profiles (`Real-Time Snapshot`, `Past 24 Hours (Avg Rollup)`, `Past 7 Days (Avg Rollup)`, `Past 30 Days (Avg Rollup)`, or a custom UTC history window), and run **Analyze Selection Profile** (or **Preflight**).
3. **3. Sizing & Savings** — Review cluster and per-host NVMe Memory Tiering projections across target tiering ratios (`25% (4:1 DRAM:NVMe)`, `50% (2:1 DRAM:NVMe)`, and `100% (1:1 DRAM:NVMe)`) along with VM `DRAM_Only` pinning exclusions.

## Multi-range evaluation and 24-hour interval selection

For vCenter assessments, Step 2 provides multi-select checkboxes for **Real-Time Snapshot**, **Past 24 Hours (Avg Rollup)**, **Past 7 Days (Avg Rollup)**, and **Past 30 Days (Avg Rollup)**, plus a **Select All** / **Deselect All** toggle. When multiple ranges are selected, a single **Analyze Selection Profile** job collects each requested range in sequence, retains the longest historical rollup as the primary baseline range for single-range `hosts.csv` and `vms.csv` exports, and combines all analyzed ranges into `hosts_history.csv`, `vms_history.csv`, `matrix.csv`, and `export.zip`.

When using the `auto` historical interval selector on vCenter:

- Windows of 24 hours or less (`<= 86400` seconds, such as **Past 24 Hours (Avg Rollup)**) accept any enabled Level 2 or higher interval of at least 5 minutes (`>= 300` seconds, or about 288 samples at 5-minute sampling) that retains the requested duration.
- Windows longer than 24 hours (such as **Past 7 Days** and **Past 30 Days**) continue to require an enabled Level 2 or higher interval of at least 30 minutes (`>= 1800` seconds) that retains the requested duration.

## Baseline Qualification Checklist and Range Comparison Matrix

When an assessment finishes, Step 2 renders two primary reporting cards above the expandable host and VM telemetry tables:

- **Baseline Qualification Checklist (`#mtatChecklistCard`)** — Evaluates raw cluster hardware metrics against the three MTAT qualification thresholds (defaulting to the longest analyzed historical rollup range, with a dropdown switcher when multiple ranges are collected):
  - **CPU Usage** (`Target: <= 50%`): Reports `[ ✓ ] PASS` when cluster average host CPU utilization is `<= 50.0%`, or `[ ! ] REVIEW` when `> 50.0%`.
  - **Active Memory** (`Target: <= 50%`): Reports `[ ✓ ] PASS` when active working-set memory is `<= 50.0%` of connected physical DRAM, or `[ ! ] REVIEW` when `> 50.0%`.
  - **Consumed Memory** (`Target: >= 80%`): Reports `[ ✓ ] PASS` when consumed memory is `>= 80.0%` of connected physical DRAM, or `[ i ] NOTE` with `(Memory Tiering will not trigger until there is memory pressure (80%))` when `< 80.0%`.
- **Range Comparison Matrix (`#mtatMatrixCard`)** — Tracks historical workload trends side by side across all analyzed ranges (`Target Cluster Scope`, `Analyzed Range Profile`, `CPU Avg/Peak`, `Active Memory %`, and `Consumed Memory %`). Choose **Export Matrix CSV** (`/api/plugins/mtat/jobs/<id>/matrix.csv`) to download the matrix as an RFC 4180 CSV file, or **Download Export ZIP** for the full MTAT export bundle.

## Sizing & Savings projections

Step 3 (**3. Sizing & Savings**) models NVMe Memory Tiering capacity and DRAM reclamation for the selected reference workload range and target tiering ratio:

- **Target NVMe Tiering Ratios**: Supports **25% (4:1 DRAM:NVMe)** conservative, **50% (2:1 DRAM:NVMe)** balanced default, and **100% (1:1 DRAM:NVMe)** aggressive tiering profiles (requiring active memory `<= 40%` for 100% viability).
- **VM Eligibility & DRAM-Only Exclusions**: Summarizes powered-on VMs and provisioned/active memory pinned to DRAM (`DRAM_Only`) due to vGPU, SR-IOV, PCIe passthrough, RDMA, pinned guest memory, high latency sensitivity, Fault Tolerance, or explicit tiering opt-out, comparing the frozen `MTAT 3.2` policy against `vSphere Current` (`vsphere-current-2026-11-10`).
- **Cluster & Per-Host Sizing Breakdown**: Displays cluster KPI cards and a per-host table covering Physical DRAM, Consumed Memory, Active Working Set, Pinned `DRAM_Only` VM footprint, Observed NVMe capacity, Recommended NVMe Tier allocation, Effective Tiered Capacity, and Projected Reclaimable DRAM.

## TCO Scenario Explorer

Below the per-host table, Step 3 has an interactive **TCO Scenario Explorer (Estimate)**. It compares memory cost for DRAM only and for each tiering ratio, using the selected reference workload range. Everything runs in the browser tab. Prices are not saved and are not sent to the server, and the explorer does not change `export.zip`, the CSV files, or the manifest.

Controls:

- **Memory overcommit target**: provisioned VM memory divided by total memory capacity (DRAM plus NVMe tier), from 1.0x to 3.0x. It starts at the observed ratio (provisioned VM memory divided by connected host DRAM), held to that range.
- **DIMM size**: 16, 32, 64, 96, 128, or 256 GB. It sets the default DRAM price and the DIMM rounding.
- **DRAM price ($/GB)**: defaults to **$50/GB** for 64 GB and smaller DIMMs and **$100/GB** for larger DIMMs. Type your own price to override it. A typed price is kept when the DIMM size changes, and **Reset to default** restores the default.
- **NVMe price ($/GB)**: defaults to **$1.50/GB**. Type your own price to override it.
- **NVMe drive capacity (GB)**: defaults to 3840 GB and is used only to round each host's tier up to whole drives.

For each ratio `r` (0, 25%, 50%, 100%) at overcommit `O`:

- Required capacity is `provisioned / O`. DRAM is `capacity / (1 + r)`, but never less than the Step 3 minimum DRAM (twice the active working set, or pinned `DRAM_Only` plus eligible active memory). When that minimum is used, the row is noted **DRAM floor applied**.
- DRAM per host rounds up to whole DIMMs. The NVMe tier per host is `DRAM per host × r`, rounded up to whole drives.
- Cost is `DRAM GB × DRAM $/GB + purchased NVMe GB × NVMe $/GB`. Savings are compared with DRAM only at the same overcommit.
- A ratio that fails the Step 3 qualification check is noted **Review qualification**.

The line chart shows total cost across the overcommit range, one line per ratio, with a marker at the current setting. Point at it to see values. The bar chart splits DRAM and NVMe cost per ratio at the current setting. Select a bar to set the Step 3 tiering ratio. A table lists the same numbers.

These figures are planning estimates. They do not model DIMM channel population rules, spares, licensing, power, or support costs.

## Privacy of assessment exports

MTAT CSVs, reports and sidecar manifests retain environment identifiers such as host, VM, cluster and source names. They are private assessment evidence, not anonymized public samples. Review them before sharing. Passwords and authentication tokens must not appear in exports or diagnostic errors. Saved accounts are an explicit Credential Vault choice; collection jobs resolve selected credentials on the server.
