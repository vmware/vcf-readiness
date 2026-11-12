# vSphere Inventory (Experimental)

vSphere Inventory (Experimental) is available by default beside MTAT on the Plugins page. No startup flag is required; each collection still requires acknowledgement.

Experimental vSphere inventory export and host reconciliation. Verify inventory completeness before sizing or migration decisions.

The feature reads a vCenter inventory through the same pinned pyVmomi artifact the MTAT feature uses. It writes a workbook whose tab names and column layout follow the common vSphere inventory spreadsheet convention, so existing review habits and spreadsheet formulas carry over. It does not include or depend on any third-party inventory tool.

## What it collects

The workbook has 25 inventory tabs plus `vMetaData`:

vInfo, vCPU, vMemory, vDisk, vPartition, vNetwork, vCD, vUSB, vSnapshot, vTools, vSource, vRP, vCluster, vHost, vHBA, vNIC, vSwitch, vPort, dvSwitch, dvPort, vSC_VMK, vDatastore, vMultiPath, vLicense, vHealth, vMetaData.

`vFileInfo` (datastore file listing) is off unless **Include datastore file listing** is selected; it is bounded to 50,000 files. `vHost` also reports memory tiering state (`Enabled`, `Disabled`, or `Unknown`) and the NVMe tier size.

License keys are masked to their last five characters. Passwords are never written to jobs, manifests, logs, or sessions, and are cleared from memory once the connection is made.

## Running a collection

1. In the Web UI, open **Plugins** and select **Open vSphere Inventory** on the vSphere Inventory card.
2. Enter the vCenter hostname, or paste a vSphere Client URL; only its HTTPS host and port are used. Enter a read-only user and a password.
3. If vCenter uses a certificate that the system trust store does not accept, select **Review certificate**. VCF-R fetches the certificate without sending credentials and shows its subject, issuer, expiry and SHA-256 fingerprint. Compare the fingerprint with vCenter, then select **Trust this SHA-256 fingerprint**. A different certificate then blocks the connection before any credentials are sent. Changing the endpoint clears the pin.
4. Select the per-run acknowledgement beside the vCenter options, then select **Connect** below the datastore file-listing option. This checks access, shows inventory counts, and fills the cluster list. Pick one cluster or keep **All clusters**; a single cluster is selected automatically. Use **Discover clusters** to refresh the list.
5. Select **Collect** in Review and collect to run. The password stays in the form for retries and is cleared when a collection completes. It is never stored in the browser.
6. The finished inventory lands in the session **Inventory library**. Download it as `.xlsx` or as a `.zip` containing the workbook, a JSON snapshot, and a manifest. Each download has an obfuscated variant.

You can also import a previously exported workbook or JSON snapshot. Imports need no credentials.

Collection is read-only. It uses container views and the property collector only; nothing is written to vCenter. Disabling TLS verification without a pin adds a warning to `vMetaData`; a pinned connection records the pin verification instead.

Failures show a code and a 12-character reference that also appears in the server log. Messages never include upstream exception text or credentials. **Connection diagnostics** lists the last 20 events for the page.

| Code | What to check |
|---|---|
| `authentication` | User name with its SSO domain, password, account lockout. |
| `permission` | The account needs at least the Read-only role on the vCenter root, or on the selected cluster, with propagation. |
| `tls_certificate` | Review and pin the certificate, or add the vCenter CA to the system trust store. |
| `certificate_pin_mismatch` | The certificate changed since it was pinned. No credentials were sent. Confirm the vCenter identity before pinning again. |
| `dns`, `connection_refused`, `network`, `timeout` | Name resolution, the HTTPS port, and firewalls or proxies between VCF-R and vCenter. |
| `cluster_not_found` | Discover clusters again and pick one from the list. |
| `resource_limit`, `result_too_large`, `deadline_exceeded` | Limit collection to one cluster, or skip the datastore file listing. |
| `internal` | A collector bug. Enable debug logging and send the log with the reference. |

## Debug logging

Set `VCF_READINESS_VINV_DEBUG=1` before starting the Web UI to log each collection step to the console: TLS mode, connection time, objects and pages per inventory type, stage timings, the cluster scope and the tab row counts. To also write a file, set `VCF_READINESS_VINV_DEBUG_LOG` to a path; it is created with owner-only permissions.

Debug lines never contain passwords, user names or upstream exception text. Failures are logged as an error code, a stage, the exception type chain and the source location of the failing line, so a log can be shared for support. Without the variable, only failures with their reference are logged.

## Reconciling with Redfish results (Phase 2)

Reconciliation merges the vCenter inventory with Redfish hardware captures of the same physical hosts. MTAT and Operations workload captures are separate inputs for workload assessment; they are not required for this merged inventory report.

1. Under **Reconciled reports**, set **Scan library folder** and select **Find Redfish scans**.
2. Choose the original hardware scan and select **Use selected Redfish scan**. This replaces the active assessment and writes new assembled reports; source captures stay unchanged. You can instead keep the current assessment. To upload a scan ZIP or JSON, follow **Scan Library → Import prior scan**. A VCF-R hardware Excel workbook is an output, not the scan input.
3. Collect vCenter inventory above or import a vSphere inventory workbook/JSON. An inventory workbook must contain populated `vHost` or `vInfo` inventory sheets; host reconciliation needs `vHost` identifiers. A hardware workbook does not supply these.
4. In **Inventory library**, select **Attach** on the inventory for the same hosts.
5. Select **Download reconciled fleet report**, or use the main assessment Excel export for the merged workbook. For a shareable version, use the obfuscated report/export after matching original identifiers.
6. Review matched hosts, unmatched hosts and discrepancies. An unmatched record means identity evidence did not establish a match; it is not proof of a hardware fault.

With an inventory attached:

- The main Excel export adds a `Reconciliation` tab after `Decision`, followed by the vSphere tabs at the end of the workbook. Four tabs are renamed to avoid colliding with Redfish tabs: `vCPU` becomes `vmCPU`, `vMemory` becomes `vmMemory`, `vNetwork` becomes `vmNetwork`, and `vHBA` becomes `esxHBA`.
- **Download reconciled fleet report** produces the combined fleet HTML with a vSphere Reconciliation panel, plus a vSphere Context card, workload and health section, and a vmnic-to-Redfish-port table in each matched host report.

Hosts are matched by manual override (programmatic only), then SMBIOS UUID (both byte orders), then system serial/service tag, then hostname or IP. CPU serials and NIC hashes are not match keys; NIC MAC addresses correlate network ports after the host is identified. Each record shows the method used. Discrepancies reported include serial, BIOS, core count, memory size, and NIC link-speed mismatches. Hosts present only in Redfish or only in vCenter are listed separately.

When the BMC did not report an operating system, the host report shows the ESXi version from vCenter, labelled as coming from vCenter reconciliation.

## Obfuscation

Obfuscated workbooks and reports replace vCenter, datacenter, cluster, host, VM, datastore, port group, switch, IP, MAC, serial, and UUID values with salted tokens. Reconciled hosts use the same `Host-N` alias in the Redfish tabs, the `Reconciliation` tab, and the vSphere tabs. Serial-mismatch details are reduced to the finding name.

## Limits

One collection runs at a time. Collections stop at 2,000 hosts, 25,000 VMs, 4,000 datastores, or a 48 MiB snapshot. Imports are limited to 48 MiB, 32 sheets, and 250,000 rows. A session keeps up to eight inventories; the server keeps up to 32.

vCenter 7.0, 8.0, and 9.x are validation lanes, not claims of support.
