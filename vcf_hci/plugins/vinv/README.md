# Experimental vSphere Inventory

The standalone workbook uses the reference inventory sheet names and ordered
standard columns, followed by VCF-R extensions and discovered custom attributes.
Schema 1.1 accepts legacy VCF-R headers as aliases without emitting duplicate
columns. Internal dictionary consumers retain those aliases. Imports retain additional
columns through XLSX and JSON round trips. Merged Redfish workbooks retain their
existing sheet collision renames. Measurement columns use numeric Excel cells
for RVTools-compatible calculations; identifiers, versions, booleans and dates
remain text. Boolean values are `True`/`False`, dates are UTC, and a blank means
unavailable, not zero or false.

Collection uses read-only inventory properties, cached compliance results,
license assignments and certificate information. It does not trigger a compliance
check or change configuration. Optional properties are queried separately so an
older API can return its base inventory with explicit warnings. Warnings appear
in JSON and the `Collection Warnings` metadata column.

## Evidence mappings

| Fields | Source and interpretation |
| --- | --- |
| VM settings, failover, suspension, maximum CPU/memory | VM config/runtime properties; CPU maximum in MHz, memory maximum in MiB |
| CPU readiness, active memory, FT metrics | VM summary quick stats, preserving their reported units |
| SRM placeholder | Managed-by extension/type or SRM managed-by extra-config markers; never a VM-name heuristic |
| HA settings and cluster rules | Cluster configuration, VM overrides with inherited defaults, VM membership by managed-object ID |
| VMRef | VM managed-object ID; distinct from instance UUID and SMBIOS UUID |
| VM networks | Eight reference summary slots; all adapters remain in vNetwork |
| USB | Attached virtual USB devices, excluding USB controllers |
| Snapshot files and sizes | Matching snapshot layout and file keys; deduplicated file keys; missing sizes remain unknown |
| Custom attributes | Field definitions and per-object custom values, respecting object type; deterministic ordering and prefixed collisions |
| Resource pools | Distinct VM membership across descendants; runtime reservation counters; memory runtime bytes converted to MiB |
| Host inventory | BIOS/system identity, DNS search/domain lists, power policy, storage-vMotion capability, advanced ATS settings and vSAN fault-domain properties |
| Host certificate and compliance | Certificate manager properties and cached compliance query; no refresh/check task |
| Assigned host licenses | License assignment names; workbook license keys retain masking |
| Multipath | Datastore-backed LUNs only; Disk is the canonical disk name, Object ID is the datastore reference |
| Datastores | VMFS backing extents or NFS address; datastore-cluster capacity/free bytes converted to MiB |
| Distributed switch members | Host member names, separate from host count |
| Source patch level | vCenter AboutInfo.patchLevel |

## Deliberate boundaries

- `vHealth` is outside reference parity; existing internal health evaluation is retained.
- VCF-R does not claim to be the reference workbook's producer. It retains its own
  tool/schema version, collection scope and provenance, with server/creation-time aliases.
- `vFileInfo` requires the existing datastore-file-listing option. A disabled
  listing is recorded as skipped; permissions, inaccessible datastores and limits
  can produce partial results. Enable the option when comparing full exports.
- `vTools.Required Version` has no verified required-version source in the
  supported inventory property contract. It stays blank with a collection warning;
  installed Tools version is not substituted as a required version. Imported
  required-version values are preserved. This remains a parity limitation.
- Guest reboot status (`Boot Required`) requires a newer API/SDK than some
  supported installations, including the current pinned SDK. It remains unknown
  with a warning when the property is not exposed; no SDK pin is changed here.
- Deprecated or absent API properties, missing guest Tools, denied permissions and
  unavailable layout data remain blank and must be reviewed with collection warnings.

Obfuscated exports tokenize new identifiers, free text, custom field names and
values, paths, and collection warnings. They preserve the original inventory for
reconciliation before applying aliases. Private captures are not test fixtures.
The Inventory Library offers both obfuscated workbook and obfuscated ZIP links;
the ZIP contains the same obfuscated workbook and JSON snapshot. Imported
workbooks retain explicit TLS verification and collection warnings. Workbooks
without a TLS verification field are treated as unverified.
