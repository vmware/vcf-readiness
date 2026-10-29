# Ordered enrichment stages

[`../enrichment.py`](../enrichment.py) owns the public `enrich_host_result()` facade,
saved-summary preflight, cache guard, local HCL fallback and completion marker.
Callers should keep using that facade. These modules contain ordinary synchronous
functions that mutate the supplied host evidence; they do not discover plugins or
fetch data from remote services.

| Module | Responsibility and ordering |
| --- | --- |
| [system.py](system.py) | Resolve identity, CPU/firmware/cooling and memory topology. Return the actual system and CPU references and the socket count consumed later. A missing system's fallback remains detached. |
| [network.py](network.py) | Normalize FC identity before PCIe synthesis; enrich NICs and then other I/O link findings after synthesis. Local catalog lookup and physical-device identity remain unchanged. |
| [pcie.py](pcie.py) | Synthesize/correlate PCIe evidence and evaluate the CPU lane budget, preserving collected versus derived provenance. |
| [storage.py](storage.py) | Consolidate direct NVMe controllers, correlate boot devices and qualify drive firmware/HCL evidence. The separate `storage_pcie` view still owns drive-versus-controller evidence policy. |
| [security.py](security.py) | Evaluate and redact security evidence/findings; preserve imported audits, legacy config and the existing exception boundary. |
| [bios.py](bios.py) | Describe current/pending VMD, dispatch existing OEM evaluators, then derive multi-socket telemetry from their normalized attributes. Evaluator rules stay in `vcf_hci/bios/`. |
| [findings.py](findings.py) | Evaluate jobs, then events and blocker verdicts. Final hardware annotation and `_enriched` remain in the facade. |

Stages must not import the facade or run in parallel. Pass the small set of actual
references each stage consumes; do not copy the host, recompute upstream defaults,
or introduce a catch-all pipeline context. Preflight deliberately copies storage
containers and refreshes the readiness-warning list, so not every nested object
retains identity. Existing stage-specific exception scopes and partial results
are intentional compatibility behavior.

The facade re-exports `enrich_fc_hbas`, `evaluate_optical_link_health`,
`consolidate_direct_attached_nvme_controllers`, `is_vmd_active_in_bios`,
`detect_liquid_cooling`, `synthesize_pcie_slots` and
`correlate_direct_attached_nvme_pcie`. Tests that replace an evaluator should patch
its owning stage module; the repository had no such facade patches to migrate at
extraction time. See [test selection](../../tests/README.md) and the
[E1 plan](../../docs/plans/refactor-2026-10-29/03-enrichment.md) for validation and
preserved behavior.
