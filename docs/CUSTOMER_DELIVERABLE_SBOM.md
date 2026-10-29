# Software Bill of Materials (SBOM) — Customer Deliverables

> **Product:** VCF / vSphere 9.1 HCI Readiness Assessment Tool (`vcf-readiness`)
> **Runtime version in this checkout:** 9.12.0 (`vcf_hci/constants.py`)
> **Source-document review:** 2026-10-29
> **Historical JSON inventory:** 2026-09-27; `docs/sbom/cyclonedx-customer-v9.7.1.json` and `docs/sbom/spdx-customer-v9.7.1.json`
> **License:** [CA, Inc. Software License Agreement](../LICENSE.md)

This is a source-component overview, not an attestation of a particular ZIP or executable. The v9.7.1 companion JSON remains historical. New v9.12.0 CycloneDX/SPDX JSON and a matching file-hash manifest describe a locally prepared sanitized source snapshot; they do not attest a published release or compiled executable. The development checkout includes build/export tools, management-pack sources and `tools/generate_sboms.py`; exported source distributions can omit developer tooling. The customer generator now requires an explicit sanitized artifact root and derives source/component identities and hashes from that tree. It does not infer executable contents from the developer environment.

## Runtime and distribution boundaries

Core scanning requires Python 3.9+ with no required third-party pip packages. The optional vault selects AES-256-GCM when installed `pycryptodomex` or `pycryptodome` support is available; otherwise it uses the documented stdlib fallback. An existing AES vault still requires AES support to open. See [vault crypto and storage](CREDENTIAL_VAULT.md).

Styles and selected Clarity SVG icons are embedded for offline operation. The browser server also checks GitHub release metadata once per launch by default; set `VCF_READINESS_CHECK_UPDATES=0` before launch to disable that request. Public HCL downloads, Dell warranty enrichment and external credential providers require explicit operator action. Source execution does not require a package-index connection.

Standalone builds include a selected Python interpreter and its native libraries and bootloader. Their actual versions, hashes, platform and inclusion must be recorded from the build artifact. A developer machine’s installed versions or historical version list cannot establish an executable’s contents.

## Component overview

| Component | Version / identity | License / notice | Inclusion |
|---|---|---|---|
| `vcf_hci` | 9.12.0 runtime label; working-tree changes may be unreleased | LicenseRef-CA-Inc | Scanner source and generated application assets |
| `@cds/core` CSS, dark theme and selected SVG outlines | 5.7.0 | MIT; [retained notice](../licenses/clarity-core-MIT.txt) | Embedded local UI/report assets; Angular and Core custom-element runtimes are not included |
| Packaged Network I/O catalog | `vcf_hci/hcl/io_nics.json`; preserve dataset metadata/hash | Broadcom dataset terms; separate from the Clarity license | Local Network I/O correlation |
| vSAN HCL data | Operator’s local/imported snapshot; preserve provenance, timestamp and hash | Dataset terms apply | Explicit download/import or selected distribution data; not implied by tool version |
| Optional AES implementation | Actual installed `pycryptodomex` / `pycryptodome` version | Retain the installed package’s notices | Optional vault path; no required project dependency |
| Python and native runtime libraries | Build-specific | See [third-party notices](../THIRD_PARTY_LICENSES.md) and build inventory | Supplied by the operator for source use; included as selected by standalone builds |
| PyInstaller bootloader | Build-specific | GPL with bootloader exception; retain actual build notice | Standalone executable only |

`tools/bundle_assets.py` and `tools/bundle_clarity_icons.py` maintain the development checkout’s embedded assets. Running the application does not require Node.js or those generation tools.

## Excluded private and operator content

Upstream VDT remains operator-supplied through ZIP upload/install or an approved extracted folder. Local payloads under root `Plugins/` are outside source exports, wheels, offline ZIPs and executables. Scanner-owned integration code under `vcf_hci/plugins/` is separate from those upstream payloads. Managed VDT uses appliance-provided libraries; this does not make them scanner runtime dependencies or grant redistribution rights.

The Redfish working/reference library, private PSO copies, captures and experiments are outside customer shipment sources. Release tools apply private-experiment exclusions to staged copies. Review the manifest of the actual sanitized export before making shipment claims.

## Artifact verification and maintenance

For a release inventory, identify the exact source revision and build, enumerate the actual included files and dependency versions, retain notices, and generate/check CycloneDX or SPDX JSON against that artifact. Historical companion JSON remains historical. The current source snapshot inventories use `cyclonedx-customer-v9.12.0.json`, `spdx-customer-v9.12.0.json` and `customer-file-manifest-v9.12.0.json` under `docs/sbom/`. The manifest’s inventory digest ties both formats to identical observed bytes. Metadata, Python caches and derived SBOM files are excluded to avoid self-reference. This workflow did not build or publish a release executable.

From the development checkout, after preparing a sanitized source copy:

```bash
python3 tools/generate_sboms.py --scope customer --artifact-root /path/to/sanitized-source --output-dir docs/sbom
```

The generator preserves this guide. Private references, operator VDT payloads, symlinks and binary runtimes without a separate build inventory are rejected rather than silently included or assigned guessed versions.

A minimal required package set reduces supply-chain exposure; it does not eliminate vulnerabilities in Python, OpenSSL, bundled assets, optional crypto, or build tools. BMC certificate verification is disabled by default; enable `--verify-ssl` and an appropriate CA for identity validation. HTTP targets carry credentials without TLS and are accepted only with a warning.

Reports render locally. Public hyperlinks, Help illustrations or release links can require internet access when opened; no scan telemetry is sent to the project. Review obfuscated exports and exclude private keys/raw captures before sharing.
