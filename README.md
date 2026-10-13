# VCF Readiness Assessment Tool

<p align="center">
  <img src="docs/branding/branding-kit/production/vcf-r-readme-header.svg" alt="VCF-R - VCF Readiness Assessment" width="720">
</p>

VCF Readiness is a source-available Python tool that reads hardware inventory from server management controllers and produces local VCF 9.1 and vSAN readiness reports.

The recommended path is to run the source in this repository. It requires no runtime packages beyond Python's standard library.

## Before you start

You need:

- Python 3.9 or newer.
- A current browser for the local web interface.
- Network access from this computer to each BMC management address.
- A BMC account intended for read-only inventory access.
- Permission from the system or network owner to assess the targets.

Check Python:

```bash
python3 --version          # macOS or Linux
python --version           # Windows
```

Run all commands below from the repository root, the directory containing `vcfr_web.py`.

## Glossary

- **BMC**: the out-of-band management controller, such as Dell iDRAC, HPE iLO, Lenovo XCC, Cisco IMC, or a generic Redfish controller.
- **Redfish**: the HTTPS management API used to read hardware inventory.
- **VCF**: VMware Cloud Foundation.
- **vSAN ESA/OSA**: vSAN storage architectures evaluated by the readiness rules.
- **HCL/BCG**: locally cached compatibility data and links to the Broadcom Compatibility Guide.
- **Fleet report**: one summary covering all successfully assessed hosts.

## Run your first verified scan

### 1. Start the local web interface

macOS or Linux:

```bash
python3 vcfr_web.py
```

Windows:

```cmd
python vcfr_web.py
```

The server binds to loopback and opens a one-time launch URL in your browser. If no browser opens, use the URL printed in the terminal. The preferred port is `7182`; the server selects a nearby free port if it is occupied.

### 2. Enter one target

In the browser:

1. Enter one BMC IP address or hostname that you are authorized to assess.
2. Enter the read-only BMC username and password.
3. Leave the scan profile at its default for the first run.
4. Choose an output directory you control.
5. Start the assessment and wait for the completed-host message.

### 3. Verify the result

Open the generated scan directory. A successful scan normally contains:

- `00_fleet_summary.html`: fleet-level dashboard.
- `00_fleet_combined.html`: combined fleet and host view, unless disabled.
- an `.xlsx` workbook, unless disabled.
- `reports/vsphere_vsan_report_<target>.html`: standalone host report.
- `MANIFEST.json` and `Readme.txt`: provenance and output guidance.
- `data/`: structured data when the selected options produce it.

Exact files depend on scan success and options such as `--save-json`, `--csv-export`, `--obfuscate`, `--crawl`, and `--no-combined`.

## Command-line scan

Use an environment variable so the password is not placed in shell history:

```bash
export REDFISH_PASSWORD='replace-me'
python3 vcfr_collector.py \
  --targets 192.0.2.50 \
  --username readonly \
  --password-env REDFISH_PASSWORD \
  --output-dir ./VCF-Scans
```

On Windows Command Prompt:

```cmd
set REDFISH_PASSWORD=replace-me
python vcfr_collector.py --targets 192.0.2.50 --username readonly --password-env REDFISH_PASSWORD --output-dir VCF-Scans
```

Inspect the authoritative option list in your checkout:

```bash
python3 vcfr_collector.py --help
python3 -m vcf_hci.web --help
```

Supported target input is an IP address, hostname, comma-separated list, final-octet range such as `192.0.2.1-20`, or CIDR. Use `--profile readiness-lean` or `--lean` for the supported faster readiness profile.

Previously saved summaries can be rendered without contacting BMCs:

```bash
python3 vcfr_collector.py --from-summary ./VCF-Scans/Scan_example
```

## Security and network behavior

### Strict read-only collection

The collector blocks BMC configuration changes. It permits read methods, Redfish session creation and teardown, and protocol-required read-semantic POSTs used by WS-Man and Cisco XML inventory. It does not invoke power, reset, firmware, account, BIOS, boot, or configuration actions.

A read-only BMC account is still required. A vendor may restrict some inventory endpoints, so missing fields can reflect account permissions or firmware behavior.

### Offline by default

An ordinary scan contacts the targets you provide and writes reports locally. It does not send analytics, telemetry, crash reports, or scan results to the project.

Public-network egress is explicit:

- `--refresh-hcl`, `--bundle-hcl`, or the equivalent web action downloads public Broadcom HCL data.
- Dell TechDirect warranty enrichment contacts Dell only after credentials are supplied and the feature is enabled.
- External credential providers contact their configured service only when explicitly configured.
- Experimental jump-host execution uses SSH only when selected in the local web UI.

The CLI and web UI otherwise use existing local HCL data and packaged baselines. See [Security Architecture](docs/SECURITY_ARCHITECTURE.md) for the protocol details.

### TLS

BMC certificate verification is disabled by default to support self-signed management controllers. Prefer `--verify-ssl` and `--ca-bundle` when your environment has a trusted BMC CA. `--legacy-tls` deliberately weakens protocol compatibility and should be used only for an approved legacy controller.

The browser UI is local-only by default. For a headless host, keep it on loopback and use SSH port forwarding; see [Installation](docs/INSTALL.md).

## What the assessment covers

Depending on what a BMC exposes, reports can include:

- CPU generation and VCF support classification.
- Memory inventory and topology observations.
- Storage controllers, physical drives, NVMe health, and vSAN readiness.
- Network adapters, link speeds, firmware data, and LLDP/CDP neighbors.
- BIOS, BMC firmware, TPM, boot, power, thermal, GPU, and event-log inventory.
- Read-only BMC security findings.
- Fleet HTML, host HTML, Excel, CSV, JSON, and obfuscated outputs.

Collectors include generic DMTF Redfish plus OEM handling for vendors represented in `vcf_hci/collector/oem/`. Support depth varies by model, BMC generation, firmware, license, and exposed schema.

## Limitations

- This is an assessment aid, not a substitute for current Broadcom product documentation, support policy, or a final design review.
- A green result does not certify a server or guarantee upgrade success.
- Compatibility data can become stale. The default-offline behavior does not refresh it automatically.
- Self-signed TLS is accepted unless verification is enabled.
- Some BMCs omit fields, rate-limit requests, require extra licenses, or return partial inventory.
- The tool does not configure hardware, remediate findings, install software, or change firmware.
- Remote jump-host execution is experimental and available through the local web UI; there is no standalone remote-scan CLI.
- This repository does not promise prebuilt binaries or release assets. Run from source unless a separately verified distribution is supplied by your organization.

## Troubleshooting

### `python` or `python3` is not found

Install Python 3.9 or newer from [python.org](https://www.python.org/downloads/) or your operating system's approved package source, then open a new terminal.

### `ModuleNotFoundError: No module named 'vcf_hci'`

Change to the repository root before launching:

```bash
cd /path/to/vcf-readiness
python3 vcfr_web.py
```

### The browser does not open

Copy the one-time URL printed by `vcfr_web.py`. For a headless machine, follow the SSH forwarding steps in [docs/INSTALL.md](docs/INSTALL.md).

### Authentication fails

Confirm the BMC address, username, password, account lockout state, and read privileges. Do not paste credentials into an issue or log.

### The BMC is unreachable or the scan is partial

Check the management VLAN or VPN route and HTTPS reachability. Reduce `--threads`, increase `--host-timeout`, or try `--allow-partial` for slow controllers. Review the generated failed-host CSV and debug log before sharing them; they may contain sensitive infrastructure data.

### Certificate validation fails

Use the correct enterprise CA with `--ca-bundle`, confirm the target hostname matches the certificate, and enable DNS lookup only if your environment permits it. Do not work around a production trust failure without approval.

### No HCL match appears

The local dataset may be absent or stale. Import an approved offline bundle with `--import-hcl`, or explicitly refresh from an internet-connected environment with `--refresh-hcl`.

## More documentation

- [Installation and headless use](docs/INSTALL.md)
- [Architecture](ARCHITECTURE.md)
- [Security architecture](docs/SECURITY_ARCHITECTURE.md)
- [Credential vault](docs/CREDENTIAL_VAULT.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE.md)