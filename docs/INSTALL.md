# Install and run from source

Running the tracked Python source is the supported, auditable path. This checkout does not promise a prebuilt executable or a local build script.

## Requirements

- Python 3.9 or newer.
- A modern browser for the web UI.
- Network access to authorized BMC management addresses.
- A read-only BMC account.

No runtime `pip install` is required. VCF Readiness uses the Python standard library.

## Get the source

Use your organization's approved Git workflow, then enter the repository root:

```bash
git clone https://github.com/vmware/vcf-readiness.git
cd vcf-readiness
```

If you received an approved source archive instead, extract it and change into the directory containing `vcfr_web.py`.

## Verify Python

macOS or Linux:

```bash
python3 --version
```

Windows:

```cmd
python --version
```

The result must be Python 3.9 or newer. If Python is absent, install it from [python.org](https://www.python.org/downloads/) or an operating-system/package source approved by your organization.

## Start the web UI

macOS or Linux:

```bash
python3 vcfr_web.py
```

Windows:

```cmd
python vcfr_web.py
```

The UI binds to loopback and prints a one-time launch URL. It normally opens that URL in the default browser. Stop it with `Ctrl-C` or the Quit control.

Check all web-server options:

```bash
python3 -m vcf_hci.web --help
```

## Run the CLI

Show the authoritative options:

```bash
python3 vcfr_collector.py --help
```

Example:

```bash
export REDFISH_PASSWORD='replace-me'
python3 vcfr_collector.py \
  --targets 192.0.2.50 \
  --username readonly \
  --password-env REDFISH_PASSWORD \
  --output-dir ./VCF-Scans
```

Windows Command Prompt:

```cmd
set REDFISH_PASSWORD=replace-me
python vcfr_collector.py --targets 192.0.2.50 --username readonly --password-env REDFISH_PASSWORD --output-dir VCF-Scans
```

Passwords are not accepted as a CLI value. Interactive prompting, `--password-env`, `--creds-stdin`, or the opt-in local vault supplies them without placing a secret in the argument list.

## Headless host with SSH forwarding

Keep the web UI on loopback. From your workstation, open a tunnel:

```bash
ssh -L 7182:127.0.0.1:7182 user@server
```

In that SSH session, from the repository root:

```bash
python3 vcfr_web.py --no-browser
```

Copy the one-time URL printed by the server and open it on your workstation. If port `7182` was already occupied, use the selected port shown in the output and recreate the tunnel for that port.

Do not expose the UI on a reachable interface merely to avoid SSH forwarding. Non-loopback server mode is advanced, requires explicit remote-listener permission and TLS material, and disables local-workstation features. It is different from experimental jump-host scan execution.

## Offline and air-gapped operation

Ordinary scans use packaged or existing local compatibility data and do not download HCL data automatically.

To import an approved offline bundle:

```bash
python3 vcfr_collector.py \
  --targets 192.0.2.50 \
  --import-hcl /approved-transfer/vcf_hcl_bundle.zip
```

On an internet-connected staging host, these commands explicitly allow a public Broadcom HCL download:

```bash
python3 vcfr_collector.py --bundle-hcl
python3 vcfr_collector.py --targets 192.0.2.50 --refresh-hcl
```

Transfer generated data through your organization's approved process. HCL bundles are local archives, not encrypted containers.

## TLS choices

The default supports self-signed BMC certificates and therefore does not verify them. Where an enterprise BMC CA exists, use:

```bash
python3 vcfr_collector.py \
  --targets bmc01.rainpole.net \
  --verify-ssl \
  --ca-bundle /path/to/bmc-ca.pem
```

Only use `--legacy-tls` for an approved legacy controller. It relaxes TLS protocol compatibility.

## Optional development environment

Application runtime needs no installation. Contributors can install the declared development tools in an isolated environment:

```bash
python3 -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
python -m pip install -e '.[dev]'
```

See [CONTRIBUTING.md](../CONTRIBUTING.md) for canonical checks.

## Troubleshooting

### Python cannot find `vcf_hci`

Run the command from the repository root:

```bash
cd /path/to/vcf-readiness
python3 vcfr_web.py
```

### The launch URL does not open

Copy the URL from the terminal. It contains a one-time token, so do not post or share it.

### The BMC cannot be reached

Verify management VLAN or VPN connectivity and HTTPS access to the target. The application cannot route around a firewall.

### Authentication fails

Confirm the account is enabled, not locked, and has enough read access to inventory endpoints. Do not send credentials in bug reports.

### The scan is slow or partial

Reduce `--threads`, increase `--host-timeout`, or use `--allow-partial`. For a supported faster profile, use `--profile readiness-lean` or `--lean`.

### Certificate verification fails

Confirm the CA file, certificate validity, and hostname. If you target an IP while the certificate names a DNS host, verification can fail.

### Reports are not where expected

Check the final output directory printed by the application. The default is under `~/Desktop/VCF-Scans`; a scan-specific directory contains the generated artifacts.

### The HCL appears stale

Default-offline operation intentionally does not refresh data. Use an approved imported bundle or explicitly run an HCL refresh from a network where public egress is allowed.
