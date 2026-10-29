# Install and run from source

Running the Python source is the supported, auditable path. Release archives may also provide platform executables; check the actual assets for your release. Developer build tooling lives in the development checkout and is not required for source execution.

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

In source bundles that include it, double-click `Launch-VCF-Readiness-Web.bat` to find Python 3.9+ and start the UI. Extract the entire ZIP first and keep the launcher beside `vcfr_web.py`. In standalone Windows bundles, the same launcher runs the included EXE without Python. Windows does not use `chmod`.

The Python commands above work without executable permissions. The source ZIP stores Unix executable permissions, which some extractors may discard. If you choose to launch directly with `./vcfr_web.py` on macOS/Linux and get a permission error, run `chmod +x vcfr_web.py` first.

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

The browser scanner separately checks public GitHub release metadata once per launch in a background thread. A newer stable release adds an **Update available** link beside the version. The check does not send scan targets, credentials or results, and it does not install updates. Network failures do not delay scanning. To suppress this optional request on an offline host, set `VCF_READINESS_CHECK_UPDATES=0` before starting the scanner:

```bash
VCF_READINESS_CHECK_UPDATES=0 python3 vcfr_web.py
```

On Windows Command Prompt:

```cmd
set VCF_READINESS_CHECK_UPDATES=0
python vcfr_web.py
```

In the browser, open **Advanced Configuration → Broadcom HCL Database & Dark-Site Bundle**:

1. On a connected scanner, choose **Refresh Live HCL** if newer data is needed, then **Export Dark-Site HCL ZIP**.
2. Transfer the downloaded ZIP to the disconnected scanner.
3. Choose **Import Dark-Site HCL ZIP** there and review its source, dataset age and coverage before scanning. The same HCL controls are available from the Scan Wizard.

Export snapshots the active custom bundle, existing local bundle or local cache without downloading new data. It includes compatibility catalogs and provenance/hashes, not scan results, credentials or application code. Exporting does not make old data fresh. CPU policy and built-in supplements belong to the scanner version; use matching scanner versions for consistent policy results. Browser exports are capped at 23 MiB so the existing browser importer can accept them.

To preload a transferred bundle when starting the Web UI from a terminal:

```bash
python3 vcfr_web.py --import-hcl /approved-transfer/vcf_hcl_bundle.zip
```

To import an approved offline bundle for a CLI scan:

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

The default output is `vcf_hcl_bundle_YYYYMMDD.zip` under `~/.vcf-readiness/hcl/` (`%USERPROFILE%/.vcf-readiness/hcl/` on Windows). On Windows, use `python` instead of `python3`. Transfer the ZIP to the scanner workstation and select **Scan Wizard → HCL readiness → Import Dark-Site HCL Zip**. The same import control is available in **Advanced Configuration**.

The generator can fall back to an existing cache or a limited baseline when download fails. New bundles retain the cached dataset timestamp; the wizard flags known baselines and missing, unknown, or stale evidence. Confirm the data source and coverage before treating results as certification evidence. Older bundles may only record packaging time rather than the original dataset age.

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

### Scanner appearance and forgotten vault passphrases

Scanner and HTML reports use local Clarity SVG icons by default. No icon download is needed in a darksite. The legacy emoji display controls have been retired; old saved settings are ignored. Collected data, user labels, copied paths and text exports preserve their original Unicode.

If the vault passphrase is forgotten, open **Credential Vault → Forgot the vault passphrase?** for the actual file path and reset procedure. Quit the app first, then rename or delete only that encrypted vault file, restart and create a new vault. Stored credentials and jump-host data must be recreated; scan/report files need not be deleted. See [vault reset instructions](CREDENTIAL_VAULT.md#forgotten-passphrase-reset-the-local-vault).
