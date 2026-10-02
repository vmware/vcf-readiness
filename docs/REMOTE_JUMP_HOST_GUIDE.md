# Remote jump-host scans (Experimental) — operator guide

> **Experimental Feature Notice:**
> Remote jump-host execution is currently in active preview / experimental status. This feature deploys an ephemeral, unprivileged self-contained Python zipapp worker to remote Linux jump hosts via SSH. Ensure test connectivity, mandatory SSH host key pinning, and prerequisite verification (Python 3.9+, 500 MiB free in `/tmp`) prior to large-scale fleet scans.

The web UI stays on `127.0.0.1`. A remote scan copies a single Python zipapp to a Linux jump host, runs it as an unprivileged user under `/tmp`, and pulls the reports back. The jump host needs OpenSSH and Python 3.9 or newer. It does not need pip, a virtualenv, or root.

Examples below use the documentation names `jump.rainpole.net`, `192.0.2.0/24`, and `198.51.100.0/24`.

## Add a jump host

```bash
python -m vcf_hci.vault jump-host add \
  --id dal-jump-01 \
  --host 192.0.2.10 \
  --user ubuntu \
  --key ~/.ssh/id_ed25519 \
  --subnets "192.0.2.0/24, 192.0.3.0/24" \
  --note "Dallas lab"
```

`--key` stores the path. The private key stays in your `~/.ssh` directory. To store the key inside the vault instead, pass `--key-file` or `--key-env`. Those values are encrypted with the vault. `jump-host list` never prints them.

### Attach more subnets or edit without recreating

You can add or update subnets on an existing jump host at any time without recreating it or re-entering keys/passwords:

```bash
# Add more subnets to an existing jump host
python -m vcf_hci.vault jump-host add-subnet --id dal-jump-01 198.51.100.0/24 203.0.113.0/24

# Replace all attached subnets
python -m vcf_hci.vault jump-host set-subnets --id dal-jump-01 192.0.2.0/24 192.0.3.0/24

# Edit properties in place
python -m vcf_hci.vault jump-host edit --id dal-jump-01 --note "Updated Dallas lab"
```

In the Web UI, click the **Subnets** button on any row in the Jump hosts table to add or remove subnets interactively via the **Edit Subnets** modal, or click **Edit** to populate the configuration form in edit mode with stored secrets preserved.

CSV import accepts key paths only, not passwords or private keys:

```bash
python -m vcf_hci.vault jump-host template > jump_hosts.csv
python -m vcf_hci.vault jump-host import-csv jump_hosts.csv
```

Mark one host with `--default` (or `is_default` in the CSV) so hostnames and unmatched addresses have somewhere to go.

### Mandatory SSH Host Key Pinning

Jump host connections strictly enforce SSH host key pinning before credentials or commands are transmitted (`StrictHostKeyChecking=yes` against an isolated `known_hosts` file).

To pin a jump host SSH public key via the CLI:

```bash
# Interactive check (probes host key, displays fingerprint, prompts to pin)
python -m vcf_hci.vault jump-host pin-key --id dal-jump-01

# Non-interactive / automation check against verified out-of-band fingerprint
python -m vcf_hci.vault jump-host pin-key \
  --id dal-jump-01 \
  --accept-fingerprint 'SHA256:...'
```

In the Web UI, clicking **Pin Key** (or clicking **Test** or **Run Assessment** on an unpinned host) probes the host key via `ssh-keyscan` without sending credentials, displays the SHA256 fingerprint, and records the pin only after operator approval via **Trust & Pin**.

## Scan from the command line

Remote execution is fully integrated with the encrypted credential vault and Web UI.
To execute a scan against targets routed through the configured network profile:

```bash
python3 vcfr_collector.py --targets 192.0.2.10,198.51.100.20
```

## Scan from the web UI

1. Unlock the credential vault.
2. Open Jump hosts, save the profile, and use Test.
3. On the scan form choose Remote jump host, then Auto-route by subnet or a specific host.
4. Leave Use encrypted credential vault checked and start the scan.

Progress uses the same live event stream as a local scan. Reports land in the output folder you already chose.

## What the jump host must allow

- SSH on the configured port (usually 22).
- `python3` at version 3.9 or newer (`python3 --version`).
- A writable `/tmp` with at least 500 MiB free.
- Network reachability from the jump host to the BMC addresses.

Ubuntu 20.04 often ships Python 3.8 as `python3`. Install a 3.9+ interpreter or use a newer image. This tool does not run `apt` for you.

## If a run is interrupted

The remote directory is `/tmp/vcfr_remote_` plus 8 to 16 hex characters. After a successful artifact pull the current sandbox is deleted (`retain=0`). The next scan also deletes a leftover directory only when it contains a valid `.vcfr_marker` and the lock pid is not a live collector. A live scan is left alone unless you pass `--force` on the command line.

If the report download fails, the remote directory is kept and the message names it for troubleshooting. Leftover sandboxes in `/tmp` can be safely inspected or removed after diagnostics.
