# Encrypted Credential Vault Guide (optional)

> **Off by default.** Nothing in this guide happens unless you explicitly create a vault and ask a scan to use it. If you only ever scan with one username/password, you do not need this feature.

## 1. When to use it

- Your fleet uses **different BMC passwords per rack, cluster, or server generation** (Dell 14G vs 16G, HPE Gen9 vs Gen10, and so on).
- You want to stop keeping a **plaintext credentials CSV** on your laptop or jump box.
- You run **scripted / non-interactive** scans and need per-host credentials without putting them on the command line.

The vault stores entries of three kinds and picks the most specific one for each target:

| Kind | Example target | Matches |
|---|---|---|
| `exact` | `192.0.2.10`, `idrac-r740-01.rainpole.net`, `2001:db8::10` | that one host (hostnames are case-insensitive) |
| `cidr` | `192.0.2.0/24`, `2001:db8::/64` | any address in the subnet; the **longest prefix wins** (`/28` beats `/24`) |
| `default` | `default` (also `*`) | everything else |

Precedence: **exact → longest CIDR → default**. IPv4 ranges such as `198.51.100.10-20` are accepted on input and expanded into individual `exact` entries (up to 1,024 per range).

## 2. Security summary

- Encrypted with a passphrase you choose (12+ characters). Key derivation is PBKDF2-HMAC-SHA256 with 600,000 iterations.
- **Dual Cryptographic Modes (Progressive Enhancement):**
  - **AES-256-GCM (Hardware Accelerated):** Used automatically whenever `pycryptodomex` is installed (`pip install "vcf-readiness[crypto]"` or `pip install pycryptodomex`). Employs standard NIST AES-256-GCM with hardware AES-NI instructions.
  - **HMAC-SHA256 (Stdlib Fallback):** Used when running from source on bare bastion or jump boxes without external dependencies. Built exclusively from OpenSSL-backed stdlib primitives (`hashlib`, `hmac`, `secrets`) using counter-mode PRF keystream with Encrypt-then-MAC.
  - Both modes provide authenticated encryption with header binding (AAD) so tampering with KDF parameters, iterations, or salt is detected before decryption. See the [Security Architecture whitepaper, §3.3](SECURITY_ARCHITECTURE.md#33-optional-encrypted-local-credential-vault-opt-in-off-by-default) for details.
- Stored at `~/.vcf-readiness/credentials.vault` with owner-only permissions (`0600`; Windows ACL restricted to your account).
- **There is no passphrase recovery.** If you lose it, delete the file and create a new vault.
- Passwords are **never displayed**, never returned by the Web API, and never accepted on the command line.
- The Web UI vault features are **disabled when the server runs with `--allow-remote`**.
- Auto-locks after 60 minutes of inactivity in the Web UI and whenever the tool exits.

## 3. CSV format

```csv
# Lines starting with # and blank lines are ignored. Header names are case-insensitive.
target,username,password,note
192.0.2.10,root,CHANGE_ME,exact host
idrac-r740-01.rainpole.net,root,CHANGE_ME,hostname entry
192.0.2.0/24,admin,CHANGE_ME,whole rack (CIDR)
198.51.100.10-20,root,CHANGE_ME,IPv4 range (expanded on import)
default,root,CHANGE_ME,fallback for everything else
```

- Required columns: `target` (aliases `ip`, `host`, `hostname`, `address`), `username` (`user`), `password` (`pass`). `note` is optional.
- Quote values that contain commas or quotes per normal CSV rules (`"pa,ss""word"`).
- If the same target appears twice, the **last row wins** (a warning is shown).
- Import is **all-or-nothing** by default: one bad row aborts the whole import so you can fix it. Use `--skip-invalid` (CLI) or *Skip invalid rows* (Web UI) to import the good rows anyway.
- Get a starter file with `python -m vcf_hci.vault template > credentials.csv` or the *Download template* button in the Web UI.
- **Delete the CSV after importing.** The whole point is to not leave plaintext on disk.

## 4. Command line

### 4.1 Manage the vault

```bash
# Create (prompts twice for a new passphrase)
python -m vcf_hci.vault init

# Bulk import, then delete the plaintext file
python -m vcf_hci.vault import-csv credentials.csv
rm credentials.csv            # del credentials.csv on Windows

# Add / replace a single entry (password is prompted, or read from an env var)
python -m vcf_hci.vault add --target 192.0.2.0/24 --username admin
BMC_PW='...' python -m vcf_hci.vault add --target default --username root --password-env BMC_PW

# Inspect (no passwords are ever printed)
python -m vcf_hci.vault list
python -m vcf_hci.vault info
python -m vcf_hci.vault resolve 192.0.2.10 192.0.2.77 203.0.113.5

# Housekeeping
python -m vcf_hci.vault remove --target 192.0.2.10
python -m vcf_hci.vault change-passphrase
```

Global options for every subcommand:

| Option | Meaning |
|---|---|
| `--vault PATH` | Use a vault file other than `~/.vcf-readiness/credentials.vault` |
| `--passphrase-env VAR` | Read the vault passphrase from environment variable `VAR` instead of prompting (required when there is no TTY) |

Exit codes: `0` success, `1` vault problem (missing, wrong passphrase, corrupt), `2` usage problem (bad CSV rows, no TTY without `--passphrase-env`).

### 4.2 Scan with the vault

```bash
# Interactive: you are prompted for the vault passphrase
python vcfr_collector.py --targets 192.0.2.0/24 --vault

# Non-interactive / scheduled
export VCF_VAULT_PASSPHRASE='...'
python vcfr_collector.py --targets 192.0.2.0/24 --vault --vault-passphrase-env VCF_VAULT_PASSPHRASE --no-input

# Custom vault path
python vcfr_collector.py --targets "192.0.2.10,192.0.2.11" --vault /secure/lab.vault --vault-passphrase-env VCF_VAULT_PASSPHRASE
```

What happens:

1. The vault is opened and a coverage line is printed, e.g. `[🔐] Vault [AES-256-GCM]: 254/254 target(s) matched (exact 12, cidr 240, default 2)`.
2. Targets with **no** vault match use the ordinary `--username` / `--password-env` / `REDFISH_PASSWORD` credentials if you supplied any; otherwise they are skipped and reported as `No Credentials Provided` in the fleet report.
3. The vault is locked as soon as the scan finishes.

Without `--vault` the CLI behaves exactly as before.

## 5. Web UI

1. Open **🔐 Encrypted Credential Vault** (collapsed under the Credentials card).
2. **Create Vault** the first time (passphrase twice), or **Unlock** later. The status badge shows `no vault` / `locked` / `unlocked`.
3. An encryption mode badge beside the status badge displays the operating mode:
   - `AES-256-GCM` (blue badge) when encrypted with hardware-accelerated AES-GCM via `pycryptodomex`.
   - `HMAC-SHA256 (Stdlib)` (grey badge) when encrypted with pure standard-library primitives.
   - When no vault exists, the badge indicates creation readiness (`AES-256-GCM Ready` or `Stdlib Mode`).
4. Add entries one at a time, or **Import CSV**: paste text into the box or *Choose CSV file…*, tick *Skip invalid rows* / *Replace all existing entries* as needed, and click **Import into Vault**. Per-line errors and warnings are listed under the button.
5. In the Credentials card, tick **Use encrypted credential vault for this scan**. The checkbox is disabled until a vault is unlocked and is **never pre-selected**. A coverage line appears under it after you enter targets or probe hosts, e.g. `Vault coverage: 12 of 14 target(s) (exact 4 · CIDR 8 · default 0) — 2 unmatched: …`.
6. Optionally type a username/password in the normal fields: with the vault enabled they act only as a **fallback for unmatched hosts**. Leave the password empty to skip unmatched hosts instead.
7. Click **Run Assessment**. Credentials are resolved on the local server process; the browser never receives them. Auto-retry passes reuse the same resolved credentials.
8. Click **Lock** when you are done, or just quit — the vault locks on shutdown and after 60 minutes idle.

## 6. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Vault passphrase incorrect (or vault file tampered with)` | Wrong passphrase, or the file was modified/corrupted. Both look identical by design. |
| `Vault is encrypted with AES-256-GCM. Install 'pycryptodomex' to unlock: pip install pycryptodomex` | The vault was created on an environment with `pycryptodomex`. Install the optional package on the current system (`pip install "vcf-readiness[crypto]"` or `pip install pycryptodomex`). |
| `No credential vault at …` | Run `python -m vcf_hci.vault init` or pass the right `--vault PATH`. |
| `--vault requires --vault-passphrase-env <VAR> in non-interactive mode` | There is no TTY (cron, CI, `--no-input`). Put the passphrase in an environment variable and name it. |
| Web UI badge says `disabled` | The server was started with `--allow-remote`. The vault is local-workstation only. |
| Hosts reported as `No Credentials Provided` | They had no vault match and no fallback password. Add a `default` entry or type a fallback password. |
| Import aborted on one bad row | Fix the row (line numbers are shown) or enable *Skip invalid rows* / `--skip-invalid`. |

## 7. Files and code

| Path | Purpose |
|---|---|
| `~/.vcf-readiness/credentials.vault` | The encrypted vault (JSON envelope, base64 fields, no plaintext) |
| `vcf_hci/vault/crypto.py` | PBKDF2 + AES-256-GCM / HMAC-SHA256 EtM authenticated encryption primitives (no I/O) |
| `vcf_hci/vault/store.py` | File format, atomic `0600` writes, entries, resolver |
| `vcf_hci/vault/csv_import.py` | CSV parser |
| `vcf_hci/vault/__main__.py` | `python -m vcf_hci.vault` management commands |
| `vcf_hci/web/vault_session.py` | Single in-memory unlocked vault for the Web UI, idle auto-lock |
| `tests/test_vault_*.py`, `tests/test_web_vault_api.py` | Test coverage |

## 8. Jump hosts (Experimental)

> **Experimental Feature:** Jump-host SSH profiling and remote execution orchestration are experimental capabilities. Profiles configure ephemeral SSH worker sessions to run assessments directly within customer network segments.

Jump-host SSH profiles live in the same vault file as BMC credentials, under a `jump_hosts` object. Older vaults that lack the object open with an empty jump-host list.

```bash
# Add a jump host with one or more subnets
python -m vcf_hci.vault jump-host add --id dal-jump-01 --host 192.0.2.10 --user ubuntu --key ~/.ssh/id_ed25519 --subnets "192.0.2.0/24, 192.0.3.0/24"

# Add more subnets to an existing jump host without recreating it
python -m vcf_hci.vault jump-host add-subnet --id dal-jump-01 198.51.100.0/24 203.0.113.0/24

# Replace all attached subnets
python -m vcf_hci.vault jump-host set-subnets --id dal-jump-01 192.0.2.0/24 192.0.3.0/24

# Remove specific subnets
python -m vcf_hci.vault jump-host remove-subnet --id dal-jump-01 203.0.113.0/24

# Edit jump host properties (subnets, note, host, etc.) keeping secrets intact
python -m vcf_hci.vault jump-host edit --id dal-jump-01 --note "Updated Dallas lab" --add-subnets 10.0.0.0/16

# List jump hosts
python -m vcf_hci.vault jump-host list

# Remove a jump host
python -m vcf_hci.vault jump-host remove --id dal-jump-01

# CSV export template & import
python -m vcf_hci.vault jump-host template > jump_hosts.csv
python -m vcf_hci.vault jump-host import-csv jump_hosts.csv
```

CSV columns: `id,host,port,username,key_path,subnets,note,is_default`. Subnets in one cell are separated by semicolons. The cell `default` marks the fallback host. Do not put passwords or private keys in the CSV. `list` prints ids, hosts, usernames, and subnet maps only.

### Web UI Jump Host Management

The web UI Jump hosts table allows full management without recreation:
- **Subnets Button**: Click **Subnets** on any jump host row to open the interactive **Edit Subnets** modal. You can view existing subnets, delete unwanted subnets (✕), or add one or more new CIDRs at once (comma, space, or semicolon separated). Saving updates the vault immediately without touching private keys, passwords, or host key pins.
- **Edit Button**: Click **Edit** on a jump host row to populate the configuration form in edit mode. Existing private keys and passwords remain stored and encrypted in the vault unless explicitly overwritten. Click **Update jump host** to save or **Cancel edit** to reset the form.
- **Multi-Subnet Input**: The Subnets input field supports multiple CIDRs separated by commas (e.g. `192.0.2.0/24, 192.0.3.0/24, 10.0.0.0/16`).

The web UI Jump hosts section uses the same records. Test connection checks Python 3.9+, a writable `/tmp`, and free space. It does not print key material.
