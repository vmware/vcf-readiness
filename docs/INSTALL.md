# Installing & Running the VCF Readiness Tool

This guide covers every way to run the tool, from the simplest (download a binary, double-click) to the most flexible (run from Python source on any platform).

| Scenario | Who it's for |
|----------|-------------|
| [Option A — Download & double-click](#option-a--download-the-pre-built-binary-simplest) | Anyone — no Python, no command line |
| [Option B — Web UI from source](#option-b--web-ui-from-python-source-recommended) | Users who can open a terminal — easiest source path |
| [Option C — Build the binary yourself](#option-c--build-the-binary-yourself) | Developers or anyone who wants to compile their own copy |

---

## Option A — Download the pre-built binary (simplest)

No Python installation required. The binary bundles everything.

### Windows

1. Go to the [**Latest Release page**](https://github.com/vmware/vcf-readiness/releases/latest) and download **`VCF-Readiness-Web.exe`**.
2. Move it anywhere convenient — your Desktop is fine.
3. Double-click `VCF-Readiness-Web.exe`.
4. **First launch only:** Windows SmartScreen may show "Windows protected your PC."
   - Click **More info**
   - Click **Run anyway**
   - You only have to do this once per machine.
5. Your browser opens automatically at `http://127.0.0.1:7182`. Fill in your BMC IP addresses, credentials, and output folder, then click **Run Assessment**.

> **Why the warning?** SmartScreen blocks executables without a download reputation. This is normal for internal tools. "Run anyway" is safe.

### macOS

1. Go to the [**Latest Release page**](https://github.com/vmware/vcf-readiness/releases/latest) and download **`VCF-Readiness-Web-v<version>-mac.zip`**.
2. Double-click the `.zip` archive to extract it. Inside the unzipped folder you will find:
   - **`Launch-VCF-Readiness-Web.command`** (Double-click launcher script)
   - **`VCF-Readiness-Web-v<version>-mac`** (Standalone binary)
   - **`HOW_TO_OPEN_ON_MAC.txt`** (Quick start instructions)
3. **Double-click `Launch-VCF-Readiness-Web.command`** to start the web server.
4. **First launch only (macOS Gatekeeper bypass):**
   - If macOS shows *"cannot be opened because the developer cannot be verified"*:
   - **Right-click** (or Control-click) `Launch-VCF-Readiness-Web.command` → choose **Open**
   - Click **Open** in the confirmation dialog.
   - After doing this once, double-clicking will work every time.
5. Your browser opens automatically at `http://127.0.0.1:7182`.

> **Why the launcher script (`.command`)?** macOS Finder recognizes `.command` files as runnable scripts and launches them in Terminal.app with execute permissions intact, starting the web server and opening your browser.

> **Why the warning?** Apple's Gatekeeper blocks software not distributed through the Mac App Store. Right-click → Open is the standard bypass for trusted internal tools. You only do this once.

---

## Option B — Web UI from Python source (recommended)

The browser UI requires **no Tkinter** and no GUI framework — only Python 3.9+ and a browser. This is the cleanest source-based path on all three platforms.

### Do you have Python?

Open a terminal and run:
```bash
python3 --version    # macOS / Linux
python --version     # Windows
```
If it prints `Python 3.9.x` or higher, skip to [Launch the web UI](#launch-the-web-ui). Otherwise install Python first:

---

### Install Python — Windows

1. Go to [https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/) and download the latest **Windows installer (64-bit)**.
2. Run the installer.
   - **Critical:** On the first screen, check **"Add python.exe to PATH"** before clicking Install Now.
3. Open **Command Prompt** (Start → type `cmd` → Enter).
4. Verify: `python --version` — should print `Python 3.x.x`

---

### Install Python — macOS

1. Open **Terminal** (Spotlight → type `Terminal` → Enter).
2. Install Homebrew if you don't already have it:
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```
3. Install Python:
   ```bash
   brew install python
   ```
4. Verify: `python3 --version` — should print `Python 3.x.x`

> **No `brew install python-tk` needed.** The web UI runs in your browser — it has no Tkinter requirement.

---

### Install Python — Linux

Most Linux distributions include Python 3. If the `python3 --version` check shows nothing or an older version:

```bash
# Ubuntu / Debian / Linux Mint
sudo apt update && sudo apt install python3

# RHEL / CentOS / AlmaLinux / Rocky Linux
sudo dnf install python3

# Arch Linux
sudo pacman -S python
```

Verify: `python3 --version`

---

### Launch the web UI

Once Python is installed, download or clone the project, then:

```bash
# macOS / Linux
cd ~/Documents/Distribution-Redfish-Scraper
python3 vcfr_web.py

# Windows (Command Prompt)
cd C:\Users\YourName\Documents\Distribution-Redfish-Scraper
python vcfr_web.py
```

Your browser opens at `http://127.0.0.1:7182` automatically. The tool runs until you click **Quit** in the browser or press `Ctrl-C` in the terminal.

> **No `pip install` needed.** This tool has zero external dependencies — it runs entirely on the Python standard library.

---

### Using on a headless or SSH-accessed server

The web UI still works if the tool runs on a machine you access via SSH (e.g., a bastion host, a Linux VM, or a management server with no display). Forward port 7182 to your local machine:

```bash
# Run this on your local machine (replace user@server with your details)
ssh -L 7182:127.0.0.1:7182 user@server

# Inside the SSH session, start the tool:
python3 vcfr_web.py

# Now open http://127.0.0.1:7182 in your local browser
```

The scan runs on the server (with direct access to your BMC network) while the browser UI is on your laptop.

---

## Option C — Build the binary yourself

This produces a single double-click file that you can hand to colleagues with no Python installation.

### Prerequisites

- Python 3.9 or newer (see Option B above)
- The project source code (this repository)

### Web UI binary (recommended)

```bash
# macOS / Linux
cd ~/Documents/Distribution-Redfish-Scraper
chmod +x build-web.sh    # one time only
./build-web.sh
# → dist/VCF-Readiness-Web-v<version>-mac   (macOS, with .zip archive)
# → dist/VCF-Readiness-Web-v<version>-linux (Linux, with .zip archive)

# Windows (Command Prompt)
cd C:\Users\YourName\Documents\Distribution-Redfish-Scraper
build-web.bat
# → dist\VCF-Readiness-Web-v<version>-win.exe (with .zip archive)
# → logs\build-web.log
```

The build scripts install PyInstaller automatically if it isn't already present. When the build finishes:

```
==> Build complete:  dist/VCF-Readiness-Web-mac
```

### Corporate / Firewall-Restricted Environments (Internal PyPI Mirrors)

Corporate firewalls frequently block direct outbound access to public PyPI (`files.pythonhosted.org`), which causes `pip install` or PyInstaller setup to fail with `Connection refused` or `HTTPSConnectionPool` timeouts.

If your organization hosts an internal PyPI mirror or artifact repository (such as Artifactory or Nexus), configure `pip` or `uv` to point to your internal index:

#### Linux (`~/.pip/pip.conf` or system-wide `/etc/pip.conf`)
```ini
[global]
index-url = https://packages.rainpole.net/artifactory/api/pypi/pypi-virtual/simple
extra-index-url = https://pypi.rainpole.net/simple
trusted-host = packages.rainpole.net pypi.rainpole.net
```
*(Replace `packages.rainpole.net` with your organization's internal mirror hostname).*

#### macOS (`~/Library/Application Support/pip/pip.conf` or `~/.pip/pip.conf`)
```ini
[global]
index-url = https://packages.rainpole.net/artifactory/api/pypi/pypi-virtual/simple
extra-index-url = https://pypi.rainpole.net/simple
trusted-host = packages.rainpole.net pypi.rainpole.net
```

#### Windows (`%APPDATA%\pip\pip.ini` or `C:\ProgramData\pip\pip.ini`)
```ini
[global]
index-url = https://packages.rainpole.net/artifactory/api/pypi/pypi-virtual/simple
extra-index-url = https://pypi.rainpole.net/simple
trusted-host = packages.rainpole.net pypi.rainpole.net
```

#### Using `uv` (`~/.config/uv/uv.toml`)
```toml
[[index]]
url = "https://packages.rainpole.net/artifactory/api/pypi/pypi-virtual/simple"
default = true

[[index]]
url = "https://pypi.rainpole.net/simple"
```

#### Command-Line Arguments
You can also supply your internal mirror index directly on any `pip install` command:
```bash
pip install "pyinstaller==6.*" \
  --index-url https://packages.rainpole.net/artifactory/api/pypi/pypi-virtual/simple \
  --extra-index-url https://pypi.rainpole.net/simple
```

### Building Windows Binaries

On a Windows build host with Python 3.9+ and PyInstaller installed:
```cmd
build-web.bat
```
This produces the standalone Windows single-file executable and zip archive in `dist/`.

---

## What the tool needs at runtime

The tool only needs network access to your **BMC management IPs** — the iDRAC / iLO / BMC addresses on your lab or customer network. It does not phone home, and it does not require internet access to run a scan.

An internet connection is used only for optional features:
- **HCL refresh** (`--refresh-hcl`) — downloads the latest Broadcom vSAN drive certification list (`all.json` cached in `~/.vcf-readiness/hcl/` with 30-day max-age)

### Dark-Site Air-Gapped Environments

For environments with no internet access:
- **Auto dark-site bundle**: Automatically created and maintained under `~/.vcf-readiness/hcl/vcf_hcl_bundle_latest.zip` (30-day freshness).
- **Import existing bundle**: Use `--import-hcl <path/to/bundle.zip>` during CLI scans to import an air-gapped HCL bundle archive.
- **Export bundle on internet-connected host**: Run `python vcfr_collector.py --bundle-hcl` to generate `vcf_hcl_bundle_YYYYMMDD.zip` for transfer to dark-site environments.

### About bundled Clarity CSS

The browser UI is styled with [Clarity Design System](https://clarity.design/) tokens. The CSS is pre-bundled inside `vcf_hci/web/assets.py` as compressed, base64-encoded data — **no internet connection is needed at runtime**.

If you are a developer and want to refresh the bundled CSS to a newer Clarity release:
```bash
python tools/bundle_assets.py    # requires internet — dev only
```

---

## Security & InfoSec Compliance

If your organization's Information Security or Cyber Risk team requires review and vetting before granting BMC access or running the assessment:
- See the comprehensive [**Security Architecture Whitepaper**](SECURITY_ARCHITECTURE.md).
- Explains the **Principle of Least Privilege** (read-only BMC account, zero write/flash), **Zero Telemetry** guarantee, **Zero Third-Party Pip Dependencies** (Python stdlib-only), **Data Obfuscation Engine**, and legal permissions for running automated SAST or LLM code audits (e.g., Mythos, Fable, CodeQL).
- If your fleet uses different BMC passwords per rack or generation, the optional (off by default) **encrypted local credential vault** is documented in the [Credential Vault Guide](CREDENTIAL_VAULT.md) and whitepaper §3.3.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| macOS: "cannot be opened because the developer cannot be verified" | Right-click → Open → Open |
| Windows: "Windows protected your PC" | More info → Run anyway |
| Windows: `python` not found | Re-run the Python installer, check "Add python.exe to PATH" |
| Linux: browser doesn't open automatically | Manually navigate to `http://127.0.0.1:7182` |
| Linux: port 7182 blocked by firewall | Tool is bound to `127.0.0.1` (loopback only) — no firewall rule needed for local use; for SSH forwarding see Option B |
| Cannot reach BMC IPs | Confirm you're on the correct management VLAN / VPN |
| Reports not generated | Check the output folder path has no special characters; try `~/Desktop` |
| `ModuleNotFoundError: No module named 'vcf_hci'` | Run from the project root directory (where `vcfr_web.py` lives) |
| `pip install` fails with `Connection refused` or `HTTPSConnectionPool` | Corporate firewall blocks public PyPI. Configure `pip.conf` / `pip.ini` with internal Artifactory mirrors (see above). |

---

## CLI usage (advanced)

The tool also has a command-line interface for scripting and automation:

```bash
# macOS / Linux (from source)
python3 vcfr_collector.py --targets 10.0.0.1 --output-dir ~/Desktop/reports

# Scan a range with 8 parallel threads
python3 vcfr_collector.py --targets "192.168.1.0/24" --threads 8

# Force-refresh the Broadcom HCL drive list
python3 vcfr_collector.py --targets 10.0.0.1 --refresh-hcl

# Verbose debug log (useful for troubleshooting BMC connectivity)
python3 vcfr_collector.py --targets 10.0.0.1 --debug

# Optional: per-host / per-subnet passwords from the encrypted local vault (off unless --vault is given)
python3 -m vcf_hci.vault init && python3 -m vcf_hci.vault import-csv credentials.csv
python3 vcfr_collector.py --targets "192.168.1.0/24" --vault
```

If you installed the package via `pip install .`, the console script entry points `vcf-assess` (CLI) and `vcf-readiness-web` (Browser UI) are available:

```bash
vcf-assess --targets 10.0.0.1
vcf-readiness-web
```
