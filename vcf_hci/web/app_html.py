"""
VCF Readiness Tool — Clarity-styled single-page app HTML template.

build_app_html() returns a fully self-contained HTML string that the server
serves on GET /. All CSS (Clarity tokens + custom components) and JavaScript
(SSE client, form logic, dark mode) are inlined — zero external requests at
runtime.
"""
from vcf_hci.web.app_css import APP_CSS
from vcf_hci.web.app_js import APP_JS


def build_app_html(tool_version: str, collector_ok: bool, server_token: str = "", oem_mode: bool = False) -> str:
    keychain_note = _get_keychain_label()

    return f"""<!DOCTYPE html>
<html lang="en" cds-base-font="16" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>VCF Readiness  v{tool_version}</title>
  <link rel="stylesheet" href="/assets/clarity.css">
  <style>
{APP_CSS}
  </style>
</head>
<body>

<!-- ── Navigation header ────────────────────────────────────────────────── -->
<header class="nav-header">
  <span class="nav-brand">VCF / vSphere 9.1 Readiness Assessment</span>
  {"<span class='badge info' style='background:#0284c7;color:#fff;font-size:0.75rem;padding:0.2rem 0.5rem;border-radius:4px;font-weight:600;'>🔬 OEM Import Mode</span>" if oem_mode else ""}
  <span class="nav-version">v{tool_version}</span>
  <a href="/docs" target="_blank" class="nav-btn" style="text-decoration:none" title="Open Documentation &amp; User Guide in a new tab">❓ Help</a>
  <button class="nav-btn" id="themeToggle" title="Toggle dark/light mode">🌙 Dark</button>
  <button class="nav-btn" id="shutdownBtn" title="Quit the assessment tool">✕ Quit</button>
</header>

<!-- ── Main content ─────────────────────────────────────────────────────── -->
<div class="main-wrap">

  <!-- Collector not found warning -->
  {'<div class="alert alert-warning"><strong>⚠ Collector unavailable.</strong> vcf_hci package not found — scan functionality is disabled.</div>' if not collector_ok else ''}

  <!-- Root user warning banner -->
  <div id="rootAlertBanner" class="alert alert-warning hidden" style="margin-bottom:1rem">
    <strong>⚠ Running as Root / Superuser:</strong> Root privileges are not required for Redfish BMC connections. Default report folder set to: <code id="rootBannerPath"></code>
  </div>

  <!-- ── 1. Profiles ─────────────────────────────────────────────────────── -->
  <div class="card">
    <div class="card-header">🔖 Saved Profiles</div>
    <div class="card-body">
      <div class="form-grid">
        <div class="clr-form-group">
          <label class="clr-control-label">Load Profile</label>
          <select class="clr-select" id="profileSelect">
            <option value="">— select —</option>
          </select>
        </div>
        <div class="clr-form-group" style="justify-content:flex-end;flex-direction:row;align-items:flex-end;gap:.5rem">
          <button class="btn btn-flat btn-sm" id="loadProfileBtn">Load</button>
          <button class="btn btn-flat btn-sm" id="saveProfileBtn">Save as…</button>
          <button class="btn btn-flat btn-sm" id="deleteProfileBtn">Delete</button>
        </div>
      </div>
      <p class="clr-hint mt-half" id="keychainNote">Passwords stored in: {keychain_note}</p>
    </div>
  </div>

  <!-- ── 2. Discovery ────────────────────────────────────────────────────── -->
  <div class="card">
    <div class="card-header">🔍 Host Discovery &amp; Selection</div>
    <div class="card-body">
      <div class="form-grid">
        <div class="clr-form-group span-2">
          <label class="clr-control-label">Target Range</label>
          <input class="clr-input" id="rangeInput" type="text"
            placeholder="10.0.0.1  or  10.0.0.1-20  or  192.168.1.0/24  or  host.fqdn">
          <span class="clr-hint">Comma-separated for multiple ranges/IPs</span>
        </div>
      </div>
      <div class="flex gap-sm mt-half" style="flex-wrap:wrap">
        <button class="btn btn-outline btn-sm" id="discoverBtn">Probe Hosts</button>
        <button class="btn btn-flat btn-sm" id="selAllBtn">Select All</button>
        <button class="btn btn-flat btn-sm" id="selNoneBtn">Deselect All</button>
        <span class="spinner hidden" id="discSpinner"></span>
        <span class="text-sm text-muted" id="discStatus"></span>
      </div>
      <div id="vpnWarning" class="alert alert-warning hidden" style="margin-top:0.5rem;">
        <span>⚠️ <strong>Remote Connection / High Latency Detected:</strong> Average RTT is <strong><span id="vpnLatency">0</span> ms</strong>. Concurrent host count automatically set to <strong>6</strong> to prevent socket timeouts.</span>
      </div>
      <div id="retryBanner" class="alert alert-info hidden" style="margin-top:0.5rem; display:flex; align-items:center; justify-content:space-between;">
        <span>🔄 <strong>Gentle Retry Profile Applied:</strong> <span id="retryBannerText"></span></span>
        <button type="button" class="btn btn-sm btn-link" style="padding:0; margin-left:0.5rem; color:inherit; text-decoration:none;" onclick="document.getElementById('retryBanner').classList.add('hidden')">✕</button>
      </div>
      <div id="certTrustBanner" class="alert alert-info hidden" style="margin-top:0.5rem; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:0.5rem;">
        <span id="certTrustBannerText">🔒 <strong><span id="certTrustCount">0</span> host(s)</strong> present TLS certificates.</span>
        <div id="certTrustActions" class="flex gap-xs" style="align-items:center;">
          <button type="button" class="btn btn-sm btn-outline" id="reviewCertsBtn" data-action="review-certs" style="color:inherit; border-color:currentColor;">Review Certificates</button>
          <button type="button" class="btn btn-sm btn-primary" id="acceptAllCertsBtn" data-action="accept-all-certs">Accept All (Pin Thumbprints)</button>
        </div>
      </div>
      <div id="hostList" class="host-list mt-half hidden"></div>
    </div>
  </div>

  <!-- ── 3. Credentials ─────────────────────────────────────────────────── -->
  <div class="card">
    <div class="card-header">🔑 Credentials</div>
    <div class="card-body">
      <div class="clr-check-row" style="margin-bottom:.75rem">
        <input type="checkbox" id="sameCredsChk" checked>
        <label for="sameCredsChk">Use same credentials for all hosts</label>
      </div>
      <div id="sharedCreds" class="form-grid">
        <div class="clr-form-group">
          <label class="clr-control-label">Username</label>
          <input class="clr-input" id="usernameInput" type="text" value="root" autocomplete="username">
        </div>
        <div class="clr-form-group">
          <label class="clr-control-label">Password</label>
          <input class="clr-input" id="passwordInput" type="password" autocomplete="current-password">
        </div>
      </div>
      <div id="perHostCreds" class="hidden">
        <p class="text-sm text-muted">Per-host credentials — populated after Probe:</p>
        <div id="perHostRows"></div>
      </div>
      <div class="flex gap-sm mt-half" style="flex-wrap:wrap">
        <button class="btn btn-flat btn-sm" id="testCredsBtn">Test Connection</button>
        <span class="text-sm text-muted" id="testCredsStatus"></span>
      </div>
      <div class="clr-check-row mt-half" id="useVaultRow">
        <input type="checkbox" id="useVaultChk" disabled>
        <label for="useVaultChk">Use encrypted credential vault for this scan
          <span class="text-xs text-muted" id="useVaultHint">(off — create or unlock a vault below)</span></label>
      </div>
      <div id="vaultCoverage" class="text-sm text-muted hidden" style="margin-top:.35rem"></div>
      <div class="mt-half">
        <p class="text-sm" style="margin-bottom:.3rem"><strong>Execution target</strong></p>
        <div class="clr-check-row"><input type="radio" name="execTarget" id="execLocal" value="local" checked><label for="execLocal">Local workstation</label></div>
        <div class="clr-check-row"><input type="radio" name="execTarget" id="execRemote" value="remote"><label for="execRemote">Remote jump host <span class="badge badge-warning" style="font-size:0.7rem;margin-left:0.35rem;text-transform:uppercase;">Experimental</span></label></div>
        <div id="jumpTargetHint" class="text-xs" style="margin-left:1.5rem;margin-top:0.2rem;margin-bottom:0.35rem;"></div>
        <div id="jumpSelectRow" class="hidden" style="margin-top:.35rem">
          <label class="clr-control-label" for="jumpHostSelect">Jump host <span class="text-xs text-muted">(Experimental)</span></label>
          <select class="clr-select" id="jumpHostSelect"><option value="auto">Auto-route by subnet</option></select>
          <div id="jumpSelectHint" class="text-xs text-muted hidden" style="margin-top:0.25rem"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ── 3b. Encrypted Credential Vault (collapsible, opt-in) ───────────── -->
  <div class="card">
    <div class="card-header" style="cursor:pointer" id="vaultToggle">
      🔐 Encrypted Credential Vault
      <span class="text-muted text-sm" style="margin-left:.4rem;font-weight:400;text-transform:none;letter-spacing:0">
        — optional, off by default; per-host / per-subnet / default BMC passwords, encrypted on disk
      </span>
      <span style="margin-left:auto;font-size:.85rem" id="vaultArrow">▶</span>
    </div>
    <div id="vaultBody" class="collapsible">
      <div class="card-body">
        <div class="flex gap-sm" style="align-items:center;flex-wrap:wrap;margin-bottom:.6rem">
          <span class="badge badge-secondary" id="vaultStateBadge">checking…</span>
          <span class="badge hidden" id="vaultCipherBadge"></span>
          <span class="text-sm text-muted" id="vaultStatusText"></span>
          <button class="btn btn-flat btn-sm hidden" id="vaultLockBtn">Lock</button>
        </div>

        <!-- Create -->
        <div id="vaultCreateBlock" class="hidden">
          <p class="text-sm text-muted">No vault exists yet. Choose a passphrase (12+ characters).
            <strong>There is no recovery</strong> — if you forget it, delete the file and start over.</p>
          <div class="form-grid">
            <div class="clr-form-group">
              <label class="clr-control-label">New passphrase</label>
              <input class="clr-input" id="vaultNewPass1" type="password" autocomplete="new-password">
            </div>
            <div class="clr-form-group">
              <label class="clr-control-label">Confirm passphrase</label>
              <input class="clr-input" id="vaultNewPass2" type="password" autocomplete="new-password">
            </div>
          </div>
          <button class="btn btn-primary btn-sm mt-half" id="vaultCreateBtn">Create Vault</button>
        </div>

        <!-- Unlock -->
        <div id="vaultUnlockBlock" class="hidden">
          <div class="form-grid">
            <div class="clr-form-group">
              <label class="clr-control-label">Vault passphrase</label>
              <input class="clr-input" id="vaultUnlockPass" type="password" autocomplete="current-password">
            </div>
            <div class="clr-form-group" style="align-self:end">
              <button class="btn btn-primary btn-sm" id="vaultUnlockBtn">Unlock</button>
            </div>
          </div>
        </div>

        <!-- Unlocked: entries + add + import -->
        <div id="vaultOpenBlock" class="hidden">
          <div class="vault-entries-toggle" id="vaultEntriesToggle">
            <strong>Stored Vault Entries</strong>
            <span class="badge badge-secondary" id="vaultEntriesCountBadge" style="margin-left:.5rem">0</span>
            <span class="text-xs text-muted" style="margin-left:.5rem">click to expand / collapse</span>
            <span style="margin-left:auto;font-size:.85rem" id="vaultEntriesArrow">▶</span>
          </div>
          <div id="vaultEntriesBody" class="collapsible">
            <div class="vault-table-container">
              <table class="results-table" id="vaultTable">
                <thead><tr><th>Target</th><th>Kind</th><th>Username</th><th>Note</th><th></th></tr></thead>
                <tbody id="vaultTableBody"></tbody>
              </table>
            </div>
            <p class="text-xs text-muted" style="margin:.3rem 0 .6rem">Precedence: exact host → longest CIDR → default. Passwords are never displayed or sent to the browser.</p>
          </div>

          <hr class="vcf-sep">
          <p class="text-sm" style="margin-bottom:.3rem"><strong>Add / update one entry</strong></p>
          <div class="form-grid">
            <div class="clr-form-group">
              <label class="clr-control-label">Target (IP, CIDR, hostname, a.b.c.d-e range, or <code>default</code>)</label>
              <input class="clr-input" id="vaultAddTarget" type="text" placeholder="192.0.2.10  |  192.0.2.0/24  |  default">
            </div>
            <div class="clr-form-group">
              <label class="clr-control-label">Username</label>
              <input class="clr-input" id="vaultAddUser" type="text" value="root" autocomplete="off">
            </div>
            <div class="clr-form-group">
              <label class="clr-control-label">Password</label>
              <input class="clr-input" id="vaultAddPass" type="password" autocomplete="new-password">
            </div>
            <div class="clr-form-group">
              <label class="clr-control-label">Note (optional)</label>
              <input class="clr-input" id="vaultAddNote" type="text" maxlength="200">
            </div>
          </div>
          <button class="btn btn-outline btn-sm mt-half" id="vaultAddBtn">Save Entry</button>

          <hr class="vcf-sep">
          <p class="text-sm" style="margin-bottom:.3rem"><strong>Import CSV</strong>
            <span class="text-xs text-muted">— columns: <code>target,username,password[,note]</code>. Lines starting with <code>#</code> are ignored.</span></p>
          <textarea class="clr-textarea" id="vaultCsvText" rows="4"
                    placeholder="target,username,password,note&#10;192.0.2.10,root,••••••,exact host&#10;192.0.2.0/24,admin,••••••,rack A&#10;default,root,••••••,fallback"></textarea>
          <input type="file" id="vaultCsvInput" accept=".csv,.txt,text/csv" class="hidden">
          <div class="flex gap-sm mt-half" style="align-items:center;flex-wrap:wrap">
            <button class="btn btn-flat btn-sm" id="vaultCsvChooseBtn">Choose CSV file…</button>
            <button class="btn btn-flat btn-sm" id="vaultCsvTemplateBtn">Download template</button>
            <span class="text-xs text-muted" id="vaultCsvFileName"></span>
          </div>
          <div class="flex gap-sm mt-half" style="align-items:center;flex-wrap:wrap">
            <div class="clr-check-row"><input type="checkbox" id="vaultCsvReplace"><label for="vaultCsvReplace">Replace all existing entries</label></div>
            <div class="clr-check-row"><input type="checkbox" id="vaultCsvSkipInvalid"><label for="vaultCsvSkipInvalid">Skip invalid rows</label></div>
            <button class="btn btn-primary btn-sm" id="vaultCsvImportBtn">Import into Vault</button>
          </div>
          <div id="vaultImportResult" class="text-sm hidden" style="margin-top:.5rem;white-space:pre-wrap"></div>
          <hr class="vcf-sep">
          <p class="text-sm" style="margin-bottom:.3rem"><strong>Jump hosts</strong> <span class="badge badge-warning" style="font-size:0.7rem;margin-left:0.35rem;text-transform:uppercase;">Experimental</span></p>
          <p class="text-xs text-muted">SSH profiles used to run scans from a Linux jump host (Experimental feature — remote execution via ephemeral SSH worker). Secrets stay in the vault.</p>
          <div style="overflow-x:auto"><table class="results-table"><thead><tr><th>Id</th><th>Login</th><th>Subnets</th><th>Host Key</th><th>Connection</th><th></th></tr></thead><tbody id="jumpHostBody"></tbody></table></div>
          <div id="jumpEditBanner" class="alert alert-info hidden" style="margin-top:0.75rem;margin-bottom:0.75rem;font-size:0.85rem;display:flex;justify-content:space-between;align-items:center;">
            <span>✏ Editing jump host <strong id="jumpEditingId"></strong> (existing secrets preserved unless overwritten)</span>
            <button type="button" class="btn btn-flat btn-sm" id="jumpCancelEditTopBtn" style="color:inherit;padding:2px 8px;">Cancel Edit</button>
          </div>
          <div class="form-grid">
            <div class="clr-form-group"><label class="clr-control-label">Id</label><input class="clr-input" id="jumpId" type="text" placeholder="dal-jump-01"></div>
            <div class="clr-form-group"><label class="clr-control-label">Host</label><input class="clr-input" id="jumpHost" type="text" placeholder="192.0.2.10"></div>
            <div class="clr-form-group"><label class="clr-control-label">Port</label><input class="clr-input" id="jumpPort" type="number" value="22"></div>
            <div class="clr-form-group"><label class="clr-control-label">Username</label><input class="clr-input" id="jumpUser" type="text" value="ubuntu"></div>
            <div class="clr-form-group"><label class="clr-control-label">Auth</label><select class="clr-select" id="jumpAuth"><option value="key">SSH key</option><option value="password">Password</option></select></div>
            <div class="clr-form-group" id="jumpKeyPathGroup"><label class="clr-control-label" id="jumpKeyPathLabel">Key path</label><input class="clr-input" id="jumpKeyPath" type="text" placeholder="~/.ssh/id_ed25519"></div>
            <div class="clr-form-group"><label class="clr-control-label">Subnets</label><input class="clr-input" id="jumpSubnets" type="text" placeholder="192.0.2.0/24, 192.0.3.0/24"><span class="clr-hint" style="font-size:0.75rem;">Comma-separated CIDRs (supports multiple subnets)</span></div>
            <div class="clr-form-group"><label class="clr-control-label">Note</label><input class="clr-input" id="jumpNote" type="text"></div>
            <div class="clr-form-group">
              <label class="clr-control-label">Host Key (TOFU)</label>
              <div style="display:flex;gap:0.4rem;align-items:center;">
                <input class="clr-input" id="jumpHostKey" type="text" placeholder="Not pinned (auto-probed on save/test)" readonly style="font-size:0.8rem;font-family:monospace;">
                <input type="hidden" id="jumpHostKeyRaw">
                <button type="button" class="btn btn-outline btn-sm" id="jumpProbeKeyBtn" style="white-space:nowrap;">Probe Key</button>
              </div>
            </div>
          </div>
          <div class="clr-form-group" id="jumpPrivKeyGroup"><label class="clr-control-label" id="jumpPrivKeyLabel">Private key (optional, stored encrypted)</label><textarea class="clr-textarea" id="jumpPrivateKey" rows="3"></textarea></div>
          <div class="clr-form-group" id="jumpPasswordGroup"><label class="clr-control-label" id="jumpPasswordLabel">SSH password (optional)</label><input class="clr-input" id="jumpPassword" type="password" autocomplete="new-password"></div>
          <div class="clr-check-row"><input type="checkbox" id="jumpDefault"><label for="jumpDefault">Default jump host when no subnet matches</label></div>
          <div style="display:flex;gap:.5rem;align-items:center;margin-top:.5rem;flex-wrap:wrap">
            <button type="button" class="btn btn-outline btn-sm" id="jumpTestBtn">Test connection</button>
            <button type="button" class="btn btn-primary btn-sm" id="jumpSaveBtn">Save jump host</button>
            <button type="button" class="btn btn-flat btn-sm hidden" id="jumpCancelEditBtn">Cancel edit</button>
          </div>
          <div id="jumpMsg" class="text-sm hidden" style="margin-top:.5rem"></div>
          <p class="text-xs text-muted mt-half">After a successful import, delete the plaintext CSV from disk. The vault file is <code id="vaultPathText"></code> (owner-only permissions).</p>
        </div>
        <div id="vaultMsg" class="text-sm hidden" style="margin-top:.5rem"></div>
      </div>
    </div>
  </div>

  <!-- ── 4. Options ─────────────────────────────────────────────────────── -->
  <div class="card">
    <div class="card-header">⚙ Options</div>
    <div class="card-body">
      <div class="form-grid">
        <div class="clr-form-group">
          <label class="clr-control-label">Concurrent Hosts</label>
          <input class="clr-input" id="threadsInput" type="number" value="12" min="1" max="32" style="width:80px">
          <span class="clr-hint">Recommended: 4–8 over VPN/WAN, 8–16 on local LAN</span>
        </div>
        <div class="clr-form-group">
          <label class="clr-control-label">Output Folder</label>
          <div style="display:flex;gap:0.4rem;align-items:center;">
            <input class="clr-input" id="outdirInput" type="text" value="~/Desktop/VCF-Scans" style="flex:1;">
            <button class="btn btn-outline btn-sm" id="browseOutdirBtn" type="button" title="Browse for output folder" style="white-space:nowrap;">📁 Browse…</button>
          </div>
        </div>
      </div>
      <hr class="vcf-sep">
      <div class="clr-form-control" style="margin-top:0.25rem;">
        <label class="clr-control-label" style="font-weight:600;">Scan Depth Profile</label>
        <div class="clr-control-container" style="margin-top:0.25rem;">
          <div style="display:flex;flex-direction:column;gap:0.4rem;">
            <div class="clr-radio-wrapper">
              <input type="radio" name="scanProfile" id="profFull" value="readiness-full" checked>
              <label for="profFull"><strong>Readiness Full</strong> <span class="text-muted text-sm">— Exhaustive audit (Phase 1 + Phase 2 + HCL + PCIe + Telemetry + Interleaving, ~60–90 s/host)</span></label>
            </div>
            <div class="clr-radio-wrapper">
              <input type="radio" name="scanProfile" id="profLean" value="readiness-lean">
              <label for="profLean"><strong>Readiness Lean</strong> <span class="text-muted text-sm">— High-speed VCF 9.1 / vSAN ESA audit (skips historical telemetry logs & secondary member scans, ~15–30 s/host)</span></label>
            </div>
            <div class="clr-radio-wrapper">
              <input type="radio" name="scanProfile" id="profLite" value="inventory-lite">
              <label for="profLite"><strong>Inventory Lite</strong> <span class="text-muted text-sm">— Rapid hardware inventory pre-screening (Systems, Power/Thermal rollup, Storage rollup, NIC summary, ~5–10 s/host)</span></label>
            </div>
          </div>
        </div>
      </div>
      <hr class="vcf-sep">
      <div class="clr-check-row">
        <input type="checkbox" id="combinedChk" checked>
        <label for="combinedChk">Generate Fleet Hub HTML report  <span class="text-muted text-sm">— single-file inline hub (&le;64 hosts) or sidecar hub pack (&gt;64 hosts); for multi-scan aggregation use Open Fleet Library assemble</span></label>
        <div id="combinedNote" class="text-muted text-sm" style="display:none; margin-top:0.25rem;">Large fleet (&gt;64 hosts): Fleet Hub will be generated as a sidecar pack with lazy on-demand host frames (no 256-host limit). fleet_summary.html is also generated. For multiple independent scans, use Open Fleet Library to assemble.</div>
      </div>
      <div class="clr-check-row">
        <input type="checkbox" id="debugChk">
        <label for="debugChk">Enable debug log  <span class="text-muted text-sm">— writes verbose log to vcf_assess_debug.log</span></label>
      </div>
      <div class="clr-check-row">
        <input type="checkbox" id="saveJsonChk">
        <label for="saveJsonChk">Save summary JSON  <span class="text-muted text-sm">— save host & fleet .json files for offline import or analysis</span></label>
      </div>
      <div class="clr-check-row">
        <input type="checkbox" id="includeRawChk">
        <label for="includeRawChk">Include raw Redfish capture  <span class="text-muted text-sm">— include raw API response payloads in summary JSON</span></label>
      </div>
      <div class="clr-check-row">
        <input type="checkbox" id="crawlEndpointsChk">
        <label for="crawlEndpointsChk">Deep Redfish Crawl &amp; OEM Import  <span class="text-muted text-sm">— captures all endpoints for future tooling &amp; offline mockups</span></label>
      </div>
      <div id="crawlWarningBox" class="hidden" style="margin-left:1.5rem;margin-top:0.35rem;margin-bottom:0.6rem;padding:0.65rem 0.85rem;background:rgba(217, 83, 79, 0.08);border-left:4px solid #d9534f;border-radius:4px;font-size:0.8rem;line-height:1.45;">
        <div style="font-weight:600;color:#c9302c;margin-bottom:0.3rem;">⏱️ Extended Scan Time Warning</div>
        <div>Deep Redfish Crawling walks all available OEM and standard endpoints for future tooling and offline mockup generation.</div>
        <ul style="margin:0.35rem 0 0.45rem 1.2rem;padding:0;">
          <li><strong>Standard 1U/2U hosts:</strong> Adds approximately <strong>+1.5 to +3 minutes</strong> per host (~600 endpoints).</li>
          <li><strong>Heavy storage chassis &amp; multi-socket hosts</strong> (e.g. Dell R7525/R750 with 24 NVMe drives, modular chassis): Adds <strong>+4 to +6 minutes</strong> per host (~900–1,400+ endpoints).</li>
          <li>Host timeout is automatically adjusted to <strong>15 minutes</strong> to prevent premature aborts.</li>
        </ul>
        <div class="text-muted" style="font-style:italic;">Recommended only for onboarding unscanned reference models. Not recommended for routine fleet assessments.</div>
      </div>
      <div class="clr-check-row">
        <input type="checkbox" id="obfuscateChk">
        <label for="obfuscateChk">Generate obfuscated copies  <span class="text-muted text-sm">— IPs → Host-N, MACs/S/Ns → hash tokens</span></label>
      </div>
      <div class="clr-check-row">
        <input type="checkbox" id="exportSpreadsheetChk" checked>
        <label for="exportSpreadsheetChk">Auto-export CSV &amp; Excel workbook  <span class="text-muted text-sm">— generates fleet_summary.csv and .xlsx upon scan completion</span></label>
      </div>
      <div class="clr-check-row">
        <input type="checkbox" id="allowPartialChk">
        <label for="allowPartialChk">Allow partial scans  <span class="text-muted text-sm">— generate reports from partial data if host times out (default: Off)</span></label>
      </div>
      <div class="clr-check-row">
        <input type="checkbox" id="extendTimeoutChk">
        <label for="extendTimeoutChk">Extend host scan timeout</label>
        <span id="extendTimeoutBox" class="hidden" style="margin-left:0.5rem;">
          <input class="clr-input" id="timeoutMinutesInput" type="number" value="10" min="1" max="45" style="width:65px; padding:0.15rem 0.35rem; text-align:center;">
          <span class="text-muted text-sm">minutes (max 45 min)</span>
        </span>
      </div>
      <div class="clr-check-row">
        <input type="checkbox" id="autoRetryChk" checked>
        <label for="autoRetryChk">Auto-retry incomplete / failed hosts once  <span class="text-muted text-sm">— automatically run one gentle retry pass if timeouts or partial data occur</span></label>
      </div>
      <hr class="vcf-sep">
      <!-- ── TLS & Security Hardening (collapsible) ── -->
      <div style="margin-bottom:0.75rem;">
        <label class="clr-control-label" style="font-weight:600;margin-bottom:0.35rem">🛡 TLS &amp; Target Security</label>
        <div class="clr-check-row">
          <input type="checkbox" id="ignoreTlsChk" checked>
          <label for="ignoreTlsChk">Ignore BMC TLS certificate errors <span class="text-muted text-sm">(recommended for self-signed BMC certificates)</span></label>
        </div>
        <div id="tlsVerifyOptions" class="hidden" style="margin-left:1.5rem;margin-top:0.35rem;padding:0.5rem;background:rgba(0,0,0,0.05);border-radius:4px;">
          <div style="display:flex;flex-direction:column;gap:0.35rem;">
            <div class="clr-check-row">
              <input type="radio" name="tlsMode" id="tlsModeSystem" value="system" checked>
              <label for="tlsModeSystem">Verify with system trust store</label>
            </div>
            <div class="clr-check-row">
              <input type="radio" name="tlsMode" id="tlsModeCustom" value="custom">
              <label for="tlsModeCustom">Verify with custom CA bundle file</label>
            </div>
            <div id="tlsCustomBox" class="hidden" style="margin-left:1.5rem;margin-top:0.25rem;">
              <input class="clr-input" id="caBundleInput" type="text" placeholder="/path/to/enterprise-ca-bundle.pem" style="width:100%;max-width:400px;">
              <span class="text-muted text-xs">Path to enterprise root/intermediate CA .pem or .crt</span>
            </div>
          </div>
        </div>
        <div class="clr-check-row" style="margin-top:0.4rem;">
          <input type="checkbox" id="dnsLookupChk">
          <label for="dnsLookupChk">Perform FCrDNS host lookups <span class="text-muted text-sm">— resolve reverse PTR and verify forward A-record</span></label>
        </div>
        <div class="clr-check-row" style="margin-top:0.4rem;">
          <input type="checkbox" id="restrictPrivateChk">
          <label for="restrictPrivateChk">Restrict targets to private IP ranges <span class="text-muted text-sm">— block public/internet IP scanning (RFC1918/loopback/link-local)</span></label>
        </div>
        <div class="clr-check-row" style="margin-top:0.4rem;">
          <input type="checkbox" id="enableDashChk">
          <label for="enableDashChk">Enable AMD DASH legacy probe <span class="text-muted text-sm">— probe ports 624/623 (disabled by default for security)</span></label>
        </div>
      </div>
      <hr class="vcf-sep">
      <div id="hclSection">
        <div class="flex flex-col gap-xs">
          <div class="flex items-center justify-between" style="flex-wrap:wrap;gap:.5rem">
            <label class="clr-control-label" style="font-weight:600;margin-bottom:0">Broadcom HCL Database &amp; Dark-Site Bundle</label>
            <div id="hclFreshnessBadge"></div>
          </div>
          <div id="hclBadge" class="text-sm text-muted">Loading HCL status…</div>
          <div id="hclCounts" class="flex gap-xs mt-xs text-xs" style="flex-wrap:wrap"></div>
          <div class="flex gap-sm mt-xs" style="flex-wrap:wrap;align-items:center">
            <button class="btn btn-outline btn-sm" id="hclRefreshBtn">🔄 Refresh Live HCL</button>
            <input type="file" id="hclFileInput" accept=".zip" class="hidden">
            <button class="btn btn-outline btn-sm" id="hclUploadBtn">Import Dark-Site HCL Zip</button>
            <button class="btn btn-flat btn-sm hidden" id="hclResetBtn">Reset to Default HCL</button>
            <span id="hclRefreshSpinner" class="hidden text-sm text-muted" style="display:none;align-items:center;gap:.3rem">
              <span class="spinner"></span> Downloading latest HCL from Broadcom…
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- ── 5. Dell Service Tag (collapsible) ──────────────────────────────── -->
  <div class="card">
    <div class="card-header" style="cursor:pointer" id="dellToggle">
      🏷 Dell Service Tag Lookup
      <span class="text-muted text-sm" style="margin-left:.4rem;font-weight:400;text-transform:none;letter-spacing:0">
        — optional, requires TechDirect API key
      </span>
      <span style="margin-left:auto;font-size:.85rem" id="dellArrow">▶</span>
    </div>
    <div id="dellBody" class="collapsible">
      <div class="card-body">
        <div class="form-grid">
          <div class="clr-form-group">
            <label class="clr-control-label">Client ID</label>
            <input class="clr-input" id="dellIdInput" type="text" placeholder="TechDirect client_id"
                   autocomplete="off">
          </div>
          <div class="clr-form-group">
            <label class="clr-control-label">Client Secret</label>
            <input class="clr-input" id="dellSecretInput" type="password" placeholder="TechDirect secret"
                   autocomplete="off">
          </div>
        </div>
        <div class="flex gap-sm mt-half" style="align-items:center;flex-wrap:wrap;">
          <button class="btn btn-flat btn-sm" id="dellSaveCredsBtn">Save to Keychain</button>
          <button class="btn btn-flat btn-sm" id="dellLoadCredsBtn">Load from Keychain</button>
          <span class="text-xs text-muted" style="margin-left:0.25rem;">Storage: {keychain_note}</span>
        </div>
        <hr class="vcf-sep">
        <div class="clr-form-group">
          <label class="clr-control-label">Service Tags (comma-separated or one per line)</label>
          <textarea class="clr-textarea" id="dellTagsInput" rows="2"
                    placeholder="ABC1234, DEF5678"></textarea>
        </div>
        <div class="clr-check-row">
          <input type="checkbox" id="dellEnabledChk">
          <label for="dellEnabledChk">Enrich scan results with Dell TechDirect warranty data</label>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Run & Actions section ───────────────────────────────────────────── -->
  <div class="card" style="margin: 1.25rem 0; padding: 1rem;">
    <!-- Primary Actions -->
    <div class="flex gap-sm items-center flex-wrap">
      <button class="btn btn-primary btn-run" id="runBtn"
              {'disabled' if not collector_ok else ''}>▶  Run Assessment</button>
      <button class="btn btn-danger btn-sm hidden" id="cancelBtn">🛑 Cancel Scan</button>
      <input type="file" id="importSummaryInput" accept=".json,.gz,.zip" style="display:none;" multiple>
      <button class="btn btn-outline btn-sm" id="importScanBtn" title="Import prior scan data (data/fleet_summary.json, vcf_readiness_scan_*.zip, or vcf_summary_*.json) to regenerate consolidated reports offline">📁 Import Scan</button>
      <button class="btn btn-outline btn-sm" id="importSummaryBtn" title="Import host or fleet summary JSON">📁 Import Summary</button>
      <button class="btn btn-outline btn-sm" id="openLibraryBtn" title="Discover and assemble multiple scan drops from a central library folder (~/Desktop/VCF-Scans)">📚 Open Fleet Library</button>
    </div>

    <!-- Conditional 100+ Fleet Notice Banner -->
    <div id="fleetNotice" class="alert alert-warning text-xs hidden" style="margin-top: 0.75rem;">
      <span>⚡ <strong>Large fleet detected (<span id="fleetCountLabel">100+</span> hosts):</strong> Fleets of 100+ hosts should use CLI <code>--from-summary</code> for optimal performance.</span>
    </div>

    <!-- Post-Scan / Report & Export Actions -->
    <div id="postScanActions" class="hidden" style="margin-top: 0.85rem; padding-top: 0.85rem; border-top: 1px solid var(--vcf-border);">
      <!-- Finished Scan Summary Card -->
      <div id="postScanSummaryCard" class="card mb-md hidden" style="width: 100%; margin-bottom: 0.85rem;">
        <div class="card-header" style="font-weight: 600; display: flex; align-items: center; justify-content: space-between;">
          <span>🏁 Finished Scan Summary</span>
          <span id="summarySuccessBadge" class="badge badge-success">0/0 succeeded</span>
        </div>
        <div class="card-body" style="padding: 0.75rem 1rem; display: flex; flex-direction: column; gap: 0.5rem; font-size: 0.85rem;">
          <div id="summaryMetricsRow" class="text-muted" style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
            <span>⏱️ <strong>Scan Performance:</strong></span>
            <span id="summaryMetricsText">—</span>
          </div>
          <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
            <span>📊 <strong>VCF Readiness:</strong></span>
            <span id="summarySupportedBadge" class="badge badge-success">0 Supported</span>
            <span id="summaryDeprecatedBadge" class="badge badge-warning">0 Deprecated</span>
            <span id="summaryUnsupportedBadge" class="badge badge-danger">0 Unsupported</span>
            <span id="summaryRemediatedBadge" class="badge badge-success hidden" style="background:#16a34a;color:#fff">0 Remediated</span>
          </div>
          <div id="summaryOutdirRow" class="text-muted" style="display: flex; align-items: center; gap: 0.5rem; word-break: break-all; flex-wrap: wrap;">
            <span>📁 <strong>Output Folder:</strong></span>
            <code id="summaryOutdirText" style="font-size: 0.8rem;">—</code>
            <button class="btn btn-outline btn-sm" id="summaryOpenFolderBtn" type="button" style="padding: 0.1rem 0.4rem; font-size: 0.75rem; margin-left: 0.25rem;">📂 Open Folder</button>
          </div>
          <div id="summaryZipRow" class="text-muted hidden" style="display: flex; align-items: center; gap: 0.5rem; word-break: break-all;">
            <span>📦 <strong>Zip Archive:</strong></span>
            <code id="summaryZipText" style="font-size: 0.8rem;">—</code>
          </div>
        </div>
      </div>

      <div class="flex gap-xl flex-wrap items-start">
        <!-- View Reports Column -->
        <div id="reportLinksGroup" class="flex flex-col gap-xs items-start">
          <span class="fw-bold text-xs text-muted mb-3xs">VIEW REPORTS</span>
          <button class="btn btn-success-solid btn-sm hidden" id="openSummaryBtn">
            📊  Open Fleet Summary
          </button>
          <button class="btn btn-outline btn-sm hidden" id="openObfSummaryBtn" style="color:#7c3aed;border-color:#7c3aed">
            🔒  Open Obfuscated Summary
          </button>
          <button class="btn btn-success-solid btn-sm hidden" id="openReportBtn">
            ✔  Open Combined Report
          </button>
          <button class="btn btn-outline btn-sm hidden" id="openObfReportBtn" style="color:#7c3aed;border-color:#7c3aed">
            🔒  Open Obfuscated Combined
          </button>
        </div>

        <!-- Export Data Column -->
        <div id="exportLinksGroup" class="flex flex-col gap-xs items-start">
          <span class="fw-bold text-xs text-muted mb-3xs">EXPORT DATA</span>
          <button class="btn btn-flat btn-sm hidden" id="openFolderBtn">
            📂 Open Scan Folder
          </button>
          <button class="btn btn-flat btn-sm hidden" id="exportXlsxBtn">
            ⬇  Export Excel
          </button>
          <button class="btn btn-flat btn-sm hidden" id="exportObfXlsxBtn" style="color:#7c3aed">
            🔒 Export Obfuscated Excel + Key
          </button>
          <button class="btn btn-flat btn-sm hidden" id="exportObfZipBtn" style="color:#2563eb" title="Download sanitized ZIP archive with HTML hub, sub-reports, Excel, and CSVs (safe to post or share externally)">
            📦 Export Obfuscated Package (.zip)
          </button>
          <button class="btn btn-flat btn-sm hidden" id="exportCsvBtn">
            ⬇  Export CSV
          </button>
          <button class="btn btn-flat btn-sm hidden" id="exportSummaryJsonBtn">
            📁 Export Summary JSON
          </button>
          <button class="btn btn-flat btn-sm hidden" id="prerenderReportsBtn" title="Pre-generate all single-host HTML reports across the fleet for fully offline portable bundles">
            ⚡ Pre-render All Host Reports
          </button>
        </div>

        <!-- Remediation / Retry Column -->
        <div id="retryActionsGroup" class="flex flex-col gap-xs items-start hidden" style="min-width:260px">
          <span class="fw-bold text-xs text-muted mb-3xs">REMEDIATION &amp; RETRY</span>
          <div id="retryBreakdownBadges" class="flex gap-2xs flex-wrap mb-2xs" style="font-size:0.75rem">
            <span id="badgePartialCount" class="badge badge-warning hidden">⚠️ <span id="cntPartial">0</span> Partial</span>
            <span id="badgeTimeoutCount" class="badge badge-warning hidden">⏱️ <span id="cntTimeout">0</span> Timed Out</span>
            <span id="badgeAuthCount" class="badge badge-danger hidden">🔒 <span id="cntAuth">0</span> Auth Failed</span>
            <span id="badgeUnreachCount" class="badge hidden" style="background:#64748b;color:#ffffff">🔌 <span id="cntUnreach">0</span> Unreachable</span>
          </div>
          <button class="btn btn-warning-solid btn-sm" id="retryIssuesBtn" style="background:#ca8a04;border-color:#ca8a04;color:#ffffff;font-weight:600">
            🔄 Retry Active Issues (<span id="retryIssuesCount">0</span>)
          </button>
          <button class="btn btn-outline btn-sm hidden" id="retryAllBtn" style="font-size:0.78rem">
            🔄 Retry All Non-Success (<span id="retryAllCount">0</span>)
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Progress ───────────────────────────────────────────────────────── -->
  <div id="progressSection" class="hidden">
    <!-- ── Jump Host Reconnect Alert Banner ── -->
    <div id="jumpReconnectAlert" class="alert alert-warning hidden" style="margin-bottom: 0.75rem; display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap;">
      <div>
        <strong>⚡ Jump Host Connection Lost:</strong>
        <span id="jumpReconnectText">SSH session disconnected (VPN dropped). The remote worker is still running on the jump host.</span>
      </div>
      <button class="btn btn-warning-solid btn-sm" id="jumpReconnectBtn" style="background:#ca8a04; border-color:#ca8a04; color:#ffffff; font-weight:600; white-space:nowrap;">
        🔄 Reconnect &amp; Pull Results
      </button>
    </div>
    <div class="card">
      <div class="card-header">
        <span class="spinner" id="scanSpinner"></span>
        <span id="progressLabel">Scanning…</span>
      </div>
      <div class="card-body">
        <div class="progress-track">
          <div class="progress-bar" id="progressBar"></div>
        </div>
        <p class="progress-label" id="progressText">0 / 0 hosts</p>

        <div class="log-box" id="logBox"></div>
        <div class="flex gap-sm mt-half">
          <button class="btn btn-flat btn-sm" id="clearLogBtn">Clear Log</button>
        </div>

        <!-- ── Active In-Process Hosts (Below logs, above Results) ── -->
        <div id="activeScansBox" class="active-scans-box hidden">
          <div class="active-scans-header">
            <span>⚡ In-Process Hosts (<span id="activeCount">0</span>)</span>
            <span class="text-xs text-muted ms-auto" style="font-weight:400">Monitored live • Skipped hosts finish current GET then stop</span>
          </div>
          <div id="activeScansList" class="active-scans-list"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Results table ──────────────────────────────────────────────────── -->
  <div id="resultsSection" class="hidden">
    <div class="card">
      <div class="card-header" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
        <span>📋 Results</span>
        <div id="resultsControls" style="display:flex; gap:0.75rem; align-items:center; font-size:0.85rem;">
          <input type="text" id="resultsFilterInput" class="clr-input input-sm" placeholder="Filter results…" style="max-width:180px;">
          <label style="display:inline-flex; align-items:center; gap:0.35rem; color:var(--text-muted,#64748b);">
            Show:
            <select id="resultsPageSizeSelect" style="padding:2px 6px; border-radius:4px; border:1px solid var(--vcf-border,#cbd5e1); background:var(--vcf-card,#ffffff); color:inherit; font-size:0.85rem;">
              <option value="25">25</option>
              <option value="50" selected>50</option>
              <option value="100">100</option>
              <option value="all">All</option>
            </select>
          </label>
          <div style="display:inline-flex; align-items:center; gap:0.35rem;">
            <button type="button" class="btn btn-sm btn-outline" id="resultsPrevPageBtn" disabled>‹</button>
            <span id="resultsPageInfo" style="font-weight:600; min-width:80px; text-align:center;">Page 1</span>
            <button type="button" class="btn btn-sm btn-outline" id="resultsNextPageBtn" disabled>›</button>
          </div>
        </div>
      </div>
      <div class="card-body" style="padding:0;overflow-x:auto">
        <table class="results-table">
          <thead>
            <tr>
              <th>Host</th>
              <th>Model</th>
              <th>VCF Support</th>
              <th>Report</th>
            </tr>
          </thead>
          <tbody id="resultsBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ── Failed / Incomplete Scans Table ────────────────────────────────────── -->
  <div id="failedHostsSection" class="hidden" style="margin-top:1rem">
    <div class="card" style="border-left: 3px solid var(--vcf-danger, #dc2626)">
      <div class="card-header" style="display:flex; align-items:center; justify-content:space-between">
        <span>⚠️ Failed / Incomplete Scans (<span id="failedCount">0</span>)</span>
        <input type="text" id="failedFilter" class="clr-input input-sm" placeholder="Filter failed hosts…" style="max-width:220px; margin-left:auto">
      </div>
      <div class="card-body" style="padding:0; overflow-x:auto">
        <table class="results-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>BMC IP</th>
              <th>Hostname</th>
              <th>Failure Reason</th>
              <th>Stage &amp; Details</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="failedHostsBody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ── Certificate Trust Review Modal (TOFU) ────────────────────────── -->
  <div id="certModal" class="vcf-modal-backdrop hidden">
    <div class="vcf-modal-dialog">
      <div class="vcf-modal-header">
        <h3 style="margin:0; font-size:1.1rem; font-weight:600;">🔒 Certificate Trust &amp; Thumbprint Review (TOFU)</h3>
        <button type="button" id="closeCertModalBtn" style="cursor:pointer; background:none; border:none; color:inherit; font-size:1.2rem; line-height:1;">✕</button>
      </div>
      <div class="vcf-modal-body">
        <p class="text-sm text-muted" style="margin-top:0; margin-bottom:0.75rem;">
          Review SSL/TLS certificates presented by target BMCs. Pinning thumbprints allows secure verification on self-signed and untrusted enterprise certificates without disabling TLS integrity.
        </p>
        <table class="vcf-cert-table">
          <thead>
            <tr style="border-bottom:1px solid var(--vcf-border);">
              <th style="width:36px;"><input type="checkbox" id="selectAllCertsChk" checked></th>
              <th>Host IP</th>
              <th>Subject CN</th>
              <th>Issuer</th>
              <th>Expiry</th>
              <th>SHA-256 Thumbprint</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody id="certTableBody"></tbody>
        </table>
      </div>
      <div class="vcf-modal-footer">
        <span class="text-xs text-muted" id="pinnedCertSummary">0 thumbprint(s) pinned</span>
        <div class="flex gap-sm">
          <button type="button" class="btn btn-flat btn-sm" id="cancelCertModalBtn">Close</button>
          <button type="button" class="btn btn-outline btn-sm" id="acceptSelectedCertsBtn">Accept Selected</button>
          <button type="button" class="btn btn-primary btn-sm" id="modalAcceptAllCertsBtn">Accept All &amp; Pin</button>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Jump Host Key Trust Review Modal (TOFU) ──────────────────────── -->
  <div id="jumpHostKeyModal" class="vcf-modal-backdrop hidden">
    <div class="vcf-modal-dialog" style="max-width:620px; width:95%;">
      <div class="vcf-modal-header">
        <h3 style="margin:0; font-size:1.1rem; font-weight:600;">🔒 SSH Host Key Trust &amp; Pinning (TOFU)</h3>
        <button type="button" id="closeJumpHostKeyModalBtn" style="cursor:pointer; background:none; border:none; color:inherit; font-size:1.2rem; line-height:1;">✕</button>
      </div>
      <div class="vcf-modal-body">
        <p class="text-sm text-muted" style="margin-top:0; margin-bottom:0.75rem;">
          Verify the remote SSH host identity before sending credentials. Pinning the host key protects against Man-in-the-Middle (MITM) attacks and ensures your SSH password or private key is never transmitted to an untrusted or spoofed server.
        </p>
        <div style="background:var(--vcf-bg-subtle); border:1px solid var(--vcf-border); border-radius:6px; padding:12px; margin-bottom:1rem;">
          <div style="display:grid; grid-template-columns:130px 1fr; row-gap:8px; font-size:0.875rem;">
            <div style="font-weight:600; color:var(--vcf-text-muted);">Target Host:</div>
            <div id="jumpKeyModalHost" style="font-family:monospace; font-weight:bold;"></div>
            <div style="font-weight:600; color:var(--vcf-text-muted);">Key Type:</div>
            <div id="jumpKeyModalType" style="font-family:monospace;"></div>
            <div style="font-weight:600; color:var(--vcf-text-muted);">SHA-256 Fingerprint:</div>
            <div id="jumpKeyModalFingerprint" style="font-family:monospace; word-break:break-all; font-weight:bold; color:var(--vcf-primary);"></div>
            <div style="font-weight:600; color:var(--vcf-text-muted);">Trust Status:</div>
            <div id="jumpKeyModalStatus"></div>
          </div>
        </div>
        <div id="jumpKeyModalWarning" class="alert alert-warning hidden" style="font-size:0.85rem; margin-bottom:0.75rem;">
          ⚠ <strong>Host Key Mismatch Warning:</strong> The host key returned does not match the pinned key previously trusted for this jump host! If the server was not recently re-installed, this could indicate a Man-in-the-Middle attack or IP address collision.
        </div>
      </div>
      <div class="vcf-modal-footer">
        <button type="button" class="btn btn-flat btn-sm" id="cancelJumpHostKeyModalBtn">Cancel</button>
        <button type="button" class="btn btn-primary btn-sm" id="acceptJumpHostKeyBtn">Trust &amp; Pin Host Key</button>
      </div>
    </div>
  </div>

  <!-- ── Jump Host Edit Subnets Modal ────────────────────────────────────── -->
  <div id="jumpHostSubnetsModal" class="vcf-modal-backdrop hidden">
    <div class="vcf-modal-dialog" style="max-width:560px; width:95%;">
      <div class="vcf-modal-header">
        <h3 style="margin:0; font-size:1.1rem; font-weight:600;">🌐 Edit Subnets for Jump Host</h3>
        <button type="button" id="closeJumpHostSubnetsModalBtn" style="cursor:pointer; background:none; border:none; color:inherit; font-size:1.2rem; line-height:1;">✕</button>
      </div>
      <div class="vcf-modal-body">
        <p class="text-sm text-muted" style="margin-top:0; margin-bottom:0.75rem;">
          Configure CIDR subnets routed through <strong id="jumpSubnetsModalHostId"></strong>. Targets matching these subnets will automatically route through this jump host. Multiple subnets can be added.
        </p>
        <div style="margin-bottom:1rem;">
          <label style="font-weight:600; font-size:0.85rem; display:block; margin-bottom:0.35rem;">Attached Subnets</label>
          <div id="jumpSubnetsModalList" style="display:flex; flex-wrap:wrap; gap:0.4rem; min-height:40px; padding:6px; background:var(--vcf-bg-subtle); border:1px solid var(--vcf-border); border-radius:4px; align-items:center;">
          </div>
          <div id="jumpSubnetsModalEmpty" class="text-xs text-muted hidden" style="margin-top:0.25rem;">No subnets currently attached (receives explicit target routing or fallback if default).</div>
        </div>
        <div class="clr-form-group" style="margin-bottom:0.75rem;">
          <label class="clr-control-label" for="jumpSubnetsModalInput">Add Subnet(s)</label>
          <div style="display:flex; gap:0.4rem;">
            <input class="clr-input" id="jumpSubnetsModalInput" type="text" placeholder="192.0.2.0/24, 198.51.100.0/24" style="flex:1;">
            <button type="button" class="btn btn-outline btn-sm" id="jumpSubnetsModalAddBtn" style="white-space:nowrap;">+ Add Subnet(s)</button>
          </div>
          <span class="clr-hint" style="font-size:0.75rem;">Enter one or more CIDR subnets separated by comma, space, or semicolon (e.g. <code>192.0.2.0/24, 10.0.0.0/16</code>).</span>
        </div>
        <div id="jumpSubnetsModalMsg" class="text-sm hidden" style="margin-top:.5rem"></div>
      </div>
      <div class="vcf-modal-footer">
        <button type="button" class="btn btn-flat btn-sm" id="cancelJumpHostSubnetsModalBtn">Cancel</button>
        <button type="button" class="btn btn-primary btn-sm" id="saveJumpHostSubnetsModalBtn">Save Subnets</button>
      </div>
    </div>
  </div>

  <!-- ── Fleet Library Modal (Multi-Scan Drop & Assemble) ─────────────── -->
  <div id="fleetLibraryModal" class="vcf-modal-backdrop hidden">
    <div class="vcf-modal-dialog" style="max-width:880px; width:95%;">
      <div class="vcf-modal-header">
        <h3 style="margin:0; font-size:1.1rem; font-weight:600;">📚 Fleet Library — Multi-Scan Assembly</h3>
        <button type="button" id="closeFleetLibraryModalBtn" style="cursor:pointer; background:none; border:none; color:inherit; font-size:1.2rem; line-height:1;">✕</button>
      </div>
      <div class="vcf-modal-body">
        <p class="text-sm text-muted" style="margin-top:0; margin-bottom:0.75rem;">
          Discover and merge multiple scan drops (folders or zip archives) from across datacenters, jump boxes, or offline drives into a unified fleet dataset with deduplication.
        </p>
        <div style="display:flex; gap:0.5rem; align-items:center; margin-bottom:1rem; flex-wrap:wrap;">
          <label style="font-weight:600; font-size:0.85rem; white-space:nowrap;">Library Folder:</label>
          <input type="text" id="fleetLibraryPathInput" class="clr-input" value="~/Desktop/VCF-Scans" style="flex:1; min-width:240px; font-family:monospace; font-size:0.85rem;" placeholder="~/Desktop/VCF-Scans">
          <button type="button" class="btn btn-outline btn-sm" id="fleetLibraryDiscoverBtn">🔍 Discover Scans</button>
        </div>

        <div id="fleetLibraryLoading" class="text-sm text-muted hidden" style="margin:1rem 0;">
          <span>⏳ Scanning library folder for scan directories and zip archives…</span>
        </div>

        <div id="fleetLibraryEmpty" class="alert alert-info text-xs hidden" style="margin-bottom:1rem;">
          <span>No scan folders or zip archives found in this library directory. Drop prior scan folders or .zip files into this folder and click <strong>Discover Scans</strong>.</span>
        </div>

        <div id="fleetLibraryScansWrap" class="hidden" style="margin-bottom:1rem;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
            <span class="text-xs text-muted" id="fleetLibraryCount">0 scan(s) discovered</span>
            <span class="text-xs text-muted">Newest scan wins during deduplication</span>
          </div>
          <div style="max-height:280px; overflow-y:auto; border:1px solid var(--vcf-border); border-radius:4px;">
            <table class="vcf-cert-table" style="margin:0;">
              <thead>
                <tr style="border-bottom:1px solid var(--vcf-border);">
                  <th style="width:36px;"><input type="checkbox" id="selectAllLibraryScansChk" checked></th>
                  <th>Scan ID / Name</th>
                  <th>Date</th>
                  <th>Hosts</th>
                  <th>Site</th>
                  <th>Type</th>
                </tr>
              </thead>
              <tbody id="fleetLibraryTableBody"></tbody>
            </table>
          </div>
        </div>

        <div style="display:flex; gap:1rem; align-items:center; flex-wrap:wrap; margin-top:0.75rem;">
          <div style="display:flex; gap:0.4rem; align-items:center;">
            <label style="font-size:0.85rem; font-weight:600;">Default Site:</label>
            <input type="text" id="fleetLibrarySiteInput" class="clr-input input-sm" placeholder="e.g. DC1" style="max-width:140px;">
          </div>
          <label style="display:flex; gap:0.4rem; align-items:center; font-size:0.85rem; cursor:pointer;">
            <input type="checkbox" id="fleetLibraryObfuscateChk"> Obfuscate customer identifiers
          </label>
        </div>
        <div id="fleetLibraryStatusMsg" class="text-xs text-muted" style="margin-top:0.5rem;"></div>
      </div>
      <div class="vcf-modal-footer">
        <span class="text-xs text-muted" id="fleetLibrarySelectionSummary">0 scan(s) selected</span>
        <div class="flex gap-sm">
          <button type="button" class="btn btn-flat btn-sm" id="cancelFleetLibraryModalBtn">Cancel</button>
          <button type="button" class="btn btn-primary btn-sm" id="fleetLibraryAssembleBtn" disabled>⚡ Assemble Fleet</button>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Missing Password Warning Modal ────────────────────────────── -->
  <div id="missingPasswordModal" class="vcf-modal-backdrop hidden">
    <div class="vcf-modal-dialog" style="max-width:540px; width:95%;">
      <div class="vcf-modal-header">
        <h3 style="margin:0; font-size:1.1rem; font-weight:600;">⚠️ Missing BMC Password</h3>
        <button type="button" id="closeMissingPasswordModalBtn" style="cursor:pointer; background:none; border:none; color:inherit; font-size:1.2rem; line-height:1;">✕</button>
      </div>
      <div class="vcf-modal-body">
        <p style="margin-top:0; font-size:0.95rem; font-weight:600; color:var(--vcf-text);">
          No BMC password entered and the Credential Vault is not active.
        </p>
        <p class="text-sm text-muted" id="missingPasswordText">
          Targeting host(s) without credentials. Most enterprise BMCs (iDRAC, iLO, XCC, Supermicro) require authentication.
          The assessment will likely fail with 401 Unauthorized errors and consecutive timeouts.
        </p>
        <div id="missingPasswordHostsWrap" class="hidden" style="margin:0.75rem 0;">
          <div style="font-size:0.75rem; font-weight:600; margin-bottom:0.25rem; text-transform:uppercase; letter-spacing:0.04em;" class="text-muted">Affected Targets:</div>
          <div id="missingPasswordHostsList" class="missing-pwd-hosts-box"></div>
        </div>
      </div>
      <div class="vcf-modal-footer">
        <span class="text-xs text-muted">Click Enter Password to fix, or Continue Anyway to proceed.</span>
        <div class="flex gap-sm">
          <button type="button" class="btn btn-outline btn-sm" id="continueWithoutPasswordBtn">Continue Anyway</button>
          <button type="button" class="btn btn-flat btn-sm hidden" id="unlockVaultModalBtn">🔓 Unlock Vault</button>
          <button type="button" class="btn btn-primary btn-sm" id="enterPasswordModalBtn">Enter Password</button>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Active Remote Scan Conflict Modal ────────────────────────── -->
  <div id="activeScanConflictModal" class="vcf-modal-backdrop hidden">
    <div class="vcf-modal-dialog" style="max-width:580px; width:95%;">
      <div class="vcf-modal-header">
        <h3 style="margin:0; font-size:1.1rem; font-weight:600;">⚡ Active Scan Detected on Jump Host</h3>
        <button type="button" id="closeActiveScanConflictModalBtn" style="cursor:pointer; background:none; border:none; color:inherit; font-size:1.2rem; line-height:1;">✕</button>
      </div>
      <div class="vcf-modal-body">
        <p style="margin-top:0; font-size:0.95rem; font-weight:600; color:var(--vcf-text);">
          An active assessment is currently running in the sandbox on this jump host.
        </p>
        <p class="text-sm text-muted">
          Launching a new assessment concurrently will compete for BMC sessions and network sockets. You can reattach to the running scan, safely terminate it, or cancel your request.
        </p>
        <div id="activeScanDetailsWrap" style="margin:0.75rem 0; padding:0.75rem; border:1px solid var(--vcf-border); border-radius:6px; background:var(--vcf-surface-2, rgba(0,0,0,0.02));">
          <div id="activeScanDetailsContent" class="text-xs font-mono" style="white-space:pre-wrap; word-break:break-all;"></div>
        </div>
      </div>
      <div class="vcf-modal-footer">
        <button type="button" class="btn btn-outline btn-sm" id="abortActiveScanBtn">Abort</button>
        <div class="flex gap-sm">
          <button type="button" class="btn btn-danger btn-sm" id="killAndRestartScanBtn" style="background-color:#d9534f; border-color:#d43f3a; color:#fff;">Terminate &amp; Restart</button>
          <button type="button" class="btn btn-primary btn-sm" id="resumeActiveScanBtn">⚡ Reattach &amp; Stream</button>
        </div>
      </div>
    </div>
  </div>

</div><!-- /main-wrap -->

<script>
{APP_JS}
</script>
</body>
</html>"""


def _get_keychain_label() -> str:
    import shutil
    import sys
    if sys.platform == "darwin" and shutil.which("security"):
        return "macOS Keychain"
    if sys.platform == "win32":
        return "Windows DPAPI"
    if shutil.which("secret-tool"):
        return "Linux keyring (libsecret)"
    return "not available on this system"
