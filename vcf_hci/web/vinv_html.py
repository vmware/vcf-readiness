"""Experimental vSphere inventory panel. The warning text is the frozen constant."""

from vcf_hci.web.plugin_credential_html import service_picker

VINV_PANEL = """
<section id="vinv-experimental" data-app-section aria-labelledby="vinvHeading" hidden>
  <nav aria-label="Breadcrumb"><p><a href="#plugins">Plugins</a> / <span aria-current="page">vSphere Inventory Experimental</span></p></nav>
  <h1 id="vinvHeading" class="section-heading" tabindex="-1">vSphere Inventory Export (Experimental)</h1>
  <p id="vinvBanner" class="alert alert-warning" role="status">Experimental vSphere inventory export and host reconciliation. Verify inventory completeness before sizing or migration decisions.</p>
  <p id="vinvEnablement"></p>
  <form id="vinvForm">
    <div class="card"><div class="card-body"><h2>Collect from vCenter</h2>
    <div class="vinv-credential-row">__VINV_PICKER__</div><div class="form-grid">
    <div class="clr-form-group"><label class="clr-control-label" for="vinvEndpoint">vCenter</label><input class="clr-input" id="vinvEndpoint" type="text" autocomplete="off" placeholder="vcsa-01.rainpole.net" aria-describedby="vinvEndpointHelp"><p id="vinvEndpointHelp" class="clr-hint">Enter a hostname, or paste a vSphere Client URL. Only its HTTPS host and port are used.</p></div>
    <div class="clr-form-group"><label class="clr-control-label" for="vinvUsername">Username</label><input class="clr-input" id="vinvUsername" type="text" autocomplete="off"></div>
    <div class="clr-form-group"><label class="clr-control-label" for="vinvPassword">Password</label><input class="clr-input" id="vinvPassword" type="password" autocomplete="off"></div>
    </div>
    <h3>1. Review connection security</h3>
    <p class="clr-hint">Verify TLS uses your system trust store. Review certificate is optional when that trust succeeds; use it to inspect and pin a certificate for a private vCenter.</p>
    <div class="clr-check-row"><input id="vinvVerifyTls" type="checkbox" checked><label for="vinvVerifyTls">Verify TLS</label></div>
    <div class="flex gap-sm mt-half" style="flex-wrap:wrap">
    <button class="btn btn-outline btn-sm" type="button" data-action="vinv-review-cert">Review certificate</button>
    <button class="btn btn-outline btn-sm" type="button" data-action="vinv-clear-pin" id="vinvClearPin" hidden>Clear pin</button>
    </div>
    <p id="vinvPinStatus" class="clr-hint" role="status">No certificate pinned. Verify TLS uses the system trust store.</p>
    <div id="vinvCertReview" hidden><pre id="vinvCertDetails"></pre>
    <button class="btn btn-primary btn-sm" type="button" data-action="vinv-accept-pin">Trust this SHA-256 fingerprint</button></div>
    <h3>2. Acknowledge and connect</h3>
    <div class="clr-check-row"><input id="vinvAck" type="checkbox"><label for="vinvAck">I acknowledge this experimental collection</label></div>
    <button class="btn btn-outline mt-half" type="button" data-action="vinv-preflight" disabled>Connect</button>
    <p id="vinvFlowStatus" class="clr-hint" role="status" aria-live="polite">Review TLS, acknowledge the experimental collection, then Connect.</p>
    <div id="vinvPreflightDetails" role="status" aria-live="polite"></div>
    <h3>3. Choose scope</h3>
    <div class="clr-form-group"><label class="clr-control-label" for="vinvCluster">Cluster</label><select class="clr-input" id="vinvCluster"><option value="">All clusters</option></select>
    <button class="btn btn-outline btn-sm" type="button" data-action="vinv-discover" disabled>Discover clusters</button><p id="vinvDiscoveryStatus" class="clr-hint" role="status">Connect to discover clusters automatically. Use Discover clusters to refresh the list.</p></div>
    </div></div>
    <div class="card"><div class="card-body"><h2>4. Review and collect</h2>
    <div class="clr-check-row"><input id="vinvHints" type="checkbox" checked><label for="vinvHints">Include CDP/LLDP network hints</label></div>
    <div class="clr-check-row"><input id="vinvFileInfo" type="checkbox"><label for="vinvFileInfo">Include datastore file listing (vFileInfo, slow)</label></div>
    <div class="flex gap-sm mt-half" style="flex-wrap:wrap">
    <button class="btn btn-primary" type="button" data-action="vinv-run" disabled>Collect</button>
    <button class="btn btn-outline" type="button" data-action="vinv-cancel" disabled>Cancel</button>
    </div><p id="vinvProgress" role="status" aria-live="polite"></p></div></div>
    <div class="card"><div class="card-body"><h2>Scan Library</h2>
    <p>Completed vSphere inventory exports are saved under VCF-Scans/vSphere-Inventory. Load one below to attach it to this assessment.</p>
    <div style="overflow-x:auto"><table class="table" id="vinvSavedLibrary"><thead><tr><th>vCenter</th><th>Generated (UTC)</th><th>Hosts</th><th>VMs</th><th>Actions</th></tr></thead><tbody></tbody></table></div>
    <p class="clr-hint">You can also import an older workbook or JSON snapshot.</p>
    <p id="vinvWorkbookHelp" class="clr-hint">A previously exported .xlsx workbook or .json snapshot, up to 48 MiB. Imports need no credentials.</p>
    <div class="clr-form-group"><label class="clr-control-label" for="vinvWorkbook">Workbook (.xlsx) or snapshot (.json)</label><input class="clr-input" aria-describedby="vinvWorkbookHelp" id="vinvWorkbook" type="file" accept=".xlsx,.json"></div>
    <button class="btn btn-outline" type="button" data-action="vinv-import" disabled>Import file</button>
    </div></div>
  </form>
  <details><summary>Connection diagnostics</summary><pre id="vinvDiagnostics">No diagnostics recorded.</pre></details>
  <div class="card"><div class="card-body"><h2>Inventory library</h2>
  <p>The latest collected or loaded inventory attaches automatically to the current Redfish assessment. Use Attach to switch between inventories.</p>
  <div style="overflow-x:auto"><table class="table" id="vinvLibrary">
    <thead><tr><th scope="col">Source</th><th scope="col">vCenter</th><th scope="col">Generated (UTC)</th><th scope="col">Hosts</th><th scope="col">VMs</th><th scope="col">Findings</th><th scope="col">Attached</th><th scope="col">Actions</th></tr></thead>
    <tbody></tbody>
  </table></div>
  </div></div>
  <div class="card"><div class="card-body"><h2>Reconciled reports</h2>
  <p>Merge a Redfish hardware scan with the vCenter inventory attached above. MTAT workload assessment is optional.</p>
  <ol><li>Choose a Redfish scan below, or use the assessment already loaded.</li><li>Collect or load vSphere inventory; the latest result attaches automatically. Use <strong>Attach</strong> in Inventory library to switch results.</li><li>Download the merged fleet report or the main assessment Excel export.</li></ol>
  <div class="clr-form-group"><label class="clr-control-label" for="vinvScanLibrary">Scan library folder</label>
    <input class="clr-input" id="vinvScanLibrary" type="text" value="~/Desktop/VCF-Scans"></div>
  <button class="btn btn-outline" type="button" data-action="vinv-discover-scans">Find Redfish scans</button>
  <div class="clr-form-group"><label class="clr-control-label" for="vinvRedfishScan">Redfish scan</label>
    <select class="clr-input" id="vinvRedfishScan"><option value="">Find scans to choose a hardware capture</option></select></div>
  <button class="btn btn-outline" type="button" data-action="vinv-load-scan" disabled>Use selected Redfish scan</button>
  <p id="vinvScanStatus" role="status" aria-live="polite">The current assessment is used unless you load a scan here. Loading replaces the active assessment; original scan files are preserved.</p>
  <p class="clr-hint">Need to upload scan files instead? Open <a href="#scan-library">Scan Library → Import prior scan</a>. Use scan JSON or a scan ZIP, not the hardware Excel report.</p>
  <p class="clr-hint">Hosts match by SMBIOS UUID (including byte-order variants), system serial/service tag, then hostname or IP. NIC MACs correlate ports after host matching; CPU serials and NIC hashes are not used.</p>
  <p>With an inventory attached, the main Excel export adds the Reconciliation and vSphere tabs automatically. The fleet report below adds vSphere context to the combined HTML.</p>
  <div class="flex gap-sm mt-half" style="flex-wrap:wrap">
    <a class="btn btn-outline" id="vinvFleetReport" href="/api/plugins/vinv/reconciled/fleet.html">Download reconciled fleet report</a>
    <a class="btn btn-outline" id="vinvFleetReportObf" href="/api/plugins/vinv/reconciled/fleet.html?obfuscated=1">Download obfuscated reconciled fleet report</a>
  </div>
  </div></div>
</section>
"""

VINV_PANEL = VINV_PANEL.replace('__VINV_PICKER__', service_picker('vinv', 'vinv-experimental', 'vinvEndpoint', 'vinvUsername', 'vinvPassword', '', ''))
