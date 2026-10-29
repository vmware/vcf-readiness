"""VDT installation, collection and import workflow beneath Plugins."""

VDT_NAV = '<a href="#vdt-plugin" data-section-link="vdt-plugin">VDT</a>'

VDT_WIZARD = '''<div class="alert alert-info"><strong>Optional management diagnostics</strong><p>For a hybrid assessment, complete this native scan, then <a href="#vdt-plugin">collect and import VDT evidence</a> for the same environment. Use remote collection to supply appliance SSH and vCenter SSO credentials for this run, or collect an export on the appliance and import it manually.</p></div>'''

VDT_PANEL = '''
<section id="vdt-plugin" data-app-section aria-labelledby="vdtHeading" hidden>
  <h1 id="vdtHeading" class="section-heading" tabindex="-1">VCF Diagnostic Tool for vSphere (VDT)</h1>
  <p>Combine appliance diagnostics with the current native Redfish assessment. The combined report includes an executive brief, separate readiness dimensions, evidence, and a PSO assessment coverage checklist.</p>
  <div class="card" id="vdtInstallCard"><div class="card-body">
    <h2>Install VDT packages</h2>
    <p id="vdtPackageState" class="plugin-state" role="status">Checking package availability</p>
    <p id="vdtInstalled" role="status">Checking installed packages…</p>
    <p>Download VDT from <a href="https://knowledge.broadcom.com/external/article/344917/using-the-vcf-diagnostic-tool-for-vspher.html" target="_blank" rel="noopener noreferrer">Broadcom’s official VDT download page</a>, then upload the original ZIP below. You can install both releases; archive names and build suffixes do not determine the version.</p>
    <ul><li>VDT 1.1.4: vCenter 6.5, 6.7 and 7.0. Legacy appliance collection is manual.</li><li>VDT 2.3.2: vCenter 7.x, 8.x and 9.x. Preferred for vCenter 7; managed collection requires the reviewed package and appliance Python 3.9 or newer.</li></ul>
    <div class="clr-form-group"><label class="clr-control-label" for="vdtZipFiles">VDT ZIP packages</label><input class="clr-input" id="vdtZipFiles" type="file" accept=".zip,application/zip" multiple aria-describedby="vdtZipHelp"></div>
    <p id="vdtZipHelp">Choose one or both ZIPs. Maximum 32 MiB per ZIP. Validated packages are extracted into the server’s Plugins folder and become available immediately. Uploading does not run VDT.</p>
    <button class="btn btn-primary" id="vdtInstallZip" type="button">Install selected ZIPs</button>
    <p id="vdtInstallStatus" role="status" aria-live="polite" style="overflow-wrap:anywhere"></p>
  </div></div>
  <div class="card" id="vdtRemoteCard"><div class="card-body">
    <h2>Collect VDT over SSH</h2>
    <p>Deploy the detected VDT folder to an appliance, run the reviewed checks there, validate the returned JSON, and import it into this assessment. Remote collection currently supports the reviewed VDT 2.3.2 for vCenter check set. Use manual import below for VKS and SDDC Manager.</p>
    <p>SSH credentials open the appliance terminal; SSO credentials authenticate the diagnostic checks. Both are used for this run only and are not saved to the vault or settings. The check set excludes unsafe checks and support-manifest writes; this remains partial VDT evidence.</p>
    <p id="vdtRemoteUnavailable" class="alert alert-info" role="status" hidden></p>
    <div id="vdtRemoteWorkflow" class="workflow">
      <nav class="workflow-steps" aria-label="Remote VDT collection steps"><ol>
        <li><button type="button" data-vdt-remote-step="0" aria-current="step">1. Appliance</button></li>
        <li><button type="button" data-vdt-remote-step="1" disabled>2. Trust &amp; credentials</button></li>
        <li><button type="button" data-vdt-remote-step="2" disabled>3. Review &amp; collect</button></li>
        <li><button type="button" data-vdt-remote-step="3" disabled>4. Progress &amp; results</button></li>
      </ol></nav>
      <div class="workflow-content">
        <p id="vdtRemoteStepStatus" class="text-muted" role="status">Step 1 of 4</p>
        <div id="vdtRemoteError" class="alert alert-danger" role="alert" tabindex="-1" hidden></div>
        <div data-vdt-remote-panel="0">
          <h3 tabindex="-1">Choose the appliance and VDT installation</h3>
          <div class="clr-form-group mt-half"><label class="clr-control-label" for="vdtRemoteFolder">Detected installation</label><select class="clr-select" id="vdtRemoteFolder"></select></div>
          <div class="clr-form-group mt-half"><label class="clr-control-label" for="vdtRemoteProduct">Remote product</label><select class="clr-select" id="vdtRemoteProduct"><option value="vcenter">vCenter</option></select></div>
          <div class="clr-form-group mt-half"><label class="clr-control-label" for="vdtRemoteHost">Appliance hostname or address</label><input class="clr-input" id="vdtRemoteHost" type="text" maxlength="2048" autocomplete="off" placeholder="vc-01.rainpole.net" aria-describedby="vdtRemoteHostHelp"></div>
          <p id="vdtRemoteHostHelp" class="text-muted">You can paste an HTTP or HTTPS URL; only its hostname is used. Set the SSH port separately below.</p>
          <div class="clr-form-group mt-half"><label class="clr-control-label" for="vdtRemoteApiPort">vCenter HTTPS port</label><input class="clr-input" id="vdtRemoteApiPort" type="number" min="1" max="65535" value="443"></div>
          <button class="btn btn-outline mt-half" id="vdtRemoteDiscover" type="button">Detect vCenter version &amp; select VDT</button>
          <p id="vdtRemoteDiscovery" role="status" aria-live="polite">Detect the vCenter version before continuing. No vCenter credentials are required for version discovery.</p>
          <p id="vdtRemoteLegacy" class="alert alert-info" hidden>VDT 1.1.4 is installed and selected for this vCenter. Its Python 2-era execution and text-log output require manual collection using Broadcom’s instructions; this application does not run legacy scripts through the VDT 2 adapter.</p>
          <div class="clr-form-group mt-half"><label class="clr-control-label" for="vdtRemotePort">SSH port</label><input class="clr-input" id="vdtRemotePort" type="number" min="1" max="65535" value="22"></div>
        </div>
        <div data-vdt-remote-panel="1" hidden>
          <h3 tabindex="-1">Verify SSH trust and supply credentials</h3>
          <p>Compare the presented SSH fingerprint with a trusted appliance record before accepting it. Trust applies only to this collection and is checked again by SSH when connecting.</p>
          <button class="btn btn-outline" id="vdtRemoteProbe" type="button">Read SSH fingerprint</button>
          <p id="vdtRemoteFingerprint" class="text-muted" style="overflow-wrap:anywhere" role="status">No fingerprint read.</p>
          <div class="clr-check-row"><input id="vdtRemoteTrust" type="checkbox" disabled><label for="vdtRemoteTrust">I verified this SSH fingerprint and trust it for this run.</label></div>
          <div class="clr-form-group mt-half"><label class="clr-control-label" for="vdtRemoteUsername">Appliance SSH username</label><input class="clr-input" id="vdtRemoteUsername" type="text" value="root" autocomplete="off"></div>
          <div class="clr-form-group mt-half"><label class="clr-control-label" for="vdtRemotePassword">Appliance SSH password</label><input class="clr-input" id="vdtRemotePassword" type="password" autocomplete="new-password"></div>
          <p>The reviewed collector requires root appliance access. This is separate from the vCenter SSO account.</p>
          <div class="clr-form-group mt-half"><label class="clr-control-label" for="vdtRemoteSsoUsername">vCenter SSO username</label><input class="clr-input" id="vdtRemoteSsoUsername" type="text" autocomplete="off" placeholder="administrator@vsphere.local"></div>
          <div class="clr-form-group mt-half"><label class="clr-control-label" for="vdtRemoteSsoPassword">vCenter SSO password</label><input class="clr-input" id="vdtRemoteSsoPassword" type="password" autocomplete="new-password"></div>
          <p>SSO credentials are supplied directly for the reviewed checks; the collector does not extract the appliance machine-account secret.</p>
          <button class="btn btn-outline mt-half" id="vdtRemotePreflight" type="button" disabled>Check appliance prerequisites</button>
          <p id="vdtRemotePreflightStatus" role="status">Check SSH access, Python, root privileges, appliance markers, and temporary space before continuing. Native libraries, payload integrity, and SSO authentication are validated during collection.</p>
          <ul id="vdtRemoteWarnings"></ul>
        </div>
        <div data-vdt-remote-panel="2" hidden>
          <h3 tabindex="-1">Review collection scope and output</h3>
          <dl id="vdtRemoteReview" class="workflow-review"></dl>
          <div class="clr-form-group mt-half"><label class="clr-control-label" for="vdtRemoteOutput">Local artifact folder</label><input class="clr-input" id="vdtRemoteOutput" type="text" autocomplete="off" placeholder="Use the native assessment output folder"></div>
          <p>The collection uploads a temporary VDT copy and wrapper, runs the reviewed checks on the appliance, writes diagnostic logs, and pulls the validated exports into this local folder. The tool reports remote cleanup status; retain the artifact bundle for consulting evidence.</p>
          <div class="clr-check-row"><input id="vdtRemoteEffects" type="checkbox"><label for="vdtRemoteEffects">I reviewed this appliance, partial check scope, temporary upload, diagnostic logs, and local artifact destination.</label></div>
        </div>
        <div data-vdt-remote-panel="3" hidden>
          <h3 tabindex="-1">Collection progress and results</h3>
          <p id="vdtRemoteProgress" role="status" aria-live="polite">No collection started.</p>
          <ol id="vdtRemoteTimeline" class="workflow-timeline" aria-label="Collection stages"></ol>
          <details class="log-disclosure"><summary>Collection events and diagnostic details</summary><ol id="vdtRemoteEvents"></ol></details>
          <p id="vdtRemoteWarning" class="alert alert-warning" role="status" hidden></p>
          <p id="vdtRemoteSavedOutput" style="overflow-wrap:anywhere"></p>
          <ul id="vdtRemoteScopeNotes"></ul>
          <ul id="vdtRemoteArtifacts"></ul>
          <p id="vdtRemoteCleanup" role="status" class="text-muted" style="overflow-wrap:anywhere"></p>
          <button class="btn btn-outline" id="vdtRemoteCancel" type="button" hidden>Cancel collection</button>
          <button class="btn btn-outline" id="vdtRemoteRefresh" type="button" hidden>Check collection status</button>
          <button class="btn btn-primary" id="vdtRemoteRetry" type="button" hidden>Start another collection</button>
        </div>
        <div class="workflow-footer">
          <span class="text-muted">Credentials are kept out of review and progress.</span>
          <button class="btn btn-outline" id="vdtRemoteBack" type="button" disabled>Back</button>
          <button class="btn btn-primary" id="vdtRemoteNext" type="button">Next</button>
          <button class="btn btn-primary" id="vdtRemoteRun" type="button" hidden disabled>Deploy and collect VDT</button>
        </div>
      </div>
    </div>
  </div></div>
  <div class="card"><div class="card-body"><h2>Manual collection and import</h2>
    <p>VDT runs on vCenter or SDDC Manager using their installed libraries. Copy your approved VDT folder to the appliance and follow its collection procedure in an appliance terminal.</p>
    <div class="clr-form-group mt-half"><label class="clr-control-label" for="vdtProduct">VDT product</label><select class="clr-select" id="vdtProduct"><option value="vcenter">vCenter</option><option value="vks">VKS (on vCenter)</option><option value="sddc_manager">SDDC Manager</option></select></div>
    <p id="vdtAccess"></p>
    <p>The supplied VDT release has no remote credential API and can change appliance files and SSH trust records. The remote workflow above uses SSH to run a reviewed subset on vCenter. For a full VDT run or other products, collect on the appliance using the approved VDT procedure and import the export below.</p>
    <p>For VDT 2, return the JSON from <code>/var/log/vmware/vdt/json/</code>. Retain the complete VDT bundle separately for consulting evidence. Import a separate export for each appliance and product.</p>
    <p>Legacy VDT 1.1.4 produces <code>vdt-report-*</code> text logs in its appliance log directory. Run it using Broadcom’s legacy instructions and retain those logs separately; the JSON importer and hybrid evidence workflow below do not parse legacy text logs.</p>
  </div></div>
  <div class="card"><div class="card-body"><h2>2. Import native VDT 2 JSON</h2>
    <p>Product and appliance labels are supplied by you; VDT JSON does not reliably identify either. Match the evidence to the native scan environment before exporting.</p>
    <div class="clr-form-group mt-half"><label class="clr-control-label" for="vdtTarget">Appliance / environment label</label><input class="clr-input" id="vdtTarget" type="text" maxlength="255" placeholder="vc-01.rainpole.net / Production" autocomplete="off"></div>
    <div class="clr-form-group mt-half"><label class="clr-control-label" for="vdtFile">VDT JSON export (8 MiB maximum)</label><input class="clr-input" id="vdtFile" type="file" accept=".json,application/json"></div>
    <button class="btn btn-primary mt-half" id="vdtImport" type="button">Import VDT export</button>
    <p>Imports stay in this browser session on the server until removed or the server restarts. They are not saved to the credential vault, settings, or scan folder. Keep original files to reload later.</p>
    <p id="vdtStatus" role="status" aria-live="polite"></p>
    <p id="vdtRunsEmpty" class="text-muted" hidden>No VDT evidence imported yet. Collect diagnostics above or import a saved JSON export.</p>
    <ul id="vdtRuns"></ul>
    <button class="btn btn-outline" id="vdtClear" type="button">Clear imported evidence</button>
  </div></div>
  <div class="card"><div class="card-body"><h2>3. Export the hybrid assessment</h2>
    <p>Complete a native scan or import a native summary in Scanner / Scan Library first. This report uses the current native results plus the VDT exports listed above; it does not automatically match BMC hosts to vCenter inventory.</p>
    <div class="clr-check-row"><input id="vdtScopeConfirm" type="checkbox"><label for="vdtScopeConfirm">I reviewed these exports and the current native results and confirm they belong to this assessment.</label></div>
    <p><button class="btn btn-primary" id="vdtHybrid" type="button" disabled>Download hybrid HTML report</button></p>
    <p>The report contains original infrastructure identifiers and diagnostic details. Open the downloaded HTML to review and print to PDF. PSO evidence still needed includes RVTools, HST, interviews, and environment-specific compatibility validation.</p>
  </div></div>
</section>
'''
