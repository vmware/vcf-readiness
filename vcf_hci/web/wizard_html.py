"""Scan Wizard markup. Credential pickers reuse the vault service control."""

from vcf_hci.web.plugin_credential_html import service_picker


def wizard_section(collector_ok: bool, vdt_available: bool = True) -> str:
    run_disabled = "disabled" if not collector_ok else ""
    vdt_disabled = "" if vdt_available else "disabled"
    readonly_picker = service_picker("wizRo", "scan-wizard", "wizRoEndpoint", "wizRoUser", "wizRoPass", "", "", "readonly")
    admin_picker = service_picker("wizAdmin", "scan-wizard", "wizAdminEndpoint", "wizAdminUser", "wizAdminPass", "", "", "administrator")
    ops_picker = service_picker("wizOps", "scan-wizard", "wizOpsEndpoint", "wizOpsUser", "wizOpsPass", "wizOpsSource")
    return f'''
  <section id="scan-wizard" data-app-section aria-labelledby="wizardHeading" hidden>
    <h1 id="wizardHeading" class="section-heading" tabindex="-1">Scan Wizard</h1>
    <p class="text-muted">Choose what to collect, enter only the credentials that choice needs, then discover hosts before anything runs.</p>
    <div class="workflow">
      <nav class="workflow-steps" aria-label="Scan setup steps">
        <ol>
          <li><button type="button" data-wizard-step="0" aria-current="step">1. What to collect</button></li>
          <li><button type="button" data-wizard-step="1" disabled>2. Credentials</button></li>
          <li><button type="button" data-wizard-step="2" disabled>3. Discovery</button></li>
          <li><button type="button" data-wizard-step="3" disabled>4. HCL readiness</button></li>
          <li><button type="button" data-wizard-step="4" disabled>5. Options and output</button></li>
          <li><button type="button" data-wizard-step="5" disabled>6. Review and run</button></li>
        </ol>
      </nav>
      <div class="workflow-content">
        <p id="wizardStepStatus" class="text-muted" role="status">Step 1 of 6</p>
        <div id="wizardError" class="alert alert-danger hidden" role="alert" tabindex="-1"></div>

        <div data-wizard-panel="0">
          <h2 tabindex="-1">What to collect</h2>
          <p class="text-muted">The recommended path is hardware, inventory, and MTAT. VDT and the quick check stay off until you turn them on.</p>
          <fieldset class="wizard-group">
            <legend class="clr-control-label">Core readiness and sizing</legend>
            <div class="clr-toggle-row">
              <label class="clr-toggle-label" for="discVcfr">
                <input type="checkbox" role="switch" class="clr-toggle" id="discVcfr" checked aria-describedby="discVcfrHint">
                <span class="ui-switch-track" aria-hidden="true"></span>
                <span>VCF-R hardware scan</span>
              </label>
              <span id="discVcfrHint" class="clr-check-hint">Out-of-band Redfish hardware, compatibility checks, and the BMC security audit.</span>
            </div>
            <fieldset id="wizardHwAccess" class="wizard-sub-fieldset" aria-label="Hardware access method">
              <div class="clr-radio-wrapper">
                <input type="radio" name="hwAccess" id="hwBmc" value="bmc" checked>
                <label for="hwBmc">BMC (Redfish), direct or through a jump host</label>
              </div>
              <div class="clr-radio-wrapper">
                <input type="radio" name="hwAccess" id="hwEsxi" value="esxi_ssh" aria-describedby="hwEsxiHint hwEsxiSshWarning">
                <label for="hwEsxi">ESXi SSH to USB BMC</label>
                <button type="button" class="ui-help-trigger" id="esxiUsbHelpBtn" aria-expanded="false" aria-controls="esxiUsbHelp" aria-label="About ESXi SSH to USB BMC">Info</button>
                <div id="esxiUsbHelp" class="vcf-signpost" role="region" aria-label="ESXi SSH to USB BMC details" hidden>
                  <strong>When to use ESXi SSH to USB BMC</strong>
                  <p>Use this when the out-of-band BMC network is not reachable from this workstation or a jump host. The scan connects to ESXi over SSH and reads Redfish through the host USB BMC interface.</p>
                  <p class="text-xs text-muted">BMC direct and ESXi SSH do not run in the same pass.</p>
                  <button type="button" class="btn btn-flat btn-sm" id="esxiUsbHelpClose">Close</button>
                </div>
              </div>
              <span id="hwEsxiHint" class="clr-check-hint">For isolated BMC networks. Requires SSH on the ESXi hosts.</span>
              <div id="hwEsxiSshWarning" class="alert alert-warning" role="status" hidden><a href="https://github.com/vmware/vcf-security-and-compliance-guidelines/tree/main/security-configuration-hardening-guide" target="_blank" rel="noopener noreferrer">Leaving SSH enabled on an ESXi host is not advised</a></div>
              <span id="hwEsxiJumpHint" class="clr-check-hint" hidden>A jump host with ESXi SSH is not available until the USB BMC scanner says it can use one.</span>
            </fieldset>
            <div class="clr-toggle-row">
              <label class="clr-toggle-label" for="discVinv">
                <input type="checkbox" role="switch" class="clr-toggle" id="discVinv" checked aria-describedby="discVinvHint">
                <span class="ui-switch-track" aria-hidden="true"></span>
                <span>vSphere Inventory</span>
              </label>
              <span id="discVinvHint" class="clr-check-hint">Read-only vCenter workbook and host reconciliation with the hardware scan.</span>
            </div>
            <div class="clr-toggle-row">
              <label class="clr-toggle-label" for="discMtat">
                <input type="checkbox" role="switch" class="clr-toggle" id="discMtat" checked aria-describedby="discMtatHint">
                <span class="ui-switch-track" aria-hidden="true"></span>
                <span>MTAT workload assessment</span>
              </label>
              <span id="discMtatHint" class="clr-check-hint">Memory tiering qualification from vCenter. VCF Operations is optional.</span>
            </div>
          </fieldset>
          <fieldset class="wizard-group">
            <legend class="clr-control-label">Appliance diagnostics</legend>
            <div class="clr-toggle-row">
              <label class="clr-toggle-label" for="discVdt">
                <input type="checkbox" role="switch" class="clr-toggle" id="discVdt" aria-describedby="discVdtHint" {vdt_disabled}>
                <span class="ui-switch-track" aria-hidden="true"></span>
                <span>VDT appliance diagnostics</span>
              </label>
              <span id="discVdtHint" class="clr-check-hint">Needs an installed VDT package, appliance SSH, and a vCenter administrator account.</span>
            </div>
            <div class="clr-toggle-row">
              <label class="clr-toggle-label" for="discQuick">
                <input type="checkbox" role="switch" class="clr-toggle" id="discQuick" aria-describedby="discQuickHint">
                <span class="ui-switch-track" aria-hidden="true"></span>
                <span>vCenter quick check</span>
              </label>
              <span id="discQuickHint" class="clr-check-hint">Version, build, and cluster count. Does not deploy VDT.</span>
              <button type="button" class="ui-help-trigger tooltip tooltip-md tooltip-top-right" aria-describedby="discQuickTip">Info<span id="discQuickTip" class="tooltip-content" role="tooltip">Uses the administrator account so the check can see the same vCenter VDT would use.</span></button>
            </div>
          </fieldset>
          <fieldset class="wizard-group">
            <legend class="clr-control-label">Vault and network routing</legend>
            <div class="clr-toggle-row">
              <label class="clr-toggle-label" for="useVaultSlide">
                <input type="checkbox" role="switch" class="clr-toggle" id="useVaultSlide" aria-describedby="useVaultSlideHint">
                <span class="ui-switch-track" aria-hidden="true"></span>
                <span>Use credential vault</span>
              </label>
              <span id="useVaultSlideHint" class="clr-check-hint">Unlock your existing vault now. Saved accounts will be offered by default in Credentials.</span>
            </div>
            <div class="clr-toggle-row">
              <label class="clr-toggle-label" for="useJumpSlide">
                <input type="checkbox" role="switch" class="clr-toggle" id="useJumpSlide" aria-describedby="useJumpSlideHint">
                <span class="ui-switch-track" aria-hidden="true"></span>
                <span>Use a jump host</span>
              </label>
              <span id="useJumpSlideHint" class="clr-check-hint">Runs BMC collection from an SSH jump host. Turning this on also enables the vault.</span>
            </div>
            <p id="jumpVaultLiveNote" class="clr-hint" role="status" aria-live="polite"></p>
          </fieldset>
        </div>

        <div data-wizard-panel="1" hidden>
          <h2 tabindex="-1">Credentials</h2>
          <p class="text-muted">Only the accounts for the tools you selected are shown. Passwords stay out of the review step.</p>
          <div id="wizardAccessSlot"></div>
          <div id="wizardBmcSavedRow" class="clr-check-row" hidden>
            <input type="checkbox" id="wizardBmcUseSaved">
            <label for="wizardBmcUseSaved">Use saved BMC credentials</label>
            <p class="clr-hint">Saved credentials are matched to the hosts selected in Discovery. Hosts without a matching entry need credentials before scanning.</p>
          </div>
          <div id="wizardEsxiCreds" hidden>
            <h3>ESXi SSH — Dell preview</h3>
            <p>One selected Dell host with an existing USB BMC network. Collection uses the inventory-lite profile.</p>
            <label for="wizEsxiHost">ESXi address</label><input class="clr-input" id="wizEsxiHost" autocomplete="off">
            <label for="wizEsxiKey">Reviewed SSH public host key (type and base64 key)</label><textarea class="clr-textarea" id="wizEsxiKey"></textarea>
            <label for="wizEsxiBmcUser">BMC username</label><input class="clr-input" id="wizEsxiBmcUser" autocomplete="off">
            <label for="wizEsxiBmcPass">BMC password</label><input class="clr-input" id="wizEsxiBmcPass" type="password" autocomplete="new-password">
            <div class="clr-check-row"><input type="checkbox" id="wizEsxiVerifyTls"><label for="wizEsxiVerifyTls">Verify the BMC TLS certificate</label></div>
            <label for="wizEsxiBmcPin">BMC SHA256 certificate pin (optional)</label><input class="clr-input" id="wizEsxiBmcPin" autocomplete="off">
            <p class="clr-hint">Default account is root. Pin each host key during discovery before the scan starts.</p>
            <div class="form-grid">
              <div class="clr-form-group"><label class="clr-control-label" for="wizEsxiUser">Username</label><input class="clr-input" id="wizEsxiUser" type="text" value="root" autocomplete="off"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="wizEsxiPass">Password</label><input class="clr-input" id="wizEsxiPass" type="password" autocomplete="new-password" aria-describedby="wizEsxiPassFieldError"></div>
            </div>
          </div>
          <div id="wizardMtatSourceBlock">
            <label class="clr-control-label" for="wizMtatEngine">MTAT engine</label>
            <select class="clr-select" id="wizMtatEngine"><option value="embedded">Embedded MTAT 3.2</option><option value="upstream">Installed upstream plugin</option></select>
            <div id="wizardMtatModeBlock" hidden>
              <label class="clr-control-label" for="wizMtatMode">Upstream workflow</label>
              <select class="clr-select" id="wizMtatMode"><option value="live">Collect live</option><option value="import">Import offline files</option><option value="saved">Open saved dataset</option></select>
              <p class="clr-hint">Activate a compatible package in <a href="#plugins">Plugins</a>. Imports and saved review need no live credentials. Their evidence can be combined with independently selected hardware or Inventory scans.</p>
              <label class="clr-control-label" for="wizMtatPolicy">Eligibility policy</label>
              <select class="clr-select" id="wizMtatPolicy"><option value="mtat-3.2">MTAT 3.2 compatibility</option><option value="vsphere-current-2026-11-10">Current vSphere policy (2026-11-10)</option></select>
              <label class="clr-control-label" for="wizMtatCaFile">Enterprise CA bundle path (optional)</label>
              <input class="clr-input" id="wizMtatCaFile" type="text" autocomplete="off" aria-describedby="wizMtatCaHelp">
              <p class="clr-hint" id="wizMtatCaHelp">For live MTAT connections, use a PEM CA bundle on this workstation. Reviewed certificate pins remain enforced.</p>
            </div>
            <label class="clr-control-label" for="wizMtatSource">MTAT data source</label>
            <select class="clr-select" id="wizMtatSource"><option value="vcenter">vCenter</option><option value="operations-rest">VCF Operations</option></select>
            <p class="clr-hint">Choose one source for MTAT. Inventory and ESXi host discovery still use vCenter when selected.</p>
          </div>
          <div id="wizardRoBlock" hidden>
            <h3>vCenter read-only</h3>
            <p class="clr-hint">Used for Inventory, MTAT, and listing ESXi hosts. A read-only role on the vCenter root is enough.</p>
            {readonly_picker}
            <div class="form-grid">
              <div class="clr-form-group"><label class="clr-control-label" for="wizRoEndpoint">HTTPS hostname or URL</label><input class="clr-input" id="wizRoEndpoint" type="text" autocomplete="off" placeholder="vc-01.rainpole.net"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="wizRoUser">Username</label><input class="clr-input" id="wizRoUser" type="text" autocomplete="off" placeholder="readonly@vsphere.local"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="wizRoPass">Password</label><input class="clr-input" id="wizRoPass" type="password" autocomplete="new-password"></div>
            </div>
            <p class="clr-hint">The next step checks the connection and lets you review and trust a private vCenter certificate.</p>
          </div>
          <div id="wizardAdminBlock" hidden>
            <h3>vCenter administrator</h3>
            <button type="button" class="ui-help-trigger" id="adminRoleHelpBtn" aria-expanded="false" aria-controls="adminRoleHelp">Why a separate account?</button>
            <div id="adminRoleHelp" class="vcf-signpost" role="region" hidden>
              <strong>Read-only and administrator stay separate</strong>
              <p>Inventory and MTAT use a read-only account. VDT and the quick check need an administrator SSO account. Choosing the same vCenter copies the hostname only, not the password.</p>
              <button type="button" class="btn btn-flat btn-sm" id="adminRoleHelpClose">Close</button>
            </div>
            <div class="clr-check-row"><input type="checkbox" id="wizSameVcenter"><label for="wizSameVcenter">Same vCenter hostname as the read-only account</label></div>
            {admin_picker}
            <div class="form-grid">
              <div class="clr-form-group"><label class="clr-control-label" for="wizAdminEndpoint">HTTPS hostname or URL</label><input class="clr-input" id="wizAdminEndpoint" type="text" autocomplete="off"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="wizAdminUser">Username</label><input class="clr-input" id="wizAdminUser" type="text" autocomplete="off" placeholder="administrator@vsphere.local"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="wizAdminPass">Password</label><input class="clr-input" id="wizAdminPass" type="password" autocomplete="new-password"></div>
            </div>
          </div>
          <div id="wizardApplianceBlock" hidden>
            <h3>VDT appliance SSH</h3>
            <p class="clr-hint">Used for this run only unless you later add an appliance SSH vault entry. This is not the vCenter SSO password.</p>
            <div class="form-grid">
              <div class="clr-form-group"><label class="clr-control-label" for="wizAppHost">Appliance host</label><input class="clr-input" id="wizAppHost" type="text" autocomplete="off"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="wizAppUser">SSH username</label><input class="clr-input" id="wizAppUser" type="text" value="root" autocomplete="off"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="wizAppPass">SSH password</label><input class="clr-input" id="wizAppPass" type="password" autocomplete="new-password"></div>
            </div>
          </div>
          <div id="wizardOpsBlock" hidden>
            <h3>VCF Operations — MTAT source</h3>
            <input type="hidden" id="wizOpsSource" value="operations-rest">
            {ops_picker}
            <div class="form-grid">
              <div class="clr-form-group"><label class="clr-control-label" for="wizOpsEndpoint">Operations URL</label><input class="clr-input" id="wizOpsEndpoint" type="text" autocomplete="off"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="wizOpsUser">Username</label><input class="clr-input" id="wizOpsUser" type="text" autocomplete="off"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="wizOpsPass">Password</label><input class="clr-input" id="wizOpsPass" type="password" autocomplete="new-password"></div>
            </div>
            <label for="wizOpsAuthSource">Authentication source (optional)</label><input class="clr-input" id="wizOpsAuthSource" autocomplete="off">
            <div class="clr-check-row"><input type="checkbox" id="wizOpsVerifyTls" checked><label for="wizOpsVerifyTls">Verify the Operations TLS certificate</label></div>
            <label for="wizOpsCluster">Operations cluster name or resource ID (optional)</label><input class="clr-input" id="wizOpsCluster" autocomplete="off">
            <p class="clr-hint">Blank includes all accessible Operations clusters. Operations resource IDs differ from vCenter IDs. Operations currently supplies host metrics; VM eligibility is not assessed.</p>
          </div>
          <div id="wizardJumpSetup" hidden>
            <h3>Jump host</h3>
            <p id="wizardJumpStatus" class="clr-hint" role="status">Checking saved jump hosts…</p>
            <div id="wizardJumpSavedRow" class="clr-check-row" hidden><input type="checkbox" id="wizardJumpUseSaved"><label for="wizardJumpUseSaved">Use a saved jump host</label></div>
            <div id="wizardJumpSavedSlot" hidden></div>
            <div id="wizardJumpManual">
            <p class="clr-hint">If none are saved, add one here. The SSH key must be pinned before Next.</p>
            <div class="form-grid">
              <div class="clr-form-group"><label class="clr-control-label" for="wizJumpId">Id</label><input class="clr-input" id="wizJumpId" type="text" placeholder="dal-jump-01"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="wizJumpHost">Host</label><input class="clr-input" id="wizJumpHost" type="text"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="wizJumpPort">Port</label><input class="clr-input" id="wizJumpPort" type="number" value="22" min="1" max="65535"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="wizJumpUser">Username</label><input class="clr-input" id="wizJumpUser" type="text" value="ubuntu"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="wizJumpSubnets">Subnets</label><input class="clr-input" id="wizJumpSubnets" type="text" placeholder="192.0.2.0/24"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="wizJumpPass">SSH password</label><input class="clr-input" id="wizJumpPass" type="password" autocomplete="new-password"></div>
            </div>
            <button type="button" class="btn btn-outline btn-sm" id="wizJumpPin">Probe and pin SSH key</button>
            <button type="button" class="btn btn-primary btn-sm" id="wizJumpSave" disabled>Save jump host</button>
            <p id="wizJumpPinStatus" class="clr-hint" role="status">No key pinned for this form yet.</p>
            </div>
          </div>
        </div>

        <div data-wizard-panel="2" hidden>
          <h2 tabindex="-1">Discovery</h2>
          <p id="wizardDiscoverLead">Probe BMCs or list ESXi hosts, then pick the vCenter cluster shared by Inventory and MTAT.</p>
          <div id="wizardRoTrustBlock" hidden>
            <h3>vCenter certificate trust</h3>
            <div class="clr-check-row"><input type="checkbox" id="wizVerifyTls" checked><label for="wizVerifyTls">Verify TLS with the system trust store</label></div>
            <p class="clr-hint">A trusted fingerprint replaces CA verification for this endpoint. Review only inspects; select Trust certificate to accept it. Saved accounts retain accepted fingerprints in the encrypted vault.</p>
            <div id="wizRoCertAction" class="alert alert-warning" role="alert" hidden></div>
            <button type="button" class="btn btn-outline btn-sm" id="wizRoReviewCert" aria-describedby="wizRoCertAction wizRoCertStatus">Review certificate</button>
            <p id="wizRoCertStatus" class="clr-hint" role="status">Using the system trust store. Review and trust a private certificate if discovery fails.</p>
            <div id="wizRoCertReview" class="alert alert-info" style="flex-direction:column;align-items:stretch" hidden>
              <pre id="wizRoCertDetails" style="white-space:pre-wrap;overflow-wrap:anywhere"></pre>
              <p>Compare this SHA-256 fingerprint with vCenter through a trusted channel before accepting. A changed fingerprint requires explicit trust again.</p>
              <div>
                <button type="button" class="btn btn-primary btn-sm" id="wizRoTrustCert">Trust certificate</button>
                <button type="button" class="btn btn-flat btn-sm" id="wizRoCancelCert">Cancel</button>
              </div>
            </div>
            <div id="wizRoSaveBar" class="alert alert-info" hidden>
              <span id="wizRoSaveText">Save this read-only account to the vault?</span>
              <button type="button" class="btn btn-outline btn-sm" id="wizRoSaveYes">Save to vault</button>
              <button type="button" class="btn btn-flat btn-sm" id="wizRoSaveNo">Not now</button>
            </div>
          </div>
          <div id="wizardTargetsSlot"></div>
          <div id="wizardBmcTestSlot">
            <details id="wizardBmcTlsDetails"><summary>BMC certificate check details</summary><div id="wizardBmcTlsDiagnostic" aria-live="polite"><p>Certificate checks appear here when you continue or pin certificates.</p></div></details>
          </div>
          <div id="wizardEsxiDiscover" hidden>
            <button type="button" class="btn btn-outline btn-sm" id="wizEsxiList">List ESXi hosts from vCenter</button>
            <p id="wizEsxiListStatus" class="clr-hint" role="status">Hosts appear after the read-only account connects.</p>
            <ul id="wizEsxiHostList"></ul>
          </div>
          <div id="wizardClusterBlock" hidden>
            <label class="clr-control-label" for="wizCluster">Cluster</label>
            <select class="clr-select" id="wizCluster"><option value="">All clusters</option></select>
            <button type="button" class="btn btn-outline btn-sm" id="wizDiscoverClusters">Discover clusters</button>
            <p id="wizClusterStatus" class="clr-hint" role="status">Discover clusters with the read-only account to fill this list.</p>
          </div>
          <div id="wizardMtatUpstreamScope" hidden>
            <h3>Upstream MTAT scope</h3>
            <button type="button" class="btn btn-outline btn-sm" id="wizMtatUpstreamDiscover">Connect and discover MTAT clusters</button>
            <label class="clr-control-label" for="wizMtatClusters">MTAT clusters</label>
            <select class="clr-select" id="wizMtatClusters" multiple size="5"></select>
            <p class="clr-hint" id="wizMtatUpstreamStatus" role="status">This scope is independent of the Inventory cluster and hardware targets.</p>
            <p><a href="#mtat-experimental">Open upstream workspace to import files or choose a saved dataset</a></p>
          </div>
          <p id="wizardQuickStatus" class="clr-hint" role="status"></p>
        </div>

        <div data-wizard-panel="3" hidden>
          <h2 tabindex="-1">Check HCL readiness</h2>
          <p id="wizardHclSkip" class="alert alert-info" hidden>HCL is not used because the VCF-R hardware scan is off. This step is already complete.</p>
          <div id="wizardHclActive">
            <p>The workflow checks the local compatibility database. Download an update when connected, or import an approved dark-site ZIP.</p>
            <p id="wizardHclStatus" role="status">Checking local HCL…</p>
            <div id="wizardHclSlot"></div>
            <div id="wizardHclAckRow" class="clr-check-row" hidden><input type="checkbox" id="wizardHclAck"><label for="wizardHclAck">Continue with limited or unverified HCL evidence. I understand this does not establish hardware certification.</label></div>
          </div>
        </div>

        <div data-wizard-panel="4" hidden>
          <h2 tabindex="-1">Scan options and output</h2>
          <div id="wizardMtatEmbeddedOptions" class="clr-form-group">
            <label class="clr-control-label" for="wizMtatRange">MTAT collection window (when selected)</label>
            <select class="clr-select" id="wizMtatRange" aria-describedby="wizMtatRangeHint wizMtatStatus">
              <option value="Past 24 Hours">Past 24 Hours</option>
              <option value="Past 7 Days">Past 7 Days</option>
              <option value="Past 30 Days">Past 30 Days</option>
              <option value="realtime">Real-time snapshot</option>
            </select>
            <p class="clr-hint" id="wizMtatRangeHint">Available history is checked automatically. The most detailed available historical window is selected; real-time is the fallback.</p>
            <div id="wizMtatRealtimeWarning" class="alert alert-warning" role="status" style="flex-direction:column;align-items:stretch" hidden>
              <p id="wizMtatRealtimeWarningText"></p>
            <p id="wizMtatRetentionHelp" class="clr-hint"><a href="https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/configuring-vcenter-server-8-0/configuring-vcenter-server-using-the-vsphere-client/configuring-vcenter-server-in-the-vsphere-client/configuring-statistics-settings-in-the-vsphere-client.html" target="_blank" rel="noopener noreferrer">Configure statistics collection intervals, retention and levels (Broadcom documentation)</a></p>
            </div>
            <ul id="wizMtatAvailability" aria-live="polite"></ul>
            <p id="wizMtatStatus" role="status" class="clr-hint"></p>
          </div>
          <div id="wizardMtatUpstreamOptions" class="clr-form-group" hidden>
            <label class="clr-control-label" for="wizMtatRanges">Upstream collection ranges</label>
            <select class="clr-select" id="wizMtatRanges" multiple size="5"></select>
            <p class="clr-hint">Ranges come from the selected clusters. Latest Operations samples are not vCenter real-time snapshots. Reports retain actual coverage and evidence gaps.</p>
            <div class="clr-check-row"><input id="wizMtatCustom" type="checkbox" disabled><label for="wizMtatCustom">Include a custom UTC history window (when supported by this package)</label></div>
            <div class="form-grid"><div><label for="wizMtatCustomBegin">Begin (UTC)</label><input class="clr-input" id="wizMtatCustomBegin" type="datetime-local"></div><div><label for="wizMtatCustomEnd">End (UTC)</label><input class="clr-input" id="wizMtatCustomEnd" type="datetime-local"></div></div>
          </div>
          <div class="clr-check-row"><input type="checkbox" id="wizOverlap" checked><label for="wizOverlap">Run Inventory and MTAT alongside the host scan</label></div>
          <p class="clr-hint">Optional: one vCenter collection runs at a time, Inventory then MTAT. Host scan workers stay available for BMCs. The unified workbook waits for collection to finish.</p>
          <div id="wizardThreadsSlot"></div>
          <div id="wizardOutputSlot"></div>
          <p><a href="#advanced-configuration">More settings: TLS, exports, warranty, and scan behavior</a>.</p>
        </div>

        <div data-wizard-panel="5" hidden>
          <h2 tabindex="-1">Review and run</h2>
          <p>Review the selected assessments and scheduling. Each phase shows its own progress below.</p>
          <dl id="wizardReview" class="workflow-review"></dl>
          <ol id="wizardTimeline" class="workflow-timeline" aria-label="Collection stages"></ol>
          <p id="wizardRunStatus" role="status" aria-live="polite"></p>
          <details open><summary>Collection activity</summary><ol id="wizardActivityLog" class="wizard-activity-log" aria-label="Collection activity log"></ol></details>
        </div>

        <p id="wizardResetStatus" class="clr-hint" role="status" aria-live="polite"></p>
        <p class="clr-hint">Reset clears setup and wizard progress. Wait for active collections to finish, or cancel the hardware scan in Scanner first. Saved vault entries and reports are retained.</p>
        <div class="workflow-footer">
          <button type="button" id="wizardResetBtn" class="btn btn-outline">Reset wizard</button>
          <a href="#scanner" class="btn btn-flat">Exit wizard</a>
          <button type="button" id="wizardBackBtn" class="btn btn-outline" disabled>Back</button>
          <button type="button" id="wizardNextBtn" class="btn btn-primary">Next</button>
          <button type="button" id="wizardRunBtn" class="btn btn-primary" hidden {run_disabled}>Run selected assessments</button>
        </div>
      </div>
    </div>
    <dialog id="wizardVaultDialog" aria-labelledby="wizardVaultTitle" style="max-width:30rem;width:calc(100% - 2rem)">
      <form id="wizardVaultForm">
        <h2 id="wizardVaultTitle">Unlock credential vault</h2>
        <p>Enter the vault passphrase to use your saved accounts and jump hosts.</p>
        <label for="wizardVaultPassword">Vault passphrase</label>
        <input class="clr-input" id="wizardVaultPassword" type="password" autocomplete="current-password" required>
        <p id="wizardVaultError" role="alert" hidden></p>
        <div class="flex gap-sm mt-half">
          <button class="btn btn-primary" id="wizardVaultUnlock" type="submit">Unlock vault</button>
          <button class="btn btn-flat" id="wizardVaultCancel" type="button">Cancel</button>
        </div>
      </form>
    </dialog>
  </section>
'''
