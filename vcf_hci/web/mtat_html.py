"""Experimental MTAT panel. The warning text is the frozen constant."""

MTAT_INTRO = """<div><p>This is an experimental Python port of the <a href="https://github.com/VMware/MTAT" target="_blank" rel="noopener noreferrer">MTAT tool</a>, maintained by Dave Morrera.</p>
<p>MTAT analyzes workload memory usage to help assess and size memory tiering deployments.</p></div>"""

from vcf_hci.web.plugin_credential_html import service_picker

MTAT_PANEL = """
<section id="mtat-experimental" data-app-section aria-labelledby="mtatHeading" hidden>
  <nav aria-label="Breadcrumb"><p><a href="#plugins">Plugins</a> / <span aria-current="page">MTAT Experimental</span></p></nav>
  <h1 id="mtatHeading" class="section-heading" tabindex="-1">MTAT Workload Assessment (Experimental)</h1>
  <div class="alert alert-info" id="mtatIntroduction">__INTRO__</div>
  <p id="mtatBanner" class="alert alert-warning" role="status">Experimental workload assessment. Validate against MTAT 3.2 before sizing or deployment decisions.</p>
  <p id="mtatEnablement"></p>
  <div id="mtatWorkflow" class="mtat-workflow" data-active-step="0">
    <nav id="mtatStepper" class="workflow-steps mtat-stepper" aria-label="MTAT assessment steps">
      <ol>
        <li><button type="button" id="mtatStepBtn0" data-mtat-step="0" aria-current="step">1. Source &amp; Connection</button></li>
        <li><button type="button" id="mtatStepBtn1" data-mtat-step="1">2. Baseline Assessment</button></li>
        <li><button type="button" id="mtatStepBtn2" data-mtat-step="2">3. Sizing &amp; Savings</button></li>
      </ol>
    </nav>
    <p id="mtatStepStatus" class="text-muted mtat-step-status" role="status">Step 1 of 3 — Source &amp; Connection</p>
    <div class="mtat-workflow-body">
      <form id="mtatForm">
        <div id="mtatStep0Panel" data-mtat-panel="0">
          <div class="card" id="mtatConnectionCard"><div class="card-body">
            <div class="mtat-section-header">
              <h2 id="mtatStep0Heading" tabindex="-1">1. Source and connection</h2>
              <span id="mtatSourceModeBadge" class="badge badge-info">vCenter Live API</span>
            </div>
            <div class="clr-form-group"><label class="clr-control-label" for="mtatSource">Source</label><select class="clr-select" id="mtatSource">
                <option value="vcenter">vCenter</option>
                <option value="operations-rest">Operations REST</option>
                <option value="operations-xlsx">Operations workbook</option>
              </select></div>
            <div class="form-grid">
              <div class="clr-form-group" id="mtatEndpointGroup"><label class="clr-control-label" for="mtatEndpoint">Endpoint</label><input class="clr-input" id="mtatEndpoint" type="text" autocomplete="off"></div>
              <div class="clr-form-group" id="mtatUsernameGroup"><label class="clr-control-label" for="mtatUsername">Username</label><input class="clr-input" id="mtatUsername" type="text" autocomplete="off"></div>
              <div class="clr-form-group" id="mtatPasswordGroup"><label class="clr-control-label" for="mtatPassword">Password</label><input class="clr-input" id="mtatPassword" type="password" autocomplete="off"></div>
            </div>
            <div class="clr-check-row mt-half"><input id="mtatVerifyTls" type="checkbox" checked><label for="mtatVerifyTls">Verify TLS</label></div>
            <div id="mtatCertControls"><button type="button" class="btn btn-outline" id="mtatReviewCert">Review certificate / TOFU</button><button type="button" class="btn btn-outline" id="mtatClearPin" hidden>Remove pin</button>
              <p id="mtatPinStatus" class="clr-hint" role="status">No certificate pinned. Verify TLS uses the system trust store.</p>
              <div id="mtatCertReview" hidden><pre id="mtatCertDetails" style="white-space:pre-wrap;overflow-wrap:anywhere"></pre><p class="clr-hint">This first-use observation does not prove identity. Confirm the SHA-256 fingerprint through a trusted channel before accepting. Trust applies only to this vCenter endpoint in this page; changing the endpoint or reloading requires review again.</p><button type="button" class="btn btn-outline" id="mtatAcceptPin">Trust this SHA-256 fingerprint</button></div>
            </div>
            <div id="mtatWorkbookSection" class="mtat-workbook-section mt-half">
              <h3>Workbook import</h3>
              <p id="mtatWorkbookHelp" class="clr-hint">For Operations workbook source only. Choose an .xlsx file up to 32 MiB; auto detects its memory unit.</p>
              <div class="form-grid">
                <div class="clr-form-group"><label class="clr-control-label" for="mtatUnit">Workbook memory unit</label><select class="clr-select" aria-describedby="mtatWorkbookHelp" id="mtatUnit"><option>auto</option><option>GB</option><option>GiB</option><option>MB</option><option>MiB</option><option>KB</option><option>KiB</option><option>B</option></select></div>
                <div class="clr-form-group"><label class="clr-control-label" for="mtatWorkbook">Workbook</label><input class="clr-input" aria-describedby="mtatWorkbookHelp" id="mtatWorkbook" type="file" accept=".xlsx"></div>
              </div>
            </div>
            <div class="clr-check-row mt-half"><input id="mtatAck" type="checkbox"><label for="mtatAck">I acknowledge this experimental collection</label></div>
            <div class="flex gap-sm mt-half" style="flex-wrap:wrap;align-items:center">
              <button class="btn btn-outline" type="button" id="mtatDiscover" aria-describedby="mtatDiscoveryStatus mtatClusterHelp" disabled>Discover clusters and history</button>
              <button class="btn btn-flat btn-sm" type="button" id="mtatStep1Next">Continue to Baseline Assessment →</button>
            </div>
            <p id="mtatDiscoveryStatus" class="clr-hint" role="status" aria-live="polite">Enter connection details and acknowledge experimental collection above to enable discovery.</p>
            <p id="mtatClusterHelp" class="clr-hint">Enter vCenter credentials, acknowledge experimental collection, then discover clusters and history. A single cluster is selected automatically. Your password stays in this form for Preflight and Run.</p>
            <div id="mtatHistorySettings" hidden><h3>vCenter history settings</h3><p class="clr-hint">Configured retention does not guarantee complete metric history. MTAT historical collection requires enabled Level 2 or higher statistics.</p><div style="overflow-x:auto"><table class="table"><thead><tr><th scope="col">Interval key</th><th scope="col">Sampling</th><th scope="col">Retention</th><th scope="col">Statistics level</th><th scope="col">Status</th></tr></thead><tbody id="mtatHistoryRows"></tbody></table></div></div>
          </div></div>
        </div>

        <div id="mtatStep1Panel" data-mtat-panel="1">
          <div class="card" id="mtatScopeCard"><div class="card-body">
            <div class="mtat-section-header">
              <h2 id="mtatStep1Heading" tabindex="-1">2. Baseline Assessment — Collection Scope &amp; History</h2>
              <span id="mtatScopeSummaryBadge" class="badge badge-secondary">1 Range Selected</span>
            </div>
            <p id="mtatHistoryHelp" class="clr-hint">Live sources default to the past seven days. Dates are UTC; the date picker uses your browser’s display format. Edit both dates for a custom window.</p>
            <div class="form-grid mtat-scope-grid">
              <div class="mtat-scope-left">
                <div class="clr-form-group"><label class="clr-control-label" for="mtatCluster">Target Cluster Scope</label><input class="clr-input" id="mtatCluster" type="text" autocomplete="off" hidden disabled><select class="clr-select" id="mtatClusterSelect" aria-label="Discovered cluster" aria-describedby="mtatClusterHelp"><option value="">Discover clusters to select</option></select></div>
                <div class="clr-form-group mt-half" id="mtatHistoryRangeGroup"><label class="clr-control-label" for="mtatHistoryRange">Range</label><select class="clr-select" id="mtatHistoryRange" aria-describedby="mtatRetentionHint"><option value="week">Past 7 Days</option><option value="month">Past 30 Days</option><option value="day">Past 24 Hours</option><option value="custom">Custom history</option><option value="realtime">Realtime</option></select></div>
              </div>
              <div class="mtat-scope-right" id="mtatMultiRangeGroup">
                <div class="mtat-range-header">
                  <span class="clr-control-label">Evaluation Metrics Range</span>
                  <button type="button" class="btn btn-flat btn-sm" id="mtatRangeToggleAll">Select All</button>
                </div>
                <div class="mtat-range-box" role="group" aria-label="Evaluation metrics range profiles">
                  <div class="clr-check-row"><input id="mtatCheckRealtime" type="checkbox" data-mtat-range="realtime"><label for="mtatCheckRealtime">Real-Time Snapshot</label></div>
                  <div class="clr-check-row"><input id="mtatCheckDay" type="checkbox" data-mtat-range="day"><label for="mtatCheckDay">Past 24 Hours (Avg Rollup)</label></div>
                  <div class="clr-check-row"><input id="mtatCheckWeek" type="checkbox" data-mtat-range="week" checked><label for="mtatCheckWeek">Past 7 Days (Avg Rollup)</label></div>
                  <div class="clr-check-row"><input id="mtatCheckMonth" type="checkbox" data-mtat-range="month"><label for="mtatCheckMonth">Past 30 Days (Avg Rollup)</label></div>
                </div>
              </div>
            </div>
            <div class="form-grid mt-half" id="mtatWindowFields">
              <div class="clr-form-group" id="mtatRangeGroup"><label class="clr-control-label" for="mtatRange">Range label</label><input class="clr-input" id="mtatRange" type="text" value="Past 7 Days" autocomplete="off"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="mtatBegin">History begin (UTC)</label><input class="clr-input" aria-describedby="mtatHistoryHelp" id="mtatBegin" type="datetime-local"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="mtatEnd">History end (UTC)</label><input class="clr-input" aria-describedby="mtatHistoryHelp" id="mtatEnd" type="datetime-local"></div>
              <div class="clr-form-group"><label class="clr-control-label" for="mtatInterval">vCenter interval key</label><input class="clr-input" aria-describedby="mtatIntervalHelp" id="mtatInterval" value="auto"></div>
            </div>
            <p class="clr-hint" id="mtatIntervalHelp">For vCenter history, auto selects an available interval of at least 30 minutes and aligns the window to retained samples. Enter an interval key for explicit selection.</p>
            <p id="mtatRetentionHint" class="clr-hint" role="status">Discover vCenter history to check which ranges are supported.</p>
            <div class="mtat-action-bar mt-half">
              <button class="btn btn-primary mtat-analyze-btn" type="button" id="mtatRun" disabled>Analyze Selection Profile</button>
              <button class="btn btn-outline" type="button" id="mtatPreflight">Preflight</button>
              <button class="btn btn-outline" type="button" id="mtatCancel" disabled>Cancel</button>
            </div>
          </div></div>
        </div>
      </form>

      <p id="mtatProgress" role="status" aria-live="polite"></p>
      <div id="mtatResults"></div>

      <div id="mtatBaselineReport" hidden>
        <div class="card mtat-report-card" id="mtatChecklistCard"><div class="card-body">
          <div class="mtat-section-header">
            <h3 id="mtatChecklistHeading" class="mtat-checklist-heading">BASELINE QUALIFICATION CHECKLIST (RAW HARDWARE)</h3>
            <div class="mtat-inline-control" id="mtatChecklistRangeWrap" hidden>
              <label class="clr-control-label" for="mtatChecklistRangeSelect">Baseline Range</label>
              <select class="clr-select" id="mtatChecklistRangeSelect"></select>
            </div>
          </div>
          <div class="mtat-checklist-panel" id="mtatChecklistRows" role="list"></div>
        </div></div>

        <div class="card mtat-report-card" id="mtatMatrixCard"><div class="card-body">
          <div class="mtat-section-header">
            <h3>Range Comparison Matrix (Historical Workload Trend Tracking)</h3>
            <div class="flex gap-sm" style="flex-wrap:wrap;align-items:center">
              <a class="btn btn-primary btn-sm" id="mtatExportMatrixCsv" href="#" download="experimental-mtat-matrix.csv">Export Matrix CSV</a>
              <a class="btn btn-outline btn-sm" id="mtatExportZipBtn" href="#">Download Export ZIP</a>
              <button class="btn btn-outline btn-sm" type="button" id="mtatStep2Next">3. Sizing &amp; Savings →</button>
            </div>
          </div>
          <div style="overflow-x:auto">
            <table class="table mtat-matrix-table" id="mtatMatrixTable">
              <thead>
                <tr>
                  <th scope="col">Target Cluster Scope</th>
                  <th scope="col">Analyzed Range Profile</th>
                  <th scope="col">CPU Avg/Peak</th>
                  <th scope="col">Active Memory %</th>
                  <th scope="col">Consumed Memory %</th>
                </tr>
              </thead>
              <tbody id="mtatMatrixRows"></tbody>
            </table>
          </div>
          <details class="mt-half" id="mtatDetailDisclosure">
            <summary>Host &amp; VM Telemetry Breakdown</summary>
            <div class="flex gap-sm mt-half" style="flex-wrap:wrap">
              <a class="btn btn-outline btn-sm" id="mtatExportHostsCsv" href="#">Download hosts.csv</a>
              <a class="btn btn-outline btn-sm" id="mtatExportVmsCsv" href="#">Download vms.csv</a>
              <a class="btn btn-outline btn-sm" id="mtatExportHostsHistCsv" href="#">Download hosts_history.csv</a>
              <a class="btn btn-outline btn-sm" id="mtatExportVmsHistCsv" href="#">Download vms_history.csv</a>
            </div>
            <h4 class="mt-half">Host Telemetry Summary</h4>
            <div style="overflow-x:auto">
              <table class="table" id="mtatHostTable">
                <thead>
                  <tr>
                    <th scope="col">Cluster</th>
                    <th scope="col">Host</th>
                    <th scope="col">Tiering</th>
                    <th scope="col" class="numeric">CPU %</th>
                    <th scope="col" class="numeric">Physical RAM (GB)</th>
                    <th scope="col" class="numeric">Consumed (GB)</th>
                    <th scope="col" class="numeric">Active Peak (GB)</th>
                    <th scope="col" class="numeric">Active %</th>
                    <th scope="col" class="numeric">Active Avg (GB)</th>
                    <th scope="col" class="numeric">NVMe (GB)</th>
                  </tr>
                </thead>
                <tbody id="mtatHostRows"></tbody>
              </table>
            </div>
            <h4 class="mt-half">VM Eligibility &amp; DRAM-Only Pinning</h4>
            <div style="overflow-x:auto">
              <table class="table" id="mtatVmTable">
                <thead>
                  <tr>
                    <th scope="col">Host</th>
                    <th scope="col">VM</th>
                    <th scope="col" class="numeric">Provisioned (GB)</th>
                    <th scope="col" class="numeric">Active (GB)</th>
                    <th scope="col" class="numeric">Active %</th>
                    <th scope="col">DRAM_Only (MTAT 3.2)</th>
                    <th scope="col">1GB Pages</th>
                    <th scope="col">2MB Pages</th>
                  </tr>
                </thead>
                <tbody id="mtatVmRows"></tbody>
              </table>
            </div>
          </details>
        </div></div>
      </div>

      <div id="mtatSizingPanel" data-mtat-panel="2" hidden>
        <div class="card mtat-report-card" id="mtatSizingCard"><div class="card-body">
          <div class="mtat-section-header">
            <h2 id="mtatStep2Heading" tabindex="-1">3. Sizing &amp; Savings Projections</h2>
            <span id="mtatSizingBadge" class="badge badge-info">NVMe Memory Tiering</span>
          </div>
          <p id="mtatSizingEmpty" class="clr-hint">Run Analyze Selection Profile in Step 2 to calculate cluster and host NVMe Memory Tiering sizing and DRAM reclamation estimates.</p>
          <div id="mtatSizingContent" hidden>
            <div class="form-grid mtat-sizing-controls">
              <div class="clr-form-group">
                <label class="clr-control-label" for="mtatSizingRangeSelect">Reference Workload Range</label>
                <select class="clr-select" id="mtatSizingRangeSelect"></select>
              </div>
              <div class="clr-form-group">
                <label class="clr-control-label" for="mtatSizingRatioSelect">Target NVMe Tiering Ratio</label>
                <select class="clr-select" id="mtatSizingRatioSelect">
                  <option value="25">25% (4:1 DRAM:NVMe)</option>
                  <option value="50" selected>50% (2:1 DRAM:NVMe)</option>
                  <option value="100">100% (1:1 DRAM:NVMe)</option>
                </select>
              </div>
            </div>
            <div class="mtat-kpi-grid mt-half" id="mtatSizingKpis"></div>
            <h3 class="mt-half">Per-Host Sizing &amp; Tiering Breakdown</h3>
            <div style="overflow-x:auto">
              <table class="table" id="mtatSizingHostTable">
                <thead>
                  <tr>
                    <th scope="col">Host</th>
                    <th scope="col">Tiering Status</th>
                    <th scope="col" class="numeric">Physical DRAM (GB)</th>
                    <th scope="col" class="numeric">Consumed (GB)</th>
                    <th scope="col" class="numeric">Active Working Set (GB)</th>
                    <th scope="col" class="numeric">Pinned DRAM_Only (GB)</th>
                    <th scope="col" class="numeric">Observed NVMe (GB)</th>
                    <th scope="col" class="numeric">Recommended NVMe Tier (GB)</th>
                    <th scope="col" class="numeric">Effective Capacity (GB)</th>
                    <th scope="col" class="numeric">Projected Reclaimable DRAM (GB)</th>
                  </tr>
                </thead>
                <tbody id="mtatSizingHostRows"></tbody>
              </table>
            </div>
            <section class="mtat-tco mt-half" id="mtatTcoCard" aria-labelledby="mtatTcoHeading">
              <div class="mtat-section-header">
                <h3 id="mtatTcoHeading">TCO Scenario Explorer (Estimate)</h3>
                <span class="badge badge-info">Interactive</span>
              </div>
              <p class="clr-hint" id="mtatTcoDisclaimer">Planning estimate only. Prices are defaults or values you enter; they stay in this page and are not saved or sent to the server. DRAM rounds up to whole DIMMs and NVMe to whole drives per host. DIMM channel population rules are not modeled.</p>
              <div class="form-grid mtat-tco-controls">
                <div class="clr-form-group span-2">
                  <label class="clr-control-label" for="mtatTcoOvercommit">Memory overcommit target (provisioned VM memory : memory capacity)</label>
                  <div class="mtat-tco-range-row">
                    <input id="mtatTcoOvercommit" type="range" min="1" max="3" step="0.1" value="1" aria-describedby="mtatTcoObserved">
                    <output id="mtatTcoOvercommitValue" for="mtatTcoOvercommit">1.0x</output>
                  </div>
                  <p class="clr-hint" id="mtatTcoObserved">Observed: —</p>
                </div>
                <div class="clr-form-group">
                  <label class="clr-control-label" for="mtatTcoDimmSize">DIMM size</label>
                  <select class="clr-select" id="mtatTcoDimmSize" aria-describedby="mtatTcoDimmHelp">
                    <option value="16">16 GB</option>
                    <option value="32">32 GB</option>
                    <option value="64" selected>64 GB</option>
                    <option value="96">96 GB</option>
                    <option value="128">128 GB</option>
                    <option value="256">256 GB</option>
                  </select>
                  <p class="clr-hint" id="mtatTcoDimmHelp">64 GB and smaller default to $50/GB. Larger DIMMs default to $100/GB.</p>
                </div>
                <div class="clr-form-group">
                  <label class="clr-control-label" for="mtatTcoDramPrice">DRAM price ($/GB)</label>
                  <input class="clr-input" id="mtatTcoDramPrice" type="number" min="0" step="0.01" value="50" inputmode="decimal">
                  <div class="mtat-tco-price-state"><span id="mtatTcoDramPriceState" class="badge badge-info">Default price</span><button type="button" class="btn btn-flat btn-sm" id="mtatTcoDramReset" disabled>Reset to default</button></div>
                </div>
                <div class="clr-form-group">
                  <label class="clr-control-label" for="mtatTcoNvmePrice">NVMe price ($/GB)</label>
                  <input class="clr-input" id="mtatTcoNvmePrice" type="number" min="0" step="0.01" value="1.50" inputmode="decimal">
                  <div class="mtat-tco-price-state"><span id="mtatTcoNvmePriceState" class="badge badge-info">Default price</span><button type="button" class="btn btn-flat btn-sm" id="mtatTcoNvmeReset" disabled>Reset to default</button></div>
                </div>
                <div class="clr-form-group">
                  <label class="clr-control-label" for="mtatTcoDriveGb">NVMe drive capacity (GB)</label>
                  <input class="clr-input" id="mtatTcoDriveGb" type="number" min="0" step="1" value="3840" inputmode="numeric" aria-describedby="mtatTcoDriveHelp">
                  <p class="clr-hint" id="mtatTcoDriveHelp">Used to round each host's NVMe tier up to whole drives.</p>
                </div>
              </div>
              <div class="mtat-kpi-grid mt-half" id="mtatTcoKpis"></div>
              <div class="mtat-tco-charts mt-half">
                <figure class="mtat-tco-figure">
                  <figcaption>Total memory cost by overcommit target</figcaption>
                  <div class="mtat-tco-chart-scroll"><div class="mtat-tco-chart-wrap">
                    <svg id="mtatTcoLineChart" class="mtat-tco-chart" viewBox="0 0 640 270" role="img" aria-label="Total memory cost by overcommit target"></svg>
                    <div id="mtatTcoTooltip" class="mtat-tco-tooltip" hidden></div>
                  </div></div>
                  <ul class="mtat-tco-legend" aria-hidden="true">
                    <li><span class="mtat-tco-swatch mtat-tco-r0"></span>DRAM only</li>
                    <li><span class="mtat-tco-swatch mtat-tco-r25"></span>25% (4:1)</li>
                    <li><span class="mtat-tco-swatch mtat-tco-r50"></span>50% (2:1)</li>
                    <li><span class="mtat-tco-swatch mtat-tco-r100"></span>100% (1:1)</li>
                  </ul>
                </figure>
                <figure class="mtat-tco-figure">
                  <figcaption>DRAM and NVMe cost at the selected overcommit</figcaption>
                  <div class="mtat-tco-chart-scroll"><div class="mtat-tco-chart-wrap">
                    <svg id="mtatTcoBarChart" class="mtat-tco-chart" viewBox="0 0 640 250" aria-label="DRAM and NVMe cost per NVMe tier ratio"></svg>
                  </div></div>
                  <ul class="mtat-tco-legend" aria-hidden="true">
                    <li><span class="mtat-tco-swatch mtat-tco-dram"></span>DRAM</li>
                    <li><span class="mtat-tco-swatch mtat-tco-nvme"></span>NVMe</li>
                  </ul>
                </figure>
              </div>
              <h4 class="mt-half">Scenario Comparison at Selected Overcommit</h4>
              <div style="overflow-x:auto">
                <table class="table" id="mtatTcoTable">
                  <thead>
                    <tr>
                      <th scope="col">NVMe Tier Ratio</th>
                      <th scope="col" class="numeric">DRAM (GB)</th>
                      <th scope="col" class="numeric">DIMMs per Host</th>
                      <th scope="col" class="numeric">NVMe Tier (GB)</th>
                      <th scope="col" class="numeric">Drives per Host</th>
                      <th scope="col" class="numeric">DRAM Cost</th>
                      <th scope="col" class="numeric">NVMe Cost</th>
                      <th scope="col" class="numeric">Total Cost</th>
                      <th scope="col" class="numeric">Savings vs DRAM Only</th>
                      <th scope="col">Notes</th>
                    </tr>
                  </thead>
                  <tbody id="mtatTcoRows"></tbody>
                </table>
              </div>
            </section>
          </div>
        </div></div>
      </div>
    </div>
  </div>
  <details class="mt-half"><summary>Connection diagnostics</summary><pre id="mtatDiagnostics" style="white-space:pre-wrap">No connection requests yet.</pre></details>
</section>
""".replace("__INTRO__", MTAT_INTRO)

MTAT_PANEL = MTAT_PANEL.replace('<div class="form-grid">', service_picker('mtat', 'mtat-experimental', 'mtatEndpoint', 'mtatUsername', 'mtatPassword', 'mtatSource', '') + '<div class="form-grid">', 1)
