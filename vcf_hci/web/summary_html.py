"""Grouped post-scan report and data actions, retaining the scanner ID contract."""

from vcf_hci.ui_clarity import icon_html

SUMMARY_ACTIONS = f"""
      <div class="summary-action-sections">
        <section id="reportLinksGroup" class="summary-action-section" aria-labelledby="summaryReportsHeading">
          <h3 id="summaryReportsHeading">Reports</h3>
          <div class="summary-action-columns" aria-hidden="true">
            <span>Report</span><span>Standard</span><span>Obfuscated</span>
          </div>
          <div class="summary-action-row">
            <span class="summary-artifact">Executive summary</span>
            <div class="summary-action-cell" data-variant="Standard">
              <button type="button" class="btn btn-outline btn-sm hidden" id="executivePdfBtn">{icon_html('pdf-file')} Executive summary (PDF)</button>
              <button type="button" class="btn btn-outline btn-sm hidden" id="executiveHtmlBtn">View executive summary</button>
            </div>
            <div class="summary-action-cell" data-variant="Obfuscated">
              <button type="button" class="btn btn-outline btn-sm hidden" id="executiveObfPdfBtn">{icon_html('pdf-file')} Executive PDF — obfuscated</button>
            </div>
          </div>
          <div class="summary-action-row">
            <span class="summary-artifact">Fleet summary</span>
            <div class="summary-action-cell" data-variant="Standard">
              <button type="button" class="btn btn-outline btn-sm hidden" id="openSummaryBtn">📊 Open Fleet Summary</button>
            </div>
            <div class="summary-action-cell" data-variant="Obfuscated">
              <button type="button" class="btn btn-outline btn-sm hidden" id="openObfSummaryBtn">🔒 Open Obfuscated Summary</button>
            </div>
          </div>
          <div class="summary-action-row">
            <span class="summary-artifact">Combined host report</span>
            <div class="summary-action-cell" data-variant="Standard">
              <button type="button" class="btn btn-outline btn-sm hidden" id="openReportBtn">{icon_html('host-group')} Open Combined Host Report</button>
            </div>
            <div class="summary-action-cell" data-variant="Obfuscated">
              <button type="button" class="btn btn-outline btn-sm hidden" id="openObfReportBtn">🔒 Open Obfuscated Combined</button>
            </div>
          </div>
        </section>

        <section id="exportLinksGroup" class="summary-action-section" aria-labelledby="summaryExportHeading">
          <h3 id="summaryExportHeading">Export data</h3>
          <div class="summary-action-columns" aria-hidden="true">
            <span>Data</span><span>Standard</span><span>Obfuscated</span>
          </div>
          <div class="summary-action-row">
            <span class="summary-artifact">Excel inventory</span>
            <div class="summary-action-cell" data-variant="Standard">
              <button type="button" class="btn btn-outline btn-sm hidden" id="exportXlsxBtn">{icon_html('xls-file')} Export Excel</button>
            </div>
            <div class="summary-action-cell" data-variant="Obfuscated">
              <button type="button" class="btn btn-outline btn-sm hidden" id="exportObfXlsxBtn" title="Includes the obfuscation key. Keep the key private when sharing the workbook.">{icon_html('xls-file')} Export Obfuscated Excel + Key</button>
            </div>
          </div>
          <div class="summary-export-tools">
            <button type="button" class="btn btn-outline btn-sm hidden" id="exportCsvBtn">{icon_html('file')} Export CSV</button>
            <button type="button" class="btn btn-outline btn-sm hidden" id="exportSummaryJsonBtn">{icon_html('file')} Export Summary JSON</button>
            <button type="button" class="btn btn-outline btn-sm hidden" id="exportObfZipBtn" title="Download the obfuscated HTML hub, sub-reports, Excel, and CSVs. Review the contents before sharing externally.">{icon_html('file-zip')} Export Obfuscated Package (.zip)</button>
          </div>
          <div class="summary-export-tools summary-file-tools" aria-label="Scan files">
            <button type="button" class="btn btn-flat btn-sm hidden" id="openFolderBtn">📂 Open Scan Folder</button>
            <button type="button" class="btn btn-flat btn-sm hidden" id="prerenderReportsBtn" title="Pre-generate all single-host HTML reports across the fleet for fully offline portable bundles">⚡ Pre-render All Host Reports</button>
          </div>
        </section>
      </div>
"""
