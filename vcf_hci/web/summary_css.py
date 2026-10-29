"""Theme-aware finished-summary layout and grouped secondary actions."""

SUMMARY_CSS = """
    /* Clarity: use outline actions for groups of equal priority. */
    #postScanActions {
      margin-top: 0 !important;
      padding: 0 1rem 1rem !important;
      border-top: 0 !important;
    }
    #postScanSummaryCard {
      border: 0;
      box-shadow: none;
      margin-bottom: 1rem !important;
    }
    #postScanSummaryCard > .card-header {
      padding: 1rem 0 .75rem;
      color: var(--vcf-text);
      font-size: .9rem;
      letter-spacing: .02em;
      flex-wrap: wrap;
      gap: .75rem;
    }
    #postScanSummaryCard > .card-body {
      padding: .85rem 0 !important;
      gap: .75rem !important;
      color: var(--vcf-text);
    }
    #postScanSummaryCard .text-muted { color: var(--vcf-text); }
    #summaryMetricsRow:not(.hidden), #summaryOutdirRow:not(.hidden), #summaryZipRow:not(.hidden) {
      display: grid !important;
      grid-template-columns: 10rem minmax(0, 1fr);
      align-items: start !important;
      gap: .35rem .75rem !important;
      word-break: normal !important;
    }
    #summaryOutdirRow:not(.hidden) { grid-template-columns: 10rem minmax(0, 1fr) auto; }
    #summaryOutdirText, #summaryZipText {
      overflow-wrap: anywhere;
      white-space: normal;
      color: var(--vcf-text);
    }
    #summaryOpenFolderBtn {
      margin: 0 !important;
      padding: .25rem .65rem !important;
      font-size: .78rem !important;
    }
    .summary-action-sections { width: 100%; min-width: 0; }
    .summary-action-section + .summary-action-section { margin-top: 1.5rem; }
    .summary-action-section h3 {
      margin: 0 0 .65rem;
      color: var(--vcf-text);
      font-size: .95rem;
      font-weight: 600;
    }
    .summary-action-columns, .summary-action-row {
      display: grid;
      grid-template-columns: minmax(9rem, .65fr) minmax(0, 1fr) minmax(0, 1fr);
      column-gap: 1rem;
    }
    .summary-action-columns {
      padding: 0 .5rem .4rem;
      color: var(--vcf-text);
      font-size: .75rem;
      font-weight: 600;
    }
    .summary-action-row {
      align-items: start;
      padding: .6rem .5rem;
      border-top: 1px solid var(--vcf-border);
    }
    .summary-action-row:not(:has(button:not(.hidden))) { display: none; }
    .summary-artifact { color: var(--vcf-text); font-size: .85rem; font-weight: 500; }
    .summary-action-cell, .summary-export-tools {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: .5rem;
      min-width: 0;
    }
    .summary-action-sections .btn {
      margin: 0;
      min-height: 2.25rem;
      max-width: 100%;
      white-space: normal;
      text-align: left;
      line-height: 1.4;
      font-weight: 500;
    }
    .summary-action-sections .btn-outline { color: var(--vcf-primary); border-color: var(--vcf-primary); }
    .summary-action-sections .btn:focus-visible, #summaryOpenFolderBtn:focus-visible {
      outline: 2px solid var(--vcf-primary);
      outline-offset: 3px;
    }
    .summary-export-tools { padding: .6rem .5rem 0; }
    .summary-file-tools { padding-top: .9rem; }
    #retryActionsGroup { width: 100%; padding-top: 1rem; border-top: 1px solid var(--vcf-border); }
    @media (max-width: 700px) {
      #postScanActions { padding-inline: .75rem !important; }
      #summaryMetricsRow:not(.hidden), #summaryOutdirRow:not(.hidden), #summaryZipRow:not(.hidden) { grid-template-columns: minmax(0, 1fr); }
      #summaryOpenFolderBtn { justify-self: start; }
      .summary-action-columns { display: none; }
      .summary-action-row { grid-template-columns: minmax(0, 1fr); row-gap: .65rem; padding: .85rem 0; }
      .summary-action-cell:not(:has(button:not(.hidden))) { display: none; }
      .summary-action-cell::before {
        content: attr(data-variant);
        flex-basis: 100%;
        color: var(--vcf-text);
        font-size: .75rem;
      }
      .summary-export-tools { padding-inline: 0; }
    }
"""
