"""
Clarity-token-aligned custom component CSS for the web UI.
"""

APP_CSS = """
    /* ── Clarity-token-aligned custom component CSS ───────────────── */

    /* Palette — light */
    :root {
      --vcf-bg:        #f4f6f8;
      --vcf-card:      #ffffff;
      --vcf-nav:       #1b2a32;
      --vcf-nav-text:  #e2eaf0;
      --vcf-text:      #313131;
      --vcf-muted:     #737373;
      --vcf-text-muted:#737373;
      --vcf-border:    #cccccc;
      --vcf-primary:   #0072a3;
      --vcf-primary-h: #005674;
      --vcf-success:   #62a420;
      --vcf-warning:   #c47d00;
      --vcf-danger:    #c92100;
      --vcf-info:      #0072a3;
      --vcf-radius:    3px;
      --vcf-shadow:    0 1px 3px rgba(0,0,0,.15);
      --vcf-input-bg:  #ffffff;
      --vcf-select-bg: #ffffff;
      --vcf-bg-subtle:   #f8f9fa;
      --vcf-bg-secondary:#f4f6f8;
      --vcf-pulse-shadow: rgba(0, 114, 163, 0.7);
      --vcf-pulse-shadow-fade: rgba(0, 114, 163, 0.25);
    }

    /* Palette — dark */
    [data-theme="dark"] {
      --vcf-bg:        #0f171c;
      --vcf-card:      #1b2a32;
      --vcf-nav:       #0a1218;
      --vcf-nav-text:  #c5d5de;
      --vcf-text:      #eaeff2;
      --vcf-muted:     #8a9aa5;
      --vcf-text-muted:#8a9aa5;
      --vcf-border:    #3a4e5a;
      --vcf-primary:   #49afd9;
      --vcf-primary-h: #6dcfee;
      --vcf-success:   #6ea005;
      --vcf-warning:   #c47d00;
      --vcf-danger:    #f54f47;
      --vcf-info:      #49afd9;
      --vcf-shadow:    0 1px 3px rgba(0,0,0,.5);
      --vcf-input-bg:  #243544;
      --vcf-select-bg: #243544;
      --vcf-bg-subtle:   #141f26;
      --vcf-bg-secondary:#16222c;
      --vcf-pulse-shadow: rgba(73, 175, 217, 0.75);
      --vcf-pulse-shadow-fade: rgba(73, 175, 217, 0.25);
    }

    *, *::before, *::after { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: "CDS City", "Metropolis", "Avenir Next", "Helvetica Neue", Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      background: var(--vcf-bg);
      color: var(--vcf-text);
      transition: background .15s, color .15s;
    }

    /* ── Navigation header ───────────────────────────────────────────── */
    .nav-header {
      background: var(--vcf-nav);
      color: var(--vcf-nav-text);
      display: flex;
      align-items: center;
      padding: 0 1.25rem;
      height: 48px;
      box-shadow: 0 1px 4px rgba(0,0,0,.4);
      position: sticky;
      top: 0;
      z-index: 100;
      gap: .75rem;
    }
    .nav-brand { font-size: 1rem; font-weight: 600; letter-spacing: .01em; flex: 1; }
    .nav-version { font-size: .75rem; color: #8a9aa5; }
    .nav-btn {
      background: none;
      border: 1px solid rgba(255,255,255,.2);
      color: var(--vcf-nav-text);
      border-radius: var(--vcf-radius);
      padding: .25rem .6rem;
      font-size: .78rem;
      cursor: pointer;
      transition: background .12s;
    }
    .nav-btn:hover { background: rgba(255,255,255,.08); }

    /* ── Layout ──────────────────────────────────────────────────────── */
    .main-wrap {
      max-width: 1100px;
      margin: 0 auto;
      padding: 1.5rem 1.25rem 3rem;
    }

    /* ── Cards ───────────────────────────────────────────────────────── */
    .card {
      background: var(--vcf-card);
      border: 1px solid var(--vcf-border);
      border-radius: var(--vcf-radius);
      box-shadow: var(--vcf-shadow);
      margin-bottom: 1rem;
    }
    .card-header {
      padding: .6rem 1rem;
      border-bottom: 1px solid var(--vcf-border);
      font-size: .78rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .07em;
      color: var(--vcf-muted);
      display: flex;
      align-items: center;
      gap: .5rem;
    }
    .card-body { padding: 1rem; }
    .card-footer {
      padding: .6rem 1rem;
      border-top: 1px solid var(--vcf-border);
      display: flex;
      gap: .5rem;
      align-items: center;
      flex-wrap: wrap;
    }

    /* ── Two-column form grid ────────────────────────────────────────── */
    .form-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: .75rem 1.25rem;
    }
    .form-grid .span-2 { grid-column: 1 / -1; }
    @media (max-width: 640px) {
      .form-grid { grid-template-columns: 1fr; }
      .form-grid .span-2 { grid-column: 1; }
    }

    /* ── Form fields ─────────────────────────────────────────────────── */
    .clr-form-group { display: flex; flex-direction: column; gap: .25rem; }
    .clr-control-label {
      font-size: .78rem;
      font-weight: 600;
      color: var(--vcf-muted);
      text-transform: uppercase;
      letter-spacing: .05em;
    }
    .clr-input, .clr-select, .clr-textarea {
      width: 100%;
      padding: .42rem .65rem;
      border: 1px solid var(--vcf-border);
      border-radius: var(--vcf-radius);
      background: var(--vcf-input-bg);
      color: var(--vcf-text);
      font-size: .875rem;
      font-family: inherit;
      outline: none;
      transition: border-color .12s, box-shadow .12s;
    }
    .clr-input:focus, .clr-select:focus, .clr-textarea:focus {
      border-color: var(--vcf-primary);
      box-shadow: 0 0 0 2px rgba(0,114,163,.2);
    }
    .clr-input[readonly], .clr-textarea[readonly] {
      background: var(--vcf-bg-subtle);
      color: var(--vcf-text);
      cursor: default;
    }
    .clr-input::placeholder, .clr-textarea::placeholder {
      color: var(--vcf-muted);
      opacity: 0.75;
    }
    .clr-textarea { resize: vertical; min-height: 56px; }
    .clr-select { appearance: none; -webkit-appearance: none;
                   background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%23737373'/%3E%3C/svg%3E");
                   background-repeat: no-repeat;
                   background-position: right .6rem center;
                   padding-right: 2rem; }
    .clr-hint { font-size: .75rem; color: var(--vcf-muted); margin-top: .15rem; }

    /* Inline checkbox / radio */
    .clr-check-row { display: flex; align-items: center; gap: .5rem; padding: .2rem 0; }
    .clr-check-row input[type=checkbox],
    .clr-check-row input[type=radio] {
      width: 14px; height: 14px; accent-color: var(--vcf-primary); cursor: pointer; flex-shrink: 0;
    }
    .clr-check-row label { font-size: .875rem; cursor: pointer; }
    .clr-check-hint { font-size: .75rem; color: var(--vcf-muted); margin-left: 1.4rem; }

    /* Number spinbox */
    input[type=number].clr-input { -moz-appearance: textfield; }
    input[type=number].clr-input::-webkit-inner-spin-button,
    input[type=number].clr-input::-webkit-outer-spin-button { opacity: 1; }

    /* ── Buttons ─────────────────────────────────────────────────────── */
    .btn {
      display: inline-flex;
      align-items: center;
      gap: .35rem;
      padding: .42rem 1rem;
      border: 1px solid transparent;
      border-radius: var(--vcf-radius);
      font-size: .875rem;
      font-weight: 600;
      cursor: pointer;
      transition: background .12s, border-color .12s, color .12s;
      white-space: nowrap;
      text-decoration: none;
      font-family: inherit;
    }
    .btn:disabled { opacity: .45; cursor: not-allowed; }
    .btn-primary {
      background: var(--vcf-primary);
      border-color: var(--vcf-primary);
      color: #fff;
    }
    .btn-primary:hover:not(:disabled) { background: var(--vcf-primary-h); border-color: var(--vcf-primary-h); }
    .btn-outline {
      background: transparent;
      border-color: var(--vcf-primary);
      color: var(--vcf-primary);
    }
    .btn-outline:hover:not(:disabled) { background: rgba(0,114,163,.08); }
    .btn-flat {
      background: transparent;
      border-color: var(--vcf-border);
      color: var(--vcf-text);
    }
    .btn-flat:hover:not(:disabled) { background: var(--vcf-bg); }
    .btn-danger {
      background: var(--vcf-danger);
      border-color: var(--vcf-danger);
      color: #fff;
    }
    .btn-danger:hover:not(:disabled) { filter: brightness(.88); }
    .btn-success-solid {
      background: var(--vcf-success);
      border-color: var(--vcf-success);
      color: #fff;
    }
    .btn-success-solid:hover:not(:disabled) { filter: brightness(.9); }
    .btn-sm { padding: .25rem .65rem; font-size: .78rem; }
    .btn-run {
      padding: .7rem 2rem;
      font-size: 1rem;
      letter-spacing: .02em;
    }

    /* ── Badge / label chips ─────────────────────────────────────────── */
    .badge {
      display: inline-block;
      padding: .18rem .55rem;
      border-radius: 2px;
      font-size: .75rem;
      font-weight: 700;
      vertical-align: middle;
    }
    .badge-success { background: #dff0d2; color: var(--vcf-success); }
    .badge-warning  { background: #fef3e0; color: var(--vcf-warning); }
    .badge-danger   { background: #fae1de; color: var(--vcf-danger);  }
    .badge-info     { background: #ddf0f7; color: var(--vcf-info);    }
    .badge-secondary { background: #e2e8f0; color: #475569; }
    [data-theme="dark"] .badge-success { background: #2b4a10; color: #a3d64c; }
    [data-theme="dark"] .badge-warning  { background: #4a3200; color: #e8aa3a; }
    [data-theme="dark"] .badge-danger   { background: #4a1210; color: #f88; }
    [data-theme="dark"] .badge-info     { background: #0c3550; color: #49afd9; }
    [data-theme="dark"] .badge-secondary { background: #334155; color: #cbd5e1; }

    /* ── Alert banners ───────────────────────────────────────────────── */
    .alert {
      display: flex;
      align-items: flex-start;
      gap: .6rem;
      padding: .65rem .9rem;
      border-radius: var(--vcf-radius);
      font-size: .875rem;
      margin-bottom: .75rem;
      border-left: 3px solid transparent;
    }
    .alert-success { background: #dff0d2; border-color: var(--vcf-success); color: #2e6200; }
    .alert-warning  { background: #fef3e0; border-color: var(--vcf-warning); color: #7a4900; }
    .alert-danger   { background: #fae1de; border-color: var(--vcf-danger);  color: #7e1700; }
    .alert-info     { background: #ddf0f7; border-color: var(--vcf-info);    color: #004a68; }
    [data-theme="dark"] .alert-success { background: #2b4a10; color: #a3d64c; }
    [data-theme="dark"] .alert-warning  { background: #4a3200; color: #e8aa3a; }
    [data-theme="dark"] .alert-danger   { background: #4a1210; color: #f88; }
    [data-theme="dark"] .alert-info     { background: #0c3550; color: #49afd9; }

    /* ── Progress bar ────────────────────────────────────────────────── */
    .progress-track {
      height: 6px;
      background: var(--vcf-border);
      border-radius: 3px;
      overflow: hidden;
      margin: .4rem 0;
    }
    .progress-bar {
      height: 100%;
      background: var(--vcf-primary);
      border-radius: 3px;
      transition: width .3s ease;
      width: 0%;
    }
    .progress-label { font-size: .78rem; color: var(--vcf-muted); }

    /* ── Host discovery list ─────────────────────────────────────────── */
    .host-list {
      max-height: 160px;
      overflow-y: auto;
      border: 1px solid var(--vcf-border);
      border-radius: var(--vcf-radius);
      background: var(--vcf-input-bg);
    }
    .host-row {
      display: flex;
      align-items: center;
      gap: .5rem;
      padding: .3rem .65rem;
      border-bottom: 1px solid var(--vcf-border);
      font-size: .8rem;
    }
    .host-row:last-child { border-bottom: none; }
    .host-row input { flex-shrink: 0; accent-color: var(--vcf-primary); }
    .host-ip { font-family: monospace; font-size: .8rem; }
    .host-port { font-size: .72rem; color: var(--vcf-muted); }
    .host-status { margin-left: auto; }

    /* ── Certificate Trust Modal & Components ─────────────────────────── */
    .vcf-modal-backdrop {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: 1rem;
    }
    .vcf-modal-dialog {
      background: var(--vcf-card);
      border: 1px solid var(--vcf-border);
      border-radius: var(--vcf-radius);
      box-shadow: 0 8px 32px rgba(0,0,0,0.45);
      width: 100%;
      max-width: 950px;
      padding: 1.25rem;
      color: var(--vcf-text);
      display: flex;
      flex-direction: column;
      max-height: 85vh;
    }
    .vcf-modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--vcf-border);
      padding-bottom: 0.75rem;
    }
    .vcf-modal-body {
      overflow-y: auto;
      padding: 1rem 0;
      flex: 1;
    }
    .vcf-modal-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-top: 1px solid var(--vcf-border);
      padding-top: 0.75rem;
      flex-wrap: wrap;
      gap: 0.5rem;
    }
    .vcf-cert-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
    }
    .vcf-cert-table th, .vcf-cert-table td {
      padding: 0.4rem 0.5rem;
      border-bottom: 1px solid var(--vcf-border);
      text-align: left;
    }
    .vcf-thumbprint-code {
      font-family: monospace;
      font-size: 0.75rem;
      letter-spacing: 0.02em;
      word-break: break-all;
      background: var(--vcf-input-bg);
      padding: 2px 4px;
      border-radius: 2px;
      border: 1px solid var(--vcf-border);
      display: inline-block;
    }

    /* ── Missing BMC Password Modal Target Box ──────────────────────── */
    .missing-pwd-hosts-box {
      max-height: 140px;
      overflow-y: auto;
      background: var(--vcf-bg-subtle);
      border: 1px solid var(--vcf-border);
      border-radius: var(--vcf-radius);
      padding: 0.5rem 0.75rem;
      font-family: "SFMono-Regular", "Consolas", "Liberation Mono", monospace;
      font-size: 0.82rem;
      line-height: 1.5;
      color: var(--vcf-text);
    }
    .missing-pwd-host-item {
      display: flex;
      align-items: center;
      gap: 0.45rem;
      padding: 0.15rem 0;
      color: var(--vcf-text);
    }
    .missing-pwd-host-bullet {
      color: var(--vcf-warning);
      font-weight: bold;
      font-size: 0.85rem;
      line-height: 1;
      user-select: none;
    }
    .missing-pwd-host-ip {
      font-family: inherit;
      color: var(--vcf-text);
      letter-spacing: 0.02em;
    }

    /* ── Active in-flight scans box ─────────────────────────────────── */
    .active-scans-box {
      background: var(--vcf-card, #f8fafc);
      border: 1px solid var(--vcf-border, #cbd5e1);
      border-radius: var(--vcf-radius, 6px);
      padding: .75rem 1rem;
      margin-top: .9rem;
      margin-bottom: .5rem;
    }
    .active-scans-header {
      display: flex;
      align-items: center;
      font-size: .85rem;
      font-weight: 600;
      margin-bottom: .5rem;
      padding-bottom: .4rem;
      border-bottom: 1px solid var(--vcf-border, #e2e8f0);
    }
    .active-scans-list {
      display: flex;
      flex-direction: column;
      gap: .5rem;
      max-height: 280px;
      overflow-y: auto;
    }
    .active-scan-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: .75rem;
      background: var(--vcf-bg, #ffffff);
      border: 1px solid var(--vcf-border, #cbd5e1);
      border-radius: 6px;
      padding: .45rem .75rem;
      font-size: .83rem;
      transition: background .15s ease, border-color .15s ease;
    }
    [data-theme="dark"] .active-scan-row {
      background: var(--vcf-input-bg, #1e293b);
    }
    .active-scan-row.slow-host {
      background: #fefce8;
      border-color: #fde047;
    }
    [data-theme="dark"] .active-scan-row.slow-host {
      background: #422006;
      border-color: #ca8a04;
    }
    .active-scan-info {
      display: flex;
      align-items: center;
      gap: .6rem;
      flex-wrap: wrap;
      min-width: 0;
    }
    .active-scan-actions {
      display: flex;
      align-items: center;
      gap: .6rem;
      flex-shrink: 0;
    }
    .active-spinner {
      display: inline-block;
      width: 14px;
      height: 14px;
      border: 2px solid var(--vcf-primary, #2563eb);
      border-top-color: transparent;
      border-radius: 50%;
      animation: spin .75s linear infinite;
      flex-shrink: 0;
    }
    .stage-pill {
      display: inline-flex;
      align-items: center;
      gap: .35rem;
      background: rgba(37, 99, 235, 0.08);
      color: var(--vcf-primary, #2563eb);
      border: 1px solid rgba(37, 99, 235, 0.2);
      padding: .15rem .55rem;
      border-radius: 12px;
      font-size: .75rem;
      font-weight: 500;
      white-space: nowrap;
    }
    [data-theme="dark"] .stage-pill {
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      border-color: rgba(96, 165, 250, 0.3);
    }
    .pulse-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background-color: var(--vcf-primary, #2563eb);
      display: inline-block;
      animation: pulse-ring 1.5s infinite ease-in-out;
    }
    @keyframes pulse-ring {
      0%, 100% { opacity: .3; transform: scale(.8); }
      50% { opacity: 1; transform: scale(1.2); }
    }
    .timer-badge {
      font-family: monospace;
      font-size: .78rem;
      font-weight: 600;
      color: var(--vcf-muted, #64748b);
      background: var(--vcf-card, #f1f5f9);
      padding: .2rem .5rem;
      border-radius: 4px;
      border: 1px solid var(--vcf-border, #cbd5e1);
      white-space: nowrap;
    }
    [data-theme="dark"] .timer-badge {
      background: rgba(255, 255, 255, 0.05);
    }
    .btn-skip {
      background: #dc2626;
      color: #ffffff;
      border: none;
      padding: .25rem .6rem;
      border-radius: 4px;
      font-size: .75rem;
      font-weight: 600;
      cursor: pointer;
      transition: background .15s ease;
    }
    .btn-skip:hover { background: #b91c1c; }
    .btn-skip:disabled { opacity: .5; cursor: not-allowed; }

    /* ── Log output ──────────────────────────────────────────────────── */
    .log-box {
      background: var(--vcf-nav);
      color: #a8c0cb;
      font-family: "SFMono-Regular", "Consolas", "Liberation Mono", monospace;
      font-size: .78rem;
      line-height: 1.5;
      padding: .75rem;
      border-radius: var(--vcf-radius);
      height: 180px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .log-box .ok    { color: #6ea005; }
    .log-box .err   { color: #f54f47; }
    .log-box .warn  { color: #e59c00; }
    .log-box .lock  { color: #49afd9; }
    .log-box .retry { color: #49afd9; font-weight: 500; }
    .log-box .info  { color: #0079b8; font-weight: 500; }

    /* ── Results table ───────────────────────────────────────────────── */
    .results-table {
      width: 100%;
      border-collapse: collapse;
      font-size: .83rem;
    }
    .results-table th, .results-table td {
      padding: .45rem .75rem;
      text-align: left;
      border-bottom: 1px solid var(--vcf-border);
    }
    .results-table th {
      font-size: .75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .05em;
      color: var(--vcf-muted);
      background: var(--vcf-bg);
    }
    .results-table a { color: var(--vcf-primary); text-decoration: none; font-weight: 600; }
    .results-table a:hover { text-decoration: underline; }

    /* ── Vault table scroll container & sticky header ────────────────── */
    .vault-table-container {
      max-height: 280px;
      overflow-y: auto;
      overflow-x: auto;
      border: 1px solid var(--vcf-border);
      border-radius: 4px;
    }
    .vault-table-container thead th {
      position: sticky;
      top: 0;
      background: var(--vcf-bg);
      z-index: 2;
      box-shadow: 0 1px 0 var(--vcf-border);
    }
    .vault-entries-toggle {
      display: flex;
      align-items: center;
      cursor: pointer;
      user-select: none;
      padding: .4rem .6rem;
      background: var(--vcf-bg-subtle, #f8f9fa);
      border: 1px solid var(--vcf-border);
      border-radius: 4px;
      font-size: .83rem;
      margin-bottom: .5rem;
    }
    .vault-entries-toggle:hover {
      background: var(--vcf-bg);
    }

    /* ── Collapsible section ─────────────────────────────────────────── */
    .collapsible { display: none; }
    .collapsible.open { display: block; }

    /* ── Separator ───────────────────────────────────────────────────── */
    .vcf-sep { border: none; border-top: 1px solid var(--vcf-border); margin: 1rem 0; }

    /* ── Loading spinner ─────────────────────────────────────────────── */
    @keyframes spin { to { transform: rotate(360deg); } }
    .spinner {
      display: inline-block;
      width: 14px; height: 14px;
      border: 2px solid var(--vcf-border);
      border-top-color: var(--vcf-primary);
      border-radius: 50%;
      animation: spin .7s linear infinite;
      vertical-align: middle;
    }

    /* ── Pulse highlight animation for anchor navigation ─────────────── */
    @keyframes pulse-highlight {
      0% {
        box-shadow: 0 0 0 0 var(--vcf-pulse-shadow, rgba(0, 114, 163, 0.7));
        border-color: var(--vcf-primary, #0072a3);
      }
      50% {
        box-shadow: 0 0 0 8px var(--vcf-pulse-shadow-fade, rgba(0, 114, 163, 0.25));
        border-color: var(--vcf-primary, #0072a3);
      }
      100% {
        box-shadow: 0 0 0 0 transparent;
      }
    }
    .pulse-highlight {
      animation: pulse-highlight 2s ease-out 2 !important;
      border-color: var(--vcf-primary, #0072a3) !important;
      outline: none !important;
    }

    /* ── Utility ─────────────────────────────────────────────────────── */
    .hidden { display: none !important; }
    .text-muted { color: var(--vcf-muted); }
    .text-sm { font-size: .78rem; }
    .text-xs { font-size: .72rem; }
    .fw-bold { font-weight: 600; }
    .mt-half { margin-top: .5rem; }
    .mb-3xs { margin-bottom: .2rem; }
    .flex { display: flex; }
    .flex-col { flex-direction: column; }
    .flex-wrap { flex-wrap: wrap; }
    .gap-xs { gap: .35rem; }
    .gap-sm { gap: .5rem; }
    .gap-md { gap: 1rem; }
    .gap-lg { gap: 1.5rem; }
    .gap-xl { gap: 2rem; }
    .items-center { align-items: center; }
    .items-start { align-items: flex-start; }
"""
