"""
VCF Readiness Tool — Documentation portal CSS styles.
"""

DOCS_CSS = """\
    :root {
      --vcf-bg:        #f4f6f8;
      --vcf-card:      #ffffff;
      --vcf-nav:       #1b2a32;
      --vcf-nav-text:  #e2eaf0;
      --vcf-text:      #313131;
      --vcf-muted:     #737373;
      --vcf-border:    #cccccc;
      --vcf-primary:   #0072a3;
      --vcf-primary-h: #005674;
      --vcf-radius:    3px;
      --vcf-shadow:    0 1px 3px rgba(0,0,0,.15);
      --vcf-code-bg:   #243544;
      --vcf-code-text: #e2eaf0;
    }

    [data-theme="dark"] {
      --vcf-bg:        #0f171c;
      --vcf-card:      #1b2a32;
      --vcf-nav:       #0a1218;
      --vcf-nav-text:  #c5d5de;
      --vcf-text:      #eaeff2;
      --vcf-muted:     #8a9aa5;
      --vcf-border:    #3a4e5a;
      --vcf-primary:   #49afd9;
      --vcf-primary-h: #6dcfee;
      --vcf-shadow:    0 1px 3px rgba(0,0,0,.5);
      --vcf-code-bg:   #0a1218;
      --vcf-code-text: #6dcfee;
    }

    *, *::before, *::after { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: "CDS City", "Metropolis", "Avenir Next", "Helvetica Neue", Arial, sans-serif;
      font-size: 14px;
      line-height: 1.6;
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
      text-decoration: none;
      transition: background .12s;
    }
    .nav-btn:hover { background: rgba(255,255,255,.08); }

    /* ── Documentation Layout ────────────────────────────────────────── */
    .docs-layout {
      display: grid;
      grid-template-columns: 260px 1fr;
      gap: 1.5rem;
      max-width: 1400px;
      margin: 0 auto;
      padding: 1.5rem 1.25rem 3rem;
    }

    @media (max-width: 860px) {
      .docs-layout { grid-template-columns: 1fr; }
    }

    /* ── Sidebar ─────────────────────────────────────────────────────── */
    .docs-sidebar {
      background: var(--vcf-card);
      border: 1px solid var(--vcf-border);
      border-radius: var(--vcf-radius);
      box-shadow: var(--vcf-shadow);
      padding: 1rem;
      position: sticky;
      top: 64px;
      max-height: calc(100vh - 80px);
      overflow-y: auto;
    }

    .sidebar-title {
      font-size: .75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .07em;
      color: var(--vcf-muted);
      margin-bottom: .75rem;
    }

    .doc-nav-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: .5rem;
      padding: .45rem .65rem;
      border-radius: var(--vcf-radius);
      color: var(--vcf-text);
      text-decoration: none;
      font-size: .85rem;
      font-weight: 500;
      transition: background .12s, color .12s, opacity .15s;
      cursor: pointer;
      margin-bottom: .2rem;
    }

    .doc-nav-item:hover {
      background: rgba(0,114,163,.08);
      color: var(--vcf-primary);
    }

    [data-theme="dark"] .doc-nav-item:hover {
      background: rgba(73,175,217,.12);
      color: var(--vcf-primary);
    }

    .doc-nav-item.active {
      background: var(--vcf-primary);
      color: #ffffff;
    }

    .doc-item-title {
      display: flex;
      align-items: center;
      gap: .55rem;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .doc-badge {
      display: none;
      font-size: .7rem;
      font-weight: 700;
      padding: .1rem .45rem;
      border-radius: 10px;
      background: rgba(0, 114, 163, .12);
      color: var(--vcf-primary);
      line-height: 1.2;
      flex-shrink: 0;
    }

    [data-theme="dark"] .doc-badge {
      background: rgba(73, 175, 217, .18);
      color: #6dcfee;
    }

    .doc-nav-item.active .doc-badge {
      background: rgba(255, 255, 255, .25);
      color: #ffffff;
    }

    .doc-nav-item.search-dim {
      opacity: .4;
    }

    /* ── Main content card ───────────────────────────────────────────── */
    .docs-main {
      background: var(--vcf-card);
      border: 1px solid var(--vcf-border);
      border-radius: var(--vcf-radius);
      box-shadow: var(--vcf-shadow);
      padding: 2rem;
      min-width: 0;
    }

    /* ── Search & Controls bar ───────────────────────────────────────── */
    .docs-toolbar {
      display: flex;
      gap: .75rem;
      align-items: center;
      margin-bottom: 1.5rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--vcf-border);
      flex-wrap: wrap;
    }

    .search-input-wrap {
      position: relative;
      flex: 1;
      min-width: 240px;
      display: flex;
      align-items: center;
    }

    .search-icon {
      position: absolute;
      left: .75rem;
      pointer-events: none;
      color: var(--vcf-muted);
      font-size: .85rem;
    }

    .docs-search {
      width: 100%;
      padding: .45rem 2rem .45rem 2.2rem;
      border: 1px solid var(--vcf-border);
      border-radius: var(--vcf-radius);
      background: var(--vcf-bg);
      color: var(--vcf-text);
      font-size: .875rem;
      outline: none;
      transition: border-color .15s, box-shadow .15s;
    }

    .docs-search:focus {
      border-color: var(--vcf-primary);
      box-shadow: 0 0 0 2px rgba(0, 114, 163, .2);
    }

    [data-theme="dark"] .docs-search:focus {
      box-shadow: 0 0 0 2px rgba(73, 175, 217, .25);
    }

    .search-clear-btn {
      position: absolute;
      right: .4rem;
      background: none;
      border: none;
      color: var(--vcf-muted);
      cursor: pointer;
      font-size: .9rem;
      padding: .2rem .45rem;
      border-radius: var(--vcf-radius);
      display: none;
      line-height: 1;
    }

    .search-clear-btn:hover {
      color: var(--vcf-text);
      background: rgba(128, 128, 128, .15);
    }

    .search-controls {
      display: none;
      align-items: center;
      gap: .4rem;
      font-size: .82rem;
      color: var(--vcf-muted);
      white-space: nowrap;
    }

    .search-count {
      padding: .25rem .55rem;
      background: var(--vcf-bg);
      border: 1px solid var(--vcf-border);
      border-radius: var(--vcf-radius);
      font-variant-numeric: tabular-nums;
      font-size: .78rem;
      font-weight: 600;
    }

    .search-nav-btn {
      background: var(--vcf-bg);
      border: 1px solid var(--vcf-border);
      color: var(--vcf-text);
      border-radius: var(--vcf-radius);
      padding: .25rem .55rem;
      cursor: pointer;
      font-size: .75rem;
      line-height: 1.2;
      transition: background .12s, color .12s, border-color .12s;
    }

    .search-nav-btn:hover:not(:disabled) {
      background: rgba(0, 114, 163, .12);
      color: var(--vcf-primary);
      border-color: var(--vcf-primary);
    }

    [data-theme="dark"] .search-nav-btn:hover:not(:disabled) {
      background: rgba(73, 175, 217, .18);
      color: #6dcfee;
      border-color: var(--vcf-primary);
    }

    .search-nav-btn:disabled {
      opacity: .4;
      cursor: not-allowed;
    }

    /* ── Highlighting ────────────────────────────────────────────────── */
    .docs-highlight {
      background-color: #ffe066;
      color: #111111;
      padding: .05em .2em;
      border-radius: 2px;
      box-decoration-break: clone;
      -webkit-box-decoration-break: clone;
    }

    [data-theme="dark"] .docs-highlight {
      background-color: #996d00;
      color: #ffffff;
    }

    .docs-highlight.active {
      background-color: #ff6b00 !important;
      color: #ffffff !important;
      outline: 2px solid #ffa31a;
      box-shadow: 0 0 6px rgba(255, 107, 0, .6);
      font-weight: 700;
    }

    /* ── Search No Results & Cross-document Banner ───────────────────── */
    .search-no-results {
      background: var(--vcf-bg);
      border: 1px dashed var(--vcf-border);
      border-radius: var(--vcf-radius);
      padding: 1.25rem 1.5rem;
      margin-bottom: 1.5rem;
    }

    .search-no-results-title {
      font-size: .95rem;
      font-weight: 600;
      color: var(--vcf-text);
      margin-bottom: .4rem;
    }

    .search-no-results-desc {
      font-size: .85rem;
      color: var(--vcf-muted);
      margin-bottom: .85rem;
    }

    .search-cross-links {
      display: flex;
      flex-wrap: wrap;
      gap: .5rem;
    }

    .search-cross-btn {
      background: var(--vcf-card);
      border: 1px solid var(--vcf-primary);
      color: var(--vcf-primary);
      border-radius: var(--vcf-radius);
      padding: .35rem .75rem;
      font-size: .82rem;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: .4rem;
      transition: background .12s, color .12s;
    }

    .search-cross-btn:hover {
      background: var(--vcf-primary);
      color: #ffffff;
    }

    /* ── Table of Contents ───────────────────────────────────────────── */
    .toc-box {
      background: var(--vcf-bg);
      border: 1px solid var(--vcf-border);
      border-radius: var(--vcf-radius);
      padding: 1rem 1.25rem;
      margin-bottom: 1.75rem;
    }

    .toc-title {
      font-size: .78rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .05em;
      color: var(--vcf-muted);
      margin-bottom: .5rem;
    }

    .toc-list {
      list-style: none;
      padding: 0;
      margin: 0;
      font-size: .85rem;
    }

    .toc-list li { margin-bottom: .25rem; }
    .toc-list li.toc-h2 { padding-left: 0; font-weight: 600; }
    .toc-list li.toc-h3 { padding-left: 1rem; color: var(--vcf-muted); }
    .toc-list a { color: var(--vcf-primary); text-decoration: none; }
    .toc-list a:visited { color: var(--vcf-primary); }
    .toc-list a:hover { text-decoration: underline; color: var(--vcf-primary-h); }

    /* ── Rendered Markdown Styling ───────────────────────────────────── */
    .docs-content {
      font-size: .92rem;
      line-height: 1.65;
    }

    .docs-content h1 { font-size: 1.75rem; border-bottom: 2px solid var(--vcf-border); padding-bottom: .4rem; margin-top: 0; }
    .docs-content h2 { font-size: 1.35rem; border-bottom: 1px solid var(--vcf-border); padding-bottom: .3rem; margin-top: 1.75rem; }
    .docs-content h3 { font-size: 1.1rem; margin-top: 1.25rem; }
    .docs-content h4 { font-size: .95rem; margin-top: 1rem; }

    .docs-content a { color: var(--vcf-primary); text-decoration: none; font-weight: 500; }
    .docs-content a:visited { color: var(--vcf-primary); }
    .docs-content a:hover { text-decoration: underline; color: var(--vcf-primary-h); }
    .docs-content a code { color: inherit; text-decoration: inherit; }

    .docs-content pre {
      background: var(--vcf-code-bg);
      color: var(--vcf-code-text);
      padding: 1rem;
      border-radius: var(--vcf-radius);
      overflow-x: auto;
      font-family: "SFMono-Regular", "Consolas", "Liberation Mono", monospace;
      font-size: .83rem;
      line-height: 1.45;
    }

    .docs-content code {
      background: rgba(0,114,163,.1);
      color: var(--vcf-primary);
      padding: .15rem .35rem;
      border-radius: 3px;
      font-family: "SFMono-Regular", "Consolas", "Liberation Mono", monospace;
      font-size: .85em;
    }

    [data-theme="dark"] .docs-content code {
      background: rgba(73,175,217,.15);
      color: #6dcfee;
    }

    .docs-content pre code {
      background: none;
      color: inherit;
      padding: 0;
    }

    .docs-content blockquote {
      border-left: 4px solid var(--vcf-primary);
      margin: 1rem 0;
      padding: .5rem 1rem;
      background: var(--vcf-bg);
      color: var(--vcf-muted);
    }

    .docs-table-wrap { overflow-x: auto; margin: 1rem 0; }
    .docs-table {
      width: 100%;
      border-collapse: collapse;
      font-size: .85rem;
    }
    .docs-table th, .docs-table td {
      padding: .5rem .75rem;
      border: 1px solid var(--vcf-border);
      text-align: left;
    }
    .docs-table th {
      background: var(--vcf-bg);
      font-weight: 700;
    }

    .docs-img { max-width: 100%; height: auto; border-radius: var(--vcf-radius); }
"""
