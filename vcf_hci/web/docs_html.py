"""
VCF Readiness Tool — Documentation viewer HTML builder.
Renders packed DOCS_DATA into a Clarity-styled interactive documentation portal.
"""

import json
from typing import Dict

from vcf_hci.constants import TOOL_VERSION
from vcf_hci.web.docs_css import DOCS_CSS
from vcf_hci.web.docs_js import DOCS_JS

try:
    from vcf_hci.web.docs_data import DOCS_DATA
except ImportError:
    DOCS_DATA: Dict[str, dict] = {}


def build_docs_html(initial_doc_id: str = "readme", tool_version: str = TOOL_VERSION) -> str:
    """Build a standalone, single-page documentation app with tab switching and search."""
    if not initial_doc_id or initial_doc_id not in DOCS_DATA:
        initial_doc_id = "readme"

    docs_json = json.dumps(DOCS_DATA, ensure_ascii=False).replace("</script", "<\\/script")

    return f"""<!DOCTYPE html>
<html lang="en" cds-base-font="16" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>VCF Readiness — Documentation &amp; Help</title>
  <link rel="stylesheet" href="/assets/clarity.css">
  <style>
{DOCS_CSS}  </style>
</head>
<body>

<header class="nav-header">
  <span class="nav-brand">VCF Readiness Assessment — Documentation &amp; Help</span>
  <span class="nav-version">v{tool_version}</span>
  <a href="/" class="nav-btn">← Back to Scanner</a>
  <button class="nav-btn" id="themeToggle">🌙 Dark</button>
</header>

<div class="docs-layout">

  <!-- Sidebar -->
  <aside class="docs-sidebar">
    <div class="sidebar-title">Documentation Index</div>
    <div id="sidebarList"></div>
  </aside>

  <!-- Main Content -->
  <main class="docs-main">
    <div class="docs-toolbar">
      <div class="search-input-wrap">
        <span class="search-icon">🔍</span>
        <input type="text" id="docSearch" class="docs-search" placeholder="Search in document or across all guides... (e.g. python, redfish)" autocomplete="off" spellcheck="false">
        <button type="button" id="searchClear" class="search-clear-btn" title="Clear search (Esc)">✕</button>
      </div>
      <div id="searchControls" class="search-controls">
        <span id="searchMatchCount" class="search-count">0 matches</span>
        <button type="button" id="searchPrevBtn" class="search-nav-btn" title="Previous match (Shift+Enter)">▲</button>
        <button type="button" id="searchNextBtn" class="search-nav-btn" title="Next match (Enter)">▼</button>
      </div>
    </div>

    <div id="tocBox" class="toc-box">
      <div class="toc-title">Table of Contents</div>
      <ul id="tocList" class="toc-list"></ul>
    </div>

    <article id="docContent" class="docs-content"></article>
  </main>

</div>

<script>
(function() {{
  "use strict";

  var DOCS_DATA = {docs_json};
  var currentDocId = "{initial_doc_id}";
{DOCS_JS}
}})();
</script>
</body>
</html>"""
