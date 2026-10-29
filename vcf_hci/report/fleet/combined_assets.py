"""Static combined shell CSS/browser blocks and explicit offline composition."""
from vcf_hci.branding import FAVICON_DATA_URI
from vcf_hci.constants import TOOL_VERSION
from vcf_hci.report.presentation import REPORT_UI_CSS, REPORT_UI_JS
from vcf_hci.report.styles import HOST_REPORT_CSS

COMBINED_SHELL_CSS = r"""
    html,body{margin:0;padding:0}
    .tab-bar{display:flex;background:#0f172a;padding:0 1rem;gap:4px;position:sticky;top:0;z-index:100;
              box-shadow:0 2px 8px rgba(0,0,0,.4);overflow-x:auto;align-items:center}
    [data-theme='light'] .tab-bar{background:#f1f5f9;box-shadow:0 2px 8px rgba(0,0,0,.1);border-bottom:1px solid #cbd5e1}

    .host-picker-bar{display:flex;align-items:center;margin-left:auto;gap:8px;padding:4px 0}
    [data-theme='light'] #host-picker-search, [data-theme='light'] #host-picker-select{
      background:#ffffff;color:#0f172a;border-color:#cbd5e1;
    }

    .tab-btn{padding:.75rem 1.15rem;cursor:pointer;color:var(--text-muted);background:none;border:none;
              border-bottom:3px solid transparent;font-size:.84rem;font-weight:600;white-space:nowrap;
              border-radius:4px 4px 0 0;
              transition:color .12s,border-color .12s,background .12s}
    [data-theme='light'] .tab-btn{color:var(--text-muted)}
    .tab-btn:hover{color:#e2e8f0;background:#1e293b}
    [data-theme='light'] .tab-btn:hover{color:#0f172a;background:#e2e8f0}
    .tab-btn.active{color:#f1f5f9;border-bottom-color:#3b82f6;background:#1e293b}
    [data-theme='light'] .tab-btn.active{color:#0f172a;border-bottom-color:#2563eb;background:#ffffff}

    .docs-embedded-content h1{font-size:1.6rem;border-bottom:2px solid var(--border,#334155);padding-bottom:.4rem;margin-top:0}
    .docs-embedded-content h2{font-size:1.3rem;border-bottom:1px solid var(--border,#334155);padding-bottom:.3rem;margin-top:1.5rem}
    .docs-embedded-content h3{font-size:1.05rem;margin-top:1.2rem}
    .docs-embedded-content h4{font-size:0.95rem;margin-top:1rem}
    .docs-embedded-content a{color:var(--primary,#60a5fa);text-decoration:none;font-weight:500}
    .docs-embedded-content a:visited{color:var(--primary,#60a5fa)}
    .docs-embedded-content a:hover{text-decoration:underline;color:#93c5fd}
    .docs-embedded-content a code{color:inherit;text-decoration:inherit}
    .docs-embedded-content pre{background:var(--code-bg,#0f172a);padding:1rem;border-radius:6px;overflow-x:auto}
    .docs-embedded-content code{background:var(--code-bg,#0f172a);padding:.2rem .4rem;border-radius:4px;font-family:monospace}
    .docs-embedded-content pre code{padding:0;background:none}
    .docs-embedded-content table{width:100%;border-collapse:collapse;margin:1rem 0}
    .docs-embedded-content th, .docs-embedded-content td{border:1px solid var(--border,#334155);padding:.5rem .75rem;text-align:left}
    .docs-embedded-content th{background:var(--th-bg,#1e293b)}
    .docs-embedded-content blockquote{border-left:4px solid var(--primary,#60a5fa);margin:1rem 0;padding:.5rem 1rem;background:var(--card,#1e293b)}
    .docs-embedded-content ul, .docs-embedded-content ol{padding-left:1.5rem;margin:.5rem 0 1rem}
    .docs-embedded-content li{margin-bottom:.25rem}
    .docs-embedded-content hr{border:none;border-top:1px solid var(--border,#334155);margin:1.5rem 0}

    [data-theme='light'] .docs-embedded-content a{color:#2563eb}
    [data-theme='light'] .docs-embedded-content a:visited{color:#2563eb}
    [data-theme='light'] .docs-embedded-content a:hover{color:#1d4ed8}
    [data-theme='light'] .docs-embedded-content pre{background:#f8fafc;border:1px solid #e2e8f0}
    [data-theme='light'] .docs-embedded-content code{background:#f1f5f9;color:#0f172a}
    [data-theme='light'] .docs-embedded-content th{background:#f8fafc}
    [data-theme='light'] .docs-embedded-content th, [data-theme='light'] .docs-embedded-content td{border-color:#e2e8f0}
    [data-theme='light'] .docs-embedded-content h1, [data-theme='light'] .docs-embedded-content h2{border-bottom-color:#e2e8f0}
    [data-theme='light'] .docs-embedded-content blockquote{background:#f8fafc;border-left-color:#2563eb}
    [data-theme='light'] .docs-embedded-content hr{border-top-color:#e2e8f0}
    .docs-embedded-content h1, .docs-embedded-content h2, .docs-embedded-content h3, .docs-embedded-content h4{scroll-margin-top:4.5rem}

    .tab-content{display:none}.tab-content.active{display:block}
    body{padding:0}.container{padding-top:1.5rem}
    .sort-ind{margin-left:.3rem;opacity:.35;font-size:.7rem;vertical-align:middle}
    th.sorted .sort-ind{opacity:1}
    th{cursor:pointer;user-select:none;position:relative}
    .col-resizer{position:absolute;top:0;right:0;width:5px;cursor:col-resize;user-select:none;height:100%;z-index:10}
    .col-resizer:hover,.col-resizer.resizing{background:var(--primary,#3b82f6);opacity:0.8}

    .host-report-toolbar{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:4px 12px;background:var(--th-bg);padding:4px 16px;border-bottom:1px solid var(--border)}
    .host-report-toolbar .view-mode-btn{padding:3px 8px;font-size:.8rem}
    /* Segmented Slider Toggle */
    .view-mode-toggle{display:inline-flex;background:var(--code-bg,#0f172a);border:1px solid var(--border,#334155);border-radius:8px;padding:3px;gap:2px;user-select:none}
    .view-mode-btn{padding:.38rem .85rem;font-size:.82rem;font-weight:600;border:1px solid transparent;border-radius:6px;background:transparent;color:var(--text-muted,#94a3b8);cursor:pointer;display:inline-flex;align-items:center;gap:.4rem;transition:all .15s ease}
    .view-mode-btn:hover{color:var(--text,#f8fafc);background:rgba(255,255,255,0.05)}
    .view-mode-btn.active{background:var(--primary,#3b82f6);color:var(--on-primary,#fff);border-color:var(--primary);box-shadow:0 1px 3px rgba(0,0,0,0.25)}
    [data-theme='light'] .view-mode-toggle{background:#e2e8f0;border-color:#cbd5e1}
    [data-theme='light'] .view-mode-btn{color:var(--text-muted)}
    [data-theme='light'] .view-mode-btn:hover{color:#0f172a;background:rgba(0,0,0,0.04)}
    [data-theme='light'] .view-mode-btn.active{background:var(--primary);color:var(--on-primary,#fff)}

    /* Outlined Sub-Report Button */
    .btn-subreport-outline{padding:.42rem .95rem;font-size:.82rem;font-weight:700;border:2px solid var(--primary,#3b82f6);background:rgba(59,130,246,0.12);color:var(--primary,#60a5fa);border-radius:6px;cursor:pointer;display:inline-flex;align-items:center;gap:.4rem;transition:all .15s ease}
    .btn-subreport-outline:hover{background:rgba(59,130,246,0.28);color:#ffffff;box-shadow:0 0 8px rgba(59,130,246,0.35)}
    [data-theme='light'] .btn-subreport-outline{border-color:#2563eb;background:#eff6ff;color:#1d4ed8}
    [data-theme='light'] .btn-subreport-outline:hover{background:#dbeafe;color:#1e40af}

    /* Interactive Spec Cards in Simplified View */
    .host-spec-card-clickable{cursor:pointer;position:relative;transition:transform .12s ease,border-color .15s ease,box-shadow .15s ease}
    .host-spec-card-clickable:hover{transform:translateY(-2px);border-color:var(--primary,#3b82f6);box-shadow:0 4px 12px rgba(59,130,246,0.2)}
    .host-spec-card-clickable .jump-arrow{position:absolute;top:0.6rem;right:0.75rem;font-size:0.85rem;opacity:1;color:var(--text-muted);transition:opacity .15s ease,transform .15s ease}
    .host-spec-card-clickable:hover .jump-arrow{opacity:1;transform:translate(2px,-2px);color:var(--primary,#60a5fa)}
"""


COMBINED_NAV_JS = r"""
var _lruFrames = [];
var _subreportsState = 'unknown';
var _fallbackTimer = null;

window.addEventListener('message', function(ev) {
  var ownedFrame = Array.from(document.querySelectorAll('.tab-content iframe')).find(function(frame){return frame.contentWindow === ev.source;});
  if (!ownedFrame) return;
  if (ev.data && ev.data.type === 'vcf-report-height') {
    var height = ev.data.height;
    if (typeof height === 'number' && Number.isFinite(height) && height > 0 && height <= 2000000) {
      ownedFrame.style.height = Math.ceil(height) + 'px';
    }
    return;
  }
  if (ev.data && ev.data.type === 'vcf-subreport-ready') {
    _subreportsState = 'available';
    if (_fallbackTimer) {
      clearTimeout(_fallbackTimer);
      _fallbackTimer = null;
    }
  }
});

function _esc(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function syncIframeTheme(targetIframe) {
  try {
    var th = document.documentElement.getAttribute('data-theme') || 'dark';
    var ifr = targetIframe || document.querySelector('.tab-content.active iframe');
    if(ifr && ifr.contentWindow)ifr.contentWindow.postMessage({type:'vcf-report-theme',theme:th},'*');
    if (ifr && ifr.contentDocument && ifr.contentDocument.documentElement) {
      ifr.contentDocument.documentElement.setAttribute('data-theme', th);
      var ibtn = ifr.contentDocument.getElementById('themeToggle');
      if (ibtn && ibtn.getAttribute('role')!=='switch') ibtn.textContent = th === 'dark' ? '🌙 Dark' : '☀️ Light';
    }
  } catch(e) {}
}

function sendSubTabActivation(iframe, subTab, attempt) {
  if (!iframe || !subTab) return;
  attempt = attempt || 0;
  var done = false;
  try {
    if (iframe.contentWindow) {
      iframe.contentWindow.postMessage({ type: 'vcf_activate_tab', tab: subTab }, '*');
    }
    var iwin = iframe.contentWindow;
    var idoc = iframe.contentDocument || (iwin && iwin.document);
    if (iwin && typeof iwin.activateTab === 'function') {
      done = iwin.activateTab(subTab, true);
    } else if (idoc) {
      var btn = idoc.querySelector('.tab-nav [data-tab="' + subTab + '"]') || idoc.querySelector('[data-tab="' + subTab + '"]');
      if (btn) {
        btn.click();
        var inav = idoc.querySelector('.tab-nav');
        if (inav) {
          setTimeout(function(){
            try { inav.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch(ex) { inav.scrollIntoView(true); }
          }, 40);
        }
        done = true;
      }
    }
  } catch(e) {}
  if (!done && attempt < 25) {
    setTimeout(function(){ sendSubTabActivation(iframe, subTab, attempt + 1); }, 40);
  }
}

function attachIframeSync(iframe, n, subTab) {
  syncIframeTheme(iframe);
  iframe.addEventListener('load', function(){
    syncIframeTheme();
    syncIframeTheme(iframe);
    try {
      if (iframe.contentDocument && iframe.contentDocument.title && !iframe.contentDocument.title.includes('404')) {
        _subreportsState = 'available';
        if (_fallbackTimer) {
          clearTimeout(_fallbackTimer);
          _fallbackTimer = null;
        }
      }
    } catch(e) {}
    if (subTab) {
      sendSubTabActivation(iframe, subTab);
    }
  });
}

var _preferredViewMode = 'advanced';

function setHostViewMode(n, mode, subTab) {
  var card = document.getElementById('card-tab-' + n);
  var wrap = document.getElementById('iframe-wrap-tab-' + n);
  var pane = document.getElementById('tab-' + n);
  if (!card || !wrap || !pane) return;

  if (!subTab) {
    _preferredViewMode = mode;
  }

  var btnSimple = document.getElementById('btn-mode-simple-' + n);
  var btnAdv = document.getElementById('btn-mode-advanced-' + n);
  var btnSimpleIfr = document.getElementById('btn-mode-simple-ifr-' + n);
  var btnAdvIfr = document.getElementById('btn-mode-advanced-ifr-' + n);

  if (mode === 'simplified') {
    wrap.style.display = 'none';
    card.style.display = 'block';
    if (btnSimple) btnSimple.classList.add('active');
    if (btnAdv) btnAdv.classList.remove('active');
    if (btnSimpleIfr) btnSimpleIfr.classList.add('active');
    if (btnAdvIfr) btnAdvIfr.classList.remove('active');

    if (subTab) {
      var targetSecId = null;
      if (subTab === 'tab-storage') targetSecId = 'host-drives-sec-' + n;
      else if (subTab === 'tab-network' || subTab === 'tab-hba') targetSecId = 'host-nics-sec-' + n;
      else if (subTab === 'tab-health') targetSecId = 'host-health-sec-' + n;
      else if (subTab === 'tab-cpu' || subTab === 'tab-security') targetSecId = 'host-specs-grid-' + n;
      if (targetSecId) {
        var el = document.getElementById(targetSecId);
        if (el) {
          setTimeout(function(){
            try { el.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
            catch(ex) { el.scrollIntoView(true); }
          }, 50);
        }
      }
    }
  } else {
    card.style.display = 'none';
    wrap.style.display = 'block';
    if (btnSimple) btnSimple.classList.remove('active');
    if (btnAdv) btnAdv.classList.add('active');
    if (btnSimpleIfr) btnSimpleIfr.classList.remove('active');
    if (btnAdvIfr) btnAdvIfr.classList.add('active');

    var mount = document.getElementById('iframe-mount-' + n);
    var iframe = mount ? mount.querySelector('iframe') : null;
    if (!iframe && pane.hasAttribute('data-src')) {
      iframe = document.createElement('iframe');
      iframe.style.width = '100%';
      iframe.style.height = 'calc(100vh - 100px)';
      iframe.style.border = 'none';
      iframe.title = 'Host Report ' + (n - 2);
      iframe.src = pane.getAttribute('data-src');
      var srcLbl = document.getElementById('iframe-src-label-' + n);
      if (srcLbl) srcLbl.textContent = pane.getAttribute('data-src');
      mount.appendChild(iframe);
      attachIframeSync(iframe, n, subTab);

      _lruFrames = _lruFrames.filter(function(x){ return x !== n; });
      _lruFrames.push(n);
      while (_lruFrames.length > 3) {
        var oldN = _lruFrames.shift();
        var oldMount = document.getElementById('iframe-mount-' + oldN);
        if (oldMount) { oldMount.innerHTML = ''; }
        var oldCard = document.getElementById('card-tab-' + oldN);
        var oldWrap = document.getElementById('iframe-wrap-tab-' + oldN);
        if (oldCard && oldWrap) {
          oldWrap.style.display = 'none';
          oldCard.style.display = 'block';
          var oldSimple = document.getElementById('btn-mode-simple-' + oldN);
          var oldAdv = document.getElementById('btn-mode-advanced-' + oldN);
          if (oldSimple) oldSimple.classList.add('active');
          if (oldAdv) oldAdv.classList.remove('active');
        }
      }
    } else if (iframe) {
      if (!iframe.srcdoc && iframe.hasAttribute('data-srcdoc')) {
        iframe.srcdoc = iframe.getAttribute('data-srcdoc');
        iframe.removeAttribute('data-srcdoc');
        attachIframeSync(iframe, n, subTab);
      }
      if (subTab) {
        sendSubTabActivation(iframe, subTab);
      }
    }
  }
}

function toggleHostSubreport(n, subTab) {
  var wrap = document.getElementById('iframe-wrap-tab-' + n);
  var isShowingIframe = (wrap && wrap.style.display !== 'none');
  setHostViewMode(n, isShowingIframe ? 'simplified' : 'advanced', subTab);
}

function handleSpecCardClick(n, targetSubTab, fallbackSecId) {
  if (_subreportsState === 'unavailable') {
    var sec = document.getElementById(fallbackSecId);
    if (sec) {
      setTimeout(function(){
        try { sec.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
        catch(ex) { sec.scrollIntoView(true); }
      }, 50);
    }
  } else {
    setHostViewMode(n, 'advanced', targetSubTab);
  }
}

function renderEmbeddedHostCard(n, pane) {
  if (document.getElementById('card-tab-' + n)) return true;

  var hostIdx = n - 3;
  var invScript = document.getElementById('fleet-inv-data');
  if (!invScript) return false;
  var invData;
  try {
    invData = JSON.parse(invScript.textContent);
  } catch(e) {
    return false;
  }
  if (!invData || !invData.hosts || !invData.hosts[hostIdx]) return false;

  var h = invData.hosts[hostIdx];
  var hostDrives = (invData.drives || []).filter(function(d){ return d.host_idx === hostIdx; });
  var hostNics = (invData.nics || []).filter(function(ni){ return ni.host_idx === hostIdx; });
  var hostHealth = (invData.health || []).filter(function(hl){ return hl.host_idx === hostIdx; });

  var container = document.createElement('div');
  container.className = 'host-embedded-card';
  container.id = 'card-tab-' + n;
  container.style.padding = '0 1rem 2rem';

  var targetSrc = pane.getAttribute('data-src') || (pane.querySelector('iframe') ? (pane.querySelector('iframe').getAttribute('src') || '') : '') || ('reports/OBFUSCATED_Host-' + (hostIdx + 1) + '.html');

  // Header & Controls
  var headerHtml = '<div style="display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid var(--border,#334155);padding:1rem 0;margin-bottom:1.5rem;flex-wrap:wrap;gap:1rem">' +
    '<div>' +
      '<div style="display:flex;align-items:center;gap:.6rem;flex-wrap:wrap">' +
        '<h1 style="margin:0;font-size:1.6rem;color:var(--h-color,#f8fafc)">🖥️ <span>' + _esc(h.hostname || ('Host ' + (hostIdx + 1))) + '</span></h1>' +
        '<span class="badge info" style="font-size:.85rem">' + _esc((h.vendor ? h.vendor + ' ' : '') + (h.model || '')) + '</span>' +
        (h.ip ? '<span class="badge" style="font-size:.85rem;background:var(--code-bg,#263548);border:1px solid var(--border,#334155)">' + _esc(h.ip) + '</span>' : '') +
      '</div>' +
      '<div style="color:var(--text-muted,#94a3b8);font-size:.85rem;margin-top:.4rem">' +
        'Sub-report target: <code>' + _esc(targetSrc) + '</code>' +
      '</div>' +
    '</div>' +
    '<div style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap">' +
      '<div class="view-mode-toggle" id="view-mode-toggle-' + n + '">' +
        '<button type="button" class="view-mode-btn active" id="btn-mode-simple-' + n + '" data-action="set-view-mode" data-host-idx="' + n + '" data-mode="simplified">' +
          '📄 Summary view' +
        '</button>' +
        '<button type="button" class="view-mode-btn" id="btn-mode-advanced-' + n + '" data-action="set-view-mode" data-host-idx="' + n + '" data-mode="advanced">' +
          '🔬 Detailed view' +
        '</button>' +
      '</div>' +
    '</div>' +
  '</div>';

  // Offline Notice Banner
  var bannerHtml = '<div class="alert alert-info" id="host-banner-' + n + '" style="margin-bottom:1.5rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem">' +
    '<div>ℹ️ <strong>Simplified Host View:</strong> Consolidated Host Specifications from fleet scan data.</div>' +
    '<button type="button" class="btn-subreport-outline" id="btn-toggle-subreport-' + n + '" data-action="set-view-mode" data-host-idx="' + n + '" data-mode="advanced">' +
      '🔬 Switch to Advanced Report View' +
    '</button>' +
  '</div>';

  // Overview Cards Grid
  var secBadge = h.sec_badge || (h.tpm_ok ? '<span class="badge success">TPM 2.0 OK</span>' : '<span class="badge danger">TPM Action Req</span>');
  var gridHtml = '<div class="grid" id="host-specs-grid-' + n + '" style="margin-bottom:1.5rem">' +
    '<div class="card host-spec-card-clickable" data-action="spec-card-click" data-host-idx="' + n + '" data-subtab="tab-cpu" data-target-sec="host-specs-grid-' + n + '" title="Click to view CPU details in Advanced Report">' +
      '<span class="jump-arrow">↗</span>' +
      '<div style="font-size:.78rem;font-weight:700;color:var(--text-muted,#94a3b8);text-transform:uppercase;letter-spacing:.03em">CPU Compatibility</div>' +
      '<div style="font-size:1.15rem;font-weight:700;margin:.35rem 0 .2rem;color:var(--h-color,#f8fafc)">' + (h.cpu_verdict ? h.cpu_verdict : 'N/A') + '</div>' +
      '<div style="font-size:.85rem;color:var(--text-muted,#94a3b8)">' + _esc(h.cpu_model || 'Unknown CPU') + '</div>' +
    '</div>' +
    '<div class="card host-spec-card-clickable" data-action="spec-card-click" data-host-idx="' + n + '" data-subtab="tab-memory" data-target-sec="host-specs-grid-' + n + '" title="Click to view Memory details in Advanced Report">' +
      '<span class="jump-arrow">↗</span>' +
      '<div style="font-size:.78rem;font-weight:700;color:var(--text-muted,#94a3b8);text-transform:uppercase;letter-spacing:.03em">Memory &amp; Population</div>' +
      '<div style="font-size:1.15rem;font-weight:700;margin:.35rem 0 .2rem;color:var(--h-color,#f8fafc)">' + (h.ram_gb || 0) + ' GB <span style="font-size:.85rem;font-weight:500;color:var(--text-muted,#94a3b8)">(' + (h.dimm_count || 0) + ' DIMMs)</span></div>' +
      '<div style="font-size:.85rem;color:var(--text-muted,#94a3b8)">Interleaving: <strong>' + _esc(h.interleaving_str || 'N/A') + '</strong></div>' +
    '</div>' +
    '<div class="card host-spec-card-clickable" data-action="spec-card-click" data-host-idx="' + n + '" data-subtab="tab-storage" data-target-sec="host-drives-sec-' + n + '" title="Click to view Storage &amp; vSAN details in Advanced Report">' +
      '<span class="jump-arrow">↗</span>' +
      '<div style="font-size:.78rem;font-weight:700;color:var(--text-muted,#94a3b8);text-transform:uppercase;letter-spacing:.03em">vSAN ESA / OSA Readiness</div>' +
      '<div style="font-size:1.15rem;font-weight:700;margin:.35rem 0 .2rem;color:var(--h-color,#f8fafc)">' + _esc(h.esa_tier || 'N/A') + '</div>' +
      '<div style="font-size:.85rem;color:var(--text-muted,#94a3b8)">' + _esc(h.esa_profile || '') + (h.esa_display ? ' · ' + _esc(h.esa_display) : '') + '</div>' +
    '</div>' +
    '<div class="card host-spec-card-clickable" data-action="spec-card-click" data-host-idx="' + n + '" data-subtab="tab-network" data-target-sec="host-nics-sec-' + n + '" title="Click to view Network details in Advanced Report">' +
      '<span class="jump-arrow">↗</span>' +
      '<div style="font-size:.78rem;font-weight:700;color:var(--text-muted,#94a3b8);text-transform:uppercase;letter-spacing:.03em">Network Connectivity</div>' +
      '<div style="font-size:1.15rem;font-weight:700;margin:.35rem 0 .2rem;color:var(--h-color,#f8fafc)">' + (h.nic_max_gbps || 0) + ' Gbps Max</div>' +
      '<div style="font-size:.85rem;color:var(--text-muted,#94a3b8)">' + _esc(h.nic_display || 'No NICs recorded') + '</div>' +
    '</div>' +
    '<div class="card host-spec-card-clickable" data-action="spec-card-click" data-host-idx="' + n + '" data-subtab="tab-security" data-target-sec="host-health-sec-' + n + '" title="Click to view Security &amp; TPM details in Advanced Report">' +
      '<span class="jump-arrow">↗</span>' +
      '<div style="font-size:.78rem;font-weight:700;color:var(--text-muted,#94a3b8);text-transform:uppercase;letter-spacing:.03em">Security Baseline &amp; TPM</div>' +
      '<div style="margin:.35rem 0 .2rem">' + secBadge + '</div>' +
      '<div style="font-size:.85rem;color:var(--text-muted,#94a3b8)">TPM 2.0: ' + (h.tpm_ok ? '🟢 Enabled' : '🔴 Missing/Disabled') + ' · VMD: ' + (h.vmd_on ? '⚠️ Enabled' : '🟢 Disabled') + '</div>' +
    '</div>' +
  '</div>';

  // Storage Drives Section
  var drivesHtml = '<h2 id="host-drives-sec-' + n + '" style="margin:1.8rem 0 .75rem;font-size:1.15rem;color:var(--h-color,#f8fafc)">💾 Storage Subsystem (' + hostDrives.length + ' Drives)</h2>';
  if (hostDrives.length > 0) {
    drivesHtml += '<div style="overflow-x:auto;margin-bottom:1.5rem"><table><thead><tr>' +
      '<th>Drive / Controller</th><th>Model</th><th>Type</th><th>Protocol</th><th>Capacity</th><th>Firmware</th><th>Endurance</th><th>vSAN Category</th><th>Status</th>' +
    '</tr></thead><tbody>';
    hostDrives.forEach(function(d){
      var capStr = d.capacity_data_quality_note ? 'Unknown' : (d.capacity_gb ? (d.capacity_gb >= 1000 ? (d.capacity_gb / 1000).toFixed(1) + ' TB' : Number(d.capacity_gb).toFixed(0) + ' GB') : 'N/A');
      var endStr = (d.endurance_pct !== null && d.endurance_pct !== undefined) ? d.endurance_pct + '%' : 'N/A';
      var statusBadge = (d.drive_health === 'OK' || d.drive_health === 'Good') ? '<span class="badge success">OK</span>' : '<span class="badge warning">' + _esc(d.drive_health || 'Unknown') + '</span>';
      drivesHtml += '<tr>' +
        '<td><strong>' + _esc(d.ctrl_name || 'Direct / Unknown') + '</strong></td>' +
        '<td>' + _esc(d.model || 'Unknown Model') + '</td>' +
        '<td>' + _esc(d.media_type_display || d.media_type || 'Not reported') + '</td>' +
        '<td>' + _esc(d.protocol_display || d.protocol || 'Not reported') + '</td>' +
        '<td>' + capStr + '</td>' +
        '<td><code>' + _esc(d.firmware || 'N/A') + '</code></td>' +
        '<td>' + endStr + '</td>' +
        '<td>' + _esc(d.category || 'N/A') + '</td>' +
        '<td>' + statusBadge + '</td>' +
      '</tr>';
    });
    drivesHtml += '</tbody></table></div>';
  } else {
    drivesHtml += '<p style="color:var(--text-muted,#94a3b8);margin-bottom:1.5rem">No storage drives recorded for this host.</p>';
  }

  // Network Interfaces Section
  var nicsHtml = '<h2 id="host-nics-sec-' + n + '" style="margin:1.8rem 0 .75rem;font-size:1.15rem;color:var(--h-color,#f8fafc)">🌐 Network Interfaces (' + hostNics.length + ' Ports)</h2>';
  if (hostNics.length > 0) {
    nicsHtml += '<div style="overflow-x:auto;margin-bottom:1.5rem"><table><thead><tr>' +
      '<th>Adapter</th><th>Port ID</th><th>Speed</th><th>Link Status</th><th>MAC Address</th><th>Firmware</th><th>ESA ≥25G</th>' +
    '</tr></thead><tbody>';
    hostNics.forEach(function(ni){
      var speedStr = ni.speed_gbps ? ni.speed_gbps + ' Gbps' : 'N/A';
      var linkBadge = (ni.link_status === 'Up' || ni.link_status === 'LinkUp') ? '<span class="badge success">Up</span>' : '<span class="badge" style="background:var(--code-bg);color:var(--text-muted)">' + _esc(ni.link_status || 'Down') + '</span>';
      var esaBadge = ni.meets_25g ? '<span class="badge success">🟢 Yes</span>' : '<span class="badge warning">🟡 &lt;25G</span>';
      nicsHtml += '<tr>' +
        '<td><strong>' + _esc(ni.adapter || 'Integrated NIC') + '</strong></td>' +
        '<td>' + _esc(ni.port_id || 'Port') + '</td>' +
        '<td>' + speedStr + '</td>' +
        '<td>' + linkBadge + '</td>' +
        '<td><code>' + _esc(ni.mac_address || '02:00:00:00:00:00') + '</code></td>' +
        '<td><code>' + _esc(ni.firmware || 'N/A') + '</code></td>' +
        '<td>' + esaBadge + '</td>' +
      '</tr>';
    });
    nicsHtml += '</tbody></table></div>';
  } else {
    nicsHtml += '<p style="color:var(--text-muted,#94a3b8);margin-bottom:1.5rem">No network interfaces recorded for this host.</p>';
  }

  // Health Alarms Section
  var healthHtml = '<h2 id="host-health-sec-' + n + '" style="margin:1.8rem 0 .75rem;font-size:1.15rem;color:var(--h-color,#f8fafc)">⚠️ Health Alarms &amp; Event Logs (' + hostHealth.length + ' Items)</h2>';
  if (hostHealth.length > 0) {
    healthHtml += '<div style="overflow-x:auto;margin-bottom:1.5rem"><table><thead><tr>' +
      '<th>Severity</th><th>Subsystem</th><th>Message</th><th>Target</th><th>Timestamp</th>' +
    '</tr></thead><tbody>';
    hostHealth.forEach(function(hl){
      var sev = String(hl.severity || 'Warning');
      var sevBadge = '<span class="badge ' + (sev === 'Critical' ? 'danger' : (sev === 'Warning' ? 'warning' : 'info')) + '">' + _esc(sev) + '</span>';
      healthHtml += '<tr>' +
        '<td>' + sevBadge + '</td>' +
        '<td><strong>' + _esc(hl.subsystem || 'System') + '</strong></td>' +
        '<td>' + _esc(hl.message || '') + '</td>' +
        '<td><code>' + _esc(hl.target || 'System') + '</code></td>' +
        '<td style="font-size:.82rem;color:var(--text-muted,#94a3b8);white-space:nowrap">' + _esc(hl.timestamp || 'N/A') + '</td>' +
      '</tr>';
    });
    healthHtml += '</tbody></table></div>';
  } else {
    healthHtml += '<div class="alert alert-success" style="margin-top:1rem">🟢 No active health alarms or critical SEL events recorded for this host.</div>';
  }

  container.innerHTML = headerHtml + bannerHtml + gridHtml + drivesHtml + nicsHtml + healthHtml;

  var iframeWrapper = document.createElement('div');
  iframeWrapper.className = 'host-iframe-wrapper';
  iframeWrapper.id = 'iframe-wrap-tab-' + n;
  iframeWrapper.style.display = 'none';
  iframeWrapper.innerHTML = '<div class="host-report-toolbar">' +
    '<div style="display:flex;align-items:center;gap:.75rem;flex-wrap:wrap">' +
      '      <div class="view-mode-toggle" id="view-mode-toggle-iframe-' + n + '">' +
        '<button type="button" class="view-mode-btn" id="btn-mode-simple-ifr-' + n + '" data-action="set-view-mode" data-host-idx="' + n + '" data-mode="simplified">' +
          '📄 Simplified Host View' +
        '</button>' +
        '<button type="button" class="view-mode-btn active" id="btn-mode-advanced-ifr-' + n + '" data-action="set-view-mode" data-host-idx="' + n + '" data-mode="advanced">' +
          '🔬 Advanced Report View' +
        '</button>' +
      '</div>' +
      '<span hidden><code id="iframe-src-label-' + n + '">' + _esc(targetSrc) + '</code></span>' +
    '</div>' +
    '<div style="display:flex;align-items:center;gap:.5rem">' +
      '<button type="button" class="inv-btn" data-action="open-tab-src" data-src="' + _esc(targetSrc) + '" style="padding:.3rem .75rem;font-size:.8rem" title="Open full sub-report in separate browser tab">' +
        '↗ Open in New Tab' +
      '</button>' +
    '</div>' +
  '</div>' +
  '<div id="iframe-mount-' + n + '"></div>';

  var existingIframe = pane.querySelector('iframe');
  if (existingIframe) {
    existingIframe.style.height = 'calc(100vh - 100px)';
    var mount = iframeWrapper.querySelector('#iframe-mount-' + n);
    if (mount) {
      mount.appendChild(existingIframe);
    }
  }

  pane.appendChild(container);
  pane.appendChild(iframeWrapper);
  return true;
}

function showTab(n, subTab){
  document.querySelectorAll('.tab-content').forEach(function(el){
    el.classList.toggle('active', el.id === 'tab-' + n);
    el.hidden = el.id !== 'tab-' + n;
  });
  var activeBtn = null;
  document.querySelectorAll('.tab-btn').forEach(function(el, i){
    var isActive = (i === n);
    el.classList.toggle('active', isActive);
    if (isActive) activeBtn = el;
  });

  var hostSelect = document.getElementById('host-picker-select');
  var activeHostBtn = document.getElementById('active-host-btn');
  if (hostSelect) {
    if (n >= 3) {
      hostSelect.value = String(n);
      if (activeHostBtn) {
        var selOpt = hostSelect.options[hostSelect.selectedIndex];
        activeHostBtn.dataset.tabTarget = 'tab-' + n;
        activeHostBtn.setAttribute('aria-controls', 'tab-' + n);
        activeHostBtn.textContent = (selOpt ? selOpt.textContent : ('Host ' + (n - 2)));
        activeHostBtn.style.display = 'inline-block';
        activeHostBtn.classList.add('active');
        activeBtn = activeHostBtn;
      }
    } else {
      hostSelect.value = '';
      if (activeHostBtn) {
        activeHostBtn.classList.remove('active');
        activeHostBtn.style.display = 'none';
      }
    }
  }

  if (activeBtn && typeof activeBtn.scrollIntoView === 'function') {
    try {
      activeBtn.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'nearest' });
    } catch(e) {}
  }
  window.scrollTo(0, 0);

  try {
    if (history.replaceState) {
      var h = '#tab-' + n + (subTab ? ':' + subTab : '');
      history.replaceState(null, '', h);
    }
  } catch(e) {}

  if (n >= 3) {
    var pane = document.getElementById('tab-' + n);
    if (pane) {
      var hasCard = renderEmbeddedHostCard(n, pane);
      if (hasCard) {
        var isInline = !!(pane.querySelector('iframe[srcdoc], iframe[data-srcdoc]'));
        var targetMode = subTab ? 'advanced' : (_subreportsState === 'unavailable' ? 'simplified' : _preferredViewMode);
        setHostViewMode(n, targetMode, subTab);
        if (!isInline && _subreportsState === 'unknown' && targetMode === 'advanced') {
          if (_fallbackTimer) clearTimeout(_fallbackTimer);
          _fallbackTimer = setTimeout(function() {
            _fallbackTimer = null;
            if (_subreportsState === 'unknown') {
              _subreportsState = 'unavailable';
              setHostViewMode(n, 'simplified', subTab);
              var banner = document.getElementById('host-banner-' + n);
              if (banner) {
                banner.className = 'alert alert-warning';
                banner.innerHTML = '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.75rem;width:100%">' +
                  '<div>⚠️ <strong>Sub-report file not found:</strong> Could not load <code>' + _esc(pane.getAttribute('data-src')) + '</code>. Showing Simplified Host View (Consolidated Host Specifications).</div>' +
                  '<button type="button" class="btn-subreport-outline" data-action="set-view-mode" data-host-idx="' + n + '" data-mode="advanced">Retry Loading 🔬</button>' +
                '</div>';
              }
            }
          }, 1200);
        }
      } else {
        // Fallback for environments without fleet-inv-data
        var iframe = pane.querySelector('iframe');
        if (iframe) {
          if (!iframe.srcdoc && iframe.hasAttribute('data-srcdoc')) {
            iframe.srcdoc = iframe.getAttribute('data-srcdoc');
            iframe.removeAttribute('data-srcdoc');
            attachIframeSync(iframe, n, subTab);
          }
          sendSubTabActivation(iframe, subTab);
          iframe.addEventListener('load', function(){ sendSubTabActivation(iframe, subTab); }, {once: true});
        } else if (pane.hasAttribute('data-src')) {
          iframe = document.createElement('iframe');
          iframe.style.width = '100%';
          iframe.style.height = 'calc(100vh - 50px)';
          iframe.style.border = 'none';
          iframe.title = 'Host Report ' + (n - 2);
          iframe.src = pane.getAttribute('data-src');
          pane.appendChild(iframe);
          attachIframeSync(iframe, n, subTab);
        }
      }
    }
  }
}
window.showTab = showTab;

(function initHostPicker(){
  var hostSearch = document.getElementById('host-picker-search');
  var hostSelect = document.getElementById('host-picker-select');
  if (!hostSearch || !hostSelect) return;
  var allOptions = Array.from(hostSelect.options).slice(1);
  hostSearch.addEventListener('input', function() {
    var q = hostSearch.value.trim().toLowerCase();
    allOptions.forEach(function(opt) {
      var s = (opt.getAttribute('data-search') || opt.textContent).toLowerCase();
      opt.style.display = (q === '' || s.indexOf(q) !== -1) ? '' : 'none';
    });
  });
  hostSearch.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      var q = hostSearch.value.trim().toLowerCase();
      var firstMatch = allOptions.find(function(opt) {
        var s = (opt.getAttribute('data-search') || opt.textContent).toLowerCase();
        return (q === '' || s.indexOf(q) !== -1);
      });
      if (firstMatch) {
        hostSelect.value = firstMatch.value;
        showTab(parseInt(firstMatch.value, 10));
      }
    }
  });
})();

function handleHashChange(){
  var rawHash = (location.hash || '').replace(/^#/, '').trim();
  if (!rawHash) return;

  var match = rawHash.match(/^tab-(\d+)(?:[:/_-](tab-[a-z0-9_-]+|[a-z0-9_-]+))?$/i);
  if (match) {
    var tabNum = parseInt(match[1], 10);
    var sub = match[2] || '';
    if (sub && !sub.startsWith('tab-') && !sub.startsWith('inv-')) sub = 'tab-' + sub;
    showTab(tabNum, sub);
    return;
  }

  var ipMatch = rawHash.match(/^([0-9a-z.-]+)(?:[:/_-](tab-[a-z0-9_-]+|[a-z0-9_-]+))?$/i);
  if (ipMatch) {
    var hostId = ipMatch[1];
    var subId = ipMatch[2] || '';
    if (subId && !subId.startsWith('tab-') && !subId.startsWith('inv-')) subId = 'tab-' + subId;
    var foundPane = document.querySelector('.tab-content[data-host-ip="' + hostId + '"]') ||
                    document.querySelector('.tab-content[data-hostname="' + hostId + '"]');
    if (foundPane && foundPane.id) {
      var n = parseInt(foundPane.id.replace('tab-', ''), 10);
      if (!isNaN(n)) {
        showTab(n, subId);
        return;
      }
    }
  }

  var subName = rawHash.toLowerCase();
  if (subName === 'tab-security' || subName === 'security') {
    var activePane = document.querySelector('.tab-content.active');
    if (activePane && activePane.id && parseInt(activePane.id.replace('tab-', ''), 10) >= 3) {
      var hostN = parseInt(activePane.id.replace('tab-', ''), 10);
      showTab(hostN, 'tab-security');
    } else {
      showTab(1);
      var fn = window.showInvView || window.showInvTab;
      if (fn) fn('security');
    }
    return;
  }
  if (subName === 'tab-cpu' || subName === 'cpu') {
    var activePane = document.querySelector('.tab-content.active');
    if (activePane && activePane.id && parseInt(activePane.id.replace('tab-', ''), 10) >= 3) {
      var hostN = parseInt(activePane.id.replace('tab-', ''), 10);
      showTab(hostN, 'tab-cpu');
    } else {
      showTab(1);
      var fn = window.showInvView || window.showInvTab;
      if (fn) fn('hosts');
    }
    return;
  }

  if (subName.startsWith('inv-') || ['hosts','drives','nics','bios','health'].indexOf(subName) !== -1) {
    showTab(1);
    var vName = subName.replace('inv-', '');
    var fn = window.showInvView || window.showInvTab;
    if (fn) fn(vName);
    return;
  }
}

window.addEventListener('hashchange', handleHashChange);
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', handleHashChange);
} else {
  handleHashChange();
}

document.addEventListener('click', function(e) {
  if (!e.target || !e.target.closest) return;

  var target = e.target.closest('.tab-jump');
  if (target) {
    var t = parseInt(target.getAttribute('data-tab') || target.dataset.tab, 10);
    var sub = target.getAttribute('data-subtab') || target.dataset.subtab || '';
    if (!isNaN(t)) {
      e.preventDefault();
      showTab(t, sub);
    }
    return;
  }

  var actionEl = e.target.closest('[data-action]');
  if (actionEl) {
    var action = actionEl.getAttribute('data-action');
    if (action === 'set-view-mode') {
      e.preventDefault();
      var hostIdx = parseInt(actionEl.getAttribute('data-host-idx'), 10);
      var mode = actionEl.getAttribute('data-mode');
      if (!isNaN(hostIdx) && mode) {
        setHostViewMode(hostIdx, mode);
      }
    } else if (action === 'spec-card-click') {
      e.preventDefault();
      var hostIdx = parseInt(actionEl.getAttribute('data-host-idx'), 10);
      var subTab = actionEl.getAttribute('data-subtab') || '';
      var targetSec = actionEl.getAttribute('data-target-sec') || '';
      if (!isNaN(hostIdx)) {
        handleSpecCardClick(hostIdx, subTab, targetSec);
      }
    } else if (action === 'open-tab-src') {
      e.preventDefault();
      var src = actionEl.getAttribute('data-src');
      if (src) {
        window.open(src, '_blank', 'noopener,noreferrer');
      }
    } else if (action === 'fleet-detail-view') {
      e.preventDefault();
      var view = actionEl.getAttribute('data-fleet-view') || 'hosts';
      if (window.showFleetDetailView) {
        window.showFleetDetailView(view);
      }
    }
  }
});
"""


COMBINED_PRIVACY_JS = r"""
var table = document.querySelector('.sortable-table');
if (table) {
  var summaryPager = window.initFleetTablePager ? window.initFleetTablePager({
    table: table,
    rowSelector: 'tbody tr',
    pageSizeSelect: '#sumPageSize',
    prevBtn: '#sumPrevBtn',
    nextBtn: '#sumNextBtn',
    pageInfo: '#sumPageInfo',
    warnEl: '#sumPageWarn',
    filterFn: function(row) {
      var oem = (document.getElementById('oem-filter') || {}).value || 'all';
      var hideUnsup = (document.getElementById('hide-unsupported') || {}).checked || false;
      var vendor = row.getAttribute('data-vendor') || '';
      var unsup  = row.getAttribute('data-unsupported') === '1';
      if (window.VCFReportUI && !window.VCFReportUI.matchesHost(row)) return false;
      if (oem !== 'all' && vendor !== oem) return false;
      if (hideUnsup && unsup) return false;
      return true;
    }
  }) : null;

  var headers = table.querySelectorAll('thead th');
  var sortState = {};

  headers.forEach(function(th, colIdx) {
    th.addEventListener('click', function() {
      var tbody = table.querySelector('tbody');
      var rows = Array.from(tbody.querySelectorAll('tr'));
      var dir = (sortState[colIdx] === 'asc') ? -1 : 1;
      sortState = {};
      sortState[colIdx] = (dir === 1) ? 'asc' : 'desc';

      headers.forEach(function(h, i) {
        h.classList.remove('sorted');
        var ind = h.querySelector('.sort-ind');
        if (ind) ind.textContent = (i === colIdx) ? (dir === 1 ? '\u25b2' : '\u25bc') : '\u21c5';
      });
      th.classList.add('sorted');

      rows.sort(function(a, b) {
        var aCell = a.querySelectorAll('td')[colIdx];
        var bCell = b.querySelectorAll('td')[colIdx];
        if (!aCell || !bCell) return 0;
        var aVal = (aCell.hasAttribute('data-sort') ? aCell.getAttribute('data-sort') : aCell.textContent).trim();
        var bVal = (bCell.hasAttribute('data-sort') ? bCell.getAttribute('data-sort') : bCell.textContent).trim();
        var aNum = parseFloat(aVal), bNum = parseFloat(bVal);
        if (!isNaN(aNum) && !isNaN(bNum)) return dir * (aNum - bNum);
        return dir * aVal.toLowerCase().localeCompare(bVal.toLowerCase());
      });
      rows.forEach(function(row) { tbody.appendChild(row); });
      if (summaryPager) {
        summaryPager.update();
      } else {
        applyTableFilters();
      }
    });
  });

  function applyTableFilters() {
    if (summaryPager) {
      summaryPager.setPage(1);
    } else {
      var oem = (document.getElementById('oem-filter') || {}).value || 'all';
      var hideUnsup = (document.getElementById('hide-unsupported') || {}).checked || false;
      var tbody = table.querySelector('tbody');
      if (!tbody) return;
      Array.from(tbody.querySelectorAll('tr')).forEach(function(row) {
        var vendor = row.getAttribute('data-vendor') || '';
        var unsup  = row.getAttribute('data-unsupported') === '1';
        var show = !window.VCFReportUI || window.VCFReportUI.matchesHost(row);
        if (oem !== 'all' && vendor !== oem) show = false;
        if (hideUnsup && unsup) show = false;
        row.style.display = show ? '' : 'none';
      });
    }
  }

  window.addEventListener('vcf-overview-filter', applyTableFilters);
  var oemSel = document.getElementById('oem-filter');
  var hideChk = document.getElementById('hide-unsupported');
  if (oemSel) oemSel.addEventListener('change', applyTableFilters);
  if (hideChk) hideChk.addEventListener('change', applyTableFilters);
}



(function(){
  var cb = document.getElementById('maskPII');
  var dlBtn = document.getElementById('dlObf');
  var dlCombBtn = document.getElementById('dlObfCombined');

  if (cb) {
    cb.addEventListener('change', function() {
      var isMasked = cb.checked;
      document.querySelectorAll('.pii').forEach(function(el) {
        el.textContent = isMasked ? el.dataset.mask : el.dataset.real;
      });
      var thMac = document.getElementById('thNicMac');
      if (thMac) {
        thMac.innerHTML = isMasked ? 'MAC <em>(obfuscated)</em>' : 'MAC';
      }
      if (dlBtn) dlBtn.style.display = isMasked ? 'inline-block' : 'none';
      document.querySelectorAll('iframe').forEach(function(iframe) {
        try {
          if(iframe.contentWindow)iframe.contentWindow.postMessage({type:'vcf-report-mask',checked:isMasked},'*');
          if (iframe.contentDocument) {
            var icb = iframe.contentDocument.getElementById('maskPII');
            if (icb) {
              icb.checked = isMasked;
              icb.dispatchEvent(new Event('change'));
            } else {
              iframe.contentDocument.querySelectorAll('.pii').forEach(function(el) {
                el.textContent = isMasked ? el.dataset.mask : el.dataset.real;
              });
            }
          }
        } catch(e){}
      });
    });
  }

  function downloadObfuscatedCombined(e) {
    if (e) e.preventDefault();
    var replacements = [];
    document.querySelectorAll('.pii[data-real]').forEach(function(el) {
      var real=el.dataset.real, mask=el.dataset.mask;
      if(real && mask && real!==mask)replacements.push([real,mask]);
    });
    replacements.sort(function(a,b){return b[0].length-a[0].length;});
    function redactAttributes(root) {
      root.querySelectorAll('[title],[aria-label],[data-search]').forEach(function(el) {
        ['title','aria-label','data-search'].forEach(function(attr) {
          if(!el.hasAttribute(attr))return;
          var value=el.getAttribute(attr);
          replacements.forEach(function(pair){value=value.split(pair[0]).join(pair[1]);});
          el.setAttribute(attr,value);
        });
      });
    }
    function markPublic(root) {
      var checkbox=root.querySelector('#maskPII');
      if(checkbox){
        var badge=(root.ownerDocument||root).createElement('span');
        badge.className='badge info';badge.textContent='🔒 Obfuscated report';
        (checkbox.closest('label')||checkbox).replaceWith(badge);
      }
      var duplicate=root.querySelector('#dlObf');if(duplicate)duplicate.remove();
    }
    var clone = document.documentElement.cloneNode(true);
    markPublic(clone);
    clone.querySelectorAll('.pii').forEach(function(el) {
      var mask = el.dataset.mask || el.textContent;
      el.textContent = mask;
      el.removeAttribute('data-real');
      el.setAttribute('data-mask', mask);
    });
    clone.querySelectorAll('[data-host-ip]').forEach(function(el) {
      el.removeAttribute('data-host-ip');
    });
    clone.querySelectorAll('[data-hostname]').forEach(function(el) {
      el.removeAttribute('data-hostname');
    });

    var thMacClone = clone.querySelector('#thNicMac');
    if (thMacClone) {
      thMacClone.innerHTML = 'MAC <em>(obfuscated)</em>';
    }

    // Reset and sanitize sidecar host panes
    clone.querySelectorAll('.tab-content[data-src]').forEach(function(pane, idx) {
      pane.setAttribute('data-src', 'reports/OBFUSCATED_Host-' + (idx + 1) + '.html');
      var ifrWrap = pane.querySelector('.host-iframe-wrapper');
      if (ifrWrap) {
        var mount = ifrWrap.querySelector('[id^="iframe-mount-"]');
        if (mount) mount.innerHTML = '';
        ifrWrap.style.display = 'none';
        var srcLbl = ifrWrap.querySelector('[id^="iframe-src-label-"]');
        if (srcLbl) srcLbl.textContent = 'reports/OBFUSCATED_Host-' + (idx + 1) + '.html';
      }
      var card = pane.querySelector('.host-embedded-card');
      if (card) {
        card.style.display = 'block';
      }
      pane.querySelectorAll('iframe').forEach(function(ifr) {
        if (!ifr.hasAttribute('data-srcdoc') && !ifr.hasAttribute('srcdoc')) {
          if (ifr.parentNode) ifr.parentNode.removeChild(ifr);
        }
      });
    });

    clone.querySelectorAll('iframe').forEach(function(iframe) {
      var srcdoc = iframe.getAttribute('srcdoc') || iframe.getAttribute('data-srcdoc');
      if (srcdoc) {
        var cleanSrcdoc = srcdoc.replace(/<span\s+class=["']pii["'][^>]*data-mask=["']([^"']+)["'][^>]*>([\s\S]*?)<\/span>/gi, function(match, mask) {
          return '<span class="pii" data-mask="' + mask + '">' + mask + '</span>';
        });
        cleanSrcdoc = cleanSrcdoc.replace(/\s+data-real=["'][^"']*["']/gi, '');
        cleanSrcdoc = cleanSrcdoc.replace(/<title>.*?<\/title>/gi, '<title>VCF Readiness<\/title>');
        cleanSrcdoc = cleanSrcdoc.replace(/(^|[^0-9])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?=[^0-9]|$)/g, '$1192.0.2.1');
        var parsedSrcdoc = new DOMParser().parseFromString(cleanSrcdoc, 'text/html');
        redactAttributes(parsedSrcdoc);
        markPublic(parsedSrcdoc);
        cleanSrcdoc = '<!DOCTYPE html>' + parsedSrcdoc.documentElement.outerHTML;
        if (iframe.hasAttribute('data-srcdoc')) {
          iframe.setAttribute('data-srcdoc', cleanSrcdoc);
        } else {
          iframe.setAttribute('srcdoc', cleanSrcdoc);
        }
      }
    });
    var invScript = clone.querySelector('#fleet-inv-data');
    if (invScript) {
      try {
        var invData = JSON.parse(invScript.textContent);
        if (invData.hosts) {
          invData.hosts.forEach(function(h, idx) {
            h.hostname = 'Host-' + (idx + 1);
            h.ip = '192.0.2.' + ((idx % 250) + 1);
          });
        }
        if (invData.drives) {
          invData.drives.forEach(function(d) {
            var hidx = (d.host_idx !== undefined ? d.host_idx : 0);
            if (d.hostname) d.hostname = 'Host-' + (hidx + 1);
            if (d.ip) d.ip = '192.0.2.' + ((hidx % 250) + 1);
            if (d.serial) d.serial = 'MASKED';
          });
        }
        if (invData.nics) {
          invData.nics.forEach(function(n) {
            var hidx = (n.host_idx !== undefined ? n.host_idx : 0);
            if (n.hostname) n.hostname = 'Host-' + (hidx + 1);
            if (n.ip) n.ip = '192.0.2.' + ((hidx % 250) + 1);
            if (n.mac_address) n.mac_address = '02:00:00:00:00:00';
          });
        }
        if (invData.health) {
          invData.health.forEach(function(hl) {
            var hidx = (hl.host_idx !== undefined ? hl.host_idx : 0);
            if (hl.hostname) hl.hostname = 'Host-' + (hidx + 1);
            if (hl.ip) hl.ip = '192.0.2.' + ((hidx % 250) + 1);
            if (hl.message) {
              hl.message = hl.message.replace(/(^|[^0-9])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?=[^0-9]|$)/g, '$1192.0.2.1');
            }
          });
        }
        invData.meta = invData.meta || {};
        invData.meta.obfuscated = true;
        invScript.textContent = JSON.stringify(invData);
      } catch(e) {
        invScript.textContent = '{}';
      }
    }
    var pickerOpts = clone.querySelectorAll('#host-picker-select option');
    pickerOpts.forEach(function(opt, idx) {
      if (idx > 0) {
        opt.textContent = 'Host-' + idx;
        opt.removeAttribute('data-search');
      }
    });
    var activeBtn = clone.querySelector('#active-host-btn');
    if (activeBtn) {
      activeBtn.textContent = '';
      activeBtn.style.display = 'none';
      activeBtn.classList.remove('active');
    }

    // A shared copy must never retain the original report's private key export.
    clone.querySelectorAll('[data-private-export]').forEach(function(button){button.remove();});
    clone.querySelectorAll('[data-inventory-export="excel"]').forEach(function(button){button.textContent='Export Excel (Obfuscated)';});

    // Reset active tab to tab-0 in clone
    clone.querySelectorAll('.tab-content').forEach(function(el) {
      el.classList.toggle('active', el.id === 'tab-0');
    });
    clone.querySelectorAll('.tab-btn').forEach(function(el, i) {
      el.classList.toggle('active', i === 0);
    });

    var titleEl = clone.querySelector('title');
    if (titleEl && titleEl.textContent.indexOf('Obfuscated') === -1) {
      titleEl.textContent = titleEl.textContent.replace('VCF Readiness', 'VCF Readiness (Obfuscated)');
    }

    var cbClone = clone.querySelector('#maskPII');
    if (cbClone) cbClone.checked = true;
    redactAttributes(clone);
    var rawHtml = '<!DOCTYPE html>' + clone.outerHTML;
    // Preserve a public workbook while stripping both raw data and private keys.
    var publicMatch=rawHtml.match(/var _PUBLIC_EXCEL_B64 = "([^"]*)";/);
    var publicExcel=publicMatch?publicMatch[1]:'';
    rawHtml=rawHtml.replace(/var _PUBLIC_REPORT_EXPORT = (?:true|false);/g,'var _PUBLIC_REPORT_EXPORT = true;');
    rawHtml=rawHtml.replace(/var _EMBEDDED_EXCEL_B64 = "[^"]*";/g,'var _EMBEDDED_EXCEL_B64 = "'+publicExcel+'";');
    rawHtml=rawHtml.replace(/var _EMBEDDED_OBF_ZIP_B64 = "[^"]*";/g,'var _EMBEDDED_OBF_ZIP_B64 = "";');
    // Scrub any stray private IPs that might appear in free-text outer HTML
    rawHtml = rawHtml.replace(/(^|[^0-9])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?=[^0-9]|$)/g, '$1192.0.2.1');
    var blob = new Blob([rawHtml], {type: 'text/html'});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.download = '00_OBFUSCATED_fleet_combined.html';
    a.href = url;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  if (dlBtn) dlBtn.addEventListener('click', downloadObfuscatedCombined);
  if (dlCombBtn) dlCombBtn.addEventListener('click', downloadObfuscatedCombined);

  // Theme synchronization and localStorage persistence
  var storedTheme;
  try { storedTheme = localStorage.getItem('vcf-theme') || localStorage.getItem('vcf-report-theme'); } catch(e) {}
  var initialTheme = storedTheme || document.documentElement.getAttribute('data-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', initialTheme);

  var tt = document.getElementById('themeToggle');
  if (tt) {
    if(tt.getAttribute('role')!=='switch')tt.textContent = initialTheme === 'dark' ? '🌙 Dark' : '☀️ Light';
    tt.addEventListener('click', function() {
      var cur = document.documentElement.getAttribute('data-theme') || 'dark';
      var next = cur === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try { localStorage.setItem('vcf-report-theme', next); } catch(e) {}
      if(tt.getAttribute('role')!=='switch')tt.textContent = next === 'dark' ? '🌙 Dark' : '☀️ Light';
      document.querySelectorAll('iframe').forEach(function(iframe) {
        try {
          if(iframe.contentWindow)iframe.contentWindow.postMessage({type:'vcf-report-theme',theme:next},'*');
          if (iframe.contentDocument && iframe.contentDocument.documentElement) {
            iframe.contentDocument.documentElement.setAttribute('data-theme', next);
            var ibtn = iframe.contentDocument.getElementById('themeToggle');
            if (ibtn && ibtn.getAttribute('role')!=='switch') ibtn.textContent = next === 'dark' ? '🌙 Dark' : '☀️ Light';
          }
        } catch(e){}
      });
    });
  }

  // Propagate active theme to every iframe on load and immediately
  document.querySelectorAll('iframe').forEach(function(iframe) {
    function applyToIframe() {
      try {
        var th = document.documentElement.getAttribute('data-theme') || 'dark';
        if (iframe.contentDocument && iframe.contentDocument.documentElement) {
          iframe.contentDocument.documentElement.setAttribute('data-theme', th);
          var ibtn = iframe.contentDocument.getElementById('themeToggle');
          if (ibtn && ibtn.getAttribute('role')!=='switch') ibtn.textContent = th === 'dark' ? '🌙 Dark' : '☀️ Light';
        }
      } catch(e) {}
    }
    applyToIframe();
    iframe.addEventListener('load', applyToIframe);
  });
})();
"""


def render_combined_document(page_title: str, tab_btns: str, panels: str, timestamp: str) -> str:
    """Compose offline shell assets in their original cascade and script order."""
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <title>{page_title}</title>
  <link rel="icon" type="image/svg+xml" href="{FAVICON_DATA_URI}">
  <style>
{HOST_REPORT_CSS}{COMBINED_SHELL_CSS}{REPORT_UI_CSS}
  </style>
</head>
<body>
<div class="tab-bar">{tab_btns}</div>
<script>{COMBINED_NAV_JS}</script>
{panels}
<script>{COMBINED_PRIVACY_JS}</script>
<!-- VCF Readiness v{TOOL_VERSION} · {timestamp} -->
{REPORT_UI_JS}
</body></html>"""
