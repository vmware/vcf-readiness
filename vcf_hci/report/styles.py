"""
VCF Readiness Tool — inline CSS for standalone HTML reports.

All CSS constants in this module use single { } braces (standard CSS).
They are injected into report HTML templates as Python string substitutions:
    html = f"<style>{HOST_REPORT_CSS}</style>"

Dark mode is supported via [data-theme="dark"] on <html> and
@media (prefers-color-scheme: dark) for OS-preference detection.
THEME_TOGGLE_JS adds a small script that persists the user's choice to
localStorage, inserted once per report just before </body>.
"""

# ── Theme toggle JavaScript ───────────────────────────────────────────────────
# Injected once per page, just before </body>.
THEME_TOGGLE_JS = """\
<script>
(function(){
  var root=document.documentElement;
  var btn=document.getElementById('themeToggle');
  var parentTheme=null;
  try {
    if (window.parent && window.parent !== window && window.parent.document && window.parent.document.documentElement) {
      parentTheme = window.parent.document.documentElement.getAttribute('data-theme');
    }
  } catch(e) {}
  var stored;try{stored=localStorage.getItem('vcf-report-theme');}catch(e){}
  var cur=parentTheme || stored || root.getAttribute('data-theme') || 'dark';
  function apply(t, notifyParent){
    root.setAttribute('data-theme',t);
    if(btn)btn.textContent=t==='dark'?'🌙 Dark':'☀️ Light';
    try{localStorage.setItem('vcf-report-theme',t);}catch(e){}
    cur=t;
    if (notifyParent !== false) {
      try {
        if (window.parent && window.parent !== window && window.parent.document) {
          var pRoot = window.parent.document.documentElement;
          if (pRoot && pRoot.getAttribute('data-theme') !== t) {
            pRoot.setAttribute('data-theme', t);
            var pBtn = window.parent.document.getElementById('themeToggle');
            if (pBtn) pBtn.textContent = t === 'dark' ? '🌙 Dark' : '☀️ Light';
          }
        }
      } catch(ex) {}
    }
  }
  apply(cur, false);
  if(btn)btn.addEventListener('click',function(){apply(cur==='dark'?'light':'dark', true);});
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change',function(e){
    var s;try{s=localStorage.getItem('vcf-report-theme');}catch(ex){}
    if(!s && !parentTheme)apply(e.matches?'dark':'light', true);
  });
})();
function _esc(s){if(!s)return'';return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function showChassisBayInfo(el){
  var slot=_esc(el.getAttribute('data-slot'));
  var pos=_esc(el.getAttribute('data-pos'));
  var rawModel=el.getAttribute('data-model');
  var model=_esc(rawModel);
  var rawPn=el.getAttribute('data-pn');
  var pn=_esc(rawPn);
  var cap=_esc(el.getAttribute('data-cap'));
  var proto=_esc(el.getAttribute('data-proto'));
  var ctrl=_esc(el.getAttribute('data-ctrl'));
  var hlth=_esc(el.getAttribute('data-health'));
  var end=_esc(el.getAttribute('data-endurance'));
  var vsan=_esc(el.getAttribute('data-vsan'));
  var container=el.closest?el.closest('.chassis-diagram-container'):null;
  var p=container?container.querySelector('#chassis-bay-detail-content'):document.getElementById('chassis-bay-detail-content');
  if(!p)return;
  if(!rawModel||rawModel==='Empty Slot'||rawModel==='Empty'){
    p.innerHTML='<strong>Slot '+slot+' ('+(pos||'Front')+')</strong> &mdash; <span style="color:var(--text-muted)">Empty Slot / Blank Filler</span>';
    return;
  }
  var pnStr=(rawPn&&rawPn!=='N/A')?' <small style="opacity:.85">(Part #: <b>'+pn+'</b>)</small>':'';
  p.innerHTML='<div style="line-height:1.4"><strong style="color:var(--primary);font-size:.92rem">Slot '+slot+'</strong> '+
              '<small style="color:var(--text-muted)">('+(pos||'Front')+')</small>: '+
              '<strong>'+model+'</strong>'+pnStr+' &bull; '+
              '<b>'+cap+' GB</b> '+proto+' &bull; '+
              'Attached Controller: <code>'+(ctrl||'N/A')+'</code></div>'+
              '<div style="margin-top:.25rem;font-size:.8rem;color:var(--text-muted)">Health: <b style="color:var(--success)">'+(hlth||'OK')+'</b> &bull; '+
              'Endurance Remaining: <b>'+(end||'N/A')+'</b> &bull; '+
              'vSAN HCL Status: <b>'+(vsan||'N/A')+'</b></div>';
}
</script>"""

# ── Host report CSS ───────────────────────────────────────────────────────────
# Injected as: f"<style>{HOST_REPORT_CSS}</style>"
# All braces are single (plain CSS syntax).
HOST_REPORT_CSS = (
    ":root{"
    "--bg:#f8fafc;--card:#fff;--text:#1e293b;--text-muted:#64748b;"
    "--border:#e2e8f0;--primary:#2563eb;--success:#16a34a;--warning:#ca8a04;--danger:#dc2626;"
    "--th-bg:#f8fafc;--code-bg:#f1f5f9;--card-bg-subtle:#e0f2fe;--pci-bg:#e0f2fe;--pci-color:#0369a1;--accordion-summary-bg:#f8fafc;"
    "--accordion-summary-hover:#f1f5f9;--callout-bg:#eff6ff;--rollup-bg:#f8fafc;--h-color:#0f172a}"
    "[data-theme='dark']{"
    "--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--text-muted:#94a3b8;"
    "--border:#334155;--primary:#60a5fa;--success:#4ade80;--warning:#fbbf24;--danger:#f87171;"
    "--th-bg:#1e293b;--code-bg:#263548;--card-bg-subtle:#1e293b;--pci-bg:#1e293b;--pci-color:#38bdf8;--accordion-summary-bg:#263548;"
    "--accordion-summary-hover:#2d3f52;--callout-bg:#1e2f4a;--rollup-bg:#1e293b;--h-color:#e2e8f0}"
    "@media(prefers-color-scheme:dark){:root:not([data-theme='light']){"
    "--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--text-muted:#94a3b8;"
    "--border:#334155;--primary:#60a5fa;--success:#4ade80;--warning:#fbbf24;--danger:#f87171;"
    "--th-bg:#1e293b;--code-bg:#263548;--card-bg-subtle:#1e293b;--pci-bg:#1e293b;--pci-color:#38bdf8;--accordion-summary-bg:#263548;"
    "--accordion-summary-hover:#2d3f52;--callout-bg:#1e2f4a;--rollup-bg:#1e293b;--h-color:#e2e8f0}}"
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
    "background:var(--bg);color:var(--text);padding:2rem;line-height:1.5}"
    ".container{max-width:1340px;margin:0 auto}"
    ".header{display:flex;justify-content:space-between;border-bottom:2px solid var(--border);"
    "padding-bottom:1rem;margin-bottom:2rem}"
    ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));"
    "gap:1.25rem;margin-bottom:2rem}"
    ".card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.25rem}"
    ".card-nested{background:var(--code-bg);padding:1.5rem}"
    ".badge{display:inline-block;padding:.25rem .6rem;border-radius:4px;font-weight:600;font-size:.82rem}"
    ".badge.success{background:#dcfce7;color:var(--success)}"
    ".badge.warning{background:#fef9c3;color:var(--warning)}"
    ".badge.danger{background:#fee2e2;color:var(--danger)}"
    ".badge.info{background:#e0f2fe;color:#0369a1}"
    ".badge.cyber-recovery{background:#f3e8ff;color:#7c3aed}"
    "[data-theme='dark'] .badge.success{background:#14532d;color:#4ade80}"
    "[data-theme='dark'] .badge.warning{background:#422006;color:#fbbf24}"
    "[data-theme='dark'] .badge.danger{background:#450a0a;color:#f87171}"
    "[data-theme='dark'] .badge.info{background:#0c2240;color:#60a5fa}"
    "[data-theme='dark'] .badge.cyber-recovery{background:#2e1065;color:#c4b5fd}"
    "@media(prefers-color-scheme:dark){"
    ":root:not([data-theme='light']) .badge.success{background:#14532d;color:#4ade80}"
    ":root:not([data-theme='light']) .badge.warning{background:#422006;color:#fbbf24}"
    ":root:not([data-theme='light']) .badge.danger{background:#450a0a;color:#f87171}"
    ":root:not([data-theme='light']) .badge.info{background:#0c2240;color:#60a5fa}"
    ":root:not([data-theme='light']) .badge.cyber-recovery{background:#2e1065;color:#c4b5fd}}"
    "table{width:100%;border-collapse:collapse;background:var(--card);border-radius:8px;"
    "border:1px solid var(--border);margin-bottom:1.5rem}"
    "th,td{padding:.75rem 1rem;text-align:left;border-bottom:1px solid var(--border);font-size:.88rem}"
    "th{background:var(--th-bg);font-weight:600}"
    "code{background:var(--code-bg);padding:.2rem .4rem;border-radius:4px;font-family:monospace}"
    "a{color:var(--primary);text-decoration:none}"
    "a:visited{color:var(--primary)}"
    "a:hover{text-decoration:underline;filter:brightness(1.15)}"
    ".btn-link{color:var(--primary);text-decoration:none;font-weight:600}"
    ".btn-link:visited{color:var(--primary)}"
    ".callout-box{background:var(--callout-bg);border-left:4px solid var(--primary);"
    "padding:1.25rem;border-radius:6px;margin-bottom:2rem}"
    ".alert{padding:.85rem 1.15rem;border-radius:6px;margin:1rem 0;font-size:.88rem;line-height:1.5;border:1px solid transparent}"
    ".alert-warning{background:var(--callout-warn-bg,#fefce8);border-color:var(--callout-warn-border,#fef08a);border-left:4px solid var(--warning,#ca8a04);color:var(--callout-warn-h,#854d0e)}"
    ".alert-warning strong,.alert-warning h4{color:var(--callout-warn-h,#854d0e)}"
    ".alert-warning p,.alert-warning ul,.alert-warning li{color:var(--callout-warn-ul,#713f12)}"
    ".alert-danger{background:var(--tint-danger-bg,#fef2f2);border-color:var(--tint-danger-border,#fca5a5);border-left:4px solid var(--danger,#dc2626);color:var(--tint-danger-text,#991b1b)}"
    ".alert-danger strong,.alert-danger h4{color:var(--tint-danger-text,#991b1b)}"
    ".alert-danger p,.alert-danger ul,.alert-danger li{color:var(--tint-danger-text,#991b1b)}"
    ".alert-success{background:var(--callout-ok-bg,#f0fdf4);border-color:var(--callout-ok-border,#bbf7d0);border-left:4px solid var(--success,#16a34a);color:var(--callout-ok-h,#166534)}"
    ".alert-info{background:var(--callout-blue-bg,#f0f9ff);border-color:var(--callout-blue-border,#bae6fd);border-left:4px solid var(--primary,#2563eb);color:var(--callout-blue-title,#0369a1)}"
    "details.accordion{background:var(--card);border:1px solid var(--border);"
    "border-radius:8px;margin-bottom:2rem;overflow:hidden}"
    "details.accordion summary{padding:1rem 1.25rem;font-weight:600;cursor:pointer;"
    "background:var(--accordion-summary-bg);display:flex;align-items:center;"
    "justify-content:space-between;user-select:none}"
    "details.accordion summary:hover{background:var(--accordion-summary-hover)}"
    "details.accordion .accordion-body{padding:1.25rem;border-top:1px solid var(--border)}"
    "h2{margin:2rem 0 1rem;color:var(--h-color)}"
    "h3{color:var(--h-color)}"
    ".tab-nav{display:flex;gap:3px;border-bottom:2px solid var(--border);margin-bottom:1.5rem;"
    "flex-wrap:wrap;padding-bottom:0;scroll-margin-top:1rem}"
    ".tab-btn{background:var(--th-bg,#f8fafc);border:1px solid var(--border,#e2e8f0);border-bottom:3px solid transparent;"
    "margin-bottom:-2px;padding:.6rem 1.3rem;font-size:.95rem;font-weight:600;cursor:pointer;"
    "color:var(--text-muted,#64748b);border-radius:6px 6px 0 0;white-space:nowrap;display:inline-flex;"
    "align-items:center;gap:.4rem;transition:color .15s,background .15s,border-color .15s}"
    ".tab-btn:hover{color:var(--text,#1e293b);background:var(--border,#e2e8f0)}"
    ".tab-btn.active{background:var(--card,#fff);color:var(--primary,#2563eb);border-bottom-color:var(--primary,#2563eb);"
    "font-weight:700;border-color:var(--border,#e2e8f0)}"
    "[data-theme='dark'] .tab-btn{background:#1e293b;border-color:#334155;color:#94a3b8}"
    "[data-theme='dark'] .tab-btn:hover{background:#334155;color:#e2e8f0}"
    "[data-theme='dark'] .tab-btn.active{background:#0f172a;color:#f8fafc;border-color:#334155;border-bottom-color:var(--primary)}"
    "@media(prefers-color-scheme:dark){"
    ":root:not([data-theme='light']) .tab-btn{background:#1e293b;border-color:#334155;color:#94a3b8}"
    ":root:not([data-theme='light']) .tab-btn:hover{background:#334155;color:#e2e8f0}"
    ":root:not([data-theme='light']) .tab-btn.active{background:#0f172a;color:#f8fafc;border-color:#334155;border-bottom-color:var(--primary)}}"
    ".tab-pane{display:none;scroll-margin-top:4rem}.tab-pane.active{display:block}"
    ".tab-dot{display:inline-block;width:8px;height:8px;border-radius:50%;flex-shrink:0}"
    ".dot-success{background:var(--success)}.dot-warning{background:var(--warning)}"
    ".dot-danger{background:var(--danger)}.dot-info{background:#94a3b8}"
    ".alert-rollup{display:flex;flex-wrap:wrap;gap:.5rem;padding:.65rem 1rem;"
    "background:var(--rollup-bg);border:1px solid var(--border);border-radius:8px;"
    "margin-bottom:1.25rem;align-items:center}"
    ".tab-pane h2{margin:1.5rem 0 .75rem;font-size:1.1rem}"
    "#themeToggle{background:none;border:1px solid var(--border);color:var(--text-muted);"
    "border-radius:4px;padding:.2rem .55rem;font-size:.78rem;cursor:pointer;"
    "transition:background .12s;margin-left:.5rem;vertical-align:middle}"
    "#themeToggle:hover{background:var(--th-bg)}"
    # ── Dark-mode–safe colour tokens (appended to merge with :root / dark blocks) ─
    ":root{"
    "--ms-1dpc-color:#16a34a;--ms-1dpc-bg:#f0fdf4;--ms-1dpc-border:#86efac;"
    "--ms-2dpc-color:#2563eb;--ms-2dpc-bg:#eff6ff;--ms-2dpc-border:#93c5fd;"
    "--ms-3dpc-color:#7c3aed;--ms-3dpc-bg:#f5f3ff;--ms-3dpc-border:#c4b5fd;"
    "--ms-empty-bg:#f8fafc;--ms-empty-border:#cbd5e1;--ms-empty-text:#64748b;"
    "--ms-slot1-bg:#f0fdf4;--ms-slot1-border:#86efac;--ms-slot1-color:#166534;"
    "--ms-slot2-bg:#f0f9ff;--ms-slot2-border:#7dd3fc;--ms-slot2-color:#075985;"
    "--ms-crit-bg:#fef2f2;--ms-crit-border:#fca5a5;--ms-crit-color:#991b1b;"
    "--ms-warn-bg:#fefce8;--ms-warn-border:#fde047;--ms-warn-color:#854d0e;"
    "--ms-sock-bg:#f8fafc;--ms-badge-bg:#ffffff;--ms-score-track:#e2e8f0;"
    "--tint-danger-bg:#fef2f2;--tint-danger-border:#fca5a5;--tint-danger-text:#991b1b;"
    "--tint-warning-bg:#fefce8;--tint-warning-border:#fef08a;--tint-warning-text:#854d0e;"
    "--tint-success-bg:#f0fdf4;--tint-info-bg:#f8fafc;"
    "--callout-warn-bg:#fefce8;--callout-warn-border:#fef08a;"
    "--callout-warn-h:#854d0e;--callout-warn-ul:#713f12;"
    "--callout-ok-bg:#f0fdf4;--callout-ok-border:#bbf7d0;"
    "--callout-ok-h:#166534;--callout-ok-ul:#15803d;"
    "--callout-blue-bg:#f0f9ff;--callout-blue-border:#bae6fd;"
    "--callout-blue-title:#0369a1;--callout-blue-body:#0c4a6e;"
    "--callout-info-bg:#eff6ff;--callout-info-border:#bfdbfe;--callout-info-h:#1e40af;"
    "--nps-warn-bg:#fef3c7;--nps-warn-border:#fde68a;--nps-warn-color:#92400e;"
    "--nps-info-bg:#dbeafe;--nps-info-border:#bfdbfe;--nps-info-color:#1e40af;"
    "--sec-ht-warn-bg:#fffbeb;--sec-ht-warn-color:#92400e;"
    "--sec-footer-bg:#f8fafc;--sec-footer-border:#e2e8f0;"
    "--sec-muted-bg:#f8fafc;"
    "--lbtn-blue-bg:#eff6ff;--lbtn-blue-border:#bfdbfe;--lbtn-blue-text:#1d4ed8;"
    "--lbtn-green-bg:#f0fdf4;--lbtn-green-border:#bbf7d0;--lbtn-green-text:#15803d;"
    "--lbtn-orange-bg:#fff7ed;--lbtn-orange-border:#fed7aa;--lbtn-orange-text:#c2410c;"
    "--lbtn-purple-bg:#faf5ff;--lbtn-purple-border:#e9d5ff;--lbtn-purple-text:#7e22ce;"
    "--os-vcf-note-bg:#fef9c3;--os-vcf-note-color:#78350f;"
    "--chassis-bg:#f1f5f9;--chassis-border:#cbd5e1;--chassis-empty-fill:#e2e8f0;--chassis-empty-stroke:#cbd5e1;--chassis-empty-face:#cbd5e1;--chassis-empty-text:#64748b;"
    "--numa-sock-bg:#faf5ff;--numa-sock-border:#6366f1;--numa-sock-title:#4f46e5;--numa-box-border:#8b5cf6;--numa-box-bg:rgba(139,92,246,.04);--numa-box-title:#7c3aed;--numa-chip-bg:#eff6ff;--numa-chip-border:#93c5fd;--numa-chip-title:#1e40af;}"
    "[data-theme='dark']{"
    "--ms-1dpc-color:#4ade80;--ms-1dpc-bg:#052e16;--ms-1dpc-border:#166534;"
    "--ms-2dpc-color:#60a5fa;--ms-2dpc-bg:#0c1f3a;--ms-2dpc-border:#1e3a8a;"
    "--ms-3dpc-color:#a78bfa;--ms-3dpc-bg:#1a0a2e;--ms-3dpc-border:#5b21b6;"
    "--ms-empty-bg:#1e293b;--ms-empty-border:#334155;--ms-empty-text:#94a3b8;"
    "--ms-slot1-bg:#052e16;--ms-slot1-border:#166534;--ms-slot1-color:#4ade80;"
    "--ms-slot2-bg:#0c1f3a;--ms-slot2-border:#1e3a8a;--ms-slot2-color:#60a5fa;"
    "--ms-crit-bg:#450a0a;--ms-crit-border:#991b1b;--ms-crit-color:#fca5a5;"
    "--ms-warn-bg:#2a1400;--ms-warn-border:#b45309;--ms-warn-color:#fbbf24;"
    "--ms-sock-bg:#263548;--ms-badge-bg:#263548;--ms-score-track:#334155;"
    "--tint-danger-bg:#2d0a0a;--tint-danger-border:#991b1b;--tint-danger-text:#f87171;"
    "--tint-warning-bg:#2a1400;--tint-warning-border:#78350f;--tint-warning-text:#fbbf24;"
    "--tint-success-bg:#052e16;--tint-info-bg:#1e293b;"
    "--callout-warn-bg:#2a1400;--callout-warn-border:#78350f;"
    "--callout-warn-h:#fbbf24;--callout-warn-ul:#fde68a;"
    "--callout-ok-bg:#052e16;--callout-ok-border:#166534;"
    "--callout-ok-h:#4ade80;--callout-ok-ul:#86efac;"
    "--callout-blue-bg:#0c1f3a;--callout-blue-border:#1e3a8a;"
    "--callout-blue-title:#60a5fa;--callout-blue-body:#bfdbfe;"
    "--callout-info-bg:#0c1f3a;--callout-info-border:#1e3a8a;--callout-info-h:#60a5fa;"
    "--nps-warn-bg:#2a1400;--nps-warn-border:#78350f;--nps-warn-color:#fbbf24;"
    "--nps-info-bg:#0c1f3a;--nps-info-border:#1e3a8a;--nps-info-color:#60a5fa;"
    "--sec-ht-warn-bg:#2a1400;--sec-ht-warn-color:#fbbf24;"
    "--sec-footer-bg:#1e293b;--sec-footer-border:#334155;"
    "--sec-muted-bg:#1e293b;"
    "--lbtn-blue-bg:#0c1f3a;--lbtn-blue-border:#1e3a8a;--lbtn-blue-text:#60a5fa;"
    "--lbtn-green-bg:#052e16;--lbtn-green-border:#166534;--lbtn-green-text:#4ade80;"
    "--lbtn-orange-bg:#2a0e00;--lbtn-orange-border:#7c2d12;--lbtn-orange-text:#fb923c;"
    "--lbtn-purple-bg:#1a0a2e;--lbtn-purple-border:#5b21b6;--lbtn-purple-text:#a78bfa;"
    "--os-vcf-note-bg:#2a1400;--os-vcf-note-color:#fbbf24;"
    "--chassis-bg:#0f172a;--chassis-border:#334155;--chassis-empty-fill:#1e293b;--chassis-empty-stroke:#334155;--chassis-empty-face:#243b55;--chassis-empty-text:#475569;"
    "--numa-sock-bg:#1e1b4b;--numa-sock-border:#6366f1;--numa-sock-title:#a5b4fc;--numa-box-border:#a78bfa;--numa-box-bg:rgba(167,139,250,.08);--numa-box-title:#c4b5fd;--numa-chip-bg:#1e293b;--numa-chip-border:#3b82f6;--numa-chip-title:#60a5fa;}"
    "@media(prefers-color-scheme:dark){:root:not([data-theme='light']){"
    "--ms-1dpc-color:#4ade80;--ms-1dpc-bg:#052e16;--ms-1dpc-border:#166534;"
    "--ms-2dpc-color:#60a5fa;--ms-2dpc-bg:#0c1f3a;--ms-2dpc-border:#1e3a8a;"
    "--ms-3dpc-color:#a78bfa;--ms-3dpc-bg:#1a0a2e;--ms-3dpc-border:#5b21b6;"
    "--ms-empty-bg:#1e293b;--ms-empty-border:#334155;--ms-empty-text:#94a3b8;"
    "--ms-slot1-bg:#052e16;--ms-slot1-border:#166534;--ms-slot1-color:#4ade80;"
    "--ms-slot2-bg:#0c1f3a;--ms-slot2-border:#1e3a8a;--ms-slot2-color:#60a5fa;"
    "--ms-crit-bg:#450a0a;--ms-crit-border:#991b1b;--ms-crit-color:#fca5a5;"
    "--ms-warn-bg:#2a1400;--ms-warn-border:#b45309;--ms-warn-color:#fbbf24;"
    "--ms-sock-bg:#263548;--ms-badge-bg:#263548;--ms-score-track:#334155;"
    "--tint-danger-bg:#2d0a0a;--tint-danger-border:#991b1b;--tint-danger-text:#f87171;"
    "--tint-warning-bg:#2a1400;--tint-warning-border:#78350f;--tint-warning-text:#fbbf24;"
    "--tint-success-bg:#052e16;--tint-info-bg:#1e293b;"
    "--callout-warn-bg:#2a1400;--callout-warn-border:#78350f;"
    "--callout-warn-h:#fbbf24;--callout-warn-ul:#fde68a;"
    "--callout-ok-bg:#052e16;--callout-ok-border:#166534;"
    "--callout-ok-h:#4ade80;--callout-ok-ul:#86efac;"
    "--callout-blue-bg:#0c1f3a;--callout-blue-border:#1e3a8a;"
    "--callout-blue-title:#60a5fa;--callout-blue-body:#bfdbfe;"
    "--callout-info-bg:#0c1f3a;--callout-info-border:#1e3a8a;--callout-info-h:#60a5fa;"
    "--nps-warn-bg:#2a1400;--nps-warn-border:#78350f;--nps-warn-color:#fbbf24;"
    "--nps-info-bg:#0c1f3a;--nps-info-border:#1e3a8a;--nps-info-color:#60a5fa;"
    "--sec-ht-warn-bg:#2a1400;--sec-ht-warn-color:#fbbf24;"
    "--sec-footer-bg:#1e293b;--sec-footer-border:#334155;"
    "--sec-muted-bg:#1e293b;"
    "--lbtn-blue-bg:#0c1f3a;--lbtn-blue-border:#1e3a8a;--lbtn-blue-text:#60a5fa;"
    "--lbtn-green-bg:#052e16;--lbtn-green-border:#166534;--lbtn-green-text:#4ade80;"
    "--lbtn-orange-bg:#2a0e00;--lbtn-orange-border:#7c2d12;--lbtn-orange-text:#fb923c;"
    "--lbtn-purple-bg:#1a0a2e;--lbtn-purple-border:#5b21b6;--lbtn-purple-text:#a78bfa;"
    "--os-vcf-note-bg:#2a1400;--os-vcf-note-color:#fbbf24;"
    "--chassis-bg:#0f172a;--chassis-border:#334155;--chassis-empty-fill:#1e293b;--chassis-empty-stroke:#334155;--chassis-empty-face:#243b55;--chassis-empty-text:#475569;"
    "--numa-sock-bg:#1e1b4b;--numa-sock-border:#6366f1;--numa-sock-title:#a5b4fc;--numa-box-border:#a78bfa;--numa-box-bg:rgba(167,139,250,.08);--numa-box-title:#c4b5fd;--numa-chip-bg:#1e293b;--numa-chip-border:#3b82f6;--numa-chip-title:#60a5fa;}}"
    ".chassis-bay-slot{transition:transform .12s,filter .12s;transform-origin:center}.chassis-bay-slot:hover{filter:brightness(1.35);stroke-width:2.5px}"
)

# ── Fleet summary tile CSS ────────────────────────────────────────────────────
# Injected inside the fleet tiles <style> block.
FLEET_EXTRA_CSS = (
    ".tile-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));"
    "gap:1rem;margin:1rem 0}"
    ".tile{background:var(--card,#fff);border:1px solid var(--border,#e2e8f0);"
    "border-radius:8px;padding:1.25rem}"
    ".tile h3{margin:0 0 .75rem;font-size:.72rem;text-transform:uppercase;"
    "letter-spacing:.06em;color:var(--text-muted,#94a3b8);font-weight:700}"
    ".tile-wide{grid-column:span 2}"
    ".tile-full{grid-column:1/-1}"
    "h2.tile-section{font-size:.9rem;font-weight:700;color:var(--text-muted,#475569);"
    "margin:2rem 0 .75rem;text-transform:uppercase;letter-spacing:.04em}"
    "@media(max-width:900px){.tile-wide,.tile-full{grid-column:span 1}}"
)

# ── Fleet page CSS (standalone fleet_summary.html) ────────────────────────────
FLEET_PAGE_CSS = (
    ":root{--primary:#2563eb;--success:#16a34a;--warning:#ca8a04;--danger:#dc2626;"
    "--bg:#f8fafc;--card:#fff;--text:#1e293b;--text-muted:#64748b;--border:#e2e8f0;"
    "--th-bg:#f8fafc;--th-hover:#f1f5f9;"
    "--code-bg:#f1f5f9;--card-bg-subtle:#e0f2fe;--pci-bg:#e0f2fe;--pci-color:#0369a1;--accordion-summary-bg:#f8fafc;"
    "--accordion-summary-hover:#f1f5f9;--callout-bg:#eff6ff;--rollup-bg:#f8fafc;--h-color:#0f172a;"
    "--callout-warn-bg:#fefce8;--callout-warn-border:#fef08a;--callout-warn-h:#854d0e;--callout-warn-ul:#713f12;"
    "--callout-ok-bg:#f0fdf4;--callout-ok-border:#bbf7d0;--callout-ok-h:#166534;--callout-ok-ul:#15803d;"
    "--callout-blue-bg:#f0f9ff;--callout-blue-border:#bae6fd;--callout-blue-title:#0369a1;--callout-blue-body:#0c4a6e;"
    "--callout-info-bg:#eff6ff;--callout-info-border:#bfdbfe;--callout-info-h:#1e40af;"
    "--tint-danger-bg:#fef2f2;--tint-danger-border:#fca5a5;--tint-danger-text:#991b1b;"
    "--tint-warning-bg:#fefce8;--tint-warning-border:#fef08a;--tint-warning-text:#854d0e}"
    "[data-theme='dark']{--primary:#60a5fa;--success:#4ade80;--warning:#fbbf24;--danger:#f87171;"
    "--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--text-muted:#94a3b8;--border:#334155;"
    "--th-bg:#1e293b;--th-hover:#263548;"
    "--code-bg:#263548;--card-bg-subtle:#1e293b;--pci-bg:#1e293b;--pci-color:#38bdf8;--accordion-summary-bg:#263548;"
    "--accordion-summary-hover:#2d3f52;--callout-bg:#1e2f4a;--rollup-bg:#1e293b;--h-color:#e2e8f0;"
    "--callout-warn-bg:#2a1400;--callout-warn-border:#78350f;--callout-warn-h:#fbbf24;--callout-warn-ul:#fde68a;"
    "--callout-ok-bg:#052e16;--callout-ok-border:#166534;--callout-ok-h:#4ade80;--callout-ok-ul:#86efac;"
    "--callout-blue-bg:#0c1f3a;--callout-blue-border:#1e3a8a;--callout-blue-title:#60a5fa;--callout-blue-body:#bfdbfe;"
    "--callout-info-bg:#0c1f3a;--callout-info-border:#1e3a8a;--callout-info-h:#60a5fa;"
    "--tint-danger-bg:#2d0a0a;--tint-danger-border:#991b1b;--tint-danger-text:#f87171;"
    "--tint-warning-bg:#2a1400;--tint-warning-border:#78350f;--tint-warning-text:#fbbf24}"
    "@media(prefers-color-scheme:dark){:root:not([data-theme='light']){"
    "--primary:#60a5fa;--success:#4ade80;--warning:#fbbf24;--danger:#f87171;"
    "--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--text-muted:#94a3b8;--border:#334155;"
    "--th-bg:#1e293b;--th-hover:#263548;"
    "--code-bg:#263548;--card-bg-subtle:#1e293b;--pci-bg:#1e293b;--pci-color:#38bdf8;--accordion-summary-bg:#263548;"
    "--accordion-summary-hover:#2d3f52;--callout-bg:#1e2f4a;--rollup-bg:#1e293b;--h-color:#e2e8f0;"
    "--callout-warn-bg:#2a1400;--callout-warn-border:#78350f;--callout-warn-h:#fbbf24;--callout-warn-ul:#fde68a;"
    "--callout-ok-bg:#052e16;--callout-ok-border:#166534;--callout-ok-h:#4ade80;--callout-ok-ul:#86efac;"
    "--callout-blue-bg:#0c1f3a;--callout-blue-border:#1e3a8a;--callout-blue-title:#60a5fa;--callout-blue-body:#bfdbfe;"
    "--callout-info-bg:#0c1f3a;--callout-info-border:#1e3a8a;--callout-info-h:#60a5fa;"
    "--tint-danger-bg:#2d0a0a;--tint-danger-border:#991b1b;--tint-danger-text:#f87171;"
    "--tint-warning-bg:#2a1400;--tint-warning-border:#78350f;--tint-warning-text:#fbbf24}}"
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;"
    "background:var(--bg);padding:2rem;color:var(--text)}"
    ".card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.25rem}"
    ".card-nested{background:var(--code-bg);padding:1.5rem}"
    "code{background:var(--code-bg);padding:.2rem .4rem;border-radius:4px;font-family:monospace}"
    "a{color:var(--primary);text-decoration:none}"
    "a:visited{color:var(--primary)}"
    "a:hover{text-decoration:underline;filter:brightness(1.15)}"
    ".btn-link{color:var(--primary);text-decoration:none;font-weight:600}"
    ".btn-link:visited{color:var(--primary)}"
    ".alert{padding:.85rem 1.15rem;border-radius:6px;margin:1rem 0;font-size:.88rem;line-height:1.5;border:1px solid transparent}"
    ".alert-warning{background:var(--callout-warn-bg,#fefce8);border-color:var(--callout-warn-border,#fef08a);border-left:4px solid var(--warning,#ca8a04);color:var(--callout-warn-h,#854d0e)}"
    ".alert-warning strong,.alert-warning h4{color:var(--callout-warn-h,#854d0e)}"
    ".alert-warning p,.alert-warning ul,.alert-warning li{color:var(--callout-warn-ul,#713f12)}"
    ".alert-danger{background:var(--tint-danger-bg,#fef2f2);border-color:var(--tint-danger-border,#fca5a5);border-left:4px solid var(--danger,#dc2626);color:var(--tint-danger-text,#991b1b)}"
    ".alert-danger strong,.alert-danger h4{color:var(--tint-danger-text,#991b1b)}"
    ".alert-danger p,.alert-danger ul,.alert-danger li{color:var(--tint-danger-text,#991b1b)}"
    ".alert-success{background:var(--callout-ok-bg,#f0fdf4);border-color:var(--callout-ok-border,#bbf7d0);border-left:4px solid var(--success,#16a34a);color:var(--callout-ok-h,#166534)}"
    ".alert-info{background:var(--callout-blue-bg,#f0f9ff);border-color:var(--callout-blue-border,#bae6fd);border-left:4px solid var(--primary,#2563eb);color:var(--callout-blue-title,#0369a1)}"
    ".container{max-width:1500px;margin:0 auto}"
    "h1{margin-bottom:.25rem}"
    "h2{font-size:.9rem;font-weight:700;color:var(--text-muted);margin:2rem 0 .75rem;"
    "text-transform:uppercase;letter-spacing:.04em}"
    "table{width:100%;border-collapse:collapse;background:var(--card);border-radius:8px;"
    "border:1px solid var(--border);margin-top:1rem}"
    "th,td{padding:.75rem 1rem;text-align:left;border-bottom:1px solid var(--border);font-size:.88rem}"
    "th{background:var(--th-bg);font-weight:600;cursor:pointer;user-select:none;white-space:nowrap}"
    "th:hover{background:var(--th-hover)}"
    ".sort-ind{margin-left:.3rem;opacity:.35;font-size:.7rem;vertical-align:middle}"
    "th.sorted .sort-ind{opacity:1}"
    ".badge{display:inline-block;padding:.25rem .6rem;border-radius:4px;font-weight:600;font-size:.8rem}"
    ".badge.success{background:#dcfce7;color:var(--success)}"
    ".badge.warning{background:#fef9c3;color:var(--warning)}"
    ".badge.danger{background:#fee2e2;color:var(--danger)}"
    ".badge.info{background:#e0f2fe;color:#0369a1}"
    ".badge.cyber-recovery{background:#f3e8ff;color:#7c3aed}"
    "[data-theme='dark'] .badge.success{background:#14532d;color:#4ade80}"
    "[data-theme='dark'] .badge.warning{background:#422006;color:#fbbf24}"
    "[data-theme='dark'] .badge.danger{background:#450a0a;color:#f87171}"
    "[data-theme='dark'] .badge.info{background:#0c2240;color:#60a5fa}"
    "[data-theme='dark'] .badge.cyber-recovery{background:#2e1065;color:#c4b5fd}"
    "@media(prefers-color-scheme:dark){"
    ":root:not([data-theme='light']) .badge.success{background:#14532d;color:#4ade80}"
    ":root:not([data-theme='light']) .badge.warning{background:#422006;color:#fbbf24}"
    ":root:not([data-theme='light']) .badge.danger{background:#450a0a;color:#f87171}"
    ":root:not([data-theme='light']) .badge.info{background:#0c2240;color:#60a5fa}"
    ":root:not([data-theme='light']) .badge.cyber-recovery{background:#2e1065;color:#c4b5fd}}"
    ".btn-link{color:var(--primary);text-decoration:none;font-weight:600}"
    "#themeToggle{background:none;border:1px solid var(--border);color:var(--text-muted);"
    "border-radius:4px;padding:.2rem .55rem;font-size:.78rem;cursor:pointer;transition:background .12s}"
    "#themeToggle:hover{background:var(--th-bg)}"
)
