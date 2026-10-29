"""Clarity-aligned semantic report layout; no framework or network dependency."""
import html
import re

from vcf_hci.ui_clarity import APPEARANCE_JS

CLARITY_REPORT_CSS = """
/* Clarity Core 5.7.0 assets — MIT License

Copyright (c) 2016-2021 VMware, Inc.  All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
/* Appearance remains available above every report tab. */
.report-appearance-bar{position:sticky;top:0;z-index:300;display:flex;align-items:center;justify-content:flex-end;height:44px;box-sizing:border-box;padding:3px 24px;background:var(--card);border-bottom:1px solid var(--border)}
.report-appearance-bar+.tab-bar{top:44px}
body:has(>.report-appearance-bar) .tab-nav{top:44px}
body:has(>.report-appearance-bar) .report-help-nav{top:100px}
html[data-report-embedded='true'] .report-appearance-bar{display:none}
html[data-report-embedded='true'] body .tab-nav{top:0}
html[data-report-embedded='true'] body .report-help-nav{top:56px}
/* Combined fleet reports use one shared navigation/search/appearance header. */
body .tab-bar:has(>.report-tabs){display:grid;grid-template-columns:minmax(0,1.15fr) minmax(260px,1fr) auto;gap:16px;min-height:48px;top:0;overflow:visible;align-items:center;padding:0 16px}
.report-tabs{display:flex;align-items:stretch;gap:0;min-width:0;overflow-x:auto;scrollbar-width:thin}
.report-tabs .tab-btn-host{max-width:180px;overflow:hidden;text-overflow:ellipsis}
body .tab-bar .host-picker-bar{margin:0;padding:4px 0;min-width:0;flex-wrap:nowrap;justify-content:center}
.host-search{position:relative;display:block;flex:1 1 150px;min-width:0;max-width:240px}
.host-search>.ui-icon{position:absolute;inset-inline-start:10px;top:50%;transform:translateY(-50%);margin:0;pointer-events:none;color:var(--text-muted)}
body .tab-bar .host-picker-bar select{flex:1 1 160px;min-width:0;width:160px}
.tab-bar>.report-appearance-bar{position:static;height:auto;padding:0;background:transparent;border:0;min-width:0}
.tab-bar .appearance-controls{float:none;margin:0}
html[data-report-header='unified']{scroll-padding-top:calc(var(--report-header-height,48px) + 16px)}
html[data-report-header='unified'] .report-help-nav{top:calc(var(--report-header-height,48px) + 56px)}
@media(max-width:1000px){body .tab-bar:has(>.report-tabs){grid-template-columns:minmax(0,1fr) auto;gap:4px 12px}.report-tabs{grid-column:1/-1}}
@media(max-width:600px){.report-appearance-bar{padding-inline:12px}body .tab-bar:has(>.report-tabs){grid-template-columns:minmax(0,1fr);gap:4px;padding:0 8px}.tab-bar>.report-appearance-bar{justify-self:end;padding-bottom:4px}body .tab-bar .host-picker-bar{width:100%;box-sizing:border-box}.host-search{max-width:none}}
@media print{.report-appearance-bar{display:none!important}}
:root{--report-table-padding:8px 12px;--report-table-font:14px}
html[data-report-density='compact']{--report-table-padding:4px 8px;--report-table-font:13px}
body table:not(.chassis-layout){border-collapse:separate;border-spacing:0;background:var(--card);border:1px solid var(--border);border-radius:3px;font-size:var(--report-table-font);line-height:1.5}
body table:not(.chassis-layout) th,body table:not(.chassis-layout) td{padding:var(--report-table-padding);vertical-align:top;border:0;border-bottom:1px solid var(--border);text-align:left}
body table:not(.chassis-layout) th{background:var(--th-bg);font-weight:600;color:var(--text)}
body table:not(.chassis-layout) tbody tr:last-child td{border-bottom:0}
body table:not(.chassis-layout) tbody tr:hover{background:var(--th-bg)}
body table .report-number,body table [data-column-key='ram_gb'],body table [data-column-key='gpu_count']{text-align:right;font-variant-numeric:tabular-nums}
body table .inv-sticky{border-inline-end:1px solid var(--border)}
body table caption{text-align:left;padding:8px 12px;font-weight:600;color:var(--text)}
.report-help-layout{display:grid;grid-template-columns:minmax(180px,240px) minmax(0,1fr);gap:24px;align-items:start;padding:24px;max-width:1600px;margin:0;text-align:left}
.report-help-nav{position:sticky;top:76px;max-height:calc(100vh - 100px);overflow:auto;border-inline-end:1px solid var(--border);padding-inline-end:16px}
.report-help-nav summary{font-weight:600;cursor:pointer;padding:8px 0}
.report-help-nav ol{list-style:none;margin:0;padding:0}
.report-help-nav a{display:block;padding:6px 8px;color:var(--text-muted);text-decoration:none;border-inline-start:3px solid transparent;overflow-wrap:anywhere;font-size:14px;line-height:1.4}
.report-help-nav a[data-level='3']{padding-inline-start:20px;font-size:12px}
.report-help-nav a:hover{background:var(--th-bg);color:var(--text)}
.report-help-nav a[aria-current='location']{color:var(--primary);border-inline-start-color:var(--primary);background:var(--th-bg)}
.report-help-content{min-width:0;padding:24px;text-align:left;line-height:1.6}
.report-help-heading{display:flex;gap:16px;align-items:start;justify-content:space-between;flex-wrap:wrap;border-bottom:1px solid var(--border);padding-bottom:16px;margin-bottom:24px}
.report-help-heading h1{margin:0;font-size:24px}
.report-help-content .docs-embedded-content{font-size:14px;line-height:1.6;overflow-wrap:anywhere}
.report-help-content .docs-embedded-content [align='center'],.report-help-content .docs-embedded-content [style*='text-align:center'],.report-help-content .docs-embedded-content [style*='text-align: center']{text-align:left!important;justify-content:flex-start!important}
.report-help-content .docs-embedded-content th{cursor:default;user-select:text}
.report-help-content .docs-embedded-content table{display:block;overflow:auto;max-width:100%}
.report-help-content .docs-embedded-content h2{font-size:20px}
.report-help-content .docs-embedded-content h3{font-size:16px}
.report-help-content .docs-embedded-content pre{max-width:100%;white-space:pre;overflow:auto}
.report-group-tags{display:flex;gap:4px;flex-wrap:wrap;min-width:120px;max-width:240px}
.report-group-tag{padding:2px 6px;border:1px solid var(--border);border-radius:3px;background:var(--th-bg);color:var(--text);font-size:12px;line-height:1.4;overflow-wrap:anywhere}
#invRoot .inv-table th,#invRoot .inv-table td{border-inline:0;border-bottom:1px solid var(--border);vertical-align:top}
#invRoot .inv-table thead th{background:var(--th-bg);color:var(--text);line-height:1.4}
#invRoot .inv-table tbody tr:hover td{background:var(--th-bg)}
#invRoot .inv-filters{gap:12px;padding:12px 0;border-bottom:1px solid var(--border);margin-bottom:12px}
#invRoot .inv-filters label{display:inline-flex;align-items:center;gap:8px;color:var(--text-muted)}
#invRoot .inv-filters select[multiple]{min-height:72px;max-width:220px}
#invRoot .inv-table [data-column-key='server_groups']{white-space:normal;min-width:140px}
@media(max-width:800px){.report-help-layout{grid-template-columns:1fr;padding:16px;gap:16px}.report-help-nav{position:static;max-height:none;border-inline-end:0;border-bottom:1px solid var(--border);padding:0 0 12px}.report-help-content{padding:16px}.report-help-nav ol{max-height:240px;overflow:auto}.report-help-heading h1{font-size:22px}.report-density-control{margin-inline-start:0}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;animation:none!important;transition:none!important}}
@media print{.report-help-nav,.report-density-control,.clarity-theme-toggle{position:relative;display:none!important}.report-help-layout{display:block;padding:0}.report-help-content{padding:0}.report-help-content .docs-embedded-content [align='center'],.report-help-content .docs-embedded-content [style*='text-align:center'],.report-help-content .docs-embedded-content [style*='text-align: center']{text-align:left!important;justify-content:flex-start!important}
.report-help-content .docs-embedded-content th{cursor:default;user-select:text}
.report-help-content .docs-embedded-content table{display:table;overflow:visible}}
"""


def build_help_layout(content: str, version: str) -> str:
    """Add section navigation without changing documentation content or links."""
    links = []
    count = 0

    def heading(match):
        nonlocal count
        tag, attrs, body = match.group(1), match.group(2) or '', match.group(3)
        count += 1
        identifier = re.search(r'\bid=["\']([^"\']+)["\']', attrs)
        anchor = html.unescape(identifier.group(1)) if identifier else f'help-section-{count}'
        if not identifier:
            attrs += f' id="{anchor}"'
        label = html.unescape(re.sub(r'<[^>]+>', '', body)).strip()
        links.append(f'<li><a href="#{html.escape(anchor, quote=True)}" data-help-section="{html.escape(anchor, quote=True)}" data-level="{tag[1]}">{html.escape(label)}</a></li>')
        return f'<{tag}{attrs}>{body}</{tag}>'

    content = re.sub(r'<(h[23])(\s[^>]*)?>(.*?)</\1\s*>', heading, content, flags=re.I | re.S)
    return (
        '<div class="report-help-layout">'
        '<nav class="report-help-nav" aria-label="User guide sections"><details open><summary>On this page</summary><ol>'
        + ''.join(links) + '</ol></details></nav>'
        '<article class="card report-help-content"><header class="report-help-heading">'
        '<h1>📖 VCF Readiness — User Guide &amp; Reference</h1>'
        f'<span class="badge info">v{html.escape(version)} Standalone</span></header>'
        f'<div class="docs-embedded-content">{content}</div></article></div>'
    )


CLARITY_REPORT_JS = APPEARANCE_JS + """
(function(){
 function init(){
  var root=document.documentElement,button=document.getElementById('themeToggle');
  root.removeAttribute('data-report-embedded');
  function theme(){
   var dark=root.getAttribute('data-theme')==='dark';
   if(dark)root.setAttribute('cds-theme','dark');else root.removeAttribute('cds-theme');
   var value=dark?'dark':'light';try{localStorage.setItem('vcf-theme',value);localStorage.setItem('vcf-report-theme',value);}catch(e){}
   document.querySelectorAll('iframe').forEach(function(frame){if(frame.contentWindow)frame.contentWindow.postMessage({type:'vcf-report-theme',theme:value},'*');});
   window.VCFAppearance.theme(button,dark);
  }
  window.addEventListener('storage',function(event){if((event.key==='vcf-theme'||event.key==='vcf-report-theme')&&(event.newValue==='dark'||event.newValue==='light')&&root.getAttribute('data-theme')!==event.newValue)root.setAttribute('data-theme',event.newValue);});
  theme();new MutationObserver(theme).observe(root,{attributes:true,attributeFilter:['data-theme']});
  var density=document.getElementById('invDensity'),densityButton=null;
  if(button){
   densityButton=document.getElementById('reportDensityToggle')||document.createElement('button');densityButton.type='button';densityButton.id='reportDensityToggle';
   var group=window.VCFAppearance.group(button,densityButton);
   var appearanceBar=button.closest('.report-appearance-bar')||document.createElement('div');appearanceBar.className='report-appearance-bar';
   var reportHeader=document.querySelector('.tab-bar:has(>.report-tabs)');
   if(reportHeader){
    reportHeader.append(appearanceBar);root.dataset.reportHeader='unified';
    function headerSize(){root.style.setProperty('--report-header-height',reportHeader.getBoundingClientRect().height+'px');}
    if('ResizeObserver' in window)new ResizeObserver(headerSize).observe(reportHeader);
    headerSize();
   }else document.body.prepend(appearanceBar);
   appearanceBar.append(group);
  }
  function sendAppearance(frame){
   if(frame.contentWindow)frame.contentWindow.postMessage({type:'vcf-report-appearance',density:root.dataset.reportDensity||'comfortable'},'*');
  }
  window.addEventListener('message',function(event){
   var data=event.data;if(!data||typeof data!=='object')return;
   if(data.type==='vcf-report-appearance-request'&&document.querySelector('.report-appearance-bar')){
    var frame=Array.from(document.querySelectorAll('iframe')).find(function(item){return item.contentWindow===event.source;});
    if(frame)sendAppearance(frame);
   }
   if(data.type==='vcf-report-appearance'&&window.parent!==window&&event.source===window.parent&&(data.density==='compact'||data.density==='comfortable')){
    root.dataset.reportEmbedded='true';setDensity(data.density,false);
   }
  });
  function setDensity(value,persist){
   value=value==='compact'?'compact':'comfortable';root.dataset.reportDensity=value;
   if(density&&density.value!==value){density.value=value;density.dispatchEvent(new Event('change',{bubbles:true}));}
   window.VCFAppearance.density(densityButton,value);
   if(persist){try{localStorage.setItem('vcf-report-density',value);}catch(e){}}
   document.querySelectorAll('iframe').forEach(sendAppearance);
  }
  var initialDensity=density?density.value:'comfortable';
  if(!density){try{initialDensity=localStorage.getItem('vcf-report-density')||initialDensity;}catch(e){}}
  setDensity(initialDensity,false);
  if(window.parent!==window)window.parent.postMessage({type:'vcf-report-appearance-request'},'*');
  if(densityButton)new MutationObserver(function(){window.VCFAppearance.density(densityButton,root.dataset.reportDensity);}).observe(root,{attributes:true,attributeFilter:['data-report-density']});
  if(density)density.addEventListener('change',function(){setDensity(density.value,true);});
  if(densityButton)densityButton.addEventListener('click',function(){setDensity(root.dataset.reportDensity==='compact'?'comfortable':'compact',true);});
  var nav=document.querySelector('.report-help-nav');
  if(nav){
   var links=Array.from(nav.querySelectorAll('[data-help-section]'));
   function current(id){links.forEach(function(link){if(link.dataset.helpSection===id)link.setAttribute('aria-current','location');else link.removeAttribute('aria-current');});}
   function navigate(){var id;try{id=decodeURIComponent(location.hash.slice(1));}catch(e){return;}if(!links.some(function(link){return link.dataset.helpSection===id;}))return;if(typeof window.showTab==='function')window.showTab(2);current(id);try{history.replaceState(null,'','#'+encodeURIComponent(id));}catch(e){}var target=document.getElementById(id);if(target){target.tabIndex=-1;target.focus({preventScroll:true});target.scrollIntoView({block:'start'});}}
   nav.addEventListener('click',function(event){var link=event.target.closest('[data-help-section]');if(!link)return;if(typeof window.showTab==='function')window.showTab(2);current(link.dataset.helpSection);});
   window.addEventListener('hashchange',navigate);navigate();
   if('IntersectionObserver' in window){var observer=new IntersectionObserver(function(entries){var visible=entries.filter(function(entry){return entry.isIntersecting;}).sort(function(a,b){return a.boundingClientRect.top-b.boundingClientRect.top;});if(visible.length)current(visible[0].target.id);},{rootMargin:'-76px 0px -60% 0px'});links.forEach(function(link){var target=document.getElementById(link.dataset.helpSection);if(target)observer.observe(target);});}
   var details=nav.querySelector('details');if(details&&window.matchMedia('(max-width:800px)').matches)details.open=false;
  }
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
"""
