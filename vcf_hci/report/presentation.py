"""Shared offline report presentation tokens and accessible browser primitives.

Static assets remain Python constants so installed and bundled distributions use
exactly the same sources without a frontend build or package-data loader.
"""

REPORT_UI_CSS = """
:root,[data-theme='light']{
 color-scheme:light;--report-body:14px;--report-small:12px;--report-space:8px;--report-control:32px;
 --report-radius:4px;--bg:#f4f6f8;--card:#fff;--text:#243746;--text-muted:#526777;
 --border:#c5cdd4;--control-border:#6c8290;--primary:#006a91;--accent:#006a91;--success:#146c43;--warning:#805000;--danger:#b4232d;
 --th-bg:#edf1f4;--code-bg:#edf1f4;--h-color:#243746;--report-success-bg:#e2f3e9;
 --report-warning-bg:#fff1cd;--report-danger-bg:#fde7e9;--report-unknown-bg:#edf1f4;
}
[data-theme='dark']{
 color-scheme:dark;--bg:#17242d;--card:#21333f;--text:#e5edf2;--text-muted:#b5c6d1;--border:#647b8a;--control-border:#8ba2b1;
 --primary:#78c9f0;--accent:#78c9f0;--success:#8be0b1;--warning:#ffd17a;--danger:#ffabb0;
 --th-bg:#293f4c;--code-bg:#293f4c;--h-color:#e5edf2;--report-success-bg:#143d2c;
 --report-warning-bg:#483614;--report-danger-bg:#4b242b;--report-unknown-bg:#293f4c;
}
.report-sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
html{font-size:16px;scroll-padding-top:76px}
body{font-family:'CDS City','Metropolis','Avenir Next','Segoe UI',Arial,sans-serif;font-size:var(--report-body);line-height:1.45}
button,input,select,textarea{--border:var(--control-border);font:inherit;color:inherit;box-sizing:border-box}
button,select,input:not([type='checkbox']):not([type='radio']){min-height:var(--report-control)}
button{cursor:pointer}
:where(button,a,input,select,textarea,summary,[tabindex]):focus-visible{outline:2px solid var(--primary);outline-offset:3px}
[hidden]{display:none!important}
.container{max-width:1600px;padding:24px;margin:0 auto;min-width:0}
body h1{font-size:24px;line-height:1.3;letter-spacing:normal;margin:16px 0 12px;overflow-wrap:anywhere}
body h2{font-size:18px;text-transform:none;letter-spacing:normal;color:var(--text);margin:24px 0 12px}
body h3{font-size:16px;text-transform:none;letter-spacing:normal}
body small{font-size:var(--report-small)}
body .card,body .tile{border-radius:var(--report-radius);box-shadow:none}
body .tile-grid{align-items:start;gap:16px}
body .tile{min-width:0;overflow-wrap:anywhere}
body .tile h3{font-size:14px;text-transform:none;letter-spacing:normal;line-height:1.4}
body .tab-bar{background:var(--card);border-bottom:1px solid var(--border);box-shadow:none;gap:0;flex-wrap:wrap;padding:0 24px}
body .tab-bar .tab-btn,body .tab-nav .tab-btn{
 background:transparent;color:var(--text-muted);border:0;border-bottom:3px solid transparent;
 border-radius:0;font-size:14px;font-weight:500;min-height:44px;padding:10px 16px;box-shadow:none
}
body .tab-bar .tab-btn:hover,body .tab-nav .tab-btn:hover{background:var(--th-bg);color:var(--text)}
body .tab-bar .tab-btn.active,body .tab-nav .tab-btn.active{color:var(--primary);background:transparent;border-bottom-color:var(--primary);font-weight:600}
body .host-picker-bar{flex-wrap:wrap;min-width:0}
body .host-picker-bar input,body .host-picker-bar select{max-width:100%}
body .tab-nav{background:var(--card);border-bottom:1px solid var(--border);gap:0}
body .badge,body .inv-chip{display:inline-flex;align-items:center;justify-content:center;box-sizing:border-box;min-block-size:24px;max-inline-size:32ch;padding:4px 8px;line-height:16px;border-radius:3px;vertical-align:middle;white-space:normal;overflow-wrap:anywhere}
/* Override legacy per-badge padding/borders so wrapped heights stay consistent. */
body .badge{font-size:12px;padding:4px 8px!important;border-width:0!important;line-height:16px!important}
body .badge.success{color:var(--success);background:var(--report-success-bg)}
body .badge.warning{color:var(--warning);background:var(--report-warning-bg)}
body .badge.danger{color:var(--danger);background:var(--report-danger-bg)}
body .badge.info{color:var(--primary);background:var(--report-unknown-bg)}
.fleet-leading-grid{display:grid;grid-template-columns:minmax(340px,.95fr) minmax(0,1.35fr);grid-template-rows:auto auto auto;gap:8px 16px;align-items:stretch;margin:20px 0 24px}
.fleet-leading-assessment{display:contents}
.fleet-resource-section,.fleet-leading-assessment .report-overview{display:grid;grid-template-rows:subgrid;grid-row:span 3;min-width:0;margin:0}
.fleet-resource-section>h2,.fleet-leading-assessment .report-overview h2{margin:0}
.fleet-resource-section>p,.fleet-leading-assessment .report-overview>p{margin:0 0 8px;font-size:12px;color:var(--text-muted)}
.fleet-leading-assessment .report-overview-grid{gap:12px;align-items:stretch}
.fleet-leading-assessment .report-overview-card{padding:12px}
.fleet-leading-assessment .report-overview-card h3{font-size:14px}
.fleet-leading-assessment .report-overview-card li{margin:2px 0}
.fleet-leading-assessment .report-overview-card a,.fleet-leading-assessment .report-metric-empty{align-items:start;padding:3px 0}
.fleet-leading-assessment .report-overview-card p.report-qualification-note{margin:12px 0 0;font-size:12px}
.fleet-status-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;align-items:stretch;margin:0 0 24px}
.fleet-status-grid>.tile{min-block-size:168px;box-sizing:border-box}
.fleet-status-secondary{grid-template-columns:repeat(2,minmax(0,1fr))}
.fleet-tpm-summary{display:flex;flex-wrap:wrap;justify-content:space-between;gap:4px 12px;padding:6px 0;border-top:1px solid var(--border);font-size:12px}
.fleet-tpm-summary strong span{font-weight:400;color:var(--text-muted)}
.fleet-resource-metrics{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin:12px 0}
.fleet-resource-summary{min-width:0;display:flex;flex-direction:column;padding:16px}
.fleet-resource-summary .fleet-resource-metrics{margin-top:0}
.fleet-resource-summary .resource-metric-card{min-block-size:76px;box-sizing:border-box}
.fleet-sizing-note{margin-top:auto;padding:8px 12px;background:var(--th-bg);border-left:3px solid var(--primary);font-size:12px;color:var(--text-muted)}
.fleet-sizing-note p{margin:0 0 4px}
.fleet-sizing-note summary{cursor:pointer;color:var(--primary);font-weight:600}
.fleet-sizing-note details>p{margin:8px 0 0}
.fleet-resource-links{display:flex;flex-wrap:wrap;gap:12px;margin-top:10px;font-size:12px}
.fleet-leading-assessment>.report-filter-context{grid-column:1/-1}
@media(max-width:1100px){.fleet-leading-grid{grid-template-columns:1fr}.fleet-leading-assessment .report-overview-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.fleet-status-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
.report-overview{margin:20px 0 24px}
.report-overview>p{color:var(--text-muted);margin:8px 0 16px;font-size:12px}
.report-overview-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}
.report-overview-card{padding:16px;border:1px solid var(--border);border-radius:4px;background:var(--card);min-width:0}
.report-overview-card h3{margin:0 0 4px}
.report-overview-card p{margin:0 0 12px;color:var(--text-muted);font-size:12px}
.report-overview-card ul{list-style:none;padding:0;margin:0}
.report-overview-card li{margin:4px 0}
.report-overview-card a,.report-metric-empty{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:4px 0;color:var(--text);text-decoration:none}
.report-overview-card a:hover{text-decoration:underline}
.report-component-row{position:relative;display:flex;align-items:center;justify-content:space-between;gap:8px;padding:3px 0}
.report-component-label{display:inline-flex;align-items:center;gap:6px;min-width:0}
.report-overview-card a.report-component-link{display:inline;padding:0;color:var(--primary)}
.report-overview-card a.report-component-count{min-width:24px;min-height:24px;justify-content:flex-end;padding:0}
.report-info{display:inline-flex;align-items:center}
button.report-info-trigger{min-height:24px;min-width:24px;width:24px;height:24px;padding:0;border:1px solid currentColor;border-radius:50%;background:transparent;color:var(--primary);font-size:12px;font-weight:700}
.report-info-tooltip{position:absolute;inset-inline:0;bottom:100%;z-index:20;padding:10px;background:var(--card);color:var(--text);border:1px solid var(--primary);border-radius:4px;font-size:12px;line-height:1.45;visibility:hidden}
.report-info-tooltip:after{content:'';position:absolute;inset-inline:0;bottom:-12px;height:12px}
.report-info:hover .report-info-tooltip,.report-info:focus-within .report-info-tooltip{visibility:visible}
.report-info.tooltip-dismissed .report-info-tooltip{visibility:hidden}
.report-status:before{display:inline-block;width:1.2em;font-weight:700}
.report-status-success{color:var(--success)}.report-status-success:before{content:'✓'}
.report-status-info{color:var(--primary)}.report-status-info:before{content:'i'}
.report-status-warning{color:var(--warning)}.report-status-warning:before{content:'▲'}
.report-status-danger{color:var(--danger)}.report-status-danger:before{content:'!'}
.report-status-unknown{color:var(--text-muted)}.report-status-unknown:before{content:'?'}
.report-filter-context{padding:12px 16px;border:1px solid var(--border);border-left:3px solid var(--primary);background:var(--card);margin:12px 0;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.report-filter-context button{background:var(--card);color:var(--primary);border:1px solid var(--border);border-radius:3px;padding:4px 12px}
.report-evidence-controls{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
.report-evidence-controls button{background:var(--card);border:1px solid var(--border);border-radius:3px;color:var(--primary);padding:4px 12px;font-size:14px}
.report-evidence{border:1px solid var(--border);border-radius:4px;margin:12px 0;background:var(--card)}
.report-evidence>summary{padding:12px 16px;cursor:pointer;font-weight:600;background:var(--th-bg)}
.report-evidence-body{padding:16px;overflow:auto}
.report-scroll-region{overflow:auto;max-width:100%}
@media(max-width:800px){
 .report-overview-grid,.fleet-leading-assessment .report-overview-grid,.fleet-status-grid{grid-template-columns:1fr}
 .fleet-status-grid>.tile{min-block-size:0}
 body .container{padding:16px}
 body .tab-bar{position:relative;padding:0 8px}
 body .host-picker-bar{width:100%;margin:0;padding:8px}
 body .tab-bar .tab-btn{padding:8px}
 body .tab-bar .tab-btn-host:not(.active){display:none}
 body h1{font-size:22px}
}
@media print{
 .report-info-trigger,.report-info-tooltip:after{display:none}
 .report-component-label,.report-info{display:block}
 .report-component-row .report-info-tooltip{visibility:visible!important;position:static;display:block;padding:4px 0;border:0}
 .tab-bar,.tab-nav,.inv-toolbar,.inv-filters,.report-filter-context{display:none!important}
 .report-evidence-body{overflow:visible}
 .report-overview-card{break-inside:avoid}
}
"""

REPORT_UI_JS = """<script>
(function(){
 'use strict';
 if(window.VCFReportUI)return;
 var selected=null;
 var dialogState=null;
 var resizeHandles=new WeakSet();
 var api=window.VCFReportUI={};
 document.addEventListener('mouseover',function(e){
  var info=e.target.closest('[data-info-tooltip]');
  if(info&&!info.contains(e.relatedTarget))info.classList.remove('tooltip-dismissed');
 });
 document.addEventListener('focusin',function(e){
  var info=e.target.closest('[data-info-tooltip]');if(info)info.classList.remove('tooltip-dismissed');
 });
 document.addEventListener('keydown',function(e){
  if(e.key!=='Escape')return;
  document.querySelectorAll('[data-info-tooltip]:hover,[data-info-tooltip]:focus-within').forEach(function(info){
   info.classList.add('tooltip-dismissed');
  });
 });
 api.hasSelection=function(){return !!selected;};
 api.matchesHost=function(row){var index=row.getAttribute('data-host-idx');return !selected||(index!==null&&selected.indices.indexOf(Number(index))>=0);};
 function context(){
  document.querySelectorAll('.report-filter-context').forEach(function(el){
   el.hidden=!selected;
   el.querySelector('span').textContent=selected?selected.label+' — '+selected.indices.length+' host(s).':'';
  });
 }
 function applySelection(){
  context();
  if(window.applyInvFilters)window.applyInvFilters();
  window.dispatchEvent(new Event('vcf-overview-filter'));
 }
 function hashTarget(){try{return document.getElementById(decodeURIComponent(location.hash.slice(1)));}catch(e){return null;}}
 function reveal(target,focus){
  if(!target)return;
  for(var p=target.parentElement;p;p=p.parentElement){if(p.tagName==='DETAILS')p.open=true;}
  if(focus){target.setAttribute('tabindex','-1');target.focus({preventScroll:true});target.scrollIntoView({block:'center'});}
 }
 api.reveal=reveal;
 api.syncTabs=function(nav){
  nav.querySelectorAll('[role="tab"]').forEach(function(button){
   var active=button.classList.contains('active');
   if(button.dataset.tabTarget)button.setAttribute('aria-controls',button.dataset.tabTarget);
   button.setAttribute('aria-selected',String(active));button.tabIndex=active?0:-1;
   var panel=document.getElementById(button.getAttribute('aria-controls'));
   if(panel){panel.setAttribute('role','tabpanel');panel.hidden=!active;panel.setAttribute('aria-labelledby',button.id);}
  });
 };
 function tabs(nav,buttons,panelId,label){
  if(!nav)return;
  nav.setAttribute('role','tablist');nav.setAttribute('aria-label',label);
  buttons.forEach(function(b,i){
   var id=panelId(b,i);var panel=document.getElementById(id);if(!panel)return;
   b.id=b.id||'report-tab-'+id;b.setAttribute('role','tab');b.setAttribute('aria-controls',id);
   panel.setAttribute('role','tabpanel');
   if(!panel.hasAttribute('tabindex'))panel.tabIndex=0;
  });
  api.syncTabs(nav);
  new MutationObserver(function(){api.syncTabs(nav);}).observe(nav,{subtree:true,attributes:true,attributeFilter:['class','data-tab-target']});
 }
 api.openDialog=function(id){
  if(dialogState)return;
  var backdrop=document.getElementById(id);if(!backdrop)return;
  var card=backdrop.querySelector('[role="dialog"]');if(!card)return;
  dialogState={backdrop:backdrop,card:card,trigger:document.activeElement,overflow:document.body.style.overflow,siblings:[]};
  for(var node=backdrop;node&&node!==document.body;node=node.parentElement){
   Array.from(node.parentElement.children).forEach(function(sibling){
    if(sibling!==node&&!sibling.matches('script,style')){dialogState.siblings.push([sibling,sibling.inert]);sibling.inert=true;}
   });
  }
  backdrop.hidden=false;backdrop.classList.add('open');document.body.style.overflow='hidden';
  card.tabIndex=-1;
  (card.querySelector('button,[href],input,select,[tabindex="0"]')||card).focus();
 };
 api.closeDialog=function(){
  if(!dialogState)return;
  var state=dialogState;dialogState=null;
  state.backdrop.classList.remove('open');state.backdrop.hidden=true;
  state.siblings.forEach(function(pair){pair[0].inert=pair[1];});document.body.style.overflow=state.overflow;
  if(state.trigger&&state.trigger.isConnected)state.trigger.focus();
 };
 document.addEventListener('keydown',function(e){
  if(!dialogState)return;
  if(e.key==='Escape'){e.preventDefault();e.stopImmediatePropagation();api.closeDialog();return;}
  if(e.key==='Tab'){
   var items=Array.from(dialogState.card.querySelectorAll('button,[href],input,select,textarea,[tabindex]')).filter(function(el){return !el.disabled&&el.tabIndex>=0&&el.getClientRects().length;});
   var first=items[0]||dialogState.card,last=items[items.length-1]||first;
   if(e.shiftKey&&(document.activeElement===first||document.activeElement===dialogState.card)){e.preventDefault();last.focus();}
   else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}
  }
 },true);
 api.setupResizers=function(root){
  (root||document).querySelectorAll('table.inv-table,table.sortable-table').forEach(function(table){
   table.querySelectorAll('thead th').forEach(function(th){
    var handle=th.querySelector('.col-resizer');
    if(!handle){handle=document.createElement('span');handle.className='col-resizer';th.appendChild(handle);}
    if(resizeHandles.has(handle))return;resizeHandles.add(handle);
    handle.tabIndex=0;handle.setAttribute('role','separator');handle.setAttribute('aria-orientation','vertical');
    handle.setAttribute('aria-label','Resize '+th.textContent.trim()+' column');
    handle.setAttribute('aria-valuemin','80');handle.setAttribute('aria-valuemax','800');
    function width(value){value=Math.max(80,Math.min(800,value));th.style.width=value+'px';th.style.minWidth=value+'px';handle.setAttribute('aria-valuenow',String(value));}
    handle.addEventListener('click',function(e){e.stopPropagation();});
    handle.addEventListener('keydown',function(e){
     if(e.key==='ArrowLeft'||e.key==='ArrowRight'){e.preventDefault();e.stopPropagation();width(th.offsetWidth+(e.key==='ArrowRight'?16:-16));}
    });
    handle.addEventListener('mousedown',function(e){
     e.preventDefault();e.stopPropagation();var start=e.pageX,initial=th.offsetWidth;handle.classList.add('resizing');
     function move(event){width(initial+event.pageX-start);}
     function end(){handle.classList.remove('resizing');document.removeEventListener('mousemove',move);document.removeEventListener('mouseup',end);}
     document.addEventListener('mousemove',move);document.addEventListener('mouseup',end);
    });
   });
  });
 };
 window.setupTableResizers=api.setupResizers;
 window.addEventListener('message',function(e){
  var data=e.data;if(!data||typeof data!=='object')return;
  var owned=Array.from(document.querySelectorAll('iframe')).some(function(frame){return frame.contentWindow===e.source;});
  if(data.type==='vcf-report-theme-request'&&owned){e.source.postMessage({type:'vcf-report-theme',theme:document.documentElement.getAttribute('data-theme')||'dark'},'*');return;}
  if(data.type==='vcf-report-mask-request'&&owned){var mask=document.getElementById('maskPII');e.source.postMessage({type:'vcf-report-mask',checked:!!(mask&&mask.checked)},'*');return;}
  if(data.type==='vcf-report-mask'&&window.parent!==window&&e.source===window.parent&&typeof data.checked==='boolean'){
   var checkbox=document.getElementById('maskPII');if(checkbox&&checkbox.checked!==data.checked){checkbox.checked=data.checked;checkbox.dispatchEvent(new Event('change'));}return;
  }
  if(data.theme!=='light'&&data.theme!=='dark')return;
  if(data.type==='vcf-report-theme'&&window.parent!==window&&e.source===window.parent){window.dispatchEvent(new CustomEvent('vcf-report-theme',{detail:data.theme}));}
  if(data.type==='vcf-report-theme-change'&&owned){
   document.documentElement.setAttribute('data-theme',data.theme);
   var button=document.getElementById('themeToggle');if(button)button.textContent=data.theme==='dark'?'🌙 Dark':'☀️ Light';
   try{localStorage.setItem('vcf-report-theme',data.theme);}catch(error){}
   document.querySelectorAll('iframe').forEach(function(frame){if(frame.contentWindow&&frame.contentWindow!==e.source)frame.contentWindow.postMessage({type:'vcf-report-theme',theme:data.theme},'*');});
  }
 });
 function init(){
  var bar=document.querySelector('.tab-bar');
  if(bar)tabs(bar,bar.querySelectorAll('.tab-btn'),function(b,i){return b.dataset.tabTarget||'tab-'+i;},'Report views');
  document.querySelectorAll('.tab-nav').forEach(function(nav){tabs(nav,nav.querySelectorAll('[data-tab]'),function(b){return b.dataset.tab;},'Host subsystems');});
  document.querySelectorAll('.inv-seg').forEach(function(nav){tabs(nav,nav.querySelectorAll('[data-inv-view]'),function(b){return 'inv-pane-'+b.dataset.invView;},'Inventory views');});
  document.querySelectorAll('.fleet-detail-seg').forEach(function(nav){tabs(nav,nav.querySelectorAll('[data-fleet-view]'),function(b){return 'fleet-detail-'+b.dataset.fleetView;},'Fleet detail views');});
  document.querySelectorAll('th').forEach(function(th){
   if(th.closest('thead'))th.setAttribute('scope','col');
   if(th.querySelector('.sort-ind')){th.tabIndex=0;th.setAttribute('aria-sort','none');}
  });
  document.querySelectorAll('input[type="search"],#host-picker-search,#host-picker-select').forEach(function(el){
   if(!el.labels||!el.labels.length)el.setAttribute('aria-label',el.id==='host-picker-select'?'Select host':el.id==='host-picker-search'?'Find host':'Filter inventory');
  });
  document.querySelectorAll('.tab-dot').forEach(function(el){el.setAttribute('aria-hidden','true');});
  if(window.parent!==window){window.parent.postMessage({type:'vcf-report-theme-request'},'*');window.parent.postMessage({type:'vcf-report-mask-request'},'*');}
  api.setupResizers(document);
  context();
  reveal(hashTarget(),false);
 }
 document.addEventListener('keydown',function(e){
  var tab=e.target.closest('[role="tab"]');
  if(tab){
   var nav=tab.closest('[role="tablist"]');
   var buttons=Array.from(nav.querySelectorAll('[role="tab"]')).filter(function(b){return b.getClientRects().length&&!b.disabled;});
   var index=buttons.indexOf(tab),next;
   if(e.key==='ArrowRight'||e.key==='ArrowDown')next=(index+1)%buttons.length;
   if(e.key==='ArrowLeft'||e.key==='ArrowUp')next=(index+buttons.length-1)%buttons.length;
   if(e.key==='Home')next=0;if(e.key==='End')next=buttons.length-1;
   if(next!==undefined){e.preventDefault();buttons.forEach(function(b){b.tabIndex=-1;});buttons[next].tabIndex=0;buttons[next].focus();}
   if(e.key==='Enter'||e.key===' '){e.preventDefault();tab.click();}
  }
  if(e.target.matches('th[aria-sort]')&&(e.key==='Enter'||e.key===' ')){e.preventDefault();e.target.click();}
 });
 document.addEventListener('click',function(e){
  var action=e.target.closest('[data-action]');
  if(action&&action.dataset.action==='inventory-view'&&window.showInvView)window.showInvView(action.dataset.invView);
  if(action&&action.dataset.action==='open-reference')api.openDialog('invRefModal');
  if(action&&action.dataset.action==='close-reference')api.closeDialog();
  if(action&&action.dataset.action==='dialog-backdrop'&&e.target===action)api.closeDialog();
  if(action&&action.dataset.action==='report-tab'){e.preventDefault();if(window.showTab)window.showTab(Number(action.dataset.tabTarget.slice(4)));}
  if(action&&action.dataset.action==='overview-evidence'){
   e.preventDefault();selected={label:action.dataset.evidenceLabel,indices:action.dataset.hostIndices.split(',').map(Number)};
   ['invOem','invCpu','invEsa','invCtrl','invNic','invLink','invSec','invFilter'].forEach(function(id){var el=document.getElementById(id);if(el)el.value='';});
   var oem=document.getElementById('oem-filter');if(oem)oem.value='all';
   var hide=document.getElementById('hide-unsupported');if(hide)hide.checked=false;
   if(window.showTab&&document.getElementById('invRoot')){window.showTab(1);window.showInvView('hosts');}
   if(window.showFleetDetailView)window.showFleetDetailView('hosts');
   applySelection();
   reveal(document.querySelector('#invRoot .inv-filters')||document.getElementById('fleet-per-host-table'),true);
  }
  if(action&&(action.dataset.action==='expand-evidence'||action.dataset.action==='collapse-evidence')){
   var scope=action.closest('.tab-pane,.fleet-detail-pane,.container')||document;
   scope.querySelectorAll('details[data-report-evidence],details.accordion').forEach(function(details){
    if(action.dataset.action==='expand-evidence')details.open=true;
    else if(details.dataset.reportEvidence==='supporting')details.open=false;
   });
  }
  if(action&&action.dataset.action==='clear-overview'){selected=null;applySelection();}
  var th=e.target.closest('th[aria-sort]');
  if(th){setTimeout(function(){
   var table=th.closest('table');table.querySelectorAll('th[aria-sort]').forEach(function(h){h.setAttribute('aria-sort','none');});
   var indicator=th.querySelector('.sort-ind');th.setAttribute('aria-sort',indicator&&indicator.textContent==='▼'?'descending':'ascending');
  },0);}
  var jump=e.target.closest('a.tab-jump,a.tab-jump-link');
  if(jump)reveal(document.querySelector('.tab-content.active')||document.querySelector('.tab-pane.active'),true);
  var anchor=e.target.closest('a[href^="#"]');
  if(anchor&&anchor.hash){var target=document.getElementById(decodeURIComponent(anchor.hash.slice(1)));if(target)reveal(target,false);}
 });
 var printOpen=[];
 window.addEventListener('beforeprint',function(){
  if(printOpen.length)return;
  document.querySelectorAll('details').forEach(function(el){printOpen.push([el,el.open]);el.open=true;});
 });
 window.addEventListener('afterprint',function(){
  printOpen.forEach(function(pair){pair[0].open=pair[1];});printOpen=[];
 });
 window.addEventListener('hashchange',function(){reveal(hashTarget(),true);});
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
</script>"""
