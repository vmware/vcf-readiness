"""Offline inventory layout controls; display state never changes export data."""

INVENTORY_VIEW_CSS = """
#invRoot{--inv-font-size:14px;--inv-secondary-size:12px;--inv-row-padding:8px 12px;padding:24px;font-family:inherit}
#invRoot[data-density='compact']{--inv-font-size:13px;--inv-row-padding:4px 8px}
#invRoot .inv-table{font-size:var(--inv-font-size);line-height:1.45}
#invRoot .inv-table th,#invRoot .inv-table td{font-size:var(--inv-font-size);padding:var(--inv-row-padding)}
#invRoot .inv-table small{font-size:var(--inv-secondary-size)}
#invRoot .inv-table [data-column-key='hostname']{min-width:180px;max-width:240px;white-space:normal;overflow-wrap:anywhere}
#invRoot .inv-table [data-column-key='model']{min-width:120px;max-width:200px;white-space:normal;overflow-wrap:anywhere}
#invRoot .inv-table [data-column-key='cpu_model']{min-width:150px;max-width:220px;white-space:normal}
#invRoot .inv-cpu-label{display:block;font-size:var(--inv-font-size);line-height:1.4;white-space:normal}
#invRoot .inv-cpu-verdict{display:block;font-size:var(--inv-secondary-size);margin-top:4px}
#invRoot .inv-filters,#invRoot .inv-count,#invRoot .inv-page-controls{font-size:12px}
#invRoot .inv-btn,#invRoot .inv-filters select,#invRoot .inv-filters input,#invRoot .inv-seg button,#invRoot .inv-layout select{font-size:14px;min-height:32px}
#invRoot .inv-btn{padding:4px 12px;box-sizing:border-box}
#invRoot .inv-seg{display:flex;flex-wrap:wrap;gap:0;margin:12px 0}
#invRoot .inv-seg button{border:0;border-radius:0;border-bottom:3px solid transparent;padding:8px 12px;background:transparent;color:var(--text-muted)}
#invRoot .inv-seg button.active{color:var(--primary);border-bottom-color:var(--primary);background:transparent}
#invRoot .inv-scroll{border-color:var(--border);scrollbar-width:auto;scrollbar-gutter:stable;max-height:calc(100vh - 180px)}
#invRoot .inv-layout{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
#invRoot .inv-layout select{background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:3px;padding:4px 8px}
#invRoot .inv-layout label{font-size:12px;display:flex;align-items:center;gap:8px}
#invRoot .inv-columns{position:relative;border:0;margin:0;padding:0}
#invRoot .inv-columns summary{cursor:pointer;list-style:none;display:flex;align-items:center;gap:4px;border:1px solid var(--border);border-radius:4px;background:var(--card);color:var(--text)}
#invRoot .inv-columns summary>.ui-icon{margin:0}
#invRoot .inv-columns summary:after{content:' ▾';margin-left:8px}
#invRoot .inv-column-options{position:absolute;top:100%;left:0;z-index:120;min-width:220px;max-height:60vh;overflow:auto;background:var(--card);border:1px solid var(--border);border-radius:4px;padding:12px;box-shadow:0 4px 12px #0002}
#invRoot .inv-column-options label{min-height:32px;font-size:14px;white-space:nowrap}
#invRoot .inv-column-options input{width:16px;height:16px;accent-color:var(--primary)}
#invRoot .inv-column-options p{font-size:12px;color:var(--text-muted);white-space:normal;margin:0 0 8px}
#invRoot .inv-table .inv-muted{color:var(--text-muted)}
#invRoot .inv-table .inv-good{color:var(--success)}
#invRoot .inv-table .inv-warn{color:var(--warning)}
#invRoot .inv-table .inv-bad{color:var(--danger)}
@media(max-width:800px){#invRoot{padding:16px}#invRoot .inv-page-controls{margin-left:0}#invRoot .inv-columns .inv-column-options{position:static}}
@media print{#invRoot .inv-scroll{max-height:none;overflow:visible}}
"""

INVENTORY_VIEW_JS = """<script>
(function(){
 'use strict';
 function init(){
  var root=document.getElementById('invRoot'),table=document.getElementById('invHostTable');
  if(!root||!table||window.VCFInventoryView)return;
  var headers=Array.from(table.querySelectorAll('thead [data-column-key]'));
  var keys=headers.map(function(th){return th.dataset.columnKey;});
  var defaultHidden=headers.filter(function(th){return th.dataset.defaultVisible==='false';}).map(function(th){return th.dataset.columnKey;});
  var state={density:'comfortable',hidden:defaultHidden.slice()};
  var storageKey='vcf-report-inventory-layout-v1';
  try{
   var saved=JSON.parse(localStorage.getItem(storageKey)||'null');
   if(saved&&typeof saved==='object'&&!Array.isArray(saved)){
    if(saved.density==='comfortable'||saved.density==='compact')state.density=saved.density;
    if(Array.isArray(saved.hidden))state.hidden=Array.from(new Set(saved.hidden.filter(function(key){return typeof key==='string'&&key!=='hostname'&&keys.indexOf(key)>=0;})));
   }
  }catch(e){}
  var options=document.getElementById('invColumnOptions');
  headers.forEach(function(th){
   var key=th.dataset.columnKey,label=document.createElement('label'),input=document.createElement('input');
   input.type='checkbox';input.dataset.columnChoice=key;input.disabled=key==='hostname';
   label.appendChild(input);label.appendChild(document.createTextNode(th.dataset.columnLabel||th.textContent.replace('⇅','').trim()));options.appendChild(label);
  });
  function persist(){try{localStorage.setItem(storageKey,JSON.stringify({density:state.density,hidden:state.hidden}));}catch(e){}}
  function apply(){
   root.dataset.density=state.density;
   document.documentElement.dataset.reportDensity=state.density;
   try{localStorage.setItem('vcf-report-density',state.density);}catch(e){}
   var density=document.getElementById('invDensity');if(density)density.value=state.density;
   table.querySelectorAll('[data-column-key]').forEach(function(cell){cell.hidden=state.hidden.indexOf(cell.dataset.columnKey)>=0;});
   options.querySelectorAll('input').forEach(function(input){input.checked=state.hidden.indexOf(input.dataset.columnChoice)<0;});
   if(window.VCFReportUI&&window.VCFReportUI.syncTableWidths)window.VCFReportUI.syncTableWidths(table);
   var count=keys.length-state.hidden.length;
   table.querySelectorAll('tbody td[colspan]').forEach(function(cell){cell.colSpan=count;});
  }
  window.VCFInventoryView={reset:function(){
   state={density:'comfortable',hidden:defaultHidden.slice()};
   if(window.VCFReportUI&&window.VCFReportUI.resetTableWidths)window.VCFReportUI.resetTableWidths(table);
   table.querySelectorAll('th').forEach(function(th){th.style.removeProperty('width');th.style.removeProperty('min-width');th.style.removeProperty('max-width');});
   apply();persist();
  }};
  root.addEventListener('change',function(e){
   var input=e.target;
   if(input.id==='invDensity'){state.density=input.value==='compact'?'compact':'comfortable';apply();persist();}
   if(input.dataset.columnChoice&&input.dataset.columnChoice!=='hostname'){
    var key=input.dataset.columnChoice;state.hidden=state.hidden.filter(function(value){return value!==key;});
    if(!input.checked)state.hidden.push(key);apply();persist();
   }
  });
  root.addEventListener('click',function(e){var button=e.target.closest('[data-action="reset-inventory-layout"]');if(button)window.VCFInventoryView.reset();});
  window.addEventListener('vcf-inventory-view',function(e){document.getElementById('invColumnsChooser').hidden=e.detail!=='hosts';});
  var shown=document.getElementById('invShown');
  if(shown){var announcement=document.createElement('span');announcement.className='report-sr-only';announcement.setAttribute('role','status');root.appendChild(announcement);var timer;
   new MutationObserver(function(){clearTimeout(timer);timer=setTimeout(function(){announcement.textContent=shown.textContent+' matching rows';},250);}).observe(shown,{subtree:true,childList:true,characterData:true});
  }
  root.querySelectorAll('.inv-scroll').forEach(function(scroll){scroll.tabIndex=0;scroll.setAttribute('role','region');scroll.setAttribute('aria-label','Inventory comparison table; scroll horizontally for more columns');});
  apply();
 }
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();
</script>"""
