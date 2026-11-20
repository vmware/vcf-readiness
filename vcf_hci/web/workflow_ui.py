"""Offline semantic controls following Clarity progress, form and alert patterns."""

WORKFLOW_CSS = """
.operation-progress { display:flex; align-items:center; gap:.75rem; margin:.75rem 0; min-width:0; }
.operation-progress[hidden] { display:none; }
.operation-progress progress { width:min(22rem,70%); height:.5rem; accent-color:var(--vcf-primary); }
.operation-progress-time { font-variant-numeric:tabular-nums; color:var(--vcf-muted); white-space:nowrap; }
.progress-indeterminate .progress-bar { width:30%!important; animation:operation-sweep 1.5s ease-in-out infinite alternate; }
@keyframes operation-sweep { from { transform:translateX(0); } to { transform:translateX(220%); } }
.operation-progress-label { overflow-wrap:anywhere; }
.workflow-timeline { list-style:none; padding:0; margin:1rem 0; border-inline-start:2px solid var(--vcf-border); }
.workflow-timeline li { padding:.5rem .75rem; margin-inline-start:.5rem; position:relative; }
.workflow-timeline li::before { content:''; width:.5rem; height:.5rem; border:2px solid var(--vcf-border); border-radius:50%; position:absolute; inset-inline-start:-.86rem; top:.9rem; background:var(--vcf-card); }
.workflow-timeline li[aria-current="step"] { background:var(--vcf-bg-subtle); border-radius:3px; font-weight:600; }
.workflow-timeline li[aria-current="step"]::before { border-color:var(--vcf-primary); background:var(--vcf-primary); }
.workflow-timeline progress { width:min(30rem,100%); height:.6rem; accent-color:var(--vcf-primary); }
.workflow-timeline li[data-state="running"] { border-inline-start:3px solid var(--vcf-primary); }
.workflow-timeline li[data-state="done"] progress { accent-color:var(--vcf-success); }
.wizard-activity-log { max-height:16rem; overflow:auto; padding-inline-start:1.5rem; font-size:.85rem; }
.workflow-timeline small { display:block; color:var(--vcf-muted); font-weight:400; }
.field-error[hidden], .context-message[hidden] { display:none; }
.field-error { display:block; color:var(--vcf-danger); margin:.25rem 0; line-height:1.5; }
[aria-invalid="true"] { border-color:var(--vcf-danger)!important; outline:1px solid var(--vcf-danger); }
.context-message { margin:.75rem 0; overflow-wrap:anywhere; white-space:pre-line; }
.plugin-state { font-weight:600; display:inline-block; border:1px solid var(--vcf-border); border-radius:3px; padding:.15rem .5rem; margin:.25rem 0; }
.plugin-card-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(min(22rem,100%),1fr)); gap:1rem; }
.plugin-card-grid .card { margin:0; }
.plugin-card-grid .card-body { display:flex; flex-direction:column; align-items:flex-start; height:100%; }
.plugin-card-grid .card-body .btn { margin-top:auto; }
.log-disclosure { margin:.75rem 0; }
.log-disclosure summary { cursor:pointer; font-weight:600; padding:.5rem 0; }
@media (prefers-reduced-motion:reduce) { .operation-progress progress, .progress-indeterminate .progress-bar, .spinner, .active-spinner, .pulse-dot { animation:none!important; transition:none!important; } }
.wizard-group { border:1px solid var(--vcf-border); border-radius:3px; margin:0 0 1rem; padding:.75rem 1rem; }
.wizard-group legend { padding:0 .25rem; }
.wizard-sub-fieldset { border:0; margin:.25rem 0 .75rem 1.5rem; padding:0; }
.clr-toggle-row { margin:.35rem 0; }
.clr-toggle-label { display:flex; align-items:center; gap:.6rem; font-weight:600; cursor:pointer; }
.clr-toggle { position:absolute; opacity:0; width:1px; height:1px; }
.clr-toggle + .ui-switch-track { background:var(--vcf-bg-secondary); border-color:var(--vcf-control-border); color:var(--vcf-muted); }
.clr-toggle:checked + .ui-switch-track { background:var(--vcf-success); border-color:var(--vcf-success); }
.clr-toggle:checked + .ui-switch-track:before { background:var(--vcf-card); }
.clr-toggle:disabled + .ui-switch-track { opacity:.45; cursor:not-allowed; }
.clr-toggle:focus-visible + .ui-switch-track { outline:2px solid var(--vcf-primary); outline-offset:3px; }
.clr-toggle:checked + .ui-switch-track:before { transform:translateX(12px); }
.ui-help-trigger { margin-left:.4rem; border:0; background:transparent; color:var(--vcf-primary); font-weight:600; cursor:pointer; padding:0 .2rem; }
.vcf-signpost { margin:.5rem 0 .75rem; max-width:360px; padding:.75rem 1rem; border:1px solid var(--vcf-border); border-radius:3px; background:var(--vcf-card); }
.vcf-signpost[hidden] { display:none; }
.tooltip { position:relative; display:inline-flex; }
.tooltip-content { display:none; position:absolute; z-index:5; width:240px; padding:.4rem .6rem; background:var(--vcf-text); color:var(--vcf-card); border-radius:3px; font-size:12px; font-weight:400; line-height:1.4; }
.tooltip:hover .tooltip-content, .tooltip:focus-visible .tooltip-content, .tooltip:focus-within .tooltip-content { display:block; }
.tooltip-top-right .tooltip-content { bottom:100%; left:0; margin-bottom:.35rem; }
"""

JS_WORKFLOW = r"""
  var operationStates = Object.create(null);
  function setOperationProgress(id, options) {
    var anchor = document.getElementById(id); if (!anchor) return;
    var state = operationStates[id];
    if (!state) {
      var box = document.createElement('div'); box.className = 'operation-progress'; box.id = id + 'Indicator'; box.hidden = true;
      var bar = document.createElement('progress'); bar.setAttribute('aria-label', options.label || 'Operation in progress');
      var time = document.createElement('span'); time.className = 'operation-progress-time'; time.setAttribute('aria-hidden','true');
      box.append(bar,time); anchor.before(box);
      state = operationStates[id] = {box:box,bar:bar,time:time,started:0,timer:null};
    }
    state.bar.setAttribute('aria-label', options.label || 'Operation in progress');
    state.box.hidden = !options.busy;
    anchor.setAttribute('aria-busy', String(!!options.busy));
    if (options.determinate && Number(options.max) > 0) { state.bar.max = Number(options.max); state.bar.value = Math.max(0,Math.min(Number(options.max),Number(options.value)||0)); }
    else state.bar.removeAttribute('value');
    if (options.busy && !state.timer) {
      state.started = Date.now();
      var tick = function() { var seconds = Math.floor((Date.now()-state.started)/1000); state.time.textContent = Math.floor(seconds/60) + ':' + String(seconds%60).padStart(2,'0') + ' elapsed'; };
      tick(); state.timer = setInterval(tick,1000);
    } else if (!options.busy && state.timer) { clearInterval(state.timer); state.timer = null; }
  }
  function showContextMessage(text, anchor, kind) {
    if (typeof anchor === 'string') anchor = document.getElementById(anchor);
    anchor = anchor || document.querySelector('[data-app-section]:not([hidden])') || document.getElementById('mainContent');
    if (!anchor) return;
    var id = (anchor.id || 'application') + 'ContextMessage';
    var box = document.getElementById(id);
    if (!box) { box = document.createElement('div'); box.id = id; box.tabIndex = -1; anchor.prepend(box); }
    box.className = 'alert context-message alert-' + (kind || 'danger');
    box.setAttribute('role',kind === 'info' ? 'status' : 'alert');
    box.textContent = String(text || ''); box.hidden = !text;
    if (text) { box.focus({preventScroll:true}); box.scrollIntoView({block:'nearest'}); }
  }
  function clearContextMessage(anchor) {
    if (typeof anchor === 'string') anchor = document.getElementById(anchor);
    if (!anchor) return;
    var box = document.getElementById((anchor.id || 'application') + 'ContextMessage'); if (box) box.hidden = true;
  }
  function markFieldError(inputId, message) {
    var input = typeof inputId === 'string' ? document.getElementById(inputId) : inputId; if (!input) return;
    if (!input.id) return;
    var id = input.id + 'FieldError', error = document.getElementById(id);
    var described = (input.getAttribute('aria-describedby') || '').split(/\s+/).filter(function(value) { return value && value !== id; });
    if (message) {
      if (!error) { error = document.createElement('span'); error.id = id; error.className = 'field-error'; input.after(error); }
      error.textContent = message; error.hidden = false;
      input.setAttribute('aria-invalid','true'); described.push(id);
    } else { input.removeAttribute('aria-invalid'); if (error) error.hidden = true; }
    if (described.length) input.setAttribute('aria-describedby',described.join(' ')); else input.removeAttribute('aria-describedby');
  }
  document.addEventListener('input',function(event) { if (event.target.matches('[aria-invalid="true"]')) markFieldError(event.target,''); });
"""
