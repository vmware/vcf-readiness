"""Shared saved-instance selector; secrets are resolved only by the server."""

JS_PLUGIN_CREDENTIALS = r"""
var pluginCredentials = (function () {
  var widgets = {}, entries = [], revision = 0, editing = '';
  function el(id) { return document.getElementById(id); }
  function kind(w) {
    var source = el(w.root.dataset.source);
    return source && source.value === 'operations-rest' ? 'operations' : 'vcenter';
  }
  function workbook(w) { var source = el(w.root.dataset.source); return source && source.value === 'operations-xlsx'; }
  function changed(input, value) {
    if (!input || input.value === value) return;
    input.value = value;
    input.dispatchEvent(new Event('input', {bubbles:true}));
    input.dispatchEvent(new Event('change', {bubbles:true}));
  }
  function selected(w) { return entries.find(function(e) { return e.id === w.select.value && e.kind === kind(w); }); }
  function sync(w) {
    var use = w.toggle.checked && !workbook(w), record = use ? selected(w) : null;
    w.fields.hidden = !use; w.toggle.setAttribute('aria-expanded',String(use));
    w.select.disabled = !use || !entries.some(function(e) { return e.kind === kind(w); });
    w.select.required = use;
    ['endpoint','username','password','port'].forEach(function(key) {
      var input = el(w.root.dataset[key]); if (!input) return;
      var group = input.closest('.clr-form-group'); if (group) group.hidden = use;
      input.disabled = use;
    });
    if (use) {
      var endpoint = record ? record.endpoint : '', port = '';
      if (record && w.root.dataset.port) { var url = new URL(endpoint); endpoint = url.hostname; port = url.port || '443'; }
      changed(el(w.root.dataset.endpoint), endpoint);
      changed(el(w.root.dataset.username), record ? record.username : '');
      if (w.root.dataset.port && record) changed(el(w.root.dataset.port), port);
      var password = el(w.root.dataset.password); if (password) password.value = '';
    }
  }
  function populate(w, error) {
    var previous = w.select.value;
    w.select.replaceChildren(new Option('Select an instance',''));
    entries.filter(function(e) { return e.kind === kind(w); }).forEach(function(e) {
      w.select.add(new Option(e.label + ' — ' + e.endpoint + ' (' + e.username + ')',e.id));
    });
    if (entries.some(function(e) { return e.id === previous && e.kind === kind(w); })) w.select.value = previous;
    el(w.prefix+'SavedStatus').textContent = error || (w.select.options.length > 1 ? 'Select an instance. Its password stays in the vault.' : 'No saved ' + (kind(w) === 'operations' ? 'VCF Operations' : 'vCenter') + ' instances. Add one in Credential Vault.');
    var manage=w.root.querySelector('[data-credential-manage]');
    if(manage) manage.textContent=error ? 'Unlock Credential Vault in a new tab' : (w.select.options.length>1 ? 'Manage saved instances in a new tab' : 'Add an instance in a new tab');
    if(manage) manage.href='/?credential_kind='+encodeURIComponent(kind(w))+'#credential-vault';
    w.root.hidden = !!workbook(w);
    if (workbook(w)) w.toggle.checked = false;
    sync(w);
  }
  function resetEditor() {
    editing = '';
    ['Label','Endpoint','Username','Password','AuthSource'].forEach(function(k) { var input=el('vaultService'+k); if(input) input.value=''; });
    if(el('vaultServiceCancel')) el('vaultServiceCancel').hidden=true;
    if(el('vaultServiceSave')) el('vaultServiceSave').textContent='Save instance';
  }
  function renderManager(error) {
    var body = el('vaultServiceRows'); if(!body) return;
    body.replaceChildren();
    if(error || !entries.length) {
      var row=document.createElement('tr'), cell=document.createElement('td'); cell.colSpan=5; cell.textContent=error || 'No saved service instances.'; row.appendChild(cell); body.appendChild(row); return;
    }
    entries.forEach(function(e) {
      var row=document.createElement('tr');
      [e.kind==='vcenter'?'vCenter':'VCF Operations',e.label,e.endpoint,e.username].forEach(function(value) { var cell=document.createElement('td'); cell.textContent=value; row.appendChild(cell); });
      var actions=document.createElement('td');
      ['Edit','Remove'].forEach(function(action) { var button=document.createElement('button'); button.type='button'; button.className='btn btn-flat btn-sm'; button.dataset.serviceAction=action.toLowerCase(); button.dataset.serviceId=e.id; button.textContent=action; button.setAttribute('aria-label',action+' '+e.label); actions.appendChild(button); });
      row.appendChild(actions); body.appendChild(row);
    });
  }
  function refresh() {
    var version=++revision;
    return get('/api/vault/services').then(function(data) {
      if(version!==revision) return;
      entries=data.entries || []; renderManager(); Object.keys(widgets).forEach(function(k) { populate(widgets[k]); });
    }).catch(function(error) {
      if(version!==revision) return;
      entries=[]; resetEditor(); renderManager(error.message);
      if(typeof _vaultState !== 'undefined' && typeof refreshVaultStatus === 'function' && ((error.status===423 && _vaultState.unlocked) || (error.status===403 && !_vaultState.remote_disabled))) refreshVaultStatus();
      Object.keys(widgets).forEach(function(k) { populate(widgets[k], error.message || 'Unlock Credential Vault to select an instance.'); });
    });
  }
  document.querySelectorAll('[data-credential-picker]').forEach(function(root) {
    var prefix=root.dataset.credentialPicker;
    var w={root:root,prefix:prefix,toggle:el(prefix+'UseSaved'),select:el(prefix+'SavedInstance'),fields:el(prefix+'SavedFields')}; widgets[prefix]=w;
    w.toggle.addEventListener('change',function() { sync(w); if(w.toggle.checked) refresh(); });
    w.select.addEventListener('change',function() { sync(w); });
    var source=el(root.dataset.source); if(source) source.addEventListener('change',function() { w.select.value=''; queueMicrotask(function() { populate(w); if(w.toggle.checked) refresh(); }); });
  });
  document.addEventListener('click',function(event) {
    var refreshLink=event.target.closest('[data-credential-refresh]'); if(refreshLink) { refresh(); return; }
    var manage=event.target.closest('[data-credential-manage]');
    if(manage) {
      var w=widgets[manage.dataset.credentialManage]; if(!w) return;
      manage.href='/?credential_kind='+encodeURIComponent(kind(w))+'#credential-vault';
    }
    var action=event.target.closest('[data-service-action]'); if(!action) return;
    var record=entries.find(function(e) { return e.id===action.dataset.serviceId; }); if(!record) return;
    if(action.dataset.serviceAction==='edit') {
      editing=record.id;
      ['Kind','Label','Endpoint','Username','AuthSource'].forEach(function(k) { el('vaultService'+k).value=record[k.replace(/[A-Z]/g,function(c,i) { return (i?'_':'')+c.toLowerCase(); })] || ''; });
      el('vaultServicePassword').value=''; el('vaultServiceCancel').hidden=false; el('vaultServiceSave').textContent='Update instance';
      el('vaultServiceKind').dispatchEvent(new Event('change')); el('vaultServiceLabel').focus();
      el('vaultServiceStatus').textContent='Enter the password to save this update. Stored passwords are never displayed.';
    } else if(window.confirm('Remove saved instance “'+record.label+'”?')) {
      post('/api/vault/services/remove',{id:record.id}).then(function() { resetEditor(); refresh(); if(typeof refreshVaultStatus==='function') refreshVaultStatus(); }).catch(function(error) { el('vaultServiceStatus').textContent=error.message; });
    }
  });
  if(el('vaultServiceKind')) el('vaultServiceKind').addEventListener('change',function() { el('vaultServiceAuthSourceGroup').hidden=this.value!=='operations'; });
  if(el('vaultServiceCancel')) el('vaultServiceCancel').addEventListener('click',resetEditor);
  if(el('vaultServiceSave')) el('vaultServiceSave').addEventListener('click',async function() {
    var button=this, status=el('vaultServiceStatus');
    var data={kind:el('vaultServiceKind').value,label:el('vaultServiceLabel').value,endpoint:el('vaultServiceEndpoint').value,username:el('vaultServiceUsername').value,password:el('vaultServicePassword').value,auth_source:el('vaultServiceAuthSource').value};
    if(editing) data.id=editing;
    el('vaultServicePassword').value=''; button.disabled=true;
    try { await post('/api/vault/services',data); resetEditor(); status.textContent='Saved in the encrypted vault.'; await refresh(); if(typeof refreshVaultStatus==='function') await refreshVaultStatus(); }
    catch(error) { status.textContent=error.message; }
    finally { data.password=''; button.disabled=false; }
  });
  document.addEventListener('vault-state-change',function() { refresh(); });
  if(location.hash==='#credential-vault') {
    var requestedKind=new URLSearchParams(location.search).get('credential_kind');
    if((requestedKind==='vcenter' || requestedKind==='operations') && el('vaultServiceKind')) {
      el('vaultServiceKind').value=requestedKind;
      el('vaultServiceKind').dispatchEvent(new Event('change'));
      var back=el('vaultServiceReturn'); if(back) { back.textContent='Close this tab to return to your plugin'; back.href='#credential-vault'; back.removeAttribute('data-section-link'); back.addEventListener('click',function(event) { event.preventDefault(); window.close(); }); }
    }
  }
  window.addEventListener('focus',function() { if(Object.keys(widgets).some(function(k) { return widgets[k].toggle.checked; })) refresh(); });
  window.addEventListener('hashchange',function() { if(location.hash==='#credential-vault' || Object.keys(widgets).some(function(k) { return widgets[k].toggle.checked; })) refresh(); });
  window.addEventListener('pagehide',function() { var password=el('vaultServicePassword'); if(password) password.value=''; });
  function active(prefix) { var w=widgets[prefix]; return !!(w && w.toggle.checked && !workbook(w)); }
  return {
    active:active,
    ready:function(prefix) { var w=widgets[prefix]; return !!(w && active(prefix) && selected(w)); },
    payload:function(prefix,body) {
      var w=widgets[prefix]; if(!w || !active(prefix)) return body;
      if(!selected(w)) el(prefix+'SavedStatus').textContent='Unlock Credential Vault and select a saved instance.';
      body.vault_credential_id=w.select.value;
      ['endpoint','host','username','password','sso_username','sso_password','auth_source'].forEach(function(k) { delete body[k]; });
      return body;
    }
  };
})();
"""
