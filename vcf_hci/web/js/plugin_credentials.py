"""Shared saved-instance selector; secrets are resolved only by the server."""

JS_PLUGIN_CREDENTIALS = r"""
var pluginCredentials = (function () {
  var widgets = {}, entries = [], revision = 0, editing = '';
  var serviceTrust = null, serviceReviewed = null, serviceInspectRevision = 0, serviceSaving = false;
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
  function roleOk(w, entry) {
    var need = w.root.dataset.role || '';
    if (!need) return true;
    if (need === 'readonly') return !entry.role || entry.role === 'readonly';
    return entry.role === need;
  }
  function selected(w) { return entries.find(function(e) { return e.id === w.select.value && e.kind === kind(w) && roleOk(w, e); }); }
  function sync(w) {
    var use = w.toggle.checked && !workbook(w), record = use ? selected(w) : null;
    w.fields.hidden = !use; w.toggle.setAttribute('aria-expanded',String(use));
    w.select.disabled = !use || !entries.some(function(e) { return e.kind === kind(w) && roleOk(w, e); });
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
    document.dispatchEvent(new CustomEvent('plugin-credentials-change', {detail:w.prefix}));
  }
  function populate(w, error) {
    var previous = w.select.value;
    w.select.replaceChildren(new Option('Select an instance',''));
    entries.filter(function(e) { return e.kind === kind(w) && roleOk(w, e); }).forEach(function(e) {
      var role = e.kind === 'vcenter' ? (e.role === 'administrator' ? 'administrator' : (e.role === 'readonly' ? 'read-only' : 'unscoped')) : '';
      w.select.add(new Option(e.label + ' — ' + e.endpoint + ' (' + e.username + (role ? ', ' + role : '') + ')',e.id));
    });
    if (entries.some(function(e) { return e.id === previous && e.kind === kind(w) && roleOk(w, e); })) w.select.value = previous;
    if (w.preferSaved !== undefined && !w.userChoice) {
      var eligible = entries.filter(function(e) { return e.kind === kind(w) && roleOk(w, e); });
      w.toggle.checked = w.preferSaved && eligible.length > 0;
      if (w.toggle.checked && !w.select.value && eligible.length === 1) w.select.value = eligible[0].id;
    }
    el(w.prefix+'SavedStatus').textContent = error || (w.select.options.length > 1 ? 'Select an instance. Its password stays in the vault.' : 'No saved ' + (kind(w) === 'operations' ? 'VCF Operations' : 'vCenter') + ' instances. Add one in Credential Vault.');
    var manage=w.root.querySelector('[data-credential-manage]');
    if(manage) manage.textContent=error ? 'Unlock Credential Vault in a new tab' : (w.select.options.length>1 ? 'Manage saved instances in a new tab' : 'Add an instance in a new tab');
    if(manage) manage.href='/?credential_kind='+encodeURIComponent(kind(w))+'#credential-vault';
    w.root.hidden = !!workbook(w);
    if (workbook(w)) w.toggle.checked = false;
    sync(w);
  }
  function serviceEndpoint() {
    var endpoint = el('vaultServiceEndpoint').value.trim();
    var url = new URL(endpoint.indexOf('://') < 0 ? 'https://' + endpoint : endpoint);
    if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.search || url.hash) throw new Error('Enter an HTTPS vCenter hostname or URL without embedded credentials.');
    return url.origin;
  }
  function syncServiceTrust() {
    var vcenter = el('vaultServiceKind').value === 'vcenter', endpoint = '';
    try { endpoint = serviceEndpoint(); } catch (error) { /* An incomplete field cannot carry trust. */ }
    if (!vcenter || (serviceTrust && serviceTrust.endpoint !== endpoint)) serviceTrust = null;
    el('vaultServiceTrustBlock').hidden = !vcenter;
    el('vaultServiceSave').disabled = serviceSaving || (vcenter && !serviceTrust);
    el('vaultServiceTrustStatus').textContent = serviceTrust ? 'Certificate fingerprint accepted. It will be retained with this account when you save.' : 'Review and explicitly trust this vCenter certificate before saving. Its SHA-256 fingerprint is stored with the account in the encrypted vault.';
  }
  function clearServiceReview() {
    serviceInspectRevision += 1;
    serviceReviewed = null;
    el('vaultServiceCertReview').hidden = true;
  }
  if(el('vaultServiceEndpoint')) el('vaultServiceEndpoint').addEventListener('input',function() { clearServiceReview(); syncServiceTrust(); });
  if(el('vaultServiceReviewCert')) el('vaultServiceReviewCert').addEventListener('click',async function() {
    clearServiceReview();
    var version = serviceInspectRevision;
    this.disabled = true;
    try {
      var endpoint = serviceEndpoint(), target = new URL(endpoint);
      var data = await get('/api/inspect-cert?host=' + encodeURIComponent(target.hostname.replace(/^\[|\]$/g, '')) + '&port=' + encodeURIComponent(target.port || '443'));
      if(version !== serviceInspectRevision || el('vaultServiceKind').value !== 'vcenter' || endpoint !== serviceEndpoint()) return;
      var pin = String(data.sha256_raw || data.sha256 || '').replace(/:/g, '').toUpperCase();
      if(!data.reachable || !/^[A-F0-9]{64}$/.test(pin)) throw new Error('Certificate inspection failed. Check the hostname and HTTPS port.');
      serviceReviewed = {endpoint:endpoint, pin:pin};
      el('vaultServiceCertDetails').textContent = (serviceTrust && serviceTrust.pin !== pin ? 'CERTIFICATE CHANGED: confirm the replacement before trusting.\n' : '') + 'Endpoint: ' + endpoint + '\nSubject: ' + (data.subject_cn || 'Unknown') + '\nIssuer: ' + (data.issuer_cn || 'Unknown') + '\nExpires: ' + (data.not_after || 'Unknown') + '\nSHA-256: ' + pin;
      el('vaultServiceCertReview').hidden = false;
      el('vaultServiceTrustStatus').textContent = 'Certificate inspected. Compare the fingerprint below, then select Trust certificate to accept it.';
      el('vaultServiceTrustCert').focus();
    } catch(error) { if(version === serviceInspectRevision) el('vaultServiceTrustStatus').textContent = error.message || 'Could not inspect the certificate.'; }
    finally { this.disabled = false; }
  });
  if(el('vaultServiceTrustCert')) el('vaultServiceTrustCert').addEventListener('click',function() {
    if(!serviceReviewed || serviceReviewed.endpoint !== serviceEndpoint() || el('vaultServiceKind').value !== 'vcenter') return;
    serviceTrust = serviceReviewed;
    clearServiceReview();
    syncServiceTrust();
    el('vaultServiceSave').focus();
  });
  if(el('vaultServiceCancelCert')) el('vaultServiceCancelCert').addEventListener('click',function() { clearServiceReview(); syncServiceTrust(); });
  function resetEditor() {
    editing = '';
    serviceTrust = null;
    clearServiceReview();
    ['Label','Endpoint','Username','Password','AuthSource'].forEach(function(k) { var input=el('vaultService'+k); if(input) input.value=''; });
    if(el('vaultServiceCancel')) el('vaultServiceCancel').hidden=true;
    if(el('vaultServiceSave')) el('vaultServiceSave').textContent='Save instance';
    syncServiceTrust();
  }
  function renderManager(error) {
    var body = el('vaultServiceRows'); if(!body) return;
    body.replaceChildren();
    if(error || !entries.length) {
      var row=document.createElement('tr'), cell=document.createElement('td'); cell.colSpan=6; cell.textContent=error || 'No saved service instances.'; row.appendChild(cell); body.appendChild(row); return;
    }
    entries.forEach(function(e) {
      var row=document.createElement('tr');
      [e.kind==='vcenter'?'vCenter':'VCF Operations', e.kind==='vcenter'?(e.role==='administrator'?'Administrator':(e.role==='readonly'?'Read-only':'Unscoped')):'—', e.label,e.endpoint,e.username].forEach(function(value) { var cell=document.createElement('td'); cell.textContent=value; row.appendChild(cell); });
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
    ['endpoint','username','password'].forEach(function(key) {
      var input=el(root.dataset[key]);
      if(input) input.addEventListener('input',function(event) { if(event.isTrusted && !w.toggle.checked) w.userChoice=true; });
    });
    w.toggle.addEventListener('change',function() { w.userChoice = true; sync(w); if(w.toggle.checked) refresh(); });
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
      if (el('vaultServiceRole')) el('vaultServiceRole').value = record.role === 'administrator' ? 'administrator' : 'readonly';
      el('vaultServicePassword').value=''; el('vaultServiceCancel').hidden=false; el('vaultServiceSave').textContent='Update instance';
      el('vaultServiceKind').dispatchEvent(new Event('change'));
      if(record.kind==='vcenter' && record.certificate_pin) serviceTrust={endpoint:record.endpoint,pin:record.certificate_pin};
      syncServiceTrust();
      el('vaultServiceLabel').focus();
      el('vaultServiceStatus').textContent='Enter the password to save this update. Stored passwords are never displayed.';
    } else if(window.confirm('Remove saved instance “'+record.label+'”?')) {
      post('/api/vault/services/remove',{id:record.id}).then(function() { resetEditor(); refresh(); if(typeof refreshVaultStatus==='function') refreshVaultStatus(); }).catch(function(error) { el('vaultServiceStatus').textContent=error.message; });
    }
  });
  if(el('vaultServiceKind')) el('vaultServiceKind').addEventListener('change',function() {
    clearServiceReview();
    serviceTrust = null;
    syncServiceTrust();
    el('vaultServiceAuthSourceGroup').hidden=this.value!=='operations';
    if (el('vaultServiceRoleGroup')) el('vaultServiceRoleGroup').hidden=this.value!=='vcenter';
  });
  if(el('vaultServiceKind')) el('vaultServiceKind').dispatchEvent(new Event('change'));
  if(el('vaultServiceCancel')) el('vaultServiceCancel').addEventListener('click',resetEditor);
  if(el('vaultServiceSave')) el('vaultServiceSave').addEventListener('click',async function() {
    var button=this, status=el('vaultServiceStatus');
    var data={kind:el('vaultServiceKind').value,label:el('vaultServiceLabel').value,endpoint:el('vaultServiceEndpoint').value,username:el('vaultServiceUsername').value,password:el('vaultServicePassword').value,auth_source:el('vaultServiceAuthSource').value,role:el('vaultServiceKind').value==='vcenter'&&el('vaultServiceRole')?el('vaultServiceRole').value:''};
    if(data.kind==='vcenter') {
      syncServiceTrust();
      if(!serviceTrust || serviceTrust.endpoint!==serviceEndpoint()) { status.textContent='Review and trust the vCenter certificate before saving.'; return; }
      data.certificate_pin=serviceTrust.pin;
    }
    if(editing) data.id=editing;
    el('vaultServicePassword').value=''; serviceSaving=true; button.disabled=true;
    try { await post('/api/vault/services',data); resetEditor(); status.textContent='Saved in the encrypted vault.'; await refresh(); if(typeof refreshVaultStatus==='function') await refreshVaultStatus(); }
    catch(error) { status.textContent=error.message; }
    finally { data.password=''; serviceSaving=false; syncServiceTrust(); }
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
    preferSaved:function(prefix, enabled) {
      var w=widgets[prefix]; if(!w) return;
      if(w.preferSaved !== enabled) w.userChoice=false;
      w.preferSaved=enabled;
      populate(w);
    },
    active:active,
    selected:function(prefix) { var w=widgets[prefix], record=w && active(prefix) && selected(w); return record ? Object.assign({}, record) : null; },
    refresh:refresh,
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
