"""Progressive VDT UI; file data stays out of persistence and query strings."""

import json

from vcf_hci.plugins.mtat.lifecycle import catalog_entry
from vcf_hci.plugins.vinv.lifecycle import catalog_entry as vinv_catalog_entry
from vcf_hci.web.mtat_html import MTAT_INTRO

JS_PLUGINS = """
  var mtatUpstreamActiveFolder = '';
  function assessmentCatalogGroup() {
    var parent = document.getElementById('plugins');
    if (!parent) return null;
    var group = document.getElementById('assessmentCatalogGroup');
    if (!group) {
      group = document.createElement('div'); group.id = 'assessmentCatalogGroup';
      group.className = 'plugin-card-grid'; group.setAttribute('aria-label', 'Experimental assessments');
      parent.append(group);
    }
    return group;
  }
  function renderMtatCatalog(entry) {
    var parent = assessmentCatalogGroup();
    if (!parent) return;
    var card = document.getElementById('mtatCatalogCard');
    if (!card) {
      card = document.createElement('div'); card.id = 'mtatCatalogCard'; card.className = 'card';
      var body = document.createElement('div'); body.className = 'card-body';
      ['h2', 'p', 'p', 'p', 'p'].forEach(function(tag, index) {
        var child = document.createElement(tag); child.id = 'mtatCatalogField' + index;
        if (index === 1) { child.setAttribute('role', 'status'); child.setAttribute('aria-live', 'polite'); }
        body.append(child);
      });
      var intro = document.createElement('div'); intro.className = 'alert alert-info'; intro.innerHTML = __MTAT_INTRO__;
      body.insertBefore(intro, body.children[1]);
      var open = document.createElement('a'); open.href = '#mtat-experimental'; open.className = 'btn btn-outline'; open.textContent = 'Open MTAT assessment';
      var help = document.createElement('a'); help.href = '/docs/mtat_experimental'; help.textContent = 'Read the MTAT assessment guidance';
      var actions = document.createElement('div'); actions.className = 'flex gap-sm mt-half';
      actions.style.flexWrap = 'wrap'; actions.style.alignItems = 'center'; actions.style.gap = '1rem';
      actions.append(open, help); body.append(actions);
      var packageLabel = document.createElement('label'); packageLabel.htmlFor = 'mtatPluginZip'; packageLabel.textContent = 'Install an upstream MTAT package';
      var packageInput = document.createElement('input'); packageInput.type = 'file'; packageInput.id = 'mtatPluginZip'; packageInput.accept = '.zip';
      var install = document.createElement('button'); install.type = 'button'; install.id = 'mtatPluginInstall'; install.className = 'btn btn-outline btn-sm'; install.textContent = 'Install MTAT ZIP'; install.disabled = true;
      var packageStatus = document.createElement('p'); packageStatus.id = 'mtatPluginStatus'; packageStatus.setAttribute('role', 'status'); packageStatus.setAttribute('aria-live', 'polite');
      var packageList = document.createElement('ul'); packageList.id = 'mtatPluginPackages';
      body.append(packageLabel, packageInput, install, packageStatus, packageList);
      var runtimeLabel = document.createElement('label'); runtimeLabel.htmlFor = 'mtatPluginVersion'; runtimeLabel.textContent = 'Upstream engine for this session';
      var runtimeSelect = document.createElement('select'); runtimeSelect.id = 'mtatPluginVersion'; runtimeSelect.className = 'clr-select';
      var activate = document.createElement('button'); activate.type = 'button'; activate.id = 'mtatPluginActivate'; activate.className = 'btn btn-outline btn-sm'; activate.textContent = 'Activate upstream engine';
      var deactivate = document.createElement('button'); deactivate.type = 'button'; deactivate.id = 'mtatPluginDeactivate'; deactivate.className = 'btn btn-outline btn-sm'; deactivate.textContent = 'Stop upstream engine';
      body.append(runtimeLabel, runtimeSelect, activate, deactivate);
      activate.addEventListener('click', async function () {
        if (!runtimeSelect.value) return;
        activate.disabled = true;
        try {
          var request = {folder:runtimeSelect.value};
          try { var saved = localStorage.getItem('vcfr.mtat.workspace'); if (/^[a-f0-9]{32}$/.test(saved || '')) request.workspace_id = saved; } catch (ignore) { /* storage is optional */ }
          var result = await post('/api/plugins/mtat/upstream/activate', request);
          if (result.error) throw new Error(typeof result.error === 'string' ? result.error : result.error.message);
          mtatUpstreamActiveFolder = runtimeSelect.value;
          try { localStorage.setItem('vcfr.mtat.engine.folder', runtimeSelect.value); } catch (ignore) { /* Default to newest when browser storage is unavailable. */ }
          if (result.workspace_id) { try { localStorage.setItem('vcfr.mtat.workspace', result.workspace_id); } catch (ignore) { /* retain only this session */ } }
          document.dispatchEvent(new CustomEvent('mtat-upstream-activated', {detail:{folder:runtimeSelect.value}}));
          var catalog = await get('/api/plugins'); renderMtatCatalog(catalog.mtat);
          packageStatus.textContent = 'Upstream engine selected. The wizard will keep using this version until you choose another here.';
        } catch (error) { packageStatus.textContent = error.message; }
        finally { activate.disabled = !runtimeSelect.value; }
      });
      deactivate.addEventListener('click', async function () {
        deactivate.disabled = true;
        try {
          var result = await post('/api/plugins/mtat/upstream/close', {});
          if (result.error) throw new Error(typeof result.error === 'string' ? result.error : result.error.message);
          mtatUpstreamActiveFolder = '';
          document.dispatchEvent(new CustomEvent('mtat-upstream-activated', {detail:{folder:''}}));
          var catalog = await get('/api/plugins'); renderMtatCatalog(catalog.mtat);
          packageStatus.textContent = 'Upstream engine stopped. Saved data is retained; the embedded engine remains available.';
        } catch (error) { packageStatus.textContent = error.message; }
        finally { deactivate.disabled = !mtatUpstreamActiveFolder; }
      });
      packageInput.addEventListener('change', function () { install.disabled = !packageInput.files.length || packageInput.disabled; });
      install.addEventListener('click', async function () {
        var file = packageInput.files[0];
        if (!file || packageInput.disabled || packageInput.dataset.busy === 'true') return;
        packageInput.dataset.busy = 'true'; install.disabled = true; packageInput.disabled = true;
        packageStatus.textContent = 'Uploading and verifying MTAT package…';
        try {
          if (file.size > 32 * 1024 * 1024) throw new Error('Choose a ZIP no larger than 32 MiB.');
          var response = await fetch('/api/plugins/mtat/install', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/zip'}, body:file});
          var result = await response.json();
          if (!response.ok) throw new Error(result.error || 'MTAT package installation failed.');
          var catalog = await get('/api/plugins');
          renderMtatCatalog(catalog.mtat);
          packageStatus.textContent = (result.installed.already_installed ? 'Already installed. ' : 'Installed. ') + 'SHA-256: ' + result.installed.archive_sha256 + '. The wizard will select the newest compatible installed engine by default.';
        } catch (error) { packageStatus.textContent = error.message; }
        finally { packageInput.dataset.busy = 'false'; packageInput.value = ''; packageInput.disabled = packageInput.dataset.allowed !== 'true'; install.disabled = true; }
      });
      card.append(body); parent.append(card);
    }
    document.getElementById('mtatCatalogField0').textContent = entry.name;
    document.getElementById('mtatCatalogField1').textContent = entry.enabled
      ? '' : 'Unavailable.';
    document.getElementById('mtatCatalogField2').textContent = entry.warning;
    document.getElementById('mtatCatalogField1').hidden = entry.enabled;
    document.getElementById('mtatCatalogField3').hidden = true;
    document.getElementById('mtatCatalogField4').textContent = 'MTAT ' + entry.mtat_contract + ' · ' + entry.sources.map(function(source) {
      return source.kind + ': ' + source.readiness;
    }).join(' · ');
    var packages = entry.packages || {installations:[], install_allowed:false};
    if (packages.active_folder !== undefined) mtatUpstreamActiveFolder = packages.active_folder || '';
    var packageInput = document.getElementById('mtatPluginZip');
    packageInput.dataset.allowed = packages.install_allowed ? 'true' : 'false';
    packageInput.disabled = !packages.install_allowed || packageInput.dataset.busy === 'true';
    var packageList = document.getElementById('mtatPluginPackages'); packageList.replaceChildren();
    var runtimeSelect = document.getElementById('mtatPluginVersion'), priorRuntime = runtimeSelect.value; runtimeSelect.replaceChildren();
    packages.installations.slice().sort(function(a,b) { return String(b.version).localeCompare(String(a.version), undefined, {numeric:true, sensitivity:'base'}) || String(b.folder).localeCompare(String(a.folder)); }).forEach(function (item) {
      var row = document.createElement('li'); row.textContent = item.version + ' · source ' + item.source_build + (mtatUpstreamActiveFolder === item.folder ? ' · active for this session' : ' · installed, inactive'); packageList.append(row);
      if (item.integration === 'vcfr-mtat/1') runtimeSelect.add(new Option(item.version + ' · ' + item.source_build, item.folder));
    });
    var preferredRuntime = '';
    try { preferredRuntime = localStorage.getItem('vcfr.mtat.engine.folder') || ''; } catch (ignore) { /* Optional preference. */ }
    if (Array.from(runtimeSelect.options).some(function (option) { return option.value === preferredRuntime; })) runtimeSelect.value = preferredRuntime;
    else if (Array.from(runtimeSelect.options).some(function (option) { return option.value === priorRuntime; })) runtimeSelect.value = priorRuntime;
    else if (runtimeSelect.options.length) runtimeSelect.selectedIndex = 0;
    document.getElementById('mtatPluginActivate').disabled = !runtimeSelect.value || packages.install_allowed === false;
    document.getElementById('mtatPluginDeactivate').disabled = !mtatUpstreamActiveFolder;
    document.getElementById('mtatPluginStatus').textContent = (packages.installations.length ? 'Upstream packages installed. ' : 'No upstream package installed. ') + (packages.installations.length ? 'The wizard uses the newest compatible installed engine by default. Activate a specific version here to make it the saved preference.' : 'The wizard uses embedded MTAT 3.2 because no compatible upstream package is installed.') + (packages.invalid_installations ? ' Some installed packages failed integrity checks.' : '');
  }
  renderMtatCatalog(__MTAT_DEFAULT_CATALOG__);

  function renderVinvCatalog(entry) {
    var parent = assessmentCatalogGroup();
    if (!parent) return;
    var card = document.getElementById('vinvCatalogCard');
    if (!card) {
      card = document.createElement('div'); card.id = 'vinvCatalogCard'; card.className = 'card';
      var body = document.createElement('div'); body.className = 'card-body';
      ['h2', 'p', 'p', 'p', 'p'].forEach(function(tag, index) {
        var child = document.createElement(tag); child.id = 'vinvCatalogField' + index;
        if (index === 1) { child.setAttribute('role', 'status'); child.setAttribute('aria-live', 'polite'); }
        body.append(child);
      });
      var open = document.createElement('a'); open.id = 'vinvCatalogOpen'; open.href = '#vinv-experimental'; open.className = 'btn btn-outline'; open.textContent = 'Open vSphere Inventory';
      var help = document.createElement('a'); help.href = '/docs/vsphere_inventory_experimental'; help.textContent = 'Read the vSphere inventory guidance';
      var actions = document.createElement('div'); actions.className = 'flex gap-sm mt-half';
      actions.style.flexWrap = 'wrap'; actions.style.alignItems = 'center'; actions.style.gap = '1rem';
      actions.append(open, help); body.append(actions); card.append(body); parent.append(card);
    }
    document.getElementById('vinvCatalogOpen').hidden = !entry.enabled;
    document.getElementById('vinvCatalogField0').textContent = entry.name;
    document.getElementById('vinvCatalogField1').textContent = entry.enabled
      ? '' : 'Unavailable.';
    document.getElementById('vinvCatalogField2').textContent = entry.warning;
    document.getElementById('vinvCatalogField1').hidden = entry.enabled;
    document.getElementById('vinvCatalogField3').hidden = true;
    document.getElementById('vinvCatalogField4').textContent = 'Schema ' + entry.schema_version + ' · ' + entry.sources.map(function(source) {
      return source.kind + ': ' + source.readiness;
    }).join(' · ');
  }
  renderVinvCatalog(__VINV_DEFAULT_CATALOG__);

  if (document.getElementById('vdt-plugin')) {
    var vdtBusy = false;
    var vdtRunCount = 0;
    function vdtMessage(message) { document.getElementById('vdtStatus').textContent = message; }
    function vdtButtons() {
      document.getElementById('vdtImport').disabled = vdtBusy;
      document.getElementById('vdtClear').disabled = vdtBusy || !vdtRunCount;
      document.getElementById('vdtHybrid').disabled = vdtBusy || !vdtRunCount || !document.getElementById('vdtScopeConfirm').checked;
    }
    function vdtAccess() {
      var product = document.getElementById('vdtProduct').value;
      document.getElementById('vdtAccess').textContent = product === 'sddc_manager'
        ? 'Access: an appliance terminal account with the privileges required by VDT, plus management vCenter SSO credentials when VDT prompts.'
        : 'Access: a vCenter appliance terminal account with the privileges required by VDT. VDT tries machine credentials first and may prompt for SSO credentials. VKS also accesses Supervisor systems.';
    }
    function renderVdtRuns(data) {
      var list = document.getElementById('vdtRuns');
      list.replaceChildren();
      vdtRunCount = data.runs.length;
      document.getElementById('vdtScopeConfirm').checked = false;
      data.runs.forEach(function(run) {
        var li = document.createElement('li');
        var label = document.createElement('p');
        label.textContent = run.product + ' / ' + run.target + ' — ' + run.filename + ' — collected: ' + (run.collected_at || 'unknown') + ' (appliance timestamp)';
        var counts = document.createElement('p');
        counts.textContent = Object.keys(run.counts).map(function(key) { return key + ': ' + run.counts[key]; }).join(' · ');
        var hash = document.createElement('p'); hash.textContent = 'SHA-256: ' + run.sha256; hash.style.overflowWrap = 'anywhere';
        var remove = document.createElement('button'); remove.type = 'button'; remove.className = 'btn btn-flat btn-sm'; remove.textContent = 'Remove export';
        remove.addEventListener('click', async function() {
          if (vdtBusy) return;
          vdtBusy = true; vdtButtons();
          try { renderVdtRuns(await post('/api/plugins/vdt/remove', {id:run.id})); vdtMessage('Export removed.'); }
          catch (error) { vdtMessage(error.message); }
          finally { setOperationProgress('vdtStatus',{busy:false,label:'Operation finished'}); vdtBusy = false; vdtButtons(); }
        });
        li.append(label, counts, hash, remove); list.append(li);
      });
      document.getElementById('vdtRunsEmpty').hidden = !!data.runs.length;
      vdtButtons();
    }
    document.getElementById('vdtProduct').addEventListener('change', vdtAccess);
    document.getElementById('vdtScopeConfirm').addEventListener('change', vdtButtons);
    document.getElementById('vdtImport').addEventListener('click', async function() {
      var file = document.getElementById('vdtFile').files[0];
      var target = document.getElementById('vdtTarget').value.trim();
      if (!target || !file) { vdtMessage('Supply an appliance label and choose a native VDT JSON export.'); if (!target) markFieldError('vdtTarget','Enter an appliance / environment label.'); if (!file) markFieldError('vdtFile','Choose a native VDT JSON export.'); return; }
      if (file.size > 8 * 1024 * 1024) { vdtMessage('VDT exports must be no larger than 8 MiB.'); return; }
      vdtBusy = true; vdtButtons(); vdtMessage('Importing VDT evidence…'); setOperationProgress('vdtStatus',{busy:true,label:'Validating and importing VDT evidence'});
      try {
        var content = new TextDecoder('utf-8', {fatal:true, ignoreBOM:true}).decode(await file.arrayBuffer());
        renderVdtRuns(await post('/api/plugins/vdt/import', {product:document.getElementById('vdtProduct').value, target:target, filename:file.name, content:content}));
        document.getElementById('vdtFile').value = ''; vdtMessage('VDT export imported. Review the source labels before downloading the hybrid report.');
      } catch (error) { vdtMessage(error.message); }
      finally { setOperationProgress('vdtStatus',{busy:false,label:'Operation finished'}); vdtBusy = false; vdtButtons(); }
    });
    document.getElementById('vdtClear').addEventListener('click', async function() {
      if (vdtBusy) return;
      vdtBusy = true; vdtButtons();
      try { renderVdtRuns(await post('/api/plugins/vdt/clear', {})); vdtMessage('VDT evidence cleared.'); }
      catch (error) { vdtMessage(error.message); }
      finally { setOperationProgress('vdtStatus',{busy:false,label:'Operation finished'}); vdtBusy = false; vdtButtons(); }
    });
    document.getElementById('vdtHybrid').addEventListener('click', async function() {
      vdtBusy = true; vdtButtons(); vdtMessage('Building hybrid report…'); setOperationProgress('vdtStatus',{busy:true,label:'Building hybrid assessment report'});
      try {
        var response = await fetch('/api/plugins/vdt/hybrid', {credentials:'same-origin'});
        if (!response.ok) { var error = await response.json(); throw new Error(error.error || 'Report export failed.'); }
        var url = URL.createObjectURL(await response.blob());
        var link = document.createElement('a'); link.href = url; link.download = '00_hybrid_assessment.html';
        document.body.append(link); link.click(); link.remove();
        setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
        vdtMessage('Hybrid report downloaded.');
      } catch (error) { vdtMessage(error.message); }
      finally { setOperationProgress('vdtStatus',{busy:false,label:'Operation finished'}); vdtBusy = false; vdtButtons(); }
    });
    document.addEventListener('vdt-evidence-updated', function(event) { renderVdtRuns(event.detail); });
    vdtAccess();
    var vdtInstalling = false, vdtInstallAllowed = true;
    function renderVdtCatalog(catalog) {
      var labels = (catalog.installations || []).map(function(item) {
        var versions = item.products.map(function(product) { return product + ': ' + (item.versions[product] || 'version unknown'); });
        return (item.folder === '.' ? 'Plugin root' : item.folder) + ' (' + versions.join('; ') + ')';
      });
      document.getElementById('vdtInstalled').textContent = labels.length
        ? 'Installed: ' + labels.join(', ')
        : 'VDT is not installed. Download one or both releases below and upload their ZIPs to get started.';
      var stateText = labels.length ? 'Installed · discover vCenter to select a compatible version' : 'Package required · download and upload VDT';
      document.getElementById('vdtPackageState').textContent = stateText;
      if (document.getElementById('vdtLandingState')) document.getElementById('vdtLandingState').textContent = stateText;
      vdtInstallAllowed = !catalog.remote_collection || catalog.remote_collection.available !== false;
      document.getElementById('vdtZipFiles').disabled = !vdtInstallAllowed || vdtInstalling;
      document.getElementById('vdtInstallZip').disabled = !vdtInstallAllowed || vdtInstalling || !document.getElementById('vdtZipFiles').files.length;
      if (!vdtInstallAllowed) document.getElementById('vdtInstallStatus').textContent = 'Package installation is available only from the local web listener.';
    }
    function refreshVdtCatalog() {
      return get('/api/plugins').then(function(data) {
        renderVdtCatalog(data.vdt);
        if (data.mtat) renderMtatCatalog(data.mtat);
        if (data.vinv) renderVinvCatalog(data.vinv);
        document.dispatchEvent(new CustomEvent('vdt-installations-updated', {detail:data}));
        return data;
      });
    }
    document.getElementById('vdtZipFiles').addEventListener('change', function() {
      document.getElementById('vdtInstallZip').disabled = vdtInstalling || !vdtInstallAllowed || !this.files.length;
    });
    document.getElementById('vdtInstallZip').addEventListener('click', async function() {
      var files = Array.from(document.getElementById('vdtZipFiles').files);
      if (!files.length || vdtInstalling || !vdtInstallAllowed) return;
      vdtInstalling = true; this.disabled = true; document.getElementById('vdtZipFiles').disabled = true;
      var results = [];
      setOperationProgress('vdtInstallStatus',{busy:true,label:'Uploading and validating VDT packages; duration unknown'});
      try {
        for (var file of files) {
          document.getElementById('vdtInstallStatus').textContent = 'Installing ' + file.name + '…';
          try {
            if (file.size > 32 * 1024 * 1024) throw new Error('ZIP packages must be no larger than 32 MiB.');
            var response = await fetch('/api/plugins/vdt/install', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/zip'}, body:file});
            var data = await response.json();
            if (!response.ok) throw new Error(data.error || 'ZIP installation failed.');
            var installed = data.installed;
            results.push(file.name + ': ' + (installed.already_installed ? 'already installed' : 'installed') + '. SHA-256: ' + installed.archive_sha256);
          } catch (error) { results.push(file.name + ': ' + error.message); }
        }
        await refreshVdtCatalog();
      } catch (error) { results.push('Could not refresh the package list: ' + error.message); }
      finally {
        setOperationProgress('vdtInstallStatus',{busy:false,label:'Package processing finished'});
        vdtInstalling = false; document.getElementById('vdtZipFiles').value = '';
        document.getElementById('vdtZipFiles').disabled = !vdtInstallAllowed;
        document.getElementById('vdtInstallZip').disabled = true;
        document.getElementById('vdtInstallStatus').textContent = results.join(' ');
      }
    });
    refreshVdtCatalog().catch(function(error) { vdtMessage(error.message); });
    get('/api/plugins/vdt/runs').then(renderVdtRuns).catch(function(error) { vdtMessage(error.message); });
  }
""".replace("__MTAT_INTRO__", json.dumps(MTAT_INTRO)).replace(
    "__MTAT_DEFAULT_CATALOG__", json.dumps(catalog_entry(True))
).replace("__VINV_DEFAULT_CATALOG__", json.dumps(vinv_catalog_entry(True)))
