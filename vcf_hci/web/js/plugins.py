"""Progressive VDT UI; file data stays out of persistence and query strings."""

JS_PLUGINS = """
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
"""
