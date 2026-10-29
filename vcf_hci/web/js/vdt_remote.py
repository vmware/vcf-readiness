"""Ephemeral credentials and explicit SSH trust for remote VDT collection."""

JS_VDT_REMOTE = """
  if (document.getElementById('vdtRemoteCard')) {
    (function() {
      var step = 0, reached = 0, busy = false, verified = false;
      var hostKey = '', job = null, timer = null, remoteProducts = ['vcenter'];
      var installations = [], available = false, pollGeneration = 0, discovery = null, cancelling = false;
      var terminal = ['completed', 'failed', 'needs_credentials', 'cancelled'];
      function el(id) { return document.getElementById('vdtRemote' + id); }
      function active() { return job && terminal.indexOf(job.status) < 0; }
      function clearPasswords() { el('Password').value = ''; el('SsoPassword').value = ''; }
      function message(text, focus) {
        el('Error').textContent = text || ''; el('Error').hidden = !text;
        if (text && focus) el('Error').focus();
        if (text && focus) {
          var invalid = step === 0 ? ['Host','ApiPort','Port'] : step === 1 ? ['Username','Password','SsoUsername','SsoPassword'] : ['Output'];
          invalid.forEach(function(id) { var input = el(id); if (!input.value.trim() || (input.type === 'number' && !input.validity.valid)) markFieldError(input,text); });
        }
      }
      function normalizeApplianceHost() {
        var value = el('Host').value.trim();
        if (value.indexOf('://') >= 0) {
          try {
            var url = new URL(value);
            if (['http:', 'https:'].indexOf(url.protocol) < 0 || url.username || url.password || !url.hostname) throw new Error();
            value = url.hostname;
            if (value.charAt(0) === '[' && value.charAt(value.length - 1) === ']') value = value.slice(1, -1);
          } catch (error) {
            throw new Error('Enter a valid HTTP or HTTPS appliance URL without embedded credentials.');
          }
        }
        el('Host').value = value;
        return value;
      }
      function target() {
        return {host:normalizeApplianceHost(), port:Number(el('Port').value),
          username:el('Username').value.trim(), auth_type:'password',
          password:el('Password').value, host_key:hostKey};
      }
      function hostError() {
        try { normalizeApplianceHost(); } catch (error) { return error.message; }
        if (!el('Host').value.trim()) return 'Enter the appliance hostname or address.';
        var port = Number(el('ApiPort').value);
        if (!Number.isInteger(port) || port < 1 || port > 65535) return 'vCenter HTTPS port must be a whole number between 1 and 65535.';
        return '';
      }
      function applianceError() {
        var error = hostError(); if (error) return error;
        if (!discovery) return 'Detect the vCenter version before continuing.';
        if (!el('Folder').value) return discovery.selection.reason || 'Choose a detected VDT installation.';
        if (remoteProducts.indexOf(el('Product').value) < 0) return 'Choose a supported remote product. Other products can be imported manually.';
        var selected = (discovery.selection.candidates || []).find(function(item) { return item.folder === el('Folder').value; });
        if (!selected) return 'The selected VDT release does not match this vCenter version. Detect the version again or install the compatible package.';
        if (!selected.remote_supported) return 'VDT ' + selected.version + ' requires manual collection; this release has no reviewed managed runner.';
        var port = Number(el('Port').value);
        if (!Number.isInteger(port) || port < 1 || port > 65535) return 'SSH port must be a whole number between 1 and 65535.';
        return '';
      }
      async function detectVcenter() {
        var error = hostError(); if (error) throw new Error(error);
        busy = true; invalidate(true, true); message('', false);
        el('Discovery').textContent = 'Detecting vCenter version…';
        try {
          var response = await post('/api/plugins/vdt/discover', {host:el('Host').value.trim(), https_port:Number(el('ApiPort').value)});
          if (!response.vcenter || !response.selection) throw new Error('vCenter discovery did not return product and compatibility details.');
          discovery = response;
          if (response.selection.selected_folder) el('Folder').value = response.selection.selected_folder;
          else el('Folder').selectedIndex = -1;
          selectProducts();
          el('Legacy').hidden = response.selection.selected_family !== '1';
          el('Discovery').textContent = 'vCenter ' + response.vcenter.version + (response.vcenter.build ? ' (build ' + response.vcenter.build + ')' : '') + '. '
            + (response.selection.selected_version ? 'Selected VDT ' + response.selection.selected_version + '. ' : '') + response.selection.reason;
          return response;
        } finally { busy = false; render(false); }
      }
      function accessError() {
        if (!hostKey || !el('Trust').checked) return 'Read and verify the appliance SSH fingerprint, then confirm trust for this run.';
        if (!el('Username').value.trim() || !el('Password').value) return 'Enter the appliance SSH username and password.';
        if (!el('SsoUsername').value.trim() || !el('SsoPassword').value) return 'Enter the separate vCenter SSO username and password.';
        return '';
      }
      function review() {
        var list = el('Review'); list.replaceChildren();
        [['Appliance', el('Host').value.trim() + ':' + el('Port').value],
         ['vCenter version', discovery ? discovery.vcenter.version : 'Not discovered'],
         ['Installation', el('Folder').value], ['Product', el('Product').selectedOptions[0].textContent],
         ['Scope', 'Reviewed VDT 2.3.2 for vCenter check set; partial VDT evidence'],
         ['SSH trust', el('Fingerprint').textContent],
         ['Authentication', 'Separate SSH and SSO credentials supplied for this run only']].forEach(function(row) {
          var term = document.createElement('dt'), value = document.createElement('dd');
          term.textContent = row[0]; value.textContent = row[1]; list.append(term, value);
        });
      }
      function render(focus) {
        document.querySelectorAll('[data-vdt-remote-panel]').forEach(function(panel) { panel.hidden = Number(panel.dataset.vdtRemotePanel) !== step; });
        document.querySelectorAll('[data-vdt-remote-step]').forEach(function(button) {
          var index = Number(button.dataset.vdtRemoteStep);
          button.disabled = !available || busy || !!active() || index > reached;
          button.classList.toggle('step-complete', index < step);
          if (index === step) button.setAttribute('aria-current','step'); else button.removeAttribute('aria-current');
        });
        el('StepStatus').textContent = 'Step ' + (step + 1) + ' of 4';
        ['Folder','Product','Host','Port','ApiPort','Username','Password','SsoUsername','SsoPassword','Output'].forEach(function(id) {
          el(id).disabled = busy || !!active() || !available;
        });
        el('Trust').disabled = busy || !!active() || !hostKey || !available;
        el('Effects').disabled = busy || !!active() || !available;
        el('Discover').disabled = busy || !!active() || !available;
        el('Probe').disabled = busy || !!active() || !available;
        el('Preflight').disabled = busy || !!active() || !!accessError() || !available;
        el('Back').disabled = step === 0 || step === 3 || busy || !!active();
        el('Next').hidden = step >= 2; el('Next').disabled = busy || !available || (step === 1 && !verified);
        el('Run').hidden = step !== 2;
        el('Run').disabled = busy || !!active() || !verified || !el('Effects').checked || !el('Output').value.trim();
        el('Cancel').hidden = !active(); el('Cancel').disabled = busy;
        el('Retry').hidden = !job || !!active();
        if (step === 2) review();
        if (focus) { var heading = document.querySelector('[data-vdt-remote-panel="' + step + '"] h3'); heading.focus({preventScroll:true}); }
      }
      function invalidate(resetTrust, resetDiscovery) {
        if (resetDiscovery) { discovery = null; el('Legacy').hidden = true; el('Discovery').textContent = 'Detect the vCenter version before continuing.'; }
        verified = false; el('Effects').checked = false;
        el('PreflightStatus').textContent = 'Check appliance prerequisites again after changing connection settings.';
        el('Warnings').replaceChildren();
        if (resetTrust) { hostKey = ''; el('Trust').checked = false; el('Fingerprint').textContent = 'No fingerprint read.'; }
        render(false);
      }
      function selectProducts() {
        var selected = installations.find(function(item) { return item.folder === el('Folder').value; });
        var products = selected ? selected.products.filter(function(product) { return remoteProducts.indexOf(product) >= 0; }) : [];
        el('Product').replaceChildren();
        products.forEach(function(product) { var option = document.createElement('option'); option.value = product; option.textContent = product === 'vcenter' ? 'vCenter' : product; el('Product').append(option); });
        if (!products.length) { var option = document.createElement('option'); option.value = ''; option.textContent = 'No reviewed remote product in this installation'; el('Product').append(option); }
      }
      function showJob(current) {
        if (!job || job.id !== current.id) cancelling = false;
        job = current;
        var running = active();
        var stages = [['preflight','Preflight'],['upload','Upload'],['run','Run checks'],['validate','Validate artifacts'],['pull','Retrieve exports'],['cleanup','Remote cleanup'],['import','Import evidence']];
        var eventsData = current.events || [];
        var reachedStages = eventsData.map(function(event) { return event.stage; });
        var activeStage = current.stage;
        if (!stages.some(function(stage) { return stage[0] === activeStage; })) activeStage = reachedStages.slice().reverse().find(function(stage) { return stages.some(function(item) { return item[0] === stage; }); });
        var text = cancelling && running ? 'Cancellation requested. Waiting for the collector to stop and report cleanup.' : (current.stage || current.status || 'Collection') + ' — ' + current.status;
        if (el('Progress').textContent !== text) el('Progress').textContent = text;
        setOperationProgress('vdtRemoteProgress',{busy:!!running,label:cancelling ? 'Waiting for cancellation and cleanup' : 'VDT collection: ' + (activeStage || current.status)});
        var timeline = el('Timeline');
        var signature = JSON.stringify([reachedStages,activeStage,current.status,cancelling]);
        if (timeline.dataset.signature !== signature) {
          timeline.dataset.signature = signature; timeline.replaceChildren();
          stages.forEach(function(stage) {
            var row = document.createElement('li'), label = document.createElement('span'), detail = document.createElement('small');
            label.textContent = stage[1]; row.dataset.stage = stage[0];
            if (running && stage[0] === activeStage) { row.setAttribute('aria-current','step'); detail.textContent = cancelling ? 'Stopping; awaiting confirmation' : 'In progress — duration unknown'; }
            else if (reachedStages.indexOf(stage[0]) >= 0 || stage[0] === activeStage) detail.textContent = stage[0] === activeStage && current.status !== 'completed' ? 'Stopped here: ' + current.status : 'Stage reached';
            else detail.textContent = 'Not reached';
            row.append(label,detail); timeline.append(row);
          });
        }
        var events = el('Events'); events.replaceChildren();
        (current.events || []).forEach(function(event) { var row = document.createElement('li'); row.textContent = (event.stage ? event.stage + ': ' : '') + (event.message || ''); events.append(row); });
        var artifacts = el('Artifacts'); artifacts.replaceChildren();
        (current.artifacts || []).forEach(function(filename) { var row = document.createElement('li'); row.textContent = typeof filename === 'string' ? filename : filename.filename || filename.name || 'Collected artifact'; artifacts.append(row); });
        el('Warning').textContent = current.warning || ''; el('Warning').hidden = !current.warning;
        el('SavedOutput').textContent = current.output_dir ? 'Saved artifact folder: ' + current.output_dir : '';
        el('ScopeNotes').replaceChildren();
        (current.scope_notes || []).forEach(function(note) { var row = document.createElement('li'); row.textContent = note; el('ScopeNotes').append(row); });
        el('Cleanup').textContent = current.cleaned === true ? 'Temporary remote collection files were removed.' : current.cleaned === false ? 'Remote cleanup was not confirmed.' : '';
        if (current.remote_dir) el('Cleanup').textContent += ' Remote collection directory: ' + current.remote_dir + '. Review collection events for details.';
        if (current.error) message(current.error, false);
        else if (current.status === 'needs_credentials') message('Authentication did not complete. Start another collection and supply fresh SSH and SSO credentials.', false);
        else message('', false);
        render(false);
      }
      async function refreshRuns() {
        var data = await get('/api/plugins/vdt/runs');
        document.dispatchEvent(new CustomEvent('vdt-evidence-updated', {detail:data}));
      }
      async function completion() {
        var completedId = job.id;
        await refreshRuns();
        if (!job || job.id !== completedId) return;
        if (job.imported_exports > 0) el('Progress').textContent = 'Collection completed. ' + job.imported_exports + ' validated export(s) imported into this assessment.';
        else if (job.imported_exports === 0) el('Progress').textContent = 'Collection completed. Exports were saved locally but were not imported into this browser assessment. Import the saved JSON manually below.';
        else el('Progress').textContent = 'Collection completed. Review saved artifacts and the imported evidence list below.';
      }
      async function poll() {
        if (!job) return;
        clearTimeout(timer); el('Refresh').hidden = true;
        var polledId = job.id, generation = ++pollGeneration;
        try {
          var data = await get('/api/plugins/vdt/remote/status?job_id=' + encodeURIComponent(job.id));
          if (!job || job.id !== polledId || generation !== pollGeneration) return;
          if (!data.job || !data.job.id) throw new Error('Collection status was incomplete. Check status again.');
          showJob(data.job);
          if (active()) timer = setTimeout(poll, 1000);
          else if (job.status === 'completed') await completion();
        } catch (error) {
          if (!job || job.id !== polledId || generation !== pollGeneration) return;
          message('Connection interrupted. The collection may still be running. Check status again: ' + error.message, false);
          setOperationProgress('vdtRemoteProgress',{busy:false,label:'Collection status unavailable'});
          el('Refresh').hidden = false;
        }
      }
      async function restoreJob() {
        busy = true; render(false);
        try {
          var response = await get('/api/plugins/vdt/remote/status');
          if (response.job && response.job.id) {
            clearPasswords(); step = 3; reached = 3; showJob(response.job);
            if (active()) poll();
            else if (job.status === 'completed') await completion();
          }
        } catch (error) {
          if (error.status !== 404) message('Could not restore the previous collection status: ' + error.message, false);
        } finally { busy = false; render(false); }
      }
      el('Next').addEventListener('click', async function() {
        if (step === 0 && !discovery) {
          try { await detectVcenter(); } catch (error) { message(error.message, true); return; }
        }
        var error = step === 0 ? applianceError() : accessError();
        if (error) { message(error, true); return; }
        if (step === 1 && !verified) { message('Complete appliance preflight before continuing.', true); return; }
        message('', false); step++; reached = Math.max(reached, step);
        if (step === 2 && !el('Output').value) el('Output').value = document.getElementById('outdirInput').value.trim();
        render(true);
      });
      el('Back').addEventListener('click', function() { step = Math.max(0, step - 1); message('', false); render(true); });
      document.querySelectorAll('[data-vdt-remote-step]').forEach(function(button) {
        button.addEventListener('click', function() { if (busy || active()) return; step = Number(button.dataset.vdtRemoteStep); message('', false); render(true); });
      });
      ['Host','Port','ApiPort'].forEach(function(id) { el(id).addEventListener('input', function() { invalidate(true, id !== 'Port'); }); });
      el('Discover').addEventListener('click', async function() { try { await detectVcenter(); } catch (error) { message(error.message, true); } });
      el('Host').addEventListener('blur', function() { try { normalizeApplianceHost(); } catch (error) { message(error.message, false); } });
      ['Username','Password','SsoUsername','SsoPassword'].forEach(function(id) { el(id).addEventListener('input', function() { invalidate(false); }); });
      el('Folder').addEventListener('change', function() { selectProducts(); invalidate(false); });
      el('Product').addEventListener('change', function() { invalidate(false); });
      el('Trust').addEventListener('change', function() { verified = false; el('Effects').checked = false; render(false); });
      el('Output').addEventListener('input', function() { el('Effects').checked = false; render(false); });
      el('Effects').addEventListener('change', function() { render(false); });
      el('Probe').addEventListener('click', async function() {
        var error = applianceError(); if (error) { message(error, true); return; }
        busy = true; invalidate(true); message('', false);
        try {
          var data = await post('/api/plugins/vdt/remote/probe', {host:el('Host').value.trim(), port:Number(el('Port').value)});
          if (!data.host_key || !data.fingerprint) throw new Error('The appliance did not return a usable SSH fingerprint.');
          hostKey = data.host_key; el('Fingerprint').textContent = data.fingerprint;
        } catch (failure) { message(failure.message, true); }
        finally { busy = false; render(false); }
      });
      el('Preflight').addEventListener('click', async function() {
        var error = applianceError() || accessError(); if (error) { message(error, true); return; }
        busy = true; verified = false; message('', false); render(false);
        try {
          var body = target(); body.https_port = Number(el('ApiPort').value); body.folder = el('Folder').value; body.product = el('Product').value;
          var data = await post('/api/plugins/vdt/remote/preflight', body);
          if (data.supported_products && data.supported_products.indexOf(el('Product').value) < 0) throw new Error('This product is not supported for reviewed remote collection. Use manual export and import.');
          if (!data.ok) throw new Error(data.error || 'Appliance prerequisites were not met.');
          if (data.vcenter && data.selection) discovery = {vcenter:data.vcenter, selection:data.selection};
          verified = true;
          el('PreflightStatus').textContent = 'SSH and basic appliance checks passed. Native libraries, payload integrity, and SSO authentication are checked during collection.';
          el('Warnings').replaceChildren();
          (data.warnings || []).forEach(function(warning) { var row = document.createElement('li'); row.textContent = warning; el('Warnings').append(row); });
        } catch (failure) { message(failure.message, true); el('PreflightStatus').textContent = 'Preflight did not pass. Check credentials, access, and the appliance prerequisites, then retry.'; }
        finally { busy = false; render(false); }
      });
      el('Run').addEventListener('click', async function() {
        var error = applianceError() || accessError();
        if (error || !verified || !el('Effects').checked || !el('Output').value.trim()) { message(error || 'Complete preflight, choose the output folder, and review collection effects.', true); return; }
        busy = true; message('', false); render(false);
        try {
          var response = await post('/api/plugins/vdt/remote/run', {target:target(), folder:el('Folder').value,
            product:el('Product').value, https_port:Number(el('ApiPort').value), sso_username:el('SsoUsername').value.trim(), sso_password:el('SsoPassword').value,
            output_dir:el('Output').value.trim()});
          if (!response.job || !response.job.id) throw new Error('The collection did not return a job identifier. Check local server status before retrying.');
          clearPasswords(); verified = false; el('Trust').checked = false; el('Effects').checked = false;
          step = 3; reached = 3; showJob(response.job); poll();
        } catch (failure) { message(failure.message, true); }
        finally { busy = false; render(false); }
      });
      el('Cancel').addEventListener('click', async function() {
        if (!active() || busy) return;
        busy = true; render(false);
        try { await post('/api/plugins/vdt/remote/cancel', {job_id:job.id}); cancelling = true; el('Progress').textContent = 'Cancellation requested. Waiting for the collector to stop and report cleanup.'; poll(); }
        catch (failure) { message(failure.message, true); }
        finally { busy = false; render(false); }
      });
      el('Refresh').addEventListener('click', poll);
      el('Retry').addEventListener('click', function() {
        clearTimeout(timer); pollGeneration++; clearPasswords(); job = null; verified = false; cancelling = false; setOperationProgress('vdtRemoteProgress',{busy:false,label:'No collection running'});
        el('Trust').checked = false; el('Effects').checked = false; el('Refresh').hidden = true;
        step = applianceError() ? 0 : 1; reached = step; message('', false); el('PreflightStatus').textContent = 'Supply fresh credentials, confirm SSH trust for this run, and repeat preflight.'; render(true);
      });
      function applyCatalog(data, restore) {
        var catalog = data.vdt, remote = catalog.remote_collection || {available:true, products:['vcenter']};
        available = remote.available !== false; remoteProducts = remote.products || ['vcenter'];
        installations = (catalog.installations || []).filter(function(item) { return item.products.indexOf('vcenter') >= 0; });
        el('Folder').replaceChildren();
        installations.forEach(function(item) { var option = document.createElement('option'); option.value = item.folder; option.textContent = (item.folder === '.' ? 'Plugin root' : item.folder) + ' — VDT ' + (item.versions.vcenter || 'version unknown'); el('Folder').append(option); });
        selectProducts();
        var reason = remote.reason || 'Remote collection is unavailable in this server mode. Use manual import below.';
        el('Unavailable').hidden = available; el('Unavailable').textContent = reason;
        el('Workflow').hidden = !available;
        if (!restore && !active()) invalidate(false, true);
        render(false);
        if (available && restore) restoreJob();
      }
      get('/api/plugins').then(function(data) { applyCatalog(data, true); }).catch(function(error) { available = false; message('Could not load remote collection capabilities: ' + error.message, false); render(false); });
      document.addEventListener('vdt-installations-updated', function(event) { applyCatalog(event.detail, false); });
      window.addEventListener('pagehide', function() { clearPasswords(); });
      render(false);
    })();
  }
"""
