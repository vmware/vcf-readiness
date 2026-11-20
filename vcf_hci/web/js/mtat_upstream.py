"""Native upstream MTAT controls; domain calculations remain in the plugin."""

JS_MTAT_UPSTREAM = r"""
  var mtatUpstream = (function () {
    var ready = false, activeJob = '', activeImport = '', selectedDataset = '', lastResult = null, latestDatasets = [];
    var discoveryGeneration = 0, rangeGeneration = 0;
    function el(id) { return document.getElementById(id); }
    async function call(operation, payload) {
      var body = Object.assign({}, payload || {}, {acknowledged:true});
      var result = await post('/api/plugins/mtat/upstream/' + operation, body);
      if (result && result.error) throw new Error(typeof result.error === 'string' ? result.error : (result.error.message || 'MTAT operation failed.'));
      return result;
    }
    function values(id) { return Array.from(el(id).selectedOptions).map(function (item) { return item.value; }).filter(Boolean); }
    function status(message) { ['mtatUpstreamStatus','mtatUpstreamExportStatus'].forEach(function (id) { if (el(id)) el(id).textContent = message; }); }
    function show(value) {
      el('mtatUpstreamOutput').textContent = JSON.stringify(value, null, 2);
      var target = el('mtatUpstreamTables'); target.replaceChildren();
      function table(title, rows) {
        if (!rows.length) return;
        var heading = document.createElement('h3'); heading.textContent = title; target.append(heading);
        var columns = Array.from(new Set(rows.reduce(function (keys, row) { return keys.concat(Object.keys(row)); }, [])));
        var container = document.createElement('div'); container.style.overflowX = 'auto';
        var grid = document.createElement('table'); grid.className = 'table table-compact';
        var head = document.createElement('thead'), header = document.createElement('tr');
        columns.forEach(function (key) { var th = document.createElement('th'); th.textContent = key.replace(/_/g, ' '); header.append(th); });
        head.append(header); grid.append(head);
        var body = document.createElement('tbody');
        rows.slice(0, 500).forEach(function (row) { var tr = document.createElement('tr'); columns.forEach(function (key) { var td = document.createElement('td'), cell = row[key]; td.textContent = cell === null || cell === undefined ? 'Unknown' : (typeof cell === 'object' ? JSON.stringify(cell) : String(cell)); tr.append(td); }); body.append(tr); });
        grid.append(body); container.append(grid); target.append(container);
      }
      if (Array.isArray(value)) table('Saved evidence', value.filter(function (row) { return row && typeof row === 'object'; }));
      else if (value && typeof value === 'object') {
        Object.keys(value).forEach(function (key) { if (key !== 'clusters' && Array.isArray(value[key]) && value[key].length && typeof value[key][0] === 'object') table(key.replace(/_/g, ' '), value[key]); });
        if (Array.isArray(value.clusters)) value.clusters.forEach(function (cluster) {
          var title = cluster.cluster + ' · ' + cluster.range_name;
          if (cluster.summary) table('Assessment · ' + title, Object.keys(cluster.summary).map(function (key) { return {metric:key, value:cluster.summary[key]}; }));
          if (cluster.qualification) table('Qualification · ' + title, Array.isArray(cluster.qualification) ? cluster.qualification : [cluster.qualification]);
          if (cluster.sizing) {
            table('Sizing evidence · ' + title, [{status:cluster.sizing.status, blocked_reasons:cluster.sizing.blocked_reasons, assumptions:cluster.sizing.assumptions}]);
            ['brownfield','greenfield'].forEach(function (name) { var plan = cluster.sizing[name]; if (plan) table((name === 'brownfield' ? 'Existing host expansion · ' : 'Hardware refresh · ') + title, Object.keys(plan).map(function (key) { return {metric:key, value:plan[key]}; })); });
          }
        });
        if (!target.children.length) table('Evidence summary', Object.keys(value).map(function (key) { return {metric:key.replace(/_/g, ' '), value:value[key]}; }));
      }
      if (value && value.result) lastResult = value.result;
    }
    async function describe() {
      var result = await call('describe');
      if (result.active === false) { ready = false; throw new Error('Activate a compatible upstream package in Plugins first.'); }
      ready = true;
      el('wizMtatCustom').disabled = !(result.capabilities && result.capabilities.custom_windows);
      if (el('wizMtatCustom').disabled) el('wizMtatCustom').checked = false;
      status('Upstream MTAT connected. Calculations and reports use the installed plugin.');
      return result;
    }
    function chooseOptions(select, rows, selected) {
      select.replaceChildren();
      rows.forEach(function (row) { var item = new Option(row.label, row.value); item.selected = selected || false; select.add(item); });
    }
    function clusterChoices() {
      var target = el('wizMtatClusterChoices'), select = el('wizMtatClusters');
      target.replaceChildren();
      Array.from(select.options).forEach(function (option, index) {
        var row = document.createElement('div'); row.className = 'clr-check-row';
        var box = document.createElement('input'); box.type = 'checkbox'; box.id = 'wizMtatClusterChoice' + index;
        box.checked = option.selected;
        var label = document.createElement('label'); label.htmlFor = box.id; label.textContent = option.textContent;
        box.addEventListener('change', function () { option.selected = box.checked; select.dispatchEvent(new Event('change', {bubbles:true})); });
        row.append(box, label); target.append(row);
      });
      el('wizMtatClustersAll').disabled = !select.options.length;
      if (!select.options.length) target.textContent = 'No MTAT clusters loaded. Activate the upstream package in Plugins, then connect to the selected source.';
    }
    async function discover(credentials) {
      var generation = ++discoveryGeneration;
      rangeGeneration += 1;
      chooseOptions(el('wizMtatClusters'), [], false);
      chooseOptions(el('wizMtatRanges'), [], false);
      clusterChoices();
      el('wizMtatUpstreamStatus').textContent = 'Checking the installed MTAT engine…';
      await describe();
      if (generation !== discoveryGeneration) return;
      el('wizMtatUpstreamStatus').textContent = 'Connecting and discovering clusters…';
      var result = await call('connect', credentials);
      if (generation !== discoveryGeneration) return;
      var clusters = result.clusters || [];
      chooseOptions(el('wizMtatClusters'), clusters.map(function (row) { return {value:row.Value || row.id || row.key, label:row.Text || row.name || row.Value}; }), clusters.length === 1);
      clusterChoices();
      el('wizMtatUpstreamStatus').textContent = clusters.length + ' accessible MTAT cluster(s). Select the MTAT scope independently of Inventory.';
      if (result.failedTargets && result.failedTargets.length) {
        var hints = {tls_certificate:'Certificate validation failed. Review certificate trust, pin or CA bundle.', authentication_failed:'Authentication failed. Review credentials and the Operations authentication source.', permission_denied:'Access denied. Review inventory and metric read permissions.', invalid_request:'Connection input was rejected. Review the endpoint and credentials.'};
        el('wizMtatUpstreamStatus').textContent += ' ' + Array.from(new Set(result.failedTargets.map(function (item) { return hints[item.error_code] || 'Connection failed. Review the MTAT source connection diagnostics.'; }))).join(' ');
      } else if (!clusters.length) el('wizMtatUpstreamStatus').textContent += ' No clusters were returned. Check the selected source and account inventory scope.';
      await ranges();
      return result;
    }
    async function ranges() {
      var generation = ++rangeGeneration;
      var keys = values('wizMtatClusters'), common = null;
      for (var key of keys) {
        var result = await call('ranges', {cluster:key});
        if (generation !== rangeGeneration) return [];
        var available = result.ranges || [];
        common = common === null ? available : common.filter(function (name) { return available.indexOf(name) >= 0; });
      }
      chooseOptions(el('wizMtatRanges'), (common || []).map(function (name) { return {value:name, label:name}; }), true);
      return common || [];
    }
    function validate() {
      if (!ready) return 'Activate a compatible upstream package in Plugins, then check the upstream connection.';
      var mode = el('wizMtatMode').value;
      if (mode === 'live' && (!values('wizMtatClusters').length || (!values('wizMtatRanges').length && !el('wizMtatCustom').checked))) return 'Discover and select MTAT clusters and at least one supported range.';
      if (mode === 'live' && values('wizMtatRanges').length + (el('wizMtatCustom').checked ? 1 : 0) > 5) return 'Choose at most five collection ranges, including the custom window.';
      if (mode === 'live' && el('wizMtatCustom').checked) {
        var window = customWindow();
        if (!Number.isFinite(window.begin) || !Number.isFinite(window.end) || window.begin >= window.end || window.end > Date.now()) return 'Enter a valid custom UTC window whose end is not in the future.';
      }
      if (mode !== 'live' && !selectedDataset) return 'Import or select a saved MTAT dataset in the upstream workspace before running.';
      return '';
    }
    async function datasets() {
      await describe();
      var result = await call('query', {action:'datasets'});
      var rows = (Array.isArray(result) ? result : result.datasets || []).filter(function (row) { return (!row.state || row.state === 'complete') && row.batchComplete !== 0; });
      var previousExports = values('mtatUpstreamExportDatasets');
      chooseOptions(el('mtatUpstreamDataset'), rows.map(function (row) { return {value:row.id || row.Id, label:(row.name || row.Name || row.id) + ' · ' + (row.range || '')}; }), false);
      if (selectedDataset) el('mtatUpstreamDataset').value = selectedDataset;
      if (!el('mtatUpstreamDataset').value && rows.length) el('mtatUpstreamDataset').selectedIndex = 0;
      selectedDataset = el('mtatUpstreamDataset').value;
      chooseOptions(el('mtatUpstreamExportDatasets'), rows.map(function (row) { return {value:row.id || row.Id, label:(row.name || row.Name || row.id) + ' · ' + (row.range || '')}; }), false);
      var selectedExports = latestDatasets.length ? latestDatasets : (previousExports.length ? previousExports : [selectedDataset]);
      Array.from(el('mtatUpstreamExportDatasets').options).forEach(function (option) { option.selected = selectedExports.indexOf(option.value) >= 0; });
      show(result); return result;
    }
    async function poll(id, onProgress) {
      activeJob = id;
      while (true) {
        var state = await call('jobs.status', {id:id});
        show(state);
        if (onProgress) onProgress(state);
        if (['completed','partial','failed','cancelled','timedOut','interrupted'].indexOf(state.status) >= 0) {
          activeJob = '';
          var completedTasks = (state.tasks || []).filter(function (task) { return task.status === 'completed' && task.dataset_id; });
          latestDatasets = completedTasks.map(function (task) { return task.dataset_id; });
          if (completedTasks.length) selectedDataset = completedTasks[0].dataset_id;
          await datasets();
          if (state.status !== 'completed') {
            var completed = (state.tasks || []).some(function (task) { return task.status === 'completed'; });
            if (!completed) throw new Error(state.message || 'MTAT job ' + state.status + '.');
            status('MTAT ' + state.status + '; completed tasks are available. Reconnect to resume unfinished tasks.');
          }
          return state;
        }
        await new Promise(function (resolve) { setTimeout(resolve, 700); });
      }
    }
    async function run(onProgress) {
      var error = validate(); if (error) throw new Error(error);
      if (el('wizMtatMode').value !== 'live') return {id:'', dataset:selectedDataset, status:'completed'};
      var request = {clusters:values('wizMtatClusters'), ranges:values('wizMtatRanges'), policy:el('wizMtatPolicy').value, acknowledged:true};
      if (el('wizMtatCustom').checked) { request.ranges.push('Custom history'); request.windows = {'Custom history':customWindow()}; }
      var result = await call('jobs.start', request);
      activeJob = result.id;
      var outcome = await poll(result.id, onProgress);
      return {id:result.id, dataset:selectedDataset, status:outcome.status};
    }
    function customWindow() {
      return {begin:Date.parse(el('wizMtatCustomBegin').value + 'Z'), end:Date.parse(el('wizMtatCustomEnd').value + 'Z')};
    }
    async function query() {
      selectedDataset = el('mtatUpstreamDataset').value;
      if (!selectedDataset) throw new Error('Select a saved MTAT dataset.');
      var payload = {action:el('mtatUpstreamQuery').value, ds:selectedDataset, cluster:el('mtatUpstreamCluster').value.trim(),
        kind:el('mtatUpstreamKind').value, page:Number(el('mtatUpstreamPage').value), size:Number(el('mtatUpstreamSize').value),
        sort:'name', descending:false, maxPoints:1000, id:el('mtatUpstreamEntity').value.trim(), query:el('mtatUpstreamSearch').value.trim(),
        tenant:el('mtatUpstreamTenant').value.trim(), threshold:Number(el('mtatUpstreamThreshold').value), persistence:Number(el('mtatUpstreamPersistence').value)};
      show(await call('query', payload)); status('Saved evidence loaded. Missing observations remain unknown.');
    }
    function inputs() {
      return {strategy:el('mtatUpstreamStrategy').value, ratio:Number(el('mtatUpstreamRatio').value),
        node_capacity_gb:Number(el('mtatUpstreamCapacity').value), target_usable_hosts:Math.max(1, Number(el('mtatUpstreamHosts').value)),
        node_mode:Number(el('mtatUpstreamHosts').value) > 0 ? 'hosts' : 'capacity', mode:el('mtatUpstreamSizingMode').value,
        drive_gb:Number(el('mtatUpstreamDrive').value), custom_ratio_pct:Number(el('mtatUpstreamCustomRatio').value),
        ha:Number(el('mtatUpstreamHa').value), cpu_multiplier:Number(el('mtatUpstreamCpu').value),
        consumed_ceiling:Number(el('mtatUpstreamCeiling').value) / 100, dram_price:Number(el('mtatUpstreamDramPrice').value),
        nvme_price:Number(el('mtatUpstreamNvmePrice').value), chassis_cost:Number(el('mtatUpstreamChassis').value),
        mirroring:el('mtatUpstreamMirror').checked, allow_assumptions:el('mtatUpstreamAssumptions').checked};
    }
    async function calculate() {
      selectedDataset = el('mtatUpstreamDataset').value;
      if (!selectedDataset) throw new Error('Select a dataset first.');
      var result = await call('calculate', {dataset:selectedDataset, datasets:values('mtatUpstreamExportDatasets'), inputs:inputs(), policy:el('wizMtatPolicy').value});
      show(result); status('Sizing returned by upstream MTAT. Review evidence gaps and assumptions before using the scenario.');
    }
    async function exportResult() {
      selectedDataset = el('mtatUpstreamDataset').value;
      if (!selectedDataset) throw new Error('Select a dataset first.');
      var sections = ['assessment','analytics','sizing'].filter(function (name) { return el('mtatUpstreamSection-' + name).checked; });
      if (!sections.length) throw new Error('Select at least one report section.');
      status('Preparing export…');
      var result = await call('export', {dataset:selectedDataset, datasets:values('mtatUpstreamExportDatasets'), format:el('mtatUpstreamFormat').value, table:el('mtatUpstreamCsvTable').value, inputs:inputs(), policy:el('wizMtatPolicy').value,
        sections:sections, obfuscate:el('mtatUpstreamObfuscate').checked});
      var encoded = result.content_base64 || result.content_b64 || result.base64;
      if (!encoded && !result.content) throw new Error('MTAT returned an empty export. Select a completed dataset and retry.');
      var content = encoded ? Uint8Array.from(atob(encoded), function (character) { return character.charCodeAt(0); }) : (result.content || '');
      var url = URL.createObjectURL(new Blob([content], {type:result.content_type || 'application/octet-stream'}));
      var link = document.createElement('a'); link.href = url; link.download = result.filename || 'mtat-export'; document.body.appendChild(link); link.click(); link.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
      status('Download requested. Check your browser downloads.');
    }
    async function importFiles() {
      await describe();
      var files = Array.from(el('mtatUpstreamFiles').files);
      if (!files.length) throw new Error('Select MTAT, Operations or RVTools files to import.');
      await datasets();
      var previous = Array.from(el('mtatUpstreamDataset').options).map(function (option) { return option.value; });
      var batch = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(function (value) { return value.toString(16).padStart(2, '0'); }).join('');
      for (var file of files) {
        var allocation = await call('query', {action:'upload', name:file.name, bytes:file.size, format:el('mtatUpstreamImportFormat').value,
          range:el('mtatUpstreamImportRange').value.trim() || 'Imported Data', unit:el('mtatUpstreamUnits').value, batch:batch, files:files.length});
        activeImport = allocation.id;
        for (var start = 0; start < file.size; start += 1024 * 1024) {
          var bytes = new Uint8Array(await file.slice(start, start + 1024 * 1024).arrayBuffer()), pieces = [];
          for (var offset = 0; offset < bytes.length; offset += 16384) pieces.push(String.fromCharCode.apply(null, bytes.subarray(offset, offset + 16384)));
          await call('import.chunk', {id:allocation.id, offset:start, content_base64:btoa(pieces.join(''))});
          status('Uploading ' + file.name + ': ' + Math.min(start + bytes.length, file.size) + ' / ' + file.size + ' bytes.');
        }
        var result = await call('query', {action:'import', id:allocation.id});
        show(result);
        if (result.id) {
          while (['complete','completed','failed','cancelled','interrupted'].indexOf(result.state || result.status) < 0) {
            await new Promise(function (resolve) { setTimeout(resolve, 700); });
            result = await call('import.status', {id:result.id}); show(result);
          }
          if (['complete','completed'].indexOf(result.state || result.status) < 0) throw new Error(result.message || 'Import did not complete.');
        }
        activeImport = '';
      }
      await datasets();
      var added = Array.from(el('mtatUpstreamDataset').options).filter(function (option) { return previous.indexOf(option.value) < 0; });
      if (added.length) { selectedDataset = added[added.length - 1].value; el('mtatUpstreamDataset').value = selectedDataset; latestDatasets = added.map(function (option) { return option.value; }); Array.from(el('mtatUpstreamExportDatasets').options).forEach(function (option) { option.selected = latestDatasets.indexOf(option.value) >= 0; }); }
      status('Import complete. The imported dataset is selected for assessment and sizing.');
    }
    function mount() {
      var parent = el('mtat-experimental'); if (!parent || el('mtatUpstreamWorkspace')) return;
      var card = document.createElement('section'); card.hidden = true; card.className = 'card'; card.id = 'mtatUpstreamWorkspace';
      card.innerHTML = '<div class="card-body"><h2>Upstream MTAT workspace</h2><p>Review saved plugin evidence, import offline files, and request upstream calculations. Inputs stay in this browser session; credentials are resolved by VCF-R.</p>' +
        '<label for="mtatUpstreamSource">Input source</label><select class="clr-select" id="mtatUpstreamSource"><option value="saved">Saved plugin datasets</option><option value="offline">Offline files / workbook</option></select>' +
        '<p id="mtatUpstreamStatus" role="status" aria-live="polite">Activate a compatible package in Plugins to start.</p>' +
        '<div class="form-grid"><div class="clr-form-group"><label for="mtatUpstreamDataset">Saved dataset</label><select class="clr-select" id="mtatUpstreamDataset"></select></div>' +
        '<div class="clr-form-group"><label for="mtatUpstreamCluster">Cluster key (optional filter)</label><input class="clr-input" id="mtatUpstreamCluster"></div>' +
        '<div class="clr-form-group"><label for="mtatUpstreamQuery">Evidence view</label><select class="clr-select" id="mtatUpstreamQuery"><option>summary</option><option>page</option><option>vms</option><option>timeline</option><option>histogram</option><option>crossings</option><option>tenants</option><option>assessmentgroups</option></select></div>' +
        '<div><label for="mtatUpstreamKind">Group evidence by</label><select class="clr-select" id="mtatUpstreamKind"><option value="host">Hosts</option><option value="cluster">Clusters</option></select></div>' +
        '<div><label for="mtatUpstreamEntity">Host or cluster identity (timeline)</label><input class="clr-input" id="mtatUpstreamEntity"></div>' +
        '<div><label for="mtatUpstreamSearch">Search rows</label><input class="clr-input" id="mtatUpstreamSearch" maxlength="200"></div>' +
        '<div><label for="mtatUpstreamTenant">Tenant (optional)</label><input class="clr-input" id="mtatUpstreamTenant"></div>' +
        '<div><label for="mtatUpstreamThreshold">Active memory threshold (%)</label><input class="clr-input" id="mtatUpstreamThreshold" type="number" min="0" max="100" value="50"></div>' +
        '<div><label for="mtatUpstreamPersistence">Required observation share (%)</label><input class="clr-input" id="mtatUpstreamPersistence" type="number" min="0" max="100" value="5"></div>' +
        '<div><label for="mtatUpstreamPage">Page (zero based)</label><input class="clr-input" id="mtatUpstreamPage" type="number" value="0" min="0"></div>' +
        '<div><label for="mtatUpstreamSize">Rows per page</label><input class="clr-input" id="mtatUpstreamSize" type="number" value="25" min="1" max="500"></div></div>' +
        '<div class="flex gap-sm mt-half"><button class="btn btn-outline" type="button" data-upstream-action="datasets">Open saved datasets</button><button class="btn btn-outline" type="button" data-upstream-action="query">Load evidence</button><button class="btn btn-outline" type="button" data-upstream-action="jobs">Jobs / recovery</button><button class="btn btn-outline" type="button" data-upstream-action="cancel">Cancel active job</button></div>' +
        '<label for="mtatUpstreamRecoveryKind">Recovery workflow</label><select class="clr-select" id="mtatUpstreamRecoveryKind"><option value="collection">Live collection</option><option value="import">Offline import</option></select>' +
        '<label for="mtatUpstreamResume">Job ID to resume after reconnecting</label><input class="clr-input" id="mtatUpstreamResume"><button class="btn btn-outline" type="button" data-upstream-action="resume">Resume job</button>' +
        '<details id="mtatUpstreamImport" hidden><summary>Import offline evidence</summary><div class="form-grid"><div><label for="mtatUpstreamImportFormat">Source format</label><select class="clr-select" id="mtatUpstreamImportFormat"><option value="vrops">Operations</option><option value="rvtools">RVTools</option><option value="mtat">MTAT Hosts/VMs</option><option value="history">MTAT history</option></select></div>' +
        '<div><label for="mtatUpstreamFiles">Files</label><input id="mtatUpstreamFiles" type="file" multiple accept=".csv,.xlsx"></div><div><label for="mtatUpstreamImportRange">Range label</label><input class="clr-input" id="mtatUpstreamImportRange" value="Imported Data"></div>' +
        '<div><label for="mtatUpstreamUnits">Memory units</label><select class="clr-select" id="mtatUpstreamUnits"><option value="auto">From source</option><option>GB</option><option>VMWARE_GB</option><option>MB</option><option>KB</option></select></div></div><button class="btn btn-outline" type="button" data-upstream-action="import">Import files</button></details>' +
        '<details><summary>Sizing and savings</summary><p>These are scenario inputs. Unknown configuration must be verified; optional assumptions do not establish eligibility.</p><div class="form-grid">' +
        '<div><label for="mtatUpstreamStrategy">Strategy</label><select class="clr-select" id="mtatUpstreamStrategy"><option value="brownfield">Expand existing hosts</option><option value="greenfield">Refresh hosts</option></select></div>' +
        '<div><label for="mtatUpstreamRatio">NVMe / DRAM ratio</label><select class="clr-select" id="mtatUpstreamRatio"><option value="0.5">50%</option><option value="1" selected>100%</option><option value="2">200%</option><option value="3">300%</option><option value="4">400%</option></select></div>' +
        '<div><label for="mtatUpstreamSizingMode">NVMe planning input</label><select class="clr-select" id="mtatUpstreamSizingMode"><option value="ratio">Target ratio</option><option value="drive">Drive capacity</option><option value="custom">Custom ratio</option></select></div>' +
        '<div><label for="mtatUpstreamDrive">NVMe drive capacity (GB)</label><input class="clr-input" id="mtatUpstreamDrive" type="number" min="1" value="3840"></div>' +
        '<div><label for="mtatUpstreamCustomRatio">Custom NVMe / DRAM (%)</label><input class="clr-input" id="mtatUpstreamCustomRatio" type="number" min="0" max="400" value="100"></div>' +
        '<div><label for="mtatUpstreamCapacity">Target node DRAM (GB)</label><input class="clr-input" id="mtatUpstreamCapacity" type="number" min="1" value="1024"></div>' +
        '<div><label for="mtatUpstreamHosts">Target usable hosts (0 = calculate)</label><input class="clr-input" id="mtatUpstreamHosts" type="number" min="0" value="0"></div>' +
        '<div><label for="mtatUpstreamHa">HA reserve hosts</label><input class="clr-input" id="mtatUpstreamHa" type="number" min="0" max="2" value="1"></div>' +
        '<div><label for="mtatUpstreamCpu">CPU capacity multiplier</label><input class="clr-input" id="mtatUpstreamCpu" type="number" min="0.1" step="0.1" value="1"></div>' +
        '<div><label for="mtatUpstreamCeiling">Consumed ceiling after HA (%)</label><input class="clr-input" id="mtatUpstreamCeiling" type="number" min="10" max="90" value="85"></div>' +
        '<div><label for="mtatUpstreamDramPrice">DRAM price per GB</label><input class="clr-input" id="mtatUpstreamDramPrice" type="number" min="0" value="100"></div>' +
        '<div><label for="mtatUpstreamNvmePrice">NVMe price per GB</label><input class="clr-input" id="mtatUpstreamNvmePrice" type="number" min="0" step="0.01" value="0.25"></div>' +
        '<div><label for="mtatUpstreamChassis">Chassis cost</label><input class="clr-input" id="mtatUpstreamChassis" type="number" min="0" value="15000"></div></div>' +
        '<div class="clr-check-row"><input type="checkbox" id="mtatUpstreamMirror" checked><label for="mtatUpstreamMirror">Mirror NVMe</label></div>' +
        '<div class="clr-check-row"><input type="checkbox" id="mtatUpstreamAssumptions"><label for="mtatUpstreamAssumptions">Allow explicitly listed missing-evidence assumptions for this scenario</label></div>' +
        '<button class="btn btn-outline" type="button" data-upstream-action="calculate">Calculate scenario</button></details>' +
        '<label for="mtatUpstreamExportDatasets">Datasets and collected ranges for calculation/export</label><select class="clr-select" id="mtatUpstreamExportDatasets" multiple size="5"></select><p class="clr-hint">Select several saved ranges to compare in one offline report. Queries above use the single saved dataset selector.</p>' +
        '<label for="mtatUpstreamFormat">Offline export</label><select class="clr-select" id="mtatUpstreamFormat"><option value="html">HTML report</option><option value="zip">CSV/metadata ZIP</option><option value="csv">CSV</option></select>' +
        '<fieldset><legend>Report sections</legend><div class="clr-check-row"><input id="mtatUpstreamSection-assessment" type="checkbox" checked><label for="mtatUpstreamSection-assessment">Assessment</label></div><div class="clr-check-row"><input id="mtatUpstreamSection-analytics" type="checkbox" checked><label for="mtatUpstreamSection-analytics">Analytics</label></div><div class="clr-check-row"><input id="mtatUpstreamSection-sizing" type="checkbox" checked><label for="mtatUpstreamSection-sizing">Sizing and savings</label></div></fieldset>' +
        '<div class="clr-check-row"><input id="mtatUpstreamObfuscate" type="checkbox"><label for="mtatUpstreamObfuscate">Obfuscate this MTAT export</label></div><p class="clr-hint">Aliases are local to this export. They are independent of BMC or Inventory aliases and do not establish host correlation.</p>' +
        '<label for="mtatUpstreamCsvTable">CSV table</label><select class="clr-select" id="mtatUpstreamCsvTable"><option value="hosts">Hosts</option><option value="vms">Virtual machines</option><option value="hosts_history">Hosts by range</option><option value="vms_history">VMs by range</option><option value="matrix">Qualification matrix</option></select><button class="btn btn-outline" type="button" data-upstream-action="export">Download export</button><p id="mtatUpstreamExportStatus" role="status" aria-live="polite"></p>' +
        '<div id="mtatUpstreamTables" aria-live="polite"></div><details><summary>Source evidence metadata</summary><pre id="mtatUpstreamOutput" style="white-space:pre-wrap;overflow-wrap:anywhere;max-height:36rem;overflow:auto" aria-label="Upstream result"></pre></details></div>';
      parent.append(card);
      var engine = el('mtatPageEngine');
      function selectEngine() {
        card.hidden = engine.value !== 'upstream';
        el('mtatWorkflow').hidden = engine.value === 'upstream';
      }
      engine.addEventListener('change', selectEngine);
      el('mtatUpstreamSource').addEventListener('change', function () {
        el('mtatUpstreamImport').hidden = this.value !== 'offline';
        el('mtatUpstreamImport').open = this.value === 'offline';
      });
      document.addEventListener('click', function (event) {
        var link = event.target.closest('a[href="#mtat-experimental"]');
        if (link && link.closest('#wizardMtatUpstreamScope')) { engine.value = 'upstream'; selectEngine(); }
      });
      selectEngine();
      var end = new Date(); end.setUTCSeconds(0, 0);
      el('wizMtatCustomEnd').value = end.toISOString().slice(0, 16);
      el('wizMtatCustomBegin').value = new Date(end.getTime() - 7 * 86400000).toISOString().slice(0, 16);
      card.addEventListener('click', async function (event) {
        var button = event.target.closest('[data-upstream-action]'); if (!button || button.disabled) return;
        button.disabled = true;
        try {
          var action = button.dataset.upstreamAction;
          if (action === 'datasets') await datasets();
          else if (action === 'query') await query();
          else if (action === 'calculate') await calculate();
          else if (action === 'export') await exportResult();
          else if (action === 'import') await importFiles();
          else if (action === 'jobs') show(await call(el('mtatUpstreamRecoveryKind').value === 'import' ? 'import.list' : 'jobs.list'));
          else if (action === 'cancel') { var id = activeImport || activeJob || el('mtatUpstreamResume').value.trim(); if (!id) throw new Error('Select or enter an active job ID.'); show(await call(activeImport || el('mtatUpstreamRecoveryKind').value === 'import' ? 'import.cancel' : 'jobs.cancel', {id:id})); status('Cancellation requested; waiting for acquisition and writing to stop.'); }
          else if (action === 'resume') {
            var request = {id:el('mtatUpstreamResume').value.trim(), clusters:values('wizMtatClusters'), acknowledged:true};
            var resumed = await call(el('mtatUpstreamRecoveryKind').value === 'import' ? 'import.resume' : 'jobs.resume', request);
            if (el('mtatUpstreamRecoveryKind').value === 'import') { show(resumed); status('Import resume requested. Open Jobs / recovery to check progress.'); }
            else await poll(resumed.id);
          }
        } catch (error) { status(error.message); }
        finally { button.disabled = false; }
      });
      el('mtatUpstreamDataset').addEventListener('change', function () { selectedDataset = this.value; latestDatasets = []; Array.from(el('mtatUpstreamExportDatasets').options).forEach(function (option) { option.selected = option.value === selectedDataset; }); });
    }
    el('wizMtatClustersAll').addEventListener('click', function () {
      var select = el('wizMtatClusters');
      var all = Array.from(select.options).every(function (option) { return option.selected; });
      Array.from(select.options).forEach(function (option) { option.selected = !all; });
      clusterChoices(); select.dispatchEvent(new Event('change', {bubbles:true}));
    });
    el('wizMtatClusters').addEventListener('change', function () {
      Array.from(el('wizMtatClusterChoices').querySelectorAll('input')).forEach(function (box, index) { box.checked = el('wizMtatClusters').options[index].selected; });
      el('wizMtatClustersAll').textContent = values('wizMtatClusters').length === el('wizMtatClusters').options.length && el('wizMtatClusters').options.length ? 'Clear cluster selection' : 'Select all clusters';
    });
    mount();
    return {call:call, describe:describe, discover:discover, ranges:ranges, validate:validate, run:run, datasets:datasets,
      reset:function () { discoveryGeneration += 1; rangeGeneration += 1; ready = false; selectedDataset = ''; latestDatasets = []; ['wizMtatClusters','wizMtatRanges','mtatUpstreamDataset','mtatUpstreamExportDatasets'].forEach(function (id) { if (el(id)) el(id).replaceChildren(); }); clusterChoices(); }, selected:function () { return selectedDataset; }, isReady:function () { return ready; }};
  })();
"""
