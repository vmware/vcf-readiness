"""Clarity-style scan workflow using the scanner's existing form controls."""

JS_WIZARD = """
  var wizardReady = false;
  var wizardStep = 0;
  var wizardReached = 0;
  var wizardBusy = false;
  var wizardHclSignature = '';
  var wizardMounts = [];
  var wizardVisited = false;
  function syncWizardLayout(section) {
    if (!wizardReady) return;
    if (section === 'scan-wizard') wizardVisited = true;
    document.getElementById('wizardResume').hidden = !wizardVisited || ['credential-vault', 'advanced-configuration'].indexOf(section) < 0;
    wizardMounts.forEach(function(item) {
      if (section === 'scan-wizard') item.slot.appendChild(item.node);
      else item.home.after(item.node);
    });
    if (section === 'scan-wizard') renderWizard(false);
  }
  function wizardError(message) {
    var error = document.getElementById('wizardError');
    error.textContent = message || '';
    toggle(error, !!message);
    if (message) error.focus();
    var current = document.querySelector('[data-wizard-step="' + wizardStep + '"]');
    current.classList.toggle('step-error', !!message);
  }
  function wizardHclWarning() {
    var meta = hclStatusMeta;
    if (hclStatusError || !meta || meta.error) return 'HCL status could not be verified. Retry the check, download, or import a bundle.';
    var custom = meta.is_custom_bundle || meta.source_type === 'custom_bundle';
    if (!custom && !meta.file_exists) return 'No local HCL database is available. Download it or import a dark-site ZIP.';
    var count = custom ? (meta.json_models_count || 0) + (meta.csv_models_count || 0) : (meta.counts || {}).total;
    if (meta.dataset_is_baseline) return 'This bundle contains a limited baseline, not a complete HCL. Download or import an approved full dataset.';
    if (!count) return 'The HCL has no verified indexed coverage. Download or import a complete dataset.';
    var age = custom ? meta.dataset_age_days : meta.age_days;
    if (age == null || age > 30 || meta.is_fresh === false) return 'The HCL is older than 30 days or its age is unknown. Update it or confirm use of limited evidence.';
    return '';
  }
  function updateWizardHcl() {
    if (!wizardReady) return;
    var meta = hclStatusMeta || {};
    var signature = JSON.stringify([meta.source_type, meta.bundle_filename, meta.file_exists, meta.age_days, meta.dataset_age_days, meta.json_models_count, meta.csv_models_count, meta.counts, meta.dataset_is_baseline, hclStatusError]);
    if (signature !== wizardHclSignature) document.getElementById('wizardHclAck').checked = false;
    wizardHclSignature = signature;
    var warning = wizardHclWarning();
    document.getElementById('wizardHclStatus').textContent = hclStatusPending ? 'Checking local HCL…' : warning || 'Local HCL is available and current. You can continue without importing a ZIP.';
    document.getElementById('wizardHclAckRow').hidden = !warning || hclStatusPending;
    if (wizardStep === 2) document.getElementById('wizardNextBtn').disabled = hclStatusPending || wizardBusy;
  }
  function wizardReview() {
    var target = document.getElementById('rangeInput').value.trim();
    var selected = Array.from(document.querySelectorAll('.host-chk:checked')).map(function(c) { return c.dataset.ip; });
    var depth = document.querySelector('input[name="scanProfile"]:checked');
    var rows = [
      ['Targets', selected.length ? selected.join(', ') : target],
      ['Credentials', document.getElementById('useVaultChk').checked ? 'Encrypted credential vault (manual credentials are fallback only)' : document.getElementById('sameCredsChk').checked ? 'Shared credentials; username: ' + (document.getElementById('usernameInput').value.trim() || 'root') : 'Per-host credentials'],
      ['Execution', document.getElementById('execRemote').checked ? 'Remote jump host: ' + document.getElementById('jumpHostSelect').selectedOptions[0].textContent : 'Local workstation'],
      ['HCL', wizardHclWarning() || 'Current local compatibility database'],
      ['Scan depth', depth ? depth.nextElementSibling.textContent : 'Default'],
      ['Concurrent hosts', document.getElementById('threadsInput').value],
      ['Output folder', document.getElementById('outdirInput').value.trim()],
      ['TLS', document.getElementById('ignoreTlsChk').checked ? 'Certificate verification disabled' : document.querySelector('input[name="tlsMode"]:checked') ? document.querySelector('input[name="tlsMode"]:checked').nextElementSibling.textContent : 'Scanner configuration'],
      ['Additional options', 'Obfuscated copies: ' + (document.getElementById('obfuscateChk').checked ? 'on' : 'off') + '; partial scans: ' + (document.getElementById('allowPartialChk').checked ? 'on' : 'off') + '; deep crawling: ' + (document.getElementById('crawlEndpointsChk') && document.getElementById('crawlEndpointsChk').checked ? 'on' : 'off')]
    ];
    var list = document.getElementById('wizardReview');
    list.replaceChildren();
    rows.forEach(function(row) {
      var term = document.createElement('dt'); term.textContent = row[0];
      var detail = document.createElement('dd'); detail.textContent = row[1];
      list.append(term, detail);
    });
  }
  function renderWizard(focus) {
    document.querySelectorAll('[data-wizard-panel]').forEach(function(panel) { panel.hidden = Number(panel.dataset.wizardPanel) !== wizardStep; });
    document.querySelectorAll('[data-wizard-step]').forEach(function(button) {
      var index = Number(button.dataset.wizardStep);
      button.disabled = index > wizardReached || wizardBusy;
      button.classList.toggle('step-complete', index < wizardStep);
      if (index === wizardStep) button.setAttribute('aria-current', 'step');
      else button.removeAttribute('aria-current');
    });
    document.getElementById('wizardStepStatus').textContent = 'Step ' + (wizardStep + 1) + ' of 5';
    document.getElementById('wizardBackBtn').disabled = wizardStep === 0 || wizardBusy;
    document.getElementById('wizardNextBtn').hidden = wizardStep === 4;
    document.getElementById('wizardNextBtn').disabled = wizardBusy;
    document.getElementById('wizardRunBtn').hidden = wizardStep !== 4;
    document.getElementById('wizardRunBtn').disabled = wizardBusy || document.getElementById('runBtn').disabled || !!_scanRunning;
    updateWizardHcl();
    if (wizardStep === 4) wizardReview();
    if (focus) {
      var heading = document.querySelector('[data-wizard-panel="' + wizardStep + '"] h2');
      heading.focus({preventScroll: true});
      heading.scrollIntoView({block: 'start'});
    }
  }
  function wizardFieldError(id,message) { markFieldError(id,message); return message; }
  function validateWizardStep(step) {
    if (step === 0 && !document.getElementById('rangeInput').value.trim() && !document.querySelector('.host-chk:checked')) return wizardFieldError('rangeInput','Enter at least one target address, hostname, range, or subnet.');
    if (step === 1) {
      if (document.getElementById('useVaultChk').checked && (!_vaultState.unlocked || document.getElementById('useVaultChk').disabled)) return 'Create or unlock the credential vault before using it.';
      if (!document.getElementById('useVaultChk').checked) {
        if (document.getElementById('sameCredsChk').checked && !document.getElementById('passwordInput').value.trim()) return wizardFieldError('passwordInput','Enter the BMC password, or opt in to an unlocked credential vault.');
        if (!document.getElementById('sameCredsChk').checked) {
          var inputs = Array.from(document.querySelectorAll('#perHostRows [data-field="pass"]'));
          if (!inputs.length || inputs.some(function(input) { return !input.value.trim(); })) return 'Probe and select hosts, then supply each host password, or use shared credentials.';
        }
      }
      if (document.getElementById('execRemote').checked) {
        if (!_vaultState.unlocked) return 'Remote execution requires an unlocked vault with a saved jump host.';
        if (document.getElementById('jumpHostSelect').options.length < 2) return 'Add a jump host in Credential Vault before using remote execution.';
      }
    }
    if (step === 2) {
      if (hclStatusPending) return 'Wait for the HCL check to finish.';
      if (wizardHclWarning() && !document.getElementById('wizardHclAck').checked) return 'Download or import HCL data, or explicitly acknowledge the limited evidence to continue.';
    }
    if (step === 3) {
      if (!document.getElementById('outdirInput').value.trim()) return wizardFieldError('outdirInput','Choose a folder for assessment reports.');
      var threads = Number(document.getElementById('threadsInput').value);
      if (!Number.isInteger(threads) || threads < 1 || threads > 32) return wizardFieldError('threadsInput','Concurrent hosts must be a whole number between 1 and 32.');
    }
    return '';
  }
  async function advanceWizard(run) {
    if (wizardBusy) return;
    if (_scanRunning || document.getElementById('runBtn').disabled) { wizardError('Wait for the current assessment to finish, or check that the collector is available.'); return; }
    wizardBusy = true;
    renderWizard(false);
    try {
      if ((wizardStep === 1 || run) && (document.getElementById('useVaultChk').checked || document.getElementById('execRemote').checked)) {
        var vault = await getJson('/api/vault/status');
        if (vault.status !== 200 || !vault.data.unlocked) {
          wizardStep = 1;
          wizardBusy = false;
          renderWizard(true);
          wizardError('The credential vault is locked or unavailable. Unlock it, or choose manual credentials and local execution.');
          return;
        }
        _vaultState = vault.data;
        renderVaultState();
      }
      if (run) await refreshHclStatus();
      var first = run ? 0 : wizardStep;
      var last = run ? 3 : wizardStep;
      for (var step = first; step <= last; step++) {
        var error = validateWizardStep(step);
        if (error) { wizardStep = step; wizardBusy = false; renderWizard(true); wizardError(error); return; }
      }
      wizardError('');
      if (run) {
        window.location.hash = 'scanner';
        showAppSection(false);
        document.getElementById('runBtn').click();
      } else {
        wizardStep = Math.min(4, wizardStep + 1);
        wizardReached = Math.max(wizardReached, wizardStep);
        if (wizardStep === 2) refreshHclStatus();
      }
    } catch (error) {
      wizardError('Could not verify scan settings. Retry this step.');
    } finally {
      wizardBusy = false;
      renderWizard(!run);
    }
  }
  [ ['discoveryCard','wizardTargetsSlot'], ['credentialsCard','wizardAccessSlot'], ['hclSection','wizardHclSlot'], ['scanDepthGroup','wizardDepthSlot'], ['scanThreadsGroup','wizardThreadsSlot'], ['scanSetupCard','wizardOutputSlot'] ].forEach(function(pair) {
    var node = document.getElementById(pair[0]);
    var home = document.createComment('scanner-control-home: ' + pair[0]);
    node.before(home);
    wizardMounts.push({node:node, home:home, slot:document.getElementById(pair[1])});
  });
  document.getElementById('wizardNextBtn').addEventListener('click', function() { advanceWizard(false); });
  document.getElementById('wizardRunBtn').addEventListener('click', function() { advanceWizard(true); });
  document.getElementById('wizardBackBtn').addEventListener('click', function() { wizardStep = Math.max(0, wizardStep - 1); wizardError(''); renderWizard(true); });
  document.querySelectorAll('[data-wizard-step]').forEach(function(button) {
    button.addEventListener('click', function() { wizardStep = Number(button.dataset.wizardStep); wizardError(''); renderWizard(true); });
  });
  wizardReady = true;
  showAppSection(false);
"""
