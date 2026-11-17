"""Unified scan wizard. Scope, credentials, discovery, then the existing collectors."""

JS_WIZARD = r"""
  var wizardWindowProbe = null;
  var wizardWindowProbePending = false;
  var wizardWindowProbeGeneration = 0;
  var wizardMtatRanges = [
    {value:'Past 24 Hours', seconds:86400},
    {value:'Past 7 Days', seconds:604800},
    {value:'Past 30 Days', seconds:2592000},
    {value:'realtime', seconds:0}
  ];
  var wizardRenderedStep = -1;
  var wizardReady = false;
  var wizardStep = 0;
  var wizardReached = 0;
  var wizardBusy = false;
  var wizardHclSignature = '';
  var wizardMounts = [];
  var wizardVisited = false;
  var wizardLastStep = 5;
  var wizardHclStep = 3;
  var wizardRoPin = '';
  var wizardRoContext = '';
  var wizardRoReviewed = null;
  var wizardJumpKey = '';
  var wizardRoSaveChoice = '';
  var wizardBmcProbed = false;
  var wizardClusterReady = false;
  var wizardRoCertificateError = '';
  var wizardClusterError = '';
  var wizardClusterSelectionMessage = 'Choose one cluster from the Cluster dropdown below Discover clusters. MTAT assesses one cluster at a time.';
  var wizardDiscoveryGeneration = 0;
  var wizardEsxiListed = false;
  var wizardVaultPending = null;
  var wizardVaultResolve = null;
  var wizardVaultFocus = null;
  var wizardBmcSavedChoice = null;
  var wizardJumpProfiles = [];
  var wizardJumpSavedChoice = null;
  var wizardTlsBlocked = false;
  var wizardTlsLastDiagnostic = '';
  function wizEl(id) { return document.getElementById(id); }
  function wizOn(id) { var node = wizEl(id); return !!(node && node.checked); }
  function wizardScope() {
    var upstream = wizEl('wizMtatEngine').value === 'upstream';
    var live = !upstream || wizEl('wizMtatMode').value === 'live';
    return {
      vcfr: wizOn('discVcfr'),
      vinv: wizOn('discVinv'),
      mtat: wizOn('discMtat'),
      mtatVcenter: wizOn('discMtat') && live && wizEl('wizMtatSource').value === 'vcenter',
      mtatUpstream: wizOn('discMtat') && upstream,
      mtatLive: wizOn('discMtat') && live,
      vdt: wizOn('discVdt'),
      quick: wizOn('discQuick'),
      esxi: wizOn('discVcfr') && !!(wizEl('hwEsxi') && wizEl('hwEsxi').checked),
      vault: wizOn('useVaultSlide'),
      jump: wizOn('useJumpSlide')
    };
  }
  function wizardHclNeeded() { return wizardScope().vcfr; }
  function wizardNextIndex(step) {
    var next = Math.min(wizardLastStep, step + 1);
    if (next === wizardHclStep && !wizardHclNeeded()) next = wizardHclStep + 1;
    return next;
  }
  function wizardPrevIndex(step) {
    var prev = Math.max(0, step - 1);
    if (prev === wizardHclStep && !wizardHclNeeded()) prev = wizardHclStep - 1;
    return prev;
  }
  function wizardNote(text) {
    var note = wizEl('jumpVaultLiveNote');
    if (note) note.textContent = text || '';
  }
  function syncWizardConnectionTest() {
    var needsTarget = location.hash === '#scan-wizard' && !wizEl('rangeInput').value.trim();
    wizEl('testCredsBtn').disabled = needsTarget;
  }
  wizEl('rangeInput').addEventListener('input', syncWizardConnectionTest);
  wizEl('rangeInput').addEventListener('change', syncWizardConnectionTest);
  function applyWizardSavedDefaults() {
    if (!wizardReady) return;
    var enabled = wizOn('useVaultSlide') && !!_vaultState.unlocked;
    ['wizRo', 'wizAdmin', 'wizOps'].forEach(function(prefix) {
      pluginCredentials.preferSaved(prefix, enabled);
    });
    var available = enabled && Number(_vaultState.entry_count || 0) > 0;
    var scope = wizardScope();
    var inWizard = location.hash === '#scan-wizard';
    wizEl('wizardBmcSavedRow').hidden = !(scope.vcfr && !scope.esxi && available);
    if (wizardBmcSavedChoice === null) wizEl('wizardBmcUseSaved').checked = available;
    if (!available) wizEl('wizardBmcUseSaved').checked = false;
    var useBmc = available && wizOn('wizardBmcUseSaved');
    if (inWizard) {
      var checkbox = wizEl('useVaultChk');
      if (checkbox.checked !== useBmc) {
        if (useBmc) wizEl('passwordInput').value = '';
        checkbox.checked = useBmc;
        checkbox.dispatchEvent(new Event('change', {bubbles:true}));
      }
    }
    var hideManual = inWizard && useBmc;
    wizEl('sameCredsChk').parentElement.hidden = hideManual;
    wizEl('sharedCreds').hidden = hideManual;
    wizEl('perHostCreds').hidden = hideManual;
    var savedJump = enabled && wizardJumpProfiles.length > 0;
    wizEl('wizardJumpSavedRow').hidden = !savedJump;
    if (wizardJumpSavedChoice === null) wizEl('wizardJumpUseSaved').checked = savedJump;
    if (!savedJump) wizEl('wizardJumpUseSaved').checked = false;
    wizEl('wizardJumpSavedSlot').hidden = !wizOn('wizardJumpUseSaved');
    wizEl('wizardJumpManual').hidden = wizOn('wizardJumpUseSaved');
  }
  function finishWizardVault(ok) {
    var dialog = wizEl('wizardVaultDialog');
    wizEl('wizardVaultPassword').value = '';
    if (dialog.open) dialog.close();
    if (!ok) {
      wizEl('useVaultSlide').checked = false;
      wizEl('useJumpSlide').checked = false;
      wizardNote('Vault use cancelled. Enter credentials for this run.');
      syncScopeControls();
    }
    var resolve = wizardVaultResolve;
    wizardVaultResolve = null;
    if (resolve) resolve(ok);
    if (wizardVaultFocus) wizardVaultFocus.focus();
  }
  function ensureWizardVault() {
    if (wizardVaultPending) return wizardVaultPending;
    wizardVaultFocus = document.activeElement;
    wizardVaultPending = (async function() {
      var response = await getJson('/api/vault/status');
      if (response.status !== 200 || response.data.remote_disabled) throw new Error('Credential Vault is unavailable in this listener.');
      _vaultState = response.data;
      renderVaultState();
      if (_vaultState.unlocked) { applyWizardSavedDefaults(); return true; }
      if (!_vaultState.exists) {
        wizardNote('No vault exists yet. Create one in Credential Vault, then return to the wizard.');
        return false;
      }
      return new Promise(function(resolve) {
        wizardVaultResolve = resolve;
        wizEl('wizardVaultError').hidden = true;
        wizEl('wizardVaultDialog').showModal();
        wizEl('wizardVaultPassword').focus();
      });
    })().catch(function(error) {
      wizardNote(error.message || 'Could not check Credential Vault.');
      return false;
    }).finally(function() { wizardVaultPending = null; });
    return wizardVaultPending;
  }
  wizEl('wizardVaultForm').addEventListener('submit', async function(event) {
    event.preventDefault();
    var input = wizEl('wizardVaultPassword'), button = wizEl('wizardVaultUnlock');
    var passphrase = input.value;
    input.value = '';
    button.disabled = true;
    try {
      var response = await postJson('/api/vault/unlock', {passphrase: passphrase});
      passphrase = '';
      if (response.status !== 200) throw new Error(response.data.error || 'Could not unlock the vault.');
      _vaultState = response.data;
      renderVaultState();
      await refreshVaultStatus();
      applyWizardSavedDefaults();
      if (wizOn('useJumpSlide') && typeof refreshJumpHosts === 'function') refreshJumpHosts();
      finishWizardVault(true);
    } catch (error) {
      var message = wizEl('wizardVaultError');
      message.textContent = error.message || 'Could not unlock the vault.';
      message.hidden = false;
      input.focus();
    } finally { passphrase = ''; button.disabled = false; }
  });
  wizEl('wizardVaultCancel').addEventListener('click', function() { finishWizardVault(false); });
  wizEl('wizardVaultDialog').addEventListener('cancel', function(event) { event.preventDefault(); finishWizardVault(false); });
  wizEl('wizardBmcUseSaved').addEventListener('change', function() {
    wizardBmcSavedChoice = this.checked;
    applyWizardSavedDefaults();
  });
  wizEl('wizardJumpUseSaved').addEventListener('change', function() {
    wizardJumpSavedChoice = this.checked;
    applyWizardSavedDefaults();
  });
  document.addEventListener('jump-hosts-change', function(event) {
    wizardJumpProfiles = event.detail || [];
    setTimeout(function() {
      applyWizardSavedDefaults();
      if (wizOn('wizardJumpUseSaved') && wizardJumpProfiles.length === 1) wizEl('jumpHostSelect').value = wizardJumpProfiles[0].id;
      wizEl('wizardJumpStatus').textContent = wizardJumpProfiles.length ? 'Choose a saved jump host, or enter a new one.' : 'No saved jump hosts. Add one below.';
    }, 0);
  });
  document.addEventListener('vault-state-change', function() { setTimeout(applyWizardSavedDefaults, 0); });
  function syncScopeControls() {
    var scope = wizardScope();
    wizEl('wizardHwAccess').hidden = !scope.vcfr;
    wizEl('hwEsxiSshWarning').hidden = !scope.esxi;
    wizEl('credentialsCard').hidden = !(scope.vcfr && !scope.esxi);
    wizEl('wizardEsxiCreds').hidden = !scope.esxi;
    wizEl('wizardRoBlock').hidden = !(scope.vinv || scope.mtatVcenter || scope.esxi);
    wizEl('wizardRoTrustBlock').hidden = !(scope.vinv || scope.mtatVcenter || scope.esxi);
    wizEl('wizardAdminBlock').hidden = !(scope.vdt || scope.quick);
    wizEl('wizardApplianceBlock').hidden = !scope.vdt;
    wizEl('wizMtatRetentionHelp').hidden = !scope.mtatVcenter;
    wizEl('wizardMtatSourceBlock').hidden = !scope.mtat;
    wizEl('wizardMtatModeBlock').hidden = !scope.mtatUpstream;
    wizEl('wizardMtatUpstreamScope').hidden = !scope.mtatUpstream;
    wizEl('wizardMtatEmbeddedOptions').hidden = !scope.mtat || scope.mtatUpstream;
    wizEl('wizardMtatUpstreamOptions').hidden = !scope.mtatUpstream || !scope.mtatLive;
    wizEl('wizMtatSource').disabled = scope.mtatUpstream && !scope.mtatLive;
    wizEl('wizMtatUpstreamDiscover').hidden = !scope.mtatLive;
    wizEl('wizMtatClusters').hidden = !scope.mtatLive;
    wizEl('wizardOpsBlock').hidden = !scope.mtatLive || scope.mtatVcenter;
    wizEl('wizMtatRangeHint').textContent = scope.mtatVcenter ? 'Historical windows require retained Level 2 or higher statistics. The most detailed available history is selected automatically; real-time is the fallback.' : 'History is read from VCF Operations retention. A real-time snapshot uses its latest available sample. VM eligibility is not assessed.';
    wizEl('wizardEsxiDiscover').hidden = !scope.esxi;
    wizEl('wizardClusterBlock').hidden = !(scope.vinv || (scope.mtatVcenter && !scope.mtatUpstream));
    wizEl('wizardHclSkip').hidden = wizardHclNeeded();
    wizEl('wizardHclActive').hidden = !wizardHclNeeded();
    var hclButton = document.querySelector('[data-wizard-step="' + wizardHclStep + '"]');
    if (hclButton) hclButton.classList.toggle('step-complete', !wizardHclNeeded());
    applyWizardSavedDefaults();
    wizEl('credentialsTestActions').hidden = location.hash === '#scan-wizard' && !(scope.vcfr && !scope.esxi);
    wizEl('wizardBmcTestSlot').hidden = !(scope.vcfr && !scope.esxi);
    syncWizardConnectionTest();
    if (wizEl('execRemote') && wizEl('execLocal')) {
      wizEl('execRemote').checked = scope.jump;
      wizEl('execLocal').checked = !scope.jump;
      wizEl('execRemote').dispatchEvent(new Event('change', {bubbles:true}));
    }
    wizEl('wizardJumpSetup').hidden = !scope.jump;
  }
  function syncWizardLayout(section) {
    if (!wizardReady) return;
    if (section === 'scan-wizard') wizardVisited = true;
    var resume = wizEl('wizardResume');
    if (resume) resume.hidden = !wizardVisited || ['credential-vault', 'advanced-configuration'].indexOf(section) < 0;
    wizardMounts.forEach(function(item) {
      if (section === 'scan-wizard') item.slot.appendChild(item.node);
      else item.home.after(item.node);
    });
    var vaultRow = wizEl('useVaultRow');
    var execBlock = wizEl('execTargetBlock');
    wizEl('scanDepthGroup').hidden = section === 'scan-wizard';
    if (section === 'scan-wizard') wizEl('profFull').checked = true;
    if (vaultRow) vaultRow.hidden = section === 'scan-wizard';
    if (execBlock) execBlock.hidden = section === 'scan-wizard';
    if (section !== 'scan-wizard' && wizEl('credentialsCard')) wizEl('credentialsCard').hidden = false;
    if (section !== 'scan-wizard') {
      wizEl('credentialsTestActions').hidden = false;
      syncWizardConnectionTest();
      applyWizardSavedDefaults();
    }
    if (section === 'scan-wizard') renderWizard(false);
  }
  function wizardError(message) {
    var error = wizEl('wizardError');
    error.textContent = message || '';
    toggle(error, !!message);
    if (message) {
      if (wizardStep === 2 && wizardRoCertificateError && message === wizardRoCertificateError) {
        wizEl('wizRoReviewCert').focus();
        wizEl('wizRoCertAction').scrollIntoView({block:'center'});
      } else if (wizardStep === 2 && message === wizardClusterSelectionMessage) {
        wizEl('wizCluster').focus();
        wizEl('wizCluster').scrollIntoView({block:'center'});
      } else error.focus();
    }
    var current = document.querySelector('[data-wizard-step="' + wizardStep + '"]');
    if (current) current.classList.toggle('step-error', !!message);
  }
  function wizardHclWarning() {
    if (!wizardHclNeeded()) return '';
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
    if (!wizardReady || !wizEl('wizardHclStatus')) return;
    var meta = hclStatusMeta || {};
    var signature = JSON.stringify([meta.source_type, meta.bundle_filename, meta.file_exists, meta.age_days, meta.dataset_age_days, meta.json_models_count, meta.csv_models_count, meta.counts, meta.dataset_is_baseline, hclStatusError]);
    if (signature !== wizardHclSignature && wizEl('wizardHclAck')) wizEl('wizardHclAck').checked = false;
    wizardHclSignature = signature;
    var warning = wizardHclWarning();
    wizEl('wizardHclStatus').textContent = hclStatusPending ? 'Checking local HCL…' : warning || 'Local HCL is available and current. You can continue without importing a ZIP.';
    wizEl('wizardHclAckRow').hidden = !warning || hclStatusPending || !wizardHclNeeded();
    if (wizardStep === wizardHclStep) wizEl('wizardNextBtn').disabled = wizardHclNeeded() && (hclStatusPending || wizardBusy);
  }
  function wizardReview() {
    var scope = wizardScope();
    var selected = Array.from(document.querySelectorAll('.host-chk:checked')).map(function(c) { return c.dataset.ip; });
    var tools = [];
    if (scope.vcfr) tools.push(scope.esxi ? 'VCF-R via ESXi SSH' : 'VCF-R via BMC');
    if (scope.vinv) tools.push('vSphere Inventory');
    if (scope.mtat) tools.push(scope.mtatUpstream ? 'Upstream MTAT · ' + wizEl('wizMtatMode').selectedOptions[0].textContent : 'MTAT · ' + wizEl('wizMtatSource').selectedOptions[0].textContent + ' · ' + wizEl('wizMtatRange').selectedOptions[0].textContent);
    if (scope.vdt) tools.push('VDT');
    if (scope.quick) tools.push('vCenter quick check');
    var rows = [
      ['Collect', tools.join(', ') || 'Nothing selected'],
      ['Hardware depth', scope.vcfr ? 'Readiness full' : 'Not used'],
      ['MTAT scope', scope.mtat ? (scope.mtatUpstream ? (scope.mtatLive ? Array.from(wizEl('wizMtatClusters').selectedOptions).map(function (option) { return option.textContent; }).join(', ') : 'Selected saved dataset') : (scope.mtatVcenter ? 'Selected vCenter cluster' : (wizEl('wizOpsCluster').value.trim() || 'All accessible Operations clusters'))) : 'Not used'],
      ['Targets', scope.esxi ? (wizEl('wizEsxiListStatus').textContent || 'ESXi hosts') : (selected.length ? selected.join(', ') : (wizEl('rangeInput').value.trim() || 'Not entered'))],
      ['Cluster', wizEl('wizCluster') && !wizEl('wizardClusterBlock').hidden ? wizEl('wizCluster').selectedOptions[0].textContent : 'Not used'],
      ['Vault', scope.vault || scope.jump ? 'On' : 'Off'],
      ['Execution', scope.jump ? 'Jump host' : 'This workstation'],
      ['Scheduling', wizOn('wizOverlap') ? 'Host scan alongside Inventory, then MTAT' : 'Sequential'],
      ['HCL', wizardHclNeeded() ? (wizardHclWarning() || 'Current local compatibility database') : 'Not used'],
      ['Output folder', wizEl('outdirInput').value.trim()]
    ];
    var list = wizEl('wizardReview');
    list.replaceChildren();
    rows.forEach(function(row) {
      var term = document.createElement('dt'); term.textContent = row[0];
      var detail = document.createElement('dd'); detail.textContent = row[1];
      list.append(term, detail);
    });
  }
  function syncWizardRunAvailability() {
    var blocked = wizardBusy || !!_scanRunning || !!_hardwareStartPending;
    wizEl('wizardResetBtn').disabled = blocked;
    wizEl('wizardRunBtn').disabled = blocked || (wizardScope().vcfr && wizEl('runBtn').disabled);
  }
  setInterval(function() { if (location.hash === '#scan-wizard') syncWizardRunAvailability(); }, 1000);
  function renderWizard(focus) {
    var enteringOptions = wizardStep === 4 && wizardRenderedStep !== 4;
    wizardRenderedStep = wizardStep;
    if (enteringOptions && wizardScope().mtat) wizardWindowProbe = probeWizardMtatWindows();
    syncScopeControls();
    document.querySelectorAll('[data-wizard-panel]').forEach(function(panel) { panel.hidden = Number(panel.dataset.wizardPanel) !== wizardStep; panel.inert = wizardBusy; });
    document.querySelectorAll('[data-wizard-step]').forEach(function(button) {
      var index = Number(button.dataset.wizardStep);
      button.disabled = index > wizardReached || wizardBusy;
      if (index === wizardHclStep && !wizardHclNeeded()) button.classList.add('step-complete');
      else button.classList.toggle('step-complete', index < wizardStep);
      if (index === wizardStep) button.setAttribute('aria-current', 'step');
      else button.removeAttribute('aria-current');
    });
    wizEl('wizardStepStatus').textContent = 'Step ' + (wizardStep + 1) + ' of 6';
    wizEl('wizardBackBtn').disabled = wizardStep === 0 || wizardBusy;
    syncWizardRunAvailability();
    wizEl('wizardNextBtn').hidden = wizardStep === wizardLastStep;
    wizEl('wizardNextBtn').disabled = wizardBusy || (wizardStep === 4 && wizardScope().mtat && wizardWindowProbePending);
    wizEl('wizardRunBtn').hidden = wizardStep !== wizardLastStep;
    updateWizardHcl();
    if (wizardStep === wizardLastStep) wizardReview();
    if (focus) {
      var heading = document.querySelector('[data-wizard-panel="' + wizardStep + '"] h2');
      if (heading) { heading.focus({preventScroll: true}); heading.scrollIntoView({block: 'start'}); }
      if (wizEl('wizardError').textContent) wizardError(wizEl('wizardError').textContent);
    }
  }
  function wizardFieldError(id, message) { markFieldError(id, message); return message; }
  function renderWizardBmcTrustSummary(check) {
    var container = wizEl('wizardBmcTlsDiagnostic');
    container.replaceChildren();
    function paragraph(text) {
      var node = document.createElement('p'); node.textContent = text; container.appendChild(node);
    }
    if (!check.selectedCount) paragraph('Select the BMC hosts you want to scan.');
    else if (check.reason === 'ready') paragraph('Certificate checks passed. You can continue.');
    else paragraph('Some certificates need your review before you can continue.');
    var counts = document.createElement('dl'); counts.className = 'workflow-review';
    [['Selected hosts', check.selectedCount], ['Matching pinned certificates', check.pinnedCount],
     ['Certificates to review', check.missingCount], ['Changed certificates', check.mismatchCount]].forEach(function(row) {
      var label = document.createElement('dt'), value = document.createElement('dd');
      label.textContent = row[0]; value.textContent = String(row[1]); counts.append(label, value);
    });
    container.appendChild(counts);
    if (check.customCaConfigured) paragraph('A custom CA bundle is selected for certificate verification.');
    else if (check.pinnedCount) paragraph('The pinned certificates match the thumbprints you accepted.');
    [['Review and pin', check.missingTargets, check.missingCount],
     ['Certificate changed — review the new thumbprint', check.mismatchedTargets, check.mismatchCount]].forEach(function(group) {
      if (!group[2]) return;
      paragraph(group[0] + ': ' + group[1].join(', ') + (group[2] > group[1].length ? ' (showing the first ' + group[1].length + ' hosts)' : '') + '.');
    });
  }
  function wizardBmcTrustError() {
    function thumbprint(value) {
      return String(value || '').trim().toUpperCase().replace(/^SHA-?256:/, '').replace(/[:\-\s]/g, '');
    }
    var selected = Array.from(document.querySelectorAll('.host-chk:checked')).map(function(node) { return node.dataset.ip; });
    var ignoreTls = wizOn('ignoreTlsChk');
    var tlsMode = (document.querySelector('input[name="tlsMode"]:checked') || {}).value || 'system';
    var customCa = !ignoreTls && tlsMode === 'custom' && !!wizEl('caBundleInput').value.trim();
    var missing = [], mismatched = [], pinned = 0;
    selected.forEach(function(ip) {
      var host = _discoveredHosts.find(function(item) { return item.ip === ip; });
      var info = (host || {}).cert_info || {};
      var expected = thumbprint(info.sha256 || info.sha256_raw);
      var stored = thumbprint(_pinnedThumbprints[ip]);
      if (host && Number(host.port) === 80 && !expected) return;
      if (stored && expected && stored !== expected) mismatched.push(ip);
      else if (/^[A-F0-9]{64}$/.test(stored) && stored === expected) pinned += 1;
      else if (!customCa) missing.push(ip);
    });
    var reason = !selected.length ? 'no_selected_hosts' : (mismatched.length ? 'certificate_changed' : (missing.length ? 'pins_missing' : 'ready'));
    var diagnostic = {event: 'wizard_bmc_tls_check', reason: reason,
      selectedCount: selected.length, pinnedCount: pinned, customCaConfigured: customCa,
      ignoreCertificateErrors: ignoreTls, missingCount: missing.length, mismatchCount: mismatched.length,
      missingTargets: missing.slice(0, 20), mismatchedTargets: mismatched.slice(0, 20)};
    var text = JSON.stringify(diagnostic);
    renderWizardBmcTrustSummary(diagnostic);
    if (text !== wizardTlsLastDiagnostic) {
      wizardTlsLastDiagnostic = text;
      console.info('[VCF-R wizard TLS] ' + text);
      appendLog('[Wizard TLS] ' + text);
    }
    if (!selected.length) return 'Select at least one discovered BMC host before continuing.';
    if (mismatched.length) return 'The certificate changed for ' + mismatched.length + ' selected BMC(s): ' + mismatched.slice(0, 5).join(', ') + '. Review and pin the current certificates before continuing.';
    if (missing.length) return 'Review or pin certificates for ' + missing.length + ' selected BMC(s): ' + missing.slice(0, 5).join(', ') + '.';
    return '';
  }
  document.addEventListener('bmc-trust-change', function() {
    if (wizardStep !== 2 || !wizardScope().vcfr || wizardScope().esxi) return;
    var previouslyBlocked = wizardTlsBlocked;
    var error = wizardBmcTrustError();
    if (previouslyBlocked) { wizardTlsBlocked = !!error; wizardError(error); }
  });
  function validateWizardStep(step) {
    var scope = wizardScope();
    if (step === 0 && !(scope.vcfr || scope.vinv || scope.mtat || scope.vdt || scope.quick)) return 'Select at least one discovery or diagnostic tool to continue.';
    if (step === 1) {
      if ((scope.vault || scope.jump) && (!_vaultState.unlocked || wizEl('useVaultChk').disabled)) return 'Create or unlock the credential vault before using it.';
      if (scope.vcfr && !scope.esxi && !wizEl('useVaultChk').checked && wizEl('sameCredsChk').checked && !wizEl('passwordInput').value.trim()) return wizardFieldError('passwordInput', 'Enter the BMC password, or turn on the credential vault.');
      if (scope.esxi && (!wizEl('wizEsxiHost').value.trim() || !wizEl('wizEsxiKey').value.trim() || !wizEl('wizEsxiBmcUser').value.trim() || !wizEl('wizEsxiBmcPass').value)) return 'Enter one ESXi address, its reviewed public host key, and separate BMC credentials.';
      if (scope.esxi && !wizEl('wizEsxiUser').value.trim()) return wizardFieldError('wizEsxiUser', 'Enter the ESXi SSH username.');
      if (scope.esxi && !wizEl('wizEsxiPass').value.trim()) return wizardFieldError('wizEsxiPass', 'Enter the ESXi SSH password.');
      if ((scope.vinv || scope.mtatVcenter || scope.esxi) && !wizEl('wizRoEndpoint').value.trim()) return wizardFieldError('wizRoEndpoint', 'Enter a vCenter hostname or HTTPS URL without embedded credentials (for example, vc-01.rainpole.net).');
      if ((scope.vinv || scope.mtatVcenter || scope.esxi) && !wizOn('wizRoUseSaved') && !wizEl('wizRoPass').value.trim()) return wizardFieldError('wizRoPass', 'Enter the password, or select a saved read-only instance.');
      if (scope.mtatLive && !scope.mtatVcenter && !wizEl('wizOpsEndpoint').value.trim()) return wizardFieldError('wizOpsEndpoint', 'Enter the VCF Operations HTTPS endpoint.');
      if (scope.mtatLive && !scope.mtatVcenter && !wizOn('wizOpsUseSaved') && !wizEl('wizOpsPass').value) return wizardFieldError('wizOpsPass', 'Enter the Operations password or use saved credentials.');
      if ((scope.vdt || scope.quick) && !wizEl('wizAdminEndpoint').value.trim()) return wizardFieldError('wizAdminEndpoint', 'Enter a vCenter hostname or HTTPS URL without embedded credentials (for example, vc-01.rainpole.net).');
      if ((scope.vdt || scope.quick) && !wizOn('wizAdminUseSaved') && !wizEl('wizAdminPass').value.trim()) return wizardFieldError('wizAdminPass', 'Enter the administrator password, or select a saved Administrator instance.');
      if (scope.vdt && !wizEl('wizAppHost').value.trim()) return wizardFieldError('wizAppHost', 'Enter the VDT appliance hostname.');
      if (scope.vdt && !wizEl('wizAppPass').value.trim()) return wizardFieldError('wizAppPass', 'Enter the appliance SSH password. It is separate from vCenter SSO.');
      if (scope.jump && !wizOn('wizardJumpUseSaved')) return 'Save a jump host with its reviewed SSH key, or choose a saved jump host before continuing.';
    }
    if (step === 2) {
      if (scope.vcfr && !scope.esxi && !document.querySelector('.host-chk')) return 'Probe hosts before continuing. Enter a BMC range, then select Probe Hosts.';
      if (scope.vcfr && !scope.esxi) {
        var trustError = wizardBmcTrustError();
        wizardTlsBlocked = !!trustError;
        if (trustError) return trustError;
      }
      if (scope.esxi && !wizEl('wizEsxiHost').value.trim()) return 'List ESXi hosts from vCenter, or enter ESXi addresses in the target field.';
      if ((scope.vinv || (scope.mtatVcenter && !scope.mtatUpstream)) && !wizardClusterReady) return wizardRoCertificateError || wizardClusterError || 'Select Discover clusters on this step. That check also verifies the read-only vCenter account.';
      if (scope.mtatVcenter && !scope.mtatUpstream && !wizEl('wizCluster').value) return wizardFieldError('wizCluster', wizardClusterSelectionMessage);
      if (scope.mtatUpstream) { var upstreamError = mtatUpstream.validate(); if (upstreamError) return upstreamError; }
    }
    if (step === wizardHclStep && wizardHclNeeded()) {
      if (hclStatusPending) return 'Wait for the HCL check to finish.';
      if (wizardHclWarning() && !wizEl('wizardHclAck').checked) return 'Download or import HCL data, or explicitly acknowledge the limited evidence to continue.';
    }
    if (step === 4) {
      if (scope.mtat && wizardWindowProbePending) return 'Wait for the MTAT collection-window check to finish.';
      if (scope.mtat && !scope.mtatUpstream && !wizEl('wizMtatRange').value) return 'No MTAT collection window is available. Check the connection and permissions, then return to this step to retry.';
      if (scope.mtatUpstream) { var upstreamOptionsError = mtatUpstream.validate(); if (upstreamOptionsError) return upstreamOptionsError; }
      if (!wizEl('outdirInput').value.trim()) return wizardFieldError('outdirInput', 'Choose a folder for assessment reports.');
      var threads = Number(wizEl('threadsInput').value);
      if (scope.vcfr && !scope.esxi && (!Number.isInteger(threads) || threads < 1 || threads > 32)) return wizardFieldError('threadsInput', 'Concurrent hosts must be a whole number from 1 through 32.');
    }
    return '';
  }
  function wizardCertificateAttention(message) {
    wizardRoCertificateError = message || '';
    var alert = wizEl('wizRoCertAction'), button = wizEl('wizRoReviewCert');
    alert.textContent = wizardRoCertificateError;
    alert.hidden = !wizardRoCertificateError;
    button.classList.toggle('btn-primary', !!wizardRoCertificateError);
    button.classList.toggle('btn-outline', !wizardRoCertificateError);
  }
  function wizardRoIdentity() {
    var record = pluginCredentials.selected('wizRo');
    var endpoint = wizEl('wizRoEndpoint').value.trim();
    var url = new URL(endpoint.indexOf('://') < 0 ? 'https://' + endpoint : endpoint);
    if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.search || url.hash) throw new Error('Enter a vCenter HTTPS hostname or URL without embedded credentials.');
    return {endpoint:url.origin, id:record ? record.id : '', pin:record ? (record.certificate_pin || '') : ''};
  }
  function syncWizardRoTrust() {
    var identity;
    try { identity = wizardRoIdentity(); } catch (error) { identity = {endpoint:'', id:'', pin:''}; }
    var context = identity.endpoint + '/' + identity.id;
    if (context !== wizardRoContext) {
      wizardRoContext = context;
      wizardCertificateAttention('');
      wizardClusterError = '';
      wizardDiscoveryGeneration += 1;
      wizardRoPin = '';
      wizardRoReviewed = null;
      wizardClusterReady = false;
      wizardRoSaveChoice = '';
      wizEl('wizRoSaveBar').hidden = true;
      wizEl('wizRoCertReview').hidden = true;
      wizEl('wizRoCertStatus').textContent = identity.pin ? 'Using the trusted SHA-256 fingerprint saved in the encrypted vault.' : 'Using the system trust store. Review and trust a private certificate if discovery fails.';
    }
    return identity;
  }
  ['wizRoEndpoint','wizRoUser','wizRoPass','wizRoUseSaved','wizRoSavedInstance','wizVerifyTls'].forEach(function(id) {
    wizEl(id).addEventListener('input', function() { wizardClusterReady = false; wizardDiscoveryGeneration += 1; syncWizardRoTrust(); });
    wizEl(id).addEventListener('change', function() { wizardClusterReady = false; wizardDiscoveryGeneration += 1; syncWizardRoTrust(); });
  });
  document.addEventListener('plugin-credentials-change', function(event) { if (event.detail === 'wizRo') syncWizardRoTrust(); });
  function wizardCredentialBody(role) {
    if (role !== 'administrator') syncWizardRoTrust();
    var prefix = role === 'administrator' ? 'wizAdmin' : 'wizRo';
    var body = {
      endpoint: wizEl(prefix + 'Endpoint').value.trim(),
      username: wizEl(prefix + 'User').value.trim(),
      password: wizEl(prefix + 'Pass').value,
      verify_tls: wizEl('wizVerifyTls') ? wizEl('wizVerifyTls').checked : true,
      certificate_pin: role === 'administrator' ? '' : wizardRoPin,
      acknowledged: true,
      cluster: ''
    };
    if (typeof pluginCredentials !== 'undefined' && pluginCredentials.active(prefix)) return pluginCredentials.payload(prefix, body);
    return body;
  }
  var wizardPhases = Object.create(null);
  function wizardActivity(message) {
    var list = wizEl('wizardActivityLog');
    var item = document.createElement('li');
    item.textContent = new Date().toLocaleTimeString() + ' · ' + message;
    list.appendChild(item);
    if (typeof appendLog === 'function') appendLog('[Wizard] ' + message);
    while (list.children.length > 200) list.firstChild.remove();
  }
  function updateWizardPhase(key, state, detail, completed, total) {
    var phase = wizardPhases[key];
    if (!phase) return;
    var changed = phase.state !== state || phase.detail !== detail;
    phase.state = state; phase.detail = detail;
    if (state === 'running' && !phase.started) phase.started = Date.now();
    if (state !== 'running' && phase.started && !phase.ended) phase.ended = Date.now();
    phase.item.dataset.state = state;
    phase.item.setAttribute('aria-busy', String(state === 'running'));
    phase.status.textContent = state + (detail ? ' · ' + detail : '');
    phase.bar.hidden = state !== 'running' && state !== 'done';
    if (state === 'done') { phase.bar.max = 1; phase.bar.value = 1; }
    else if (state === 'running' && Number.isFinite(total) && total > 0 && Number.isFinite(completed)) {
      phase.bar.max = total; phase.bar.value = Math.max(0, Math.min(total, completed));
      phase.status.textContent += ' (' + completed + '/' + total + ' in this stage)';
    } else phase.bar.removeAttribute('value');
    if (changed) wizardActivity(phase.label + ': ' + state + (detail ? ' · ' + detail : ''));
  }
  function tickWizardPhases() {
    Object.keys(wizardPhases).forEach(function(key) {
      var phase = wizardPhases[key];
      if (phase.started) phase.elapsed.textContent = Math.floor(((phase.ended || Date.now()) - phase.started) / 1000) + 's elapsed';
    });
  }
  function queueStages() {
    var scope = wizardScope();
    var stages = [];
    if (scope.quick) stages.push(['quick', 'vCenter quick check']);
    if (scope.vcfr) stages.push(['vcfr', scope.esxi ? 'VCF-R via ESXi SSH' : 'VCF-R hardware scan']);
    if (scope.vinv) stages.push(['vinv', 'vSphere Inventory']);
    if (scope.mtat) stages.push(['mtat', 'MTAT assessment']);
    if (scope.vdt) stages.push(['vdt', 'VDT collection']);
    if (scope.vinv || scope.mtat) stages.push(['xlsx', 'Save combined reports']);
    var list = wizEl('wizardTimeline');
    list.replaceChildren();
    wizEl('wizardActivityLog').replaceChildren();
    wizardPhases = Object.create(null);
    stages.forEach(function(stage) {
      var item = document.createElement('li');
      item.dataset.stage = stage[0];
      var title = document.createElement('strong'); title.textContent = stage[1];
      var status = document.createElement('small');
      var bar = document.createElement('progress'); bar.setAttribute('aria-label', stage[1] + ' stage progress');
      var elapsed = document.createElement('small');
      item.append(title, status, bar, elapsed);
      list.appendChild(item);
      wizardPhases[stage[0]] = {item:item, label:stage[1], status:status, bar:bar, elapsed:elapsed};
      updateWizardPhase(stage[0], 'waiting', 'Queued');
    });
    return stages;
  }
  function postJsonOk(url, body) {
    return post(url, body).then(function(data) {
      if (data && data.error) throw new Error(data.error + (data.reference ? ' Reference: ' + data.reference : ''));
      return data;
    });
  }
  function wizardMtatBody(rangeName) {
    if (wizardScope().mtatUpstream && !wizardScope().mtatLive) return {acknowledged:true, policy:wizEl('wizMtatPolicy').value};
    var source = wizEl('wizMtatSource').value;
    var body;
    if (source === 'operations-rest') {
      body = {source_kind:source, endpoint:wizEl('wizOpsEndpoint').value.trim(), username:wizEl('wizOpsUser').value.trim(),
        password:wizEl('wizOpsPass').value, auth_source:wizEl('wizOpsAuthSource').value.trim(),
        cluster:wizEl('wizOpsCluster').value.trim(), verify_tls:wizOn('wizOpsVerifyTls'), acknowledged:true};
      if (typeof pluginCredentials !== 'undefined' && pluginCredentials.active('wizOps')) body = pluginCredentials.payload('wizOps', body);
    } else {
      body = wizardCredentialBody('readonly');
      body.source_kind = 'vcenter';
      body.cluster = wizEl('wizCluster').value;
    }
    if (wizardScope().mtatUpstream) { body.policy = wizEl('wizMtatPolicy').value; body.ca_file = wizEl('wizMtatCaFile').value.trim(); return body; }
    body.range_name = rangeName || wizEl('wizMtatRange').value;
    if (body.range_name !== 'realtime') {
      var end = Math.floor(Date.now() / 1000) * (source === 'vcenter' ? 1 : 1000);
      var range = wizardMtatRanges.find(function(item) { return item.value === body.range_name; });
      if (!range) throw new Error('Select an available MTAT collection window.');
      body.window = {begin: end - range.seconds * (source === 'vcenter' ? 1 : 1000), end: end, interval: 'auto'};
    }
    return body;
  }
  async function probeWizardMtatWindows() {
    if (wizardScope().mtatUpstream) {
      wizardWindowProbePending = false;
      if (wizardScope().mtatLive) await mtatUpstream.ranges();
      return;
    }
    var generation = ++wizardWindowProbeGeneration;
    var list = wizEl('wizMtatAvailability'), select = wizEl('wizMtatRange');
    var source = wizEl('wizMtatSource').value;
    var available = [], historyUnavailable = true;
    wizardWindowProbePending = true;
    wizEl('wizMtatRealtimeWarning').hidden = true;
    wizEl('wizMtatStatus').textContent = 'Discovering available MTAT collection windows…';
    list.replaceChildren();
    select.disabled = true;
    Array.from(select.options).forEach(function(option) {
      option.disabled = true;
      option.textContent = option.value === 'realtime' ? 'Real-time snapshot — checking…' : option.value + ' — checking…';
    });
    try {
      // Use one connection/scope snapshot throughout this check.
      var bodies = wizardMtatRanges.map(function(range) { return wizardMtatBody(range.value); });
      for (var index = 0; index < wizardMtatRanges.length; index++) {
        if (generation !== wizardWindowProbeGeneration) return;
        var range = wizardMtatRanges[index], body = bodies[index];
        var option = Array.from(select.options).find(function(item) { return item.value === range.value; });
        var row = document.createElement('li');
        var label = range.value === 'realtime' ? 'Real-time snapshot' : range.value;
        row.textContent = label + ': checking…'; list.appendChild(row);
        try {
          var result = await postJsonOk('/api/plugins/mtat/preflight', body);
          if (generation !== wizardWindowProbeGeneration) return;
          var reasons = (result.messages || []).filter(function(message) { return !/^TLS /i.test(message); });
          option.disabled = !result.ready;
          if (result.ready) {
            available.push(range.value);
            option.textContent = label;
          } else {
            var configurationNeeded = source === 'vcenter' && range.seconds && reasons.some(function(message) { return /^Requested history is unavailable:/i.test(message); });
            option.textContent = label + (configurationNeeded ? ' — Configure vCenter required' : ' — Unavailable');
            if (range.seconds && !configurationNeeded) historyUnavailable = false;
          }
          row.textContent = label + (result.ready ? ': available' : ': unavailable. ' + reasons.join(' '));
        } catch (error) {
          if (generation !== wizardWindowProbeGeneration) return;
          option.textContent = label + ' — Could not verify';
          row.textContent = label + ': could not check. ' + error.message;
          if (range.seconds) historyUnavailable = false;
        }
      }
      select.value = available[0] || '';
      if (available.length === 1 && available[0] === 'realtime') {
        wizEl('wizMtatRealtimeWarningText').textContent = source === 'vcenter' && historyUnavailable ?
          'Only Real-time snapshot is available. It reflects current usage only. Historical MTAT requires retained Level 2 or higher vCenter statistics. Configure vCenter to enable the historical windows below.' :
          'Only Real-time snapshot could be verified. It reflects current usage only. Historical data is unavailable or could not be checked; review the details below and your source connection, permissions and retention.';
        wizEl('wizMtatRealtimeWarning').hidden = false;
      }
      wizEl('wizMtatStatus').textContent = available.length ? 'Selected automatically: ' + select.selectedOptions[0].textContent + '.' : 'No MTAT collection window could be verified. Check the details below and your connection, then return to this step to retry.';
    } catch (error) {
      if (generation !== wizardWindowProbeGeneration) return;
      select.value = '';
      wizEl('wizMtatStatus').textContent = error.message || 'Could not check MTAT collection windows.';
    } finally {
      if (generation === wizardWindowProbeGeneration) {
        wizardWindowProbePending = false;
        select.disabled = !available.length;
        wizEl('wizardNextBtn').disabled = wizardBusy;
      }
    }
  }
  async function checkWizardMtat(body) {
    if (wizardScope().mtatUpstream) {
      await mtatUpstream.describe();
      var upstreamError = mtatUpstream.validate(); if (upstreamError) throw new Error(upstreamError);
      return {ready:true};
    }
    wizEl('wizMtatStatus').textContent = 'Checking the selected MTAT source, cluster and history…';
    try {
      var result = await postJsonOk('/api/plugins/mtat/preflight', body);
      if (!result.ready) {
        var reasons = (result.messages || []).filter(function(message) { return !/^TLS /i.test(message); });
        var reason = reasons.join(' ') || 'The selected source or collection window is unavailable.';
        if (body.source_kind === 'vcenter' && body.range_name !== 'realtime') reason += ' Historical MTAT requires retained Level 2 or higher statistics. Choose Real-time snapshot, or select VCF Operations as the source in Credentials.';
        throw new Error('MTAT: ' + reason);
      }
      wizEl('wizMtatStatus').textContent = 'MTAT source and collection window are ready.';
      return result;
    } catch (error) { wizEl('wizMtatStatus').textContent = error.message; throw error; }
  }
  async function runWizardQueue() {
    var scope = wizardScope();
    var stages = queueStages();
    wizEl('wizardResetStatus').textContent = '';
    var artifactJobs = {output_dir:wizEl('outdirInput').value.trim()};
    var mtatRequest = scope.mtat ? wizardMtatBody() : null;
    wizardActivity('Pre-checks started');
    setOperationProgress('wizardRunStatus', {busy:true, label:'Checking collection readiness'});
    try {
      if (scope.vinv) {
        wizEl('wizardRunStatus').textContent = 'Checking vSphere Inventory connection and cluster…';
        var inventoryCheck = wizardCredentialBody('readonly');
        inventoryCheck.cluster = wizEl('wizCluster').value;
        var inventoryReady = await postJsonOk('/api/plugins/vinv/preflight', inventoryCheck);
        if (!inventoryReady.ready) throw new Error('vSphere Inventory: ' + (inventoryReady.messages || ['Connection or cluster check failed.']).join(' '));
        wizardActivity('vSphere Inventory pre-check passed');
      }
      if (scope.mtat) {
        wizEl('wizardRunStatus').textContent = 'Checking MTAT cluster and history availability…';
        await checkWizardMtat(mtatRequest);
        wizardActivity('MTAT pre-check passed');
      }
    } catch (error) {
      wizardActivity('Pre-check failed: ' + error.message);
      wizEl('wizardRunStatus').textContent = 'Pre-check failed. No collection phases started.';
      Object.keys(wizardPhases).forEach(function(key) { updateWizardPhase(key, 'skipped', 'Pre-check failed'); });
      throw error;
    } finally { setOperationProgress('wizardRunStatus', {busy:false}); }
    wizEl('wizardRunStatus').textContent = 'Starting the selected assessments.';
    wizardActivity('Pre-checks passed');
    var clock = setInterval(tickWizardPhases, 1000);
    async function executeStage(entry) {
      var stage = entry[0];
      updateWizardPhase(stage, 'running', 'Starting');
      try {
      if (stage === 'quick') {
        await postJsonOk('/api/plugins/vcenter-check', wizardCredentialBody('administrator'));
      } else if (stage === 'vcfr' && !scope.esxi) {
        wizEl('profFull').checked = true;
        updateWizardPhase('vcfr', 'running', 'Waiting for scan start; complete any credential or certificate prompt');
        var accepted = await startHardwareAssessment();
        var hardware = await waitForScan(accepted.scan_id);
        artifactJobs.scan_id = hardware.scan_id;
      } else if (stage === 'vcfr' && scope.esxi) {
        var host = wizEl('wizEsxiHost').value.trim();
        var esxiStarted = await postJsonOk('/api/plugins/esxi-usb/jobs', {
          host: host,
          profile: 'readiness-full',
          acknowledged: true,
          username: wizEl('wizEsxiUser').value.trim(),
          password: wizEl('wizEsxiPass').value,
          host_key_pin: wizEl('wizEsxiKey').value.trim(),
          bmc_user: wizEl('wizEsxiBmcUser').value.trim(),
          bmc_password: wizEl('wizEsxiBmcPass').value,
          certificate_pin: wizEl('wizEsxiBmcPin').value.trim(),
          verify_ssl: wizEl('wizEsxiVerifyTls').checked,
          output_dir: wizEl('outdirInput').value.trim()
        });
        await waitForScan(esxiStarted.scan_id);
        artifactJobs.scan_id = esxiStarted.scan_id;
      } else if (stage === 'vinv') {
        var vinvBody = wizardCredentialBody('readonly');
        vinvBody.cluster = wizEl('wizCluster').value;
        vinvBody.include_network_hints = true;
        vinvBody.include_file_info = false;
        var started = await postJsonOk('/api/plugins/vinv/jobs', vinvBody);
        await pollJob('/api/plugins/vinv/jobs/' + started.id, 'vSphere Inventory', 'vinv');
        artifactJobs.vinv_job_id = started.id;
      } else if (stage === 'mtat') {
        if (scope.mtatUpstream) {
          var upstreamJob = await mtatUpstream.run(function (state) {
            var tasks = state.tasks || [], completed = tasks.filter(function (task) { return task.status === 'completed'; }).length;
            updateWizardPhase('mtat', 'running', state.message || state.status, completed, tasks.length);
          });
          if (upstreamJob.id) artifactJobs.upstream_job_id = upstreamJob.id;
          if (upstreamJob.dataset) artifactJobs.upstream_dataset_id = upstreamJob.dataset;
          if (upstreamJob.dataset) artifactJobs.upstream_dataset = upstreamJob.dataset;
          if (upstreamJob.status !== 'completed') throw new Error('Upstream MTAT ' + upstreamJob.status + '; completed tasks are retained for export and recovery.');
        } else {
        var mtatBody = mtatRequest;
        var mtatJob = await postJsonOk('/api/plugins/mtat/jobs', mtatBody);
        await pollJob('/api/plugins/mtat/jobs/' + mtatJob.id, 'MTAT', 'mtat');
        artifactJobs.mtat_job_id = mtatJob.id;
        }
      } else if (stage === 'vdt') {
        wizEl('wizardRunStatus').textContent = 'Open Plugins, VDT, to finish appliance collection with the administrator account you entered. The wizard does not start VDT until the package check on that page passes.';
      } else if (stage === 'xlsx') {
        var saved = await postJsonOk('/api/wizard/artifacts', artifactJobs);
        wizardActivity('Reports saved in ' + saved.outdir);
        if (saved.inventory_matched_hosts !== null && saved.inventory_matched_hosts !== undefined) {
          wizardActivity('Inventory reconciliation: ' + saved.inventory_matched_hosts + '/' + saved.bmc_hosts + ' scanned BMC hosts matched.' + (saved.inventory_matched_hosts < saved.bmc_hosts ? ' Review unmatched hosts and the selected vCenter cluster in the fleet report.' : ''));
        }
      }
      updateWizardPhase(stage, stage === 'vdt' ? 'skipped' : 'done', stage === 'vdt' ? 'Continue from Plugins → VDT' : 'Finished');
      } catch (error) {
        updateWizardPhase(stage, 'failed', error.message || 'Collection failed');
        throw error;
      }
    }
    async function series(entries) {
      for (var i = 0; i < entries.length; i++) await executeStage(entries[i]);
    }
    try {
      if (wizOn('wizOverlap') && scope.vcfr && (scope.vinv || scope.mtat)) {
        wizardActivity('Overlap enabled: host scan plus one vCenter collection at a time');
        await series(stages.filter(function(entry) { return entry[0] === 'quick'; }));
        // Settle both lanes before allowing another run or exporting shared results.
        var outcomes = await Promise.allSettled([
          series(stages.filter(function(entry) { return entry[0] === 'vcfr'; })),
          series(stages.filter(function(entry) { return entry[0] === 'vinv' || entry[0] === 'mtat'; }))
        ]);
        var failure = outcomes.find(function(result) { return result.status === 'rejected'; });
        if (failure) throw failure.reason;
        await series(stages.filter(function(entry) { return entry[0] === 'vdt' || entry[0] === 'xlsx'; }));
      } else await series(stages);
      wizEl('wizardRunStatus').textContent = 'Selected assessments finished. Open MTAT, Inventory, or VDT from Plugins for the detailed views.';
    } catch (error) {
      if (artifactJobs.vinv_job_id || artifactJobs.mtat_job_id || artifactJobs.upstream_job_id || artifactJobs.upstream_dataset_id) {
        updateWizardPhase('xlsx', 'running', 'Saving completed results after a phase failure');
        try {
          var partial = await postJsonOk('/api/wizard/artifacts', artifactJobs);
          wizardActivity('Completed results saved in ' + partial.outdir);
          updateWizardPhase('xlsx', 'done', 'Completed results saved; review the failed phase');
        } catch (saveError) {
          updateWizardPhase('xlsx', 'failed', saveError.message);
        }
      }
      Object.keys(wizardPhases).forEach(function(key) {
        if (wizardPhases[key].state === 'waiting') updateWizardPhase(key, 'skipped', 'An earlier phase failed');
      });
      wizEl('wizardRunStatus').textContent = 'Wizard stopped. Check Scanner and Plugins for any collections still running before retrying or resetting.';
      throw error;
    } finally { clearInterval(clock); tickWizardPhases(); }
  }
  function waitForScan(scanId) {
    return new Promise(function(resolve, reject) {
      var ticks = 0;
      function check() {
        ticks += 1;
        fetch('/api/scan/status', {credentials: 'same-origin'}).then(function(response) {
          if (!response.ok) throw new Error('Cannot read scan status.');
          return response.json();
        }).then(function(data) {
          if (!scanId || data.scan_id !== scanId) throw new Error('The hardware scan was replaced. Check Scanner for the active run, then reset the wizard before starting new targets.');
          if (data.error) throw new Error(data.error + (data.reference ? ' Reference: ' + data.reference : ''));
          updateWizardPhase('vcfr', 'running', data.finalizing ? 'Finishing hardware reports' : 'Scanning hardware', data.completed, data.total);
          if (data.done && !data.running && !data.finalizing) { resolve(data); return; }
          if (ticks > 1200) throw new Error('Scan status deadline exceeded.');
          setTimeout(check, 500);
        }).catch(reject);
      }
      setTimeout(check, 500);
    });
  }
  async function pollJob(url, label, key) {
    while (true) {
      var response = await fetch(url, {credentials: 'same-origin'});
      if (!response.ok) throw new Error(label + ': cannot read job status (HTTP ' + response.status + '). The server job may still be running; check Plugins before retrying.');
      var data = await response.json();
      var detail = data.message || data.stage || 'Working';
      var stageLabels = {performance:'Querying performance samples', inventory:'Reading inventory', hosts:'Building host assessment', assessment:'Building assessment'};
      detail = stageLabels[detail] || detail;
      if (data.stage === 'done') return data;
      if (data.stage === 'failed' || data.stage === 'cancelled') throw new Error(label + ': ' + detail + (data.reference ? ' Reference: ' + data.reference : ''));
      updateWizardPhase(key, 'running', detail, data.completed, data.total);
      await new Promise(function(resolve) { setTimeout(resolve, 1000); });
    }
  }
  async function advanceWizard(run) {
    if (wizardBusy) return;
    wizardBusy = true;
    renderWizard(false);
    try {
      var scope = wizardScope();
      if (wizardStep === 0 && (scope.vault || scope.jump) && !await ensureWizardVault()) return;
      if ((wizardStep === 1 || run) && (scope.vault || scope.jump)) {
        var vault = await getJson('/api/vault/status');
        if (vault.status !== 200 || !vault.data.unlocked) {
          wizardStep = 1;
          wizardBusy = false;
          renderWizard(true);
          wizardError('The credential vault is locked or unavailable. Unlock it, or turn the vault off.');
          return;
        }
        _vaultState = vault.data;
        if (typeof renderVaultState === 'function') renderVaultState();
      }
      if (run) await refreshHclStatus();
      var first = run ? 0 : wizardStep;
      var last = run ? 4 : wizardStep;
      for (var step = first; step <= last; step++) {
        if (step === wizardHclStep && !wizardHclNeeded()) continue;
        var error = validateWizardStep(step);
        if (error) { wizardStep = step; wizardBusy = false; renderWizard(true); wizardError(error); return; }
      }
      wizardError('');
      if (run) {
        await runWizardQueue();
      } else {
        if (wizardStep === 4 && scope.mtat) {
          if (wizardWindowProbe) await wizardWindowProbe;
          await checkWizardMtat(wizardMtatBody());
        }
        wizardStep = wizardNextIndex(wizardStep);
        wizardReached = Math.max(wizardReached, wizardStep);
        if (wizardStep === wizardHclStep) refreshHclStatus();
        if (wizardStep === 2 && (scope.vinv || scope.mtatVcenter) && !wizardClusterReady) discoverWizardClusters();
      }
    } catch (error) {
      wizardError(error && error.message ? error.message : 'Could not verify scan settings. Retry this step.');
    } finally {
      wizardBusy = false;
      renderWizard(!run);
    }
  }
  function clearWizardRunDisplay(message) {
    wizardPhases = Object.create(null);
    wizEl('wizardTimeline').replaceChildren();
    wizEl('wizardActivityLog').replaceChildren();
    wizEl('wizardRunStatus').textContent = message || '';
  }
  async function resetWizard() {
    if (wizardBusy || _scanRunning || _hardwareStartPending) { wizardError('Wait for collection to finish, or cancel it in Scanner, before resetting.'); return; }
    wizEl('wizardResetBtn').disabled = true;
    try {
      var response = await fetch('/api/scan/status', {credentials:'same-origin'});
      if (!response.ok) throw new Error('Cannot verify whether hardware collection has stopped. Check Scanner before resetting.');
      var status = await response.json();
      if (status.running || status.finalizing || wizardBusy || _scanRunning || _hardwareStartPending) throw new Error('Hardware collection or report saving is still active. Wait for it to finish, or cancel it in Scanner, before resetting.');
      wizardDiscoveryGeneration++; wizardWindowProbeGeneration++;
      wizardWindowProbe = null; wizardWindowProbePending = false;
      wizardClusterReady = false; wizardBmcProbed = false; wizardEsxiListed = false;
      wizardRoPin = ''; wizardRoContext = ''; wizardRoReviewed = null; wizardJumpKey = '';
      wizEl('wizJumpSave').disabled = true;
      wizEl('wizJumpPinStatus').textContent = '';
      wizEl('wizRoCertReview').hidden = true; wizEl('wizRoSaveBar').hidden = true;
      wizardRoCertificateError = ''; wizardClusterError = '';
      wizardRoSaveChoice = ''; wizardBmcSavedChoice = null; wizardJumpSavedChoice = null;
      wizardTlsBlocked = false; wizardTlsLastDiagnostic = ''; wizardHclSignature = '';
      var fields = new Set(document.querySelectorAll('#scan-wizard input, #scan-wizard select, #scan-wizard textarea'));
      wizardMounts.forEach(function(mount) { mount.node.querySelectorAll('input,select,textarea').forEach(function(field) { fields.add(field); }); });
      fields.forEach(function(field) {
        if (field.type === 'checkbox' || field.type === 'radio') field.checked = field.defaultChecked;
        else if (field.tagName === 'SELECT') {
          Array.from(field.options).forEach(function(option) { option.selected = option.defaultSelected; });
          if (!field.multiple && field.selectedIndex < 0) field.selectedIndex = 0;
        } else field.value = field.type === 'password' || field.type === 'file' ? '' : field.defaultValue;
      });
      ['rangeInput','wizRoEndpoint','wizAdminEndpoint','wizOpsEndpoint','wizEsxiHost'].forEach(function(id) { if (wizEl(id)) wizEl(id).value = ''; });
      ['hostList','perHostRows','wizCluster','wizEsxiHostList','wizMtatClusters','wizMtatRanges','wizMtatAvailability'].forEach(function(id) { if (wizEl(id)) wizEl(id).replaceChildren(); });
      ['discStatus','wizRoCertStatus','wizClusterStatus','wizEsxiListStatus','wizMtatStatus'].forEach(function(id) { if (wizEl(id)) wizEl(id).textContent = ''; });
      _discoveryRequestGeneration++;
      _discoveredHosts = []; _probedTargetRaw = ''; _pinnedThumbprints = {};
      wizardCertificateAttention('');
      wizEl('outdirInput').removeAttribute('data-customized');
      ['discSpinner','hostList','certTrustBanner','vpnWarning','progressSection','postScanActions','resultsSection'].forEach(function(id) { if (wizEl(id)) hide(wizEl(id)); });
      if (typeof resetCertTrustBanner === 'function') resetCertTrustBanner(0);
      if (typeof mtatUpstream !== 'undefined') mtatUpstream.reset();
      wizardStep = 0; wizardReached = 0; wizardRenderedStep = -1;
      clearWizardRunDisplay(); wizardError(''); wizardNote('');
      fields.forEach(function(field) { markFieldError(field, ''); });
      syncScopeControls(); syncWizardConnectionTest(); renderWizard(true);
      wizEl('wizardResetStatus').textContent = 'Wizard reset. Saved vault entries, plugin datasets and reports are retained.';
      if (typeof saveSession === 'function') saveSession();
    } catch (error) { wizardError(error.message || 'Could not reset the wizard.'); }
    finally { renderWizard(false); }
  }
  function bindSignpost(buttonId, panelId, closeId) {
    var button = wizEl(buttonId), panel = wizEl(panelId);
    if (!button || !panel) return;
    button.addEventListener('click', function() {
      document.querySelectorAll('.vcf-signpost').forEach(function(other) { if (other !== panel) other.hidden = true; });
      panel.hidden = !panel.hidden;
      button.setAttribute('aria-expanded', String(!panel.hidden));
    });
    if (wizEl(closeId)) wizEl(closeId).addEventListener('click', function() { panel.hidden = true; button.setAttribute('aria-expanded', 'false'); button.focus(); });
  }
  [['discoveryCard','wizardTargetsSlot'], ['credentialsCard','wizardAccessSlot'], ['credentialsTestActions','wizardBmcTestSlot'], ['jumpSelectRow','wizardJumpSavedSlot'], ['hclSection','wizardHclSlot'], ['scanThreadsGroup','wizardThreadsSlot'], ['scanSetupCard','wizardOutputSlot']].forEach(function(pair) {
    var node = document.getElementById(pair[0]);
    var home = document.createComment('scanner-control-home: ' + pair[0]);
    node.before(home);
    wizardMounts.push({node:node, home:home, slot:document.getElementById(pair[1])});
  });
  ['discVcfr','discVinv','discMtat','discVdt','discQuick','hwBmc','hwEsxi'].forEach(function(id) {
    if (wizEl(id)) wizEl(id).addEventListener('change', function() { syncScopeControls(); });
  });
  wizEl('useJumpSlide').addEventListener('change', async function() {
    wizardJumpSavedChoice = null;
    if (this.checked && !wizOn('useVaultSlide')) {
      wizEl('useVaultSlide').checked = true;
      wizardNote('Credential Vault enabled. Jump host profiles and host-key pins are stored in the vault.');
    } else wizardNote('');
    syncScopeControls();
    if (this.checked) await ensureWizardVault();
  });
  wizEl('useVaultSlide').addEventListener('change', async function() {
    wizardBmcSavedChoice = null;
    if (!this.checked && wizOn('useJumpSlide')) {
      wizEl('useJumpSlide').checked = false;
      wizardNote('Jump host turned off because Credential Vault was disabled.');
    } else if (this.checked) wizardNote('');
    syncScopeControls();
    if (this.checked) await ensureWizardVault();
  });
  wizEl('wizSameVcenter').addEventListener('change', function() {
    if (this.checked) wizEl('wizAdminEndpoint').value = wizEl('wizRoEndpoint').value;
  });
  wizEl('wizRoSaveNo').addEventListener('click', function() { wizardRoSaveChoice = 'no'; wizEl('wizRoSaveBar').hidden = true; });
  wizEl('wizRoSaveYes').addEventListener('click', async function() {
    wizardRoSaveChoice = 'yes';
    try {
      await post('/api/vault/services', {
        kind: 'vcenter', role: 'readonly', label: wizEl('wizRoEndpoint').value.trim() || 'vCenter',
        endpoint: wizEl('wizRoEndpoint').value.trim(), username: wizEl('wizRoUser').value.trim(), password: wizEl('wizRoPass').value, certificate_pin: wizardRoPin
      });
      wizEl('wizRoSaveText').textContent = 'Account and accepted certificate fingerprint saved in the encrypted vault.';
    } catch (error) {
      wizardRoSaveChoice = '';
      wizEl('wizRoSaveText').textContent = error.message || 'Could not save to the vault.';
    }
  });
  wizEl('wizRoReviewCert').addEventListener('click', async function() {
    var button = this;
    wizardRoReviewed = null;
    wizEl('wizRoCertReview').hidden = true;
    button.disabled = true;
    try {
      var identity = syncWizardRoTrust(), context = wizardRoContext;
      var target = new URL(identity.endpoint);
      var response = await getJson('/api/inspect-cert?host=' + encodeURIComponent(target.hostname.replace(/^\[|\]$/g, '')) + '&port=' + encodeURIComponent(target.port || '443'));
      syncWizardRoTrust();
      if (context !== wizardRoContext) return;
      var data = response.data, pin = String(data.sha256_raw || data.sha256 || '').replace(/:/g, '').toUpperCase();
      if (response.status !== 200 || !data.reachable || !/^[A-F0-9]{64}$/.test(pin)) throw new Error('Certificate inspection failed. Check the hostname and HTTPS port.');
      wizardRoReviewed = {context:context, identity:identity, pin:pin};
      var prior = identity.pin || wizardRoPin;
      wizEl('wizRoCertDetails').textContent = (prior && prior.replace(/:/g, '').toUpperCase() !== pin ? 'CERTIFICATE CHANGED: confirm the replacement before trusting.\n' : '') +
        'Endpoint: ' + identity.endpoint + '\nSubject: ' + (data.subject_cn || 'Unknown') + '\nIssuer: ' + (data.issuer_cn || 'Unknown') + '\nExpires: ' + (data.not_after || 'Unknown') + '\nSHA-256: ' + pin;
      wizEl('wizRoTrustCert').textContent = identity.id ? 'Trust and save in vault' : 'Trust certificate';
      wizEl('wizRoCertReview').hidden = false;
      wizEl('wizRoCertStatus').textContent = 'Certificate inspected. Trust is unchanged until you accept.';
      wizEl('wizRoTrustCert').focus();
    } catch (error) { wizEl('wizRoCertStatus').textContent = error.message || 'Certificate inspection failed.'; }
    finally { button.disabled = false; }
  });
  wizEl('wizRoCancelCert').addEventListener('click', function() {
    wizardRoReviewed = null;
    wizEl('wizRoCertReview').hidden = true;
    wizEl('wizRoCertStatus').textContent = 'Review cancelled. Certificate trust is unchanged.';
  });
  wizEl('wizRoTrustCert').addEventListener('click', async function() {
    syncWizardRoTrust();
    var reviewed = wizardRoReviewed;
    if (!reviewed || reviewed.context !== wizardRoContext) return;
    this.disabled = true;
    try {
      if (reviewed.identity.id) {
        await post('/api/vault/services/trust', {id:reviewed.identity.id, endpoint:reviewed.identity.endpoint, certificate_pin:reviewed.pin});
        await pluginCredentials.refresh();
      }
      syncWizardRoTrust();
      if (reviewed.context !== wizardRoContext) return;
      wizardRoPin = reviewed.pin;
      wizardRoReviewed = null;
      wizardClusterReady = false;
      wizEl('wizRoCertReview').hidden = true;
      wizEl('wizRoCertStatus').textContent = reviewed.identity.id ? 'Trusted fingerprint saved in the encrypted vault.' : 'Certificate trusted for this run. Save the account after discovery to retain its fingerprint in the vault.';
      if (wizardScope().vinv || wizardScope().mtatVcenter) await discoverWizardClusters();
    } catch (error) { wizEl('wizRoCertStatus').textContent = error.message || 'Could not save certificate trust. Trust was not accepted.'; }
    finally { this.disabled = false; }
  });
  async function discoverWizardClusters() {
    var body = wizardCredentialBody('readonly');
    var generation = ++wizardDiscoveryGeneration;
    wizardClusterReady = false;
    wizardClusterError = '';
    wizEl('wizClusterStatus').textContent = 'Connecting with the read-only account and listing clusters…';
    try {
      var data = await postJsonOk('/api/plugins/vinv/preflight', body);
      if (generation !== wizardDiscoveryGeneration) return;
      if (!data.ready) throw new Error(data.error || 'vCenter connection blocked.');
      var select = wizEl('wizCluster');
      var previous = select.value;
      select.replaceChildren(new Option(wizardScope().mtatVcenter ? 'Select one cluster (required for MTAT)' : 'All clusters', ''));
      (data.clusters || []).forEach(function(item) { select.add(new Option(item.name + ' (' + item.id + ')', item.id)); });
      if (data.clusters && data.clusters.length === 1) select.value = data.clusters[0].id;
      else if (previous) select.value = previous;
      wizardClusterReady = true;
      markFieldError('wizCluster', '');
      wizardCertificateAttention('');
      wizardClusterError = '';
      wizardError('');
      wizEl('wizClusterStatus').textContent = 'vCenter ' + data.server_version + ' · ' + data.host_count + ' hosts · ' + (data.clusters || []).length + ' cluster(s).';
      var scopeNow = wizardScope();
      if (scopeNow.vault && !wizOn('wizRoUseSaved') && wizEl('wizRoPass').value && !wizardRoSaveChoice) wizEl('wizRoSaveBar').hidden = false;
    } catch (error) {
      if (generation !== wizardDiscoveryGeneration) return;
      wizardClusterReady = false;
      wizardClusterError = error.message || 'Could not discover clusters. Check the endpoint, account, and certificate.';
      var code = error.data && error.data.error_code;
      var tlsFailure = ['tls_certificate','certificate_pin_mismatch','certificate_pin_invalid'].indexOf(code) >= 0 || /certificate verification failed|certificate.*(?:changed|mismatch)|pin mismatch/i.test(wizardClusterError);
      wizardCertificateAttention(tlsFailure ? 'vCenter certificate trust is blocking cluster discovery. Select Review certificate below, compare the SHA-256 fingerprint, then select Trust certificate. Discovery will retry automatically.' : '');
      wizEl('wizClusterStatus').textContent = wizardClusterError;
      if (tlsFailure && wizardStep === 2) {
        wizEl('wizRoReviewCert').focus();
        wizEl('wizRoCertAction').scrollIntoView({block:'center'});
      }
    }
  }
  wizEl('wizMtatSource').addEventListener('change', function() { wizEl('wizMtatStatus').textContent = ''; syncScopeControls(); });
  wizEl('wizMtatCaFile').addEventListener('input', function() { if (typeof mtatUpstream !== 'undefined') mtatUpstream.reset(); });
  wizEl('wizMtatRange').addEventListener('change', function() { wizEl('wizMtatStatus').textContent = ''; });
  wizEl('wizDiscoverClusters').addEventListener('click', discoverWizardClusters);
  wizEl('wizEsxiList').addEventListener('click', async function() {
    wizEl('wizEsxiListStatus').textContent = 'Listing ESXi hosts…';
    try {
      var data = await postJsonOk('/api/plugins/esxi-usb/targets', wizardCredentialBody('readonly'));
      wizardEsxiListed = true;
      var list = wizEl('wizEsxiHostList');
      list.replaceChildren();
      (data.hosts || []).forEach(function(host) {
        var item = document.createElement('li');
        item.textContent = (host.name || 'host') + (host.management_ip ? ' · ' + host.management_ip : '');
        var choose = document.createElement('button');
        choose.type = 'button'; choose.className = 'btn btn-outline btn-sm';
        choose.textContent = 'Use this host';
        choose.addEventListener('click', function() { wizEl('wizEsxiHost').value = host.management_ip || host.name; });
        item.appendChild(choose);
        list.appendChild(item);
      });
      wizEl('wizEsxiListStatus').textContent = (data.hosts || []).length + ' host(s) listed. ' + ((data.skipped || []).length ? data.skipped.length + ' skipped because BMC already captured them.' : '');
    } catch (error) {
      wizEl('wizEsxiListStatus').textContent = error.message || 'Could not list ESXi hosts.';
    }
  });
  document.addEventListener('click', async function(event) {
    if (event.target && event.target.id === 'discoverBtn') wizardBmcProbed = false;
  });
  if (wizEl('discoverBtn')) wizEl('discoverBtn').addEventListener('click', function() {
    var generation = wizardDiscoveryGeneration;
    var watcher = setInterval(function() {
      if (generation !== wizardDiscoveryGeneration) { clearInterval(watcher); return; }
      if (document.querySelector('.host-chk') || /reachable host/.test(wizEl('discStatus').textContent || '')) {
        wizardBmcProbed = true;
        clearInterval(watcher);
      }
    }, 400);
    setTimeout(function() { clearInterval(watcher); }, 120000);
  });
  wizEl('wizardResetBtn').addEventListener('click', resetWizard);
  function invalidateWizardRun(event) {
    if (!event.isTrusted || wizardBusy || !Object.keys(wizardPhases).length) return;
    var field = event.target;
    if (field && (field.closest('#scan-wizard') || wizardMounts.some(function(mount) { return mount.node.contains(field); }))) {
      clearWizardRunDisplay('Settings changed. Run the selected assessments again to collect results for this setup.');
    }
  }
  document.addEventListener('input', invalidateWizardRun);
  document.addEventListener('change', invalidateWizardRun);
  wizEl('wizardNextBtn').addEventListener('click', function() { advanceWizard(false); });
  wizEl('wizardRunBtn').addEventListener('click', function() { advanceWizard(true); });
  wizEl('wizardBackBtn').addEventListener('click', function() { if (wizardBusy) return; wizardStep = wizardPrevIndex(wizardStep); wizardError(''); renderWizard(true); });
  document.querySelectorAll('[data-wizard-step]').forEach(function(button) {
    button.addEventListener('click', function() {
      var index = Number(button.dataset.wizardStep);
      if (wizardBusy || index > wizardReached) return;
      wizardStep = index;
      wizardError('');
      renderWizard(true);
    });
  });
  document.addEventListener('keydown', function(event) {
    if (event.key !== 'Escape') return;
    document.querySelectorAll('.vcf-signpost').forEach(function(panel) { panel.hidden = true; });
  });
  bindSignpost('esxiUsbHelpBtn', 'esxiUsbHelp', 'esxiUsbHelpClose');
  bindSignpost('adminRoleHelpBtn', 'adminRoleHelp', 'adminRoleHelpClose');
  ['wizRoEndpoint','wizAdminEndpoint','wizEsxiPass','passwordInput'].forEach(function(id) {
    if (!wizEl(id)) return;
    wizEl(id).addEventListener('blur', function() {
      if (!this.value.trim() && wizardStep === 1) wizardFieldError(id, 'Enter a value, or choose a saved account.');
    });
  });
  wizEl('wizJumpPin').addEventListener('click', function() {
    var host = wizEl('wizJumpHost').value.trim();
    var port = parseInt(wizEl('wizJumpPort').value, 10) || 22;
    if (!host) { wizardFieldError('wizJumpHost', 'Enter the jump host name or address.'); return; }
    post('/api/vault/jump-hosts/probe-key', {host: host, port: port, id: wizEl('wizJumpId').value.trim()}).then(function(data) {
      if (!data || data.error) { wizEl('wizJumpPinStatus').textContent = (data && data.error) || 'Could not read the SSH key.'; return; }
      if (typeof showJumpHostKeyModal === 'function') {
        showJumpHostKeyModal(data, function(accepted) {
          wizardJumpKey = accepted.public_key || accepted.host_key || '';
          wizEl('wizJumpPinStatus').textContent = 'SSH key pinned for this jump host. Save it to the vault.';
          wizEl('wizJumpSave').disabled = !wizardJumpKey;
        });
      } else {
        wizardJumpKey = data.public_key || '';
        wizEl('wizJumpPinStatus').textContent = wizardJumpKey ? 'SSH key read. Save the jump host.' : 'The probe did not return a key.';
        wizEl('wizJumpSave').disabled = !wizardJumpKey;
      }
    }).catch(function(error) { wizEl('wizJumpPinStatus').textContent = error.message || 'Could not read the SSH key.'; });
  });
  wizEl('wizJumpSave').addEventListener('click', function() {
    post('/api/vault/jump-hosts', {
      id: wizEl('wizJumpId').value.trim(),
      host: wizEl('wizJumpHost').value.trim(),
      port: parseInt(wizEl('wizJumpPort').value, 10) || 22,
      username: wizEl('wizJumpUser').value.trim(),
      auth_type: 'password',
      password: wizEl('wizJumpPass').value,
      host_key: wizardJumpKey,
      subnets: wizEl('wizJumpSubnets').value.trim()
    }).then(function(data) {
      if (data && data.error) { wizEl('wizardJumpStatus').textContent = data.error; return; }
      wizEl('wizardJumpStatus').textContent = 'Jump host saved.';
      wizardJumpSavedChoice = null;
      if (typeof refreshJumpHosts === 'function') refreshJumpHosts();
    }).catch(function(error) { wizEl('wizardJumpStatus').textContent = error.message || 'Could not save the jump host.'; });
  });
  wizardReady = true;
  ['wizMtatEngine','wizMtatMode'].forEach(function (id) {
    wizEl(id).addEventListener('change', function () {
      wizardWindowProbeGeneration += 1; wizardWindowProbePending = false;
      syncScopeControls();
      if (wizardScope().mtatUpstream) mtatUpstream.describe().catch(function (error) { wizEl('wizMtatUpstreamStatus').textContent = error.message; });
    });
  });
  ['wizMtatSource','wizRoEndpoint','wizRoUser','wizRoPass','wizOpsEndpoint','wizOpsUser','wizOpsPass','wizVerifyTls','wizOpsVerifyTls'].forEach(function (id) {
    wizEl(id).addEventListener('change', function () { mtatUpstream.reset(); });
  });
  document.addEventListener('mtat-upstream-activated', function () { mtatUpstream.reset(); });
  var wizardUpstreamCredentialContexts = {};
  document.addEventListener('plugin-credentials-change', function (event) {
    var prefix = event.detail;
    if (prefix !== 'wizRo' && prefix !== 'wizOps') return;
    var record = pluginCredentials.selected(prefix);
    var context = JSON.stringify(record ? [record.id, record.endpoint, record.username, record.certificate_pin, record.auth_source] : [wizEl(prefix + 'Endpoint').value, wizEl(prefix + 'User').value]);
    if (wizardUpstreamCredentialContexts[prefix] && wizardUpstreamCredentialContexts[prefix] !== context) mtatUpstream.reset();
    wizardUpstreamCredentialContexts[prefix] = context;
  });
  wizEl('wizRoTrustCert').addEventListener('click', function () { mtatUpstream.reset(); });
  wizEl('wizMtatClusters').addEventListener('change', function () { mtatUpstream.ranges().catch(function (error) { wizEl('wizMtatUpstreamStatus').textContent = error.message; }); });
  wizEl('wizMtatUpstreamDiscover').addEventListener('click', async function () {
    this.disabled = true;
    try { await mtatUpstream.discover(wizardMtatBody()); }
    catch (error) { wizEl('wizMtatUpstreamStatus').textContent = error.message; }
    finally { this.disabled = false; }
  });
  syncScopeControls();
  showAppSection(false);
"""
