"""
Dark-Site HCL Bundle & Additive Retry Web UI JavaScript: HCL bundle modal,
bundle status check/upload, direct retry execution, and offline summary import.
"""

JS_HCL = """
  // ── Dark-Site HCL Bundle Management ─────────────────────────────────────
  function formatHclDate(val) {
    if (!val) return '';
    if (typeof val === 'number') {
      var d = new Date(val * (val < 1e11 ? 1000 : 1));
      if (!isNaN(d.getTime())) {
        var mArr = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
        return mArr[d.getUTCMonth()] + ' ' + d.getUTCDate();
      }
    }
    var s = String(val).trim();
    var mMatch = s.match(/([A-Za-z]+)\\s+(\\d{1,2})/);
    var monthNames = {
      'january':'Jan','jan':'Jan','february':'Feb','feb':'Feb','march':'Mar','mar':'Mar',
      'april':'Apr','apr':'Apr','may':'May','june':'Jun','jun':'Jun','july':'Jul','jul':'Jul',
      'august':'Aug','aug':'Aug','september':'Sep','sep':'Sep','october':'Oct','oct':'Oct',
      'november':'Nov','nov':'Nov','december':'Dec','dec':'Dec'
    };
    if (mMatch && monthNames[mMatch[1].toLowerCase()]) {
      return monthNames[mMatch[1].toLowerCase()] + ' ' + parseInt(mMatch[2], 10);
    }
    var isoMatch = s.match(/\\d{4}-(\\d{2})-(\\d{2})/);
    if (isoMatch) {
      var monIdx = parseInt(isoMatch[1], 10) - 1;
      var monArr = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
      if (monIdx >= 0 && monIdx < 12) {
        return monArr[monIdx] + ' ' + parseInt(isoMatch[2], 10);
      }
    }
    return s;
  }

  function refreshHclStatus() {
    get('/api/hcl').then(function(meta) {
      var badge = document.getElementById('hclBadge');
      var freshnessBadge = document.getElementById('hclFreshnessBadge');
      var countsEl = document.getElementById('hclCounts');
      var resetBtn = document.getElementById('hclResetBtn');

      if (!meta) {
        if (badge) badge.innerHTML = '<span class="text-muted">HCL status unavailable</span>';
        return;
      }

      if (meta.is_custom_bundle || meta.source_type === 'custom_bundle') {
        var ageStr = meta.dataset_age_days != null ? meta.dataset_age_days + ' days old' : '';
        var models = (meta.json_models_count || 0) + (meta.csv_models_count || 0);
        if (badge) {
          badge.innerHTML = '🔒 <strong style="color:var(--vcf-primary,#49afd9)">Custom Dark-Site Bundle: ' + esc(meta.bundle_filename || 'bundle.zip') + '</strong> ' +
            '<span class="badge info" style="margin-left:.3rem">' + models + ' entries</span> ' +
            (ageStr ? '<span class="text-muted">(' + ageStr + ')</span>' : '');
        }
        if (freshnessBadge) {
          freshnessBadge.innerHTML = '<span class="badge badge-info">Dark-Site Offline Mode</span>';
        }
        if (countsEl) countsEl.innerHTML = '';
        if (resetBtn) resetBtn.classList.remove('hidden');
      } else if (meta.file_exists) {
        var ageDays = meta.age_days != null ? meta.age_days : (meta.dataset_age_days != null ? meta.dataset_age_days : 0);
        var isFresh = meta.is_fresh !== false && ageDays <= 30;
        var dateDisplay = meta.last_downloaded_short || formatHclDate(meta.last_downloaded_timestamp || meta.last_downloaded_display || meta.created_at) || 'Cached';
        var upstreamDisplay = meta.upstream_updated_short || formatHclDate(meta.upstream_timestamp || meta.upstream_updated_time) || '';
        var sizeMb = meta.file_size_mb_int != null ? meta.file_size_mb_int : (meta.file_size_mb ? Math.round(meta.file_size_mb) : null);

        var freshHtml = isFresh
          ? '<span class="badge badge-success">✓ Fresh (' + ageDays + 'd ago)</span>'
          : '<span class="badge badge-warning">⚠️ Outdated (' + ageDays + 'd old)</span>';
        if (freshnessBadge) freshnessBadge.innerHTML = freshHtml;

        var subInfo = 'Downloaded: <strong>' + esc(dateDisplay) + '</strong>' +
          (upstreamDisplay ? ' &nbsp;|&nbsp; Upstream: <strong>' + esc(upstreamDisplay) + '</strong>' : '') +
          (sizeMb ? ' &nbsp;(' + sizeMb + ' MB)' : '');
        if (badge) badge.innerHTML = subInfo;

        var counts = meta.counts || {};
        if (counts && (counts.ssd || counts.nic || counts.controller || counts.hdd)) {
          var chips = '';
          if (counts.ssd) chips += '<span class="badge badge-secondary">💾 ' + counts.ssd.toLocaleString() + ' SSDs</span> ';
          if (counts.nic) chips += '<span class="badge badge-secondary">🌐 ' + counts.nic.toLocaleString() + ' NICs</span> ';
          if (counts.controller) chips += '<span class="badge badge-secondary">🎛️ ' + counts.controller.toLocaleString() + ' Controllers</span> ';
          if (counts.hdd) chips += '<span class="badge badge-secondary">💿 ' + counts.hdd.toLocaleString() + ' HDDs</span> ';
          if (countsEl) countsEl.innerHTML = chips;
        } else if (meta.json_models_count || meta.csv_models_count) {
          var totalM = (meta.json_models_count || 0) + (meta.csv_models_count || 0);
          if (countsEl) countsEl.innerHTML = '<span class="badge badge-secondary">' + totalM + ' models indexed</span>';
        } else {
          if (countsEl) countsEl.innerHTML = '';
        }

        if (resetBtn) resetBtn.classList.add('hidden');
      } else {
        if (badge) badge.innerHTML = '<span class="text-muted">No local HCL cache found. Click Refresh to download.</span>';
        if (freshnessBadge) freshnessBadge.innerHTML = '<span class="badge badge-danger">Not Downloaded</span>';
        if (countsEl) countsEl.innerHTML = '';
        if (resetBtn) resetBtn.classList.add('hidden');
      }
    }).catch(function() {
      var badge = document.getElementById('hclBadge');
      if (badge) badge.innerHTML = '<span class="text-muted">Default Broadcom HCL</span>';
    });
  }
  refreshHclStatus();

  var hclRefreshBtn = document.getElementById('hclRefreshBtn');
  var hclSpinner = document.getElementById('hclRefreshSpinner');
  if (hclRefreshBtn) {
    hclRefreshBtn.addEventListener('click', function() {
      hclRefreshBtn.disabled = true;
      if (hclSpinner) hclSpinner.style.display = 'inline-flex';
      post('/api/hcl/refresh', {}).then(function(r) {
        hclRefreshBtn.disabled = false;
        if (hclSpinner) hclSpinner.style.display = 'none';
        if (r && r.error) {
          alert('HCL Refresh failed: ' + r.error);
        } else {
          refreshHclStatus();
        }
      }).catch(function(err) {
        hclRefreshBtn.disabled = false;
        if (hclSpinner) hclSpinner.style.display = 'none';
        alert('HCL Refresh error: ' + err);
      });
    });
  }

  document.getElementById('hclUploadBtn').addEventListener('click', function() {
    document.getElementById('hclFileInput').click();
  });

  document.getElementById('hclFileInput').addEventListener('change', function(e) {
    var file = e.target.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function(evt) {
      var b64 = evt.target.result.split(',')[1] || '';
      post('/api/import-hcl', {filename: file.name, content_b64: b64}).then(function(r) {
        if (r.error) {
          alert('Failed to import HCL bundle: ' + r.error);
        } else {
          refreshHclStatus();
        }
      }).catch(function(err) {
        alert('HCL upload error: ' + err);
      });
    };
    reader.readAsDataURL(file);
  });

  document.getElementById('hclResetBtn').addEventListener('click', function() {
    del('/api/hcl').then(function() {
      refreshHclStatus();
    });
  });

  // Clamp threads input blur/change
  var threadsInp = document.getElementById('threadsInput');
  if (threadsInp) {
    threadsInp.addEventListener('change', function() {
      var val = parseInt(this.value, 10) || 12;
      this.value = Math.max(1, Math.min(32, val));
    });
  }

  // Extend timeout toggle & input handling
  var extendTimeoutChk = document.getElementById('extendTimeoutChk');
  var extendTimeoutBox = document.getElementById('extendTimeoutBox');
  var timeoutMinutesInput = document.getElementById('timeoutMinutesInput');

  function updateTimeoutBoxVisibility() {
    if (extendTimeoutChk && extendTimeoutBox) {
      toggle(extendTimeoutBox, extendTimeoutChk.checked);
    }
  }

  if (extendTimeoutChk) {
    extendTimeoutChk.addEventListener('change', function() {
      updateTimeoutBoxVisibility();
      saveSession();
    });
  }

  if (timeoutMinutesInput) {
    timeoutMinutesInput.addEventListener('input', function() {
      var val = parseInt(this.value, 10);
      if (!isNaN(val)) {
        if (val > 45) this.value = 45;
        if (val < 1) this.value = 1;
      }
      saveSession();
    });
    timeoutMinutesInput.addEventListener('change', function() {
      var val = parseInt(this.value, 10) || 10;
      this.value = Math.max(1, Math.min(45, val));
      saveSession();
    });
  }

  var crawlEndpointsChk = document.getElementById('crawlEndpointsChk');
  var crawlWarningBox = document.getElementById('crawlWarningBox');

  function updateCrawlWarningVisibility() {
    if (crawlEndpointsChk && crawlWarningBox) {
      toggle(crawlWarningBox, crawlEndpointsChk.checked);
    }
  }

  if (crawlEndpointsChk) {
    crawlEndpointsChk.addEventListener('change', function() {
      updateCrawlWarningVisibility();
      if (this.checked) {
        if (extendTimeoutChk) {
          extendTimeoutChk.checked = true;
          updateTimeoutBoxVisibility();
        }
        if (timeoutMinutesInput) {
          var currentVal = parseInt(timeoutMinutesInput.value, 10) || 0;
          if (currentVal < 15) {
            timeoutMinutesInput.value = 15;
          }
        }
      }
      saveSession();
    });
  }

  // ── Direct Additive Retry Execution ──────────────────────────────────────
  function executeDirectRetry(targetIps, retryLabel) {
    if (!targetIps || !targetIps.length || _scanRunning) return;

    var rangeInp = document.getElementById('rangeInput');
    if (rangeInp) {
      rangeInp.value = targetIps.join(', ');
      updateHostGates();
    }

    // Deselect all probed hosts in hostList so rangeInput targets are used
    var hostCheckboxes = document.querySelectorAll('.host-chk');
    hostCheckboxes.forEach(function(chk) { chk.checked = false; });

    // Apply Gentle Retry Profile:
    // 1. Concurrency threads: 2 if <= 4 hosts, else 4
    var thInp = document.getElementById('threadsInput');
    var gentleThreads = targetIps.length <= 4 ? 2 : 4;
    if (thInp) {
      thInp.value = gentleThreads;
    }

    // 2. Extend host timeout to 10 minutes (600s)
    if (extendTimeoutChk) {
      extendTimeoutChk.checked = true;
      updateTimeoutBoxVisibility();
    }
    if (timeoutMinutesInput) {
      timeoutMinutesInput.value = 10;
    }

    // 3. Allow partial scans
    var partialChk = document.getElementById('allowPartialChk');
    if (partialChk) {
      partialChk.checked = true;
    }

    saveSession();

    // Prepare credentials
    var user = document.getElementById('usernameInput').value.trim() || 'root';
    var pass = document.getElementById('passwordInput').value;
    var useVaultChkEl = document.getElementById('useVaultChk');
    var useVaultOn = !!(useVaultChkEl && useVaultChkEl.checked && !useVaultChkEl.disabled);
    var creds = null;
    var credRows = useVaultOn ? [] : document.querySelectorAll('.cred-input');
    if (credRows.length) {
      var credsMap = {};
      credRows.forEach(function(inp) {
        var ip = inp.dataset.ip;
        if (!ip) return;
        if (!credsMap[ip]) credsMap[ip] = {ip: ip, user: user, pass: pass};
        credsMap[ip][inp.dataset.field] = inp.value;
      });
      creds = Object.values(credsMap);
    }

    var missingHosts = [];
    if (!useVaultOn) {
      if (!credRows.length) {
        if (!pass || !pass.trim()) {
          missingHosts = targetIps.slice();
        }
      } else {
        var credsLookup = {};
        if (creds) {
          creds.forEach(function(c) { if (c.ip) credsLookup[c.ip] = c.pass; });
        }
        targetIps.forEach(function(h) {
          var p = (h in credsLookup) ? credsLookup[h] : pass;
          if (!p || !p.trim()) missingHosts.push(h);
        });
      }
    }

    promptMissingPasswordWarning(missingHosts, function() {
      var dellCreds = null;
      if (document.getElementById('dellEnabledChk') && document.getElementById('dellEnabledChk').checked) {
        var did = document.getElementById('dellIdInput').value.trim();
        var dsec = document.getElementById('dellSecretInput').value.trim();
        if (did && dsec) dellCreds = {id: did, secret: dsec};
      }

      // Remove retried IPs from _failedHostsMap
      targetIps.forEach(function(ip) {
        delete _failedHostsMap[ip];
      });
      renderFailedHosts();

      // UI transitions
      _activeHosts = Object.create(null);
      renderActiveHosts();
      hide(document.getElementById('retryActionsGroup'));
      hide(document.getElementById('retryBanner'));
      hide(document.getElementById('postScanActions'));
      show(document.getElementById('progressSection'));
      _isRetryScan = true;
      updateProgress(0, targetIps.length, true);

      document.getElementById('progressLabel').textContent = 'Rescanning ' + targetIps.length + ' host(s)…';
      show(document.getElementById('scanSpinner'));
      show(document.getElementById('cancelBtn'));
      document.getElementById('runBtn').disabled = true;
      document.getElementById('runBtn').textContent = '⏳ Rescanning…';

      appendLog('\\n[🔄] Kicking off additive retry for ' + targetIps.length + ' host(s) (' + (retryLabel || 'Gentle Profile') + ')...');
      appendLog('  • Concurrency: ' + gentleThreads + ' threads | Timeout: 600s | Allow Partial: true');
      if (_lastScanOutdir) {
        appendLog('  • Target Scan Folder: ' + _lastScanOutdir);
      }

      document.getElementById('progressSection').scrollIntoView({ behavior: 'smooth', block: 'start' });

      var outdirVal = _lastScanOutdir || (document.getElementById('outdirInput') ? document.getElementById('outdirInput').value.trim() : '');

      var chosenProfile = (document.querySelector('input[name=scanProfile]:checked') || {}).value || 'readiness-full';
      var isQuick = chosenProfile === 'inventory-lite';
      var isLean = chosenProfile === 'readiness-lean' || chosenProfile === 'inventory-lite';

      var body = {
        targets:       targetIps.join(', '),
        username:      user,
        password:      pass,
        creds:         creds || [],
        use_vault:     useVaultOn,
        threads:       gentleThreads,
        output_dir:    outdirVal,
        profile:       chosenProfile,
        quick:         isQuick,
        lean:          isLean,
        combined:      document.getElementById('combinedChk').checked,
        debug:         document.getElementById('debugChk').checked,
        save_json:     document.getElementById('saveJsonChk').checked,
        include_raw:   document.getElementById('includeRawChk').checked,
        crawl_endpoints: document.getElementById('crawlEndpointsChk') ? document.getElementById('crawlEndpointsChk').checked : false,
        obfuscate:     document.getElementById('obfuscateChk').checked,
        export_sheets: document.getElementById('exportSpreadsheetChk') ? document.getElementById('exportSpreadsheetChk').checked : true,
        allow_partial: true,
        auto_retry:    false,
        host_timeout:  600,
        dell_creds:    dellCreds,
        is_retry:      true,
        append_outdir: _lastScanOutdir || '',
        verify_ssl:    verifySsl,
        ca_bundle:     caBundle,
        dns_lookup:    dnsLookup,
        pinned_thumbprints: _pinnedThumbprints,
        enable_dash:   document.getElementById('enableDashChk') ? document.getElementById('enableDashChk').checked : false,
      };

      _scanRunning = true;
      post('/api/scan', body).then(function(r) {
        if (r.error) {
          alert('Retry error: ' + r.error);
          document.getElementById('runBtn').disabled = false;
          document.getElementById('runBtn').textContent = '▶  Run Assessment';
          hide(document.getElementById('scanSpinner'));
          hide(document.getElementById('cancelBtn'));
          _scanRunning = false;
          return;
        }
        updateProgress(0, r.total);
        startSSE(r.scan_id);
      }).catch(function(e) {
        alert('Retry scan request failed: ' + e);
        document.getElementById('runBtn').disabled = false;
        hide(document.getElementById('cancelBtn'));
        _scanRunning = false;
      });
    });
  }

  var retryIssuesBtn = document.getElementById('retryIssuesBtn');
  if (retryIssuesBtn) {
    retryIssuesBtn.addEventListener('click', function() {
      var targets = (_retryActiveIssuesIps && _retryActiveIssuesIps.length) ? _retryActiveIssuesIps : _retryAllIncompleteIps;
      executeDirectRetry(targets, 'Active Issues');
    });
  }

  var retryAllBtn = document.getElementById('retryAllBtn');
  if (retryAllBtn) {
    retryAllBtn.addEventListener('click', function() {
      executeDirectRetry(_retryAllIncompleteIps, 'All Non-Success Hosts');
    });
  }

  function handleImportSuccess(r) {
    var tbody = document.getElementById('resultsBody');
    if (tbody) tbody.innerHTML = '';
    if (r.hosts && Array.isArray(r.hosts)) {
      r.hosts.forEach(function(h) {
        addResultRow(h);
      });
    }
    onScanDone(r);
    appendLog('[✓] Successfully imported ' + (r.count || 0) + ' host(s) offline. Reports and consolidated fleet summary generated.');
  }

  function wireImportScan() {
    var scanBtn = document.getElementById('importScanBtn');
    var sumBtn = document.getElementById('importSummaryBtn');
    var input = document.getElementById('importSummaryInput');
    if (scanBtn && input) {
      scanBtn.addEventListener('click', function() { input.click(); });
    }
    if (sumBtn && input) {
      sumBtn.addEventListener('click', function() { input.click(); });
    }
    if (input) {
      input.addEventListener('change', function(e) {
        var files = e.target.files;
        if (!files || files.length === 0) return;
        var outdirVal = document.getElementById('outdirInput') ? document.getElementById('outdirInput').value.trim() : '';

        _scanRunning = true;
        _isImportScan = true;
        _isRetryScan = false;
        document.getElementById('logBox').innerHTML = '';
        document.getElementById('resultsBody').innerHTML = '';
        _failedHostsMap = Object.create(null);
        renderFailedHosts();
        _activeHosts = Object.create(null);
        renderActiveHosts();
        hide(document.getElementById('resultsSection'));
        hide(document.getElementById('openSummaryBtn'));
        hide(document.getElementById('openCombinedBtn'));
        hide(document.getElementById('openObfSummaryBtn'));
        hide(document.getElementById('openObfCombinedBtn'));
        hide(document.getElementById('postScanSummaryCard'));

        show(document.getElementById('progressSection'));
        show(document.getElementById('scanSpinner'));
        document.getElementById('progressLabel').textContent = 'Importing & Rendering Reports…';
        document.getElementById('runBtn').disabled = true;
        document.getElementById('runBtn').textContent = '⏳ Importing…';
        if (scanBtn) { scanBtn.disabled = true; scanBtn.textContent = '⏳ Importing…'; }
        if (sumBtn) { sumBtn.disabled = true; sumBtn.textContent = '⏳ Importing…'; }

        updateProgress(0, files.length, false, true);
        startSSE('import_' + Date.now());

        function handleImportFailure(msg) {
          _scanRunning = false;
          _isImportScan = false;
          hide(document.getElementById('scanSpinner'));
          document.getElementById('runBtn').disabled = false;
          document.getElementById('runBtn').textContent = '▶  Run Assessment';
          if (scanBtn) { scanBtn.disabled = false; scanBtn.textContent = '📁 Import prior scan'; }
          if (sumBtn) { sumBtn.disabled = false; sumBtn.textContent = '📁 Import Summary'; }
          alert(msg);
          appendLog('[✗] ' + msg);
        }

        if (files.length === 1) {
          var file = files[0];
          var isLargeOrCompressed = file.size > 8 * 1024 * 1024 || file.name.indexOf('.gz') !== -1 || file.name.indexOf('.zip') !== -1;
          if (isLargeOrCompressed) {
            var headers = {};
            if (outdirVal) headers['X-Output-Dir'] = outdirVal;
            headers['Content-Disposition'] = 'attachment; filename="' + encodeURIComponent(file.name) + '"';
            appendLog('[⏳] Uploading and importing scan archive: ' + file.name + '...');
            fetch('/api/import-summary-file', {
              method: 'POST',
              headers: headers,
              credentials: 'same-origin',
              body: file,
            }).then(function(res) {
              return res.json();
            }).then(function(r) {
              if (r.error) {
                var tip = (r.error.indexOf('exceeds limit') !== -1)
                  ? '\\n\\n💡 Tip: Unzip the file and import "data/fleet_summary.json" directly (~2 MB), or use CLI: python -m vcf_hci --from-summary <path>'
                  : '';
                handleImportFailure('Import failed: ' + r.error + tip);
                return;
              }
              handleImportSuccess(r);
            }).catch(function(err) {
              handleImportFailure('Import upload error: ' + err);
            });
            input.value = '';
            return;
          }
        }

        var promises = [];
        for (var i = 0; i < files.length; i++) {
          (function(f) {
            promises.push(new Promise(function(resolve, reject) {
              var reader = new FileReader();
              reader.onload = function(evt) {
                try {
                  var parsed = JSON.parse(evt.target.result);
                  resolve(parsed);
                } catch (err) {
                  reject(new Error('Invalid JSON in ' + f.name + ': ' + err.message));
                }
              };
              reader.onerror = function(err) { reject(err); };
              reader.readAsText(f);
            }));
          })(files[i]);
        }

        appendLog('[⏳] Parsing ' + files.length + ' file(s) for offline report regeneration...');
        Promise.all(promises).then(function(parsedList) {
          var allResults = [];
          parsedList.forEach(function(item) {
            if (Array.isArray(item)) {
              allResults = allResults.concat(item);
            } else if (item && typeof item === 'object') {
              if (Array.isArray(item.results)) {
                allResults = allResults.concat(item.results);
              } else if (Array.isArray(item.hosts)) {
                allResults = allResults.concat(item.hosts);
              } else {
                allResults.push(item);
              }
            }
          });

          return post('/api/import-summary', { data: allResults, output_dir: outdirVal });
        }).then(function(r) {
          if (r.error) {
            handleImportFailure('Import failed: ' + r.error);
            return;
          }
          handleImportSuccess(r);
        }).catch(function(err) {
          handleImportFailure('Import error: ' + err.message);
        });
        input.value = '';
      });
    }
  }
  wireImportScan();

"""
