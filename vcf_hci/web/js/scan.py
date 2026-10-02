"""
Scan SSE & Assessment Web UI JavaScript: Server-Sent Events (SSE) listener,
host status cards, progress tracking, stage management, and scan trigger/cancellation.
"""

JS_SCAN = """
  // ── SSE / scan state ──────────────────────────────────────────────────────
  var _eventSource = null;
  var _scanRunning = false;
  var _scanTotal   = 0;
  var _scanDone    = 0;
  var _isRetryScan = false;
  var _isImportScan = false;
  var _isRemoteScan = false;

  function appendLog(msg) {
    var box = document.getElementById('logBox');
    if (!msg) return;
    var span = document.createElement('span');
    if (msg.indexOf('[✓]') !== -1 || msg.indexOf('[✔]') !== -1 || msg.indexOf('[🔄✓]') !== -1)  span.className = 'ok';
    else if (msg.indexOf('[✗]') !== -1 || msg.indexOf('[!]') !== -1) span.className = 'err';
    else if (msg.indexOf('[⚠️]') !== -1 || msg.indexOf('[🔄⚠️]') !== -1) span.className = 'warn';
    else if (msg.indexOf('[🔒]') !== -1) span.className = 'lock';
    else if (msg.indexOf('[🔄]') !== -1) span.className = 'retry';
    else if (msg.indexOf('[ℹ]') !== -1) span.className = 'info';
    span.textContent = msg + '\\n';
    box.appendChild(span);
    box.scrollTop = box.scrollHeight;
  }

  function updateProgress(done, total, isRescan, isImport) {
    _scanDone  = done;
    _scanTotal = total;
    if (isRescan !== undefined) {
      _isRetryScan = !!isRescan;
    }
    if (isImport !== undefined) {
      _isImportScan = !!isImport;
    }
    var safeDone = (total > 0 && done > total) ? total : done;
    var pct = total ? Math.min(100, Math.round(safeDone / total * 100)) : 0;
    document.getElementById('progressBar').style.width = pct + '%';
    if (_isImportScan) {
      document.getElementById('progressLabel').textContent = 'Importing & Rendering…';
      document.getElementById('runBtn').textContent = '⏳ Importing…';
      var scanBtn = document.getElementById('importScanBtn');
      var sumBtn = document.getElementById('importSummaryBtn');
      if (scanBtn) { scanBtn.disabled = true; scanBtn.textContent = '⏳ Importing…'; }
      if (sumBtn) { sumBtn.disabled = true; sumBtn.textContent = '⏳ Importing…'; }
      document.getElementById('progressText').textContent = 'Importing: ' + safeDone + ' / ' + total + ' hosts  (' + pct + '%)';
    } else if (_isRetryScan) {
      document.getElementById('progressLabel').textContent = 'Auto-retrying incomplete / failed hosts…';
      document.getElementById('runBtn').textContent = '⏳ Auto-Retrying…';
      document.getElementById('progressText').textContent = 'Auto-Retrying: ' + safeDone + ' / ' + total + ' hosts  (' + pct + '%)';
    } else {
      document.getElementById('progressLabel').textContent = 'Scanning…';
      document.getElementById('runBtn').textContent = '⏳ Scanning…';
      document.getElementById('progressText').textContent = safeDone + ' / ' + total + ' hosts  (' + pct + '%)';
    }
  }

  function esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function verdictBucket(h) {
    var verdict = h.verdict || '';
    var partial = !!h.partial_scan;
    if (verdict.indexOf('Unsupported') !== -1) {
      return {cls: 'badge-danger', label: verdict, bucket: 'unsupported', why: ''};
    }
    if (partial || !verdict || verdict === 'Unknown' || verdict.indexOf('Unverified') !== -1) {
      var why = h.partial_reason || (h.partial_stage ? ('Timed out during ' + h.partial_stage) : ((!verdict || verdict === 'Unknown') ? 'CPU not verified' : verdict));
      var label = partial ? 'Incomplete' : ((verdict && verdict !== 'Unknown') ? verdict : 'Incomplete');
      return {cls: 'badge-warning', label: label, bucket: 'incomplete', why: why};
    }
    if (verdict.indexOf('Deprecated') !== -1) {
      return {cls: 'badge-warning', label: verdict, bucket: 'deprecated', why: ''};
    }
    return {cls: 'badge-success', label: verdict, bucket: 'supported', why: ''};
  }

  function addResultRow(h) {
    var tbody = document.getElementById('resultsBody');
    var bucket = verdictBucket(h || {});
    var rem = h.remediation || {};
    var remTag = '';
    if (rem.status === 'fully_remediated') {
      var resSec = (rem.resolved_sections || []).join(', ');
      remTag = ' &nbsp;<span class="badge badge-success" style="font-weight:600;cursor:help" title="Recovered missing sections via targeted rescan: ' + esc(resSec) + '">🔄 Remediated</span>';
    } else if (h.partial_scan && rem.status === 'partially_remediated') {
      var resSec2 = (rem.resolved_sections || []).join(', ');
      var remSec = (rem.remaining_sections || []).join(', ');
      remTag = ' &nbsp;<span class="badge warning" style="font-weight:600;cursor:help" title="Partially remediated (recovered: ' + esc(resSec2) + '; missing: ' + esc(remSec) + ')">⚠️ Partial (Remediated)</span>';
    } else if (h.partial_scan) {
      var partialTooltip = h.partial_reason || (h.partial_stage ? 'Timed out during ' + h.partial_stage : 'Collection timed out');
      remTag = ' &nbsp;<span class="badge warning" style="font-weight:600;cursor:help" title="' + esc(partialTooltip) + '">⚠️ Partial (Incomplete)</span>';
    }
    var mainRpt = h.report || h.filename || '';
    if (!mainRpt && h.ip) {
      mainRpt = 'vsphere_vsan_report_' + h.ip.replace(/[^A-Za-z0-9_.-]/g, '_') + '.html';
    }
    var obfRpt  = h.obf_report || h.obf_filename || '';
    var isRemotePending = _scanRunning && (_isRemoteScan || !!h.is_remote);
    var links = '—';
    if (isRemotePending) {
      links = '<span class="badge badge-subtle" title="Assessment complete on jump host. Report will automatically sync to your workstation once all targets finish." style="font-size:0.75rem;cursor:help;color:#475569;background:#f1f5f9;border:1px solid #cbd5e1;padding:3px 7px;border-radius:4px;">☁️ Remote (Sync pending)</span>';
    } else {
      links = mainRpt ? '<a href="/reports/'+encodeURIComponent(mainRpt)+'" target="_blank" rel="noopener noreferrer">Open ↗</a>' : '—';
      if (obfRpt) {
        links += ' &nbsp;<a href="/reports/'+encodeURIComponent(obfRpt)+'" target="_blank" rel="noopener noreferrer" title="Open obfuscated report copy" style="color:#7c3aed;font-weight:500">🔒 Obfuscated ↗</a>';
      }
    }
    var whyHtml = bucket.why ? '<span class="run-reason">' + esc(bucket.why) + '</span>' : '';
    var inner = '<td><strong>'+esc(h.hostname)+'</strong><br><small class="text-muted">'+esc(h.ip)+'</small></td>'
      + '<td>'+esc(h.vendor)+' '+esc(h.model)+remTag+'</td>'
      + '<td><span class="badge '+bucket.cls+'">'+esc(bucket.label)+'</span>'+whyHtml+'</td>'
      + '<td>'+links+'</td>';

    var existingRow = h.ip ? tbody.querySelector('tr[data-ip="' + esc(h.ip) + '"]') : null;
    if (existingRow) {
      existingRow._lastHostData = h;
      existingRow.dataset.verdictBucket = bucket.bucket;
      existingRow.innerHTML = inner;
    } else {
      var tr = document.createElement('tr');
      if (h.ip) tr.dataset.ip = h.ip;
      tr.dataset.verdictBucket = bucket.bucket;
      tr._lastHostData = h;
      tr.innerHTML = inner;
      tbody.appendChild(tr);
    }
    show(document.getElementById('resultsSection'));
    if (typeof applyLocalResultsPage === 'function') applyLocalResultsPage();
  }

  var _lastScanOutdir = '';
  var _failedHostsMap = Object.create(null);
  var _retryActiveIssuesIps = [];
  var _retryAllIncompleteIps = [];

  function addFailedHost(f) {
    if (!f || !f.ip) return;
    _failedHostsMap[f.ip] = f;
    renderFailedHosts();
  }

  function renderFailedHosts() {
    var section = document.getElementById('failedHostsSection');
    var tbody = document.getElementById('failedHostsBody');
    var countSpan = document.getElementById('failedCount');
    var filterInput = document.getElementById('failedFilter');
    var filterVal = (filterInput ? filterInput.value : '').toLowerCase().trim();

    var list = Object.values(_failedHostsMap);
    if (!list.length) {
      hide(section);
      if (tbody) tbody.innerHTML = '';
      return;
    }

    show(section);
    if (countSpan) countSpan.textContent = list.length;

    var filtered = list.filter(function(item) {
      if (!filterVal) return true;
      var haystack = (item.ip + ' ' + (item.hostname || '') + ' ' + (item.reason_label || '') + ' ' + (item.stage || '') + ' ' + (item.detail || '')).toLowerCase();
      return haystack.indexOf(filterVal) !== -1;
    });

    if (!tbody) return;
    tbody.innerHTML = filtered.map(function(item) {
      var badgeCls = 'badge-danger';
      var badgeText = item.reason_label || 'Failed';
      var rCode = item.reason_code || '';
      var detail = (item.detail || '').toLowerCase();
      var label = (item.reason_label || '').toLowerCase();

      var isTlsFailure = false;
      var isActiveInScan = !!(_activeHosts && _activeHosts[item.ip]);
      if (isActiveInScan) {
        badgeCls = 'badge-info';
        badgeText = '🔄 Auto-Retrying…';
      } else if (rCode === 'auth_failed' || label.indexOf('auth') !== -1 || detail.indexOf('401') !== -1 || detail.indexOf('403') !== -1) {
        badgeCls = 'badge-danger';
        badgeText = '🔒 Auth Failed';
      } else if (rCode === 'timeout_after_auth' || rCode === 'timeout_before_auth' || label.indexOf('timed out') !== -1 || detail.indexOf('timed out') !== -1 || detail.indexOf('timeout') !== -1) {
        badgeCls = 'badge-warning';
        badgeText = '⏱️ Timed Out';
      } else if (rCode === 'connection_failed' || label.indexOf('unreachable') !== -1 || detail.indexOf('connection') !== -1) {
        badgeCls = 'badge-secondary';
        badgeText = '🔌 Unreachable';
      } else if (rCode && rCode.indexOf('ssl_') === 0) {
        badgeCls = 'badge-danger';
        badgeText = '🔒 TLS Error';
        isTlsFailure = true;
      }

      var actionBtn = isTlsFailure
        ? '<button type="button" class="btn btn-outline btn-sm review-failed-cert-btn" data-ip="' + esc(item.ip) + '">🔒 Review &amp; Accept Cert</button>'
        : '<span class="text-xs text-muted">—</span>';

      return '<tr>'
        + '<td><span class="badge ' + badgeCls + '">' + esc(badgeText) + '</span></td>'
        + '<td><strong class="font-mono">' + esc(item.ip) + '</strong></td>'
        + '<td>' + esc(item.hostname || 'Unknown') + '</td>'
        + '<td>' + esc(item.reason_label || 'Failed') + '</td>'
        + '<td><span class="text-xs text-muted">[' + esc(item.stage || 'N/A') + '] ' + esc(item.detail || '') + '</span></td>'
        + '<td>' + actionBtn + '</td>'
        + '</tr>';
    }).join('');

    tbody.querySelectorAll('.review-failed-cert-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var ip = this.dataset.ip;
        inspectAndReviewCert(ip);
      });
    });
  }

  var _activeHosts = Object.create(null);
  var _activeTimer = null;

  function renderActiveHosts() {
    var box = document.getElementById('activeScansBox');
    var list = document.getElementById('activeScansList');
    var countSpan = document.getElementById('activeCount');
    var ips = Object.keys(_activeHosts);

    if (!ips.length) {
      hide(box);
      list.innerHTML = '';
      if (_activeTimer) { clearInterval(_activeTimer); _activeTimer = null; }
      return;
    }

    show(box);
    countSpan.textContent = ips.length;

    var now = Date.now() / 1000;
    var hostItems = ips.map(function(ip) {
      var entry = _activeHosts[ip];
      var elapsed = Math.max(0, Math.floor(now - (entry.startTime || now)));
      return { ip: ip, entry: entry, elapsed: elapsed };
    });

    // Sort: slow hosts (elapsed >= 300s / 5m) pinned to top, then by elapsed time descending
    hostItems.sort(function(a, b) {
      var aSlow = a.elapsed >= 300;
      var bSlow = b.elapsed >= 300;
      if (aSlow && !bSlow) return -1;
      if (!aSlow && bSlow) return 1;
      return b.elapsed - a.elapsed;
    });

    list.innerHTML = hostItems.map(function(item) {
      var ip = item.ip;
      var elapsed = item.elapsed;
      var mins = Math.floor(elapsed / 60);
      var secs = elapsed % 60;
      var timeStr = (mins < 10 ? '0' : '') + mins + ':' + (secs < 10 ? '0' : '') + secs;
      var isSlow = elapsed >= 300;
      var rowCls = isSlow ? 'active-scan-row slow-host' : 'active-scan-row';
      var tag = isSlow ? '<span class="badge badge-warning text-xs">⚠️ Slow (&ge;5m)</span>' : '';
      var stageStr = item.entry.stage || (_isImportScan ? 'Rendering…' : (_isRetryScan ? 'Rescanning…' : 'Scanning…'));

      var actionHtml = '';
      if (item.entry.is_import || _isImportScan) {
        actionHtml = '<span class="text-muted text-xs">Importing</span>';
      } else if (item.entry.skipped) {
        actionHtml = '<span class="text-muted text-xs">Skipped (finishing in-flight GET)</span>';
      } else {
        actionHtml = '<button class="btn-skip" data-ip="' + esc(ip) + '">⏭️ Skip Host</button>';
      }

      return '<div class="' + rowCls + '">'
        + '<div class="active-scan-info">'
        + '  <span class="active-spinner"></span>'
        + '  <strong class="font-mono">' + esc(ip) + '</strong>'
        + '  <span class="stage-pill"><span class="pulse-dot"></span> ' + esc(stageStr) + '</span>'
        +    tag
        + '</div>'
        + '<div class="active-scan-actions">'
        + '  <span class="timer-badge">⏱️ ' + timeStr + '</span>'
        +    actionHtml
        + '</div>'
        + '</div>';
    }).join('');

    // Attach click listeners for skip buttons
    list.querySelectorAll('.btn-skip').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var ip = btn.dataset.ip;
        skipHost(ip, btn);
      });
    });

    if (Object.keys(_failedHostsMap).length > 0) {
      renderFailedHosts();
    }

    if (!_activeTimer) {
      _activeTimer = setInterval(renderActiveHosts, 1000);
    }
  }

  function showJumpReconnectAlert(info) {
    var el = document.getElementById('jumpReconnectAlert');
    if (!el) return;
    var hostName = (info && (info.host || info.jump_host_id)) || 'jump host';
    var textEl = document.getElementById('jumpReconnectText');
    if (textEl) {
      textEl.textContent = "Lost connection to '" + hostName + "' (VPN dropped). Remote assessment is still running or completed on the jump host.";
    }
    show(el);
    show(document.getElementById('progressSection'));
  }

  function hideJumpReconnectAlert() {
    var el = document.getElementById('jumpReconnectAlert');
    if (el) hide(el);
  }

  function skipHost(ip, btnElem) {
    if (btnElem) { btnElem.disabled = true; btnElem.textContent = 'Skipping…'; }
    if (_activeHosts[ip]) { _activeHosts[ip].skipped = true; }
    post('/api/scan/skip_host', { ip: ip })
      .then(function() {
        appendLog('  [⏭️] Skip requested for ' + ip);
        renderActiveHosts();
      })
      .catch(function(err) {
        appendLog('  [!] Failed to skip ' + ip + ': ' + err.message);
        if (btnElem) { btnElem.disabled = false; btnElem.textContent = '⏭️ Skip Host'; }
      });
  }

  function onScanDone(d) {
    if (!d) d = {};
    _scanRunning = false;
    _isRemoteScan = false;
    var renderedRowCount = document.querySelectorAll('#resultsBody tr[data-ip]').length;
    var resultsCount = (d.results && Array.isArray(d.results)) ? d.results.length : 0;
    var fallbackOk = Math.max(resultsCount, renderedRowCount);
    if ((!d.n_ok || d.n_ok === 0) && fallbackOk > 0) {
      d.n_ok = fallbackOk;
    }
    if (d && (d.n_ok > 0 || d.cancelled)) {
      hideJumpReconnectAlert();
    }
    var wasImport = _isImportScan || !!(d && d.is_import);
    _isImportScan = false;
    if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
    _activeHosts = Object.create(null);
    renderActiveHosts();
    if (d && d.failed_hosts && Array.isArray(d.failed_hosts)) {
      d.failed_hosts.forEach(addFailedHost);
    }
    var isCancelled = !!(d && (d.cancelled || d.error === 'Cancelled by user'));
    var isRescan = !!(d && (d.is_retry || d.had_auto_retry || _isRetryScan));
    if (isCancelled) {
      document.getElementById('progressLabel').textContent =
        '🛑 Scan cancelled — ' + (d.n_ok || 0) + '/' + (d.n_total || 0) + ' hosts completed.';
      document.getElementById('progressText').textContent = 'Cancelled';
    } else if (wasImport) {
      document.getElementById('progressBar').style.width = '100%';
      document.getElementById('progressText').textContent = '100% Imported';
      document.getElementById('progressLabel').textContent =
        '✔ Finished import — ' + (d.n_ok || 0) + '/' + (d.n_total || 0) + ' hosts processed.';
    } else {
      document.getElementById('progressBar').style.width = '100%';
      document.getElementById('progressText').textContent = isRescan ? '100% Rescanned' : '100% Scanned';
      document.getElementById('progressLabel').textContent =
        '✔ Finished ' + (isRescan ? 'rescan' : 'scan') + ' — ' + (d.n_ok || 0) + '/' + (d.n_total || 0) + ' hosts succeeded.';
    }
    hide(document.getElementById('scanSpinner'));
    hide(document.getElementById('cancelBtn'));
    document.getElementById('cancelBtn').disabled = false;
    document.getElementById('cancelBtn').textContent = '🛑 Cancel Scan';
    document.getElementById('runBtn').disabled = false;
    document.getElementById('runBtn').textContent = '▶  Run Assessment';
    var scanBtn = document.getElementById('importScanBtn');
    var sumBtn = document.getElementById('importSummaryBtn');
    if (scanBtn) { scanBtn.disabled = false; scanBtn.textContent = '📁 Import prior scan'; }
    if (sumBtn) { sumBtn.disabled = false; sumBtn.textContent = '📁 Import Summary'; }

    if (d && d.results && Array.isArray(d.results) && d.results.length > 0) {
      d.results.forEach(addResultRow);
    } else {
      var existingRows = document.querySelectorAll('#resultsBody tr[data-ip]');
      existingRows.forEach(function(tr) {
        if (tr._lastHostData) {
          addResultRow(tr._lastHostData);
        }
      });
    }

    var v = d.vcf_readiness || {supported:0, deprecated:0, unsupported:0, incomplete:0};
    var totV = (v.supported || 0) + (v.deprecated || 0) + (v.unsupported || 0) + (v.incomplete || 0);
    if (totV === 0 && (d.n_ok || 0) > 0) {
      var rows = document.querySelectorAll('#resultsBody tr');
      var sup = 0, dep = 0, unsup = 0, inc = 0;
      rows.forEach(function(r) {
        var b = r.dataset.verdictBucket || '';
        if (b === 'unsupported') unsup++;
        else if (b === 'deprecated') dep++;
        else if (b === 'incomplete') inc++;
        else if (b === 'supported') sup++;
        else {
          var txt = r.textContent || '';
          if (txt.indexOf('Unsupported') !== -1) unsup++;
          else if (txt.indexOf('Incomplete') !== -1 || txt.indexOf('Unverified') !== -1) inc++;
          else if (txt.indexOf('Deprecated') !== -1) dep++;
          else sup++;
        }
      });
      if (sup + dep + unsup + inc > 0) {
        v = { supported: sup, deprecated: dep, unsupported: unsup, incomplete: inc };
      }
    }

    appendLog('[✓] Finished ' + (isRescan ? 'rescan' : 'scan') + ' — Assessment complete (' + (d.n_ok || 0) + '/' + (d.n_total || 0) + ' hosts succeeded)');
    if (d.scan_summary) {
      appendLog('[⏱️] ' + d.scan_summary);
    }
    appendLog('[📊] VCF Readiness: ' + (v.supported || 0) + ' Supported, ' + (v.deprecated || 0) + ' Deprecated, ' + (v.unsupported || 0) + ' Unsupported, ' + (v.incomplete || 0) + ' Incomplete');
    if (d.outdir) {
      appendLog('[📁] Output folder: ' + d.outdir);
    }
    if (d.zip_path) {
      appendLog('[📦] Compressed archive: ' + d.zip_path);
    }

    var card = document.getElementById('postScanSummaryCard');
    if (card) {
      document.getElementById('summarySuccessBadge').textContent = (d.n_ok || 0) + '/' + (d.n_total || 0) + ' succeeded';
      document.getElementById('summaryMetricsText').textContent = d.scan_summary || 'Scan complete';
      document.getElementById('summarySupportedBadge').textContent = (v.supported || 0) + ' Supported';
      document.getElementById('summaryDeprecatedBadge').textContent = (v.deprecated || 0) + ' Deprecated';
      document.getElementById('summaryUnsupportedBadge').textContent = (v.unsupported || 0) + ' Unsupported';
      var incBadge = document.getElementById('summaryIncompleteBadge');
      if (incBadge) incBadge.textContent = (v.incomplete || 0) + ' Incomplete';
      var remBadge = document.getElementById('summaryRemediatedBadge');
      if (remBadge) {
        if (d.n_remediated && d.n_remediated > 0) {
          remBadge.textContent = d.n_remediated + ' Remediated via Rescan';
          show(remBadge);
        } else {
          hide(remBadge);
        }
      }
      if (d.outdir) {
        document.getElementById('summaryOutdirText').textContent = d.outdir;
        show(document.getElementById('summaryOutdirRow'));
      } else {
        hide(document.getElementById('summaryOutdirRow'));
      }
      if (d.zip_path) {
        document.getElementById('summaryZipText').textContent = d.zip_path;
        show(document.getElementById('summaryZipRow'));
      } else {
        hide(document.getElementById('summaryZipRow'));
      }
      show(card);
    }

    var sumRpt = d.summary_report || d.summary;
    if (sumRpt) {
      var sBtn = document.getElementById('openSummaryBtn');
      sBtn.dataset.report = sumRpt;
      show(sBtn);
    } else if (d.n_ok > 0) {
      var sBtn = document.getElementById('openSummaryBtn');
      sBtn.dataset.report = '00_fleet_summary.html';
      show(sBtn);
    }
    var obfSum = d.obf_summary_report || d.obf_summary;
    if (obfSum) {
      var obfBtn = document.getElementById('openObfSummaryBtn');
      obfBtn.dataset.report = obfSum;
      show(obfBtn);
    }
    if (d.fleet_report || d.fleet) {
      var btn = document.getElementById('openReportBtn');
      btn.dataset.report = d.fleet_report || d.fleet;
      show(btn);
    }
    var obfFleet = d.obf_fleet_report || d.obf_fleet;
    if (obfFleet) {
      var obfRptBtn = document.getElementById('openObfReportBtn');
      obfRptBtn.dataset.report = obfFleet;
      show(obfRptBtn);
    }

    if (d.outdir) {
      _lastScanOutdir = d.outdir;
    }

    // Failure & Incomplete categorization
    var partialIps = [];
    var timedOutIps = [];
    var authFailedIps = [];
    var unreachableIps = [];
    var seenCategoryIps = Object.create(null);

    // 1. Partial hosts (from d.partial_hosts)
    if (d.partial_hosts && Array.isArray(d.partial_hosts)) {
      d.partial_hosts.forEach(function(p) {
        var pIp = (typeof p === 'string') ? p : (p && p.ip);
        if (pIp && !seenCategoryIps[pIp]) {
          seenCategoryIps[pIp] = 'partial';
          partialIps.push(pIp);
        }
      });
    }

    // 2. Failed hosts from d.failed_hosts and _failedHostsMap
    var allFailedList = [];
    if (d.failed_hosts && Array.isArray(d.failed_hosts)) {
      d.failed_hosts.forEach(function(f) {
        if (typeof f === 'string') {
          allFailedList.push({ ip: f });
        } else if (f && f.ip) {
          allFailedList.push(f);
        }
      });
    }
    Object.values(_failedHostsMap).forEach(function(f) {
      if (f && f.ip) allFailedList.push(f);
    });

    allFailedList.forEach(function(f) {
      var fIp = f.ip;
      if (!fIp || seenCategoryIps[fIp]) return;

      var rCode = f.reason_code || '';
      var detail = (f.detail || '').toLowerCase();
      var label = (f.reason_label || '').toLowerCase();

      if (rCode === 'auth_failed' || label.indexOf('auth') !== -1 || detail.indexOf('401') !== -1 || detail.indexOf('403') !== -1 || detail.indexOf('credentials') !== -1) {
        seenCategoryIps[fIp] = 'auth';
        authFailedIps.push(fIp);
      } else if (rCode === 'timeout_after_auth' || rCode === 'timeout_before_auth' || label.indexOf('timed out') !== -1 || detail.indexOf('timed out') !== -1 || detail.indexOf('timeout') !== -1) {
        seenCategoryIps[fIp] = 'timeout';
        timedOutIps.push(fIp);
      } else {
        seenCategoryIps[fIp] = 'unreachable';
        unreachableIps.push(fIp);
      }
    });

    _retryActiveIssuesIps = [].concat(partialIps, timedOutIps, authFailedIps);
    _retryAllIncompleteIps = [].concat(_retryActiveIssuesIps, unreachableIps);

    // Update Breakdown Badges
    var badgePartial = document.getElementById('badgePartialCount');
    var badgeTimeout = document.getElementById('badgeTimeoutCount');
    var badgeAuth = document.getElementById('badgeAuthCount');
    var badgeUnreach = document.getElementById('badgeUnreachCount');

    if (badgePartial) {
      document.getElementById('cntPartial').textContent = partialIps.length;
      if (partialIps.length > 0) show(badgePartial); else hide(badgePartial);
    }
    if (badgeTimeout) {
      document.getElementById('cntTimeout').textContent = timedOutIps.length;
      if (timedOutIps.length > 0) show(badgeTimeout); else hide(badgeTimeout);
    }
    if (badgeAuth) {
      document.getElementById('cntAuth').textContent = authFailedIps.length;
      if (authFailedIps.length > 0) show(badgeAuth); else hide(badgeAuth);
    }
    if (badgeUnreach) {
      document.getElementById('cntUnreach').textContent = unreachableIps.length;
      if (unreachableIps.length > 0) show(badgeUnreach); else hide(badgeUnreach);
    }

    // Update Retry Buttons
    var retryGroup = document.getElementById('retryActionsGroup');
    var retryIssuesBtn = document.getElementById('retryIssuesBtn');
    var retryIssuesCount = document.getElementById('retryIssuesCount');
    var retryAllBtn = document.getElementById('retryAllBtn');
    var retryAllCount = document.getElementById('retryAllCount');

    if (retryGroup) {
      if (_retryAllIncompleteIps.length > 0) {
        show(retryGroup);

        if (_retryActiveIssuesIps.length > 0) {
          if (retryIssuesBtn && retryIssuesCount) {
            retryIssuesCount.textContent = _retryActiveIssuesIps.length;
            show(retryIssuesBtn);
          }
          if (retryAllBtn && retryAllCount && unreachableIps.length > 0) {
            retryAllCount.textContent = _retryAllIncompleteIps.length;
            show(retryAllBtn);
          } else if (retryAllBtn) {
            hide(retryAllBtn);
          }
        } else {
          // Only unreachable IPs exist
          if (retryIssuesBtn && retryIssuesCount) {
            retryIssuesCount.textContent = unreachableIps.length;
            show(retryIssuesBtn);
          }
          if (retryAllBtn) hide(retryAllBtn);
        }
      } else {
        hide(retryGroup);
      }
    }

    show(document.getElementById('openFolderBtn'));
    show(document.getElementById('exportXlsxBtn'));
    show(document.getElementById('exportObfXlsxBtn'));
    show(document.getElementById('exportObfZipBtn'));
    show(document.getElementById('exportCsvBtn'));
    show(document.getElementById('exportSummaryJsonBtn'));
    show(document.getElementById('prerenderReportsBtn'));
    show(document.getElementById('postScanActions'));
    var failBox = document.getElementById('summaryFailedList');
    if (failBox) {
      var seenFail = Object.create(null);
      var failLines = [];
      var failedForSummary = (typeof allFailedList !== 'undefined' && allFailedList) ? allFailedList : [];
      failedForSummary.forEach(function(f) {
        if (!f || !f.ip || seenFail[f.ip]) return;
        seenFail[f.ip] = true;
        var why = f.reason_label || f.detail || f.reason_code || 'Failed';
        failLines.push('<div><strong>' + esc(f.ip) + '</strong> — ' + esc(why) + '</div>');
      });
      if (!failLines.length) {
        failBox.innerHTML = '';
        hide(failBox);
      } else {
        var more = failLines.length > 8 ? '<div class="text-muted">and ' + (failLines.length - 8) + ' more below</div>' : '';
        failBox.innerHTML = '<strong>' + failLines.length + ' host(s) did not finish</strong>' + failLines.slice(0, 8).join('') + more;
        show(failBox);
      }
    }
    var summaryCard = document.getElementById('postScanSummaryCard');
    if (summaryCard && summaryCard.scrollIntoView) summaryCard.scrollIntoView({behavior: 'smooth', block: 'start'});
    saveSession();
    if (_eventSource) { _eventSource.close(); _eventSource = null; }
  }

  var _pollTimer = null;

  function pollScanStatus() {
    if (!_scanRunning) {
      if (_pollTimer) { clearInterval(_pollTimer); _pollTimer = null; }
      return;
    }
    get('/api/scan/status').then(function(s) {
      if (!s) return;
      if (s.disconnected_jump_scan && !s.running) {
        showJumpReconnectAlert(s.disconnected_jump_scan);
      } else if (s.running) {
        hideJumpReconnectAlert();
      }
      if (s.is_import) {
        _isImportScan = true;
      }
      if (s.is_rescan || s.is_retry) {
        _isRetryScan = true;
      }
      if (s.execution === 'remote' || s.is_remote) {
        _isRemoteScan = true;
      }
      if (s.completed !== undefined && s.total !== undefined && s.total > 0 && s.running) {
        updateProgress(s.completed, s.total, s.is_rescan || s.is_retry, s.is_import);
      }
      if (s.active_hosts && _scanRunning) {
        var serverActive = s.active_hosts;
        Object.keys(_activeHosts).forEach(function(ip) {
          if (!serverActive[ip]) {
            delete _activeHosts[ip];
          }
        });
        Object.keys(serverActive).forEach(function(ip) {
          var info = serverActive[ip];
          var startTime = (typeof info === 'object' && info.start_time) ? info.start_time : (typeof info === 'number' ? info : Date.now() / 1000);
          var isImp = (_isImportScan || (typeof info === 'object' && info.is_import));
          var defaultStage = isImp ? 'Rendering HTML Report…' : ((_isRetryScan || (typeof info === 'object' && info.is_rescan)) ? 'Rescanning…' : 'Scanning…');
          var stage = (typeof info === 'object' && info.stage) ? info.stage : defaultStage;
          if (!_activeHosts[ip]) {
            _activeHosts[ip] = { startTime: startTime, stage: stage, is_import: isImp, skipped: false };
          } else {
            _activeHosts[ip].stage = stage;
            _activeHosts[ip].is_import = isImp;
          }
        });
        renderActiveHosts();
      } else if (_scanRunning && s.active_hosts && Object.keys(s.active_hosts).length === 0 && Object.keys(_activeHosts).length > 0) {
        _activeHosts = Object.create(null);
        renderActiveHosts();
      }
      if (s.running === false && s.done === true && _scanRunning) {
        if (s.results && Array.isArray(s.results) && s.results.length > 0) {
          s.results.forEach(addResultRow);
        }
        if (s.failed_hosts && Array.isArray(s.failed_hosts)) {
          s.failed_hosts.forEach(addFailedHost);
        }
        onScanDone({
          n_ok: (s.n_ok !== undefined ? s.n_ok : (s.completed || 0)),
          n_total: s.total || 0,
          is_retry: s.is_retry,
          is_import: s.is_import,
          had_auto_retry: s.had_auto_retry,
          cancelled: s.error === 'Cancelled by user',
          summary_report: s.summary_path,
          obf_summary_report: s.obf_summary_path,
          fleet_report: s.fleet_path,
          obf_fleet_report: s.obf_fleet_path,
          scan_summary: s.scan_summary,
          vcf_readiness: s.vcf_readiness,
          failed_hosts: s.failed_hosts,
          partial_hosts: s.partial_hosts,
          results: s.results,
          outdir: s.outdir,
          zip_path: s.zip_path
        });
      }
    }).catch(function(){});
  }

  function startSSE(scanId) {
    if (_eventSource) _eventSource.close();
    if (_pollTimer) clearInterval(_pollTimer);
    _pollTimer = setInterval(pollScanStatus, 2500);
    _eventSource = new EventSource('/api/scan/events');

    _eventSource.addEventListener('status',     function(e) {
      try {
        var d = JSON.parse(e.data);
        if (d.disconnected_jump_scan && !d.running) {
          showJumpReconnectAlert(d.disconnected_jump_scan);
        } else if (d.running) {
          hideJumpReconnectAlert();
        }
        if (d.is_import) {
          _isImportScan = true;
        }
        if (d.is_rescan || d.is_retry) {
          _isRetryScan = true;
        }
        if (d.execution === 'remote' || d.is_remote) {
          _isRemoteScan = true;
        }
        if (d.active_hosts) {
          var serverActive = d.active_hosts;
          Object.keys(_activeHosts).forEach(function(ip) {
            if (!serverActive[ip]) {
              delete _activeHosts[ip];
            }
          });
          Object.keys(serverActive).forEach(function(ip) {
            var info = serverActive[ip];
            var startTime = (typeof info === 'object' && info.start_time) ? info.start_time : (typeof info === 'number' ? info : Date.now() / 1000);
            var isImp = (_isImportScan || (typeof info === 'object' && info.is_import));
            var defaultStage = isImp ? 'Rendering HTML Report…' : ((_isRetryScan || (typeof info === 'object' && info.is_rescan)) ? 'Rescanning…' : 'Scanning…');
            var stage = (typeof info === 'object' && info.stage) ? info.stage : defaultStage;
            if (!_activeHosts[ip]) {
              _activeHosts[ip] = { startTime: startTime, stage: stage, is_import: isImp, skipped: false };
            } else {
              _activeHosts[ip].stage = stage;
              _activeHosts[ip].is_import = isImp;
            }
          });
          renderActiveHosts();
        }
      } catch(ex) {}
    });
    _eventSource.addEventListener('log',       function(e) {
      try { appendLog(JSON.parse(e.data).msg); } catch(ex) {}
    });
    _eventSource.addEventListener('progress',  function(e) {
      try {
        var d = JSON.parse(e.data);
        var isImport = !!(d.is_import || (d.phase === 'import'));
        var isRescan = !!(d.is_rescan || d.is_retry || (d.phase === 'rescan'));
        if (isImport) _isImportScan = true;
        if (isRescan) _isRetryScan = true;
        updateProgress(d.completed, d.total, isRescan, isImport);
      } catch(ex) {}
    });
    _eventSource.addEventListener('host_start', function(e) {
      try {
        var d = JSON.parse(e.data);
        if (d.ip) {
          if (d.is_import) _isImportScan = true;
          if (d.is_rescan) _isRetryScan = true;
          var isImp = (_isImportScan || d.is_import);
          var defaultStage = isImp ? 'Rendering HTML Report…' : ((_isRetryScan || d.is_rescan) ? 'Connecting & Starting Rescan…' : 'Connecting & Starting Scan…');
          _activeHosts[d.ip] = { startTime: (d.start_time || Date.now() / 1000), stage: d.stage || defaultStage, is_import: isImp, skipped: false };
          renderActiveHosts();
        }
      } catch(ex) {}
    });
    _eventSource.addEventListener('host_stage', function(e) {
      try {
        var d = JSON.parse(e.data);
        if (d.ip) {
          if (d.is_import) _isImportScan = true;
          if (d.is_rescan) _isRetryScan = true;
          var isImp = (_isImportScan || d.is_import);
          var defaultStage = isImp ? 'Rendering…' : ((_isRetryScan || d.is_rescan) ? 'Rescanning…' : 'Scanning…');
          if (!_activeHosts[d.ip]) {
            _activeHosts[d.ip] = {
              startTime: Date.now() / 1000,
              stage: d.stage || defaultStage,
              is_import: isImp,
              skipped: false
            };
          } else {
            _activeHosts[d.ip].stage = d.stage || defaultStage;
            _activeHosts[d.ip].is_import = isImp;
          }
          renderActiveHosts();
        }
      } catch(ex) {}
    });
    _eventSource.addEventListener('host_done', function(e) {
      try {
        var d = JSON.parse(e.data);
        if (d.is_remote) {
          _isRemoteScan = true;
        }
        if (d.ip && _activeHosts[d.ip]) {
          delete _activeHosts[d.ip];
          renderActiveHosts();
        }
        if (!d.error && (d.report || d.filename || d.system)) {
          if (_failedHostsMap[d.ip]) {
            delete _failedHostsMap[d.ip];
            renderFailedHosts();
          }
          addResultRow(d);
        } else if (d.error) {
          addFailedHost(d);
        }
      } catch(ex) {}
    });
    _eventSource.addEventListener('jump_disconnected', function(e) {
      try {
        var d = JSON.parse(e.data);
        showJumpReconnectAlert(d);
      } catch(ex) {}
    });
    _eventSource.addEventListener('done',      function(e) {
      try { onScanDone(JSON.parse(e.data)); } catch(ex) {}
    });
    _eventSource.addEventListener('error',     function(e) {
      try {
        var d = JSON.parse(e.data);
        appendLog(d.msg || '[✗] Scan error');
        onScanDone({n_ok:0, n_total:_scanTotal, fleet_report:''});
      } catch(ex) {}
    });
    _eventSource.onerror = function() {
      if (!_scanRunning) { _eventSource.close(); }
    };
  }

  // ── TLS & Security UI toggles ──────────────────────────────────────────
  var ignoreTlsChk = document.getElementById('ignoreTlsChk');
  var tlsVerifyOptions = document.getElementById('tlsVerifyOptions');
  var tlsModeCustom = document.getElementById('tlsModeCustom');
  var tlsModeSystem = document.getElementById('tlsModeSystem');
  var tlsCustomBox = document.getElementById('tlsCustomBox');

  function syncTlsUi() {
    if (!ignoreTlsChk) return;
    toggle(tlsVerifyOptions, !ignoreTlsChk.checked);
    if (tlsCustomBox && tlsModeCustom) {
      toggle(tlsCustomBox, !ignoreTlsChk.checked && tlsModeCustom.checked);
    }
  }
  if (ignoreTlsChk) ignoreTlsChk.addEventListener('change', syncTlsUi);
  if (tlsModeCustom) tlsModeCustom.addEventListener('change', syncTlsUi);
  if (tlsModeSystem) tlsModeSystem.addEventListener('change', syncTlsUi);
  syncTlsUi();

  // ── Missing Password Warning Modal & Validation ──────────────────────────
  var _pendingScanProceed = null;

  function closeMissingPasswordModal() {
    var modal = document.getElementById('missingPasswordModal');
    if (modal) hide(modal);
    _pendingScanProceed = null;
  }

  function promptMissingPasswordWarning(missingHosts, onProceed) {
    if (!missingHosts || !missingHosts.length) {
      onProceed();
      return;
    }

    var modal = document.getElementById('missingPasswordModal');
    if (!modal) {
      var hostsStr = missingHosts.slice(0, 10).join(', ') + (missingHosts.length > 10 ? ' … and ' + (missingHosts.length - 10) + ' more' : '');
      var proceed = confirm(
        'No BMC password entered and Credential Vault is not active for ' + missingHosts.length + ' host(s):\\n\\n'
        + '  • ' + hostsStr + '\\n\\n'
        + 'Most enterprise BMCs require a password. Requests will likely fail with 401 Unauthorized errors.\\n\\n'
        + 'Click OK to continue anyway, or Cancel to enter credentials.'
      );
      if (proceed) {
        onProceed();
      } else {
        navigateToPasswordAnchor();
      }
      return;
    }

    _pendingScanProceed = onProceed;

    var textEl = document.getElementById('missingPasswordText');
    if (textEl) {
      textEl.textContent = 'Targeting ' + missingHosts.length + ' host(s) without credentials. '
        + 'Most enterprise BMCs (iDRAC, iLO, XCC, Supermicro) require authentication. '
        + 'The assessment will likely fail with 401 Unauthorized errors and consecutive timeouts.';
    }

    var hostsWrap = document.getElementById('missingPasswordHostsWrap');
    var hostsList = document.getElementById('missingPasswordHostsList');
    if (hostsWrap && hostsList) {
      var sample = missingHosts.slice(0, 10);
      var extra = missingHosts.length - sample.length;
      hostsList.innerHTML = sample.map(function(ip) {
        return '<div class="missing-pwd-host-item"><span class="missing-pwd-host-bullet">•</span> <span class="missing-pwd-host-ip">' + esc(ip) + '</span></div>';
      }).join('')
        + (extra > 0 ? '<div class="text-muted" style="margin-top:0.35rem;font-style:italic;">… and ' + extra + ' more host(s)</div>' : '');
      show(hostsWrap);
    }

    var vaultBtn = document.getElementById('unlockVaultModalBtn');
    if (vaultBtn) {
      var vs = (typeof _vaultState !== 'undefined') ? _vaultState : null;
      if (vs && vs.exists && !vs.unlocked) {
        vaultBtn.textContent = '🔓 Unlock Credential Vault';
        show(vaultBtn);
      } else if (vs && !vs.exists) {
        vaultBtn.textContent = '🔐 Create Credential Vault';
        show(vaultBtn);
      } else {
        hide(vaultBtn);
      }
    }

    show(modal);
  }

  function navigateToPasswordAnchor() {
    closeMissingPasswordModal();
    var sameChk = document.getElementById('sameCredsChk');
    var isShared = !sameChk || sameChk.checked;
    if (isShared) {
      var pwInput = document.getElementById('passwordInput');
      if (pwInput) highlightAnchor(pwInput);
    } else {
      var perHostInputs = document.querySelectorAll('#perHostRows input[data-field="pass"]');
      var targetInput = null;
      for (var i = 0; i < perHostInputs.length; i++) {
        if (!perHostInputs[i].value || !perHostInputs[i].value.trim()) {
          targetInput = perHostInputs[i];
          break;
        }
      }
      if (!targetInput && perHostInputs.length > 0) targetInput = perHostInputs[0];
      if (targetInput) {
        highlightAnchor(targetInput);
      } else {
        var pwInput = document.getElementById('passwordInput');
        if (pwInput) highlightAnchor(pwInput);
      }
    }
  }

  var closeMissingPasswordModalBtn = document.getElementById('closeMissingPasswordModalBtn');
  if (closeMissingPasswordModalBtn) {
    closeMissingPasswordModalBtn.addEventListener('click', closeMissingPasswordModal);
  }
  var enterPasswordModalBtn = document.getElementById('enterPasswordModalBtn');
  if (enterPasswordModalBtn) {
    enterPasswordModalBtn.addEventListener('click', navigateToPasswordAnchor);
  }
  var unlockVaultModalBtn = document.getElementById('unlockVaultModalBtn');
  if (unlockVaultModalBtn) {
    unlockVaultModalBtn.addEventListener('click', function() {
      closeMissingPasswordModal();
      openAndHighlightVault();
    });
  }
  var continueWithoutPasswordBtn = document.getElementById('continueWithoutPasswordBtn');
  if (continueWithoutPasswordBtn) {
    continueWithoutPasswordBtn.addEventListener('click', function() {
      var fn = _pendingScanProceed;
      closeMissingPasswordModal();
      if (typeof fn === 'function') fn();
    });
  }
  var missingPasswordModalEl = document.getElementById('missingPasswordModal');
  if (missingPasswordModalEl) {
    missingPasswordModalEl.addEventListener('click', function(e) {
      if (e.target === missingPasswordModalEl) closeMissingPasswordModal();
    });
  }

  // ── Cert pin gate before scan ────────────────────────────────────────────
  var _pendingCertPinProceed = null;
  var _certPinFetchGen = 0;
  var _certPinCheckedHosts = [];
  var _certPinRangeText = '';
  var _certPinOverrideTargets = null;
  var _certPinStartNote = '';

  function tlsVerificationAlreadyOn() {
    var ignoreEl = document.getElementById('ignoreTlsChk');
    return !!(ignoreEl && !ignoreEl.checked);
  }

  function certPinTargetTokens(raw) {
    return String(raw || '').split(/[\\s,]+/).filter(Boolean);
  }

  function certPinLooksLikeSingleIp(token) {
    return /^\\d{1,3}(\\.\\d{1,3}){3}$/.test(token);
  }

  function discreteTargetHosts(checkedHosts, rangeText) {
    if (checkedHosts && checkedHosts.length) return checkedHosts.slice();
    var tokens = certPinTargetTokens(rangeText);
    if (tokens.length && tokens.every(certPinLooksLikeSingleIp)) return tokens;
    return null;
  }

  function certPinAlreadySatisfied(checkedHosts, rangeText) {
    if (tlsVerificationAlreadyOn()) return true;
    var discrete = discreteTargetHosts(checkedHosts, rangeText);
    if (!discrete) return false;
    for (var i = 0; i < discrete.length; i++) {
      if (!_pinnedThumbprints[discrete[i]]) return false;
    }
    return true;
  }

  function closeCertPinModal() {
    _certPinFetchGen++;
    var modal = document.getElementById('certPinModal');
    if (modal) hide(modal);
    _pendingCertPinProceed = null;
  }

  function setCertPinStatus(msg) {
    var el = document.getElementById('certPinStatus');
    if (!el) return;
    if (!msg) {
      el.textContent = '';
      hide(el);
      return;
    }
    el.textContent = msg;
    show(el);
  }

  function certsFromHosts(hosts, limitTo) {
    var want = null;
    if (limitTo && limitTo.length) {
      want = {};
      limitTo.forEach(function(ip) { want[ip] = true; });
    }
    var list = [];
    (hosts || []).forEach(function(h) {
      if (!h) return;
      var ip = h.ip || h.host || '';
      if (!ip) return;
      if (want && !want[ip]) return;
      if (_pinnedThumbprints[ip]) return;
      var info = h.cert_info || h;
      var thumb = info.sha256 || info.sha256_raw || '';
      if (!thumb) return;
      list.push({
        ip: ip,
        sha256: thumb,
        subject_cn: info.subject_cn || info.subject || '',
        is_self_signed: !!info.is_self_signed
      });
    });
    return list;
  }

  function pinCoverage() {
    var discrete = discreteTargetHosts(_certPinCheckedHosts, _certPinRangeText);
    var rows = {};
    document.querySelectorAll('#certPinList .cert-pin-chk').forEach(function(chk) {
      rows[chk.getAttribute('data-ip')] = !!chk.checked;
    });
    if (!discrete) {
      var anyChecked = false;
      Object.keys(rows).forEach(function(ip) { if (rows[ip]) anyChecked = true; });
      return {kind: 'range', absent: [], unchecked: [], anyChecked: anyChecked, rowCount: Object.keys(rows).length};
    }
    var absent = [];
    var unchecked = [];
    discrete.forEach(function(ip) {
      if (_pinnedThumbprints[ip]) return;
      if (!Object.prototype.hasOwnProperty.call(rows, ip)) absent.push(ip);
      else if (!rows[ip]) unchecked.push(ip);
    });
    return {kind: 'discrete', absent: absent, unchecked: unchecked, anyChecked: unchecked.length === 0, rowCount: Object.keys(rows).length};
  }

  function refreshPinButton() {
    var pinBtn = document.getElementById('pinCertsAndScanBtn');
    if (!pinBtn) return;
    var cov = pinCoverage();
    pinBtn.disabled = false;
    if (!cov.rowCount || cov.absent.length) {
      pinBtn.textContent = cov.rowCount ? 'Fetch missing certificates' : 'Fetch and pin certificates';
      pinBtn.dataset.mode = 'fetch';
      return;
    }
    pinBtn.textContent = 'Pin selected and scan';
    pinBtn.dataset.mode = 'pin';
  }

  function renderCertPinList(certs, errorMsg) {
    var listEl = document.getElementById('certPinList');
    var emptyEl = document.getElementById('certPinEmpty');
    if (!listEl) return;
    if (errorMsg) {
      if (emptyEl) {
        emptyEl.textContent = errorMsg;
        show(emptyEl);
      }
    } else if (emptyEl) {
      hide(emptyEl);
    }
    if (!certs || !certs.length) {
      listEl.innerHTML = '';
      hide(listEl);
    } else {
      listEl.innerHTML = certs.map(function(c) {
        var badge = c.is_self_signed ? 'Self-signed' : 'CA-issued';
        var meta = badge + (c.subject_cn ? ' · ' + c.subject_cn : '');
        return '<label class="cert-pin-row">'
          + '<input type="checkbox" class="cert-pin-chk" data-ip="' + esc(c.ip) + '" data-thumb="' + esc(c.sha256) + '" checked>'
          + '<span class="cert-pin-ip">' + esc(c.ip) + '</span>'
          + '<span class="cert-pin-meta">' + esc(meta) + '</span>'
          + '<code class="vcf-thumbprint-code">' + esc(c.sha256) + '</code>'
          + '</label>';
      }).join('');
      show(listEl);
    }
    refreshPinButton();
  }

  function applySelectedPins() {
    var count = 0;
    document.querySelectorAll('#certPinList .cert-pin-chk:checked').forEach(function(chk) {
      var ip = chk.getAttribute('data-ip');
      var thumb = chk.getAttribute('data-thumb');
      if (ip && thumb) {
        _pinnedThumbprints[ip] = thumb;
        count++;
      }
    });
    if (count) {
      if (typeof saveSession === 'function') saveSession();
      if (typeof updatePinnedCertUi === 'function') updatePinnedCertUi();
    }
    return count;
  }

  function hostsWithCerts(hosts) {
    var list = [];
    (hosts || []).forEach(function(h) {
      if (!h) return;
      var ip = h.ip || h.host || '';
      var info = h.cert_info || h;
      var thumb = info.sha256 || info.sha256_raw || '';
      if (ip && thumb) list.push(ip);
    });
    return list;
  }

  function proceedIfAlreadyPinned(hosts) {
    var withCerts = hostsWithCerts(hosts);
    if (!withCerts.length) return false;
    for (var i = 0; i < withCerts.length; i++) {
      if (!_pinnedThumbprints[withCerts[i]]) return false;
    }
    var discrete = discreteTargetHosts(_certPinCheckedHosts, _certPinRangeText);
    if (discrete) {
      for (var j = 0; j < discrete.length; j++) {
        if (!_pinnedThumbprints[discrete[j]]) return false;
      }
      finishCertPinChoice('[🔒] Certificates already pinned.');
      return true;
    }
    _certPinOverrideTargets = withCerts.join(',');
    finishCertPinChoice('[🔒] Certificates already pinned. Scanning those hosts only.');
    return true;
  }

  function finishCertPinChoice(note) {
    _certPinStartNote = note || '';
    var fn = _pendingCertPinProceed;
    closeCertPinModal();
    if (typeof fn === 'function') fn();
  }

  function promptCertPinBeforeScan(checkedHosts, rangeText, onProceed) {
    if (certPinAlreadySatisfied(checkedHosts, rangeText)) {
      onProceed();
      return;
    }
    var modal = document.getElementById('certPinModal');
    if (!modal) {
      var proceed = confirm('BMC TLS checks are off. The BMC password can be read on the path to these hosts. OK scans without certificate checks. Cancel stops.');
      if (proceed) onProceed();
      return;
    }
    _pendingCertPinProceed = onProceed;
    _certPinCheckedHosts = (checkedHosts || []).slice();
    _certPinRangeText = rangeText || '';
    _certPinOverrideTargets = null;

    var limit = _certPinCheckedHosts.length ? _certPinCheckedHosts : discreteTargetHosts(null, rangeText);
    var known = certsFromHosts(_discoveredHosts || [], limit);
    var textEl = document.getElementById('certPinText');
    var discrete = discreteTargetHosts(_certPinCheckedHosts, _certPinRangeText);
    if (textEl) {
      textEl.textContent = known.length
        ? 'These BMCs already presented certificates. Pin them and the scan checks later connections against that thumbprint. Self-signed iDRAC, iLO, and XCC certificates work this way.'
        : 'Fetch the certificate each BMC presents, then pin it. Self-signed iDRAC, iLO, and XCC certificates work this way without a CA bundle.';
    }
    if (discrete) {
      setCertPinStatus('Every listed host has to be pinned before the scan starts. Scan without certificate checks is the other choice.');
    } else {
      setCertPinStatus('Pin and scan contacts only the hosts listed here. Scan without certificate checks contacts the original range with verification off.');
    }
    if (!known.length && typeof _probedTargetRaw !== 'undefined' && _probedTargetRaw === _certPinRangeText) {
      if (proceedIfAlreadyPinned(_discoveredHosts || [])) return;
    }
    renderCertPinList(known, '');
    if (discrete) {
      var cov = pinCoverage();
      if (cov.absent.length && known.length) {
        setCertPinStatus('No certificate yet for ' + cov.absent.slice(0, 6).join(', ') + (cov.absent.length > 6 ? '…' : '') + '. Fetch the missing ones, or scan without certificate checks.');
      }
    }
    show(modal);
  }

  function fetchCertsForPin() {
    var raw = (_certPinCheckedHosts && _certPinCheckedHosts.length)
      ? _certPinCheckedHosts.join(',')
      : (document.getElementById('rangeInput').value.trim() || _certPinRangeText);
    if (!raw) {
      alert('Enter a target range first.');
      return;
    }
    var pinBtn = document.getElementById('pinCertsAndScanBtn');
    if (pinBtn) {
      pinBtn.disabled = true;
      pinBtn.textContent = 'Contacting BMCs…';
    }
    var gen = ++_certPinFetchGen;
    post('/api/discover', {targets: raw}).then(function(r) {
      if (gen !== _certPinFetchGen || !_pendingCertPinProceed) return;
      if (r.error) {
        renderCertPinList([], r.error);
        return;
      }
      if (Array.isArray(r.hosts)) {
        _discoveredHosts = r.hosts;
        var rangeEl = document.getElementById('rangeInput');
        if (rangeEl && rangeEl.value.trim()) _probedTargetRaw = rangeEl.value.trim();
      }
      if (proceedIfAlreadyPinned(r.hosts || [])) return;
      var limit = _certPinCheckedHosts.length ? _certPinCheckedHosts : null;
      var certs = certsFromHosts(r.hosts || [], limit);
      var note = certs.length ? '' : 'No HTTPS certificate came back. The hosts may be down, or they answered on HTTP only.';
      renderCertPinList(certs, note);
      var cov = pinCoverage();
      if (cov.kind === 'discrete' && cov.absent.length) {
        setCertPinStatus('No certificate for ' + cov.absent.length + ' host(s): ' + cov.absent.slice(0, 6).join(', ') + (cov.absent.length > 6 ? '…' : '') + '. Fetch again, or scan without certificate checks.');
      }
    }).catch(function(err) {
      if (gen !== _certPinFetchGen || !_pendingCertPinProceed) return;
      var msg = (err && err.message) ? err.message : String(err);
      renderCertPinList([], 'Could not fetch certificates: ' + msg);
    });
  }

  function onPinCertsAndScan() {
    var pinBtn = document.getElementById('pinCertsAndScanBtn');
    if (!pinBtn || pinBtn.dataset.mode !== 'pin') {
      fetchCertsForPin();
      return;
    }
    var cov = pinCoverage();
    if (cov.kind === 'discrete' && (cov.absent.length || cov.unchecked.length)) {
      if (cov.unchecked.length) {
        setCertPinStatus('Select every listed certificate, or choose Scan without certificate checks.');
      }
      refreshPinButton();
      return;
    }
    if (cov.kind === 'range' && !cov.anyChecked) {
      setCertPinStatus('Select at least one certificate, or choose Scan without certificate checks.');
      return;
    }
    var count = applySelectedPins();
    if (!count) {
      setCertPinStatus('Select at least one certificate, or choose Scan without certificate checks.');
      return;
    }
    if (cov.kind === 'range') {
      var ips = [];
      document.querySelectorAll('#certPinList .cert-pin-chk:checked').forEach(function(chk) {
        var ip = chk.getAttribute('data-ip');
        if (ip) ips.push(ip);
      });
      _certPinOverrideTargets = ips.join(',');
      finishCertPinChoice('[🔒] Pinned ' + count + ' certificate(s). Scanning those hosts only.');
      return;
    }
    finishCertPinChoice('[🔒] Pinned ' + count + ' certificate(s).');
  }

  function onScanWithoutCertChecks() {
    var count = applySelectedPins();
    var note = '[!] Certificate checks are off for this scan. The BMC password is exposed to network interception.';
    if (count) note = '[🔒] Pinned ' + count + ' certificate(s). ' + note;
    _certPinOverrideTargets = null;
    finishCertPinChoice(note);
  }

  var closeCertPinModalBtn = document.getElementById('closeCertPinModalBtn');
  if (closeCertPinModalBtn) closeCertPinModalBtn.addEventListener('click', closeCertPinModal);
  var certPinModalEl = document.getElementById('certPinModal');
  if (certPinModalEl) {
    certPinModalEl.addEventListener('click', function(e) {
      if (e.target === certPinModalEl) closeCertPinModal();
    });
  }
  var pinCertsAndScanBtn = document.getElementById('pinCertsAndScanBtn');
  if (pinCertsAndScanBtn) pinCertsAndScanBtn.addEventListener('click', onPinCertsAndScan);
  var scanWithoutCertChecksBtn = document.getElementById('scanWithoutCertChecksBtn');
  if (scanWithoutCertChecksBtn) scanWithoutCertChecksBtn.addEventListener('click', onScanWithoutCertChecks);
  var certPinListEl = document.getElementById('certPinList');
  if (certPinListEl) {
    certPinListEl.addEventListener('change', function(e) {
      if (e.target && e.target.classList && e.target.classList.contains('cert-pin-chk')) refreshPinButton();
    });
  }

  // ── Active Scan Conflict Modal (Jump Host) ────────────────────────────────
  var _activeScanConflictScans = [];
  var _activeScanRestartFn = null;

  function closeActiveScanConflictModal() {
    var modal = document.getElementById('activeScanConflictModal');
    if (modal) hide(modal);
  }

  function resetRunBtnToIdle() {
    var runBtn = document.getElementById('runBtn');
    if (runBtn) {
      runBtn.disabled = false;
      runBtn.textContent = '▶  Run Assessment';
    }
    hide(document.getElementById('scanSpinner'));
    hide(document.getElementById('cancelBtn'));
    hide(document.getElementById('progressSection'));
    _scanRunning = false;
  }

  function promptActiveScanConflict(activeScans, onRestart) {
    _activeScanConflictScans = activeScans || [];
    _activeScanRestartFn = onRestart;

    var modal = document.getElementById('activeScanConflictModal');
    if (!modal) {
      var proceed = confirm(
        'An active assessment is currently running on the jump host.\\n\\n'
        + 'Click OK to terminate the existing scan and start the new one, or Cancel to abort.'
      );
      if (proceed && typeof onRestart === 'function') {
        post('/api/scan/kill_active', { remote_dir: 'all' }).then(function() {
          onRestart();
        }).catch(function() {
          onRestart();
        });
      } else {
        resetRunBtnToIdle();
      }
      return;
    }

    var contentEl = document.getElementById('activeScanDetailsContent');
    if (contentEl) {
      var lines = [];
      _activeScanConflictScans.forEach(function(s, idx) {
        lines.push('Jump Host: ' + (s.jump_host_id || s.host || 'unknown'));
        lines.push('  PID: ' + (s.pid || 'unknown') + ' | Directory: ' + (s.sandbox || s.sandbox_path || 'unknown'));
        if (s.start_time) {
          var elapsed = Math.max(0, Math.floor(Date.now() / 1000 - s.start_time));
          var mins = Math.floor(elapsed / 60);
          var secs = elapsed % 60;
          lines.push('  Runtime: ' + mins + 'm ' + secs + 's' + (s.run_id ? ' (Run ID: ' + s.run_id.slice(0, 8) + ')' : ''));
        }
        if (s.completed_count !== undefined && s.total_hosts) {
          lines.push('  Progress: ' + s.completed_count + ' / ' + s.total_hosts + ' hosts completed');
        } else if (s.target_count) {
          lines.push('  Targets: ' + s.target_count + ' host(s)');
        }
        if (s.latest_message) {
          lines.push('  Last status: ' + s.latest_message);
        }
        if (idx < _activeScanConflictScans.length - 1) lines.push('---');
      });
      contentEl.textContent = lines.join('\\n');
    }

    var killBtn = document.getElementById('killAndRestartScanBtn');
    if (killBtn) {
      killBtn.disabled = false;
      killBtn.textContent = 'Terminate & Restart';
    }
    var resumeBtn = document.getElementById('resumeActiveScanBtn');
    if (resumeBtn) {
      resumeBtn.disabled = false;
      resumeBtn.textContent = '⚡ Reattach & Stream';
    }

    show(modal);
  }

  var closeActiveScanConflictModalBtn = document.getElementById('closeActiveScanConflictModalBtn');
  if (closeActiveScanConflictModalBtn) {
    closeActiveScanConflictModalBtn.addEventListener('click', function() {
      closeActiveScanConflictModal();
      resetRunBtnToIdle();
    });
  }

  var abortActiveScanBtn = document.getElementById('abortActiveScanBtn');
  if (abortActiveScanBtn) {
    abortActiveScanBtn.addEventListener('click', function() {
      closeActiveScanConflictModal();
      resetRunBtnToIdle();
    });
  }

  var killAndRestartScanBtn = document.getElementById('killAndRestartScanBtn');
  if (killAndRestartScanBtn) {
    killAndRestartScanBtn.addEventListener('click', function() {
      killAndRestartScanBtn.disabled = true;
      killAndRestartScanBtn.textContent = 'Terminating…';
      var scan = _activeScanConflictScans[0] || {};
      post('/api/scan/kill_active', {
        jump_host_id: scan.jump_host_id || '',
        remote_dir: scan.sandbox || scan.sandbox_path || 'all'
      }).then(function() {
        closeActiveScanConflictModal();
        var fn = _activeScanRestartFn;
        if (typeof fn === 'function') {
          var runBtn = document.getElementById('runBtn');
          if (runBtn) runBtn.textContent = '⏳ Scanning…';
          fn();
        }
      }).catch(function(err) {
        alert('Failed to terminate remote scan: ' + (err.message || err));
        killAndRestartScanBtn.disabled = false;
        killAndRestartScanBtn.textContent = 'Terminate & Restart';
      });
    });
  }

  var resumeActiveScanBtn = document.getElementById('resumeActiveScanBtn');
  if (resumeActiveScanBtn) {
    resumeActiveScanBtn.addEventListener('click', function() {
      resumeActiveScanBtn.disabled = true;
      resumeActiveScanBtn.textContent = 'Reattaching…';
      var scan = _activeScanConflictScans[0] || {};
      var outdirVal = (document.getElementById('outdirInput') ? document.getElementById('outdirInput').value.trim() : '') || (typeof _lastScanOutdir !== 'undefined' ? _lastScanOutdir : '') || '';
      post('/api/scan/reconnect', {
        jump_host_id: scan.jump_host_id || '',
        remote_dir: scan.sandbox || scan.sandbox_path || '',
        host: scan.host || '',
        run_id: scan.run_id || '',
        outdir: outdirVal
      }).then(function(r) {
        closeActiveScanConflictModal();
        if (r.error) {
          alert('Failed to reattach: ' + r.error);
          resetRunBtnToIdle();
        } else {
          hideJumpReconnectAlert();
          _scanRunning = true;
          _isRemoteScan = true;
          show(document.getElementById('progressSection'));
          show(document.getElementById('scanSpinner'));
          show(document.getElementById('cancelBtn'));
          var runBtn = document.getElementById('runBtn');
          if (runBtn) {
            runBtn.disabled = true;
            runBtn.textContent = '⏳ Reconnecting…';
          }
          var pLabel = document.getElementById('progressLabel');
          if (pLabel) pLabel.textContent = 'Streaming from jump host…';
          startSSE(r.scan_id);
        }
      }).catch(function(err) {
        alert('Reconnect error: ' + (err.message || err));
        resumeActiveScanBtn.disabled = false;
        resumeActiveScanBtn.textContent = '⚡ Reattach & Stream';
      });
    });
  }

  var activeScanConflictModalEl = document.getElementById('activeScanConflictModal');
  if (activeScanConflictModalEl) {
    activeScanConflictModalEl.addEventListener('click', function(e) {
      if (e.target === activeScanConflictModalEl) {
        closeActiveScanConflictModal();
        resetRunBtnToIdle();
      }
    });
  }

  // ── Run assessment ────────────────────────────────────────────────────────
  document.getElementById('runBtn').addEventListener('click', function() {
    var targets = document.getElementById('rangeInput').value.trim();
    // If hosts were discovered and some are checked, use those; else use the range text
    var checkedBoxes = Array.from(document.querySelectorAll('.host-chk:checked'));
    var checkedHosts = checkedBoxes.map(function(c){ return c.dataset.ip; });

    // Guard against stale probed hosts shadowing a changed rangeInput
    if (targets && checkedHosts.length > 0) {
      var isMismatched = false;
      if (typeof _probedTargetRaw !== 'undefined' && _probedTargetRaw) {
        if (targets !== _probedTargetRaw) {
          isMismatched = true;
        }
      } else {
        var targetTokens = targets.split(/[\\s,]+/).filter(Boolean);
        var hasOverlap = checkedHosts.some(function(ip) { return targetTokens.indexOf(ip) !== -1; });
        if (!hasOverlap) {
          isMismatched = true;
        }
      }
      if (isMismatched) {
        checkedBoxes.forEach(function(c) { c.checked = false; });
        checkedHosts = [];
        var hostListEl = document.getElementById('hostList');
        if (hostListEl) {
          hide(hostListEl);
          hostListEl.innerHTML = '';
        }
        var perHostEl = document.getElementById('perHostRows');
        if (perHostEl) perHostEl.innerHTML = '';
        var discStatusEl = document.getElementById('discStatus');
        if (discStatusEl) discStatusEl.textContent = '';
        if (typeof resetCertTrustBanner === 'function') {
          resetCertTrustBanner(0);
        }
        var certBannerEl = document.getElementById('certTrustBanner');
        if (certBannerEl) hide(certBannerEl);
      }
    }

    if (!targets && !checkedHosts.length) {
      alert('Enter a target range or run Probe Hosts first.');
      return;
    }

    var finalTargets = checkedHosts.length ? checkedHosts.join(',') : targets;
    var user = document.getElementById('usernameInput').value || 'root';
    var pass = document.getElementById('passwordInput').value;
    var useVaultChkEl = document.getElementById('useVaultChk');
    var useVaultOn = !!(useVaultChkEl && useVaultChkEl.checked && !useVaultChkEl.disabled);

    var execRemoteEl = document.getElementById('execRemote');
    var isRemoteExec = !!(execRemoteEl && execRemoteEl.checked);
    if (isRemoteExec) {
      if (typeof _vaultState !== 'undefined' && !_vaultState.unlocked) {
        alert('Remote jump host execution requires an unlocked credential vault with at least one jump host profile.\\n\\nPlease unlock or create a vault in the Credential Vault panel below before running.');
        openAndHighlightVault('vaultUnlockPass');
        return;
      }
      var jSelect = document.getElementById('jumpHostSelect');
      if (jSelect && jSelect.options.length <= 1 && (!jSelect.value || jSelect.value === 'auto')) {
        alert('No jump hosts are configured in your credential vault.\\n\\nPlease add a jump host profile under "Jump Hosts (Remote Execution)" in the Credential Vault panel below.');
        openAndHighlightVault('jumpId');
        return;
      }
    }

    var creds = null;
    if (!useVaultOn && !sameChk.checked) {
      var credsMap = {};
      document.querySelectorAll('[data-ip][data-field]').forEach(function(inp) {
        var ip = inp.dataset.ip;
        if (!credsMap[ip]) credsMap[ip] = {ip: ip, user: user, pass: pass};
        credsMap[ip][inp.dataset.field] = inp.value;
      });
      creds = Object.values(credsMap);
    }

    var missingHosts = [];
    if (!useVaultOn) {
      if (sameChk.checked) {
        if (!pass || !pass.trim()) {
          missingHosts = checkedHosts.length ? checkedHosts : targets.split(/[\\s,]+/).filter(Boolean);
        }
      } else {
        var hostList = checkedHosts.length ? checkedHosts : targets.split(/[\\s,]+/).filter(Boolean);
        var credsLookup = {};
        if (creds) {
          creds.forEach(function(c) { if (c.ip) credsLookup[c.ip] = c.pass; });
        }
        hostList.forEach(function(h) {
          var p = (h in credsLookup) ? credsLookup[h] : pass;
          if (!p || !p.trim()) missingHosts.push(h);
        });
      }
    }

    promptMissingPasswordWarning(missingHosts, function() {
      promptCertPinBeforeScan(checkedHosts, targets, function() {
      if (_certPinOverrideTargets) {
        finalTargets = _certPinOverrideTargets;
        _certPinOverrideTargets = null;
      }
      var certPinNote = _certPinStartNote;
      _certPinStartNote = '';
      var dellCreds = null;
      if (document.getElementById('dellEnabledChk').checked) {
        var did = document.getElementById('dellIdInput').value.trim();
        var dsec = document.getElementById('dellSecretInput').value.trim();
        if (did && dsec) dellCreds = {id:did, secret:dsec};
      }

      document.getElementById('logBox').innerHTML = '';
      if (certPinNote) appendLog(certPinNote);
      document.getElementById('resultsBody').innerHTML = '';
      var resultsFilter = document.getElementById('resultsFilterInput');
      if (resultsFilter) resultsFilter.value = '';
      if (typeof _fleetFilterText !== 'undefined') _fleetFilterText = '';
      if (typeof _fleetPageIndex !== 'undefined') _fleetPageIndex = 0;
      _failedHostsMap = Object.create(null);
      renderFailedHosts();
      _activeHosts = Object.create(null);
      renderActiveHosts();
      hide(document.getElementById('resultsSection'));
      hide(document.getElementById('openSummaryBtn'));
      hide(document.getElementById('openObfSummaryBtn'));
      hide(document.getElementById('openReportBtn'));
      hide(document.getElementById('openObfReportBtn'));
      hide(document.getElementById('openFolderBtn'));
      hide(document.getElementById('exportXlsxBtn'));
      hide(document.getElementById('exportObfXlsxBtn'));
      hide(document.getElementById('exportObfZipBtn'));
      hide(document.getElementById('exportCsvBtn'));
      hide(document.getElementById('exportSummaryJsonBtn'));
      hide(document.getElementById('prerenderReportsBtn'));
      hide(document.getElementById('retryActionsGroup'));
      hide(document.getElementById('retryBanner'));
      hide(document.getElementById('postScanActions'));
      show(document.getElementById('progressSection'));
      _isRetryScan = false;
      updateProgress(0, 0);

      document.getElementById('progressLabel').textContent = 'Scanning…';
      show(document.getElementById('scanSpinner'));
      show(document.getElementById('cancelBtn'));
      document.getElementById('runBtn').disabled = true;
      document.getElementById('runBtn').textContent = '⏳ Scanning…';

      var extMins = parseInt(document.getElementById('timeoutMinutesInput').value, 10) || 10;
      extMins = Math.min(45, Math.max(1, extMins));
      var hostTimeoutSec = document.getElementById('extendTimeoutChk').checked ? (extMins * 60) : 300;

      var ignoreTls = document.getElementById('ignoreTlsChk') ? document.getElementById('ignoreTlsChk').checked : true;
      var verifySsl = !ignoreTls;
      var tlsMode = (document.querySelector('input[name=tlsMode]:checked') || {}).value || 'system';
      var caBundle = (verifySsl && tlsMode === 'custom') ? (document.getElementById('caBundleInput').value.trim() || null) : null;
      var dnsLookup = document.getElementById('dnsLookupChk') ? document.getElementById('dnsLookupChk').checked : false;
      var restrictPrivate = document.getElementById('restrictPrivateChk') ? document.getElementById('restrictPrivateChk').checked : false;

      var chosenProfile = (document.querySelector('input[name=scanProfile]:checked') || {}).value || 'readiness-full';
      var isQuick = chosenProfile === 'inventory-lite';
      var isLean = chosenProfile === 'readiness-lean' || chosenProfile === 'inventory-lite';

      var body = {
        targets:       finalTargets,
        username:      user,
        password:      pass,
        creds:         useVaultOn ? [] : (creds || []),
        use_vault:     useVaultOn,
        threads:       parseInt(document.getElementById('threadsInput').value)||12,
        output_dir:    document.getElementById('outdirInput').value.trim(),
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
        allow_partial: document.getElementById('allowPartialChk').checked,
        auto_retry:    document.getElementById('autoRetryChk') ? document.getElementById('autoRetryChk').checked : true,
        host_timeout:  hostTimeoutSec,
        dell_creds:    dellCreds,
        is_retry:      false,
        append_outdir: '',
        verify_ssl:    verifySsl,
        ca_bundle:     caBundle,
        dns_lookup:    dnsLookup,
        restrict_private_targets: restrictPrivate,
        pinned_thumbprints: _pinnedThumbprints,
        enable_dash:   document.getElementById('enableDashChk') ? document.getElementById('enableDashChk').checked : false,
        execution:     (document.getElementById('execRemote') && document.getElementById('execRemote').checked) ? 'remote' : 'local',
        jump_host:     (document.getElementById('jumpHostSelect') && document.getElementById('jumpHostSelect').value) || 'auto',
      };

      function startScanRequest() {
        hideJumpReconnectAlert();
        _scanRunning = true;
        _isRemoteScan = (body.execution === 'remote');
        post('/api/scan', body).then(function(r) {
          if (r.error) {
            alert('Error: ' + r.error);
            document.getElementById('runBtn').disabled = false;
            document.getElementById('runBtn').textContent = '▶  Run Assessment';
            hide(document.getElementById('scanSpinner'));
            hide(document.getElementById('cancelBtn'));
            _scanRunning = false;
            _isRemoteScan = false;
            return;
          }
          updateProgress(0, r.total);
          startSSE(r.scan_id);
        }).catch(function(e) {
          var msg = (e && e.message) ? e.message : String(e);
          alert('Scan request failed: ' + msg);
          document.getElementById('runBtn').disabled = false;
          document.getElementById('runBtn').textContent = '▶  Run Assessment';
          hide(document.getElementById('scanSpinner'));
          hide(document.getElementById('cancelBtn'));
          _scanRunning = false;
          _isRemoteScan = false;
        });
      }

      if (body.execution === 'remote') {
        document.getElementById('runBtn').textContent = '⏳ Checking jump host…';
        post('/api/scan/preflight', {
          execution: 'remote',
          jump_host: body.jump_host,
          targets: body.targets
        }).then(function(pf) {
          if (pf && pf.has_active_scan && pf.active_scans && pf.active_scans.length > 0) {
            promptActiveScanConflict(pf.active_scans, startScanRequest);
          } else {
            document.getElementById('runBtn').textContent = '⏳ Scanning…';
            startScanRequest();
          }
        }).catch(function() {
          startScanRequest();
        });
      } else {
        startScanRequest();
      }
      });
      // cert-pin gate
    });
  });

  document.getElementById('cancelBtn').addEventListener('click', function() {
    this.disabled = true;
    this.textContent = 'Stopping…';
    hideJumpReconnectAlert();
    post('/api/cancel', {}).then(function() {
      appendLog('  [!] Cancel request sent…');
    });
  });

  var jumpReconnectBtn = document.getElementById('jumpReconnectBtn');
  if (jumpReconnectBtn) {
    jumpReconnectBtn.addEventListener('click', function() {
      jumpReconnectBtn.disabled = true;
      jumpReconnectBtn.textContent = '🔄 Reconnecting…';
      appendLog('[🔄] Attempting to reconnect to jump host and resume assessment...');
      post('/api/scan/reconnect', {}).then(function(r) {
        if (r.error) {
          appendLog('[✗] Reconnect request failed: ' + r.error);
          jumpReconnectBtn.disabled = false;
          jumpReconnectBtn.textContent = '🔄 Reconnect & Pull Results';
        } else {
          appendLog('[ℹ] Reconnect command sent. Streaming session from jump host...');
          hideJumpReconnectAlert();
          _scanRunning = true;
          _isRemoteScan = true;
          show(document.getElementById('progressSection'));
          show(document.getElementById('scanSpinner'));
          show(document.getElementById('cancelBtn'));
          document.getElementById('runBtn').disabled = true;
          document.getElementById('runBtn').textContent = '⏳ Reconnecting…';
          document.getElementById('progressLabel').textContent = 'Reconnecting to jump host…';
          startSSE();
        }
      }).catch(function(e) {
        appendLog('[✗] Reconnect network error: ' + e);
        jumpReconnectBtn.disabled = false;
        jumpReconnectBtn.textContent = '🔄 Reconnect & Pull Results';
      });
    });
  }

"""
