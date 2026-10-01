"""
Fleet Actions & Export Web UI JavaScript: Report launchers, Excel/CSV/JSON exports,
host HTML pre-render, pagination controls, fleet library modal, and session teardown hooks.
"""

JS_ACTIONS = """
  // ── Open fleet summary ──────────────────────────────────────────────────
  document.getElementById('openSummaryBtn').addEventListener('click', function() {
    var rpt = this.dataset.report || '00_fleet_summary.html';
    if (rpt) window.open('/reports/' + encodeURIComponent(rpt), '_blank');
  });

  document.getElementById('openObfSummaryBtn').addEventListener('click', function() {
    var rpt = this.dataset.report || '00_OBFUSCATED_fleet_summary.html';
    if (rpt) window.open('/reports/' + encodeURIComponent(rpt), '_blank');
  });

  // ── Open combined report ──────────────────────────────────────────────────
  document.getElementById('openReportBtn').addEventListener('click', function() {
    var rpt = this.dataset.report;
    if (rpt) window.open('/reports/' + encodeURIComponent(rpt), '_blank');
  });

  document.getElementById('openObfReportBtn').addEventListener('click', function() {
    var rpt = this.dataset.report || '00_OBFUSCATED_fleet_combined.html';
    if (rpt) window.open('/reports/' + encodeURIComponent(rpt), '_blank');
  });

  // ── Export Excel ──────────────────────────────────────────────────────────
  document.getElementById('exportXlsxBtn').addEventListener('click', function() {
    var isObf = document.getElementById('obfuscateChk') && document.getElementById('obfuscateChk').checked;
    var ep = '/api/export-excel' + (isObf ? '?obfuscated=1' : '');
    fetch(ep, {method:'POST', credentials: 'same-origin'}).then(function(r) {
      if (!r.ok) { r.json().then(function(j){alert('Excel error: '+j.error);}); return; }
      return r.blob().then(function(blob) {
        var url = URL.createObjectURL(blob);
        var a2 = document.createElement('a');
        a2.href = url;
        a2.download = (isObf ? '00_OBFUSCATED_' : '') + 'vcf_readiness_' + new Date().toISOString().slice(0,10) + '.xlsx';
        a2.click();
        URL.revokeObjectURL(url);
      });
    });
  });

  // ── Export Obfuscated Excel + Key ZIP ──────────────────────────────────────
  var expObfBtn = document.getElementById('exportObfXlsxBtn');
  if (expObfBtn) {
    expObfBtn.addEventListener('click', function() {
      fetch('/api/export-inventory-excel-obfuscated', {method:'POST', credentials: 'same-origin'}).then(function(r) {
        if (!r.ok) { r.json().then(function(j){alert('Obfuscated Excel error: '+(j.error||r.status));}); return; }
        return r.blob().then(function(blob) {
          var url = URL.createObjectURL(blob);
          var a2 = document.createElement('a');
          a2.href = url;
          a2.download = 'vcf_inventory_obfuscated_' + new Date().toISOString().slice(0,10) + '.zip';
          a2.click();
          URL.revokeObjectURL(url);
        });
      });
    });
  }

  // ── Export Obfuscated Package ZIP ─────────────────────────────────────────
  var expObfZipBtn = document.getElementById('exportObfZipBtn');
  if (expObfZipBtn) {
    expObfZipBtn.addEventListener('click', function() {
      fetch('/api/export-obfuscated-zip', {method:'POST', credentials: 'same-origin'}).then(function(r) {
        if (!r.ok) { r.json().then(function(j){alert('Obfuscated ZIP error: '+(j.error||r.status));}); return; }
        return r.blob().then(function(blob) {
          var url = URL.createObjectURL(blob);
          var a2 = document.createElement('a');
          a2.href = url;
          a2.download = '00_OBFUSCATED_vcf_readiness_' + new Date().toISOString().slice(0,10) + '.zip';
          a2.click();
          URL.revokeObjectURL(url);
        });
      });
    });
  }

  // ── Export CSV ────────────────────────────────────────────────────────────
  var expCsvBtn = document.getElementById('exportCsvBtn');
  if (expCsvBtn) {
    expCsvBtn.addEventListener('click', function() {
      var isObf = document.getElementById('obfuscateChk') && document.getElementById('obfuscateChk').checked;
      var ep = '/api/export-csv' + (isObf ? '?obfuscated=1' : '');
      fetch(ep, {method:'POST', credentials: 'same-origin'}).then(function(r) {
        if (!r.ok) { r.json().then(function(j){alert('CSV error: '+j.error);}); return; }
        return r.blob().then(function(blob) {
          var url = URL.createObjectURL(blob);
          var a2 = document.createElement('a');
          a2.href = url;
          a2.download = (isObf ? '00_OBFUSCATED_' : '') + 'fleet_summary_' + new Date().toISOString().slice(0,10) + '.csv';
          a2.click();
          URL.revokeObjectURL(url);
        });
      });
    });
  }

  // ── Export Summary JSON ────────────────────────────────────────────────────
  document.getElementById('exportSummaryJsonBtn').addEventListener('click', function() {
    fetch('/api/export-summary-json', {method:'POST', credentials: 'same-origin'}).then(function(r) {
      if (!r.ok) { r.json().then(function(j){alert('Export JSON error: '+j.error);}); return; }
      return r.blob().then(function(blob) {
        var url = URL.createObjectURL(blob);
        var a2 = document.createElement('a');
        a2.href = url;
        a2.download = 'fleet_summary.json';
        a2.click();
        URL.revokeObjectURL(url);
      });
    });
  });

  // ── Pre-render all host HTML reports ──────────────────────────────────────
  var prerenderBtn = document.getElementById('prerenderReportsBtn');
  if (prerenderBtn) {
    prerenderBtn.addEventListener('click', function() {
      prerenderBtn.disabled = true;
      var origText = prerenderBtn.textContent;
      prerenderBtn.textContent = '⏳ Pre-rendering...';
      post('/api/fleet/prerender', {})
        .then(function(res) {
          prerenderBtn.disabled = false;
          if (res && res.ok) {
            prerenderBtn.textContent = '✓ Pre-rendered (' + res.rendered + '/' + res.total + ')';
            setTimeout(function() { prerenderBtn.textContent = origText; }, 4000);
            if (typeof loadFleetIndexPage === 'function') {
              loadFleetIndexPage(_fleetPageIndex);
            }
          } else {
            alert('Pre-render error: ' + (res ? res.error : 'Unknown error'));
            prerenderBtn.textContent = origText;
          }
        })
        .catch(function(err) {
          prerenderBtn.disabled = false;
          prerenderBtn.textContent = origText;
          alert('Pre-render error: ' + err);
        });
    });
  }

  // ── Open Scan Folder in File Manager ───────────────────────────────────────
  function openScanFolder(targetPath) {
    var outdir = targetPath || _lastScanOutdir || (document.getElementById('outdirInput') ? document.getElementById('outdirInput').value.trim() : '');
    post('/api/open-folder', {path: outdir}).catch(function(err) {
      alert('Could not open folder: ' + err);
    });
  }

  var sumOpenBtn = document.getElementById('summaryOpenFolderBtn');
  if (sumOpenBtn) {
    sumOpenBtn.addEventListener('click', function() {
      var pathText = document.getElementById('summaryOutdirText').textContent.trim();
      openScanFolder(pathText !== '—' ? pathText : '');
    });
  }

  var openFldBtn = document.getElementById('openFolderBtn');
  if (openFldBtn) {
    openFldBtn.addEventListener('click', function() {
      openScanFolder();
    });
  }

  // ── Results Pagination Controller ──────────────────────────────────────────
  var _fleetPageIndex = 0;
  var _fleetPageSize = 50;
  var _fleetFilterText = '';
  var _fleetFilterDebounceTimer = null;

  function loadFleetIndexPage(pageIdx) {
    if (pageIdx !== undefined) _fleetPageIndex = pageIdx;
    var offset = _fleetPageIndex * _fleetPageSize;
    var limit = _fleetPageSize;
    var q = '/api/fleet/index?offset=' + offset + '&limit=' + limit;
    if (_fleetFilterText) {
      q += '&search=' + encodeURIComponent(_fleetFilterText);
    }
    get(q)
      .then(function(resp) {
        if (!resp || !resp.ok) return;
        var tbody = document.getElementById('resultsBody');
        if (tbody) tbody.innerHTML = '';
        var items = resp.items || [];
        items.forEach(function(h) {
          addResultRow(h);
        });
        show(document.getElementById('resultsSection'));

        var total = resp.filtered_total !== undefined ? resp.filtered_total : (resp.total || 0);
        var totalPages = Math.max(1, Math.ceil(total / _fleetPageSize));
        var currPage = _fleetPageIndex + 1;
        var pageInfo = document.getElementById('resultsPageInfo');
        if (pageInfo) {
          pageInfo.textContent = 'Page ' + currPage + ' of ' + totalPages + ' (' + total + ' hosts)';
        }
        var prevBtn = document.getElementById('resultsPrevPageBtn');
        if (prevBtn) prevBtn.disabled = (_fleetPageIndex <= 0);
        var nextBtn = document.getElementById('resultsNextPageBtn');
        if (nextBtn) nextBtn.disabled = (currPage >= totalPages);
      })
      .catch(function(err) {
        console.warn('Failed loading fleet page:', err);
      });
  }

  var prevPageBtn = document.getElementById('resultsPrevPageBtn');
  if (prevPageBtn) {
    prevPageBtn.addEventListener('click', function() {
      if (_fleetPageIndex > 0) loadFleetIndexPage(_fleetPageIndex - 1);
    });
  }

  var nextPageBtn = document.getElementById('resultsNextPageBtn');
  if (nextPageBtn) {
    nextPageBtn.addEventListener('click', function() {
      loadFleetIndexPage(_fleetPageIndex + 1);
    });
  }

  var pageSizeSel = document.getElementById('resultsPageSizeSelect');
  if (pageSizeSel) {
    pageSizeSel.addEventListener('change', function() {
      var val = pageSizeSel.value;
      _fleetPageSize = (val === 'all') ? 500 : (parseInt(val, 10) || 50);
      _fleetPageIndex = 0;
      loadFleetIndexPage(0);
    });
  }

  var filterInput = document.getElementById('resultsFilterInput');
  if (filterInput) {
    filterInput.addEventListener('input', function() {
      clearTimeout(_fleetFilterDebounceTimer);
      _fleetFilterDebounceTimer = setTimeout(function() {
        _fleetFilterText = filterInput.value.trim();
        _fleetPageIndex = 0;
        loadFleetIndexPage(0);
      }, 250);
    });
  }

  // ── Fleet Library Modal & Multi-Scan Assembly ─────────────────────────────
  var _discoveredScans = [];

  function openFleetLibraryModal() {
    var modal = document.getElementById('fleetLibraryModal');
    if (modal) show(modal);
    discoverFleetScans();
  }

  function closeFleetLibraryModal() {
    var modal = document.getElementById('fleetLibraryModal');
    if (modal) hide(modal);
  }

  function updateLibrarySelectionSummary() {
    var checkedBoxes = document.querySelectorAll('#fleetLibraryTableBody input[type="checkbox"]:checked');
    var count = checkedBoxes.length;
    var summaryEl = document.getElementById('fleetLibrarySelectionSummary');
    if (summaryEl) {
      summaryEl.textContent = count + ' scan(s) selected';
    }
    var assembleBtn = document.getElementById('fleetLibraryAssembleBtn');
    if (assembleBtn) {
      assembleBtn.disabled = (count === 0);
    }
  }

  function discoverFleetScans() {
    var pathInput = document.getElementById('fleetLibraryPathInput');
    var libPath = pathInput ? pathInput.value.trim() : '';
    var loadingEl = document.getElementById('fleetLibraryLoading');
    var emptyEl = document.getElementById('fleetLibraryEmpty');
    var wrapEl = document.getElementById('fleetLibraryScansWrap');
    var statusEl = document.getElementById('fleetLibraryStatusMsg');
    var tableBody = document.getElementById('fleetLibraryTableBody');
    var countEl = document.getElementById('fleetLibraryCount');

    if (loadingEl) show(loadingEl);
    if (emptyEl) hide(emptyEl);
    if (wrapEl) hide(wrapEl);
    if (statusEl) statusEl.textContent = '';
    if (tableBody) tableBody.innerHTML = '';

    post('/api/fleet/discover', {library_dir: libPath})
      .then(function(resp) {
        if (loadingEl) hide(loadingEl);
        if (!resp || !resp.ok) {
          if (statusEl) statusEl.textContent = 'Discovery error: ' + ((resp && resp.error) || 'Failed to query library');
          return;
        }
        _discoveredScans = resp.scans || [];
        if (countEl) countEl.textContent = _discoveredScans.length + ' scan(s) discovered';

        if (_discoveredScans.length === 0) {
          if (emptyEl) show(emptyEl);
          updateLibrarySelectionSummary();
          return;
        }

        if (tableBody) {
          tableBody.innerHTML = _discoveredScans.map(function(s, idx) {
            var dateStr = s.scanned_at ? esc(s.scanned_at.substring(0, 16).replace('T', ' ')) : '—';
            var hostsStr = (s.host_count !== null && s.host_count !== undefined) ? esc(String(s.host_count)) : '—';
            var siteStr = s.site ? esc(s.site) : '<span class="text-muted">—</span>';
            var typeBadge = s.is_zip ? '<span class="badge" style="background:#e0e7ff;color:#3730a3">ZIP</span>'
                                     : '<span class="badge" style="background:#f1f5f9;color:#334155">Folder</span>';
            if (s.obfuscated) {
              typeBadge += ' <span class="badge" style="background:#fef3c7;color:#92400e">Obfuscated</span>';
            }
            return '<tr>'
              + '<td><input type="checkbox" class="lib-scan-chk" data-idx="' + idx + '" checked></td>'
              + '<td><strong title="' + esc(s.path) + '">' + esc(s.scan_id) + '</strong></td>'
              + '<td><small class="text-muted">' + dateStr + '</small></td>'
              + '<td>' + hostsStr + '</td>'
              + '<td>' + siteStr + '</td>'
              + '<td>' + typeBadge + '</td>'
              + '</tr>';
          }).join('');

          var chks = tableBody.querySelectorAll('.lib-scan-chk');
          chks.forEach(function(chk) {
            chk.addEventListener('change', updateLibrarySelectionSummary);
          });
        }

        if (wrapEl) show(wrapEl);
        updateLibrarySelectionSummary();
      })
      .catch(function(err) {
        if (loadingEl) hide(loadingEl);
        if (statusEl) statusEl.textContent = 'Discovery failed: ' + err;
      });
  }

  var openLibBtn = document.getElementById('openLibraryBtn');
  if (openLibBtn) openLibBtn.addEventListener('click', openFleetLibraryModal);

  var closeLibBtn = document.getElementById('closeFleetLibraryModalBtn');
  if (closeLibBtn) closeLibBtn.addEventListener('click', closeFleetLibraryModal);

  var cancelLibBtn = document.getElementById('cancelFleetLibraryModalBtn');
  if (cancelLibBtn) cancelLibBtn.addEventListener('click', closeFleetLibraryModal);

  var discLibBtn = document.getElementById('fleetLibraryDiscoverBtn');
  if (discLibBtn) discLibBtn.addEventListener('click', discoverFleetScans);

  var selectAllLibChk = document.getElementById('selectAllLibraryScansChk');
  if (selectAllLibChk) {
    selectAllLibChk.addEventListener('change', function() {
      var isChecked = selectAllLibChk.checked;
      var chks = document.querySelectorAll('#fleetLibraryTableBody .lib-scan-chk');
      chks.forEach(function(c) { c.checked = isChecked; });
      updateLibrarySelectionSummary();
    });
  }

  var assembleBtn = document.getElementById('fleetLibraryAssembleBtn');
  if (assembleBtn) {
    assembleBtn.addEventListener('click', function() {
      var pathInput = document.getElementById('fleetLibraryPathInput');
      var libPath = pathInput ? pathInput.value.trim() : '';
      var siteInput = document.getElementById('fleetLibrarySiteInput');
      var siteVal = siteInput ? siteInput.value.trim() : '';
      var obfChk = document.getElementById('fleetLibraryObfuscateChk');
      var isObf = obfChk ? obfChk.checked : false;

      var checkedBoxes = document.querySelectorAll('#fleetLibraryTableBody .lib-scan-chk:checked');
      var selectedPaths = [];
      checkedBoxes.forEach(function(c) {
        var idx = parseInt(c.dataset.idx, 10);
        if (_discoveredScans[idx]) {
          selectedPaths.push(_discoveredScans[idx].path || _discoveredScans[idx].scan_id);
        }
      });

      if (selectedPaths.length === 0) return;

      var statusEl = document.getElementById('fleetLibraryStatusMsg');
      if (statusEl) statusEl.textContent = '⏳ Assembling fleet artifacts across ' + selectedPaths.length + ' scan(s)…';
      assembleBtn.disabled = true;

      post('/api/fleet/assemble', {
        library_dir: libPath,
        scan_paths: selectedPaths,
        site: siteVal,
        obfuscate: isObf
      })
        .then(function(resp) {
          assembleBtn.disabled = false;
          if (!resp || !resp.ok) {
            if (statusEl) statusEl.textContent = 'Assembly error: ' + ((resp && resp.error) || 'Failed to assemble fleet');
            return;
          }
          closeFleetLibraryModal();

          // Set scan status & show post-scan actions
          _scanRunning = false;
          _isImportScan = true;
          onScanDone(resp);
          appendLog('[✓] ' + (resp.scan_summary || 'Fleet assembly completed successfully.'));

          // Load paginated results table
          loadFleetIndexPage(0);
        })
        .catch(function(err) {
          assembleBtn.disabled = false;
          if (statusEl) statusEl.textContent = 'Assembly failed: ' + err;
        });
    });
  }

  // ── Clear log ─────────────────────────────────────────────────────────────
  document.getElementById('clearLogBtn').addEventListener('click', function() {
    document.getElementById('logBox').innerHTML = '';
  });

  // ── Save session on visibility change ────────────────────────────────────
  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'hidden') saveSession();
  });
  window.addEventListener('beforeunload', saveSession);

"""
