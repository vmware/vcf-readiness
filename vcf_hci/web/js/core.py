"""
Core Web UI JavaScript: theme management, shutdown handler, DOM/network helpers,
session persistence, and profile management.
"""

JS_CORE = """
  function esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // ── Theme toggle ──────────────────────────────────────────────────────────
  var root     = document.documentElement;
  var themeBtn = document.getElementById('themeToggle');
  var savedTheme = (function() {
    try { return localStorage.getItem('vcf-theme'); } catch(e) { return null; }
  })();
  var currentTheme = savedTheme || 'dark';

  function applyTheme(t) {
    root.setAttribute('data-theme', t);
    themeBtn.textContent = (t === 'dark') ? '☀️ Light' : '🌙 Dark';
    try { localStorage.setItem('vcf-theme', t); } catch(e) {}
    currentTheme = t;
  }
  applyTheme(currentTheme);
  themeBtn.addEventListener('click', function() {
    applyTheme(currentTheme === 'dark' ? 'light' : 'dark');
  });

  // ── Quit ──────────────────────────────────────────────────────────────────
  document.getElementById('shutdownBtn').addEventListener('click', function() {
    if (!confirm('Quit the VCF Readiness tool?')) return;
    fetch('/api/shutdown', {method:'POST', credentials: 'same-origin'}).catch(function(){});
    document.body.innerHTML = '<div style="text-align:center;padding:4rem;font-size:1.1rem">✔ Shutdown signal sent — you can close this tab.</div>';
  });

  // ── Helpers ───────────────────────────────────────────────────────────────
  function show(el) { if(el) el.classList.remove('hidden'); }
  function hide(el) { if(el) el.classList.add('hidden'); }
  function toggle(el, cond) { cond ? show(el) : hide(el); }

  // ── Anchor Navigation & Pulse Highlight ───────────────────────────────────
  function highlightAnchor(element) {
    if (!element) return;
    element.scrollIntoView({ behavior: 'smooth', block: 'center' });
    try {
      element.focus({ preventScroll: true });
    } catch (e) {
      try { element.focus(); } catch (e2) {}
    }
    element.classList.remove('pulse-highlight');
    void element.offsetWidth;
    element.classList.add('pulse-highlight');
    setTimeout(function() {
      element.classList.remove('pulse-highlight');
    }, 4500);
  }

  function openAndHighlightVault(targetInputId) {
    var vBody = document.getElementById('vaultBody');
    if (vBody && !vBody.classList.contains('open')) {
      vBody.classList.add('open');
      var vArr = document.getElementById('vaultArrow');
      if (vArr) vArr.textContent = '▼';
      if (typeof refreshVaultStatus === 'function') refreshVaultStatus();
    }
    var targetEl = null;
    if (targetInputId) {
      targetEl = document.getElementById(targetInputId);
    }
    if (!targetEl) {
      if (typeof _vaultState !== 'undefined') {
        if (_vaultState.exists && !_vaultState.unlocked) {
          targetEl = document.getElementById('vaultUnlockPass');
        } else if (!_vaultState.exists) {
          targetEl = document.getElementById('vaultNewPass1');
        } else if (_vaultState.unlocked) {
          targetEl = document.getElementById('jumpId') || document.getElementById('vaultAddTarget');
        }
      }
    }
    if (!targetEl) targetEl = document.getElementById('vaultToggle');
    if (targetEl) highlightAnchor(targetEl);
  }

  function _handleFetchResponse(r) {
    return r.json().catch(function() { return null; }).then(function(data) {
      if (!r.ok) {
        var msg = (data && data.error) ? data.error : ('HTTP ' + r.status + ' ' + r.statusText);
        var err = new Error(msg);
        err.status = r.status;
        err.data = data;
        throw err;
      }
      return data || {};
    });
  }

  function post(url, body) {
    var headers = {'Content-Type': 'application/json'};
    return fetch(url, {
      method: 'POST',
      headers: headers,
      credentials: 'same-origin',
      body: JSON.stringify(body)
    }).then(_handleFetchResponse);
  }
  function get(url) {
    return fetch(url, {credentials: 'same-origin'}).then(_handleFetchResponse);
  }
  function del(url) {
    return fetch(url, {
      method: 'DELETE',
      credentials: 'same-origin'
    }).then(_handleFetchResponse);
  }

  // ── Session save/restore ──────────────────────────────────────────────────
  function saveSession() {
    var chosenProfile = (document.querySelector('input[name=scanProfile]:checked') || {}).value || 'readiness-full';
    post('/api/session', {
      range:           document.getElementById('rangeInput').value,
      username:        document.getElementById('usernameInput').value,
      output_dir:      document.getElementById('outdirInput').value,
      threads:         document.getElementById('threadsInput').value,
      profile:         chosenProfile,
      mode:            chosenProfile === 'inventory-lite' ? 'quick' : 'full',
      combined_report: document.getElementById('combinedChk').checked,
      debug_log:       document.getElementById('debugChk').checked,
      save_json:       document.getElementById('saveJsonChk').checked,
      include_raw:     document.getElementById('includeRawChk').checked,
      crawl_endpoints: document.getElementById('crawlEndpointsChk') ? document.getElementById('crawlEndpointsChk').checked : false,
      lean:            chosenProfile === 'readiness-lean' || chosenProfile === 'inventory-lite',
      obfuscate:       document.getElementById('obfuscateChk').checked,
      export_sheets:   document.getElementById('exportSpreadsheetChk') ? document.getElementById('exportSpreadsheetChk').checked : true,
      allow_partial:   document.getElementById('allowPartialChk').checked,
      auto_retry:      document.getElementById('autoRetryChk') ? document.getElementById('autoRetryChk').checked : true,
      extend_timeout:  document.getElementById('extendTimeoutChk').checked,
      host_timeout_min: parseInt(document.getElementById('timeoutMinutesInput').value, 10) || 10,
      ignore_tls:      document.getElementById('ignoreTlsChk') ? document.getElementById('ignoreTlsChk').checked : true,
      tls_mode:        (document.querySelector('input[name=tlsMode]:checked') || {}).value || 'system',
      ca_bundle:       document.getElementById('caBundleInput') ? document.getElementById('caBundleInput').value : '',
      dns_lookup:      document.getElementById('dnsLookupChk') ? document.getElementById('dnsLookupChk').checked : false,
      restrict_private: document.getElementById('restrictPrivateChk') ? document.getElementById('restrictPrivateChk').checked : false,
      enable_dash:     document.getElementById('enableDashChk') ? document.getElementById('enableDashChk').checked : false,
      pinned_thumbprints: _pinnedThumbprints,
      dark_mode:       currentTheme === 'dark',
    });
  }
  document.getElementById('outdirInput').addEventListener('input', function() {
    this.dataset.customized = 'true';
  });

  var browseBtn = document.getElementById('browseOutdirBtn');
  if (browseBtn) {
    browseBtn.addEventListener('click', function() {
      var curDir = document.getElementById('outdirInput').value.trim();
      var btn = this;
      btn.disabled = true;
      post('/api/browse-folder', {initial_dir: curDir}).then(function(res) {
        btn.disabled = false;
        if (res && res.ok && res.path) {
          var inp = document.getElementById('outdirInput');
          inp.value = res.path;
          inp.dataset.customized = 'true';
          saveSession();
        }
      }).catch(function() {
        btn.disabled = false;
      });
    });
  }

  function estimateHostCount(rawStr) {
    if (!rawStr) return 0;
    var parts = rawStr.split(/[,\\s]+/).filter(Boolean);
    var total = 0;
    parts.forEach(function(part) {
      if (part.indexOf('-') !== -1) {
        var dashParts = part.split('-');
        if (dashParts.length === 2) {
          var startIp = dashParts[0].trim();
          var endStr = dashParts[1].trim();
          var startOctets = startIp.split('.');
          if (startOctets.length === 4) {
            var startNum = parseInt(startOctets[3], 10);
            var endNum = parseInt(endStr.indexOf('.') !== -1 ? endStr.split('.')[3] : endStr, 10);
            if (!isNaN(startNum) && !isNaN(endNum) && endNum >= startNum) {
              total += (endNum - startNum + 1);
              return;
            }
          }
        }
      }
      if (part.indexOf('/') !== -1) {
        var cidrParts = part.split('/');
        if (cidrParts.length === 2) {
          var mask = parseInt(cidrParts[1], 10);
          if (!isNaN(mask) && mask >= 0 && mask <= 32) {
            total += Math.pow(2, 32 - mask);
            return;
          }
        }
      }
      total += 1;
    });
    return total;
  }

  function getHostCount() {
    var checkedHosts = Array.from(document.querySelectorAll('.host-chk:checked'));
    if (checkedHosts.length) {
      return checkedHosts.length;
    }
    var raw = document.getElementById('rangeInput').value.trim();
    return estimateHostCount(raw);
  }

  function updateCombinedGate() {
    var count = getHostCount();
    var chk = document.getElementById('combinedChk');
    var note = document.getElementById('combinedNote');
    if (!chk) return;
    chk.disabled = false;
    if (count > 64) {
      if (note) {
        note.textContent = 'Large fleet (' + count + ' hosts): Fleet Hub will be generated as a sidecar pack with lazy on-demand host frames (no 256-host limit). fleet_summary.html is also generated. For multiple independent scans, use Open Fleet Library to assemble.';
        note.style.display = 'block';
      }
    } else {
      if (note) note.style.display = 'none';
    }
  }

  function updateFleetNotice() {
    var count = getHostCount();
    var notice = document.getElementById('fleetNotice');
    var label = document.getElementById('fleetCountLabel');
    if (notice) {
      if (count >= 100) {
        if (label) label.textContent = count + ' hosts';
        show(notice);
      } else {
        hide(notice);
      }
    }
  }

  function updateHostGates() {
    updateCombinedGate();
    updateFleetNotice();
  }

  document.getElementById('rangeInput').addEventListener('input', updateHostGates);

  function restoreSession(s) {
    if (!s) return;
    if (s.range)       document.getElementById('rangeInput').value    = s.range;
    if (s.username)    document.getElementById('usernameInput').value = s.username;
    if (s.output_dir)  {
      var inp = document.getElementById('outdirInput');
      inp.value = s.output_dir;
      inp.dataset.customized = 'true';
    }
    if (s.threads)     document.getElementById('threadsInput').value  = s.threads;
    if (s.profile) {
      var pRadio = document.querySelector('input[name=scanProfile][value="'+s.profile+'"]');
      if (pRadio) pRadio.checked = true;
    } else if (s.lean) {
      var pLean = document.getElementById('profLean');
      if (pLean) pLean.checked = true;
    } else if (s.mode === 'quick') {
      var pLite = document.getElementById('profLite');
      if (pLite) pLite.checked = true;
    } else if (s.mode === 'full') {
      var pFull = document.getElementById('profFull');
      if (pFull) pFull.checked = true;
    }
    if (s.oem_mode) {
      var pFull = document.getElementById('profFull');
      if (pFull) pFull.checked = true;
      if (document.getElementById('crawlEndpointsChk')) document.getElementById('crawlEndpointsChk').checked = true;
      document.getElementById('includeRawChk').checked = true;
      document.getElementById('saveJsonChk').checked = true;
      document.getElementById('allowPartialChk').checked = true;
      document.getElementById('extendTimeoutChk').checked = true;
      document.getElementById('timeoutMinutesInput').value = 15;
    } else if ('crawl_endpoints' in s && document.getElementById('crawlEndpointsChk')) {
      document.getElementById('crawlEndpointsChk').checked = !!s.crawl_endpoints;
    }
    updateCrawlWarningVisibility();
    function setChecked(id, val) {
      var el = document.getElementById(id);
      if (el) el.checked = !!val;
    }
    function setValue(id, val) {
      var el = document.getElementById(id);
      if (el) el.value = val;
    }
    if ('combined_report' in s && !s.oem_mode) setChecked('combinedChk', s.combined_report);
    if ('debug_log' in s && !s.oem_mode)       setChecked('debugChk', s.debug_log);
    if ('save_json' in s && !s.oem_mode)       setChecked('saveJsonChk', s.save_json);
    if ('include_raw' in s && !s.oem_mode)     setChecked('includeRawChk', s.include_raw);
    if ('obfuscate' in s)       setChecked('obfuscateChk', s.obfuscate);
    if ('export_sheets' in s)   setChecked('exportSpreadsheetChk', s.export_sheets);
    if ('allow_partial' in s)   setChecked('allowPartialChk', s.allow_partial);
    if ('auto_retry' in s)      setChecked('autoRetryChk', s.auto_retry);
    if ('extend_timeout' in s)  setChecked('extendTimeoutChk', s.extend_timeout);
    if (s.host_timeout_min)     setValue('timeoutMinutesInput', String(Math.min(45, Math.max(1, parseInt(s.host_timeout_min, 10) || 10))));
    updateTimeoutBoxVisibility();
    if ('ignore_tls' in s)      setChecked('ignoreTlsChk', s.ignore_tls);
    if (s.tls_mode) {
      var tr = document.querySelector('input[name=tlsMode][value="'+s.tls_mode+'"]');
      if (tr) tr.checked = true;
    }
    if (s.ca_bundle) setValue('caBundleInput', s.ca_bundle);
    if ('dns_lookup' in s)       setChecked('dnsLookupChk', s.dns_lookup);
    if ('restrict_private' in s) setChecked('restrictPrivateChk', s.restrict_private);
    if ('enable_dash' in s)      setChecked('enableDashChk', s.enable_dash);
    if (s.pinned_thumbprints && typeof s.pinned_thumbprints === 'object') {
      _pinnedThumbprints = Object.assign({}, s.pinned_thumbprints);
      if (typeof updatePinnedCertUi === 'function') updatePinnedCertUi();
    }
    if (typeof syncTlsUi === 'function') syncTlsUi();
    if ('dark_mode' in s)       applyTheme(s.dark_mode ? 'dark' : 'light');
    updateHostGates();
  }
  get('/api/session').then(restoreSession).catch(function(){});

  get('/api/version').then(function(v) {
    if (v) {
      var outInp = document.getElementById('outdirInput');
      if (v.default_outdir && outInp && !outInp.dataset.customized) {
        var curVal = outInp.value;
        if (!curVal || curVal === '~/Desktop' || curVal === '~/Desktop/VCF-Scans') {
          outInp.value = v.default_outdir;
        }
      }
      if (v.is_root) {
        var banner = document.getElementById('rootAlertBanner');
        var pathEl = document.getElementById('rootBannerPath');
        if (pathEl) pathEl.textContent = v.default_outdir || '';
        if (banner) banner.classList.remove('hidden');
      }
    }
  }).catch(function(){});

  // ── Profile management ────────────────────────────────────────────────────
  var profileSel = document.getElementById('profileSelect');
  function refreshProfiles() {
    get('/api/profiles').then(function(profiles) {
      profileSel.innerHTML = '<option value="">— select —</option>';
      Object.keys(profiles).sort().forEach(function(name) {
        var opt = document.createElement('option');
        opt.value = name; opt.textContent = name;
        profileSel.appendChild(opt);
      });
    });
  }
  refreshProfiles();

  document.getElementById('loadProfileBtn').addEventListener('click', function() {
    var name = profileSel.value;
    if (!name) return;
    get('/api/profiles').then(function(profiles) {
      var p = profiles[name];
      if (!p) return;
      if (p.range)      { document.getElementById('rangeInput').value = p.range || ''; updateHostGates(); }
      if (p.username)   document.getElementById('usernameInput').value = p.username || '';
      if (p.output_dir) document.getElementById('outdirInput').value   = p.output_dir || '';
      if (p.threads)    document.getElementById('threadsInput').value  = p.threads || 12;
      // Load password from keychain
      post('/api/keychain/retrieve', {key: 'profile:' + name}).then(function(r) {
        if (r.value) document.getElementById('passwordInput').value = r.value;
      });
    });
  });

  document.getElementById('saveProfileBtn').addEventListener('click', function() {
    var name = prompt('Profile name:');
    if (!name || !name.trim()) return;
    post('/api/profiles', {
      name:       name.trim(),
      range:      document.getElementById('rangeInput').value,
      username:   document.getElementById('usernameInput').value,
      output_dir: document.getElementById('outdirInput').value,
      threads:    document.getElementById('threadsInput').value,
      password:   document.getElementById('passwordInput').value,
    }).then(function() { refreshProfiles(); });
  });

  document.getElementById('deleteProfileBtn').addEventListener('click', function() {
    var name = profileSel.value;
    if (!name || !confirm('Delete profile "' + name + '"?')) return;
    del('/api/profiles/' + encodeURIComponent(name))
      .then(refreshProfiles);
  });

"""
