"""
Discovery & Vault Web UI JavaScript: TOFU certificate trust inspection,
credential testing runner, encrypted credential vault UI, and Dell TechDirect keychain.
"""

JS_VAULT = """
  // ── Discovery & Certificate Trust (TOFU) ──────────────────────────────────
  var _discoveredHosts = [];
  var _pinnedThumbprints = {};
  var _modalCertsList = [];

  function updatePinnedCertUi() {
    var count = Object.keys(_pinnedThumbprints).length;
    var el = document.getElementById('pinnedCertSummary');
    if (el) el.textContent = count + ' thumbprint(s) pinned';
  }

  function openCertModal(certsList) {
    _modalCertsList = certsList || [];
    var tbody = document.getElementById('certTableBody');
    if (!tbody) return;
    if (!_modalCertsList.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-muted text-center" style="padding:1rem;">No certificate metadata available</td></tr>';
    } else {
      tbody.innerHTML = _modalCertsList.map(function(c) {
        var ip = c.ip || c.host || '';
        var safeIp = esc(ip);
        var sub = esc(c.subject_cn || c.subject || 'Unknown');
        var iss = esc(c.issuer_cn || c.issuer || 'Unknown');
        var exp = esc(c.not_after || c.expiry || 'N/A');
        var thumb = esc(c.sha256 || c.sha256_raw || '');
        var isSelfSigned = !!c.is_self_signed;
        var statusBadge = isSelfSigned
          ? '<span class="badge badge-warning">Self-Signed</span>'
          : '<span class="badge badge-info">Enterprise CA</span>';
        var checkedAttr = 'checked';
        return '<tr>'
          + '<td><input type="checkbox" class="cert-row-chk" data-ip="' + safeIp + '" data-thumb="' + thumb + '" ' + checkedAttr + '></td>'
          + '<td><strong>' + safeIp + '</strong></td>'
          + '<td>' + sub + '</td>'
          + '<td>' + iss + '</td>'
          + '<td>' + exp + '</td>'
          + '<td><code class="vcf-thumbprint-code">' + (thumb || 'N/A') + '</code></td>'
          + '<td>' + statusBadge + '</td>'
          + '</tr>';
      }).join('');
    }
    updatePinnedCertUi();
    show(document.getElementById('certModal'));
  }

  function closeCertModal() {
    hide(document.getElementById('certModal'));
  }

  function inspectAndReviewCert(ip) {
    if (!ip) return;
    get('/api/inspect-cert?host=' + encodeURIComponent(ip))
      .then(function(certData) {
        if (certData && certData.reachable) {
          certData.ip = ip;
          openCertModal([certData]);
        } else {
          alert('Could not inspect certificate on ' + ip + ': ' + (certData.error || 'Connection failed'));
        }
      })
      .catch(function(err) {
        alert('Failed inspecting certificate for ' + ip + ': ' + err);
      });
  }

  var closeCertModalBtn = document.getElementById('closeCertModalBtn');
  if (closeCertModalBtn) closeCertModalBtn.addEventListener('click', closeCertModal);
  var cancelCertModalBtn = document.getElementById('cancelCertModalBtn');
  if (cancelCertModalBtn) cancelCertModalBtn.addEventListener('click', closeCertModal);

  var selectAllCertsChk = document.getElementById('selectAllCertsChk');
  if (selectAllCertsChk) {
    selectAllCertsChk.addEventListener('change', function() {
      var chked = this.checked;
      document.querySelectorAll('.cert-row-chk').forEach(function(c) { c.checked = chked; });
    });
  }

  var acceptSelectedCertsBtn = document.getElementById('acceptSelectedCertsBtn');
  if (acceptSelectedCertsBtn) {
    acceptSelectedCertsBtn.addEventListener('click', function() {
      var count = 0;
      document.querySelectorAll('.cert-row-chk:checked').forEach(function(chk) {
        var ip = chk.dataset.ip;
        var thumb = chk.dataset.thumb;
        if (ip && thumb) {
          _pinnedThumbprints[ip] = thumb;
          count++;
        }
      });
      saveSession();
      updatePinnedCertUi();
      closeCertModal();
      document.getElementById('discStatus').textContent = 'Pinned ' + count + ' certificate thumbprint(s).';
    });
  }

  var modalAcceptAllCertsBtn = document.getElementById('modalAcceptAllCertsBtn');
  if (modalAcceptAllCertsBtn) {
    modalAcceptAllCertsBtn.addEventListener('click', function() {
      var count = 0;
      _modalCertsList.forEach(function(c) {
        var ip = c.ip || c.host || '';
        var thumb = c.sha256 || c.sha256_raw || '';
        if (ip && thumb) {
          _pinnedThumbprints[ip] = thumb;
          count++;
        }
      });
      saveSession();
      updatePinnedCertUi();
      closeCertModal();
      document.getElementById('discStatus').textContent = 'Pinned all ' + count + ' certificate thumbprint(s).';
    });
  }

  var reviewCertsBtn = document.getElementById('reviewCertsBtn');
  if (reviewCertsBtn) {
    reviewCertsBtn.addEventListener('click', function() {
      var list = [];
      _discoveredHosts.forEach(function(h) {
        if (h.cert_info && h.cert_info.sha256) {
          var ci = Object.assign({}, h.cert_info);
          ci.ip = h.ip;
          list.push(ci);
        }
      });
      openCertModal(list);
    });
  }

  var acceptAllCertsBtn = document.getElementById('acceptAllCertsBtn');
  if (acceptAllCertsBtn) {
    acceptAllCertsBtn.addEventListener('click', function() {
      var count = 0;
      _discoveredHosts.forEach(function(h) {
        if (h.cert_info && h.cert_info.sha256) {
          _pinnedThumbprints[h.ip] = h.cert_info.sha256;
          count++;
        }
      });
      saveSession();
      updatePinnedCertUi();
      document.getElementById('discStatus').textContent = 'Pinned ' + count + ' certificate thumbprint(s).';
      var certBanner = document.getElementById('certTrustBanner');
      if (certBanner) {
        certBanner.className = 'alert alert-success';
        certBanner.innerHTML = '<span>✔ <strong>All ' + count + ' certificate thumbprints pinned</strong> for secure verification.</span>';
      }
    });
  }

  function renderHostList(hosts) {
    var list = document.getElementById('hostList');
    list.innerHTML = '';
    _discoveredHosts = hosts;
    var certHosts = [];
    if (!hosts.length) {
      list.innerHTML = '<div class="host-row text-muted">No reachable hosts found</div>';
    } else {
      hosts.forEach(function(h) {
        var safeIp = esc(h.ip);
        var safePort = esc(h.port);
        var certBadge = '';
        if (h.cert_info && h.cert_info.sha256) {
          h.cert_info.ip = h.ip;
          certHosts.push(h.cert_info);
          var badgeClass = h.cert_info.is_self_signed ? 'badge-warning' : 'badge-info';
          var label = h.cert_info.is_self_signed ? 'Self-Signed' : 'TLS';
          var shortThumb = esc(h.cert_info.sha256.substring(0, 14));
          certBadge = '<span class="badge ' + badgeClass + '" style="margin-left:0.5rem; font-size:0.75rem;">' + label + ' (' + shortThumb + '…)</span>';
        }
        var row = document.createElement('div');
        row.className = 'host-row';
        row.innerHTML = '<input type="checkbox" class="host-chk" data-ip="'+safeIp+'" checked>'
          + '<span class="host-ip">'+safeIp+'</span>'
          + '<span class="host-port">:'+safePort+'</span>'
          + certBadge;
        var chk = row.querySelector('.host-chk');
        if (chk) chk.addEventListener('change', updateHostGates);
        list.appendChild(row);
      });
    }
    show(list);
    var certBanner = document.getElementById('certTrustBanner');
    if (certBanner) {
      if (certHosts.length > 0) {
        document.getElementById('certTrustCount').textContent = certHosts.length;
        show(certBanner);
      } else {
        hide(certBanner);
      }
    }
    buildPerHostCreds(hosts.map(function(h){return h.ip;}));
    updateHostGates();
  }

  document.getElementById('discoverBtn').addEventListener('click', function() {
    var raw = document.getElementById('rangeInput').value.trim();
    if (!raw) { alert('Enter a target range first.'); return; }
    show(document.getElementById('discSpinner'));
    document.getElementById('discStatus').textContent = 'Probing…';
    hide(document.getElementById('hostList'));
    hide(document.getElementById('vpnWarning'));
    post('/api/discover', {targets: raw})
      .then(function(r) {
        hide(document.getElementById('discSpinner'));
        if (r.error) {
          document.getElementById('discStatus').textContent = 'Error: ' + r.error;
        } else {
          document.getElementById('discStatus').textContent =
            r.hosts.length + ' reachable host(s) found';
          renderHostList(r.hosts);
          if (r.high_latency_detected) {
            document.getElementById('vpnLatency').textContent = r.avg_latency_ms || '0';
            show(document.getElementById('vpnWarning'));
            var thInp = document.getElementById('threadsInput');
            if (thInp && parseInt(thInp.value, 10) > 6) {
              thInp.value = '6';
            }
          } else {
            hide(document.getElementById('vpnWarning'));
          }
        }
      })
      .catch(function(e) {
        hide(document.getElementById('discSpinner'));
        document.getElementById('discStatus').textContent = 'Probe failed: ' + e;
      });
  });

  document.getElementById('selAllBtn').addEventListener('click', function() {
    document.querySelectorAll('.host-chk').forEach(function(c){ c.checked = true; });
    updateHostGates();
  });
  document.getElementById('selNoneBtn').addEventListener('click', function() {
    document.querySelectorAll('.host-chk').forEach(function(c){ c.checked = false; });
    updateHostGates();
  });

  // ── Same/Per-host creds toggle ────────────────────────────────────────────
  var sameChk = document.getElementById('sameCredsChk');
  function syncCredMode() {
    toggle(document.getElementById('sharedCreds'),  sameChk.checked);
    toggle(document.getElementById('perHostCreds'), !sameChk.checked);
  }
  sameChk.addEventListener('change', syncCredMode);
  syncCredMode();

  function buildPerHostCreds(ips) {
    var container = document.getElementById('perHostRows');
    container.innerHTML = '';
    ips.forEach(function(ip) {
      var safeIp = esc(ip);
      var row = document.createElement('div');
      row.className = 'form-grid';
      row.style.marginBottom = '.4rem';
      row.innerHTML = '<div class="clr-form-group"><label class="clr-control-label">'+safeIp+' — User</label>'
        + '<input class="clr-input" data-ip="'+safeIp+'" data-field="user" type="text" value="root"></div>'
        + '<div class="clr-form-group"><label class="clr-control-label">'+safeIp+' — Password</label>'
        + '<input class="clr-input" data-ip="'+safeIp+'" data-field="pass" type="password"></div>';
      container.appendChild(row);
    });
  }

  // ── Test credentials ──────────────────────────────────────────────────────
  document.getElementById('testCredsBtn').addEventListener('click', function() {
    var ip  = document.getElementById('rangeInput').value.trim().split(/[\\s,]+/)[0];
    if (!ip) { alert('Enter a target IP first.'); return; }
    var u = document.getElementById('usernameInput').value;
    var p = document.getElementById('passwordInput').value;
    var ignoreTls = document.getElementById('ignoreTlsChk') ? document.getElementById('ignoreTlsChk').checked : true;
    var verifySsl = !ignoreTls;
    var tlsMode = (document.querySelector('input[name=tlsMode]:checked') || {}).value || 'system';
    var caBundle = (verifySsl && tlsMode === 'custom') ? (document.getElementById('caBundleInput').value.trim() || null) : null;
    document.getElementById('testCredsStatus').textContent = 'Testing…';
    post('/api/test-creds', {
      ip: ip,
      username: u,
      password: p,
      verify_ssl: verifySsl,
      ca_bundle: caBundle,
    }).then(function(r) {
      document.getElementById('testCredsStatus').textContent =
        r.ok ? '✔ Auth OK ('+r.code+')' : '✗ Failed: '+r.detail+' ('+r.code+')';
    });
  });

  // ── Dell section toggle ───────────────────────────────────────────────────
  document.getElementById('dellToggle').addEventListener('click', function() {
    var body = document.getElementById('dellBody');
    var open = body.classList.toggle('open');
    document.getElementById('dellArrow').textContent = open ? '▼' : '▶';
  });

  // ── Encrypted Credential Vault (opt-in) ───────────────────────────────────
  // All calls are same-origin; the server never returns passwords. Nothing here
  // runs against the vault unless the user clicks Create / Unlock.
  function postJson(url, body) {
    return fetch(url, {method:'POST', headers:{'Content-Type':'application/json'},
                        credentials:'same-origin', body: JSON.stringify(body || {})})
      .then(function(r) { return r.json().catch(function(){ return {}; }).then(function(d) { return {status: r.status, data: d}; }); });
  }
  function getJson(url) {
    return fetch(url, {credentials:'same-origin'})
      .then(function(r) { return r.json().catch(function(){ return {}; }).then(function(d) { return {status: r.status, data: d}; }); });
  }
  var $v = function(id) { return document.getElementById(id); };
  var _vaultState = {exists:false, unlocked:false, entry_count:0, remote_disabled:false};

  function setVaultEntriesAccordion(open) {
    var body = $v('vaultEntriesBody');
    if (body) {
      if (open) body.classList.add('open');
      else body.classList.remove('open');
    }
    var arrow = $v('vaultEntriesArrow');
    if (arrow) arrow.textContent = open ? '▼' : '▶';
  }

  document.getElementById('vaultToggle').addEventListener('click', function() {
    var body = $v('vaultBody');
    var open = body.classList.toggle('open');
    $v('vaultArrow').textContent = open ? '▼' : '▶';
    if (open) {
      setVaultEntriesAccordion(false);
      refreshVaultStatus();
    }
  });

  var vaultEntriesToggle = $v('vaultEntriesToggle');
  if (vaultEntriesToggle) {
    vaultEntriesToggle.addEventListener('click', function() {
      var body = $v('vaultEntriesBody');
      if (!body) return;
      var open = body.classList.toggle('open');
      var arrow = $v('vaultEntriesArrow');
      if (arrow) arrow.textContent = open ? '▼' : '▶';
    });
  }

  function vaultMsg(text, isErr) {
    var el = $v('vaultMsg');
    el.textContent = text || '';
    el.style.color = isErr ? 'var(--vcf-danger)' : 'var(--vcf-success)';
    toggle(el, !!text);
  }

  function renderVaultState() {
    var s = _vaultState;
    var badge = $v('vaultStateBadge');
    if (s.remote_disabled) {
      badge.className = 'badge badge-danger'; badge.textContent = 'disabled';
      $v('vaultStatusText').textContent = 'Vault is disabled while --allow-remote is enabled.';
      hide($v('vaultCreateBlock')); hide($v('vaultUnlockBlock')); hide($v('vaultOpenBlock')); hide($v('vaultLockBtn'));
    } else if (!s.exists) {
      badge.className = 'badge badge-secondary'; badge.textContent = 'no vault';
      $v('vaultStatusText').textContent = 'Not created — using a vault is optional.';
      show($v('vaultCreateBlock')); hide($v('vaultUnlockBlock')); hide($v('vaultOpenBlock')); hide($v('vaultLockBtn'));
    } else if (!s.unlocked) {
      badge.className = 'badge badge-warning'; badge.textContent = 'locked';
      $v('vaultStatusText').textContent = 'Vault exists at ' + s.path;
      hide($v('vaultCreateBlock')); show($v('vaultUnlockBlock')); hide($v('vaultOpenBlock')); hide($v('vaultLockBtn'));
      setVaultEntriesAccordion(false);
    } else {
      badge.className = 'badge badge-success'; badge.textContent = 'unlocked';
      $v('vaultStatusText').textContent = s.entry_count + ' entr' + (s.entry_count === 1 ? 'y' : 'ies') + ' · auto-locks after 60 min idle';
      hide($v('vaultCreateBlock')); hide($v('vaultUnlockBlock')); show($v('vaultOpenBlock')); show($v('vaultLockBtn'));
    }
    var cipherBadge = $v('vaultCipherBadge');
    if (cipherBadge) {
      if (s.remote_disabled) {
        hide(cipherBadge);
      } else if (s.exists) {
        show(cipherBadge);
        if (s.cipher === 'aes-256-gcm') {
          cipherBadge.className = 'badge badge-info';
          cipherBadge.textContent = 'AES-256-GCM';
          cipherBadge.title = 'Vault is encrypted with AES-256-GCM';
        } else {
          cipherBadge.className = 'badge badge-secondary';
          cipherBadge.textContent = 'HMAC-SHA256 (Stdlib)';
          cipherBadge.title = 'Vault is encrypted with stdlib HMAC-SHA256-CTR + EtM';
        }
      } else {
        show(cipherBadge);
        if (s.aes_available) {
          cipherBadge.className = 'badge badge-info';
          cipherBadge.textContent = 'AES-256-GCM Ready';
          cipherBadge.title = 'pycryptodomex is installed: new vault will use AES-256-GCM';
        } else {
          cipherBadge.className = 'badge badge-secondary';
          cipherBadge.textContent = 'Stdlib Mode';
          cipherBadge.title = 'pycryptodomex is not installed: new vault will use stdlib HMAC-SHA256';
        }
      }
    }
    var countBadge = $v('vaultEntriesCountBadge');
    if (countBadge && typeof s.entry_count === 'number') countBadge.textContent = s.entry_count;
    $v('vaultPathText').textContent = s.path || '';
    // Scan checkbox: only usable while unlocked. Never auto-check it.
    var chk = $v('useVaultChk');
    chk.disabled = !s.unlocked;
    if (!s.unlocked) chk.checked = false;
    $v('useVaultHint').textContent = s.unlocked
      ? '(' + s.entry_count + ' entries; username/password above become the fallback for unmatched hosts)'
      : '(off — create or unlock a vault below)';
    syncUseVaultUi();
  }

  function refreshVaultStatus() {
    return getJson('/api/vault/status').then(function(r) {
      if (r.status === 403) { _vaultState = {remote_disabled:true}; }
      else if (r.status === 200) { _vaultState = r.data; }
      renderVaultState();
      if (_vaultState.unlocked) refreshVaultEntries();
    }).catch(function() {});
  }

  function refreshVaultEntries() {
    return getJson('/api/vault/entries').then(function(r) {
      var tb = $v('vaultTableBody');
      tb.innerHTML = '';
      if (r.status !== 200) { if (r.status === 423) refreshVaultStatus(); return; }
      var rows = r.data.entries || [];
      var badge = $v('vaultEntriesCountBadge');
      if (badge) badge.textContent = rows.length;
      if (!rows.length) {
        tb.innerHTML = '<tr><td colspan="5" class="text-muted">Vault is empty — add an entry or import a CSV below.</td></tr>';
      }
      rows.forEach(function(e) {
        var kindCls = e.kind === 'exact' ? 'badge-info' : (e.kind === 'cidr' ? 'badge-secondary' : 'badge-warning');
        var tr = document.createElement('tr');
        tr.innerHTML = '<td><code>' + esc(e.target) + '</code></td>'
          + '<td><span class="badge ' + kindCls + '">' + esc(e.kind) + '</span></td>'
          + '<td>' + esc(e.username) + '</td><td class="text-muted">' + esc(e.note) + '</td>'
          + '<td><button class="btn btn-flat btn-sm vault-rm" data-target="' + esc(e.target) + '">Remove</button></td>';
        tb.appendChild(tr);
      });
      _vaultState.entry_count = rows.length;
      renderVaultState();
      updateVaultCoverage();
    }).catch(function() {});
  }

  $v('vaultTableBody').addEventListener('click', function(ev) {
    var btn = ev.target.closest('.vault-rm');
    if (!btn) return;
    var t = btn.dataset.target;
    if (!confirm('Remove vault entry for ' + t + '?')) return;
    postJson('/api/vault/remove', {target: t}).then(function(r) {
      vaultMsg(r.status === 200 ? 'Removed ' + t : (r.data.error || 'Remove failed'), r.status !== 200);
      refreshVaultEntries();
    });
  });

  $v('vaultCreateBtn').addEventListener('click', function() {
    var p1 = $v('vaultNewPass1').value, p2 = $v('vaultNewPass2').value;
    if (p1.length < 12) { vaultMsg('Passphrase must be at least 12 characters.', true); return; }
    if (p1 !== p2) { vaultMsg('Passphrases do not match.', true); return; }
    postJson('/api/vault/create', {passphrase: p1}).then(function(r) {
      $v('vaultNewPass1').value = ''; $v('vaultNewPass2').value = '';
      if (r.status === 200) {
        vaultMsg('Vault created and unlocked.');
        _vaultState = r.data;
        setVaultEntriesAccordion(false);
        renderVaultState();
        refreshVaultEntries();
      } else vaultMsg(r.data.error || ('Create failed (HTTP ' + r.status + ')'), true);
    });
  });

  $v('vaultUnlockBtn').addEventListener('click', function() {
    var p = $v('vaultUnlockPass').value;
    if (!p) return;
    $v('vaultUnlockBtn').disabled = true;
    postJson('/api/vault/unlock', {passphrase: p}).then(function(r) {
      $v('vaultUnlockBtn').disabled = false;
      $v('vaultUnlockPass').value = '';
      if (r.status === 200) {
        vaultMsg('Vault unlocked.');
        _vaultState = r.data;
        setVaultEntriesAccordion(false);
        renderVaultState();
        refreshVaultEntries();
      } else vaultMsg(r.data.error || ('Unlock failed (HTTP ' + r.status + ')'), true);
    });
  });
  $v('vaultUnlockPass').addEventListener('keydown', function(e) { if (e.key === 'Enter') $v('vaultUnlockBtn').click(); });

  $v('vaultLockBtn').addEventListener('click', function() {
    postJson('/api/vault/lock', {}).then(function(r) {
      vaultMsg('Vault locked.');
      _vaultState = (r.status === 200) ? r.data : {exists:true, unlocked:false, path:_vaultState.path};
      setVaultEntriesAccordion(false);
      renderVaultState();
    });
  });

  $v('vaultAddBtn').addEventListener('click', function() {
    var body = {target: $v('vaultAddTarget').value.trim(), username: $v('vaultAddUser').value.trim(),
                password: $v('vaultAddPass').value, note: $v('vaultAddNote').value.trim()};
    if (!body.target || !body.username || !body.password) { vaultMsg('Target, username and password are required.', true); return; }
    postJson('/api/vault/entries', body).then(function(r) {
      if (r.status === 200) {
        vaultMsg('Saved ' + (r.data.written || []).length + ' entr' + ((r.data.written || []).length === 1 ? 'y' : 'ies') + '.');
        $v('vaultAddTarget').value = ''; $v('vaultAddPass').value = ''; $v('vaultAddNote').value = '';
        refreshVaultEntries();
      } else vaultMsg(r.data.error || ('Save failed (HTTP ' + r.status + ')'), true);
    });
  });

  $v('vaultCsvChooseBtn').addEventListener('click', function() { $v('vaultCsvInput').click(); });
  $v('vaultCsvInput').addEventListener('change', function() {
    var f = this.files && this.files[0];
    if (!f) return;
    if (f.size > 2000000) { vaultMsg('CSV too large (2 MB limit).', true); return; }
    var reader = new FileReader();
    reader.onload = function(e) {
      $v('vaultCsvText').value = e.target.result || '';
      $v('vaultCsvFileName').textContent = f.name + ' (' + f.size + ' bytes) loaded into the box — review, then Import.';
    };
    reader.readAsText(f);
    this.value = '';
  });

  $v('vaultCsvTemplateBtn').addEventListener('click', function() {
    var tpl = 'target,username,password,note\\n'
      + '192.0.2.10,root,CHANGE_ME,exact host\\n'
      + 'idrac-r740-01.rainpole.net,root,CHANGE_ME,hostname entry\\n'
      + '192.0.2.0/24,admin,CHANGE_ME,whole rack (CIDR)\\n'
      + '198.51.100.10-20,root,CHANGE_ME,IPv4 range (expanded on import)\\n'
      + 'default,root,CHANGE_ME,fallback for everything else\\n';
    var blob = new Blob([tpl], {type: 'text/csv'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'vcf-credentials-template.csv';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function() { URL.revokeObjectURL(a.href); }, 1000);
  });

  $v('vaultCsvImportBtn').addEventListener('click', function() {
    var text = $v('vaultCsvText').value;
    if (!text.trim()) { vaultMsg('Paste CSV text or choose a file first.', true); return; }
    var replace = $v('vaultCsvReplace').checked;
    if (replace && !confirm('Replace ALL existing vault entries with this CSV?')) return;
    var out = $v('vaultImportResult');
    postJson('/api/vault/import-csv', {csv_text: text, replace: replace, skip_invalid: $v('vaultCsvSkipInvalid').checked})
      .then(function(r) {
        var d = r.data || {};
        var lines = [];
        if (r.status === 200) lines.push('✔ Imported ' + d.imported + ', skipped ' + d.skipped + '.');
        else lines.push('✗ ' + (d.error || ('Import failed (HTTP ' + r.status + ')')));
        (d.warnings || []).forEach(function(w) { lines.push('  ! ' + w); });
        (d.errors || []).forEach(function(e) { lines.push('  ✗ ' + e); });
        out.textContent = lines.join('\\n');
        out.style.color = r.status === 200 ? 'var(--vcf-success)' : 'var(--vcf-danger)';
        show(out);
        if (r.status === 200) { $v('vaultCsvText').value = ''; $v('vaultCsvFileName').textContent = ''; $v('vaultCsvReplace').checked = false; refreshVaultEntries(); }
        else if (r.status === 423) refreshVaultStatus();
      });
  });

  // Scan-time switch: hides per-host inputs, shows coverage preview.
  function syncUseVaultUi() {
    var on = $v('useVaultChk').checked && !$v('useVaultChk').disabled;
    if (on) {
      hide($v('perHostCreds'));
      show($v('sharedCreds'));
      sameChk.disabled = true;
    } else {
      sameChk.disabled = false;
      syncCredMode();
      hide($v('vaultCoverage'));
    }
    if (on) updateVaultCoverage();
  }
  $v('useVaultChk').addEventListener('change', syncUseVaultUi);

  function currentTargetsForCoverage() {
    var checked = Array.from(document.querySelectorAll('.host-chk:checked')).map(function(c){ return c.dataset.ip; });
    if (checked.length) return checked;
    return document.getElementById('rangeInput').value.trim();
  }
  function updateVaultCoverage() {
    var chk = $v('useVaultChk');
    if (!chk.checked || chk.disabled) return;
    var targets = currentTargetsForCoverage();
    var el = $v('vaultCoverage');
    if (!targets || !targets.length) { hide(el); return; }
    postJson('/api/vault/coverage', {targets: targets}).then(function(r) {
      if (r.status !== 200) { hide(el); if (r.status === 423) refreshVaultStatus(); return; }
      var d = r.data;
      var txt = 'Vault coverage: ' + d.matched + ' of ' + d.total + ' target(s) (exact ' + d.exact + ' · CIDR ' + d.cidr + ' · default ' + d.default + ')';
      if (d.unmatched && d.unmatched.length) {
        var pw = document.getElementById('passwordInput').value;
        txt += ' — ' + d.unmatched.length + ' unmatched: ' + d.unmatched.slice(0, 6).join(', ') + (d.unmatched.length > 6 ? '…' : '');
        txt += pw ? ' (will use the username/password above)' : ' (will be SKIPPED unless you enter a fallback password above)';
      }
      el.textContent = txt;
      show(el);
    });
  }
  document.getElementById('rangeInput').addEventListener('change', updateVaultCoverage);
  document.getElementById('passwordInput').addEventListener('input', function() { if ($v('useVaultChk').checked) updateVaultCoverage(); });
  document.getElementById('hostList').addEventListener('change', updateVaultCoverage);

  // Initial, silent status probe so the scan checkbox reflects reality (no vault I/O beyond a stat()).
  refreshVaultStatus();

  document.getElementById('dellSaveCredsBtn').addEventListener('click', function() {
    var id  = document.getElementById('dellIdInput').value.trim();
    var sec = document.getElementById('dellSecretInput').value.trim();
    if (!id || !sec) { alert('Enter Client ID and Secret first.'); return; }
    Promise.all([
      post('/api/keychain/store', {key:'dell-techdirect-id',     value:id}),
      post('/api/keychain/store', {key:'dell-techdirect-secret', value:sec}),
    ]).then(function(results) {
      var err = results.find(function(r) { return r && r.ok === false; });
      if (err) {
        alert('Keychain save failed: ' + (err.error || 'Unknown error'));
      } else {
        alert('Dell TechDirect credentials saved to keychain.');
      }
    }).catch(function(e) {
      alert('Keychain save error: ' + e);
    });
  });

  document.getElementById('dellLoadCredsBtn').addEventListener('click', function() {
    Promise.all([
      post('/api/keychain/retrieve', {key:'dell-techdirect-id'}),
      post('/api/keychain/retrieve', {key:'dell-techdirect-secret'}),
    ]).then(function(results) {
      var rId = results[0];
      var rSec = results[1];
      if (rId && rId.value) document.getElementById('dellIdInput').value = rId.value;
      if (rSec && rSec.value) document.getElementById('dellSecretInput').value = rSec.value;
      if ((!rId || !rId.value) && (!rSec || !rSec.value)) {
        alert('No saved Dell TechDirect credentials found in keychain.');
      }
    }).catch(function(e) {
      alert('Keychain load error: ' + e);
    });
  });

"""
