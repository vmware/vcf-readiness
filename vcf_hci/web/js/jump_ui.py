"""Jump-host panel and scan-target toggle. Concatenated inside the web UI IIFE."""

JS_JUMP = r"""
  // ── Jump hosts (remote execution) ─────────────────────────────────────────
  var jumpConnStatus = {};
  var jumpHostNotes = {};
  var jumpHostProfiles = {};
  var editingJumpId = null;
  var currentSubnetsJumpId = null;
  var currentSubnetsList = [];

  function jumpMsg(text, isErr) {
    var el = document.getElementById('jumpMsg');
    if (!el) return;
    el.textContent = text || '';
    el.classList.toggle('hidden', !text);
    el.style.color = isErr ? 'var(--vcf-danger, #c21d00)' : 'var(--vcf-success, #2f8400)';
  }

  function renderJumpConnHtml(id, note) {
    var st = jumpConnStatus[id];
    var out = '';
    if (st && st.state === 'testing') {
      out = '<span class="badge badge-info" style="font-size:0.72rem;">● Testing…</span>';
    } else if (st && st.ok) {
      var py = st.python_version ? (st.python_version.indexOf('Python') >= 0 ? st.python_version : 'Python ' + st.python_version) : '';
      var gb = st.free_gb ? (String(st.free_gb).indexOf('free') >= 0 ? st.free_gb : st.free_gb + ' free') : '';
      var detail = py + (py && gb ? ' · ' : '') + gb;
      var title = st.message || (id + ' reachable');
      out = '<div style="display:inline-flex;align-items:center;gap:6px;flex-wrap:wrap;" title="' + esc(title) + '">' +
            '<span class="badge badge-success" style="font-size:0.72rem;">● Reachable</span>' +
            (detail ? '<span class="text-xs text-muted" style="white-space:nowrap;">' + esc(detail) + '</span>' : '') +
            '</div>';
    } else if (st && st.ok === false) {
      var cat = st.category || '';
      var shortErr = 'Failed';
      if (cat === 'auth') shortErr = 'Auth failed';
      else if (cat === 'timeout') shortErr = 'Timed out';
      else if (cat === 'refused') shortErr = 'Connection refused';
      else if (cat === 'network') shortErr = 'No route to host';
      else if (cat === 'dns') shortErr = 'DNS unresolved';
      else if (cat === 'host_key') shortErr = 'Host key mismatch';
      else if (cat === 'python_version') shortErr = 'Python < 3.9';
      else if (cat === 'disk_space') shortErr = 'Low disk space';
      else if (st.error) {
        var cleanErr = String(st.error).replace(/^Error:\s*/i, '');
        shortErr = cleanErr.length > 25 ? cleanErr.slice(0, 25) + '…' : cleanErr;
      }
      var fullTitle = (st.error || 'Connection failed') + (st.troubleshooting ? ' — ' + st.troubleshooting : '');
      out = '<div style="display:inline-flex;align-items:center;gap:6px;flex-wrap:wrap;" title="' + esc(fullTitle) + '">' +
            '<span class="badge badge-danger" style="font-size:0.72rem;">● Failed</span>' +
            '<span class="text-xs" style="color:var(--vcf-danger, #f88);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(shortErr) + '</span>' +
            '</div>';
    } else {
      out = '<span class="text-xs text-muted">Not tested</span>';
    }
    var n = (note != null) ? note : (jumpHostNotes[id] || '');
    if (n) {
      out += '<div class="text-xs text-muted" style="margin-top:2px;font-style:italic;" title="Note: ' + esc(n) + '">' + esc(n) + '</div>';
    }
    return out;
  }

  function updateJumpConnCell(id, note) {
    var cell = document.getElementById('jump-conn-' + id);
    if (cell) {
      cell.innerHTML = renderJumpConnHtml(id, note);
    }
  }

  // ── Jump Host TOFU (Trust-On-First-Use) Host Key Pinning ─────────────────
  var pendingProbeData = null;
  var pendingTofuCallback = null;

  function showJumpHostKeyModal(probeData, onAccept) {
    pendingProbeData = probeData;
    pendingTofuCallback = onAccept;

    var modal = document.getElementById('jumpHostKeyModal');
    var hostEl = document.getElementById('jumpKeyModalHost');
    var typeEl = document.getElementById('jumpKeyModalType');
    var fpEl = document.getElementById('jumpKeyModalFingerprint');
    var statusEl = document.getElementById('jumpKeyModalStatus');
    var warnEl = document.getElementById('jumpKeyModalWarning');
    if (!modal) return;

    if (hostEl) hostEl.textContent = (probeData.host || '') + ':' + (probeData.port || 22);
    if (typeEl) typeEl.textContent = probeData.key_type || 'Unknown';
    if (fpEl) fpEl.textContent = probeData.fingerprint || 'None';

    if (warnEl) warnEl.classList.add('hidden');

    if (statusEl) {
      if (probeData.is_pinned && !probeData.fingerprint_matches) {
        statusEl.innerHTML = '<span class="badge badge-danger">Mismatch (Previously: ' + esc(probeData.pinned_fingerprint || '') + ')</span>';
        if (warnEl) warnEl.classList.remove('hidden');
      } else if (probeData.is_pinned && probeData.fingerprint_matches) {
        statusEl.innerHTML = '<span class="badge badge-success">Verified &amp; Pinned</span>';
      } else {
        statusEl.innerHTML = '<span class="badge badge-info">New Host (Unverified)</span>';
      }
    }

    modal.classList.remove('hidden');
  }

  function hideJumpHostKeyModal() {
    var modal = document.getElementById('jumpHostKeyModal');
    if (modal) modal.classList.add('hidden');
    pendingProbeData = null;
    pendingTofuCallback = null;
  }

  var closeJumpKeyBtn = document.getElementById('closeJumpHostKeyModalBtn');
  var cancelJumpKeyBtn = document.getElementById('cancelJumpHostKeyModalBtn');
  var acceptJumpKeyBtn = document.getElementById('acceptJumpHostKeyBtn');

  if (closeJumpKeyBtn) closeJumpKeyBtn.addEventListener('click', hideJumpHostKeyModal);
  if (cancelJumpKeyBtn) cancelJumpKeyBtn.addEventListener('click', hideJumpHostKeyModal);
  if (acceptJumpKeyBtn) {
    acceptJumpKeyBtn.addEventListener('click', function() {
      if (!pendingProbeData) {
        hideJumpHostKeyModal();
        return;
      }
      var rawInput = document.getElementById('jumpHostKeyRaw');
      var dispInput = document.getElementById('jumpHostKey');
      if (rawInput) rawInput.value = pendingProbeData.public_key || '';
      if (dispInput) {
        var ktype = (pendingProbeData.key_type || 'SSH').replace(/^ssh-/, '').toUpperCase();
        dispInput.value = ktype + ' (' + (pendingProbeData.fingerprint || '') + ')';
      }
      var cb = pendingTofuCallback;
      var data = pendingProbeData;
      hideJumpHostKeyModal();
      if (typeof cb === 'function') {
        cb(data);
      }
    });
  }

  var jumpProbeKeyBtn = document.getElementById('jumpProbeKeyBtn');
  if (jumpProbeKeyBtn) {
    jumpProbeKeyBtn.addEventListener('click', function() {
      var host = (document.getElementById('jumpHost').value || '').trim();
      var port = parseInt(document.getElementById('jumpPort').value, 10) || 22;
      var jumpId = (document.getElementById('jumpId').value || '').trim();
      if (!host) {
        jumpMsg('Enter a jump host IP or hostname to probe its SSH key.', true);
        return;
      }
      jumpProbeKeyBtn.disabled = true;
      jumpProbeKeyBtn.textContent = 'Probing…';
      jumpMsg('Probing SSH host key on ' + host + ':' + port + ' (no credentials sent)…', false);
      postJson('/api/vault/jump-hosts/probe-key', {host: host, port: port, id: jumpId}).then(function(r) {
        jumpProbeKeyBtn.disabled = false;
        jumpProbeKeyBtn.textContent = 'Probe Key';
        var d = (r && r.data) ? r.data : (r || {});
        var isOk = (r && (r.status === 200 || (!r.status && r.ok))) && (d.ok !== false);
        if (isOk) {
          jumpMsg('SSH host key retrieved. Please review and pin fingerprint.', false);
          showJumpHostKeyModal(d, function(accepted) {
            jumpMsg('Host key pinned: ' + accepted.fingerprint, false);
          });
        } else {
          var errMsg = d.error || ('Host key probe failed (HTTP ' + (r.status || 'unknown') + ')');
          if (d.troubleshooting) errMsg += ' — ' + d.troubleshooting;
          jumpMsg(errMsg, true);
        }
      }).catch(function(e) {
        jumpProbeKeyBtn.disabled = false;
        jumpProbeKeyBtn.textContent = 'Probe Key';
        jumpMsg('Error probing host key: ' + (e.message || e), true);
      });
    });
  }

  // ── Jump host subnets modal ──────────────────────────────────────────────
  function renderSubnetsModalPills() {
    var listEl = document.getElementById('jumpSubnetsModalList');
    var emptyEl = document.getElementById('jumpSubnetsModalEmpty');
    if (!listEl) return;
    listEl.innerHTML = '';
    if (!currentSubnetsList.length) {
      if (emptyEl) emptyEl.classList.remove('hidden');
      return;
    }
    if (emptyEl) emptyEl.classList.add('hidden');
    currentSubnetsList.forEach(function(s, idx) {
      var pill = document.createElement('span');
      pill.className = 'badge badge-secondary';
      pill.style.cssText = 'font-size:0.8rem;padding:4px 8px;display:inline-flex;align-items:center;gap:6px;';
      pill.innerHTML = '<code>' + esc(s) + '</code> <button type="button" data-action="remove-modal-subnet" data-index="' + idx + '" style="background:none;border:none;color:inherit;cursor:pointer;font-weight:bold;font-size:0.9rem;padding:0;line-height:1;" title="Remove subnet">✕</button>';
      listEl.appendChild(pill);
    });
  }

  function openJumpSubnetsModal(jumpId) {
    var prof = jumpHostProfiles[jumpId];
    if (!prof) return;
    currentSubnetsJumpId = jumpId;
    currentSubnetsList = (prof.subnets || []).slice();
    var hostIdEl = document.getElementById('jumpSubnetsModalHostId');
    if (hostIdEl) hostIdEl.textContent = jumpId + ' (' + (prof.username || '') + '@' + (prof.host || '') + ')';
    var inp = document.getElementById('jumpSubnetsModalInput');
    if (inp) inp.value = '';
    var msg = document.getElementById('jumpSubnetsModalMsg');
    if (msg) { msg.textContent = ''; msg.className = 'text-sm hidden'; }
    renderSubnetsModalPills();
    var modal = document.getElementById('jumpHostSubnetsModal');
    if (modal) modal.classList.remove('hidden');
  }

  function closeJumpSubnetsModal() {
    var modal = document.getElementById('jumpHostSubnetsModal');
    if (modal) modal.classList.add('hidden');
    currentSubnetsJumpId = null;
    currentSubnetsList = [];
  }

  function addSubnetsFromModalInput() {
    var inp = document.getElementById('jumpSubnetsModalInput');
    if (!inp) return;
    var raw = inp.value.trim();
    if (!raw) return;
    var parts = raw.split(/[;,\s]+/);
    parts.forEach(function(part) {
      var p = part.trim();
      if (!p) return;
      if (currentSubnetsList.indexOf(p) === -1) {
        currentSubnetsList.push(p);
      }
    });
    inp.value = '';
    renderSubnetsModalPills();
  }

  var closeJumpSubnetsBtn = document.getElementById('closeJumpHostSubnetsModalBtn');
  if (closeJumpSubnetsBtn) closeJumpSubnetsBtn.addEventListener('click', closeJumpSubnetsModal);
  var cancelJumpSubnetsBtn = document.getElementById('cancelJumpHostSubnetsModalBtn');
  if (cancelJumpSubnetsBtn) cancelJumpSubnetsBtn.addEventListener('click', closeJumpSubnetsModal);

  var subnetsListEl = document.getElementById('jumpSubnetsModalList');
  if (subnetsListEl) {
    subnetsListEl.addEventListener('click', function(ev) {
      var rmBtn = ev.target.closest('[data-action="remove-modal-subnet"]');
      if (!rmBtn) return;
      var idx = parseInt(rmBtn.getAttribute('data-index'), 10);
      if (!isNaN(idx) && idx >= 0 && idx < currentSubnetsList.length) {
        currentSubnetsList.splice(idx, 1);
        renderSubnetsModalPills();
      }
    });
  }

  var modalAddBtn = document.getElementById('jumpSubnetsModalAddBtn');
  if (modalAddBtn) modalAddBtn.addEventListener('click', addSubnetsFromModalInput);
  var modalSubnetInp = document.getElementById('jumpSubnetsModalInput');
  if (modalSubnetInp) {
    modalSubnetInp.addEventListener('keydown', function(ev) {
      if (ev.key === 'Enter') {
        ev.preventDefault();
        addSubnetsFromModalInput();
      }
    });
  }

  var saveSubnetsBtn = document.getElementById('saveJumpHostSubnetsModalBtn');
  if (saveSubnetsBtn) {
    saveSubnetsBtn.addEventListener('click', function() {
      if (!currentSubnetsJumpId) return;
      var saveId = currentSubnetsJumpId;
      saveSubnetsBtn.disabled = true;
      var msgEl = document.getElementById('jumpSubnetsModalMsg');
      if (msgEl) { msgEl.textContent = 'Saving subnets…'; msgEl.className = 'text-sm'; }
      postJson('/api/vault/jump-hosts/subnets', {
        id: saveId,
        subnets: currentSubnetsList,
        action: 'replace'
      }).then(function(r) {
        saveSubnetsBtn.disabled = false;
        var d = (r && r.data) ? r.data : (r || {});
        var isOk = (r && (r.status === 200 || (!r.status && r.ok))) && (d.ok !== false);
        if (isOk) {
          closeJumpSubnetsModal();
          jumpMsg('Updated subnets for jump host ' + saveId + ' (' + currentSubnetsList.length + ' subnet' + (currentSubnetsList.length === 1 ? '' : 's') + ').', false);
          refreshJumpHosts();
        } else {
          if (msgEl) {
            msgEl.textContent = d.error || ('Failed to save subnets (HTTP ' + (r.status || 'unknown') + ')');
            msgEl.className = 'text-sm text-danger';
          }
        }
      }).catch(function(err) {
        saveSubnetsBtn.disabled = false;
        if (msgEl) {
          msgEl.textContent = 'Error: ' + (err.message || err);
          msgEl.className = 'text-sm text-danger';
        }
      });
    });
  }

  // ── Jump host form edit mode ──────────────────────────────────────────────
  function cancelJumpEdit() {
    editingJumpId = null;
    var idInput = document.getElementById('jumpId');
    if (idInput) {
      idInput.value = '';
      idInput.readOnly = false;
    }
    var hostInput = document.getElementById('jumpHost');
    if (hostInput) hostInput.value = '';
    var portInput = document.getElementById('jumpPort');
    if (portInput) portInput.value = '22';
    var userInput = document.getElementById('jumpUser');
    if (userInput) userInput.value = 'ubuntu';
    var authInput = document.getElementById('jumpAuth');
    if (authInput) authInput.value = 'key';
    var keyPathInput = document.getElementById('jumpKeyPath');
    if (keyPathInput) keyPathInput.value = '';
    var subnetsInput = document.getElementById('jumpSubnets');
    if (subnetsInput) subnetsInput.value = '';
    var noteInput = document.getElementById('jumpNote');
    if (noteInput) noteInput.value = '';
    var defaultInput = document.getElementById('jumpDefault');
    if (defaultInput) defaultInput.checked = false;
    var privKeyInput = document.getElementById('jumpPrivateKey');
    if (privKeyInput) {
      privKeyInput.value = '';
      privKeyInput.placeholder = '';
    }
    var passInput = document.getElementById('jumpPassword');
    if (passInput) {
      passInput.value = '';
      passInput.placeholder = '';
    }
    var rawKeyEl = document.getElementById('jumpHostKeyRaw');
    if (rawKeyEl) rawKeyEl.value = '';
    var dispKeyEl = document.getElementById('jumpHostKey');
    if (dispKeyEl) dispKeyEl.value = '';
    var editBanner = document.getElementById('jumpEditBanner');
    if (editBanner) editBanner.classList.add('hidden');
    var saveBtn = document.getElementById('jumpSaveBtn');
    if (saveBtn) saveBtn.textContent = 'Save jump host';
    var cancelBtn = document.getElementById('jumpCancelEditBtn');
    if (cancelBtn) cancelBtn.classList.add('hidden');
    updateJumpAuthVisibility();
  }

  function startJumpEdit(jumpId) {
    var prof = jumpHostProfiles[jumpId];
    if (!prof) return;
    editingJumpId = jumpId;
    var idInput = document.getElementById('jumpId');
    if (idInput) {
      idInput.value = prof.id;
      idInput.readOnly = true;
    }
    var hostInput = document.getElementById('jumpHost');
    if (hostInput) hostInput.value = prof.host || '';
    var portInput = document.getElementById('jumpPort');
    if (portInput) portInput.value = prof.port || 22;
    var userInput = document.getElementById('jumpUser');
    if (userInput) userInput.value = prof.username || '';
    var authInput = document.getElementById('jumpAuth');
    if (authInput) authInput.value = prof.auth_type || 'key';
    var keyPathInput = document.getElementById('jumpKeyPath');
    if (keyPathInput) keyPathInput.value = prof.key_path || '';
    var subnetsInput = document.getElementById('jumpSubnets');
    if (subnetsInput) subnetsInput.value = (prof.subnets || []).join(', ');
    var noteInput = document.getElementById('jumpNote');
    if (noteInput) noteInput.value = prof.note || '';
    var defaultInput = document.getElementById('jumpDefault');
    if (defaultInput) defaultInput.checked = !!prof.is_default;
    var privKeyInput = document.getElementById('jumpPrivateKey');
    if (privKeyInput) {
      privKeyInput.value = '';
      privKeyInput.placeholder = prof.has_private_key ? '(Stored in vault — leave blank to keep unchanged)' : '';
    }
    var passInput = document.getElementById('jumpPassword');
    if (passInput) {
      passInput.value = '';
      passInput.placeholder = prof.has_password ? '(Stored in vault — leave blank to keep unchanged)' : '';
    }
    var rawKeyEl = document.getElementById('jumpHostKeyRaw');
    if (rawKeyEl) rawKeyEl.value = prof.host_key || '';
    var dispKeyEl = document.getElementById('jumpHostKey');
    if (dispKeyEl) dispKeyEl.value = prof.host_key_fingerprint ? (prof.host_key_fingerprint + ' (' + (prof.host_key_type || 'SSH') + ')') : '';

    var editBanner = document.getElementById('jumpEditBanner');
    var editIdEl = document.getElementById('jumpEditingId');
    if (editIdEl) editIdEl.textContent = prof.id;
    if (editBanner) editBanner.classList.remove('hidden');

    var saveBtn = document.getElementById('jumpSaveBtn');
    if (saveBtn) saveBtn.textContent = 'Update jump host';
    var cancelBtn = document.getElementById('jumpCancelEditBtn');
    if (cancelBtn) cancelBtn.classList.remove('hidden');

    updateJumpAuthVisibility();
    if (idInput && idInput.scrollIntoView) {
      idInput.scrollIntoView({behavior: 'smooth', block: 'center'});
    }
  }

  var cancelTopBtn = document.getElementById('jumpCancelEditTopBtn');
  if (cancelTopBtn) cancelTopBtn.addEventListener('click', cancelJumpEdit);
  var cancelBottomBtn = document.getElementById('jumpCancelEditBtn');
  if (cancelBottomBtn) cancelBottomBtn.addEventListener('click', cancelJumpEdit);

  function updateJumpAuthVisibility() {
    var auth = document.getElementById('jumpAuth');
    var isPass = auth && auth.value === 'password';
    var keyLabel = document.getElementById('jumpKeyPathLabel');
    var privLabel = document.getElementById('jumpPrivKeyLabel');
    var passLabel = document.getElementById('jumpPasswordLabel');
    if (keyLabel) keyLabel.textContent = isPass ? 'Key path (optional with password)' : 'Key path';
    if (privLabel) privLabel.textContent = isPass ? 'Private key (optional)' : 'Private key (optional, stored encrypted)';
    if (passLabel) passLabel.textContent = isPass ? 'SSH password (required for password auth)' : 'SSH password (optional)';
  }

  function refreshJumpHosts() {
    var body = document.getElementById('jumpHostBody');
    var select = document.getElementById('jumpHostSelect');
    var hint = document.getElementById('jumpSelectHint');
    if (!body) return;
    getJson('/api/vault/jump-hosts').then(function(r) {
      body.innerHTML = '';
      var d = (r && r.data) ? r.data : (r || {});
      var isOk = (r && (r.status === 200 || (!r.status && r.ok))) && (d.ok !== false);
      var hosts = d.jump_hosts || [];
      if (select) {
        var current = select.value;
        select.innerHTML = '<option value="auto">Auto-route by subnet</option>';
        hosts.forEach(function(row) {
          var opt = document.createElement('option');
          opt.value = row.id;
          opt.textContent = row.id + ' (' + row.username + '@' + row.host + ')';
          select.appendChild(opt);
        });
        if (current) select.value = current;
      }
      if (hint) {
        if (r && r.status === 423) {
          var vs = (typeof _vaultState !== 'undefined') ? _vaultState : null;
          var actType = (vs && !vs.exists) ? 'create' : 'unlock';
          var actLabel = (vs && !vs.exists) ? 'Create vault below &rarr;' : 'Unlock vault below &rarr;';
          hint.innerHTML = '⚠ Credential vault is ' + ((vs && !vs.exists) ? 'not created' : 'locked') + '. <a href="#" class="jump-vault-anchor-link" data-action="' + actType + '" style="color:inherit;font-weight:600;text-decoration:underline;">' + actLabel + '</a>';
          hint.style.color = 'var(--vcf-danger, #c21d00)';
          hint.classList.remove('hidden');
        } else if (!isOk) {
          hint.textContent = '⚠ ' + (d.error || 'Jump hosts unavailable');
          hint.style.color = 'var(--vcf-danger, #c21d00)';
          hint.classList.remove('hidden');
        } else if (hosts.length === 0) {
          hint.innerHTML = '⚠ No jump hosts configured in vault. <a href="#" class="jump-vault-anchor-link" data-action="add" style="color:inherit;font-weight:600;text-decoration:underline;">Add a jump host profile below &rarr;</a>';
          hint.style.color = 'var(--vcf-warning, #d9822b)';
          hint.classList.remove('hidden');
        } else {
          hint.textContent = '✔ ' + hosts.length + ' jump host profile(s) ready in vault.';
          hint.style.color = 'var(--vcf-success, #2f8400)';
          hint.classList.remove('hidden');
        }
      }
      updateJumpTargetHint(isOk ? hosts.length : null, r && r.status === 423);
      if (!isOk) {
        jumpMsg(d.error || ('Jump hosts unavailable (HTTP ' + (r.status || 'unknown') + ')'), true);
        return;
      }
      if (hosts.length === 0) {
        var emptyTr = document.createElement('tr');
        emptyTr.innerHTML = '<td colspan="6" class="text-muted text-xs" style="text-align:center;padding:0.75rem;">No jump hosts configured in vault yet.</td>';
        body.appendChild(emptyTr);
        return;
      }
      jumpHostProfiles = {};
      hosts.forEach(function(row) {
        jumpHostProfiles[row.id] = row;
        jumpHostNotes[row.id] = row.note || '';
        if (row.last_test && !jumpConnStatus[row.id]) {
          jumpConnStatus[row.id] = row.last_test;
        }
        var tr = document.createElement('tr');
        var subnets = (row.subnets || []).join(', ') || (row.is_default ? 'default' : '—');
        var connHtml = renderJumpConnHtml(row.id, row.note);
        var keyHtml = '';
        var isPinned = !!row.host_key_fingerprint;
        if (isPinned) {
          var ktype = (row.host_key_type || 'SSH').replace(/^ssh-/, '').toUpperCase();
          var shortFp = row.host_key_fingerprint.length > 20 ? row.host_key_fingerprint.slice(0, 20) + '…' : row.host_key_fingerprint;
          keyHtml = '<div title="' + esc(row.host_key_fingerprint) + '">' +
            '<span class="badge badge-success" style="font-size:0.7rem;">● Pinned (' + esc(ktype) + ')</span>' +
            '<div class="text-xs text-muted" style="font-family:monospace;font-size:0.68rem;margin-top:2px;">' + esc(shortFp) + '</div>' +
            '</div>';
        } else {
          keyHtml = '<span class="badge badge-warning" style="font-size:0.7rem;">○ Unpinned</span>';
        }
        var pinBtnText = isPinned ? 'Re-pin Key' : 'Pin Key (TOFU)';
        tr.innerHTML = '<td>' + esc(row.id) + '</td><td>' + esc(row.username + '@' + row.host + ':' + row.port) +
          '</td><td>' + esc(subnets) + '</td><td>' + keyHtml + '</td><td id="jump-conn-' + esc(row.id) + '">' + connHtml +
          '</td><td style="white-space:nowrap;"><button type="button" class="btn btn-flat btn-sm" data-jump-subnets="' + esc(row.id) +
          '">Subnets</button> <button type="button" class="btn btn-flat btn-sm" data-jump-edit="' + esc(row.id) +
          '">Edit</button> <button type="button" class="btn btn-flat btn-sm" data-jump-test="' + esc(row.id) +
          '">Test</button> <button type="button" class="btn btn-flat btn-sm" data-jump-probe="' + esc(row.id) +
          '">' + esc(pinBtnText) + '</button> <button type="button" class="btn btn-flat btn-sm" data-jump-remove="' + esc(row.id) +
          '">Remove</button></td>';
        body.appendChild(tr);
      });
    }).catch(function(err) {
      updateJumpTargetHint(null, true);
      jumpMsg('Could not load jump hosts: ' + (err.message || err), true);
    });
  }

  var jumpAuth = document.getElementById('jumpAuth');
  if (jumpAuth) {
    jumpAuth.addEventListener('change', updateJumpAuthVisibility);
    updateJumpAuthVisibility();
  }

  var jumpBody = document.getElementById('jumpHostBody');
  if (jumpBody) {
    jumpBody.addEventListener('click', function(ev) {
      var t = ev.target;
      if (!t || !t.getAttribute) return;
      var subnetsId = t.getAttribute('data-jump-subnets');
      var editId = t.getAttribute('data-jump-edit');
      var testId = t.getAttribute('data-jump-test');
      var removeId = t.getAttribute('data-jump-remove');
      if (subnetsId) {
        openJumpSubnetsModal(subnetsId);
        return;
      }
      if (editId) {
        startJumpEdit(editId);
        return;
      }
      if (testId) {
        jumpConnStatus[testId] = { state: 'testing' };
        updateJumpConnCell(testId);
        jumpMsg('Testing reachability for ' + testId + '…', false);
        t.disabled = true;
        t.textContent = 'Testing…';
        postJson('/api/vault/jump-hosts/test', {id: testId}).then(function(r) {
          t.disabled = false;
          t.textContent = 'Test';
          var d = (r && r.data) ? r.data : (r || {});
          var isOk = (r && (r.status === 200 || (!r.status && r.ok))) && (d.ok !== false);
          if (isOk) {
            var freeGb = d.free_gb != null ? d.free_gb : (d.free_bytes != null ? (d.free_bytes / (1024*1024*1024)).toFixed(2) + ' GiB' : '');
            var pyVer = d.python_version ? ' (Python ' + d.python_version + ')' : '';
            var msg = d.message || (testId + ' reachable' + pyVer + (freeGb ? '. Free /tmp: ' + freeGb : ''));
            jumpConnStatus[testId] = {
              ok: true,
              python_version: d.python_version || '',
              free_gb: freeGb,
              message: msg
            };
            updateJumpConnCell(testId);
            jumpMsg(msg, false);
          } else {
            var errMsg = d.error || ('Test failed (HTTP ' + (r.status || 'unknown') + ')');
            if (d.troubleshooting) errMsg += ' — ' + d.troubleshooting;
            jumpConnStatus[testId] = {
              ok: false,
              category: d.category,
              error: d.error || ('Test failed (HTTP ' + (r.status || 'unknown') + ')'),
              troubleshooting: d.troubleshooting,
              message: errMsg
            };
            updateJumpConnCell(testId);
            jumpMsg(errMsg, true);
          }
        }).catch(function(e) {
          t.disabled = false;
          t.textContent = 'Test';
          var errStr = String(e && (e.message || e));
          jumpConnStatus[testId] = {
            ok: false,
            error: errStr,
            message: errStr
          };
          updateJumpConnCell(testId);
          jumpMsg(errStr, true);
        });
      }
      var probeId = t.getAttribute('data-jump-probe');
      if (probeId) {
        var origText = t.textContent;
        t.disabled = true;
        t.textContent = 'Probing…';
        jumpMsg('Probing host key for ' + probeId + '…', false);
        postJson('/api/vault/jump-hosts/probe-key', {id: probeId}).then(function(r) {
          t.disabled = false;
          t.textContent = origText;
          var d = (r && r.data) ? r.data : (r || {});
          var isOk = (r && (r.status === 200 || (!r.status && r.ok))) && (d.ok !== false);
          if (isOk) {
            showJumpHostKeyModal(d, function(accepted) {
              t.disabled = true;
              t.textContent = 'Pinning…';
              jumpMsg('Saving pinned host key for ' + probeId + '…', false);
              postJson('/api/vault/jump-hosts', {id: probeId, host_key: accepted.public_key}).then(function(sr) {
                t.disabled = false;
                t.textContent = origText;
                var sd = (sr && sr.data) ? sr.data : (sr || {});
                if (sd.ok !== false) {
                  jumpMsg('Pinned host key for ' + probeId + ' (' + accepted.fingerprint + ')', false);
                  refreshJumpHosts();
                } else {
                  jumpMsg(sd.error || 'Failed to save pinned key', true);
                }
              }).catch(function(err) {
                t.disabled = false;
                t.textContent = origText;
                jumpMsg('Error saving host key: ' + (err.message || err), true);
              });
            });
          } else {
            var errMsg = d.error || 'Failed to probe host key';
            if (d.troubleshooting) errMsg += ' — ' + d.troubleshooting;
            jumpMsg(errMsg, true);
          }
        }).catch(function(e) {
          t.disabled = false;
          t.textContent = origText;
          jumpMsg('Probe error: ' + (e.message || e), true);
        });
      }
      if (removeId) {
        t.disabled = true;
        postJson('/api/vault/jump-hosts/remove', {id: removeId}).then(function(r) {
          t.disabled = false;
          var d = (r && r.data) ? r.data : (r || {});
          var isOk = (r && (r.status === 200 || (!r.status && r.ok))) && (d.ok !== false);
          if (isOk) {
            delete jumpConnStatus[removeId];
            delete jumpHostNotes[removeId];
            delete jumpHostProfiles[removeId];
            if (editingJumpId === removeId) cancelJumpEdit();
            jumpMsg('Removed ' + removeId, false);
            refreshJumpHosts();
          } else {
            jumpMsg(d.error || ('Remove failed (HTTP ' + (r.status || 'unknown') + ')'), true);
          }
        }).catch(function(e) {
          t.disabled = false;
          jumpMsg(String(e), true);
        });
      }
    });
  }

  function executeJumpTest(body, formJumpId) {
    jumpMsg('Testing reachability to ' + body.username + '@' + body.host + '…', false);
    jumpTestBtn.disabled = true;
    postJson('/api/vault/jump-hosts/test', body).then(function(r) {
      jumpTestBtn.disabled = false;
      var d = (r && r.data) ? r.data : (r || {});
      var isOk = (r && (r.status === 200 || (!r.status && r.ok))) && (d.ok !== false);
      if (isOk) {
        var freeGb = d.free_gb != null ? d.free_gb : (d.free_bytes != null ? (d.free_bytes / (1024*1024*1024)).toFixed(2) + ' GiB' : '');
        var pyVer = d.python_version ? ' (Python ' + d.python_version + ')' : '';
        var successMsg = d.message || ('Reachability confirmed: connected to ' + body.username + '@' + body.host + pyVer + (freeGb ? '. Free /tmp: ' + freeGb : ''));
        if (formJumpId && document.getElementById('jump-conn-' + formJumpId)) {
          jumpConnStatus[formJumpId] = {
            ok: true,
            python_version: d.python_version || '',
            free_gb: freeGb,
            message: successMsg
          };
          updateJumpConnCell(formJumpId);
        }
        jumpMsg(successMsg, false);
      } else {
        var errMsg = d.error || ('Test failed (HTTP ' + (r.status || 'unknown') + ')');
        if (d.troubleshooting) {
          errMsg += ' — ' + d.troubleshooting;
        }
        if (formJumpId && document.getElementById('jump-conn-' + formJumpId)) {
          jumpConnStatus[formJumpId] = {
            ok: false,
            category: d.category,
            error: d.error || ('Test failed (HTTP ' + (r.status || 'unknown') + ')'),
            troubleshooting: d.troubleshooting,
            message: errMsg
          };
          updateJumpConnCell(formJumpId);
        }
        jumpMsg(errMsg, true);
      }
    }).catch(function(e) {
      jumpTestBtn.disabled = false;
      var errStr = String(e && (e.message || e));
      if (formJumpId && document.getElementById('jump-conn-' + formJumpId)) {
        jumpConnStatus[formJumpId] = {
          ok: false,
          error: errStr,
          message: errStr
        };
        updateJumpConnCell(formJumpId);
      }
      jumpMsg('Connection test error: ' + errStr, true);
    });
  }

  var jumpTestBtn = document.getElementById('jumpTestBtn');
  if (jumpTestBtn) {
    jumpTestBtn.addEventListener('click', function() {
      var host = (document.getElementById('jumpHost').value || '').trim();
      var user = (document.getElementById('jumpUser').value || '').trim();
      if (!host || !user) {
        jumpMsg('Host and Username are required to test connection.', true);
        return;
      }
      var rawKey = (document.getElementById('jumpHostKeyRaw') && document.getElementById('jumpHostKeyRaw').value || '').trim();
      var body = {
        id: (document.getElementById('jumpId').value || '').trim(),
        host: host,
        port: parseInt(document.getElementById('jumpPort').value, 10) || 22,
        username: user,
        auth_type: document.getElementById('jumpAuth').value,
        key_path: (document.getElementById('jumpKeyPath').value || '').trim(),
        private_key: document.getElementById('jumpPrivateKey').value,
        password: document.getElementById('jumpPassword').value,
        host_key: rawKey,
        subnets: (document.getElementById('jumpSubnets').value || '').trim(),
        note: (document.getElementById('jumpNote').value || '').trim(),
        is_default: document.getElementById('jumpDefault').checked
      };
      var formJumpId = (document.getElementById('jumpId').value || '').trim();
      if (formJumpId && document.getElementById('jump-conn-' + formJumpId)) {
        jumpConnStatus[formJumpId] = { state: 'testing' };
        updateJumpConnCell(formJumpId);
      }

      if (!rawKey) {
        jumpMsg('Inspecting SSH host key on ' + host + ':' + body.port + ' prior to testing…', false);
        jumpTestBtn.disabled = true;
        postJson('/api/vault/jump-hosts/probe-key', {host: host, port: body.port, id: formJumpId}).then(function(r) {
          jumpTestBtn.disabled = false;
          var d = (r && r.data) ? r.data : (r || {});
          var isOk = (r && (r.status === 200 || (!r.status && r.ok))) && (d.ok !== false);
          if (isOk) {
            showJumpHostKeyModal(d, function(accepted) {
              body.host_key = accepted.public_key;
              executeJumpTest(body, formJumpId);
            });
          } else {
            executeJumpTest(body, formJumpId);
          }
        }).catch(function() {
          jumpTestBtn.disabled = false;
          executeJumpTest(body, formJumpId);
        });
      } else {
        executeJumpTest(body, formJumpId);
      }
    });
  }

  function executeJumpSave(body) {
    jumpSave.disabled = true;
    postJson('/api/vault/jump-hosts', body).then(function(r) {
      jumpSave.disabled = false;
      var d = (r && r.data) ? r.data : (r || {});
      var isOk = (r && (r.status === 200 || (!r.status && r.ok))) && (d.ok !== false);
      if (isOk) {
        var savedId = (d.jump_host && d.jump_host.id) || body.id;
        delete jumpConnStatus[savedId];
        var wasEditing = !!editingJumpId;
        jumpMsg((wasEditing ? 'Updated' : 'Saved') + ' jump host ' + savedId, false);
        cancelJumpEdit();
        refreshJumpHosts();
      } else {
        jumpMsg(d.error || ('Save failed (HTTP ' + (r.status || 'unknown') + ')'), true);
      }
    }).catch(function(e) {
      jumpSave.disabled = false;
      jumpMsg('Save error: ' + (e.message || e), true);
    });
  }

  var jumpSave = document.getElementById('jumpSaveBtn');
  if (jumpSave) {
    jumpSave.addEventListener('click', function() {
      var id = document.getElementById('jumpId').value.trim();
      var host = document.getElementById('jumpHost').value.trim();
      var user = document.getElementById('jumpUser').value.trim();
      if (!id || !host || !user) {
        jumpMsg('Id, Host, and Username are required.', true);
        return;
      }
      var rawKey = (document.getElementById('jumpHostKeyRaw') && document.getElementById('jumpHostKeyRaw').value || '').trim();
      var body = {
        id: id,
        host: host,
        port: parseInt(document.getElementById('jumpPort').value, 10) || 22,
        username: user,
        auth_type: document.getElementById('jumpAuth').value,
        key_path: document.getElementById('jumpKeyPath').value.trim(),
        private_key: document.getElementById('jumpPrivateKey').value,
        password: document.getElementById('jumpPassword').value,
        host_key: rawKey,
        subnets: document.getElementById('jumpSubnets').value.trim(),
        note: document.getElementById('jumpNote').value.trim(),
        is_default: document.getElementById('jumpDefault').checked
      };

      if (!rawKey) {
        jumpMsg('Inspecting SSH host key on ' + host + ':' + body.port + ' prior to saving…', false);
        jumpSave.disabled = true;
        postJson('/api/vault/jump-hosts/probe-key', {host: host, port: body.port, id: id}).then(function(r) {
          jumpSave.disabled = false;
          var d = (r && r.data) ? r.data : (r || {});
          var isOk = (r && (r.status === 200 || (!r.status && r.ok))) && (d.ok !== false);
          if (isOk) {
            showJumpHostKeyModal(d, function(accepted) {
              body.host_key = accepted.public_key;
              executeJumpSave(body);
            });
          } else {
            executeJumpSave(body);
          }
        }).catch(function() {
          jumpSave.disabled = false;
          executeJumpSave(body);
        });
      } else {
        executeJumpSave(body);
      }
    });
  }

  function updateJumpTargetHint(hostsCount, is423) {
    var targetHint = document.getElementById('jumpTargetHint');
    if (!targetHint) return;
    var remoteEl = document.getElementById('execRemote');
    var isRemoteChecked = remoteEl && remoteEl.checked;
    var vs = (typeof _vaultState !== 'undefined') ? _vaultState : null;

    if (vs && vs.remote_disabled) {
      targetHint.innerHTML = '<span class="text-muted">Remote execution is disabled while --allow-remote is enabled.</span>';
      return;
    }

    if (is423 || (vs && !vs.unlocked)) {
      var actionText = (vs && !vs.exists) ? 'Create Vault' : 'Unlock Vault';
      var actionType = (vs && !vs.exists) ? 'create' : 'unlock';
      targetHint.innerHTML = '<span style="color:' + (isRemoteChecked ? 'var(--vcf-danger, #c21d00)' : 'var(--vcf-muted)') + ';">'
        + 'Requires an unlocked Credential Vault with SSH jump profiles. '
        + '<a href="#" class="jump-vault-anchor-link" data-action="' + actionType + '" style="color:var(--vcf-primary, #0072a3);font-weight:600;text-decoration:underline;">'
        + actionText + ' &rarr;</a></span>';
      return;
    }

    if (typeof hostsCount === 'number') {
      if (hostsCount === 0) {
        targetHint.innerHTML = '<span style="color:' + (isRemoteChecked ? 'var(--vcf-warning, #d9822b)' : 'var(--vcf-muted)') + ';">'
          + 'Vault unlocked, but no jump host profiles configured. '
          + '<a href="#" class="jump-vault-anchor-link" data-action="add" style="color:var(--vcf-primary, #0072a3);font-weight:600;text-decoration:underline;">'
          + 'Add Jump Host Profile &rarr;</a></span>';
      } else {
        targetHint.innerHTML = '<span style="color:var(--vcf-success, #2f8400);">'
          + '✔ ' + hostsCount + ' jump host profile' + (hostsCount === 1 ? '' : 's') + ' ready in vault.</span>';
      }
      return;
    }

    targetHint.innerHTML = '<span class="text-muted">Requires an unlocked Credential Vault with SSH jump profiles.</span>';
  }

  function syncExecutionTarget() {
    var remote = document.getElementById('execRemote');
    var box = document.getElementById('jumpSelectRow');
    var on = remote && remote.checked;
    if (box) box.classList.toggle('hidden', !on);
    if (on) refreshJumpHosts();
    else updateJumpTargetHint();
  }
  var execLocal = document.getElementById('execLocal');
  var execRemote = document.getElementById('execRemote');
  if (execLocal) execLocal.addEventListener('change', syncExecutionTarget);
  if (execRemote) execRemote.addEventListener('change', syncExecutionTarget);

  document.addEventListener('click', function(ev) {
    var link = ev.target && ev.target.closest ? ev.target.closest('.jump-vault-anchor-link') : null;
    if (!link) return;
    ev.preventDefault();
    var act = link.getAttribute('data-action');
    if (act === 'create') {
      openAndHighlightVault('vaultNewPass1');
    } else if (act === 'add') {
      openAndHighlightVault('jumpId');
    } else {
      openAndHighlightVault('vaultUnlockPass');
    }
  });

  if (typeof renderVaultState === 'function') {
    var _renderVaultState = renderVaultState;
    renderVaultState = function() {
      _renderVaultState();
      refreshJumpHosts();
    };
  }

  updateJumpTargetHint();
"""
