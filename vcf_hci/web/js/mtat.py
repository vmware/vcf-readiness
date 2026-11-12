"""Experimental MTAT page script. It calls only the MTAT routes."""

from vcf_hci.web.js.mtat_tco import JS_MTAT_TCO

JS_MTAT = r"""
(function () {
  var banner = document.getElementById("mtatBanner");
  if (!banner) return;
  if (typeof window.__mtatReinit === "function") {
    window.__mtatReinit();
    return;
  }
  var activeJob = null;
  var enabled = false, discovering = false, discoveryVersion = 0;
  var source = document.getElementById("mtatSource");
  var cluster = document.getElementById("mtatCluster");
  var clusterSelect = document.getElementById("mtatClusterSelect");
  var discover = document.getElementById("mtatDiscover");
  var historyRange = document.getElementById("mtatHistoryRange");
  var historyIntervals = null;
  var multiRangeMode = false;
  var currentReport = null;
  var currentLinks = null;
  var currentJobId = "";
  var certificatePin = "", reviewedCertificate = null, certificateVersion = 0;

  var RANGE_SPECS = [
    {key: "realtime", days: 0, label: "Real-Time Snapshot", legacyLabel: "realtime", checkboxId: "mtatCheckRealtime"},
    {key: "day", days: 1, label: "Past 24 Hours (Avg Rollup)", legacyLabel: "Past 24 Hours", checkboxId: "mtatCheckDay"},
    {key: "week", days: 7, label: "Past 7 Days (Avg Rollup)", legacyLabel: "Past 7 Days", checkboxId: "mtatCheckWeek"},
    {key: "month", days: 30, label: "Past 30 Days (Avg Rollup)", legacyLabel: "Past 30 Days", checkboxId: "mtatCheckMonth"}
  ];

  var STEP_TITLES = [
    "Step 1 of 3 — Source & Connection",
    "Step 2 of 3 — Baseline Assessment",
    "Step 3 of 3 — Sizing & Savings"
  ];

  function setStep(stepIndex, focusHeading) {
    var idx = Math.max(0, Math.min(2, Number(stepIndex) || 0));
    var workflow = document.getElementById("mtatWorkflow");
    if (workflow) workflow.setAttribute("data-active-step", String(idx));
    Array.from(document.querySelectorAll("[data-mtat-step]")).forEach(function (btn) {
      var btnStep = Number(btn.getAttribute("data-mtat-step"));
      if (btnStep === idx) btn.setAttribute("aria-current", "step");
      else btn.removeAttribute("aria-current");
    });
    var statusEl = document.getElementById("mtatStepStatus");
    if (statusEl) statusEl.textContent = STEP_TITLES[idx] || STEP_TITLES[0];
    var sizingPanel = document.getElementById("mtatSizingPanel");
    if (sizingPanel && (idx === 2 || currentReport)) {
      sizingPanel.hidden = false;
    }
    if (focusHeading) {
      var heading = document.getElementById("mtatStep" + idx + "Heading");
      if (heading) {
        heading.focus();
        if (typeof heading.scrollIntoView === "function") heading.scrollIntoView({block: "nearest"});
      }
    }
  }

  function markStepComplete(stepIndex, complete) {
    var btn = document.getElementById("mtatStepBtn" + stepIndex);
    if (!btn) return;
    if (complete) btn.classList.add("step-complete");
    else btn.classList.remove("step-complete");
  }

  Array.from(document.querySelectorAll("[data-mtat-step]")).forEach(function (btn) {
    btn.addEventListener("click", function () {
      setStep(Number(btn.getAttribute("data-mtat-step")), true);
    });
  });

  var step1Next = document.getElementById("mtatStep1Next");
  if (step1Next) {
    step1Next.addEventListener("click", function () {
      markStepComplete(0, true);
      setStep(1, true);
    });
  }

  var step2Next = document.getElementById("mtatStep2Next");
  if (step2Next) {
    step2Next.addEventListener("click", function () {
      markStepComplete(1, true);
      setStep(2, true);
    });
  }

  function clearCertificate() {
    certificateVersion += 1; certificatePin = ""; reviewedCertificate = null;
    document.getElementById("mtatCertReview").hidden = true;
    document.getElementById("mtatClearPin").hidden = true;
    document.getElementById("mtatPinStatus").textContent = "No certificate pinned. Verify TLS uses the system trust store.";
  }

  document.getElementById("mtatReviewCert").addEventListener("click", function () {
    var version = ++certificateVersion;
    document.getElementById("mtatCertReview").hidden = true;
    reviewedCertificate = null;
    document.getElementById("mtatPinStatus").textContent = "Inspecting certificate without sending credentials…";
    var raw = document.getElementById("mtatEndpoint").value.trim();
    var target;
    try { target = new URL(raw.indexOf("://") < 0 ? "https://" + raw : raw); }
    catch (error) { document.getElementById("mtatPinStatus").textContent = "Enter a valid HTTPS vCenter endpoint."; return; }
    if (target.protocol !== "https:" || target.username || target.password) {
      document.getElementById("mtatPinStatus").textContent = "Enter an HTTPS endpoint without embedded credentials."; return;
    }
    if (target.hostname.indexOf(":") !== -1) {
      document.getElementById("mtatPinStatus").textContent = "Certificate review currently requires a DNS hostname or IPv4 endpoint. Use system CA verification for an IPv6 literal."; return;
    }
    fetch("/api/inspect-cert?host=" + encodeURIComponent(target.hostname.replace(/^\[|\]$/g, "")) + "&port=" + encodeURIComponent(target.port || "443"), {credentials: "same-origin"})
      .then(function (response) { return response.json(); }).then(function (data) {
        if (version !== certificateVersion) return;
        if (!data.reachable || !(data.sha256 || data.sha256_raw)) throw new Error("inspection failed");
        reviewedCertificate = data;
        document.getElementById("mtatCertDetails").textContent = "Endpoint: " + target.host + "\nSubject: " + (data.subject_cn || "Unknown") + "\nIssuer: " + (data.issuer_cn || "Unknown") + "\nExpires: " + (data.not_after || "Unknown") + "\nSHA-256: " + (data.sha256 || data.sha256_raw);
        document.getElementById("mtatCertReview").hidden = false;
        document.getElementById("mtatPinStatus").textContent = "Review the fingerprint before trusting this certificate.";
      }).catch(function () { if (version === certificateVersion) document.getElementById("mtatPinStatus").textContent = "Certificate inspection failed. Check the endpoint and HTTPS connectivity."; });
  });

  document.getElementById("mtatAcceptPin").addEventListener("click", function () {
    if (!reviewedCertificate) return;
    certificatePin = reviewedCertificate.sha256 || reviewedCertificate.sha256_raw;
    document.getElementById("mtatPinStatus").textContent = "SHA-256 pin enforced for this endpoint. A different certificate will block connection.";
    document.getElementById("mtatClearPin").hidden = false;
    document.getElementById("mtatCertReview").hidden = true;
  });

  document.getElementById("mtatClearPin").addEventListener("click", clearCertificate);
  ["mtatEndpoint", "mtatSource"].forEach(function (id) {
    document.getElementById(id).addEventListener("input", clearCertificate);
    document.getElementById(id).addEventListener("change", clearCertificate);
  });

  function intervalSupports(days, interval) {
    var minSeconds = days <= 1 ? 300 : 1800;
    return interval.enabled && interval.level >= 2 && interval.seconds >= minSeconds && interval.retention_seconds >= days * 86400;
  }

  function getCheckedRangeSpecs() {
    return RANGE_SPECS.filter(function (spec) {
      var box = document.getElementById(spec.checkboxId);
      return box && box.checked && !box.disabled;
    });
  }

  function updateRangeToggleLabel() {
    var toggleBtn = document.getElementById("mtatRangeToggleAll");
    var badge = document.getElementById("mtatScopeSummaryBadge");
    var enabledSpecs = RANGE_SPECS.filter(function (spec) {
      var box = document.getElementById(spec.checkboxId);
      return box && !box.disabled;
    });
    var checkedSpecs = getCheckedRangeSpecs();
    if (toggleBtn) {
      var allChecked = enabledSpecs.length > 0 && checkedSpecs.length === enabledSpecs.length;
      toggleBtn.textContent = allChecked ? "Deselect All" : "Select All";
    }
    if (badge) {
      if (source.value === "operations-xlsx") {
        badge.textContent = "Workbook Scope";
      } else if (source.value === "vcenter" && historyRange.value === "custom") {
        badge.textContent = "Custom Window";
      } else {
        var count = multiRangeMode ? checkedSpecs.length : 1;
        badge.textContent = count + (count === 1 ? " Range Selected" : " Ranges Selected");
      }
    }
  }

  function syncCheckboxesFromSelect() {
    var val = historyRange.value;
    RANGE_SPECS.forEach(function (spec) {
      var box = document.getElementById(spec.checkboxId);
      if (box) box.checked = (spec.key === val);
    });
  }

  function updateSourceBadge() {
    var badge = document.getElementById("mtatSourceModeBadge");
    if (!badge) return;
    if (source.value === "vcenter") badge.textContent = "vCenter Live API";
    else if (source.value === "operations-rest") badge.textContent = "Operations REST API";
    else badge.textContent = "Operations Workbook";
  }

  function updateHistoryControls() {
    var vcenter = source.value === "vcenter";
    var checkedSpecs = getCheckedRangeSpecs();
    var onlyRealtime = vcenter && (multiRangeMode ? (checkedSpecs.length === 1 && checkedSpecs[0].key === "realtime") : historyRange.value === "realtime");
    document.getElementById("mtatHistoryRangeGroup").hidden = !vcenter;
    var multiGroup = document.getElementById("mtatMultiRangeGroup");
    if (multiGroup) multiGroup.hidden = !vcenter;
    document.getElementById("mtatCertControls").hidden = !vcenter;
    document.getElementById("mtatRangeGroup").hidden = vcenter && historyRange.value !== "custom";
    document.getElementById("mtatHistorySettings").hidden = !vcenter || historyIntervals === null;
    document.getElementById("mtatRetentionHint").hidden = !vcenter;
    ["mtatBegin", "mtatEnd", "mtatInterval"].forEach(function (id) {
      var control = document.getElementById(id);
      control.disabled = onlyRealtime;
      control.readOnly = vcenter && historyRange.value !== "custom";
    });
    Array.from(historyRange.options).forEach(function (option) {
      var days = option.value === "day" ? 1 : option.value === "week" ? 7 : option.value === "month" ? 30 : 0;
      option.disabled = !!(days && historyIntervals !== null && !historyIntervals.some(function (interval) { return intervalSupports(days, interval); }));
    });
    RANGE_SPECS.forEach(function (spec) {
      var box = document.getElementById(spec.checkboxId);
      if (!box) return;
      var unsupported = !!(spec.days && historyIntervals !== null && !historyIntervals.some(function (interval) { return intervalSupports(spec.days, interval); }));
      box.disabled = !vcenter || unsupported;
    });
    checkedSpecs = getCheckedRangeSpecs();
    var unavailable = vcenter && (multiRangeMode ? checkedSpecs.length === 0 : historyRange.selectedOptions[0].disabled);
    document.getElementById("mtatRun").disabled = !enabled || unavailable;
    document.getElementById("mtatRetentionHint").textContent = historyIntervals === null ?
      "Discover vCenter history to check which ranges are supported." : unavailable ?
      "This range has no enabled Level 2+ interval with sufficient retention and sampling of at least 30 minutes. Choose Custom history or Realtime." :
      "Ranges reflect vCenter's configured retention and statistics levels. Missing metric history remains unverified.";
    updateRangeToggleLabel();
  }

  function applyWindowForDays(days) {
    var end = new Date();
    end.setUTCSeconds(0, 0);
    document.getElementById("mtatEnd").value = end.toISOString().slice(0, 16);
    document.getElementById("mtatBegin").value = new Date(end.getTime() - days * 86400000).toISOString().slice(0, 16);
    document.getElementById("mtatInterval").value = "auto";
  }

  function applyHistoryRange() {
    if (source.value === "vcenter") {
      var range = historyRange.value;
      if (range === "day" || range === "week" || range === "month") {
        var days = range === "day" ? 1 : range === "week" ? 7 : 30;
        applyWindowForDays(days);
      }
      document.getElementById("mtatRange").value = range === "day" ? "Past 24 Hours" : range === "week" ? "Past 7 Days" : range === "month" ? "Past 30 Days" : range === "realtime" ? "realtime" : "Custom history";
      if (!multiRangeMode) {
        syncCheckboxesFromSelect();
      }
    }
    updateHistoryControls();
  }

  RANGE_SPECS.forEach(function (spec) {
    var box = document.getElementById(spec.checkboxId);
    if (!box) return;
    box.addEventListener("change", function () {
      multiRangeMode = true;
      var checked = getCheckedRangeSpecs();
      if (checked.length > 0) {
        var primary = checked[checked.length - 1];
        historyRange.value = primary.key;
        if (primary.days > 0) applyWindowForDays(primary.days);
        document.getElementById("mtatRange").value = primary.legacyLabel;
      }
      updateHistoryControls();
    });
  });

  var toggleAllBtn = document.getElementById("mtatRangeToggleAll");
  if (toggleAllBtn) {
    toggleAllBtn.addEventListener("click", function () {
      multiRangeMode = true;
      var enabledSpecs = RANGE_SPECS.filter(function (spec) {
        var box = document.getElementById(spec.checkboxId);
        return box && !box.disabled;
      });
      var checkedSpecs = getCheckedRangeSpecs();
      var shouldCheck = checkedSpecs.length < enabledSpecs.length;
      enabledSpecs.forEach(function (spec) {
        var box = document.getElementById(spec.checkboxId);
        if (box) box.checked = shouldCheck;
      });
      var updated = getCheckedRangeSpecs();
      if (updated.length > 0) {
        var primary = updated[updated.length - 1];
        historyRange.value = primary.key;
        if (primary.days > 0) applyWindowForDays(primary.days);
        document.getElementById("mtatRange").value = primary.legacyLabel;
      }
      updateHistoryControls();
    });
  }

  function durationLabel(seconds) {
    if (seconds >= 86400) return (seconds / 86400) + " days";
    if (seconds >= 3600) return (seconds / 3600) + " hours";
    if (seconds >= 60) return (seconds / 60) + " minutes";
    return seconds + " seconds";
  }

  function renderHistorySettings(data) {
    if (source.value !== "vcenter" || !Array.isArray(data.historical_intervals)) return;
    historyIntervals = data.historical_intervals;
    var rows = document.getElementById("mtatHistoryRows");
    rows.replaceChildren();
    historyIntervals.forEach(function (interval) {
      var row = document.createElement("tr");
      var status = !interval.enabled ? "Disabled" : !interval.level ? "Statistics level unavailable" : interval.level < 2 ? "Level 2 required for MTAT" : "Enabled";
      [interval.key, durationLabel(interval.seconds), durationLabel(interval.retention_seconds), interval.level || "Unknown", status].forEach(function (value) {
        var cell = document.createElement("td"); cell.textContent = String(value); row.appendChild(cell);
      });
      rows.appendChild(row);
    });
    if (!historyIntervals.length) {
      var row = document.createElement("tr"), cell = document.createElement("td");
      cell.colSpan = 5; cell.textContent = "No historical intervals reported by vCenter."; row.appendChild(cell); rows.appendChild(row);
    }
    updateHistoryControls();
  }

  function updateDiscovery() {
    var vcenter = source.value === "vcenter";
    updateSourceBadge();
    cluster.hidden = vcenter;
    cluster.disabled = vcenter;
    clusterSelect.hidden = !vcenter;
    clusterSelect.disabled = !vcenter;
    discover.hidden = !vcenter;
    document.getElementById("mtatClusterHelp").hidden = !vcenter;
    var reason = "";
    if (!enabled) reason = "Discovery is unavailable. Check the MTAT enablement guidance above.";
    else if (discovering) reason = "Discovering clusters and history…";
    else if (!document.getElementById("mtatEndpoint").value.trim()) reason = "Enter a vCenter endpoint above to enable discovery.";
    else if (!document.getElementById("mtatUsername").value.trim()) reason = "Enter a username above to enable discovery.";
    else if (!(typeof pluginCredentials !== "undefined" && pluginCredentials.ready("mtat")) && !password.value) reason = "Enter a password above to enable discovery.";
    else if (!document.getElementById("mtatAck").checked) reason = "Check ‘I acknowledge this experimental collection’ above to enable discovery.";
    discover.disabled = !!reason;
    document.getElementById("mtatDiscoveryStatus").hidden = !vcenter;
    document.getElementById("mtatDiscoveryStatus").textContent = reason || "Ready to discover clusters and history.";
    updateHistoryControls();
  }

  function resetDiscovery() {
    discoveryVersion += 1;
    clusterSelect.replaceChildren(new Option("Discover clusters to select", ""));
    historyIntervals = null;
    multiRangeMode = false;
    syncCheckboxesFromSelect();
    document.getElementById("mtatHistoryRows").replaceChildren();
    markStepComplete(0, false);
    updateDiscovery();
  }

  function populateClusters(data) {
    if (source.value !== "vcenter" || !Array.isArray(data.clusters)) return;
    var previous = clusterSelect.value;
    clusterSelect.replaceChildren(new Option(data.clusters.length ? "Select a cluster" : "No accessible clusters found", ""));
    data.clusters.forEach(function (item) {
      clusterSelect.add(new Option(item.name + " (" + item.id + ")", item.id));
    });
    if (data.clusters.length === 1) clusterSelect.value = data.clusters[0].id;
    else if (data.clusters.some(function (item) { return item.id === previous; })) clusterSelect.value = previous;
  }

  var diagnosticLines = [];
  function recordDiagnostic(text) {
    diagnosticLines.push(new Date().toISOString() + " " + text);
    if (diagnosticLines.length > 20) diagnosticLines.shift();
    document.getElementById("mtatDiagnostics").textContent = diagnosticLines.join("\n");
  }

  function message(data, fallback) {
    if (data.error_code) recordDiagnostic(data.error_code + (data.reference ? " Reference: " + data.reference : ""));
    return (data.error || data.message || fallback) + (data.error_code ? " [" + data.error_code + "]" : "") +
      (data.reference ? " Reference: " + data.reference : "");
  }

  function failure(error) {
    document.getElementById("mtatProgress").textContent = error && error.name === "AbortError" ?
      "The request timed out. Check network access to vCenter from the machine running VCF-R." :
      "The request could not reach the Web UI or returned an invalid response. Check that the Web UI is running and retry.";
  }

  document.getElementById("mtatForm").addEventListener("submit", function (event) { event.preventDefault(); });
  var password = document.getElementById("mtatPassword");

  ["mtatEndpoint", "mtatUsername", "mtatVerifyTls", "mtatSource"].forEach(function (id) {
    document.getElementById(id).addEventListener("input", resetDiscovery);
    document.getElementById(id).addEventListener("change", resetDiscovery);
  });
  ["mtatPassword", "mtatAck"].forEach(function (id) {
    document.getElementById(id).addEventListener("input", updateDiscovery);
    document.getElementById(id).addEventListener("change", updateDiscovery);
  });
  historyRange.addEventListener("change", function () {
    multiRangeMode = false;
    applyHistoryRange();
  });
  source.addEventListener("change", function () {
    multiRangeMode = false;
    if (source.value !== "vcenter" && document.getElementById("mtatRange").value === "realtime") {
      document.getElementById("mtatRange").value = "Past 7 Days";
    }
    applyHistoryRange();
  });
  updateDiscovery();
  window.__mtatReinit = function () {
    source.value = "vcenter";
    multiRangeMode = false;
    setStep(0, false);
    resetDiscovery();
    applyHistoryRange();
  };
  var historyEnd = new Date();
  historyEnd.setUTCSeconds(0, 0);
  document.getElementById("mtatEnd").value = historyEnd.toISOString().slice(0, 16);
  document.getElementById("mtatBegin").value = new Date(historyEnd.getTime() - 7 * 86400000).toISOString().slice(0, 16);

  function payload(extra) {
    var body = {
      source_kind: document.getElementById("mtatSource").value,
      endpoint: document.getElementById("mtatEndpoint").value,
      username: document.getElementById("mtatUsername").value,
      password: password.value,
      certificate_pin: source.value === "vcenter" ? certificatePin : "",
      cluster: source.value === "vcenter" ? clusterSelect.value : cluster.value,
      range_name: document.getElementById("mtatRange").value,
      verify_tls: document.getElementById("mtatVerifyTls").checked,
      acknowledged: document.getElementById("mtatAck").checked
    };
    if (body.source_kind === "operations-xlsx" && ["Past 24 Hours", "Past 7 Days", "Past 30 Days", "Custom history"].indexOf(body.range_name) !== -1) body.range_name = "";
    body.memory_unit = document.getElementById("mtatUnit").value;
    var begin = document.getElementById("mtatBegin").value, end = document.getElementById("mtatEnd").value;
    if (begin && end && body.source_kind !== "operations-xlsx" && !(body.source_kind === "vcenter" && historyRange.value === "realtime")) {
      var beginMs = Date.parse(begin + "Z"), endMs = Date.parse(end + "Z");
      var divisor = body.source_kind === "vcenter" ? 1000 : 1;
      if (!isNaN(beginMs) && !isNaN(endMs)) {
        body.window = {begin: Math.floor(beginMs / divisor), end: Math.floor(endMs / divisor), interval: document.getElementById("mtatInterval").value};
      }
    }
    if (!extra && body.source_kind === "vcenter" && multiRangeMode && historyRange.value !== "custom") {
      var checked = getCheckedRangeSpecs();
      if (checked.length > 0) {
        var refEndMs = end ? Date.parse(end + "Z") : Date.now();
        if (isNaN(refEndMs)) refEndMs = Date.now();
        var refEndSec = Math.floor(refEndMs / 1000);
        var intervalKey = document.getElementById("mtatInterval").value || "auto";
        body.ranges = checked.map(function (spec) {
          if (spec.days === 0) {
            return {range_name: spec.label, window: null};
          }
          return {
            range_name: spec.label,
            window: {
              begin: refEndSec - spec.days * 86400,
              end: refEndSec,
              interval: intervalKey
            }
          };
        });
        var primarySpec = checked[checked.length - 1];
        body.range_name = primarySpec.days === 0 ? "realtime" : primarySpec.legacyLabel;
        if (primarySpec.days === 0) {
          delete body.window;
        } else {
          body.window = {
            begin: refEndSec - primarySpec.days * 86400,
            end: refEndSec,
            interval: intervalKey
          };
        }
      }
    }
    if (extra) {
      Object.keys(extra).forEach(function (key) { body[key] = extra[key]; });
    }
    return typeof pluginCredentials === "undefined" ? body : pluginCredentials.payload("mtat", body);
  }

  function post(url, body) {
    if (body.source_kind === "operations-xlsx" && !body.workbook_base64) {
      var file = document.getElementById("mtatWorkbook").files[0];
      if (!file || file.size > 33554432) return Promise.resolve({ok: false, data: {error: "Select a workbook within the upload limit"}});
      return new Promise(function (resolve, reject) {
        var reader = new FileReader();
        reader.onerror = reject;
        reader.onload = function () { body.workbook_base64 = reader.result.split(",")[1]; resolve(post(url, body)); };
        reader.readAsDataURL(file);
      });
    }
    var controller = new AbortController();
    var timeout = setTimeout(function () { controller.abort(); }, 120000);
    return fetch(url, {
      signal: controller.signal,
      method: "POST",
      credentials: "same-origin",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body)
    }).then(function (response) {
      return response.json().catch(function () { return {error: "Web UI returned HTTP " + response.status + " without a JSON response. Restart the Web UI and retry."}; })
        .then(function (data) { return {ok: response.ok, status: response.status, data: data}; });
    }).finally(function () { clearTimeout(timeout); });
  }

  function renderPreflightDetails(data) {
    renderHistorySettings(data);
    var container = document.getElementById("mtatResults");
    if (!container) return;
    container.replaceChildren();
    var items = [];
    if (Array.isArray(data.messages)) {
      data.messages.forEach(function (msg) { if (msg) items.push(String(msg)); });
    }
    if (data.capabilities && typeof data.capabilities === "object") {
      var enabledKeys = Object.keys(data.capabilities).filter(function (k) { return data.capabilities[k]; });
      if (enabledKeys.length) items.push("Capabilities: " + enabledKeys.join(", "));
    }
    if (items.length) {
      var detail = document.createElement("p");
      detail.id = "mtatPreflightDetails";
      detail.textContent = items.join(" · ");
      container.appendChild(detail);
    }
  }

  function formatPct(val) {
    if (typeof val === "string") return val.indexOf("%") >= 0 ? val : val + "%";
    var num = Number(val);
    if (isNaN(num)) return "0.0%";
    return num.toFixed(1) + "%";
  }

  function formatGb(val) {
    if (val === null || val === undefined || val === "") return "—";
    var num = Number(val);
    if (isNaN(num)) return String(val);
    return num.toFixed(2);
  }

  function getRangeSummary(report, rangeName) {
    if (!report || !Array.isArray(report.ranges) || !report.ranges.length) return null;
    for (var i = 0; i < report.ranges.length; i++) {
      if (report.ranges[i].range_name === rangeName) return report.ranges[i];
    }
    return report.ranges[report.ranges.length - 1];
  }

  function formatBadgeLabel(status) {
    var upper = String(status || "").toUpperCase();
    if (upper === "PASS") return "[ ✓ ] PASS";
    if (upper === "NOTE" || upper === "INFO") return "[ i ] NOTE";
    return "[ ! ] " + (upper || "REVIEW");
  }

  function renderChecklistAndDetails(rangeName) {
    var summary = getRangeSummary(currentReport, rangeName);
    if (!summary) return;
    var heading = document.getElementById("mtatChecklistHeading");
    if (heading) {
      heading.textContent = "BASELINE QUALIFICATION CHECKLIST (RAW HARDWARE - " + String(summary.range_name || "DEFAULT").toUpperCase() + "):";
    }
    var listEl = document.getElementById("mtatChecklistRows");
    if (listEl) {
      listEl.replaceChildren();
      var checklist = Array.isArray(summary.checklist) ? summary.checklist : [];
      checklist.forEach(function (item) {
        var row = document.createElement("div");
        row.className = "mtat-checklist-row";
        row.setAttribute("role", "listitem");

        var metric = document.createElement("span");
        metric.className = "mtat-checklist-metric";
        metric.textContent = item.metric || "";

        var target = document.createElement("span");
        target.className = "mtat-checklist-target";
        var rawTarget = String(item.target || "");
        target.textContent = rawTarget.indexOf("Target:") >= 0 ? rawTarget : "[ Target: " + rawTarget + " ]";

        var val = document.createElement("span");
        val.className = "mtat-checklist-value";
        val.textContent = item.value_label || formatPct(item.value_pct);

        var badge = document.createElement("span");
        badge.className = "badge " + (item.badge_class || "badge-info");
        badge.textContent = formatBadgeLabel(item.status);

        row.append(metric, target, val, badge);
        if (item.note) {
          var note = document.createElement("span");
          note.className = "mtat-checklist-note";
          note.textContent = item.note;
          row.appendChild(note);
        }
        listEl.appendChild(row);
      });
    }

    var hostRowsEl = document.getElementById("mtatHostRows");
    if (hostRowsEl) {
      hostRowsEl.replaceChildren();
      var hosts = Array.isArray(summary.hosts) ? summary.hosts : [];
      hosts.forEach(function (h) {
        var tr = document.createElement("tr");
        var cells = [
          {text: h.cluster || ""},
          {text: h.host_name || ""},
          {text: h.tiering || ""},
          {text: h.cpu_pct || "0.00", numeric: true},
          {text: h.physical_ram_gb || "0.000", numeric: true},
          {text: h.consumed_gb || "0.000", numeric: true},
          {text: h.active_gb || "0.000", numeric: true},
          {text: h.active_pct || "0.0", numeric: true},
          {text: h.active_avg_gb || "0.000", numeric: true},
          {text: h.nvme_gb || "—", numeric: true}
        ];
        cells.forEach(function (c) {
          var td = document.createElement("td");
          if (c.numeric) td.className = "numeric";
          td.textContent = String(c.text);
          tr.appendChild(td);
        });
        hostRowsEl.appendChild(tr);
      });
    }

    var vmRowsEl = document.getElementById("mtatVmRows");
    if (vmRowsEl) {
      vmRowsEl.replaceChildren();
      var vms = Array.isArray(summary.vms) ? summary.vms : [];
      vms.forEach(function (v) {
        var tr = document.createElement("tr");
        var cells = [
          {text: v.host_name || ""},
          {text: v.vm_name || ""},
          {text: v.provisioned_gb || "0.000", numeric: true},
          {text: v.active_gb || "0.000", numeric: true},
          {text: v.active_pct || "0.0", numeric: true},
          {text: v.dram_only || "No"},
          {text: v.pages_1gb || "Unknown"},
          {text: v.pages_2mb || "Unknown"}
        ];
        cells.forEach(function (c) {
          var td = document.createElement("td");
          if (c.numeric) td.className = "numeric";
          td.textContent = String(c.text);
          tr.appendChild(td);
        });
        vmRowsEl.appendChild(tr);
      });
    }
  }

  function renderMatrixTable(report) {
    var tbody = document.getElementById("mtatMatrixRows");
    if (!tbody) return;
    tbody.replaceChildren();
    var matrix = Array.isArray(report.matrix) ? report.matrix : [];
    var scopeLabel = report.cluster_scope || "Cluster";
    matrix.forEach(function (row, index) {
      var tr = document.createElement("tr");
      if (index === 0) {
        var scopeTd = document.createElement("td");
        scopeTd.className = "mtat-cluster-cell";
        scopeTd.rowSpan = matrix.length;
        scopeTd.textContent = row.cluster_scope || scopeLabel;
        tr.appendChild(scopeTd);
      }
      var cpuDisplay = row.cpu_pct || "0.0%";
      if (row.cpu_peak_pct && row.cpu_peak_pct !== row.cpu_pct) {
        cpuDisplay = row.cpu_pct + " / " + row.cpu_peak_pct;
      }
      [row.range_name || "", cpuDisplay, row.active_pct || "0.0%", row.consumed_pct || "0.0%"].forEach(function (val) {
        var td = document.createElement("td");
        td.textContent = String(val);
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  }

  function renderSizingView() {
    var rangeSelect = document.getElementById("mtatSizingRangeSelect");
    var ratioSelect = document.getElementById("mtatSizingRatioSelect");
    if (!currentReport || !rangeSelect || !ratioSelect) return;
    var summary = getRangeSummary(currentReport, rangeSelect.value);
    if (!summary) return;
    var ratioKey = String(ratioSelect.value || "50");
    var ratioPct = Number(ratioKey) || 50;
    var ratiosObj = (summary.sizing && summary.sizing.ratios) ? summary.sizing.ratios : {};
    var proj = ratiosObj[ratioKey] || {};

    var physGb = Number(summary.total_physical_ram_gb) || 0;
    var consGb = Number(summary.total_consumed_gb) || 0;
    var actGb = Number(summary.total_active_gb) || 0;
    var recNvmeGb = proj.recommended_nvme_gb !== undefined ? Number(proj.recommended_nvme_gb) : (physGb * ratioPct / 100);
    var effCapGb = proj.effective_tiered_capacity_gb !== undefined ? Number(proj.effective_tiered_capacity_gb) : (physGb + recNvmeGb);
    var reclaimGb = proj.reclaimable_dram_gb !== undefined ? Number(proj.reclaimable_dram_gb) : 0;
    var savingsPct = proj.dram_savings_pct !== undefined ? Number(proj.dram_savings_pct) : 0;
    var vmElig = summary.vm_eligibility || {};

    var kpiGrid = document.getElementById("mtatSizingKpis");
    if (kpiGrid) {
      kpiGrid.replaceChildren();
      var cards = [
        {
          title: "Cluster Memory Footprint",
          primary: formatGb(physGb) + " GB Physical DRAM",
          sub: "Active working set: " + formatGb(actGb) + " GB (" + formatPct(summary.active_pct) + ") · Consumed: " + formatGb(consGb) + " GB (" + formatPct(summary.consumed_pct) + ")"
        },
        {
          title: "Recommended NVMe Tier & Savings",
          primary: formatGb(recNvmeGb) + " GB NVMe Tier (" + ratioPct + "%)",
          sub: "Projected reclaimable DRAM: " + formatGb(reclaimGb) + " GB (" + formatPct(savingsPct) + " savings) · Effective capacity: " + formatGb(effCapGb) + " GB"
        },
        {
          title: "VM Tiering Eligibility & Pinning",
          primary: String(vmElig.mtat_32_dram_only_count || 0) + " DRAM_Only VMs (MTAT 3.2)",
          sub: "Pinned footprint: " + formatGb(vmElig.mtat_32_dram_only_provisioned_gb || 0) + " GB · vSphere Current pinned: " + String(vmElig.current_policy_dram_only_count || 0) + " VMs (" + formatGb(vmElig.current_policy_dram_only_provisioned_gb || 0) + " GB)"
        }
      ];
      cards.forEach(function (c) {
        var card = document.createElement("div");
        card.className = "mtat-kpi-card";
        var h4 = document.createElement("h4");
        h4.textContent = c.title;
        var p1 = document.createElement("div");
        p1.className = "mtat-kpi-primary";
        p1.textContent = c.primary;
        var p2 = document.createElement("div");
        p2.className = "mtat-kpi-sub";
        p2.textContent = c.sub;
        card.append(h4, p1, p2);
        kpiGrid.appendChild(card);
      });
    }

    var sizingBadge = document.getElementById("mtatSizingBadge");
    if (sizingBadge) {
      sizingBadge.className = "badge " + (proj.viable === false ? "badge-warning" : "badge-success");
      sizingBadge.textContent = proj.viable === false ? "Review Qualification" : "Qualified for Tiering";
    }

    var hostBody = document.getElementById("mtatSizingHostRows");
    if (hostBody) {
      hostBody.replaceChildren();
      var hosts = Array.isArray(summary.hosts) ? summary.hosts : [];
      var vms = Array.isArray(summary.vms) ? summary.vms : [];
      hosts.forEach(function (h) {
        var hPhys = Number(h.physical_ram_gb) || 0;
        var hCons = Number(h.consumed_gb) || 0;
        var hAct = Number(h.active_gb) || 0;
        var hPinned = 0;
        vms.forEach(function (v) {
          if (v.host_name === h.host_name && String(v.dram_only || "").indexOf("Yes") === 0) {
            hPinned += Number(v.provisioned_gb) || 0;
          }
        });
        var hRecNvme = hPhys * (ratioPct / 100);
        var hEff = hPhys + hRecNvme;
        var hTierable = Math.max(0, hPhys - hPinned);
        var hHeadroom = Math.max(0, hPhys - Math.max(hAct * 2, hPinned));
        var hReclaim = Math.min(hTierable * ((ratioPct / 100) / (1 + ratioPct / 100)), hHeadroom);

        var tr = document.createElement("tr");
        var cells = [
          {text: h.host_name || ""},
          {text: h.tiering || ""},
          {text: formatGb(hPhys), numeric: true},
          {text: formatGb(hCons), numeric: true},
          {text: formatGb(hAct) + " (" + (h.active_pct || "0.0") + "%)", numeric: true},
          {text: formatGb(hPinned), numeric: true},
          {text: h.nvme_gb ? formatGb(h.nvme_gb) : "—", numeric: true},
          {text: formatGb(hRecNvme), numeric: true},
          {text: formatGb(hEff), numeric: true},
          {text: formatGb(hReclaim), numeric: true}
        ];
        cells.forEach(function (c) {
          var td = document.createElement("td");
          if (c.numeric) td.className = "numeric";
          td.textContent = String(c.text);
          tr.appendChild(td);
        });
        hostBody.appendChild(tr);
      });
    }
    if (window.__mtatTco) window.__mtatTco.update(summary, ratioPct);
  }

  function renderReport(data, jobId) {
    currentLinks = data.links || null;
    currentJobId = jobId || "";
    if (data.links) {
      var link = document.createElement("a");
      link.href = data.links.zip || ("/api/plugins/mtat/jobs/" + jobId + "/export.zip");
      link.textContent = "Download experimental export";
      document.getElementById("mtatResults").replaceChildren(link);
    }
    if (!data.report || !Array.isArray(data.report.ranges) || !data.report.ranges.length) {
      return;
    }
    currentReport = data.report;
    var reportEl = document.getElementById("mtatBaselineReport");
    if (reportEl) reportEl.hidden = false;

    var checklistSelect = document.getElementById("mtatChecklistRangeSelect");
    var sizingRangeSelect = document.getElementById("mtatSizingRangeSelect");
    var checklistWrap = document.getElementById("mtatChecklistRangeWrap");
    if (checklistSelect) checklistSelect.replaceChildren();
    if (sizingRangeSelect) sizingRangeSelect.replaceChildren();

    currentReport.ranges.forEach(function (r) {
      if (checklistSelect) checklistSelect.add(new Option(r.range_name, r.range_name));
      if (sizingRangeSelect) sizingRangeSelect.add(new Option(r.range_name, r.range_name));
    });

    var primaryName = currentReport.primary_range || currentReport.ranges[currentReport.ranges.length - 1].range_name;
    if (checklistSelect) checklistSelect.value = primaryName;
    if (sizingRangeSelect) sizingRangeSelect.value = primaryName;
    if (checklistWrap) checklistWrap.hidden = currentReport.ranges.length <= 1;

    var links = data.links || {};
    var matrixBtn = document.getElementById("mtatExportMatrixCsv");
    if (matrixBtn) matrixBtn.href = links.matrix || ("/api/plugins/mtat/jobs/" + jobId + "/matrix.csv");
    var zipBtn = document.getElementById("mtatExportZipBtn");
    if (zipBtn) zipBtn.href = links.zip || ("/api/plugins/mtat/jobs/" + jobId + "/export.zip");
    var hostsBtn = document.getElementById("mtatExportHostsCsv");
    if (hostsBtn) hostsBtn.href = links.hosts || ("/api/plugins/mtat/jobs/" + jobId + "/hosts.csv");
    var vmsBtn = document.getElementById("mtatExportVmsCsv");
    if (vmsBtn) vmsBtn.href = links.vms || ("/api/plugins/mtat/jobs/" + jobId + "/vms.csv");
    var hostsHistBtn = document.getElementById("mtatExportHostsHistCsv");
    if (hostsHistBtn) hostsHistBtn.href = links.hosts_history || ("/api/plugins/mtat/jobs/" + jobId + "/hosts_history.csv");
    var vmsHistBtn = document.getElementById("mtatExportVmsHistCsv");
    if (vmsHistBtn) vmsHistBtn.href = links.vms_history || ("/api/plugins/mtat/jobs/" + jobId + "/vms_history.csv");

    renderChecklistAndDetails(primaryName);
    renderMatrixTable(currentReport);

    var sizingPanel = document.getElementById("mtatSizingPanel");
    var sizingEmpty = document.getElementById("mtatSizingEmpty");
    var sizingContent = document.getElementById("mtatSizingContent");
    if (sizingPanel) sizingPanel.hidden = false;
    if (sizingEmpty) sizingEmpty.hidden = true;
    if (sizingContent) sizingContent.hidden = false;
    renderSizingView();
  }

  var checklistRangeSelect = document.getElementById("mtatChecklistRangeSelect");
  if (checklistRangeSelect) {
    checklistRangeSelect.addEventListener("change", function () {
      renderChecklistAndDetails(checklistRangeSelect.value);
    });
  }

  var sizingRangeSelect = document.getElementById("mtatSizingRangeSelect");
  if (sizingRangeSelect) {
    sizingRangeSelect.addEventListener("change", renderSizingView);
  }
  var sizingRatioSelect = document.getElementById("mtatSizingRatioSelect");
  if (sizingRatioSelect) {
    sizingRatioSelect.addEventListener("change", renderSizingView);
  }

  fetch("/api/plugins/mtat", {credentials: "same-origin"})
    .then(function (response) { return response.json(); })
    .then(function (data) {
      banner.textContent = data.warning || banner.textContent;
      document.getElementById("mtatEnablement").textContent = data.enablement || "";
      enabled = !!data.enabled;
      document.getElementById("mtatRun").disabled = !enabled;
      updateDiscovery();
    }).catch(failure);

  discover.addEventListener("click", function () {
    var version = ++discoveryVersion;
    discovering = true;
    updateDiscovery();
    document.getElementById("mtatProgress").textContent = "Discovering vCenter clusters…";
    recordDiagnostic("Discovery requested.");
    post("/api/plugins/mtat/preflight", payload({cluster: "", range_name: "realtime", window: null})).then(function (result) {
      if (version !== discoveryVersion) return;
      populateClusters(result.data);
      document.getElementById("mtatProgress").textContent = message(result.data,
        (clusterSelect.options.length === 1 ? "No accessible clusters found." :
          clusterSelect.value ? "Cluster selected. Continue with Preflight or Run." :
          "Select a discovered cluster, then continue with Preflight or Run."));
      renderPreflightDetails(result.data);
      if (result.ok) {
        markStepComplete(0, true);
        setStep(1, false);
      }
    }).catch(failure).then(function () { discovering = false; updateDiscovery(); });
  });

  document.getElementById("mtatPreflight").addEventListener("click", function () {
    var version = discoveryVersion;
    document.getElementById("mtatProgress").textContent = "Checking connection, permissions and selected history…";
    recordDiagnostic("Preflight requested.");
    post("/api/plugins/mtat/preflight", payload(null)).then(function (result) {
      if (version !== discoveryVersion) return;
      populateClusters(result.data);
      document.getElementById("mtatProgress").textContent = message(result.data, result.data.ready ? "Preflight ready" : "Preflight blocked. Review the history settings and details below.");
      if (result.ok) {
        renderPreflightDetails(result.data);
        markStepComplete(0, true);
      }
    }).catch(failure);
  });

  document.getElementById("mtatCancel").addEventListener("click", function () {
    if (activeJob) post("/api/plugins/mtat/jobs/" + activeJob + "/cancel", {}).catch(failure);
  });

  document.getElementById("mtatRun").addEventListener("click", function () {
    if (source.value === "vcenter" && !clusterSelect.value) {
      document.getElementById("mtatProgress").textContent = "Discover clusters and history, then select a cluster before running.";
      return;
    }
    document.getElementById("mtatProgress").textContent = "Starting collection…";
    recordDiagnostic("Collection requested.");
    post("/api/plugins/mtat/jobs", payload(null)).then(function (result) {
      if (!result.data.id) {
        document.getElementById("mtatProgress").textContent = message(result.data, "Job rejected");
        return;
      }
      activeJob = result.data.id;
      document.getElementById("mtatCancel").disabled = false;
      var timer = setInterval(function () {
        fetch("/api/plugins/mtat/jobs/" + result.data.id, {credentials: "same-origin"})
          .then(function (response) { if (!response.ok) throw new Error("status rejected"); return response.json(); })
          .then(function (data) {
            document.getElementById("mtatProgress").textContent = message(data, data.stage || "");
            if (data.stage === "done" || data.stage === "failed" || data.stage === "cancelled") {
              clearInterval(timer);
              activeJob = null;
              document.getElementById("mtatCancel").disabled = true;
            }
            if (data.stage === "done") {
              markStepComplete(0, true);
              markStepComplete(1, true);
            }
            if (data.links || data.report) {
              renderReport(data, result.data.id);
            }
          }).catch(function () { clearInterval(timer); activeJob = null; document.getElementById("mtatCancel").disabled = true; failure(); });
      }, 1000);
    }).catch(failure);
  });
})();
""" + JS_MTAT_TCO
