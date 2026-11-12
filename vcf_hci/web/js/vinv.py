"""Experimental vSphere inventory page script. It calls only the vinv routes."""

JS_VINV = r"""
(function () {
  var panel = document.getElementById("vinv-experimental");
  if (!panel) return;
  var activeJob = null;
  var scanLibraryBusy = false;
  var enabled = false;
  var progress = document.getElementById("vinvProgress");
  var password = document.getElementById("vinvPassword");
  var clusterSelect = document.getElementById("vinvCluster");
  var certificatePin = "", reviewedCertificate = null, certificateVersion = 0, discoveryVersion = 0;
  var diagnosticLines = [];
  function say(text) { progress.textContent = text; }
  function failure(error) {
    var timedOut = error && error.name === "AbortError";
    say(timedOut ? "The request timed out. Check network access to vCenter from the machine running VCF-R." :
      "The request could not reach the Web UI or returned an invalid response. Sign in again or retry.");
    recordDiagnostic(timedOut ? "request_timeout" : "request_failed");
  }
  function el(id) { return document.getElementById(id); }
  el("vinvForm").addEventListener("submit", function (event) { event.preventDefault(); });

  function recordDiagnostic(text) {
    diagnosticLines.push(new Date().toISOString() + " " + text);
    if (diagnosticLines.length > 20) diagnosticLines.shift();
    el("vinvDiagnostics").textContent = diagnosticLines.join("\n");
  }
  function message(data, fallback) {
    if (data.error_code) recordDiagnostic(data.error_code + (data.stage ? " at " + data.stage : "") + (data.reference ? " Reference: " + data.reference : ""));
    return (data.error || fallback) + (data.error_code ? " [" + data.error_code + "]" : "") +
      (data.reference ? " Reference: " + data.reference : "");
  }

  function clearCertificate() {
    certificateVersion += 1; certificatePin = ""; reviewedCertificate = null;
    el("vinvCertReview").hidden = true;
    el("vinvClearPin").hidden = true;
    el("vinvPinStatus").textContent = "No certificate pinned. Verify TLS uses the system trust store.";
  }
  function resetClusters() {
    discoveryVersion += 1;
    clusterSelect.replaceChildren(new Option("All clusters", ""));
    el("vinvDiscoveryStatus").textContent = "Discover clusters to limit collection to one cluster, or collect all clusters.";
  }
  function populateClusters(data) {
    if (!Array.isArray(data.clusters)) return;
    var previous = clusterSelect.value;
    clusterSelect.replaceChildren(new Option("All clusters", ""));
    data.clusters.forEach(function (item) { clusterSelect.add(new Option(item.name + " (" + item.id + ")", item.id)); });
    if (data.clusters.length === 1) clusterSelect.value = data.clusters[0].id;
    else if (data.clusters.some(function (item) { return item.id === previous; })) clusterSelect.value = previous;
    el("vinvDiscoveryStatus").textContent = data.clusters.length ?
      data.clusters.length + " accessible cluster(s) found." : "No accessible clusters found; collection covers standalone hosts only.";
  }
  el("vinvEndpoint").addEventListener("input", function () { clearCertificate(); resetClusters(); });
  el("vinvEndpoint").addEventListener("change", function () { clearCertificate(); resetClusters(); });
  el("vinvUsername").addEventListener("change", resetClusters);

  function certificateTarget() {
    var raw = el("vinvEndpoint").value.trim(), target;
    try { target = new URL(raw.indexOf("://") < 0 ? "https://" + raw : raw); }
    catch (error) { return {error: "Enter a valid HTTPS vCenter endpoint."}; }
    if (target.protocol !== "https:" || target.username || target.password) return {error: "Enter an HTTPS endpoint without embedded credentials."};
    if (target.hostname.indexOf(":") !== -1 || target.hostname.charAt(0) === "[") {
      return {error: "Certificate review requires a DNS hostname or IPv4 endpoint. Use system CA verification for an IPv6 literal."};
    }
    return {target: target};
  }

  function buttons() {
    panel.querySelectorAll("button[data-action]").forEach(function (button) {
      var action = button.getAttribute("data-action");
      if (action === "vinv-discover-scans") button.disabled = scanLibraryBusy || !!activeJob;
      else if (action === "vinv-load-scan") button.disabled = scanLibraryBusy || !!activeJob || !el("vinvRedfishScan").value;
      else if (action === "vinv-cancel") button.disabled = !activeJob;
      else if (action === "vinv-preflight" || action === "vinv-run" || action === "vinv-import" || action === "vinv-discover") button.disabled = !enabled || !!activeJob || scanLibraryBusy;
    });
  }

  el("vinvRedfishScan").addEventListener("change", buttons);
  el("vinvScanLibrary").addEventListener("input", function () {
    el("vinvRedfishScan").replaceChildren(new Option("Find scans to choose a hardware capture", ""));
    buttons();
  });

  function payload(extra) {
    var body = {
      endpoint: el("vinvEndpoint").value,
      username: el("vinvUsername").value,
      password: password.value,
      certificate_pin: certificatePin,
      cluster: clusterSelect.value,
      verify_tls: el("vinvVerifyTls").checked,
      include_network_hints: el("vinvHints").checked,
      include_file_info: el("vinvFileInfo").checked,
      acknowledged: el("vinvAck").checked
    };
    if (extra) Object.keys(extra).forEach(function (key) { body[key] = extra[key]; });
    return typeof pluginCredentials === "undefined" ? body : pluginCredentials.payload("vinv", body);
  }

  function post(url, body) {
    var controller = new AbortController();
    var timeout = setTimeout(function () { controller.abort(); }, 120000);
    return fetch(url, {
      signal: controller.signal,
      method: "POST",
      credentials: "same-origin",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body || {})
    }).then(function (response) {
      return response.json().catch(function () {
        return {error: "Web UI returned HTTP " + response.status + " without a JSON response. Restart the Web UI and retry.",
                error_code: "http_" + response.status};
      }).then(function (data) { return {ok: response.ok, status: response.status, data: data}; });
    }).finally(function () { clearTimeout(timeout); });
  }

  function cell(row, text) {
    var td = document.createElement("td");
    td.textContent = text === undefined || text === null ? "" : String(text);
    row.append(td);
    return td;
  }

  function actionButton(label, action, id) {
    var button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.setAttribute("data-action", action);
    button.setAttribute("data-entry", id);
    return button;
  }

  function actionLink(label, href) {
    var link = document.createElement("a");
    link.href = href;
    link.textContent = label;
    return link;
  }

  function renderLibrary(entries) {
    var body = el("vinvLibrary").querySelector("tbody");
    body.replaceChildren();
    (entries || []).forEach(function (entry) {
      var row = document.createElement("tr");
      cell(row, entry.source);
      cell(row, entry.vcenter_server);
      cell(row, entry.generated_utc);
      cell(row, entry.hosts);
      cell(row, entry.vms);
      cell(row, entry.health_findings);
      cell(row, entry.attached ? "Yes" : "No");
      var actions = cell(row, "");
      var base = "/api/plugins/vinv/library/" + entry.id;
      actions.append(actionLink("Workbook", base + "/export.xlsx"), " ",
                     actionLink("Obfuscated workbook", base + "/export.xlsx?obfuscated=1"), " ",
                     actionLink("ZIP", base + "/export.zip"), " ",
                     actionLink("Obfuscated ZIP", base + "/export.zip?obfuscated=1"), " ",
                     entry.attached ? actionButton("Detach", "vinv-detach", entry.id) : actionButton("Attach", "vinv-attach", entry.id),
                     " ", actionButton("Remove", "vinv-delete", entry.id));
      body.append(row);
    });
  }

  function refresh() {
    return fetch("/api/plugins/vinv", {credentials: "same-origin"})
      .then(function (response) { return response.json(); })
      .then(function (data) {
        el("vinvBanner").textContent = data.warning || el("vinvBanner").textContent;
        el("vinvEnablement").hidden = true;
        enabled = !!data.enabled;
        renderLibrary(data.library);
        buttons();
      }).catch(failure);
  }

  function renderPreflight(data) {
    var box = el("vinvPreflightDetails");
    box.replaceChildren();
    if (!data.ready) return;
    var summary = document.createElement("p");
    summary.textContent = "vCenter " + data.server_version + " (" + data.server_build + ") · " + data.host_count + " hosts · " +
      data.vm_count + " VMs · " + data.datastore_count + " datastores · clusters: " +
      (data.clusters || []).map(function (item) { return item.name; }).join(", ");
    box.append(summary);
    (data.messages || []).forEach(function (message) {
      var line = document.createElement("p");
      line.textContent = message;
      box.append(line);
    });
  }

  function poll(id) {
    var timer = setInterval(function () {
      fetch("/api/plugins/vinv/jobs/" + id, {credentials: "same-origin"})
        .then(function (response) { if (!response.ok) throw new Error("status rejected"); return response.json(); })
        .then(function (data) {
          var counter = data.total ? " (" + data.completed + "/" + data.total + ")" : "";
          say(data.stage === "failed" ? message({error: data.message, error_code: data.error_code, reference: data.reference}, "Collection failed")
            : (data.message || data.stage || "") + counter);
          if (data.stage === "done") password.value = "";
          if (data.stage === "done" || data.stage === "failed" || data.stage === "cancelled") {
            clearInterval(timer);
            activeJob = null;
            buttons();
            refresh();
          }
        }).catch(function () { clearInterval(timer); activeJob = null; buttons(); failure(); });
    }, 1000);
  }

  function readFile(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onerror = reject;
      reader.onload = function () { resolve(String(reader.result).split(",")[1] || ""); };
      reader.readAsDataURL(file);
    });
  }

  var handlers = {
    "vinv-discover-scans": function () {
      scanLibraryBusy = true; buttons();
      var select = el("vinvRedfishScan");
      select.replaceChildren(new Option("Choose a Redfish scan", ""));
      el("vinvScanStatus").textContent = "Finding scans…";
      post("/api/fleet/discover", {library_dir: el("vinvScanLibrary").value}).then(function (result) {
        if (!result.ok || !result.data.ok) { el("vinvScanStatus").textContent = result.data.error || "Scan discovery failed."; return; }
        (result.data.scans || []).forEach(function (scan) {
          select.add(new Option(scan.scan_id + " · " + (scan.host_count == null ? "unknown" : scan.host_count) + " hosts" +
            (scan.obfuscated ? " · Obfuscated" : "") + (scan.is_zip ? " · ZIP" : ""), scan.path));
        });
        el("vinvScanStatus").textContent = select.options.length > 1 ? "Select the hardware capture for the same ESXi hosts. Use original identifiers for matching." : "No scans found in this folder.";
      }).catch(function () { el("vinvScanStatus").textContent = "Scan discovery failed. Retry or use Scan Library."; })
        .finally(function () { scanLibraryBusy = false; buttons(); });
    },
    "vinv-load-scan": function () {
      var scan = el("vinvRedfishScan").value;
      if (!scan) return;
      scanLibraryBusy = true; buttons();
      el("vinvScanStatus").textContent = "Loading the selected Redfish scan and preparing reports…";
      post("/api/fleet/assemble", {library_dir: el("vinvScanLibrary").value, scan_paths: [scan], obfuscate: false}).then(function (result) {
        if (!result.ok || !result.data.ok) { el("vinvScanStatus").textContent = result.data.error || "Scan loading failed."; return; }
        el("vinvScanStatus").textContent = "Redfish scan loaded: " + result.data.total_hosts + " hosts. Attach a vSphere inventory above, then download the reconciled report.";
        if (typeof onScanDone === "function") onScanDone(Object.assign({}, result.data, {n_ok: result.data.total_hosts, n_total: result.data.total_hosts, is_assemble: true}));
      }).catch(function () { el("vinvScanStatus").textContent = "Scan loading failed. Check the active assessment before retrying."; })
        .finally(function () { scanLibraryBusy = false; buttons(); });
    },
    "vinv-review-cert": function () {
      var version = ++certificateVersion;
      el("vinvCertReview").hidden = true;
      reviewedCertificate = null;
      var parsed = certificateTarget();
      if (parsed.error) { el("vinvPinStatus").textContent = parsed.error; return; }
      var target = parsed.target;
      el("vinvPinStatus").textContent = "Inspecting certificate without sending credentials…";
      recordDiagnostic("Certificate review requested for " + target.host + ".");
      fetch("/api/inspect-cert?host=" + encodeURIComponent(target.hostname) + "&port=" + encodeURIComponent(target.port || "443"), {credentials: "same-origin"})
        .then(function (response) { return response.json(); }).then(function (data) {
          if (version !== certificateVersion) return;
          if (!data.reachable || !(data.sha256 || data.sha256_raw)) throw new Error("inspection failed");
          reviewedCertificate = data;
          el("vinvCertDetails").textContent = "Endpoint: " + target.host + "\nSubject: " + (data.subject_cn || "Unknown") + "\nIssuer: " +
            (data.issuer_cn || "Unknown") + "\nExpires: " + (data.not_after || "Unknown") + "\nSHA-256: " + (data.sha256 || data.sha256_raw);
          el("vinvCertReview").hidden = false;
          el("vinvPinStatus").textContent = "Review the fingerprint before trusting this certificate.";
        }).catch(function () {
          if (version !== certificateVersion) return;
          el("vinvPinStatus").textContent = "Certificate inspection failed. Check the endpoint and HTTPS connectivity.";
          recordDiagnostic("certificate_inspection_failed");
        });
    },
    "vinv-accept-pin": function () {
      if (!reviewedCertificate) return;
      certificatePin = reviewedCertificate.sha256 || reviewedCertificate.sha256_raw;
      el("vinvPinStatus").textContent = "SHA-256 pin enforced for this endpoint. A different certificate will block the connection before credentials are sent.";
      el("vinvClearPin").hidden = false;
      el("vinvCertReview").hidden = true;
      recordDiagnostic("Certificate pin accepted.");
    },
    "vinv-clear-pin": function () { clearCertificate(); recordDiagnostic("Certificate pin cleared."); },
    "vinv-discover": function () {
      var version = ++discoveryVersion;
      say("Discovering vCenter clusters…");
      recordDiagnostic("Discovery requested.");
      post("/api/plugins/vinv/preflight", payload({cluster: ""})).then(function (result) {
        if (version !== discoveryVersion) return;
        populateClusters(result.data);
        say(message(result.data, result.data.ready ? "Discovery complete. Select a cluster or keep All clusters." : "Discovery blocked"));
        renderPreflight(result.data);
      }).catch(failure);
    },
    "vinv-preflight": function () {
      var version = discoveryVersion;
      say("Connecting to vCenter…");
      recordDiagnostic("Connection requested.");
      post("/api/plugins/vinv/preflight", payload()).then(function (result) {
        if (version !== discoveryVersion) return;
        populateClusters(result.data);
        say(message(result.data, result.data.ready ? "Connected. Select a cluster or keep All clusters." : "Connection blocked"));
        renderPreflight(result.data);
      }).catch(failure);
    },
    "vinv-run": function () {
      recordDiagnostic("Collection requested.");
      post("/api/plugins/vinv/jobs", payload()).then(function (result) {
        if (!result.data.id) { say(message(result.data, "Job rejected")); return; }
        activeJob = result.data.id;
        buttons();
        poll(activeJob);
      }).catch(failure);
    },
    "vinv-cancel": function () {
      if (activeJob) post("/api/plugins/vinv/jobs/" + activeJob + "/cancel", {}).catch(failure);
    },
    "vinv-import": function () {
      var file = el("vinvWorkbook").files[0];
      if (!file) { say("Select a workbook or snapshot file"); return; }
      if (file.size > 50331648) { say("Select a file within the 48 MiB upload limit"); return; }
      say("Importing " + file.name);
      readFile(file).then(function (content) {
        return post("/api/plugins/vinv/import", {filename: file.name, content_base64: content, acknowledged: el("vinvAck").checked});
      }).then(function (result) {
        say(result.data.error ? message(result.data, "Import failed") : "Imported " + file.name);
        refresh();
      }).catch(failure);
    },
    "vinv-attach": function (button) {
      post("/api/plugins/vinv/library/" + button.getAttribute("data-entry") + "/attach", {})
        .then(function (result) { if (result.data.error) say(result.data.error); renderLibrary(result.data.entries); }).catch(failure);
    },
    "vinv-detach": function () {
      post("/api/plugins/vinv/detach", {})
        .then(function (result) { renderLibrary(result.data.entries); }).catch(failure);
    },
    "vinv-delete": function (button) {
      post("/api/plugins/vinv/library/" + button.getAttribute("data-entry") + "/delete", {})
        .then(function (result) { if (result.data.error) say(result.data.error); renderLibrary(result.data.entries); }).catch(failure);
    }
  };

  panel.addEventListener("click", function (event) {
    var button = event.target.closest("[data-action]");
    if (!button || !panel.contains(button)) return;
    var handler = handlers[button.getAttribute("data-action")];
    if (handler) { event.preventDefault(); handler(button); }
  });

  refresh();
})();
"""
