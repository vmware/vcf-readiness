"""Experimental MTAT TCO scenario explorer. Client-side only; prices never leave the page."""

JS_MTAT_TCO = r"""
(function () {
  if (window.__mtatTco) return;
  var card = document.getElementById("mtatTcoCard");
  if (!card) return;

  var SVG_NS = "http://www.w3.org/2000/svg";
  var TCO_DEFAULTS = {
    dimmSizeGb: 64,
    largeDimmAboveGb: 64,
    smallDimmPricePerGb: 50,
    largeDimmPricePerGb: 100,
    nvmePricePerGb: 1.5,
    nvmeDriveGb: 3840,
    overcommitMin: 1,
    overcommitMax: 3,
    overcommitStep: 0.1
  };
  var RATIOS = [0, 25, 50, 100];
  var RATIO_LABELS = {0: "DRAM only", 25: "25% (4:1)", 50: "50% (2:1)", 100: "100% (1:1)"};

  var overcommitInput = document.getElementById("mtatTcoOvercommit");
  var overcommitValue = document.getElementById("mtatTcoOvercommitValue");
  var observedHint = document.getElementById("mtatTcoObserved");
  var dimmSelect = document.getElementById("mtatTcoDimmSize");
  var dramPrice = document.getElementById("mtatTcoDramPrice");
  var dramState = document.getElementById("mtatTcoDramPriceState");
  var dramReset = document.getElementById("mtatTcoDramReset");
  var nvmePrice = document.getElementById("mtatTcoNvmePrice");
  var nvmeState = document.getElementById("mtatTcoNvmePriceState");
  var nvmeReset = document.getElementById("mtatTcoNvmeReset");
  var driveGbInput = document.getElementById("mtatTcoDriveGb");
  var kpis = document.getElementById("mtatTcoKpis");
  var lineSvg = document.getElementById("mtatTcoLineChart");
  var barSvg = document.getElementById("mtatTcoBarChart");
  var tooltip = document.getElementById("mtatTcoTooltip");
  var tableBody = document.getElementById("mtatTcoRows");

  var state = {summary: null, baseline: null, ratioPct: 50, dramCustom: false, nvmeCustom: false, overcommitTouched: false};

  var money = new Intl.NumberFormat("en-US", {style: "currency", currency: "USD", maximumFractionDigits: 0});
  var moneyCompact = new Intl.NumberFormat("en-US", {style: "currency", currency: "USD", notation: "compact", maximumFractionDigits: 1});
  var gbFormat = new Intl.NumberFormat("en-US", {maximumFractionDigits: 0});

  function num(value) {
    var n = Number(value);
    return isFinite(n) ? n : 0;
  }

  function nonNeg(value) {
    return Math.max(0, num(value));
  }

  function ceilWhole(value) {
    return Math.ceil(value - 1e-9);
  }

  function defaultDramPrice(dimmGb) {
    return Number(dimmGb) > TCO_DEFAULTS.largeDimmAboveGb ? TCO_DEFAULTS.largeDimmPricePerGb : TCO_DEFAULTS.smallDimmPricePerGb;
  }

  function baselineFromSummary(summary) {
    var vms = Array.isArray(summary.vms) ? summary.vms : [];
    var provisioned = vms.reduce(function (sum, vm) { return sum + nonNeg(vm.provisioned_gb); }, 0);
    if (!provisioned) provisioned = nonNeg(summary.total_consumed_gb);
    var physical = nonNeg(summary.total_physical_ram_gb);
    var ratios = (summary.sizing && summary.sizing.ratios) || {};
    var minDram = 0;
    var viable = {0: true};
    RATIOS.forEach(function (ratio) {
      var projection = ratios[String(ratio)];
      if (!projection) return;
      minDram = Math.max(minDram, nonNeg(projection.min_dram_required_gb));
      viable[ratio] = projection.viable !== false;
    });
    if (!minDram) minDram = 2 * nonNeg(summary.total_active_gb);
    return {
      provisionedGb: provisioned,
      physicalGb: physical,
      hosts: Math.max(1, Math.round(num(summary.connected_host_count))),
      minDramGb: minDram,
      viable: viable,
      observedOvercommit: physical > 0 ? provisioned / physical : 0
    };
  }

  // Capacity = provisioned / overcommit, split DRAM : NVMe as 1 : r. DRAM never drops
  // below the MTAT sizing floor, then rounds up to whole DIMMs and drives per host.
  function computeScenarios(baseline, inputs) {
    var overcommit = Math.max(0.01, num(inputs.overcommit));
    var dimmGb = nonNeg(inputs.dimmGb);
    var driveGb = nonNeg(inputs.driveGb);
    var dramPerGb = nonNeg(inputs.dramPricePerGb);
    var nvmePerGb = nonNeg(inputs.nvmePricePerGb);
    var hosts = Math.max(1, Math.round(num(baseline.hosts)));
    var capacity = nonNeg(baseline.provisionedGb) / overcommit;
    var scenarios = RATIOS.map(function (ratioPct) {
      var r = ratioPct / 100;
      var dramNeeded = capacity / (1 + r);
      var floorApplied = dramNeeded < baseline.minDramGb;
      var dramTarget = Math.max(dramNeeded, nonNeg(baseline.minDramGb));
      var dimmsPerHost = dimmGb > 0 ? ceilWhole(dramTarget / hosts / dimmGb) : 0;
      var dramPerHost = dimmGb > 0 ? dimmsPerHost * dimmGb : dramTarget / hosts;
      var tierPerHost = dramPerHost * r;
      var drivesPerHost = r > 0 && driveGb > 0 ? ceilWhole(tierPerHost / driveGb) : 0;
      var nvmePerHost = driveGb > 0 ? drivesPerHost * driveGb : tierPerHost;
      var dramGb = dramPerHost * hosts;
      var nvmeGb = nvmePerHost * hosts;
      var dramCost = dramGb * dramPerGb;
      var nvmeCost = nvmeGb * nvmePerGb;
      return {
        ratioPct: ratioPct,
        label: RATIO_LABELS[ratioPct],
        dramGb: dramGb,
        tierGb: tierPerHost * hosts,
        nvmeGb: nvmeGb,
        dimmsPerHost: dimmsPerHost,
        drivesPerHost: drivesPerHost,
        dramCost: dramCost,
        nvmeCost: nvmeCost,
        totalCost: dramCost + nvmeCost,
        floorApplied: floorApplied,
        viable: baseline.viable[ratioPct] !== false
      };
    });
    var dramOnly = scenarios[0].totalCost;
    scenarios.forEach(function (s) {
      s.savings = dramOnly - s.totalCost;
      s.savingsPct = dramOnly > 0 ? (s.savings / dramOnly) * 100 : 0;
    });
    return {capacityGb: capacity, overcommit: overcommit, scenarios: scenarios};
  }

  function currentInputs(overcommit) {
    return {
      overcommit: overcommit === undefined ? num(overcommitInput.value) : overcommit,
      dimmGb: num(dimmSelect.value),
      dramPricePerGb: nonNeg(dramPrice.value),
      nvmePricePerGb: nonNeg(nvmePrice.value),
      driveGb: nonNeg(driveGbInput.value)
    };
  }

  function svgEl(tag, attrs, text) {
    var el = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs || {}).forEach(function (key) { el.setAttribute(key, String(attrs[key])); });
    if (text !== undefined) el.textContent = text;
    return el;
  }

  function niceMax(value) {
    if (!(value > 0)) return 1;
    var power = Math.pow(10, Math.floor(Math.log10(value)));
    var steps = [1, 2, 2.5, 5, 10];
    for (var i = 0; i < steps.length; i++) {
      if (steps[i] * power >= value) return steps[i] * power;
    }
    return 10 * power;
  }

  function overcommitPoints() {
    var points = [];
    var steps = Math.round((TCO_DEFAULTS.overcommitMax - TCO_DEFAULTS.overcommitMin) / TCO_DEFAULTS.overcommitStep);
    for (var i = 0; i <= steps; i++) {
      points.push(Math.round((TCO_DEFAULTS.overcommitMin + i * TCO_DEFAULTS.overcommitStep) * 10) / 10);
    }
    return points;
  }

  function drawYAxis(svg, box, yMax) {
    for (var t = 0; t <= 4; t++) {
      var value = (yMax / 4) * t;
      var y = box.top + box.height - (value / yMax) * box.height;
      svg.appendChild(svgEl("line", {x1: box.left, x2: box.left + box.width, y1: y, y2: y, "class": "mtat-tco-grid"}));
      svg.appendChild(svgEl("text", {x: box.left - 6, y: y + 4, "text-anchor": "end", "class": "mtat-tco-axis"}, moneyCompact.format(value)));
    }
  }

  function renderLineChart(selected) {
    var points = overcommitPoints();
    var series = RATIOS.map(function () { return []; });
    var inputs = currentInputs();
    points.forEach(function (x) {
      var result = computeScenarios(state.baseline, Object.assign({}, inputs, {overcommit: x}));
      result.scenarios.forEach(function (s, idx) { series[idx].push(s.totalCost); });
    });
    var yMax = niceMax(Math.max.apply(null, series.map(function (s) { return Math.max.apply(null, s); })));
    var box = {left: 64, top: 14, width: 560, height: 210};
    var xFor = function (x) {
      return box.left + ((x - TCO_DEFAULTS.overcommitMin) / (TCO_DEFAULTS.overcommitMax - TCO_DEFAULTS.overcommitMin)) * box.width;
    };
    var yFor = function (v) { return box.top + box.height - (v / yMax) * box.height; };

    lineSvg.replaceChildren();
    lineSvg.appendChild(svgEl("title", {}, "Total memory cost by overcommit target for each NVMe tier ratio"));
    drawYAxis(lineSvg, box, yMax);
    points.forEach(function (x) {
      if (Math.abs((x * 2) - Math.round(x * 2)) > 1e-6) return;
      lineSvg.appendChild(svgEl("text", {x: xFor(x), y: box.top + box.height + 18, "text-anchor": "middle", "class": "mtat-tco-axis"}, x.toFixed(1) + "x"));
    });
    lineSvg.appendChild(svgEl("text", {x: box.left + box.width / 2, y: box.top + box.height + 36, "text-anchor": "middle", "class": "mtat-tco-axis-title"}, "Memory overcommit target"));

    var markerX = xFor(Math.min(TCO_DEFAULTS.overcommitMax, Math.max(TCO_DEFAULTS.overcommitMin, selected.overcommit)));
    lineSvg.appendChild(svgEl("line", {x1: markerX, x2: markerX, y1: box.top, y2: box.top + box.height, "class": "mtat-tco-marker"}));

    series.forEach(function (values, idx) {
      var ratio = RATIOS[idx];
      var d = values.map(function (v, i) { return (i ? "L" : "M") + xFor(points[i]).toFixed(1) + " " + yFor(v).toFixed(1); }).join(" ");
      var cls = "mtat-tco-line mtat-tco-r" + ratio + (ratio === state.ratioPct ? " mtat-tco-line-selected" : "");
      lineSvg.appendChild(svgEl("path", {d: d, "class": cls, "data-ratio": ratio}));
      var current = selected.scenarios[idx];
      var dot = svgEl("circle", {cx: markerX, cy: yFor(current.totalCost), r: 4, "class": "mtat-tco-dot mtat-tco-r" + ratio});
      dot.appendChild(svgEl("title", {}, current.label + ": " + money.format(current.totalCost)));
      lineSvg.appendChild(dot);
    });

    var hoverLine = svgEl("line", {x1: 0, x2: 0, y1: box.top, y2: box.top + box.height, "class": "mtat-tco-hover", visibility: "hidden"});
    lineSvg.appendChild(hoverLine);
    var overlay = svgEl("rect", {x: box.left, y: box.top, width: box.width, height: box.height, "class": "mtat-tco-overlay"});
    lineSvg.appendChild(overlay);

    overlay.addEventListener("pointermove", function (event) {
      var rect = lineSvg.getBoundingClientRect();
      var viewX = ((event.clientX - rect.left) / rect.width) * 640;
      var idx = Math.round(((viewX - box.left) / box.width) * (points.length - 1));
      idx = Math.max(0, Math.min(points.length - 1, idx));
      var x = xFor(points[idx]);
      hoverLine.setAttribute("x1", String(x));
      hoverLine.setAttribute("x2", String(x));
      hoverLine.setAttribute("visibility", "visible");
      tooltip.replaceChildren();
      var head = document.createElement("strong");
      head.textContent = points[idx].toFixed(1) + "x overcommit";
      tooltip.appendChild(head);
      RATIOS.forEach(function (ratio, sIdx) {
        var line = document.createElement("div");
        var swatch = document.createElement("span");
        swatch.className = "mtat-tco-swatch mtat-tco-r" + ratio;
        line.append(swatch, document.createTextNode(RATIO_LABELS[ratio] + ": " + money.format(series[sIdx][idx])));
        tooltip.appendChild(line);
      });
      tooltip.hidden = false;
      var left = (x / 640) * rect.width;
      tooltip.style.left = Math.min(Math.max(0, left + 12), Math.max(0, rect.width - tooltip.offsetWidth)) + "px";
      tooltip.style.top = "8px";
    });
    overlay.addEventListener("pointerleave", function () {
      hoverLine.setAttribute("visibility", "hidden");
      tooltip.hidden = true;
    });
    lineSvg.setAttribute("aria-label", "Line chart of total memory cost from " + TCO_DEFAULTS.overcommitMin.toFixed(1) + "x to " + TCO_DEFAULTS.overcommitMax.toFixed(1) + "x overcommit. At " + selected.overcommit.toFixed(1) + "x: " + selected.scenarios.map(function (s) { return s.label + " " + money.format(s.totalCost); }).join(", ") + ".");
  }

  function selectRatio(ratio) {
    var ratioSelect = document.getElementById("mtatSizingRatioSelect");
    if (!ratioSelect || ratio === 0) return;
    ratioSelect.value = String(ratio);
    ratioSelect.dispatchEvent(new Event("change", {bubbles: true}));
  }

  function renderBarChart(selected) {
    var scenarios = selected.scenarios;
    var yMax = niceMax(Math.max.apply(null, scenarios.map(function (s) { return s.totalCost; })));
    var box = {left: 64, top: 24, width: 560, height: 180};
    var slot = box.width / scenarios.length;
    var barWidth = Math.min(72, slot * 0.55);
    var yFor = function (v) { return box.top + box.height - (v / yMax) * box.height; };

    barSvg.replaceChildren();
    barSvg.appendChild(svgEl("title", {}, "DRAM and NVMe cost per NVMe tier ratio at the selected overcommit"));
    drawYAxis(barSvg, box, yMax);

    scenarios.forEach(function (s, idx) {
      var x = box.left + slot * idx + (slot - barWidth) / 2;
      var group = svgEl("g", {"class": "mtat-tco-bar" + (s.ratioPct === state.ratioPct ? " mtat-tco-selected" : ""), "data-ratio": s.ratioPct});
      var dramTop = yFor(s.dramCost);
      group.appendChild(svgEl("rect", {x: x, y: dramTop, width: barWidth, height: Math.max(0, box.top + box.height - dramTop), "class": "mtat-tco-dram"}));
      var nvmeTop = yFor(s.dramCost + s.nvmeCost);
      group.appendChild(svgEl("rect", {x: x, y: nvmeTop, width: barWidth, height: Math.max(0, dramTop - nvmeTop), "class": "mtat-tco-nvme"}));
      group.appendChild(svgEl("text", {x: x + barWidth / 2, y: nvmeTop - 6, "text-anchor": "middle", "class": "mtat-tco-value"}, moneyCompact.format(s.totalCost)));
      group.appendChild(svgEl("text", {x: x + barWidth / 2, y: box.top + box.height + 18, "text-anchor": "middle", "class": "mtat-tco-axis"}, s.label));
      var note = s.ratioPct === 0 ? "Baseline" : (s.savings >= 0 ? "Saves " : "Costs ") + Math.abs(s.savingsPct).toFixed(1) + "%";
      group.appendChild(svgEl("text", {x: x + barWidth / 2, y: box.top + box.height + 34, "text-anchor": "middle", "class": "mtat-tco-axis" + (s.savings > 0 ? " mtat-tco-good" : "")}, note));
      group.appendChild(svgEl("title", {}, s.label + ": DRAM " + money.format(s.dramCost) + " + NVMe " + money.format(s.nvmeCost) + " = " + money.format(s.totalCost)));
      if (s.ratioPct !== 0) {
        group.setAttribute("tabindex", "0");
        group.setAttribute("role", "button");
        group.setAttribute("aria-label", "Select " + s.label + " tier ratio, total " + money.format(s.totalCost));
        group.addEventListener("click", function () { selectRatio(s.ratioPct); });
        group.addEventListener("keydown", function (event) {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            selectRatio(s.ratioPct);
          }
        });
      }
      barSvg.appendChild(group);
    });
  }

  function renderKpis(selected) {
    var chosen = selected.scenarios.filter(function (s) { return s.ratioPct === state.ratioPct; })[0] || selected.scenarios[2];
    var dramOnly = selected.scenarios[0];
    var cards = [
      {
        id: "mtatTcoKpiTotal",
        title: "Selected Scenario Cost",
        primary: money.format(chosen.totalCost),
        sub: chosen.label + " at " + selected.overcommit.toFixed(1) + "x overcommit · " + gbFormat.format(chosen.dramGb) + " GB DRAM + " + gbFormat.format(chosen.nvmeGb) + " GB NVMe"
      },
      {
        id: "mtatTcoKpiSavings",
        title: "Savings vs DRAM Only",
        primary: (chosen.savings < 0 ? "-" : "") + money.format(Math.abs(chosen.savings)) + " (" + chosen.savingsPct.toFixed(1) + "%)",
        sub: "DRAM-only cost at the same overcommit: " + money.format(dramOnly.totalCost) + " for " + gbFormat.format(dramOnly.dramGb) + " GB"
      },
      {
        id: "mtatTcoKpiHost",
        title: "Per-Host Build",
        primary: chosen.dimmsPerHost + " × " + dimmSelect.value + " GB DIMMs" + (chosen.drivesPerHost ? " + " + chosen.drivesPerHost + " × " + gbFormat.format(nonNeg(driveGbInput.value)) + " GB NVMe" : ""),
        sub: "DRAM $" + nonNeg(dramPrice.value).toFixed(2) + "/GB (" + (state.dramCustom ? "custom" : "default") + ") · NVMe $" + nonNeg(nvmePrice.value).toFixed(2) + "/GB (" + (state.nvmeCustom ? "custom" : "default") + ") · " + state.baseline.hosts + " hosts"
      }
    ];
    kpis.replaceChildren();
    cards.forEach(function (c) {
      var el = document.createElement("div");
      el.className = "mtat-kpi-card";
      el.id = c.id;
      var h4 = document.createElement("h4");
      h4.textContent = c.title;
      var primary = document.createElement("div");
      primary.className = "mtat-kpi-primary";
      primary.textContent = c.primary;
      var sub = document.createElement("div");
      sub.className = "mtat-kpi-sub";
      sub.textContent = c.sub;
      el.append(h4, primary, sub);
      kpis.appendChild(el);
    });
  }

  function renderTable(selected) {
    tableBody.replaceChildren();
    selected.scenarios.forEach(function (s) {
      var tr = document.createElement("tr");
      tr.setAttribute("data-ratio", String(s.ratioPct));
      if (s.ratioPct === state.ratioPct) tr.className = "mtat-tco-row-selected";
      var notes = [];
      if (s.floorApplied) notes.push("DRAM floor applied (2x active / pinned)");
      if (!s.viable) notes.push("Review qualification");
      var cells = [
        {text: s.label},
        {text: gbFormat.format(s.dramGb), numeric: true},
        {text: String(s.dimmsPerHost), numeric: true},
        {text: gbFormat.format(s.tierGb), numeric: true},
        {text: String(s.drivesPerHost), numeric: true},
        {text: money.format(s.dramCost), numeric: true},
        {text: money.format(s.nvmeCost), numeric: true},
        {text: money.format(s.totalCost), numeric: true},
        {text: s.ratioPct === 0 ? "—" : (s.savings < 0 ? "-" : "") + money.format(Math.abs(s.savings)) + " (" + s.savingsPct.toFixed(1) + "%)", numeric: true},
        {text: notes.join("; ") || "—"}
      ];
      cells.forEach(function (c) {
        var td = document.createElement("td");
        if (c.numeric) td.className = "numeric";
        td.textContent = c.text;
        tr.appendChild(td);
      });
      tableBody.appendChild(tr);
    });
  }

  function updatePriceStates() {
    dramState.textContent = state.dramCustom ? "Custom price" : "Default price";
    dramState.className = "badge " + (state.dramCustom ? "badge-warning" : "badge-info");
    nvmeState.textContent = state.nvmeCustom ? "Custom price" : "Default price";
    nvmeState.className = "badge " + (state.nvmeCustom ? "badge-warning" : "badge-info");
    dramReset.disabled = !state.dramCustom;
    nvmeReset.disabled = !state.nvmeCustom;
  }

  function render() {
    updatePriceStates();
    if (!state.baseline) return;
    var overcommit = num(overcommitInput.value);
    overcommitValue.textContent = overcommit.toFixed(1) + "x";
    var selected = computeScenarios(state.baseline, currentInputs(overcommit));
    renderKpis(selected);
    renderLineChart(selected);
    renderBarChart(selected);
    renderTable(selected);
  }

  function clampOvercommit(value) {
    var clamped = Math.min(TCO_DEFAULTS.overcommitMax, Math.max(TCO_DEFAULTS.overcommitMin, value));
    return Math.round(clamped / TCO_DEFAULTS.overcommitStep) * TCO_DEFAULTS.overcommitStep;
  }

  overcommitInput.min = String(TCO_DEFAULTS.overcommitMin);
  overcommitInput.max = String(TCO_DEFAULTS.overcommitMax);
  overcommitInput.step = String(TCO_DEFAULTS.overcommitStep);
  dimmSelect.value = String(TCO_DEFAULTS.dimmSizeGb);
  dramPrice.value = String(defaultDramPrice(TCO_DEFAULTS.dimmSizeGb));
  nvmePrice.value = TCO_DEFAULTS.nvmePricePerGb.toFixed(2);
  driveGbInput.value = String(TCO_DEFAULTS.nvmeDriveGb);

  overcommitInput.addEventListener("input", function () {
    state.overcommitTouched = true;
    render();
  });
  dimmSelect.addEventListener("change", function () {
    if (!state.dramCustom) dramPrice.value = String(defaultDramPrice(dimmSelect.value));
    render();
  });
  dramPrice.addEventListener("input", function () {
    state.dramCustom = true;
    render();
  });
  dramReset.addEventListener("click", function () {
    state.dramCustom = false;
    dramPrice.value = String(defaultDramPrice(dimmSelect.value));
    render();
  });
  nvmePrice.addEventListener("input", function () {
    state.nvmeCustom = true;
    render();
  });
  nvmeReset.addEventListener("click", function () {
    state.nvmeCustom = false;
    nvmePrice.value = TCO_DEFAULTS.nvmePricePerGb.toFixed(2);
    render();
  });
  driveGbInput.addEventListener("input", render);

  window.__mtatTco = {
    defaults: TCO_DEFAULTS,
    defaultDramPrice: defaultDramPrice,
    baselineFromSummary: baselineFromSummary,
    computeScenarios: computeScenarios,
    update: function (summary, ratioPct) {
      if (!summary) return;
      state.ratioPct = RATIOS.indexOf(Number(ratioPct)) > 0 ? Number(ratioPct) : 50;
      if (summary !== state.summary) {
        state.summary = summary;
        state.baseline = baselineFromSummary(summary);
        observedHint.textContent = state.baseline.physicalGb > 0
          ? "Observed: " + state.baseline.observedOvercommit.toFixed(2) + "x (" + gbFormat.format(state.baseline.provisionedGb) + " GB provisioned on " + gbFormat.format(state.baseline.physicalGb) + " GB DRAM)"
          : "Observed: no connected host DRAM reported";
        if (!state.overcommitTouched) {
          overcommitInput.value = clampOvercommit(state.baseline.observedOvercommit).toFixed(1);
        }
      }
      render();
    }
  };
  updatePriceStates();
})();
"""
