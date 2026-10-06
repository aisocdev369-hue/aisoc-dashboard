/*
 * Dashboard rendering for the Stage 3 preview.
 * All data is simulated (see mock-data.js). Text is set with textContent,
 * never innerHTML, so values from the data cannot inject markup.
 */
(function () {
  "use strict";

  var D = window.SOC_MOCK;
  if (!D) {
    console.error("SOC_MOCK is missing. Check that assets/mock-data.js loaded.");
    return;
  }

  var SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
  var SEV_COLOR = { critical: "var(--sev-critical)", high: "var(--sev-high)", medium: "var(--sev-medium)", low: "var(--sev-low)" };
  var state = { q: "", sev: "all", status: "all", selectedId: null };

  function h(tag, props, kids) {
    var node = document.createElement(tag);
    if (props) {
      Object.keys(props).forEach(function (key) {
        if (key === "text") node.textContent = props[key];
        else if (key === "class") node.className = props[key];
        else node.setAttribute(key, props[key]);
      });
    }
    (kids || []).forEach(function (child) {
      if (child) node.appendChild(child);
    });
    return node;
  }

  function $(id) {
    return document.getElementById(id);
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
    return node;
  }

  function fmtDateTime(iso) {
    return new Date(iso).toLocaleString(undefined, {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"
    });
  }

  function fmtTime(iso) {
    return new Date(iso).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }

  function sevBadge(sev) {
    return h("span", { class: "sev sev-" + sev, text: SEV_LABEL[sev] });
  }

  function statusPill(status) {
    return h("span", { class: "status-pill st-" + status.toLowerCase(), text: status });
  }

  /* ---------- KPIs ---------- */
  function renderKPIs() {
    var alerts = D.alerts;
    var items = [
      { label: "Alerts (24h)", value: alerts.length, sub: "Simulated", cls: "" },
      { label: "Critical", value: alerts.filter(function (a) { return a.severity === "critical"; }).length, sub: "Needs immediate triage", cls: "kpi-critical" },
      { label: "High", value: alerts.filter(function (a) { return a.severity === "high"; }).length, sub: "Triage within one hour", cls: "kpi-high" },
      { label: "Open cases", value: alerts.filter(function (a) { return a.status !== "Closed"; }).length,
        sub: alerts.filter(function (a) { return a.status === "Investigating"; }).length + " under investigation", cls: "kpi-open" }
    ];
    var box = clear($("kpis"));
    items.forEach(function (it) {
      box.appendChild(h("article", { class: "kpi " + it.cls }, [
        h("p", { class: "kpi-label", text: it.label }),
        h("p", { class: "kpi-value", text: String(it.value) }),
        h("p", { class: "kpi-sub", text: it.sub })
      ]));
    });
  }

  /* ---------- Trend (inline SVG) ---------- */
  function svgEl(name, attrs) {
    var node = document.createElementNS("http://www.w3.org/2000/svg", name);
    Object.keys(attrs || {}).forEach(function (k) {
      node.setAttribute(k, attrs[k]);
    });
    return node;
  }

  function renderTrend() {
    var W = 640, H = 220, P = { t: 14, r: 14, b: 30, l: 34 };
    var data = D.hourly;
    var max = Math.max.apply(null, [1].concat(data.map(function (d) { return d.count; })));
    var iw = W - P.l - P.r, ih = H - P.t - P.b;
    function x(i) { return P.l + (i / (data.length - 1)) * iw; }
    function y(v) { return P.t + ih - (v / max) * ih; }

    var svg = svgEl("svg", {
      viewBox: "0 0 " + W + " " + H,
      role: "img",
      "aria-label": "Alerts per hour over the last 24 hours. Simulated data."
    });

    // Gridlines and y-axis labels
    [0, Math.round(max / 2), max].forEach(function (v) {
      svg.appendChild(svgEl("line", { x1: P.l, x2: W - P.r, y1: y(v), y2: y(v), class: "grid" }));
      var label = svgEl("text", { x: P.l - 8, y: y(v) + 4, "text-anchor": "end", class: "axis" });
      label.textContent = String(v);
      svg.appendChild(label);
    });

    // Area and line
    var pts = data.map(function (d, i) { return x(i) + "," + y(d.count); });
    svg.appendChild(svgEl("polygon", {
      points: [P.l + "," + (P.t + ih)].concat(pts, [(W - P.r) + "," + (P.t + ih)]).join(" "),
      class: "area"
    }));
    svg.appendChild(svgEl("polyline", { points: pts.join(" "), class: "line" }));

    // Points with native tooltips
    data.forEach(function (d, i) {
      var c = svgEl("circle", { cx: x(i), cy: y(d.count), r: 3.5, class: "dot-point" });
      var t = svgEl("title");
      t.textContent = fmtTime(d.hour) + ": " + d.count + " alerts (simulated)";
      c.appendChild(t);
      svg.appendChild(c);
    });

    // X-axis labels every 4 hours
    data.forEach(function (d, i) {
      if (i % 4 === 0) {
        var lbl = svgEl("text", { x: x(i), y: H - 8, "text-anchor": "middle", class: "axis" });
        lbl.textContent = fmtTime(d.hour);
        svg.appendChild(lbl);
      }
    });

    clear($("trend")).appendChild(svg);
  }

  /* ---------- Severity distribution ---------- */
  function renderSeverity() {
    var counts = {};
    D.severities.forEach(function (s) { counts[s] = 0; });
    D.alerts.forEach(function (a) { counts[a.severity]++; });
    var total = D.alerts.length || 1;

    var bar = h("div", { class: "stack-bar", role: "img",
      "aria-label": D.severities.map(function (s) { return SEV_LABEL[s] + " " + counts[s]; }).join(", ") });
    D.severities.forEach(function (s) {
      bar.appendChild(h("span", { style: "width:" + (counts[s] / total * 100) + "%;background:" + SEV_COLOR[s] }));
    });

    var legend = h("ul", { class: "legend" });
    D.severities.forEach(function (s) {
      legend.appendChild(h("li", null, [
        h("span", { class: "swatch", "aria-hidden": "true" }),
        h("span", { text: SEV_LABEL[s] }),
        h("strong", { text: String(counts[s]) })
      ]));
      legend.lastChild.querySelector(".swatch").style.background = SEV_COLOR[s];
    });

    clear($("severity")).appendChild(h("div", null, [bar, legend]));
  }

  /* ---------- Top hosts ---------- */
  function renderHosts() {
    var max = Math.max.apply(null, [1].concat(D.hosts.map(function (x) { return x.count; })));
    var list = h("ol", { class: "bars" });
    D.hosts.forEach(function (x) {
      var row = h("li", null, [
        h("span", { class: "bar-label", text: x.host }),
        h("span", { class: "bar-track" }, [
          h("span", { class: "bar-fill", style: "width:" + (x.count / max * 100) + "%" })
        ]),
        h("strong", { class: "bar-value", text: String(x.count) })
      ]);
      list.appendChild(row);
    });
    clear($("hosts")).appendChild(list);
  }

  /* ---------- Incident timeline ---------- */
  function renderTimeline() {
    var inc = D.incident;
    var list = h("ol", { class: "timeline" });
    inc.timeline.forEach(function (ev) {
      list.appendChild(h("li", null, [
        h("time", { datetime: ev.at, text: fmtDateTime(ev.at) }),
        h("p", { text: ev.text })
      ]));
    });
    var head = h("div", { class: "incident-head" }, [
      h("p", { class: "incident-id", text: inc.id }),
      sevBadge(inc.severity),
      statusPill(inc.status),
      h("p", { class: "incident-title", text: inc.title })
    ]);
    clear($("timeline")).append(head, list);
  }

  /* ---------- Alerts table and filters ---------- */
  function filteredAlerts() {
    var q = state.q.trim().toLowerCase();
    return D.alerts.filter(function (a) {
      if (state.sev !== "all" && a.severity !== state.sev) return false;
      if (state.status !== "all" && a.status !== state.status) return false;
      if (!q) return true;
      return [a.rule, a.host, a.sourceIp, a.mitre, a.id].join(" ").toLowerCase().indexOf(q) !== -1;
    });
  }

  function selectAlert(id) {
    state.selectedId = id;
    renderAlerts();
  }

  function renderAlerts() {
    var rows = filteredAlerts();
    var body = clear($("rows"));

    rows.forEach(function (a) {
      var tr = h("tr", {
        tabindex: "0",
        "data-id": a.id,
        "aria-selected": String(a.id === state.selectedId),
        class: a.id === state.selectedId ? "is-selected" : ""
      }, [
        h("td", { text: fmtDateTime(a.timestamp) }),
        h("td", null, [sevBadge(a.severity)]),
        h("td", { class: "rule", text: a.rule }),
        h("td", { class: "mono", text: a.host }),
        h("td", { class: "mono", text: a.sourceIp }),
        h("td", { class: "mono small", text: a.mitre }),
        h("td", null, [statusPill(a.status)])
      ]);
      tr.addEventListener("click", function () { selectAlert(a.id); });
      tr.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          selectAlert(a.id);
        }
      });
      body.appendChild(tr);
    });

    $("count").textContent = rows.length + " of " + D.alerts.length + " alerts shown (simulated)";
    $("empty").hidden = rows.length !== 0;
    renderDetail();
  }

  function renderDetail() {
    var box = clear($("detail"));
    var a = D.alerts.filter(function (x) { return x.id === state.selectedId; })[0];
    if (!a) {
      box.appendChild(h("p", { class: "muted", text: "Select an alert to see its details." }));
      return;
    }
    var fields = [
      ["Alert ID", a.id],
      ["Time", fmtDateTime(a.timestamp)],
      ["Rule", a.rule],
      ["Host", a.host],
      ["Source IP", a.sourceIp],
      ["MITRE ATT&CK", a.mitre]
    ];
    var dl = h("dl", { class: "fields" });
    fields.forEach(function (f) {
      dl.appendChild(h("div", null, [h("dt", { text: f[0] }), h("dd", { text: f[1] })]));
    });

    var aiButton = h("button", {
      type: "button",
      class: "btn",
      disabled: "disabled",
      title: "AI analysis is enabled in Stage 5"
    }, []);
    aiButton.textContent = "AI analysis (available in Stage 5)";

    box.append(
      h("p", { class: "detail-tag", text: "Simulated alert" }),
      h("div", { class: "detail-head" }, [sevBadge(a.severity), statusPill(a.status)]),
      h("h2", { text: a.rule }),
      dl,
      aiButton
    );
  }

  /* ---------- Wiring ---------- */
  function bindFilters() {
    $("q").addEventListener("input", function (e) {
      state.q = e.target.value;
      renderAlerts();
    });
    $("sev").addEventListener("change", function (e) {
      state.sev = e.target.value;
      renderAlerts();
    });
    $("status").addEventListener("change", function (e) {
      state.status = e.target.value;
      renderAlerts();
    });
  }

  function init() {
    renderKPIs();
    renderTrend();
    renderSeverity();
    renderHosts();
    renderTimeline();
    bindFilters();
    state.selectedId = D.alerts.length ? D.alerts[0].id : null;
    renderAlerts();
  }

  init();
})();
