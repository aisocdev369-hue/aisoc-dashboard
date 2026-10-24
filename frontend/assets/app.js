/*
 * AISOC dashboard client.
 * - Signs in against /api/v1/auth/login. The access token is kept in memory only
 *   (not localStorage), so it is lost on reload and the user signs in again.
 * - All text is written with textContent, never innerHTML.
 */
(function () {
  "use strict";

  var API = "/api/v1";
  var THEME_KEY = "aisoc-theme";
  var SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
  var SEV_ORDER = ["critical", "high", "medium", "low"];
  var SEV_COLOR = {
    critical: "var(--sev-critical)", high: "var(--sev-high)",
    medium: "var(--sev-medium)", low: "var(--sev-low)"
  };

  var session = { token: null, user: null };
  var overview = { alerts: [] };
  var table = { q: "", severity: "all", status: "all", page: 1, pageSize: 25, total: 0, rows: [], selectedId: null };

  function applyTheme(theme, persist) {
    document.documentElement.dataset.theme = theme;
    document.querySelectorAll("[data-theme-toggle]").forEach(function (button) {
      var nextTheme = theme === "dark" ? "light" : "dark";
      button.setAttribute("aria-label", "Switch to " + nextTheme + " theme");
      button.setAttribute("title", "Switch to " + nextTheme + " theme");
      button.setAttribute("aria-pressed", String(theme === "light"));
      button.querySelector(".theme-icon").textContent = nextTheme === "light" ? "☼" : "☾";
    });
    if (persist) {
      try {
        window.localStorage.setItem(THEME_KEY, theme);
      } catch (error) {
        // The selected theme remains active for this page if storage is unavailable.
      }
    }
  }

  function initTheme() {
    var savedTheme = null;
    try {
      savedTheme = window.localStorage.getItem(THEME_KEY);
    } catch (error) {
      savedTheme = null;
    }
    var systemTheme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    applyTheme(savedTheme === "light" || savedTheme === "dark" ? savedTheme : systemTheme, false);
    document.addEventListener("click", function (event) {
      if (!event.target.closest("[data-theme-toggle]")) return;
      applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark", true);
    });
  }

  /* ---------- helpers ---------- */
  function h(tag, props, kids) {
    var node = document.createElement(tag);
    if (props) {
      Object.keys(props).forEach(function (key) {
        if (key === "text") node.textContent = props[key];
        else if (key === "class") node.className = props[key];
        else node.setAttribute(key, props[key]);
      });
    }
    (kids || []).forEach(function (child) { if (child) node.appendChild(child); });
    return node;
  }
  function $(id) { return document.getElementById(id); }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }
  function fmtDateTime(iso) {
    return new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }
  function fmtHour(d) {
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }
  function sevBadge(sev) { return h("span", { class: "sev sev-" + sev, text: SEV_LABEL[sev] || sev }); }
  function statusPill(s) { return h("span", { class: "status-pill st-" + String(s).toLowerCase(), text: s }); }

  function setMessage(id, text) {
    var box = $(id);
    box.textContent = text || "";
    box.hidden = !text;
  }

  /* ---------- API ---------- */
  function api(path, options) {
    options = options || {};
    var headers = { "Accept": "application/json" };
    if (options.body) headers["Content-Type"] = "application/json";
    if (session.token) headers["Authorization"] = "Bearer " + session.token;
    return fetch(API + path, {
      method: options.method || "GET",
      headers: headers,
      body: options.body ? JSON.stringify(options.body) : undefined
    }).then(function (resp) {
      if (resp.status === 401 && session.token) {
        signOut("Your session has ended. Please sign in again.");
        throw new Error("unauthenticated");
      }
      return resp.json().catch(function () { return {}; }).then(function (data) {
        if (!resp.ok) {
          var err = new Error(messageFrom(data, resp.status));
          err.status = resp.status;
          err.detail = data && data.detail;
          throw err;
        }
        return data;
      });
    });
  }

  function messageFrom(data, status) {
    var d = data && data.detail;
    if (typeof d === "string") return d;
    if (d && typeof d.message === "string") return d.message;
    return "Request failed (" + status + ")";
  }

  /* ---------- Login / session ---------- */
  function showLogin(message) {
    $("app").hidden = true;
    $("login").hidden = false;
    showLoginForm();
    setMessage("login-error", message || "");
    $("login-email").focus();
  }

  function showApp() {
    $("login").hidden = true;
    $("app").hidden = false;
    $("user-email").textContent = session.user.email;
    $("user-role").textContent = session.user.role === "admin" ? "Admin" : "SOC Analyst";
    $("users-nav").hidden = session.user.role !== "admin" && session.user.role !== "analyst";
    $("users").hidden = true;
    if (session.user.role === "admin") loadUsers();
  }

  function signOut(message) {
    session.token = null;
    session.user = null;
    table.selectedId = null;
    showLogin(message);
  }

  function onLogin(event) {
    event.preventDefault();
    var btn = $("login-submit");
    btn.disabled = true;
    setMessage("login-error", "");
    api("/auth/login", {
      method: "POST",
      body: { email: $("login-email").value.trim(), password: $("login-password").value }
    }).then(function (tok) {
      session.token = tok.access_token;
      $("login-password").value = "";
      return api("/auth/me").then(function (me) {
        session.user = me;
        showApp();
        loadAll();
      });
    }).catch(function (err) {
      if (err.message !== "unauthenticated") setMessage("login-error", err.message);
    }).then(function () { btn.disabled = false; });
  }

  function onRegister(event) {
    event.preventDefault();
    var password = $("signup-password").value;
    if (password !== $("signup-confirm-password").value) {
      setMessage("signup-error", "Passwords do not match.");
      return;
    }

    var button = $("signup-submit");
    button.disabled = true;
    setMessage("signup-error", "");
    api("/auth/register", {
      method: "POST",
      body: { email: $("signup-email").value.trim(), password: password }
    }).then(function (tok) {
      session.token = tok.access_token;
      $("signup-password").value = "";
      $("signup-confirm-password").value = "";
      return api("/auth/me");
    }).then(function (me) {
      session.user = me;
      showApp();
      loadAll();
    }).catch(function (err) {
      session.token = null;
      session.user = null;
      if (err.message !== "unauthenticated") setMessage("signup-error", err.message || "Could not create the account.");
    }).then(function () {
      button.disabled = false;
    });
  }

  function showSignup() {
    $("login-form").hidden = true;
    $("signup-form").hidden = false;
    $("login-title").textContent = "Create Analyst account";
    $("auth-description").textContent = "Create an account to access the security dashboard.";
    $("auth-divider").textContent = "Email and password registration";
    setMessage("login-error", "");
    $("signup-email").value = $("login-email").value;
    $("signup-email").focus();
  }

  function showLoginForm() {
    $("signup-form").hidden = true;
    $("login-form").hidden = false;
    $("login-title").textContent = "Sign in";
    $("auth-description").textContent = "Sign in or create an Analyst account with your email and password. Google sign-in is also available.";
    $("auth-divider").textContent = "or continue with email and password";
    setMessage("signup-error", "");
    $("login-email").value = $("signup-email").value;
    $("login-email").focus();
  }

  function configureGoogleSignIn() {
    fetch(API + "/auth/google/config", { headers: { "Accept": "application/json" } })
      .then(function (response) {
        if (!response.ok) throw new Error("Could not load Google sign-in settings.");
        return response.json();
      })
      .then(function (config) {
        if (!config.enabled || !config.client_id) {
          $("google-signin-status").textContent = "Google sign-in is not configured. Email and password sign-in is still available.";
          $("google-signin-status").hidden = false;
          return;
        }

        var script = document.createElement("script");
        script.src = "https://accounts.google.com/gsi/client";
        script.async = true;
        script.onload = function () {
          if (!window.google || !window.google.accounts || !window.google.accounts.id) {
            $("google-signin-status").textContent = "Google sign-in could not be initialized. Try email and password sign-in.";
            $("google-signin-status").hidden = false;
            return;
          }
          window.google.accounts.id.initialize({
            client_id: config.client_id,
            callback: onGoogleCredential
          });
          $("google-signin").hidden = false;
          window.google.accounts.id.renderButton($("google-signin"), {
            theme: "filled_black",
            size: "large",
            text: "continue_with",
            shape: "rectangular",
            width: 320
          });
        };
        script.onerror = function () {
          $("google-signin-status").textContent = "Google sign-in could not load. Try email and password sign-in.";
          $("google-signin-status").hidden = false;
        };
        document.head.appendChild(script);
      })
      .catch(function () {
        $("google-signin-status").textContent = "Google sign-in is currently unavailable. Email and password sign-in is still available.";
        $("google-signin-status").hidden = false;
      });
  }

  function onGoogleCredential(response) {
    if (!response || typeof response.credential !== "string" || !response.credential) {
      setMessage("login-error", "Google did not return a valid sign-in credential. Please try again.");
      return;
    }
    setMessage("login-error", "");
    api("/auth/google", {
      method: "POST",
      body: { credential: response.credential }
    }).then(function (tok) {
      session.token = tok.access_token;
      return api("/auth/me");
    }).then(function (me) {
      session.user = me;
      showApp();
      loadAll();
    }).catch(function (err) {
      session.token = null;
      session.user = null;
      setMessage("login-error", err.message || "Google sign-in failed. Please try again.");
    });
  }

  /* ---------- Overview (KPIs, charts) ---------- */
  function loadOverview() {
    return api("/alerts?page_size=100").then(function (page) {
      overview.alerts = page.items;
      renderKPIs();
      renderTrend();
      renderSeverity();
      renderHosts();
    });
  }

  function renderKPIs() {
    var a = overview.alerts;
    var items = [
      { label: "Alerts (24h)", value: a.length, sub: "Simulated data", cls: "" },
      { label: "Critical", value: count(a, function (x) { return x.severity === "critical"; }), sub: "Needs immediate triage", cls: "kpi-critical" },
      { label: "High", value: count(a, function (x) { return x.severity === "high"; }), sub: "Triage within one hour", cls: "kpi-high" },
      { label: "Open cases", value: count(a, function (x) { return x.status !== "Closed"; }),
        sub: count(a, function (x) { return x.status === "Investigating"; }) + " under investigation", cls: "kpi-open" }
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

  function count(list, pred) {
    return list.reduce(function (n, x) { return n + (pred(x) ? 1 : 0); }, 0);
  }

  function hourlyBuckets(alerts) {
    var now = Date.now(), HOUR = 3600000, buckets = [];
    var start = now - 24 * HOUR;
    for (var i = 0; i < 24; i++) {
      var from = start + i * HOUR;
      buckets.push({ at: new Date(from), count: 0 });
    }
    alerts.forEach(function (a) {
      var t = Date.parse(a.occurred_at);
      var idx = Math.floor((t - start) / HOUR);
      if (idx >= 0 && idx < 24) buckets[idx].count++;
    });
    return buckets;
  }

  function svgEl(name, attrs) {
    var node = document.createElementNS("http://www.w3.org/2000/svg", name);
    Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    return node;
  }

  function renderTrend() {
    var W = 640, H = 220, P = { t: 14, r: 14, b: 30, l: 34 };
    var data = hourlyBuckets(overview.alerts);
    var max = Math.max.apply(null, [1].concat(data.map(function (d) { return d.count; })));
    var iw = W - P.l - P.r, ih = H - P.t - P.b;
    function x(i) { return P.l + (i / (data.length - 1)) * iw; }
    function y(v) { return P.t + ih - (v / max) * ih; }

    var svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, role: "img",
      "aria-label": "Alerts per hour over the last 24 hours (simulated data)" });
    [0, Math.round(max / 2), max].forEach(function (v) {
      svg.appendChild(svgEl("line", { x1: P.l, x2: W - P.r, y1: y(v), y2: y(v), "class": "grid" }));
      var label = svgEl("text", { x: P.l - 8, y: y(v) + 4, "text-anchor": "end", "class": "axis" });
      label.textContent = String(v);
      svg.appendChild(label);
    });
    var pts = data.map(function (d, i) { return x(i) + "," + y(d.count); });
    svg.appendChild(svgEl("polygon", {
      points: [P.l + "," + (P.t + ih)].concat(pts, [(W - P.r) + "," + (P.t + ih)]).join(" "),
      "class": "area"
    }));
    svg.appendChild(svgEl("polyline", { points: pts.join(" "), "class": "line" }));
    data.forEach(function (d, i) {
      var c = svgEl("circle", { cx: x(i), cy: y(d.count), r: 3.5, "class": "dot-point" });
      var t = svgEl("title");
      t.textContent = fmtHour(d.at) + ": " + d.count + " alerts";
      c.appendChild(t);
      svg.appendChild(c);
    });
    data.forEach(function (d, i) {
      if (i % 4 === 0) {
        var lbl = svgEl("text", { x: x(i), y: H - 8, "text-anchor": "middle", "class": "axis" });
        lbl.textContent = fmtHour(d.at);
        svg.appendChild(lbl);
      }
    });
    clear($("trend")).appendChild(svg);
  }

  function renderSeverity() {
    var total = overview.alerts.length || 1;
    var counts = {};
    SEV_ORDER.forEach(function (s) {
      counts[s] = count(overview.alerts, function (x) { return x.severity === s; });
    });
    var bar = h("div", { class: "stack-bar", role: "img",
      "aria-label": SEV_ORDER.map(function (s) { return SEV_LABEL[s] + " " + counts[s]; }).join(", ") });
    SEV_ORDER.forEach(function (s) {
      var seg = h("span");
      seg.style.width = (counts[s] / total * 100) + "%";
      seg.style.background = SEV_COLOR[s];
      bar.appendChild(seg);
    });
    var legend = h("ul", { class: "legend" });
    SEV_ORDER.forEach(function (s) {
      var sw = h("span", { class: "swatch", "aria-hidden": "true" });
      sw.style.background = SEV_COLOR[s];
      legend.appendChild(h("li", null, [sw, h("span", { text: SEV_LABEL[s] }), h("strong", { text: String(counts[s]) })]));
    });
    clear($("severity")).appendChild(h("div", null, [bar, legend]));
  }

  function renderHosts() {
    var byHost = {};
    overview.alerts.forEach(function (a) { byHost[a.host] = (byHost[a.host] || 0) + 1; });
    var hosts = Object.keys(byHost).map(function (name) {
      return { host: name, count: byHost[name] };
    }).sort(function (a, b) { return b.count - a.count; }).slice(0, 6);
    var max = Math.max.apply(null, [1].concat(hosts.map(function (x) { return x.count; })));
    var list = h("ol", { class: "bars" });
    hosts.forEach(function (x) {
      var fill = h("span", { class: "bar-fill" });
      fill.style.width = (x.count / max * 100) + "%";
      list.appendChild(h("li", null, [
        h("span", { class: "bar-label", text: x.host }),
        h("span", { class: "bar-track" }, [fill]),
        h("strong", { class: "bar-value", text: String(x.count) })
      ]));
    });
    clear($("hosts")).appendChild(list);
  }

  function renderTimeline() {
    var inc = window.SOC_MOCK_INCIDENT;
    if (!inc) return;
    var list = h("ol", { class: "timeline" });
    inc.timeline.forEach(function (ev) {
      list.appendChild(h("li", null, [
        h("time", { datetime: ev.at, text: fmtDateTime(ev.at) }),
        h("p", { text: ev.text })
      ]));
    });
    clear($("timeline")).append(
      h("div", { class: "incident-head" }, [
        h("p", { class: "incident-id", text: inc.id }),
        sevBadge(inc.severity),
        statusPill(inc.status),
        h("p", { class: "incident-title", text: inc.title })
      ]),
      list
    );
  }

  /* ---------- Alerts table (server-side filters and paging) ---------- */
  function loadTable() {
    var qs = "?page=" + table.page + "&page_size=" + table.pageSize;
    if (table.q.trim()) qs += "&q=" + encodeURIComponent(table.q.trim());
    if (table.severity !== "all") qs += "&severity=" + table.severity;
    if (table.status !== "all") qs += "&status=" + encodeURIComponent(table.status);
    return api("/alerts" + qs).then(function (page) {
      table.rows = page.items;
      table.total = page.total;
      if (!table.rows.some(function (r) { return r.external_id === table.selectedId; })) {
        table.selectedId = table.rows.length ? table.rows[0].external_id : null;
      }
      renderTable();
      renderDetail();
    });
  }

  function renderTable() {
    var body = clear($("rows"));
    table.rows.forEach(function (a) {
      var selected = a.external_id === table.selectedId;
      var tr = h("tr", { tabindex: "0", "aria-selected": String(selected), "class": selected ? "is-selected" : "" }, [
        h("td", { text: fmtDateTime(a.occurred_at) }),
        h("td", null, [sevBadge(a.severity)]),
        h("td", { class: "rule", text: a.rule }),
        h("td", { class: "mono", text: a.host }),
        h("td", { class: "mono", text: a.source_ip }),
        h("td", { class: "mono small", text: a.mitre }),
        h("td", null, [statusPill(a.status)])
      ]);
      tr.addEventListener("click", function () { select(a.external_id); });
      tr.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(a.external_id); }
      });
      body.appendChild(tr);
    });
    var pages = Math.max(1, Math.ceil(table.total / table.pageSize));
    $("count").textContent = table.total + " alerts match (simulated data)";
    $("page-info").textContent = "Page " + table.page + " of " + pages;
    $("prev").disabled = table.page <= 1;
    $("next").disabled = table.page >= pages;
    $("empty").hidden = table.rows.length !== 0;
  }

  function select(externalId) {
    table.selectedId = externalId;
    renderTable();
    renderDetail();
  }

  /* ---------- Detail panel and AI analysis ---------- */
  function currentAlert() {
    for (var i = 0; i < table.rows.length; i++) {
      if (table.rows[i].external_id === table.selectedId) return table.rows[i];
    }
    return null;
  }

  function renderDetail() {
    var box = clear($("detail"));
    var a = currentAlert();
    if (!a) {
      box.appendChild(h("p", { class: "muted", text: "Select an alert to see its details." }));
      return;
    }
    var canAnalyse = session.user && (session.user.role === "analyst" || session.user.role === "admin");
    var dl = h("dl", { class: "fields" });
    [["Alert ID", a.external_id], ["Time", fmtDateTime(a.occurred_at)], ["Host", a.host],
     ["Source IP", a.source_ip], ["MITRE ATT&CK", a.mitre]].forEach(function (f) {
      dl.appendChild(h("div", null, [h("dt", { text: f[0] }), h("dd", { text: f[1] })]));
    });

    var result = h("div", { id: "ai-result", "aria-live": "polite" });
    var msg = h("p", { id: "ai-error", class: "form-error", role: "alert", hidden: "hidden" });
    var button = h("button", { type: "button", class: "btn btn-primary", id: "ai-run" }, []);
    button.textContent = "Run AI analysis";
    button.disabled = !canAnalyse;
    button.addEventListener("click", function () { runAnalysis(a.external_id); });

    box.append(
      h("p", { class: "detail-tag", text: "Simulated alert" }),
      h("div", { class: "detail-head" }, [sevBadge(a.severity), statusPill(a.status)]),
      h("h2", { text: a.rule }),
      dl,
      h("div", { class: "ai-box" }, [
        h("p", { class: "ai-title", text: "AI analysis (Gemini)" }),
        h("p", { class: "ai-note", text: "AI output is advice for an analyst. Verify it before acting. Suggested steps are never run automatically." }),
        button,
        msg,
        result
      ])
    );
    loadHistory(a.external_id);
  }

  function loadHistory(externalId) {
    api("/alerts/" + encodeURIComponent(externalId) + "/analyses").then(function (list) {
      if (table.selectedId !== externalId) return;
      if (list.length) renderAnalysis(list[0]);
    }).catch(function () { /* history is optional */ });
  }

  function runAnalysis(externalId) {
    var button = $("ai-run");
    var msg = $("ai-error");
    button.disabled = true;
    button.textContent = "Analysing…";
    msg.hidden = true;
    api("/alerts/" + encodeURIComponent(externalId) + "/analysis", { method: "POST" }).then(function (res) {
      if (table.selectedId === externalId) renderAnalysis(res);
    }).catch(function (err) {
      if (err.message === "unauthenticated") return;
      msg.textContent = err.message || "AI analysis failed.";
      msg.hidden = false;
    }).then(function () {
      var b = $("ai-run");
      if (b) {
        b.disabled = !(session.user && (session.user.role === "analyst" || session.user.role === "admin"));
        b.textContent = "Run AI analysis";
      }
    });
  }

  function renderAnalysis(res) {
    var box = clear($("ai-result"));
    if (res.status !== "ok") {
      box.appendChild(h("p", { class: "form-error", text: "Last attempt failed (" + (res.error_code || "error") + ")." }));
      return;
    }
    var chips = h("div", { class: "chips" });
    (res.mitre_techniques || []).forEach(function (t) { chips.appendChild(h("span", { class: "chip", text: t })); });
    var recs = h("ol", { class: "recs" });
    (res.recommendations || []).forEach(function (r) { recs.appendChild(h("li", { text: r })); });

    box.append(
      h("p", { class: "ai-meta", text: "Model " + res.model + " · " + fmtDateTime(res.created_at) }),
      h("h3", { text: "Summary" }), h("p", { text: res.summary || "" }),
      h("h3", { text: "Threat assessment" }), h("p", { text: res.threat_assessment || "" }),
      h("h3", { text: "MITRE ATT&CK" }), chips.childNodes.length ? chips : h("p", { class: "muted", text: "No valid technique IDs returned." }),
      h("h3", { text: "Business impact" }), h("p", { text: res.business_impact || "" }),
      h("h3", { text: "Confidence: " + (res.confidence || "unknown") }), h("p", { text: res.confidence_explanation || "" }),
      h("h3", { text: "Recommended next steps" }), recs
    );
  }

  /* ---------- Wiring ---------- */
  var debounceTimer = null;
  function bindFilters() {
    $("q").addEventListener("input", function (e) {
      table.q = String(e.target.value || "").trim();
      table.page = 1;
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(loadTable, 250);
    });
    $("sev").addEventListener("change", function (e) { table.severity = e.target.value; table.page = 1; loadTable(); });
    $("status").addEventListener("change", function (e) { table.status = e.target.value; table.page = 1; loadTable(); });
    $("prev").addEventListener("click", function () { table.page--; loadTable(); });
    $("next").addEventListener("click", function () { table.page++; loadTable(); });
    $("signout").addEventListener("click", function () { signOut(""); });
    $("change-password").addEventListener("click", openPasswordModal);
    $("close-password-modal").addEventListener("click", closePasswordModal);
    $("cancel-password").addEventListener("click", closePasswordModal);
    $("password-form").addEventListener("submit", onChangePassword);
    $("login-form").addEventListener("submit", onLogin);
    bindPasswordToggle("login-password", "toggle-password", "toggle-password-label", "toggle-password-icon", "password", true);
    bindPasswordToggle("current-password", "toggle-current-password", null, "toggle-current-password-icon", "current password");
    bindPasswordToggle("new-password", "toggle-new-password", null, "toggle-new-password-icon", "new password");
    bindPasswordToggle("confirm-password", "toggle-confirm-password", null, "toggle-confirm-password-icon", "confirmation password");
  }

  function bindPasswordToggle(inputId, buttonId, labelId, iconId, passwordLabel, hasScreenReaderLabel) {
    $(buttonId).addEventListener("click", function () {
      togglePasswordVisibility(inputId, buttonId, labelId, iconId, passwordLabel, hasScreenReaderLabel);
    });
  }

  function togglePasswordVisibility(inputId, buttonId, labelId, iconId, passwordLabel, hasScreenReaderLabel) {
    var input = $(inputId);
    var btn = $(buttonId);
    var shown = input.type === "text";
    input.type = shown ? "password" : "text";
    btn.setAttribute("aria-pressed", String(!shown));
    btn.setAttribute("aria-label", (shown ? "Show " : "Hide ") + passwordLabel);
    if (hasScreenReaderLabel) {
      $(labelId).textContent = shown ? "Show password" : "Hide password";
    }
    $(iconId).textContent = shown ? "\u{1F441}" : "\u{1F576}";
    input.focus();
  }

  function setPasswordFeedback(type, message) {
    var error = $("password-error");
    var success = $("password-success");
    error.hidden = type !== "error";
    success.hidden = type !== "success";
    error.textContent = type === "error" ? message : "";
    success.textContent = type === "success" ? message : "";
  }

  function resetPasswordForm() {
    $("password-form").reset();
    [
      ["current-password", "toggle-current-password", "toggle-current-password-icon", "current password"],
      ["new-password", "toggle-new-password", "toggle-new-password-icon", "new password"],
      ["confirm-password", "toggle-confirm-password", "toggle-confirm-password-icon", "confirmation password"]
    ].forEach(function (ids) {
      $(ids[0]).type = "password";
      $(ids[1]).setAttribute("aria-pressed", "false");
      $(ids[1]).setAttribute("aria-label", "Show " + ids[3]);
      $(ids[2]).textContent = "\u{1F441}";
    });
    setPasswordFeedback("", "");
  }

  function openPasswordModal() {
    $("password-modal").hidden = false;
    resetPasswordForm();
    $("current-password").focus();
  }

  function closePasswordModal() {
    $("password-modal").hidden = true;
    resetPasswordForm();
  }

  function onChangePassword(event) {
    event.preventDefault();
    var form = $("password-form");
    var currentPassword = $("current-password").value;
    var newPassword = $("new-password").value;
    var confirmPassword = $("confirm-password").value;
    var submit = form.querySelector('button[type="submit"]');

    if (!currentPassword || !newPassword || !confirmPassword) {
      setPasswordFeedback("error", "Please complete all password fields.");
      return;
    }
    if (newPassword.length < 12 || newPassword.length > 72) {
      setPasswordFeedback("error", "New password must be 12 to 72 characters long.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setPasswordFeedback("error", "New passwords do not match.");
      return;
    }

    submit.disabled = true;
    setPasswordFeedback("", "");
    api("/auth/change-password", {
      method: "POST",
      body: {
        current_password: currentPassword,
        new_password: newPassword
      }
    }).then(function () {
      setPasswordFeedback("success", "Password updated successfully.");
      form.reset();
      setTimeout(function () { closePasswordModal(); }, 1000);
    }).catch(function (err) {
      setPasswordFeedback("error", err.message || "Could not update the password.");
    }).then(function () {
      submit.disabled = false;
    });
  }

  function loadAll() {
    setMessage("app-error", "");
    Promise.all([loadOverview(), loadTable()]).catch(function (err) {
      if (err.message !== "unauthenticated") setMessage("app-error", "Could not load data: " + err.message);
    });
    renderTimeline();
  }

  function loadUsers() {
    if (!session.user || (session.user.role !== "admin" && session.user.role !== "analyst")) return;
    setMessage("users-error", "");
    api("/admin/users").then(function (users) {
      renderUsers(users);
    }).catch(function (err) {
      if (err.message !== "unauthenticated") {
        setMessage("users-error", "Could not load users: " + err.message);
      }
    });
  }

  function renderUsers(users) {
    var body = clear($("user-rows"));
    var canAssignAdmin = session.user.role === "admin";
    var activeAdminCount = users.filter(function (user) {
      return user.is_active && user.role === "admin";
    }).length;
    $("users-count").textContent = users.length + (users.length === 1 ? " account" : " accounts");
    $("users-empty").hidden = users.length !== 0;
    users.forEach(function (user) {
      var analystOption = h("option", { value: "analyst", text: "Analyst" });
      var adminOption = h("option", { value: "admin", text: "Admin" });
      var isLastActiveAdmin = user.is_active && user.role === "admin" && activeAdminCount === 1;
      if (isLastActiveAdmin) {
        analystOption.disabled = true;
        analystOption.textContent = "Analyst (last active Admin protected)";
      }
      adminOption.disabled = !canAssignAdmin;
      var role = h("select", { "aria-label": "Role for " + user.email }, [
        analystOption,
        adminOption
      ]);
      if (isLastActiveAdmin) {
        role.title = "Promote another active account to Admin before demoting this account.";
      }
      role.value = user.role;
      var save = h("button", { type: "button", class: "btn btn-ghost", text: "Save role" });
      save.disabled = true;
      role.addEventListener("change", function () {
        save.disabled = role.value === user.role;
      });
      save.addEventListener("click", function () {
        save.disabled = true;
        setMessage("users-error", "");
        api("/admin/users/" + encodeURIComponent(user.id) + "/role", {
          method: "PATCH",
          body: { role: role.value }
        }).then(function () {
          loadUsers();
        }).catch(function (err) {
          if (err.message !== "unauthenticated") {
            setMessage("users-error", "Could not update role for " + user.email + ": " + err.message);
          }
          role.value = user.role;
          save.disabled = true;
        });
      });
      body.appendChild(h("tr", null, [
        h("td", { text: user.email }),
        h("td", null, [role]),
        h("td", { text: user.is_active ? "Active" : "Inactive" }),
        h("td", null, [save])
      ]));
    });
  }

  function init() {
    initTheme();
    bindFilters();
    $("signup-form").addEventListener("submit", onRegister);
    $("show-signup").addEventListener("click", showSignup);
    $("show-login").addEventListener("click", showLoginForm);
    $("toggle-signup-password").addEventListener("click", function () {
      var input = $("signup-password");
      var visible = input.type === "password";
      input.type = visible ? "text" : "password";
      $("toggle-signup-password").setAttribute("aria-pressed", String(visible));
      $("toggle-signup-password-label").textContent = visible ? "Hide password" : "Show password";
      $("toggle-signup-password").setAttribute("aria-label", visible ? "Hide password" : "Show password");
    });
    $("users-nav").addEventListener("click", function () {
      $("users").hidden = false;
      loadUsers();
    });
    showLogin("");
    configureGoogleSignIn();
  }

  init();
})();
