/*
 * SIMULATED DATA. For Stage 3 UI development only.
 * Every record below is generated locally and is NOT a real security event.
 * Replace with monitoring adapter output in Stage 6.
 * Source IPs use the RFC 5737 documentation ranges (203.0.113.0/24, 198.51.100.0/24).
 */
(function () {
  "use strict";

  // Deterministic PRNG so the same simulated data appears on every reload.
  function mulberry32(seed) {
    return function () {
      seed |= 0;
      seed = (seed + 0x6d2b79f5) | 0;
      var t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  var rand = mulberry32(20261006);
  function pick(arr) {
    return arr[Math.floor(rand() * arr.length)];
  }

  // Fixed anchor time so the simulated window does not drift between loads.
  var ANCHOR = Date.UTC(2026, 9, 6, 9, 30); // 2026-10-06T09:30:00Z
  var HOUR = 60 * 60 * 1000;

  var HOSTS = [
    "srv-db-01", "dc-01", "srv-web-02", "vpn-gw-01",
    "ws-fin-01", "ws-hr-04", "ws-dev-07", "srv-mail-01"
  ];

  var RULES = [
    { name: "Multiple failed logons", severity: "medium", mitre: "T1110 Brute Force" },
    { name: "Suspicious encoded PowerShell", severity: "high", mitre: "T1059.001 PowerShell" },
    { name: "Possible C2 beacon to rare domain", severity: "critical", mitre: "T1071 Application Layer Protocol" },
    { name: "Service created with elevated rights", severity: "high", mitre: "T1543.003 Windows Service" },
    { name: "Port scan from single source", severity: "low", mitre: "T1046 Network Service Discovery" },
    { name: "Malware signature match", severity: "high", mitre: "T1204 User Execution" },
    { name: "Unusual outbound data volume", severity: "medium", mitre: "T1041 Exfiltration Over C2" },
    { name: "Login from new geolocation", severity: "low", mitre: "T1078 Valid Accounts" }
  ];

  var STATUSES = ["New", "New", "Investigating", "Closed", "Closed"];

  function externalIp() {
    return rand() < 0.5
      ? "203.0.113." + Math.floor(rand() * 254 + 1)
      : "198.51.100." + Math.floor(rand() * 254 + 1);
  }

  var alerts = [];
  for (var i = 0; i < 48; i++) {
    var rule = pick(RULES);
    var ts = ANCHOR - Math.floor(rand() * 24 * 60) * 60 * 1000;
    alerts.push({
      id: "AL-" + (1200 + i),
      timestamp: new Date(ts).toISOString(),
      rule: rule.name,
      severity: rule.severity,
      host: pick(HOSTS),
      sourceIp: externalIp(),
      mitre: rule.mitre,
      status: pick(STATUSES)
    });
  }
  alerts.sort(function (a, b) {
    return a.timestamp < b.timestamp ? 1 : -1;
  });

  // Hourly counts for the last 24 hours, derived from the alerts above.
  var start = ANCHOR - 24 * HOUR;
  var hourly = [];
  for (var h = 0; h < 24; h++) {
    var from = start + h * HOUR;
    var to = from + HOUR;
    var count = alerts.filter(function (a) {
      var t = Date.parse(a.timestamp);
      return t >= from && t < to;
    }).length;
    hourly.push({ hour: new Date(from).toISOString(), count: count });
  }

  // Top hosts, derived from the alerts above.
  var hostCounts = {};
  alerts.forEach(function (a) {
    hostCounts[a.host] = (hostCounts[a.host] || 0) + 1;
  });
  var hosts = Object.keys(hostCounts)
    .map(function (name) {
      return { host: name, count: hostCounts[name] };
    })
    .sort(function (a, b) {
      return b.count - a.count;
    })
    .slice(0, 6);

  // One simulated incident with a timeline.
  var incident = {
    id: "INC-2041",
    title: "Encoded PowerShell followed by C2 beacon on ws-fin-01",
    severity: "critical",
    status: "Investigating",
    timeline: [
      { at: ANCHOR - 5.5 * HOUR, text: "Multiple failed logons from 203.0.113.44 against ws-fin-01" },
      { at: ANCHOR - 4.8 * HOUR, text: "Successful logon for user after failures (rule: login from new geolocation)" },
      { at: ANCHOR - 4.2 * HOUR, text: "Encoded PowerShell executed on ws-fin-01" },
      { at: ANCHOR - 3.9 * HOUR, text: "Service created with elevated rights on ws-fin-01" },
      { at: ANCHOR - 2.1 * HOUR, text: "Possible C2 beacon to rare domain from ws-fin-01" },
      { at: ANCHOR - 1.5 * HOUR, text: "Unusual outbound data volume from ws-fin-01" },
      { at: ANCHOR - 0.5 * HOUR, text: "Incident opened; analyst assigned" }
    ].map(function (e) {
      return { at: new Date(e.at).toISOString(), text: e.text };
    })
  };

  window.SOC_MOCK = {
    label: "SIMULATED",
    anchor: new Date(ANCHOR).toISOString(),
    alerts: alerts,
    hourly: hourly,
    hosts: hosts,
    incident: incident,
    severities: ["critical", "high", "medium", "low"]
  };
})();
