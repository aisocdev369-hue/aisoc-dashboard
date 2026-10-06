/*
 * SIMULATED incident timeline for the Stage 3/4 preview. Not a real incident.
 * Alerts now come from the API; incidents get an API in a later stage.
 */
(function () {
  "use strict";

  var ANCHOR = Date.UTC(2026, 9, 6, 9, 30);
  var HOUR = 60 * 60 * 1000;

  function at(hoursAgo) {
    return new Date(ANCHOR - hoursAgo * HOUR).toISOString();
  }

  window.SOC_MOCK_INCIDENT = {
    id: "INC-2041",
    title: "Encoded PowerShell followed by C2 beacon on ws-fin-01",
    severity: "critical",
    status: "Investigating",
    timeline: [
      { at: at(5.5), text: "Multiple failed logons from 203.0.113.44 against ws-fin-01" },
      { at: at(4.8), text: "Successful logon after failures (rule: login from new geolocation)" },
      { at: at(4.2), text: "Encoded PowerShell executed on ws-fin-01" },
      { at: at(3.9), text: "Service created with elevated rights on ws-fin-01" },
      { at: at(2.1), text: "Possible C2 beacon to rare domain from ws-fin-01" },
      { at: at(1.5), text: "Unusual outbound data volume from ws-fin-01" },
      { at: at(0.5), text: "Incident opened; analyst assigned" }
    ]
  };
})();
