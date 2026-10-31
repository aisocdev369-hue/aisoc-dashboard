"""Turns a raw endpoint-agent event into Alert fields using simple, explainable rules.

This is deliberately not a detection engine: it exists so the two monitored endpoints
(Windows 11, Linux) show up in the same Alert list, search and AI-analysis flow as every
other alert, without standing up Wazuh/Suricata for a two-machine deployment. See the
project doc's "Future Enhancements" section for when a real SIEM stack would be worth it.
"""

from app.db.models import Endpoint
from app.schemas import EndpointEventIn

_BASE_SEVERITY = {
    "login": "medium",
    "process_start": "low",
    "file_change": "medium",
    "network_connection": "low",
}

_BASE_MITRE = {
    "login": "T1078 Valid Accounts",
    "process_start": "T1059 Command and Scripting Interpreter",
    "file_change": "T1565 Data Manipulation",
    "network_connection": "T1071 Application Layer Protocol",
}

_FAILED_LOGIN_MARKERS = ("failed", "failure", "denied", "invalid")
_SUSPICIOUS_PROCESS_MARKERS = ("powershell -enc", "certutil", "mimikatz", "rundll32", "base64")


def build_alert_fields(endpoint: Endpoint, event: EndpointEventIn) -> dict:
    """Return the Alert column values for one event. Every submitted event becomes an
    alert — the agent, not this function, decides what's worth reporting."""
    detail_lower = event.detail.lower()
    severity = _BASE_SEVERITY.get(event.event_type, "low")
    rule = f"Endpoint agent: {event.event_type.replace('_', ' ')}"

    if event.event_type == "login" and any(marker in detail_lower for marker in _FAILED_LOGIN_MARKERS):
        severity = "high"
        rule = "Endpoint agent: failed login"
    elif event.event_type == "process_start" and any(marker in detail_lower for marker in _SUSPICIOUS_PROCESS_MARKERS):
        severity = "high"
        rule = "Endpoint agent: suspicious process start"

    return {
        "rule": rule,
        "severity": severity,
        "host": endpoint.hostname,
        "source_ip": event.source_ip or "0.0.0.0",
        "mitre": _BASE_MITRE.get(event.event_type, "T1078 Valid Accounts"),
        "status": "New",
        "occurred_at": event.occurred_at,
    }
