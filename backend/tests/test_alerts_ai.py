import pytest

from app.db.models import AIAnalysis, AuditLog
from app.services import gemini
from app.services.gemini import AnalysisOutput


def _ok_output() -> AnalysisOutput:
    return AnalysisOutput(
        summary="Beacon-like traffic from a finance workstation.",
        threat_assessment="Possible command-and-control activity. Needs analyst review.",
        mitre_techniques=["T1071", "T1071.001", "not-an-id"],
        business_impact="Finance host may be used to move data out.",
        confidence="medium",
        confidence_explanation="One alert with a rare destination; no corroborating logs yet.",
        recommendations=["Confirm the destination domain with threat intel.", "  "],
    )


@pytest.fixture
def fake_analysis(monkeypatch):
    calls = []

    def _fake(alert):
        calls.append(alert)
        return _ok_output()

    monkeypatch.setattr(gemini, "analyse_alert", _fake)
    return calls


def test_alert_list_is_paginated_and_filtered(make_user, auth_header, client, seed_alerts):
    make_user("analyst@example.com", "analyst")
    headers = auth_header("analyst@example.com")

    all_rows = client.get("/api/v1/alerts", headers=headers).json()
    assert all_rows["total"] == 3

    critical = client.get("/api/v1/alerts?severity=critical", headers=headers).json()
    assert [a["external_id"] for a in critical["items"]] == ["AL-1"]

    by_status = client.get("/api/v1/alerts?status=Closed", headers=headers).json()
    assert by_status["total"] == 1

    search = client.get("/api/v1/alerts?q=203.0.113", headers=headers).json()
    assert search["total"] == 2

    page = client.get("/api/v1/alerts?page=2&page_size=2", headers=headers).json()
    assert len(page["items"]) == 1


def test_search_treats_wildcards_literally(make_user, auth_header, client, seed_alerts):
    make_user("analyst@example.com", "analyst")
    resp = client.get("/api/v1/alerts?q=%25", headers=auth_header("analyst@example.com"))
    assert resp.json()["total"] == 0


def test_invalid_filter_is_rejected(make_user, auth_header, client):
    make_user("analyst@example.com", "analyst")
    resp = client.get("/api/v1/alerts?severity=extreme", headers=auth_header("analyst@example.com"))
    assert resp.status_code == 422


def test_ai_analysis_success_is_validated_stored_and_audited(
    make_user, auth_header, client, seed_alerts, fake_analysis, session_factory
):
    make_user("analyst@example.com", "analyst")
    resp = client.post("/api/v1/alerts/AL-1/analysis", headers=auth_header("analyst@example.com"))

    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "ok"
    assert body["mitre_techniques"] == ["T1071", "T1071.001"]  # invalid ID dropped
    assert body["recommendations"] == ["Confirm the destination domain with threat intel."]
    assert fake_analysis[0]["alert_id"] == "AL-1"

    with session_factory() as db:
        assert db.query(AIAnalysis).count() == 1
        assert "ai_analysis" in [row.action for row in db.query(AuditLog).all()]


def test_ai_analysis_failure_returns_503_with_code_and_is_recorded(
    make_user, auth_header, client, seed_alerts, monkeypatch, session_factory
):
    make_user("analyst@example.com", "analyst")

    def _boom(alert):
        raise gemini.GeminiError("timeout")

    monkeypatch.setattr(gemini, "analyse_alert", _boom)
    resp = client.post("/api/v1/alerts/AL-1/analysis", headers=auth_header("analyst@example.com"))

    assert resp.status_code == 503
    assert resp.json()["detail"]["code"] == "timeout"
    with session_factory() as db:
        row = db.query(AIAnalysis).one()
        assert row.status == "error"
        assert row.error_code == "timeout"


def test_ai_analysis_unknown_alert_is_404(make_user, auth_header, client, fake_analysis):
    make_user("analyst@example.com", "analyst")
    resp = client.post("/api/v1/alerts/AL-999/analysis", headers=auth_header("analyst@example.com"))
    assert resp.status_code == 404
    assert fake_analysis == []


def test_ai_usage_limit_is_enforced(
    make_user, auth_header, client, seed_alerts, fake_analysis, settings, monkeypatch
):
    make_user("analyst@example.com", "analyst")
    monkeypatch.setattr(settings, "ai_max_analyses_per_user_hour", 1)
    headers = auth_header("analyst@example.com")

    assert client.post("/api/v1/alerts/AL-1/analysis", headers=headers).status_code == 201
    second = client.post("/api/v1/alerts/AL-2/analysis", headers=headers)
    assert second.status_code == 429


def test_analysis_history_is_listed(make_user, auth_header, client, seed_alerts, fake_analysis):
    make_user("analyst@example.com", "analyst")
    headers = auth_header("analyst@example.com")
    client.post("/api/v1/alerts/AL-3/analysis", headers=headers)
    history = client.get("/api/v1/alerts/AL-3/analyses", headers=headers).json()
    assert len(history) == 1
    assert history[0]["alert_external_id"] == "AL-3"


def test_analysis_requires_authentication(client, seed_alerts, fake_analysis):
    resp = client.post("/api/v1/alerts/AL-1/analysis")
    assert resp.status_code == 401
    assert fake_analysis == []
