from datetime import datetime, timedelta, timezone

import pytest

from app.core.security import generate_endpoint_secret, hash_endpoint_secret
from app.db.models import Alert, Endpoint, EndpointEvent
from app.routers.sources import _external_id


@pytest.fixture
def make_endpoint(session_factory):
    def _make(hostname: str, os_name: str = "linux", active: bool = True) -> tuple[Endpoint, str]:
        secret = generate_endpoint_secret()
        with session_factory() as db:
            endpoint = Endpoint(hostname=hostname, os=os_name, token_hash=hash_endpoint_secret(secret), is_active=active)
            db.add(endpoint)
            db.commit()
            db.refresh(endpoint)
            token = f"{endpoint.id}:{secret}"
            return endpoint, token

    return _make


def _event_payload(client_event_id: str = "evt-1", event_type: str = "login", detail: str = "Successful login: test"):
    return {
        "client_event_id": client_event_id,
        "event_type": event_type,
        "detail": detail,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": "198.51.100.20",
    }


def test_ingest_rejects_missing_or_bad_token(client):
    resp = client.post("/api/v1/ingest", json={"events": [_event_payload()]})
    assert resp.status_code == 401

    resp = client.post(
        "/api/v1/ingest",
        json={"events": [_event_payload()]},
        headers={"Authorization": "Bearer 999999:not-a-real-secret"},
    )
    assert resp.status_code == 401


def test_ingest_rejects_disabled_endpoint(client, make_endpoint):
    _endpoint, token = make_endpoint("disabled-host", active=False)
    resp = client.post(
        "/api/v1/ingest",
        json={"events": [_event_payload()]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


def test_ingest_creates_alert_and_updates_last_seen(client, make_endpoint, session_factory):
    endpoint, token = make_endpoint("ws-linux-01")
    resp = client.post(
        "/api/v1/ingest",
        json={"events": [_event_payload(detail="Failed login attempt: test")]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body == {"accepted": 1, "alerts_created": 1}

    with session_factory() as db:
        alert = db.query(Alert).one()
        assert alert.external_id == _external_id(endpoint, "evt-1")
        assert alert.external_id.startswith("AGENT-")
        assert alert.is_simulated is False
        assert alert.severity == "high"  # "Failed" marker bumps login severity
        assert alert.host == "ws-linux-01"

        row = db.query(EndpointEvent).one()
        assert row.endpoint_id == endpoint.id
        assert row.alert_id == alert.id

        db.refresh(endpoint)
        assert endpoint.last_seen_at is not None


def test_ingest_is_idempotent_on_client_event_id(client, make_endpoint, session_factory):
    _endpoint, token = make_endpoint("ws-linux-02")
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"events": [_event_payload(client_event_id="dup-1")]}

    first = client.post("/api/v1/ingest", json=payload, headers=headers)
    second = client.post("/api/v1/ingest", json=payload, headers=headers)

    assert first.json()["alerts_created"] == 1
    assert second.json()["alerts_created"] == 0  # same client_event_id -> no second alert
    with session_factory() as db:
        assert db.query(Alert).count() == 1
        assert db.query(EndpointEvent).count() == 2  # raw event is still recorded both times


def test_sources_health_reports_status(client, make_endpoint, auth_header, make_user, session_factory):
    make_user("analyst@example.com", "analyst")
    never_seen, _ = make_endpoint("never-seen-host")
    stale, _ = make_endpoint("stale-host")
    disabled, _ = make_endpoint("disabled-host", active=False)

    with session_factory() as db:
        db.query(Endpoint).filter_by(id=stale.id).update({"last_seen_at": datetime.now(timezone.utc) - timedelta(hours=1)})
        db.commit()

    resp = client.get("/api/v1/sources/health", headers=auth_header("analyst@example.com"))
    assert resp.status_code == 200
    by_hostname = {row["hostname"]: row["status"] for row in resp.json()}
    assert by_hostname["never-seen-host"] == "never_seen"
    assert by_hostname["stale-host"] == "stale"
    assert by_hostname["disabled-host"] == "disabled"


def test_admin_can_register_endpoint_token_shown_once(client, auth_header, make_user, session_factory):
    make_user("admin@example.com", "admin")
    resp = client.post(
        "/api/v1/admin/endpoints",
        json={"hostname": "win11-desktop", "os": "windows"},
        headers=auth_header("admin@example.com"),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["endpoint"]["hostname"] == "win11-desktop"
    assert ":" in body["token"]

    with session_factory() as db:
        endpoint = db.query(Endpoint).filter_by(hostname="win11-desktop").one()
        assert endpoint.token_hash != body["token"]  # raw token is never stored


def test_analyst_cannot_register_endpoint(client, auth_header, make_user):
    make_user("analyst@example.com", "analyst")
    resp = client.post(
        "/api/v1/admin/endpoints",
        json={"hostname": "win11-desktop", "os": "windows"},
        headers=auth_header("analyst@example.com"),
    )
    assert resp.status_code == 403


def test_register_endpoint_rejects_duplicate_hostname(client, auth_header, make_user):
    make_user("admin@example.com", "admin")
    headers = auth_header("admin@example.com")
    payload = {"hostname": "dup-host", "os": "linux"}
    assert client.post("/api/v1/admin/endpoints", json=payload, headers=headers).status_code == 201
    assert client.post("/api/v1/admin/endpoints", json=payload, headers=headers).status_code == 409
