def test_health_reports_database_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["database"] == "ok"


def test_health_hides_connection_details_when_unavailable(monkeypatch, client):
    class BrokenEngine:
        def connect(self):
            raise RuntimeError("password=secret host=db.internal")

    monkeypatch.setattr("app.main.get_engine", lambda: BrokenEngine())
    resp = client.get("/health")
    assert resp.status_code == 503
    assert "secret" not in resp.text
    assert "db.internal" not in resp.text
