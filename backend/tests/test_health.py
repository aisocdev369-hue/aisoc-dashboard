import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    # SQLite in memory lets the health logic run without a Postgres server.
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    from app.core import config, database

    config.get_settings.cache_clear()
    database.get_engine.cache_clear()
    from app.main import app

    with TestClient(app) as c:
        yield c

    database.get_engine.cache_clear()
    config.get_settings.cache_clear()


def test_health_ok_when_database_reachable(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["database"] == "ok"


def test_health_503_when_database_not_configured(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "")
    from app.core import config, database

    config.get_settings.cache_clear()
    database.get_engine.cache_clear()
    from app.main import app

    with TestClient(app) as c:
        r = c.get("/health")
    assert r.status_code == 503
    assert r.json()["database"] == "not_configured"

    database.get_engine.cache_clear()
    config.get_settings.cache_clear()


def test_health_does_not_leak_connection_details(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:secretpw@nohost.invalid:5432/x")
    from app.core import config, database

    config.get_settings.cache_clear()
    database.get_engine.cache_clear()
    from app.main import app

    with TestClient(app) as c:
        r = c.get("/health")
    assert r.status_code == 503
    assert "secretpw" not in r.text
    assert "nohost" not in r.text

    database.get_engine.cache_clear()
    config.get_settings.cache_clear()
