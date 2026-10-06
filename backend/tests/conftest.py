import os

# Must be set before the app's settings are first read. Tests never use real secrets or keys.
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["JWT_SECRET_KEY"] = "test-only-secret-key-that-is-at-least-32-characters"
os.environ["GEMINI_API_KEY"] = ""
os.environ["CORS_ALLOWED_ORIGINS"] = "http://localhost:8080"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db import models  # noqa: E402,F401
from app.db.models import Alert, User  # noqa: E402
from app.db.session import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402

PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    yield factory
    engine.dispose()


@pytest.fixture
def client(session_factory):
    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def make_user(session_factory):
    def _make(email: str, role: str, active: bool = True) -> User:
        with session_factory() as db:
            user = User(email=email, hashed_password=hash_password(PASSWORD), role=role, is_active=active)
            db.add(user)
            db.commit()
            db.refresh(user)
            return user

    return _make


@pytest.fixture
def login(client):
    def _login(email: str, password: str = PASSWORD) -> dict:
        resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
        return resp

    return _login


@pytest.fixture
def auth_header(login):
    def _header(email: str) -> dict:
        resp = login(email)
        assert resp.status_code == 200, resp.text
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}

    return _header


@pytest.fixture
def seed_alerts(session_factory):
    from datetime import datetime, timedelta, timezone

    base = datetime(2026, 10, 6, 9, 0, tzinfo=timezone.utc)
    rows = [
        ("AL-1", "Possible C2 beacon to rare domain", "critical", "ws-fin-01", "203.0.113.5", "T1071 Application Layer Protocol", "New"),
        ("AL-2", "Multiple failed logons", "medium", "dc-01", "198.51.100.9", "T1110 Brute Force", "Closed"),
        ("AL-3", "Malware signature match", "high", "srv-web-02", "203.0.113.77", "T1204 User Execution", "Investigating"),
    ]
    with session_factory() as db:
        for i, (ext, rule, sev, host, ip, mitre, status) in enumerate(rows):
            db.add(
                Alert(
                    external_id=ext,
                    rule=rule,
                    severity=sev,
                    host=host,
                    source_ip=ip,
                    mitre=mitre,
                    status=status,
                    occurred_at=base - timedelta(minutes=i * 10),
                    is_simulated=True,
                )
            )
        db.commit()


@pytest.fixture
def settings():
    return get_settings()
