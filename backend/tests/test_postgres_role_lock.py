"""PostgreSQL-only concurrency regression test for the last-admin guard.

Set POSTGRES_TEST_URL to a disposable PostgreSQL database before running this file.
"""

from concurrent.futures import ThreadPoolExecutor
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.security import create_access_token, hash_password
from app.db import models  # noqa: F401
from app.db.models import User
from app.db.session import Base, get_db
from app.main import app

POSTGRES_TEST_URL = os.getenv("POSTGRES_TEST_URL")
pytestmark = pytest.mark.skipif(not POSTGRES_TEST_URL, reason="POSTGRES_TEST_URL is not configured")


def test_concurrent_demotions_cannot_remove_all_active_admins():
    engine = create_engine(POSTGRES_TEST_URL, pool_pre_ping=True)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with factory() as db:
        first = User(
            email="first-admin@integration.invalid",
            hashed_password=hash_password("integration-test-password"),
            role="admin",
            is_active=True,
        )
        second = User(
            email="second-admin@integration.invalid",
            hashed_password=hash_password("integration-test-password"),
            role="admin",
            is_active=True,
        )
        db.add_all([first, second])
        db.commit()
        first_id, second_id = first.id, second.id

    def postgres_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = postgres_db
    token, _ = create_access_token(first_id, "admin")
    headers = {"Authorization": f"Bearer {token}"}

    def demote(user_id: int) -> int:
        with TestClient(app) as client:
            response = client.patch(
                f"/api/v1/admin/users/{user_id}/role",
                json={"role": "analyst"},
                headers=headers,
            )
            return response.status_code

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            statuses = list(executor.map(demote, (first_id, second_id)))

        assert sorted(statuses) == [200, 409]
        with factory() as db:
            active_admins = db.scalar(
                select(User.id).where(User.role == "admin", User.is_active.is_(True))
            )
            assert active_admins is not None
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)
        engine.dispose()
