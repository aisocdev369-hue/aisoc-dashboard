from app.db.models import AuditLog, User
from app.routers import auth


def test_login_returns_token_and_role(make_user, login):
    make_user("analyst@example.com", "analyst")
    resp = login("analyst@example.com")
    assert resp.status_code == 200
    body = resp.json()
    assert body["role"] == "analyst"
    assert body["token_type"] == "bearer"
    assert body["access_token"]


def test_login_email_is_case_insensitive(make_user, login):
    make_user("admin@example.com", "admin")
    assert login("ADMIN@Example.com").status_code == 200


def test_email_registration_creates_analyst_and_signs_in(client, session_factory):
    password = "a-long-enough-password"
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "New.Analyst@example.com", "password": password},
    )

    assert response.status_code == 201
    assert response.json()["role"] == "analyst"
    headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=headers).json()["email"] == "new.analyst@example.com"
    with session_factory() as db:
        user = db.query(User).filter_by(email="new.analyst@example.com").one()
        assert user.role == "analyst"
        assert user.hashed_password != password
        assert [row.action for row in db.query(AuditLog).all()] == ["register"]


def test_email_registration_rejects_duplicate_short_password_and_role(client):
    payload = {"email": "new.analyst@example.com", "password": "a-long-enough-password"}
    assert client.post("/api/v1/auth/register", json=payload).status_code == 201
    assert client.post("/api/v1/auth/register", json=payload).status_code == 409
    assert client.post(
        "/api/v1/auth/register",
        json={"email": "short@example.com", "password": "short"},
    ).status_code == 422
    assert client.post(
        "/api/v1/auth/register",
        json={**payload, "email": "role@example.com", "role": "admin"},
    ).status_code == 422


def test_email_registration_rejects_password_over_bcrypt_byte_limit(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "unicode@example.com", "password": "é" * 37},
    )
    assert response.status_code == 422


def test_google_sign_in_registers_analyst_and_then_logs_in(client, session_factory, settings, monkeypatch):
    settings.google_client_id = "test-google-client-id"
    monkeypatch.setattr(
        auth.id_token,
        "verify_oauth2_token",
        lambda credential, request, audience: {
            "email": "new.analyst@gmail.com",
            "email_verified": True,
        },
    )

    registered = client.post("/api/v1/auth/google", json={"credential": "valid-google-id-token"})
    assert registered.status_code == 200
    assert registered.json()["role"] == "analyst"
    assert client.get(
        "/api/v1/admin/users",
        headers={"Authorization": f"Bearer {registered.json()['access_token']}"},
    ).status_code == 200
    with session_factory() as db:
        user = db.query(User).filter_by(email="new.analyst@gmail.com").one()
        assert user.role == "analyst"
        assert [row.action for row in db.query(AuditLog).all()] == ["google_register"]

    signed_in = client.post("/api/v1/auth/google", json={"credential": "valid-google-id-token"})
    assert signed_in.status_code == 200
    assert signed_in.json()["role"] == "analyst"
    with session_factory() as db:
        assert [row.action for row in db.query(AuditLog).all()] == ["google_register", "google_login"]


def test_google_sign_in_preserves_existing_admin_role(make_user, client, settings, monkeypatch):
    make_user("admin@gmail.com", "admin")
    settings.google_client_id = "test-google-client-id"
    monkeypatch.setattr(
        auth.id_token,
        "verify_oauth2_token",
        lambda credential, request, audience: {
            "email": "admin@gmail.com",
            "email_verified": True,
        },
    )

    response = client.post("/api/v1/auth/google", json={"credential": "valid-google-id-token"})
    assert response.status_code == 200
    assert response.json()["role"] == "admin"


def test_google_sign_in_rejects_unverified_email(client, settings, monkeypatch):
    settings.google_client_id = "test-google-client-id"
    monkeypatch.setattr(
        auth.id_token,
        "verify_oauth2_token",
        lambda credential, request, audience: {
            "email": "unverified@gmail.com",
            "email_verified": False,
        },
    )

    response = client.post("/api/v1/auth/google", json={"credential": "valid-google-id-token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Google account email is not verified"


def test_google_sign_in_requires_configuration(client, settings):
    settings.google_client_id = ""
    assert client.get("/api/v1/auth/google/config").json() == {"enabled": False, "client_id": None}
    response = client.post("/api/v1/auth/google", json={"credential": "any-token"})
    assert response.status_code == 503


def test_wrong_password_is_rejected_and_audited(make_user, login, session_factory):
    make_user("analyst@example.com", "analyst")
    resp = login("analyst@example.com", password="wrong-password-value")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid email or password"
    with session_factory() as db:
        actions = [row.action for row in db.query(AuditLog).all()]
    assert "login_failed" in actions


def test_current_user_can_change_password(make_user, auth_header, client):
    make_user("analyst@example.com", "analyst")
    headers = auth_header("analyst@example.com")
    new_password = "NewStrongPassword123!"

    resp = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "correct-horse-battery-staple", "new_password": new_password},
        headers=headers,
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": new_password}).status_code == 200
    assert client.post("/api/v1/auth/login", json={"email": "analyst@example.com", "password": "correct-horse-battery-staple"}).status_code == 401


def test_change_password_rejects_wrong_current_password(make_user, auth_header, client):
    make_user("analyst@example.com", "analyst")
    resp = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "wrong-password", "new_password": "NewStrongPassword123!"},
        headers=auth_header("analyst@example.com"),
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Current password is incorrect"


def test_unknown_email_gets_same_message(login):
    resp = login("nobody@example.com")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid email or password"


def test_inactive_user_cannot_log_in(make_user, login):
    make_user("gone@example.com", "analyst", active=False)
    assert login("gone@example.com").status_code == 401


def test_protected_route_requires_token(client):
    assert client.get("/api/v1/alerts").status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 401


def test_garbage_token_is_rejected(client):
    resp = client.get("/api/v1/alerts", headers={"Authorization": "Bearer not-a-jwt"})
    assert resp.status_code == 401


def test_analyst_can_view_users_but_not_create_users_or_view_audit_logs(make_user, auth_header, client):
    make_user("analyst@example.com", "analyst")
    headers = auth_header("analyst@example.com")
    assert client.get("/api/v1/admin/users", headers=headers).status_code == 200
    assert client.post(
        "/api/v1/admin/users",
        json={"email": "new@example.com", "password": "a-long-enough-password", "role": "analyst"},
        headers=headers,
    ).status_code == 403
    assert client.get("/api/v1/admin/audit-logs", headers=headers).status_code == 403


def test_analyst_can_assign_analyst_but_cannot_grant_admin(make_user, auth_header, client):
    make_user("admin@example.com", "admin")
    second_admin = make_user("second-admin@example.com", "admin")
    analyst = make_user("analyst@example.com", "analyst")
    headers = auth_header("analyst@example.com")

    promoted = client.patch(
        f"/api/v1/admin/users/{analyst.id}/role",
        json={"role": "admin"},
        headers=headers,
    )
    assert promoted.status_code == 403

    demoted = client.patch(
        f"/api/v1/admin/users/{second_admin.id}/role",
        json={"role": "analyst"},
        headers=headers,
    )
    assert demoted.status_code == 200
    assert demoted.json()["role"] == "analyst"


def test_admin_can_promote_analyst_to_admin(make_user, auth_header, client):
    make_user("admin@example.com", "admin")
    analyst = make_user("analyst@example.com", "analyst")
    analyst_headers = auth_header("analyst@example.com")

    promoted = client.patch(
        f"/api/v1/admin/users/{analyst.id}/role",
        json={"role": "admin"},
        headers=auth_header("admin@example.com"),
    )

    assert promoted.status_code == 200
    assert promoted.json()["role"] == "admin"
    assert client.get("/api/v1/admin/users", headers=analyst_headers).status_code == 200


def test_admin_cannot_demote_last_active_admin(make_user, auth_header, client):
    admin = make_user("admin@example.com", "admin")
    response = client.patch(
        f"/api/v1/admin/users/{admin.id}/role",
        json={"role": "analyst"},
        headers=auth_header("admin@example.com"),
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "Cannot demote the last active admin"


def test_admin_can_create_user_and_duplicates_conflict(make_user, auth_header, client):
    make_user("admin@example.com", "admin")
    headers = auth_header("admin@example.com")
    payload = {"email": "new.analyst@example.com", "password": "a-long-enough-password", "role": "analyst"}

    created = client.post("/api/v1/admin/users", json=payload, headers=headers)
    assert created.status_code == 201
    assert created.json()["role"] == "analyst"
    assert "hashed_password" not in created.json()

    duplicate = client.post("/api/v1/admin/users", json=payload, headers=headers)
    assert duplicate.status_code == 409


def test_short_password_is_rejected(make_user, auth_header, client):
    make_user("admin@example.com", "admin")
    resp = client.post(
        "/api/v1/admin/users",
        json={"email": "x@example.com", "password": "short", "role": "analyst"},
        headers=auth_header("admin@example.com"),
    )
    assert resp.status_code == 422


def test_role_is_read_from_database_not_token(make_user, auth_header, client, session_factory):
    user = make_user("analyst@example.com", "analyst")
    headers = auth_header("analyst@example.com")
    with session_factory() as db:
        row = db.get(User, user.id)
        row.is_active = False
        db.commit()
    assert client.get("/api/v1/alerts", headers=headers).status_code == 401


def test_me_returns_current_user(make_user, auth_header, client):
    make_user("analyst@example.com", "analyst")
    resp = client.get("/api/v1/auth/me", headers=auth_header("analyst@example.com"))
    assert resp.status_code == 200
    assert resp.json()["email"] == "analyst@example.com"
