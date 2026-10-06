from app.db.models import AuditLog, User


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


def test_wrong_password_is_rejected_and_audited(make_user, login, session_factory):
    make_user("analyst@example.com", "analyst")
    resp = login("analyst@example.com", password="wrong-password-value")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid email or password"
    with session_factory() as db:
        actions = [row.action for row in db.query(AuditLog).all()]
    assert "login_failed" in actions


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


def test_analyst_is_forbidden_from_admin_routes(make_user, auth_header, client):
    make_user("analyst@example.com", "analyst")
    resp = client.get("/api/v1/admin/users", headers=auth_header("analyst@example.com"))
    assert resp.status_code == 403


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
