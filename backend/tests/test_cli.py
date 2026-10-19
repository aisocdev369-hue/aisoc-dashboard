from app import cli
from app.core.security import verify_password
from app.db.models import User


def test_set_password_updates_existing_user_interactively(make_user, session_factory, monkeypatch, capsys):
    user = make_user("analyst@example.com", "analyst")
    monkeypatch.setattr(cli, "get_session_factory", lambda: session_factory)
    passwords = iter(["NewStrongPassword123!", "NewStrongPassword123!"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(passwords))

    assert cli.main(["set-password", "--email", "ANALYST@example.com"]) == 0
    assert capsys.readouterr().out.strip() == "Password updated for analyst@example.com"

    with session_factory() as db:
        updated = db.get(User, user.id)
        assert verify_password("NewStrongPassword123!", updated.hashed_password)


def test_set_password_rejects_mismatched_confirmation(make_user, session_factory, monkeypatch):
    user = make_user("analyst@example.com", "analyst")
    original_hash = user.hashed_password
    monkeypatch.setattr(cli, "get_session_factory", lambda: session_factory)
    passwords = iter(["NewStrongPassword123!", "different-password"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: next(passwords))

    assert cli.main(["set-password", "--email", user.email]) == 2

    with session_factory() as db:
        assert db.get(User, user.id).hashed_password == original_hash


def test_set_role_promotes_existing_user(make_user, session_factory, monkeypatch):
    make_user("admin@example.com", "admin")
    analyst = make_user("analyst@example.com", "analyst")
    monkeypatch.setattr(cli, "get_session_factory", lambda: session_factory)

    assert cli.main(["set-role", "--email", analyst.email, "--role", "admin"]) == 0

    with session_factory() as db:
        assert db.get(User, analyst.id).role == "admin"


def test_set_role_cannot_demote_last_active_admin(make_user, session_factory, monkeypatch):
    admin = make_user("admin@example.com", "admin")
    monkeypatch.setattr(cli, "get_session_factory", lambda: session_factory)

    assert cli.main(["set-role", "--email", admin.email, "--role", "analyst"]) == 1

    with session_factory() as db:
        assert db.get(User, admin.id).role == "admin"
