"""Operator commands. Run inside the API container, for example:

    docker compose exec api python -m app.cli create-user --email you@example.com --role admin
    docker compose exec api python -m app.cli set-password --email you@example.com
    docker compose exec api python -m app.cli seed-simulated --count 48

Passwords are read interactively and never accepted as command-line arguments.
"""

import argparse
import getpass
import sys

from sqlalchemy import func, select, text

from app.core.security import hash_password
from app.db.models import ROLES, User
from app.db.session import get_session_factory
from app.services import audit
from app.services.simulated import seed_simulated_alerts


def _create_user(email: str, role: str) -> int:
    if role not in ROLES:
        print(f"role must be one of {ROLES}", file=sys.stderr)
        return 2
    password = getpass.getpass("Password (min 12 characters): ")
    if len(password) < 12 or len(password) > 72:
        print("Password must be 12 to 72 characters.", file=sys.stderr)
        return 2
    if getpass.getpass("Repeat password: ") != password:
        print("Passwords do not match.", file=sys.stderr)
        return 2

    factory = get_session_factory()
    if factory is None:
        print("DATABASE_URL is not configured.", file=sys.stderr)
        return 2
    with factory() as db:
        normalised = email.lower()
        if db.scalar(select(User.id).where(User.email == normalised)) is not None:
            print("A user with this email already exists.", file=sys.stderr)
            return 1
        db.add(User(email=normalised, hashed_password=hash_password(password), role=role, is_active=True))
        db.commit()
    print(f"Created {role} user {normalised}.")
    return 0


def _set_password(email: str) -> int:
    password = getpass.getpass("New password (min 12 characters): ")
    if len(password) < 12 or len(password) > 72:
        print("Password must be 12 to 72 characters.", file=sys.stderr)
        return 2
    if getpass.getpass("Repeat new password: ") != password:
        print("Passwords do not match.", file=sys.stderr)
        return 2

    factory = get_session_factory()
    if factory is None:
        print("DATABASE_URL is not configured.", file=sys.stderr)
        return 2
    normalised = email.strip().lower()
    with factory() as db:
        user = db.scalar(select(User).where(User.email == normalised))
        if user is None:
            print("No user with this email exists.", file=sys.stderr)
            return 1
        user.hashed_password = hash_password(password)
        db.commit()
        audit.record(db, "password_reset", target=normalised)
    print(f"Password updated for {normalised}")
    return 0


def _set_role(email: str, role: str) -> int:
    if role not in ROLES:
        print(f"role must be one of {ROLES}", file=sys.stderr)
        return 2

    factory = get_session_factory()
    if factory is None:
        print("DATABASE_URL is not configured.", file=sys.stderr)
        return 2
    normalised = email.strip().lower()
    with factory() as db:
        lock_stmt = select(User).order_by(User.id)
        if db.bind is not None and db.bind.dialect.name == "postgresql":
            db.execute(text("SELECT pg_advisory_xact_lock(hashtext('soc-admin-role-change'))"))
            lock_stmt = lock_stmt.with_for_update()
        users = db.scalars(lock_stmt.execution_options(populate_existing=True)).all()
        user = next((row for row in users if row.email == normalised), None)
        if user is None:
            print("No user with this email exists.", file=sys.stderr)
            return 1
        if user.role == "admin" and user.is_active and role == "analyst":
            active_admins = sum(1 for row in users if row.role == "admin" and row.is_active)
            if active_admins <= 1:
                print("Cannot demote the last active admin.", file=sys.stderr)
                return 1
        if user.role == role:
            print(f"User {normalised} already has role {role}.")
            return 0
        user.role = role
        db.commit()
        audit.record(db, "user_role_changed", target=normalised, detail=f"role={role}")
    print(f"Set role to {role} for {normalised}.")
    return 0


def _seed(count: int) -> int:
    factory = get_session_factory()
    if factory is None:
        print("DATABASE_URL is not configured.", file=sys.stderr)
        return 2
    with factory() as db:
        inserted = seed_simulated_alerts(db, count=count)
    print(f"Inserted {inserted} simulated alerts (existing IDs are skipped).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create-user", help="Create an admin or analyst account")
    create.add_argument("--email", required=True)
    create.add_argument("--role", required=True, choices=ROLES)

    set_password = sub.add_parser("set-password", help="Reset an existing user's password")
    set_password.add_argument("--email", required=True)

    set_role = sub.add_parser("set-role", help="Set an existing user's role")
    set_role.add_argument("--email", required=True)
    set_role.add_argument("--role", required=True, choices=ROLES)

    seed = sub.add_parser("seed-simulated", help="Insert clearly labelled simulated alerts")
    seed.add_argument("--count", type=int, default=48, choices=range(1, 501), metavar="1-500")

    args = parser.parse_args(argv)
    if args.command == "create-user":
        return _create_user(args.email, args.role)
    if args.command == "set-password":
        return _set_password(args.email)
    if args.command == "set-role":
        return _set_role(args.email, args.role)
    return _seed(args.count)


if __name__ == "__main__":
    raise SystemExit(main())
