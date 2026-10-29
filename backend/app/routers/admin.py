from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.request import client_ip
from app.core.security import hash_password
from app.db.models import AuditLog, User
from app.db.session import get_db
from app.deps import require_roles
from app.schemas import AuditOut, UserCreate, UserOut, UserRoleUpdate
from app.services import audit

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])
ADMIN_ONLY = require_roles("admin")
USER_ROLE_MANAGERS = require_roles("admin", "analyst")


@router.get("/users", response_model=list[UserOut])
def list_users(_manager: User = Depends(USER_ROLE_MANAGERS), db: Session = Depends(get_db)) -> list[UserOut]:
    rows = db.scalars(select(User).order_by(User.id)).all()
    return [UserOut.model_validate(r) for r in rows]


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate,
    request: Request,
    admin: User = Depends(ADMIN_ONLY),
    db: Session = Depends(get_db),
) -> UserOut:
    email = body.email.lower()
    if db.scalar(select(User.id).where(User.email == email)) is not None:
        raise HTTPException(status_code=409, detail="A user with this email already exists")

    user = User(email=email, hashed_password=hash_password(body.password), role=body.role, is_active=True)
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="A user with this email already exists") from exc
    db.refresh(user)
    audit.record(db, "user_created", actor_id=admin.id, target=email, detail=f"role={body.role}", ip=client_ip(request))
    return UserOut.model_validate(user)


@router.patch("/users/{user_id}/role", response_model=UserOut)
def update_user_role(
    user_id: int,
    body: UserRoleUpdate,
    request: Request,
    manager: User = Depends(USER_ROLE_MANAGERS),
    db: Session = Depends(get_db),
) -> UserOut:
    # Lock rows in a consistent order so concurrent role updates cannot both
    # pass the last-active-admin check using the same stale count.
    lock_stmt = select(User).order_by(User.id)
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        # Serialize this critical section before taking a fresh READ COMMITTED snapshot.
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext('soc-admin-role-change'))"))
        lock_stmt = lock_stmt.with_for_update()
    locked_users = db.scalars(lock_stmt.execution_options(populate_existing=True)).all()
    if manager.role == "analyst" and body.role == "admin":
        raise HTTPException(status_code=403, detail="Only admins can assign the Admin role")
    user = next((row for row in locked_users if row.id == user_id), None)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.role == body.role:
        return UserOut.model_validate(user)

    if user.is_active and user.role == "admin" and body.role == "analyst":
        active_admins = sum(1 for row in locked_users if row.is_active and row.role == "admin")
        if active_admins <= 1:
            raise HTTPException(status_code=409, detail="Cannot demote the last active admin")

    user.role = body.role
    db.commit()
    db.refresh(user)
    audit.record(
        db,
        "user_role_changed",
        actor_id=manager.id,
        target=user.email,
        detail=f"role={body.role}",
        ip=client_ip(request),
    )
    return UserOut.model_validate(user)


@router.get("/audit-logs", response_model=list[AuditOut])
def list_audit_logs(
    limit: int = Query(100, ge=1, le=500),
    _admin: User = Depends(ADMIN_ONLY),
    db: Session = Depends(get_db),
) -> list[AuditOut]:
    rows = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(limit)).all()
    return [AuditOut.model_validate(r) for r in rows]
