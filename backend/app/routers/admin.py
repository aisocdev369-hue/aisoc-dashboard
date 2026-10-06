from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.db.models import AuditLog, User
from app.db.session import get_db
from app.deps import require_roles
from app.schemas import AuditOut, UserCreate, UserOut
from app.services import audit

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])
ADMIN_ONLY = require_roles("admin")


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/users", response_model=list[UserOut])
def list_users(_admin: User = Depends(ADMIN_ONLY), db: Session = Depends(get_db)) -> list[UserOut]:
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
    db.commit()
    db.refresh(user)
    audit.record(db, "user_created", actor_id=admin.id, target=email, detail=f"role={body.role}", ip=_client_ip(request))
    return UserOut.model_validate(user)


@router.get("/audit-logs", response_model=list[AuditOut])
def list_audit_logs(
    limit: int = Query(100, ge=1, le=500),
    _admin: User = Depends(ADMIN_ONLY),
    db: Session = Depends(get_db),
) -> list[AuditOut]:
    rows = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(limit)).all()
    return [AuditOut.model_validate(r) for r in rows]
