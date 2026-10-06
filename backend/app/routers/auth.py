from functools import lru_cache

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import create_access_token, timing_dummy_hash, verify_password
from app.db.models import User
from app.db.session import get_db
from app.deps import get_current_user
from app.schemas import LoginRequest, TokenOut, UserOut
from app.services import audit

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

INVALID = "Invalid email or password"


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.post("/login", response_model=TokenOut)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenOut:
    email = body.email.lower()
    ip = _client_ip(request)
    user = db.scalar(select(User).where(User.email == email))

    if user is None:
        # Spend the same time as a real check so timing does not reveal which emails exist.
        verify_password(body.password, timing_dummy_hash())
        audit.record(db, "login_failed", target=None, detail="unknown_user", ip=ip)
        raise HTTPException(status_code=401, detail=INVALID)

    if not user.is_active or not verify_password(body.password, user.hashed_password):
        audit.record(db, "login_failed", actor_id=user.id, detail="bad_credentials_or_inactive", ip=ip)
        raise HTTPException(status_code=401, detail=INVALID)

    token, ttl = create_access_token(user.id, user.role)
    audit.record(db, "login", actor_id=user.id, ip=ip)
    return TokenOut(access_token=token, expires_in=ttl, role=user.role)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)
