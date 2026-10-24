from functools import lru_cache
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from google.auth.exceptions import GoogleAuthError
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import create_access_token, hash_password, timing_dummy_hash, verify_password
from app.db.models import User
from app.db.session import get_db
from app.deps import get_current_user
from app.schemas import (
    ChangePasswordRequest,
    GoogleAuthConfig,
    GoogleCredentialRequest,
    LoginRequest,
    RegisterRequest,
    TokenOut,
    UserOut,
)
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


@router.post("/register", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> TokenOut:
    email = str(body.email).lower()
    user = User(
        email=email,
        hashed_password=hash_password(body.password),
        role="analyst",
        is_active=True,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists") from exc

    db.refresh(user)
    audit.record(db, "register", actor_id=user.id, target=email, ip=_client_ip(request))
    token, ttl = create_access_token(user.id, user.role)
    return TokenOut(access_token=token, expires_in=ttl, role=user.role)


@router.get("/google/config", response_model=GoogleAuthConfig)
def google_config() -> GoogleAuthConfig:
    client_id = get_settings().google_client_id
    return GoogleAuthConfig(enabled=bool(client_id), client_id=client_id or None)


@router.post("/google", response_model=TokenOut)
def google_login(
    body: GoogleCredentialRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenOut:
    client_id = get_settings().google_client_id
    if not client_id:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Google sign-in is not configured")

    try:
        claims = id_token.verify_oauth2_token(body.credential, GoogleRequest(), client_id)
    except (GoogleAuthError, ValueError) as exc:
        audit.record(db, "google_login_failed", detail="invalid_credential", ip=_client_ip(request))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Google credential") from exc

    email = claims.get("email")
    if not isinstance(email, str) or claims.get("email_verified") is not True:
        audit.record(db, "google_login_failed", detail="unverified_email", ip=_client_ip(request))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Google account email is not verified")

    email = email.strip().lower()
    if not email:
        audit.record(db, "google_login_failed", detail="missing_email", ip=_client_ip(request))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Google account email is missing")

    user = db.scalar(select(User).where(User.email == email))
    registered = user is None
    if user is None:
        user = User(
            email=email,
            hashed_password=hash_password(secrets.token_urlsafe(48)),
            role="analyst",
            is_active=True,
        )
        db.add(user)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            user = db.scalar(select(User).where(User.email == email))
            if user is None:
                raise
            registered = False
        else:
            db.refresh(user)

    if not user.is_active:
        audit.record(db, "google_login_failed", actor_id=user.id, detail="inactive_user", ip=_client_ip(request))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is inactive")

    audit.record(
        db,
        "google_register" if registered else "google_login",
        actor_id=user.id,
        target=email,
        ip=_client_ip(request),
    )
    token, ttl = create_access_token(user.id, user.role)
    return TokenOut(access_token=token, expires_in=ttl, role=user.role)


@router.post("/change-password")
def change_password(
    body: ChangePasswordRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    if not verify_password(body.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current password")

    user.hashed_password = hash_password(body.new_password)
    db.add(user)
    db.commit()
    audit.record(db, "password_changed", actor_id=user.id, ip=_client_ip(request))
    return {"status": "ok"}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)
