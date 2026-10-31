from collections.abc import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import decode_access_token, parse_endpoint_token, verify_endpoint_secret
from app.db.models import Endpoint, User
from app.db.session import get_db

_bearer = HTTPBearer(auto_error=False)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Resolve the bearer token to an active user. The role is always read from the database."""
    if creds is None or creds.scheme.lower() != "bearer":
        raise _unauthorized()
    try:
        payload = decode_access_token(creds.credentials)
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise _unauthorized()

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _unauthorized()
    return user


def get_current_endpoint(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> Endpoint:
    """Resolve an endpoint-agent bearer token (see app.core.security) to its active Endpoint row."""
    if creds is None or creds.scheme.lower() != "bearer":
        raise _unauthorized()
    parsed = parse_endpoint_token(creds.credentials)
    if parsed is None:
        raise _unauthorized()
    endpoint_id, secret = parsed

    endpoint = db.get(Endpoint, endpoint_id)
    if endpoint is None or not endpoint.is_active or not verify_endpoint_secret(secret, endpoint.token_hash):
        raise _unauthorized()
    return endpoint


def require_roles(*roles: str) -> Callable[..., User]:
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient privileges")
        return user

    return checker
