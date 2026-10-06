import datetime as dt
from functools import lru_cache

import bcrypt
import jwt

from app.core.config import get_settings

BCRYPT_ROUNDS = 12


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(BCRYPT_ROUNDS)).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


@lru_cache
def timing_dummy_hash() -> str:
    """Used to spend the same time on unknown emails as on wrong passwords."""
    return hash_password("timing-equaliser-not-a-real-password")


def create_access_token(user_id: int, role: str) -> tuple[str, int]:
    settings = get_settings()
    now = dt.datetime.now(dt.timezone.utc)
    ttl_seconds = settings.jwt_access_token_minutes * 60
    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": now,
        "exp": now + dt.timedelta(seconds=ttl_seconds),
    }
    token = jwt.encode(payload, settings.jwt_secret(), algorithm=settings.jwt_algorithm)
    return token, ttl_seconds


def decode_access_token(token: str) -> dict:
    settings = get_settings()
    return jwt.decode(token, settings.jwt_secret(), algorithms=[settings.jwt_algorithm])
