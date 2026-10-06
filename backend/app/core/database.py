from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine

from app.core.config import get_settings


@lru_cache
def get_engine() -> Engine | None:
    """Shared engine for the process. Returns None when DATABASE_URL is not set."""
    url = get_settings().database_url
    if not url:
        return None
    return create_engine(url, pool_pre_ping=True)
