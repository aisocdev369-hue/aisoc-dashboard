import logging

from fastapi import FastAPI, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.core.config import get_settings
from app.db.session import get_engine
from app.routers import admin, ai, alerts, auth

settings = get_settings()
logging.basicConfig(level=settings.log_level)
logger = logging.getLogger("soc")

app = FastAPI(
    title="SOC Dashboard API",
    version="0.2.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth.router)
app.include_router(alerts.router)
app.include_router(ai.router)
app.include_router(admin.router)


@app.get("/health", tags=["health"])
def health(response: Response):
    """Liveness plus database connectivity. Returns 503 when the database is not usable."""
    engine = get_engine()
    if engine is None:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "degraded", "database": "not_configured"}
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        logger.exception("database health check failed")
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "degraded", "database": "unavailable"}
    return {"status": "ok", "database": "ok", "env": settings.app_env}
