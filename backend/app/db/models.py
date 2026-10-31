from datetime import datetime, timezone

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base

ROLES = ("admin", "analyst")
SEVERITIES = ("critical", "high", "medium", "low")
ALERT_STATUSES = ("New", "Investigating", "Closed")
ENDPOINT_OS = ("windows", "linux")
EVENT_TYPES = ("login", "process_start", "file_change", "network_connection")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('admin', 'analyst')", name="ck_users_role"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint("severity IN ('critical', 'high', 'medium', 'low')", name="ck_alerts_severity"),
        CheckConstraint("status IN ('New', 'Investigating', 'Closed')", name="ck_alerts_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    external_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    rule: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    mitre: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    # Simulated alerts are flagged so the UI and reports never present them as real events.
    is_simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    requested_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    model: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # "ok" or "error"
    summary: Mapped[str | None] = mapped_column(Text)
    threat_assessment: Mapped[str | None] = mapped_column(Text)
    mitre_techniques: Mapped[str | None] = mapped_column(Text)  # JSON array as text
    business_impact: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[str | None] = mapped_column(String(16))
    confidence_explanation: Mapped[str | None] = mapped_column(Text)
    recommendations: Mapped[str | None] = mapped_column(Text)  # JSON array as text
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now, index=True)


class Endpoint(Base):
    """A registered monitoring source: one of the project's known machines (Windows 11 or Linux)."""

    __tablename__ = "endpoints"
    __table_args__ = (CheckConstraint("os IN ('windows', 'linux')", name="ck_endpoints_os"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    os: Mapped[str] = mapped_column(String(16), nullable=False)
    # SHA-256 of the per-endpoint secret half of its token (see app.core.security). Never the raw token.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)


class EndpointEvent(Base):
    """A single raw event reported by an endpoint agent, optionally promoted to an Alert."""

    __tablename__ = "endpoint_events"
    __table_args__ = (
        CheckConstraint(
            "event_type IN ('login', 'process_start', 'file_change', 'network_connection')",
            name="ck_endpoint_events_type",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    client_event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now, index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target: Mapped[str | None] = mapped_column(String(120))
    detail: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(String(45))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now, index=True)
