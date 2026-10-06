"""Initial schema: users, alerts, AI analyses, audit logs.

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-06
"""

import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role IN ('admin', 'analyst')", name="ck_users_role"),
    )

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("external_id", sa.String(64), nullable=False, unique=True),
        sa.Column("rule", sa.String(200), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("host", sa.String(120), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=False),
        sa.Column("mitre", sa.String(120), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_simulated", sa.Boolean(), nullable=False),
        sa.CheckConstraint("severity IN ('critical', 'high', 'medium', 'low')", name="ck_alerts_severity"),
        sa.CheckConstraint("status IN ('New', 'Investigating', 'Closed')", name="ck_alerts_status"),
    )
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_host", "alerts", ["host"])
    op.create_index("ix_alerts_source_ip", "alerts", ["source_ip"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_occurred_at", "alerts", ["occurred_at"])

    op.create_table(
        "ai_analyses",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("requested_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("model", sa.String(80), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("summary", sa.Text()),
        sa.Column("threat_assessment", sa.Text()),
        sa.Column("mitre_techniques", sa.Text()),
        sa.Column("business_impact", sa.Text()),
        sa.Column("confidence", sa.String(16)),
        sa.Column("confidence_explanation", sa.Text()),
        sa.Column("recommendations", sa.Text()),
        sa.Column("error_code", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ai_analyses_alert_id", "ai_analyses", ["alert_id"])
    op.create_index("ix_ai_analyses_requested_by", "ai_analyses", ["requested_by"])
    op.create_index("ix_ai_analyses_created_at", "ai_analyses", ["created_at"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_id", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target", sa.String(120)),
        sa.Column("detail", sa.Text()),
        sa.Column("ip", sa.String(45)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_logs_actor_id", "audit_logs", ["actor_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("ai_analyses")
    op.drop_table("alerts")
    op.drop_table("users")
