"""Endpoint agents: endpoints and endpoint_events tables.

Revision ID: 0002_endpoint_agents
Revises: 0001_initial
Create Date: 2026-10-31
"""

import sqlalchemy as sa
from alembic import op

revision = "0002_endpoint_agents"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "endpoints",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hostname", sa.String(120), nullable=False, unique=True),
        sa.Column("os", sa.String(16), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("os IN ('windows', 'linux')", name="ck_endpoints_os"),
    )

    op.create_table(
        "endpoint_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("endpoint_id", sa.Integer(), sa.ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False),
        sa.Column("client_event_id", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "event_type IN ('login', 'process_start', 'file_change', 'network_connection')",
            name="ck_endpoint_events_type",
        ),
    )
    op.create_index("ix_endpoint_events_endpoint_id", "endpoint_events", ["endpoint_id"])
    op.create_index("ix_endpoint_events_event_type", "endpoint_events", ["event_type"])
    op.create_index("ix_endpoint_events_occurred_at", "endpoint_events", ["occurred_at"])
    op.create_index("ix_endpoint_events_alert_id", "endpoint_events", ["alert_id"])
    op.create_index("ix_endpoint_events_created_at", "endpoint_events", ["created_at"])


def downgrade() -> None:
    op.drop_table("endpoint_events")
    op.drop_table("endpoints")
