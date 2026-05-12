"""add user_audit_logs table and last_login_at to users

Revision ID: 0012
Revises: 0011
Create Date: 2026-04-18 02:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "user_audit_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("actor_id", UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("detail", JSONB(), nullable=False, server_default="{}"),
        sa.Column("ip", sa.Text(), nullable=False, server_default=""),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_user_audit_logs_actor_id",  "user_audit_logs", ["actor_id"])
    op.create_index("ix_user_audit_logs_timestamp", "user_audit_logs", ["timestamp"])
    op.create_index("ix_user_audit_logs_action",    "user_audit_logs", ["action"])


def downgrade() -> None:
    op.drop_index("ix_user_audit_logs_action",    table_name="user_audit_logs")
    op.drop_index("ix_user_audit_logs_timestamp", table_name="user_audit_logs")
    op.drop_index("ix_user_audit_logs_actor_id",  table_name="user_audit_logs")
    op.drop_table("user_audit_logs")
    op.drop_column("users", "last_login_at")
