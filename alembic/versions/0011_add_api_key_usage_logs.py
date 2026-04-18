"""add api_key_usage_logs table

Revision ID: 0011
Revises: 0010
Create Date: 2026-04-18 01:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_key_usage_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("api_key_id", UUID(as_uuid=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("endpoint", sa.Text(), nullable=False),
        sa.Column("run_id", UUID(as_uuid=True), nullable=True),
        sa.Column("project", sa.Text(), nullable=False, server_default=""),
        sa.Column("branch", sa.Text(), nullable=False, server_default=""),
        sa.Column("score", sa.Integer(), nullable=True),
        sa.Column("ip", sa.Text(), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["api_key_id"], ["api_keys.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_api_key_usage_logs_api_key_id", "api_key_usage_logs", ["api_key_id"])
    op.create_index("ix_api_key_usage_logs_used_at", "api_key_usage_logs", ["used_at"])


def downgrade() -> None:
    op.drop_index("ix_api_key_usage_logs_used_at", table_name="api_key_usage_logs")
    op.drop_index("ix_api_key_usage_logs_api_key_id", table_name="api_key_usage_logs")
    op.drop_table("api_key_usage_logs")
