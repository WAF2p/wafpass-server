"""add compound index on runs(created_at, id) for cursor pagination

Revision ID: 0020
Revises: 0019
Create Date: 2026-04-25 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Supports keyset pagination: ORDER BY created_at DESC, id DESC
    # with WHERE (created_at, id) < (cursor_ts, cursor_id)
    op.create_index(
        "ix_runs_created_at_id",
        "runs",
        [sa.text("created_at DESC"), sa.text("id DESC")],
    )


def downgrade() -> None:
    op.drop_index("ix_runs_created_at_id", table_name="runs")
