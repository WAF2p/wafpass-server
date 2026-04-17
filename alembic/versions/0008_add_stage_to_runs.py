"""add stage column to runs

Revision ID: 0008
Revises: 0007
Create Date: 2026-04-17 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "runs",
        sa.Column("stage", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_runs_stage", "runs", ["stage"])


def downgrade() -> None:
    op.drop_index("ix_runs_stage", table_name="runs")
    op.drop_column("runs", "stage")
