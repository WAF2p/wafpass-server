"""create runs table

Revision ID: 0001
Revises:
Create Date: 2026-01-01 00:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("project", sa.Text(), nullable=False, server_default=""),
        sa.Column("branch", sa.Text(), nullable=False, server_default=""),
        sa.Column("git_sha", sa.Text(), nullable=False, server_default=""),
        sa.Column("triggered_by", sa.Text(), nullable=False, server_default="local"),
        sa.Column("iac_framework", sa.Text(), nullable=False, server_default="terraform"),
        sa.Column("score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("pillar_scores", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("findings", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_runs_project", "runs", ["project"])
    op.create_index("ix_runs_created_at", "runs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_runs_created_at", "runs")
    op.drop_index("ix_runs_project", "runs")
    op.drop_table("runs")
