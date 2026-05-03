"""add findings_comments table for team collaboration on findings

Revision ID: 0028
Revises: 0027
Create Date: 2026-05-01 00:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "findings_comments",
        sa.Column("id", sa.Uuid(), primary_key=True, default=sa.text("gen_random_uuid()")),
        sa.Column("finding_id", sa.Uuid(), nullable=False, index=True),
        sa.Column("run_id", sa.Uuid(), nullable=False, index=True),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, default=sa.text("timezone('UTC', now())")),
        sa.ForeignKeyConstraint(["finding_id"], ["run_findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )

    # Add columns to runs table for notification settings
    op.add_column(
        "runs",
        sa.Column("notification_channels", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
    )


def downgrade() -> None:
    op.drop_table("findings_comments")
    op.drop_column("runs", "notification_channels")
