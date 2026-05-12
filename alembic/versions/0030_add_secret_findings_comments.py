"""add secret_findings_comments table for team collaboration on hardcoded secrets

Revision ID: 0030
Revises: 0029
Create Date: 2026-05-02 00:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create run_secret_findings table (normalized from runs.secret_findings)
    op.create_table(
        "run_secret_findings",
        sa.Column("id", sa.Uuid(), primary_key=True, default=sa.text("gen_random_uuid()")),
        sa.Column("run_id", sa.Uuid(), nullable=False, index=True),
        sa.Column("file", sa.Text(), nullable=False, default=""),
        sa.Column("line_no", sa.Integer(), nullable=False, default=0),
        sa.Column("pattern_name", sa.Text(), nullable=False, default=""),
        sa.Column("severity", sa.Text(), nullable=False, default=""),
        sa.Column("matched_key", sa.Text(), nullable=False, default=""),
        sa.Column("masked_value", sa.Text(), nullable=False, default=""),
        sa.Column("suppressed", sa.Boolean(), nullable=False, default=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"], ondelete="CASCADE"),
    )

    # Create secret_findings_comments table
    op.create_table(
        "secret_findings_comments",
        sa.Column("id", sa.Uuid(), primary_key=True, default=sa.text("gen_random_uuid()")),
        sa.Column("secret_finding_id", sa.Uuid(), nullable=False, index=True),
        sa.Column("run_id", sa.Uuid(), nullable=False, index=True),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, default=sa.text("timezone('UTC', now())")),
        sa.ForeignKeyConstraint(["secret_finding_id"], ["run_secret_findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )


def downgrade() -> None:
    op.drop_table("secret_findings_comments")
    op.drop_table("run_secret_findings")
