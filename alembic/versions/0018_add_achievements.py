"""add project_achievements table

Revision ID: 0018
Revises: 0017
Create Date: 2026-04-23 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "project_achievements",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("project", sa.Text(), nullable=False),
        sa.Column("tier_level", sa.Integer(), nullable=False),
        sa.Column("tier_label", sa.Text(), nullable=False, server_default=""),
        sa.Column("score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("run_id", UUID(as_uuid=True), nullable=False),
        sa.Column("verification_token", sa.Text(), nullable=False, unique=True),
        sa.Column("snapshot_jsonb", JSONB(), nullable=False, server_default="{}"),
        sa.Column("achieved_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_project_achievements_project", "project_achievements", ["project"])
    op.create_unique_constraint("uq_project_achievements_project_tier", "project_achievements", ["project", "tier_level"])


def downgrade() -> None:
    op.drop_table("project_achievements")
