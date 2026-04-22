"""add project_passports table

Revision ID: 0016
Revises: 0015
Create Date: 2026-04-22 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "project_passports",
        sa.Column("project", sa.Text(), primary_key=True),
        sa.Column("display_name", sa.Text(), nullable=False, server_default=""),
        sa.Column("owner", sa.Text(), nullable=False, server_default=""),
        sa.Column("owner_team", sa.Text(), nullable=False, server_default=""),
        sa.Column("contact_email", sa.Text(), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("criticality", sa.Text(), nullable=False, server_default=""),
        sa.Column("environment", sa.Text(), nullable=False, server_default=""),
        sa.Column("cloud_provider", sa.Text(), nullable=False, server_default=""),
        sa.Column("repository_url", sa.Text(), nullable=False, server_default=""),
        sa.Column("documentation_url", sa.Text(), nullable=False, server_default=""),
        sa.Column("tags", JSONB(), nullable=False, server_default="[]"),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("updated_by", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("project_passports")
