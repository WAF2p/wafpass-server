"""add evidence table for locked, immutable audit evidence packages

Revision ID: 0015
Revises: 0014
Create Date: 2026-04-19 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evidence",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("run_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("title", sa.Text(), nullable=False, server_default=""),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("project", sa.Text(), nullable=False, server_default=""),
        sa.Column("prepared_by", sa.Text(), nullable=False, server_default=""),
        sa.Column("organization", sa.Text(), nullable=False, server_default=""),
        sa.Column("audit_period", sa.Text(), nullable=False, server_default=""),
        sa.Column("frameworks", JSONB(), nullable=False, server_default="[]"),
        sa.Column("snapshot", JSONB(), nullable=False, server_default="{}"),
        sa.Column("report_html", sa.Text(), nullable=True),
        sa.Column("hash_digest", sa.Text(), nullable=False, server_default=""),
        sa.Column("public_token", sa.Text(), nullable=False, unique=True),
        sa.Column("locked_by", UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("evidence")
