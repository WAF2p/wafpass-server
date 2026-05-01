"""add control_packs table for versioned control catalogue management

Revision ID: 0025
Revises: 0024
Create Date: 2026-04-29 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "control_packs",
        sa.Column("version", sa.Text(), primary_key=True),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("control_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("controls_snapshot", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column(
            "imported_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("imported_by", UUID(as_uuid=True), nullable=True),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("activated_by", UUID(as_uuid=True), nullable=True),
    )
    op.create_index("ix_control_packs_is_active", "control_packs", ["is_active"])


def downgrade() -> None:
    op.drop_index("ix_control_packs_is_active", table_name="control_packs")
    op.drop_table("control_packs")
