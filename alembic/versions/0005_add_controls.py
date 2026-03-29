"""add controls table

Revision ID: 0005
Revises: 0004
Create Date: 2026-03-29 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "controls",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("pillar", sa.Text, nullable=False, server_default=""),
        sa.Column("severity", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "type",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "checks",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("source", sa.Text, nullable=False, server_default="wafpass"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("ix_controls_pillar", "controls", ["pillar"])
    op.create_index("ix_controls_severity", "controls", ["severity"])


def downgrade() -> None:
    op.drop_index("ix_controls_severity", table_name="controls")
    op.drop_index("ix_controls_pillar", table_name="controls")
    op.drop_table("controls")
