"""add regulatory_mapping column to controls table

Revision ID: 0026
Revises: 0025
Create Date: 2026-04-30 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "controls",
        sa.Column(
            "regulatory_mapping",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )


def downgrade() -> None:
    op.drop_column("controls", "regulatory_mapping")
