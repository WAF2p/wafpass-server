"""add family_id to refresh_tokens for rotation and stolen-token detection

Revision ID: 0021
Revises: 0020
Create Date: 2026-04-25 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add nullable first so existing rows are accepted
    op.add_column(
        "refresh_tokens",
        sa.Column("family_id", UUID(as_uuid=True), nullable=True),
    )
    # Each existing token becomes its own family — they can't be chained anyway
    op.execute("UPDATE refresh_tokens SET family_id = gen_random_uuid() WHERE family_id IS NULL")
    op.alter_column("refresh_tokens", "family_id", nullable=False)
    op.create_index("ix_refresh_tokens_family_id", "refresh_tokens", ["family_id"])


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_family_id", table_name="refresh_tokens")
    op.drop_column("refresh_tokens", "family_id")
