"""remove validation_key_orders

Revision ID: 0041
Revises: 0040
Create Date: 2026-08-20 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0041"
down_revision: Union[str, None] = "0040"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The validation_key_orders table was created by an earlier 0041 migration
    # that has since been replaced. Drop the abandoned table if it still exists.
    op.execute("DROP TABLE IF EXISTS validation_key_orders")


def downgrade() -> None:
    # Recreate the table so the migration graph remains reversible.
    op.create_table(
        "validation_key_orders",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), nullable=True),
        sa.Column("stripe_session_id", sa.Text(), nullable=True, unique=True),
        sa.Column("stripe_payment_intent_id", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("package_id", sa.Text(), nullable=False, server_default=""),
        sa.Column("credits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("gateway_key_id", sa.Text(), nullable=True),
        sa.Column("gateway_key_prefix", sa.Text(), nullable=True),
        sa.Column("raw_key", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("paid_at", sa.DateTime(timezone=True), nullable=True),
    )
