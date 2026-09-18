"""add validation metadata and validated_at

Revision ID: 0040
Revises: 0039
Create Date: 2026-08-16 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0040"
down_revision: Union[str, None] = "0039"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("validations", sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "validations",
        sa.Column("metadata", JSONB(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("validations", "metadata")
    op.drop_column("validations", "validated_at")
