"""add validations table

Revision ID: 0038
Revises: 0037
Create Date: 2026-08-16 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "0038"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "validations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("validation_id", sa.Text(), nullable=False, unique=True),
        sa.Column("canonical_hash", sa.Text(), nullable=False, index=True),
        sa.Column("project", sa.Text(), nullable=False, server_default=""),
        sa.Column("branch", sa.Text(), nullable=False, server_default=""),
        sa.Column("git_sha", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.Text(), nullable=False, server_default="active"),
        sa.Column("run_snapshot", JSONB(), nullable=False, server_default="{}"),
        sa.Column("server_public_key", sa.Text(), nullable=False),
        sa.Column("server_signature", sa.Text(), nullable=False),
        sa.Column("certificate_chain", JSONB(), nullable=False, server_default="[]"),
        sa.Column("badge_url", sa.Text(), nullable=False, server_default=""),
        sa.Column("verification_url", sa.Text(), nullable=False, server_default=""),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_validations_project", "validations", ["project"])
    op.create_index("ix_validations_status", "validations", ["status"])


def downgrade() -> None:
    op.drop_table("validations")
