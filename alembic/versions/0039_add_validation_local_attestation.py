"""add validation local attestation fields

Revision ID: 0039
Revises: 0038
Create Date: 2026-08-16 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0039"
down_revision: Union[str, None] = "0038"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("validations", sa.Column("local_public_key", sa.Text(), nullable=False, server_default=""))
    op.add_column("validations", sa.Column("local_signature", sa.Text(), nullable=False, server_default=""))
    op.add_column("validations", sa.Column("local_signed_at", sa.Text(), nullable=False, server_default=""))
    op.add_column("validations", sa.Column("local_signer_kind", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("validations", "local_signer_kind")
    op.drop_column("validations", "local_signed_at")
    op.drop_column("validations", "local_signature")
    op.drop_column("validations", "local_public_key")
