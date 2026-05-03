"""add image_url to users

Revision ID: 0029
Revises: 0028
Create Date: 2026-05-02 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("image_url", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("users", "image_url")
