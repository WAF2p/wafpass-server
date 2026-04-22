"""add image_url to project_passports

Revision ID: 0017
Revises: 0016
Create Date: 2026-04-22 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("project_passports", sa.Column("image_url", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("project_passports", "image_url")
