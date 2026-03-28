"""add run metadata columns

Revision ID: 0002
Revises: 0001
Create Date: 2026-01-02 00:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("runs", sa.Column("path", sa.Text(), nullable=False, server_default=""))
    op.add_column("runs", sa.Column("controls_loaded", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("runs", sa.Column("controls_run", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("runs", sa.Column("detected_regions", postgresql.JSONB(), nullable=False, server_default="[]"))
    op.add_column("runs", sa.Column("source_paths", postgresql.JSONB(), nullable=False, server_default="[]"))


def downgrade() -> None:
    op.drop_column("runs", "source_paths")
    op.drop_column("runs", "detected_regions")
    op.drop_column("runs", "controls_run")
    op.drop_column("runs", "controls_loaded")
    op.drop_column("runs", "path")
