"""add_is_cicd_to_runs

Revision ID: 8da9c90184ce
Revises: 0035
Create Date: 2026-06-05 11:08:21.557839

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '8da9c90184ce'
down_revision: Union[str, None] = '0035'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('runs', sa.Column('run_metadata', sa.JSON(), nullable=False, server_default='{}'))


def downgrade() -> None:
    op.drop_column('runs', 'run_metadata')
