"""add mandant hierarchy and governance fields

Phase 6a of the multi-mandant feature — see .plan.md's "Phase 6 —
Multi-Mandate Hierarchy & Enterprise Group UI" and
decisions/adrs/ADR-003-multi-mandant-tenancy.md.

Purely additive to ``mandants``: every new column is nullable or defaulted,
no existing row needs backfilling, and no RLS policy changes at all.
``parent_id`` is organizational/display metadata only in this revision — it
does not grant a parent's admin visibility into a child's data, or vice
versa. That access-control extension (if ever built) is Phase 6b, a
separate, not-yet-decided RLS redesign — see .plan.md's Risks table for why
it isn't built here.

Revision ID: 0044
Revises: 0043
Create Date: 2026-10-10 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0044"
down_revision: Union[str, None] = "0043"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("mandants", sa.Column("parent_id", UUID(as_uuid=True), nullable=True))
    op.add_column("mandants", sa.Column("mandate_type", sa.Text(), nullable=False, server_default="subsidiary"))
    op.add_column("mandants", sa.Column("jurisdiction", sa.Text(), nullable=True))
    op.add_column("mandants", sa.Column("risk_tier", sa.Text(), nullable=True))
    op.add_column("mandants", sa.Column("data_residency", sa.Text(), nullable=True))
    op.add_column(
        "mandants", sa.Column("inherit_parent_policies", sa.Boolean(), nullable=False, server_default="true")
    )
    op.create_foreign_key(
        "fk_mandants_parent_id", "mandants", "mandants", ["parent_id"], ["id"], ondelete="SET NULL"
    )
    op.create_index("ix_mandants_parent_id", "mandants", ["parent_id"])


def downgrade() -> None:
    op.drop_index("ix_mandants_parent_id", table_name="mandants")
    op.drop_constraint("fk_mandants_parent_id", "mandants", type_="foreignkey")
    op.drop_column("mandants", "inherit_parent_policies")
    op.drop_column("mandants", "data_residency")
    op.drop_column("mandants", "risk_tier")
    op.drop_column("mandants", "jurisdiction")
    op.drop_column("mandants", "mandate_type")
    op.drop_column("mandants", "parent_id")
