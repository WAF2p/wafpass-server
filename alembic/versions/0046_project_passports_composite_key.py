"""project_passports: composite primary key (mandant_id, project)

Real production bug, found 2026-10-11: two mandates both auto-creating a
ProjectPassport row for the same bare project name collide on
``project_passports``'s original single-column primary key (``project``),
raising a raw ``UniqueViolationError`` straight through to a ``500`` on
ingest. This is the composite-key fix this plan's own "Key design
decisions" section (confirmed in ADR-003) already settled on — "keep
project as natural key and make uniqueness per-mandate via composite
(mandant_id, project), rather than introducing a UUID project key" — but
had never actually been implemented; carried in the Risks table as a
known, flagged, not-yet-fixed gap since Phase 1.

Same two-stage pattern as migration 0045 (for the identical underlying
reason): the real DB-level composite ``PRIMARY KEY`` can only exist once
``mandant_id`` is ``NOT NULL`` for every row, which is only true after
multi-mandant activation — Postgres does not allow a nullable column to
be part of a ``PRIMARY KEY`` at all, so:

- An instance that hasn't activated yet: nothing to do here. The
  companion change to ``apply_multi_mandant_ddl()`` (which already runs
  ``ALTER COLUMN mandant_id SET NOT NULL`` on this table) now also swaps
  the key immediately afterward, in the same activation transaction, for
  every *future* activation.
- An instance that's already activated (``mandant_id`` already ``NOT
  NULL`` — like the one that actually hit this bug): this migration does
  the swap directly, right now.

Revision ID: 0046
Revises: 0045
Create Date: 2026-10-11 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0046"
down_revision: Union[str, None] = "0045"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _current_instance_mode(bind) -> str | None:
    return bind.execute(sa.text("SELECT value FROM instance_settings WHERE key = 'instance_mode'")).scalar()


def upgrade() -> None:
    bind = op.get_bind()
    if _current_instance_mode(bind) == "multi_mandant":
        op.drop_constraint("project_passports_pkey", "project_passports", type_="primary")
        op.create_primary_key("project_passports_pkey", "project_passports", ["mandant_id", "project"])


def downgrade() -> None:
    bind = op.get_bind()
    if _current_instance_mode(bind) == "multi_mandant":
        # A true inverse — not a guess: if two mandates have genuinely
        # created same-named projects since this migration ran (exactly
        # the scenario this migration exists to allow), this will fail
        # loudly with a real UniqueViolationError rather than silently
        # deleting or merging anyone's data. That's the intended,
        # fail-closed behaviour, same philosophy as 0045's own downgrade.
        op.drop_constraint("project_passports_pkey", "project_passports", type_="primary")
        op.create_primary_key("project_passports_pkey", "project_passports", ["project"])
