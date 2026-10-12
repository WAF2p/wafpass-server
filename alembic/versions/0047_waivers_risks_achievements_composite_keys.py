"""waivers/risk_acceptances/project_achievements: composite natural keys

Completes the same ADR-003 composite-key fix migration 0046 applied to
project_passports, for the other tables this plan already knew carried
the identical gap:

- ``waivers.id`` / ``risk_acceptances.id`` — bare control-ids, globally
  unique at the DB layer rather than per-mandate, flagged since Phase 1
  ("Needs the same composite-key treatment already planned for
  project_passports. Flagged in both router files; will surface loudly
  as a 500... until fixed"). Likely to collide often in practice, since
  every mandate shares one global control catalogue (ADR-003's decision
  #2) — two mandates waiving the *same* control_id is the common case,
  not an edge case.
- ``project_achievements``'s ``UNIQUE (project, tier_level)`` constraint
  — found live, 2026-10-11, in the same incident as the
  project_passports crash this migration's sibling (0046) fixes: a
  second mandate's run reaching the same maturity tier for a same-named
  project collided on this constraint too, inside the same
  ``POST /runs`` request that had just fixed the passport collision.

waivers/risk_acceptances: ``PRIMARY KEY (id)`` -> ``(mandant_id, id)``
project_achievements: ``UNIQUE (project, tier_level)`` ->
``(mandant_id, project, tier_level)``

Same two-stage, ``instance_mode``-conditional pattern as 0045/0046, for
the same reason: the real DB-level constraint can only include
``mandant_id`` once it's ``NOT NULL`` for every row (a nullable column in
a ``PRIMARY KEY`` is rejected outright by Postgres; a nullable column in
a plain ``UNIQUE`` constraint is *allowed* but would silently stop
enforcing anything for existing NULL rows, since Postgres treats every
NULL as distinct from every other NULL in a uniqueness check) — so:

- An instance that hasn't activated yet: nothing to do here. The
  companion change to ``apply_multi_mandant_ddl()`` now does this same
  swap immediately after ``mandant_id`` becomes ``NOT NULL``, in the same
  activation transaction, for every *future* activation.
- An instance that's already activated: this migration does the swap
  directly, right now.

Revision ID: 0047
Revises: 0046
Create Date: 2026-10-11 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0047"
down_revision: Union[str, None] = "0046"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _current_instance_mode(bind) -> str | None:
    return bind.execute(sa.text("SELECT value FROM instance_settings WHERE key = 'instance_mode'")).scalar()


def upgrade() -> None:
    bind = op.get_bind()
    if _current_instance_mode(bind) == "multi_mandant":
        op.drop_constraint("waivers_pkey", "waivers", type_="primary")
        op.create_primary_key("waivers_pkey", "waivers", ["mandant_id", "id"])

        op.drop_constraint("risk_acceptances_pkey", "risk_acceptances", type_="primary")
        op.create_primary_key("risk_acceptances_pkey", "risk_acceptances", ["mandant_id", "id"])

        op.drop_constraint("uq_project_achievements_project_tier", "project_achievements", type_="unique")
        op.create_unique_constraint(
            "uq_project_achievements_project_tier", "project_achievements", ["mandant_id", "project", "tier_level"]
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _current_instance_mode(bind) == "multi_mandant":
        # True inverses, not guesses: if two mandates have genuinely
        # waived the same control, accepted risk on the same control, or
        # reached the same tier for a same-named project since this
        # migration ran (exactly what it exists to allow), these will
        # fail loudly with a real UniqueViolationError rather than
        # silently deleting or merging anyone's data — same fail-closed
        # philosophy as 0045's and 0046's own downgrades.
        op.drop_constraint("uq_project_achievements_project_tier", "project_achievements", type_="unique")
        op.create_unique_constraint(
            "uq_project_achievements_project_tier", "project_achievements", ["project", "tier_level"]
        )

        op.drop_constraint("risk_acceptances_pkey", "risk_acceptances", type_="primary")
        op.create_primary_key("risk_acceptances_pkey", "risk_acceptances", ["id"])

        op.drop_constraint("waivers_pkey", "waivers", type_="primary")
        op.create_primary_key("waivers_pkey", "waivers", ["id"])
