"""add mandant_ancestry closure table and group_admin/group_viewer RLS support

Phase 6b of the multi-mandant feature — see .plan.md's "Phase 6b —
Hierarchy-aware row-level security" and
decisions/adrs/ADR-004-hierarchy-aware-rls.md (accepted 2026-10-11).

Two independent things happen here:

1. Create ``mandant_ancestry`` (ancestor_id, descendant_id, depth) — a
   closure table over ``mandants.parent_id``, including a depth-0
   self-row for every mandant (ancestor_id == descendant_id), so a plain
   ``SELECT descendant_id FROM mandant_ancestry WHERE ancestor_id = X``
   already includes X itself — both the RLS policy below and
   ``admin.py``'s rollup endpoint rely on that. Backfilled once, here,
   from today's ``parent_id`` data. Kept in sync going forward by
   application code (``wafpass_server.mandant_ancestry.
   recompute_mandant_ancestry()``, called from ``admin.py``'s create/
   update mandant handlers) rather than a database trigger — ADR-004's
   "Migration" section offers this explicitly as an alternative to a
   trigger, and this codebase has zero Postgres triggers anywhere else.

2. Extend every tenant table's RLS policy with the group_admin/
   group_viewer OR-branch from ADR-004. This is *not* a no-op for a
   brand-new, not-yet-activated instance (that case is already covered
   by this revision's companion change to ``_policy_sql()`` in
   ``activate_multi_mandant_ddl.py``, which Phase 2's activation uses
   going forward) — it exists for an instance that activated *before*
   this revision shipped, whose policies were created with the *old* SQL
   and need to be re-created, not just newly defined. Guarded on
   ``instance_mode == 'multi_mandant'``: skipped entirely for an instance
   that hasn't activated yet, since ``ENABLE ROW LEVEL SECURITY``/the
   policies themselves don't exist yet for it to touch.

   The policy SQL below is a deliberate, literal snapshot of
   ``activate_multi_mandant_ddl.py``'s shape as of this revision —
   Alembic migrations in this codebase are self-contained (see 0043's
   own ``_TENANT_TABLES`` list, duplicated rather than imported), so this
   does not import application code.

Revision ID: 0045
Revises: 0044
Create Date: 2026-10-11 00:00:00.000000
"""
from __future__ import annotations

import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0045"
down_revision: Union[str, None] = "0044"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of activate_multi_mandant_ddl.ALL_TENANT_TABLES /
# _SELF_LOOKUP_TENANT_TABLES as of this revision (2026-10-11) — see this
# migration's own docstring for why it's duplicated, not imported.
_GENERIC_TENANT_TABLES = [
    "project_passports",
    "runs",
    "run_findings",
    "run_secret_findings",
    "waivers",
    "risk_acceptances",
    "project_groups",
    "notifications",
    "user_audit_logs",
    "compliance_audit_events",
    "findings_comments",
    "secret_findings_comments",
]
_SELF_LOOKUP_TENANT_TABLES: dict[str, list[str]] = {
    "users": [
        "id::text = current_setting('app.current_user_id', true)",
        "username = current_setting('app.login_username', true)",
    ],
    "api_keys": ["key_hash = current_setting('app.current_api_key_hash', true)"],
    "evidence": ["public_token = current_setting('app.public_lookup_token', true)"],
    "widgets": ["token = current_setting('app.public_lookup_token', true)"],
    "validations": ["validation_id = current_setting('app.public_lookup_token', true)"],
    "project_achievements": ["verification_token = current_setting('app.public_lookup_token', true)"],
}
_ALL_TENANT_TABLES = [*_GENERIC_TENANT_TABLES, *_SELF_LOOKUP_TENANT_TABLES.keys()]

_GROUP_USING_BRANCH = (
    "(current_setting('app.is_group_admin', true) = 'true' "
    "OR current_setting('app.is_group_viewer', true) = 'true') "
    "AND mandant_id IN (SELECT descendant_id FROM mandant_ancestry "
    "WHERE ancestor_id::text = current_setting('app.current_mandant_id', true))"
)
_GROUP_CHECK_BRANCH = (
    "current_setting('app.is_group_admin', true) = 'true' "
    "AND mandant_id IN (SELECT descendant_id FROM mandant_ancestry "
    "WHERE ancestor_id::text = current_setting('app.current_mandant_id', true))"
)


def _new_policy_sql(table: str) -> str:
    using_clauses = [
        "mandant_id::text = current_setting('app.current_mandant_id', true)",
        "current_setting('app.is_holding_admin', true) = 'true'",
        "current_setting('app.is_holding_viewer', true) = 'true'",
        _GROUP_USING_BRANCH,
    ]
    using_clauses.extend(_SELF_LOOKUP_TENANT_TABLES.get(table, []))
    check_clauses = [
        "mandant_id::text = current_setting('app.current_mandant_id', true)",
        "current_setting('app.is_holding_admin', true) = 'true'",
        _GROUP_CHECK_BRANCH,
    ]
    using_sql = "\n        OR ".join(using_clauses)
    check_sql = "\n        OR ".join(check_clauses)
    return (
        f'CREATE POLICY {table}_tenant_isolation ON "{table}"\n'
        f"    USING (\n        {using_sql}\n    )\n"
        f"    WITH CHECK (\n        {check_sql}\n    );"
    )


def _old_policy_sql(table: str) -> str:
    """The pre-6b shape (0044 and earlier) — used by downgrade() to put
    an already-activated instance's policies back exactly as they were."""
    using_clauses = [
        "mandant_id::text = current_setting('app.current_mandant_id', true)",
        "current_setting('app.is_holding_admin', true) = 'true'",
        "current_setting('app.is_holding_viewer', true) = 'true'",
    ]
    using_clauses.extend(_SELF_LOOKUP_TENANT_TABLES.get(table, []))
    check_clauses = [
        "mandant_id::text = current_setting('app.current_mandant_id', true)",
        "current_setting('app.is_holding_admin', true) = 'true'",
    ]
    using_sql = "\n        OR ".join(using_clauses)
    check_sql = "\n        OR ".join(check_clauses)
    return (
        f'CREATE POLICY {table}_tenant_isolation ON "{table}"\n'
        f"    USING (\n        {using_sql}\n    )\n"
        f"    WITH CHECK (\n        {check_sql}\n    );"
    )


def _current_instance_mode(bind) -> str | None:
    return bind.execute(sa.text("SELECT value FROM instance_settings WHERE key = 'instance_mode'")).scalar()


def upgrade() -> None:
    # ── 1. mandant_ancestry closure table ───────────────────────────────────
    op.create_table(
        "mandant_ancestry",
        sa.Column("ancestor_id", UUID(as_uuid=True), nullable=False),
        sa.Column("descendant_id", UUID(as_uuid=True), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("ancestor_id", "descendant_id", name="pk_mandant_ancestry"),
    )
    op.create_foreign_key(
        "fk_mandant_ancestry_ancestor_id", "mandant_ancestry", "mandants",
        ["ancestor_id"], ["id"], ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_mandant_ancestry_descendant_id", "mandant_ancestry", "mandants",
        ["descendant_id"], ["id"], ondelete="CASCADE",
    )
    op.create_index("ix_mandant_ancestry_ancestor", "mandant_ancestry", ["ancestor_id"])

    # ── 2. one-time backfill from today's parent_id data ────────────────────
    # Small mandate counts expected (ADR-004: "tens, not millions") — a
    # plain Python walk, same reasoning admin.py's _would_create_cycle()
    # already uses against this exact column, not a recursive SQL query.
    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id, parent_id FROM mandants")).fetchall()
    parent_of: dict[uuid.UUID, uuid.UUID | None] = {r.id: r.parent_id for r in rows}
    ancestry_rows: list[dict] = []
    for mandant_id in parent_of:
        ancestry_rows.append({"ancestor_id": mandant_id, "descendant_id": mandant_id, "depth": 0})
        depth = 1
        current = parent_of.get(mandant_id)
        seen: set[uuid.UUID] = set()
        while current is not None and current not in seen:
            ancestry_rows.append({"ancestor_id": current, "descendant_id": mandant_id, "depth": depth})
            seen.add(current)
            current = parent_of.get(current)
            depth += 1
    if ancestry_rows:
        op.bulk_insert(
            sa.table(
                "mandant_ancestry",
                sa.column("ancestor_id", UUID(as_uuid=True)),
                sa.column("descendant_id", UUID(as_uuid=True)),
                sa.column("depth", sa.Integer()),
            ),
            ancestry_rows,
        )

    # ── 3. re-create RLS policies for an *already-activated* instance ──────
    # A brand-new instance that hasn't activated yet has no policies to
    # touch — covered instead by this revision's companion change to
    # activate_multi_mandant_ddl._policy_sql() for the *next* activation.
    if _current_instance_mode(bind) == "multi_mandant":
        for table in _ALL_TENANT_TABLES:
            bind.execute(sa.text(f'DROP POLICY {table}_tenant_isolation ON "{table}"'))
            bind.execute(sa.text(_new_policy_sql(table)))


def downgrade() -> None:
    bind = op.get_bind()
    if _current_instance_mode(bind) == "multi_mandant":
        for table in _ALL_TENANT_TABLES:
            bind.execute(sa.text(f'DROP POLICY {table}_tenant_isolation ON "{table}"'))
            bind.execute(sa.text(_old_policy_sql(table)))

    op.drop_index("ix_mandant_ancestry_ancestor", table_name="mandant_ancestry")
    op.drop_constraint("fk_mandant_ancestry_descendant_id", "mandant_ancestry", type_="foreignkey")
    op.drop_constraint("fk_mandant_ancestry_ancestor_id", "mandant_ancestry", type_="foreignkey")
    op.drop_table("mandant_ancestry")
