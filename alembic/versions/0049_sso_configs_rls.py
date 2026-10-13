"""sso_configs: row-level security for default + per-mandant rows (ADR-005)

Post-Phase-7 follow-up: ``sso_configs`` was left out of the tenant
isolation policy when multi-mandant activation was introduced. It stores
both instance-wide default rows (``mandant_id IS NULL``) and per-mandant
overrides (``mandant_id`` set), so it needs its own RLS policy with a
special read carve-out for the default rows when an unauthenticated public
SSO endpoint needs to read them.

This migration:

1. Enables and forces RLS on ``sso_configs``.
2. Creates the ``sso_configs_tenant_isolation`` policy that allows:
   - the usual mandate match / holding / group-scoped branches,
   - plus reading default rows when ``app.allow_default_sso`` is true.
3. Leaves ``mandant_id`` nullable so the default rows can continue to
   exist.

Skipped entirely for instances that have not yet activated multi-mandant
mode — the activation DDL in ``activate_multi_mandant_ddl.py`` already
contains this policy shape going forward.

Revision ID: 0049
Revises: 0048
Create Date: 2026-10-11 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0049"
down_revision: Union[str, None] = "0048"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Snapshot of the relevant parts of activate_multi_mandant_ddl.py as of
# this revision, including the ADR-005 sso_configs default-row branch.
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


def _sso_policy_sql() -> str:
    using_clauses = [
        "mandant_id::text = current_setting('app.current_mandant_id', true)",
        "current_setting('app.is_holding_admin', true) = 'true'",
        "current_setting('app.is_holding_viewer', true) = 'true'",
        _GROUP_USING_BRANCH,
        "(mandant_id IS NULL AND current_setting('app.allow_default_sso', true) = 'true')",
    ]
    check_clauses = [
        "mandant_id::text = current_setting('app.current_mandant_id', true)",
        "current_setting('app.is_holding_admin', true) = 'true'",
        _GROUP_CHECK_BRANCH,
    ]
    using_sql = "\n        OR ".join(using_clauses)
    check_sql = "\n        OR ".join(check_clauses)
    return (
        'CREATE POLICY sso_configs_tenant_isolation ON "sso_configs"\n'
        f"    USING (\n        {using_sql}\n    )\n"
        f"    WITH CHECK (\n        {check_sql}\n    );"
    )


def _current_instance_mode(bind) -> str | None:
    return bind.execute(sa.text("SELECT value FROM instance_settings WHERE key = 'instance_mode'")).scalar()


def upgrade() -> None:
    bind = op.get_bind()
    if _current_instance_mode(bind) != "multi_mandant":
        return

    bind.execute(sa.text('ALTER TABLE "sso_configs" ENABLE ROW LEVEL SECURITY'))
    bind.execute(sa.text('ALTER TABLE "sso_configs" FORCE ROW LEVEL SECURITY'))
    bind.execute(sa.text('DROP POLICY IF EXISTS sso_configs_tenant_isolation ON "sso_configs"'))
    bind.execute(sa.text(_sso_policy_sql()))


def downgrade() -> None:
    bind = op.get_bind()
    if _current_instance_mode(bind) != "multi_mandant":
        return

    bind.execute(sa.text('DROP POLICY IF EXISTS sso_configs_tenant_isolation ON "sso_configs"'))
    bind.execute(sa.text('ALTER TABLE "sso_configs" NO FORCE ROW LEVEL SECURITY'))
    bind.execute(sa.text('ALTER TABLE "sso_configs" DISABLE ROW LEVEL SECURITY'))
