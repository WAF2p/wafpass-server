"""add mandants, instance_settings, and nullable mandant_id columns

Phase 0 of the multi-mandant (mandantization) feature — see
decisions/adrs/ADR-003-multi-mandant-tenancy.md and .plan.md.

This revision is purely additive and backwards-compatible: every new column
is nullable, the new ``instance_settings`` row seeds to "single_tenant", and
no existing query behaviour changes. The DDL that actually enforces
isolation (``NOT NULL`` + RLS policies) is intentionally *not* a further
Alembic revision — it lives as a plain, state-gated Python function
(``wafpass_server/db_migrations/activate_multi_mandant_ddl.py``) invoked
only by the one-way admin activation endpoint (Phase 2). That keeps a
routine ``alembic upgrade head`` from ever being able to trigger it, and
keeps this migration chain a single, uneventful line.

Revision ID: 0043
Revises: 0042
Create Date: 2026-10-09 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "0043"
down_revision: Union[str, None] = "0042"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Every tenant-scoped table that gets a nullable mandant_id column here.
# `users` is handled separately below (it also gets holding_role).
# Keep this in sync with decisions/adrs/ADR-003-multi-mandant-tenancy.md.
_TENANT_TABLES = [
    "project_passports",
    "runs",
    "run_findings",
    "run_secret_findings",
    "waivers",
    "risk_acceptances",
    "api_keys",
    "evidence",
    "project_achievements",
    "validations",
    "project_groups",
    "widgets",
    "notifications",
    "user_audit_logs",
    "compliance_audit_events",
    "findings_comments",
    "secret_findings_comments",
]


def upgrade() -> None:
    # ── mandants ────────────────────────────────────────────────────────────
    op.create_table(
        "mandants",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("slug", sa.Text(), nullable=False),
        sa.Column("logo_url", sa.Text(), nullable=False, server_default=""),
        sa.Column("settings", JSONB(), nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("slug", name="uq_mandants_slug"),
    )

    # ── instance_settings ───────────────────────────────────────────────────
    op.create_table(
        "instance_settings",
        sa.Column("key", sa.Text(), primary_key=True),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("changed_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.func.now()),
        sa.Column("changed_by_user_id", UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_instance_settings_changed_by_user_id", "instance_settings", "users",
        ["changed_by_user_id"], ["id"], ondelete="SET NULL",
    )

    # Seed the single-tenant default. No admin action "changed" this row yet,
    # so changed_by_user_id stays NULL; existing logic must keep ignoring
    # mandant_id entirely while this reads "single_tenant".
    op.execute(
        "INSERT INTO instance_settings (key, value, changed_at, changed_by_user_id) "
        "VALUES ('instance_mode', 'single_tenant', now(), NULL)"
    )

    # ── users: mandant_id + holding_role ────────────────────────────────────
    op.add_column("users", sa.Column("mandant_id", UUID(as_uuid=True), nullable=True))
    op.add_column("users", sa.Column("holding_role", sa.Text(), nullable=True))
    op.create_foreign_key(
        "fk_users_mandant_id", "users", "mandants", ["mandant_id"], ["id"],
    )
    op.create_index("ix_users_mandant_id", "users", ["mandant_id"])

    # ── every other tenant-scoped table: nullable mandant_id + FK + index ──
    for table in _TENANT_TABLES:
        op.add_column(table, sa.Column("mandant_id", UUID(as_uuid=True), nullable=True))
        op.create_foreign_key(
            f"fk_{table}_mandant_id", table, "mandants", ["mandant_id"], ["id"],
        )
        op.create_index(f"ix_{table}_mandant_id", table, ["mandant_id"])


def downgrade() -> None:
    for table in reversed(_TENANT_TABLES):
        op.drop_index(f"ix_{table}_mandant_id", table_name=table)
        op.drop_constraint(f"fk_{table}_mandant_id", table, type_="foreignkey")
        op.drop_column(table, "mandant_id")

    op.drop_index("ix_users_mandant_id", table_name="users")
    op.drop_constraint("fk_users_mandant_id", "users", type_="foreignkey")
    op.drop_column("users", "holding_role")
    op.drop_column("users", "mandant_id")

    op.drop_constraint("fk_instance_settings_changed_by_user_id", "instance_settings", type_="foreignkey")
    op.drop_table("instance_settings")
    op.drop_table("mandants")
