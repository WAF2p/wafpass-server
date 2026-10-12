"""sso_configs: optional per-mandant scope (ADR-005)

Adds a nullable ``mandant_id`` plus an explicit ``provider`` column to
``sso_configs``, so each provider type ("oidc" | "saml2") can have exactly
one instance-wide default configuration (``mandant_id IS NULL`` — today's
only row shape, unchanged) and any number of per-mandant override
configurations (``mandant_id`` set).

Backward compatible by construction: existing rows keep their existing
``id`` ("oidc" / "saml2") and get ``mandant_id = NULL`` — they become the
instance-wide default explicitly instead of implicitly. ``provider`` is
backfilled from ``id`` (today ``id`` *is* the provider for every row that
has ever existed). A new per-mandant override row gets a synthetic
``id`` of ``f"{provider}:{mandant_id}"`` (same "plain text primary key,
app-enforced convention" style already used for ``instance_settings.key``)
— see ``wafpass_server/routers/sso.py``'s ``_cfg_row_id()``.

Two partial unique indexes replace what the bare ``id`` primary key used
to enforce implicitly:

- ``ux_sso_configs_default``: at most one row per ``provider`` with
  ``mandant_id IS NULL``.
- ``ux_sso_configs_per_mandant``: at most one row per
  ``(provider, mandant_id)`` once ``mandant_id`` is set.

See decisions/adrs/ADR-005-per-mandant-sso-config.md.

Revision ID: 0048
Revises: 0047
Create Date: 2026-10-11 00:00:00.000000
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0048"
down_revision: Union[str, None] = "0047"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("sso_configs", sa.Column("provider", sa.Text(), nullable=True))
    op.add_column(
        "sso_configs",
        sa.Column("mandant_id", UUID(as_uuid=True), sa.ForeignKey("mandants.id", ondelete="CASCADE"), nullable=True),
    )
    op.execute("UPDATE sso_configs SET provider = id WHERE provider IS NULL")
    op.alter_column("sso_configs", "provider", nullable=False)

    op.create_index(
        "ux_sso_configs_default", "sso_configs", ["provider"],
        unique=True, postgresql_where=sa.text("mandant_id IS NULL"),
    )
    op.create_index(
        "ux_sso_configs_per_mandant", "sso_configs", ["provider", "mandant_id"],
        unique=True, postgresql_where=sa.text("mandant_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ux_sso_configs_per_mandant", table_name="sso_configs")
    op.drop_index("ux_sso_configs_default", table_name="sso_configs")
    # A true inverse would need every per-mandant override row deleted
    # first — dropping the column with overrides still present would
    # silently discard which mandate each one belonged to. Fail loudly
    # instead, same philosophy as 0045/0046's downgrades.
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM sso_configs WHERE mandant_id IS NOT NULL) THEN "
        "RAISE EXCEPTION 'Cannot downgrade: per-mandant sso_configs overrides exist. Delete them first.'; "
        "END IF; END $$;"
    )
    op.drop_column("sso_configs", "mandant_id")
    op.drop_column("sso_configs", "provider")
