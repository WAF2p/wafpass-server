"""convert expires / accepted_at from TEXT to DATE

Revision ID: 0022
Revises: 0021
Create Date: 2026-04-25 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None

# SQL helper: cast a TEXT column to DATE, mapping '' or whitespace-only to NULL
_CAST_TO_DATE = (
    "CASE WHEN trim({col}) = '' OR {col} IS NULL THEN NULL ELSE {col}::DATE END"
)


def upgrade() -> None:
    # ── waivers.expires ───────────────────────────────────────────────────────
    # Drop server default first — PostgreSQL refuses to retype a column when the
    # existing default value (empty string) can't be auto-cast to the target type.
    op.execute("ALTER TABLE waivers ALTER COLUMN expires DROP DEFAULT")
    op.execute(
        f"ALTER TABLE waivers "
        f"ALTER COLUMN expires TYPE DATE "
        f"USING {_CAST_TO_DATE.format(col='expires')}"
    )
    op.execute("ALTER TABLE waivers ALTER COLUMN expires DROP NOT NULL")

    # ── risk_acceptances.expires ──────────────────────────────────────────────
    op.execute("ALTER TABLE risk_acceptances ALTER COLUMN expires DROP DEFAULT")
    op.execute(
        f"ALTER TABLE risk_acceptances "
        f"ALTER COLUMN expires TYPE DATE "
        f"USING {_CAST_TO_DATE.format(col='expires')}"
    )
    op.execute("ALTER TABLE risk_acceptances ALTER COLUMN expires DROP NOT NULL")

    # ── risk_acceptances.accepted_at ──────────────────────────────────────────
    op.execute("ALTER TABLE risk_acceptances ALTER COLUMN accepted_at DROP DEFAULT")
    op.execute(
        f"ALTER TABLE risk_acceptances "
        f"ALTER COLUMN accepted_at TYPE DATE "
        f"USING {_CAST_TO_DATE.format(col='accepted_at')}"
    )
    op.execute("ALTER TABLE risk_acceptances ALTER COLUMN accepted_at DROP NOT NULL")

    # Partial indexes — enables efficient WHERE expires < now() queries
    op.create_index(
        "ix_waivers_expires",
        "waivers",
        ["expires"],
        postgresql_where=sa.text("expires IS NOT NULL"),
    )
    op.create_index(
        "ix_risk_acceptances_expires",
        "risk_acceptances",
        ["expires"],
        postgresql_where=sa.text("expires IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_risk_acceptances_expires", table_name="risk_acceptances")
    op.drop_index("ix_waivers_expires", table_name="waivers")

    op.execute(
        "ALTER TABLE risk_acceptances "
        "ALTER COLUMN accepted_at TYPE TEXT "
        "USING COALESCE(accepted_at::TEXT, '')"
    )
    op.execute("ALTER TABLE risk_acceptances ALTER COLUMN accepted_at SET NOT NULL")
    op.execute("ALTER TABLE risk_acceptances ALTER COLUMN accepted_at SET DEFAULT ''")

    op.execute(
        "ALTER TABLE risk_acceptances "
        "ALTER COLUMN expires TYPE TEXT "
        "USING COALESCE(expires::TEXT, '')"
    )
    op.execute("ALTER TABLE risk_acceptances ALTER COLUMN expires SET NOT NULL")
    op.execute("ALTER TABLE risk_acceptances ALTER COLUMN expires SET DEFAULT ''")

    op.execute(
        "ALTER TABLE waivers "
        "ALTER COLUMN expires TYPE TEXT "
        "USING COALESCE(expires::TEXT, '')"
    )
    op.execute("ALTER TABLE waivers ALTER COLUMN expires SET NOT NULL")
    op.execute("ALTER TABLE waivers ALTER COLUMN expires SET DEFAULT ''")
