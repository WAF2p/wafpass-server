"""populate run_secret_findings from runs.secret_findings JSONB

Revision ID: 0031
Revises: 0030
Create Date: 2026-05-02 00:00:00.000000
"""
from __future__ import annotations

from typing import Any

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    # Fetch all runs with secret_findings
    runs_table = sa.table(
        "runs",
        sa.column("id", sa.Uuid()),
        sa.column("secret_findings", postgresql.JSONB()),
    )

    run_secret_findings_table = sa.table(
        "run_secret_findings",
        sa.column("id", sa.Uuid()),
        sa.column("run_id", sa.Uuid()),
        sa.column("file", sa.Text()),
        sa.column("line_no", sa.Integer()),
        sa.column("pattern_name", sa.Text()),
        sa.column("severity", sa.Text()),
        sa.column("matched_key", sa.Text()),
        sa.column("masked_value", sa.Text()),
        sa.column("suppressed", sa.Boolean()),
    )

    # Select runs that have secret_findings
    select_stmt = sa.select(runs_table.c.id, runs_table.c.secret_findings).where(
        runs_table.c.secret_findings != None,
        runs_table.c.secret_findings != [],
    )

    runs = conn.execute(select_stmt).fetchall()

    if runs:
        print(f"Found {len(runs)} runs with secret findings")

    for run_id, secret_findings in runs:
        if not secret_findings:
            continue

        # Insert each secret finding as a separate row
        for sf in secret_findings:
            conn.execute(
                run_secret_findings_table.insert().values(
                    id=sf.get("id") or sa.text("gen_random_uuid()"),
                    run_id=run_id,
                    file=sf.get("file", ""),
                    line_no=sf.get("line_no", 0),
                    pattern_name=sf.get("pattern_name", ""),
                    severity=sf.get("severity", ""),
                    matched_key=sf.get("matched_key", ""),
                    masked_value=sf.get("masked_value", ""),
                    suppressed=sf.get("suppressed", False),
                )
            )

        print(f"  Processed run {run_id}: {len(secret_findings)} secret findings")


def downgrade() -> None:
    # No downgrade needed - data migration
    pass
