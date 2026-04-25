"""extract run findings into a dedicated table for indexed filtering

Each finding that was stored as an element of runs.findings (JSONB array) gets
its own row in run_findings.  Expression indexes on lower(severity),
lower(pillar), and lower(status) make GET /runs/{id}/findings filters O(index)
instead of O(full JSONB load + Python scan).

The runs.findings JSONB column is preserved so that GET /runs/{id} (RunDetail)
continues to work without a JOIN.

Revision ID: 0023
Revises: 0022
Create Date: 2026-04-25 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "run_findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("run_id", UUID(as_uuid=True), nullable=False),
        sa.Column("check_id", sa.Text(), nullable=False, server_default=""),
        sa.Column("check_title", sa.Text(), nullable=False, server_default=""),
        sa.Column("control_id", sa.Text(), nullable=False, server_default=""),
        sa.Column("pillar", sa.Text(), nullable=False, server_default=""),
        sa.Column("severity", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.Text(), nullable=False, server_default=""),
        sa.Column("resource", sa.Text(), nullable=False, server_default=""),
        sa.Column("message", sa.Text(), nullable=False, server_default=""),
        sa.Column("remediation", sa.Text(), nullable=False, server_default=""),
        sa.Column("example", JSONB(), nullable=True),
    )

    # Baseline FK-style index on run_id (covers "give me all findings for run X")
    op.create_index("ix_run_findings_run_id", "run_findings", ["run_id"])

    # Expression indexes for case-insensitive filter columns.
    # These allow queries of the form:
    #   WHERE run_id = $1 AND lower(severity) = 'critical'
    # to be answered from the index without a seq-scan.
    op.execute(
        "CREATE INDEX ix_run_findings_sev ON run_findings (run_id, lower(severity))"
    )
    op.execute(
        "CREATE INDEX ix_run_findings_pil ON run_findings (run_id, lower(pillar))"
    )
    op.execute(
        "CREATE INDEX ix_run_findings_sts ON run_findings (run_id, lower(status))"
    )

    # Migrate existing data from runs.findings JSONB → run_findings rows.
    # Runs with an empty or NULL findings array are skipped.
    op.execute(
        """
        INSERT INTO run_findings
               (id, run_id, check_id, check_title, control_id, pillar,
                severity, status, resource, message, remediation, example)
        SELECT gen_random_uuid(),
               r.id,
               coalesce(elem->>'check_id', ''),
               coalesce(elem->>'check_title', ''),
               coalesce(elem->>'control_id', ''),
               coalesce(elem->>'pillar', ''),
               coalesce(elem->>'severity', ''),
               coalesce(elem->>'status', ''),
               coalesce(elem->>'resource', ''),
               coalesce(elem->>'message', ''),
               coalesce(elem->>'remediation', ''),
               elem->'example'
        FROM   runs r,
               jsonb_array_elements(r.findings) AS elem
        WHERE  r.findings IS NOT NULL
          AND  r.findings <> '[]'::jsonb
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_run_findings_sts")
    op.execute("DROP INDEX IF EXISTS ix_run_findings_pil")
    op.execute("DROP INDEX IF EXISTS ix_run_findings_sev")
    op.drop_index("ix_run_findings_run_id", table_name="run_findings")
    op.drop_table("run_findings")
