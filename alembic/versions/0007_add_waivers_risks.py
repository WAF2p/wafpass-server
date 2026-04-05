"""add waivers and risk_acceptances tables

Revision ID: 0007
Revises: 0006
Create Date: 2026-04-05 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "waivers",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("owner", sa.Text(), nullable=False, server_default=""),
        sa.Column("expires", sa.Text(), nullable=False, server_default=""),
        sa.Column("project", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "risk_acceptances",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("approver", sa.Text(), nullable=False, server_default=""),
        sa.Column("owner", sa.Text(), nullable=False, server_default=""),
        sa.Column("rfc", sa.Text(), nullable=False, server_default=""),
        sa.Column("jira_link", sa.Text(), nullable=False, server_default=""),
        sa.Column("other_link", sa.Text(), nullable=False, server_default=""),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("risk_level", sa.Text(), nullable=False, server_default="accepted"),
        sa.Column("residual_risk", sa.Text(), nullable=False, server_default="medium"),
        sa.Column("expires", sa.Text(), nullable=False, server_default=""),
        sa.Column("accepted_at", sa.Text(), nullable=False, server_default=""),
        sa.Column("project", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("risk_acceptances")
    op.drop_table("waivers")
