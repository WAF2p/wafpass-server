"""add compliance_audit_events table

Revision ID: 0019
Revises: 0018
Create Date: 2026-04-24 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "compliance_audit_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("client_id", sa.Text(), nullable=False, server_default=""),
        sa.Column("actor", sa.Text(), nullable=False, server_default=""),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("subject_id", sa.Text(), nullable=False, server_default=""),
        sa.Column("subject_type", sa.Text(), nullable=False, server_default=""),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("before", JSONB(), nullable=True),
        sa.Column("after", JSONB(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", UUID(as_uuid=True), nullable=True),
    )
    op.create_index("ix_compliance_audit_events_client_id", "compliance_audit_events", ["client_id"])
    op.create_index("ix_compliance_audit_events_timestamp", "compliance_audit_events", ["timestamp"])


def downgrade() -> None:
    op.drop_table("compliance_audit_events")
