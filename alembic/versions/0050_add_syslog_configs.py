"""add syslog_configs singleton table

Instance-wide syslog/SIEM forwarding configuration, editable from the
Admin Audit Log UI. One row (id=1) controls host, port, protocol, format,
facility, TLS, program tag, and per-action severity overrides.

Revision ID: 0050
Revises: 0049
Create Date: 2026-10-13 00:00:00.000000
"""
from __future__ import annotations

import os
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0050"
down_revision: Union[str, None] = "0049"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _env_or_default(name: str, default, cast=None):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    if cast is bool:
        return raw.lower() in ("true", "1", "yes", "on")
    if cast is int:
        try:
            return int(raw)
        except ValueError:
            return default
    return raw


def upgrade() -> None:
    op.create_table(
        "syslog_configs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("host", sa.Text(), nullable=False, server_default=""),
        sa.Column("port", sa.Integer(), nullable=False, server_default="514"),
        sa.Column("protocol", sa.Text(), nullable=False, server_default="udp"),
        sa.Column("format", sa.Text(), nullable=False, server_default="rfc5424"),
        sa.Column("facility", sa.Integer(), nullable=False, server_default="13"),
        sa.Column("tls_enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("program_tag", sa.Text(), nullable=False, server_default="wafpass-admin"),
        sa.Column("severity_overrides", JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # Seed the singleton row from legacy environment variables, if present.
    enabled = _env_or_default("WAFPASS_SYSLOG_ENABLED", False, bool)
    host = _env_or_default("WAFPASS_SYSLOG_HOST", "")
    port = _env_or_default("WAFPASS_SYSLOG_PORT", 514, int)
    protocol = _env_or_default("WAFPASS_SYSLOG_PROTOCOL", "udp")
    fmt = _env_or_default("WAFPASS_SYSLOG_FORMAT", "rfc5424")
    facility = _env_or_default("WAFPASS_SYSLOG_FACILITY", 13, int)

    op.execute(
        sa.text(
            "INSERT INTO syslog_configs (id, enabled, host, port, protocol, format, facility, tls_enabled, program_tag, severity_overrides) "
            "VALUES (1, :enabled, :host, :port, :protocol, :format, :facility, false, 'wafpass-admin', '{}')"
        ).bindparams(
            enabled=enabled,
            host=host,
            port=port,
            protocol=protocol,
            format=fmt,
            facility=facility,
        )
    )


def downgrade() -> None:
    op.drop_table("syslog_configs")
