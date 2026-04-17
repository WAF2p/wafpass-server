"""SQLAlchemy ORM models."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from wafpass_server.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    """Local user account.  SSO users will also have a row here (password_hash=NULL)."""
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(Text, default="")
    role: Mapped[str] = mapped_column(Text, nullable=False, default="clevel")
    auth_provider: Mapped[str] = mapped_column(Text, nullable=False, default="local")
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class RefreshToken(Base):
    """Hashed refresh token records — revoked on logout."""
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Control(Base):
    __tablename__ = "controls"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    pillar: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(Text, default="")
    type: Mapped[list] = mapped_column(JSONB, default=list)
    description: Mapped[str] = mapped_column(Text, default="")
    checks: Mapped[list] = mapped_column(JSONB, default=list)
    source: Mapped[str] = mapped_column(Text, default="wafpass")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Waiver(Base):
    __tablename__ = "waivers"

    id: Mapped[str] = mapped_column(Text, primary_key=True)  # control_id
    reason: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(Text, default="")
    expires: Mapped[str] = mapped_column(Text, default="")
    project: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class RiskAcceptance(Base):
    __tablename__ = "risk_acceptances"

    id: Mapped[str] = mapped_column(Text, primary_key=True)  # control_id or custom key
    reason: Mapped[str] = mapped_column(Text, default="")
    approver: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(Text, default="")
    rfc: Mapped[str] = mapped_column(Text, default="")
    jira_link: Mapped[str] = mapped_column(Text, default="")
    other_link: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    risk_level: Mapped[str] = mapped_column(Text, default="accepted")
    residual_risk: Mapped[str] = mapped_column(Text, default="medium")
    expires: Mapped[str] = mapped_column(Text, default="")
    accepted_at: Mapped[str] = mapped_column(Text, default="")
    project: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project: Mapped[str] = mapped_column(Text, default="")
    branch: Mapped[str] = mapped_column(Text, default="")
    git_sha: Mapped[str] = mapped_column(Text, default="")
    triggered_by: Mapped[str] = mapped_column(Text, default="local")
    iac_framework: Mapped[str] = mapped_column(Text, default="terraform")
    stage: Mapped[str] = mapped_column(Text, default="")
    score: Mapped[int] = mapped_column(Integer, default=0)
    pillar_scores: Mapped[dict] = mapped_column(JSONB, default=dict)
    findings: Mapped[list] = mapped_column(JSONB, default=list)
    path: Mapped[str] = mapped_column(Text, default="")
    controls_loaded: Mapped[int] = mapped_column(Integer, default=0)
    controls_run: Mapped[int] = mapped_column(Integer, default=0)
    detected_regions: Mapped[list] = mapped_column(JSONB, default=list)
    source_paths: Mapped[list] = mapped_column(JSONB, default=list)
    controls_meta: Mapped[list] = mapped_column(JSONB, default=list)
    secret_findings: Mapped[list] = mapped_column(JSONB, default=list)
    plan_changes: Mapped[dict | None] = mapped_column(JSONB, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
