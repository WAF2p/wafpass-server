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
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class UserAuditLog(Base):
    """One row per auditable action performed by (or on) a user account."""
    __tablename__ = "user_audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # actor_id: the user who performed the action (NULL if the account was deleted)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    action: Mapped[str] = mapped_column(Text, nullable=False)     # "login" | "logout" | "run.push" | etc.
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)     # action-specific context
    ip: Mapped[str] = mapped_column(Text, default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


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


class ApiKeyUsageLog(Base):
    """One row per API-key-authenticated ingest request (POST /runs or POST /scan)."""
    __tablename__ = "api_key_usage_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    api_key_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)          # "POST /runs" | "POST /scan"
    run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    project: Mapped[str] = mapped_column(Text, default="")
    branch: Mapped[str] = mapped_column(Text, default="")
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ip: Mapped[str] = mapped_column(Text, default="")


class ApiKey(Base):
    """DB-stored API key for CI/CD pipelines and service accounts."""
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    key_prefix: Mapped[str] = mapped_column(Text, nullable=False)   # first 12 chars (display only)
    key_hash: Mapped[str] = mapped_column(Text, unique=True, nullable=False)  # SHA256 of raw key
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class GroupRoleMapping(Base):
    """Maps an IdP group/claim value to a WAF++ role.

    Evaluated during SSO login before the per-provider role_mapping in SsoConfig.
    provider = "*" matches any SSO provider.
    Higher priority = evaluated first; first match wins.
    """
    __tablename__ = "group_role_mappings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    provider: Mapped[str] = mapped_column(Text, nullable=False, default="*")  # "oidc" | "saml2" | "*"
    group_name: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)


class SsoConfig(Base):
    """SSO provider configuration (one row per provider: 'oidc' or 'saml2')."""
    __tablename__ = "sso_configs"

    id: Mapped[str] = mapped_column(Text, primary_key=True)  # "oidc" | "saml2"
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)


class Evidence(Base):
    """Locked, immutable evidence package — snapshot of a run at a point in time."""
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    title: Mapped[str] = mapped_column(Text, default="")
    note: Mapped[str] = mapped_column(Text, default="")
    project: Mapped[str] = mapped_column(Text, default="")
    prepared_by: Mapped[str] = mapped_column(Text, default="")
    organization: Mapped[str] = mapped_column(Text, default="")
    audit_period: Mapped[str] = mapped_column(Text, default="")
    frameworks: Mapped[list] = mapped_column(JSONB, default=list)
    snapshot: Mapped[dict] = mapped_column(JSONB, default=dict)  # full frozen run+findings+waivers+risks
    report_html: Mapped[str | None] = mapped_column(Text, nullable=True)  # pre-rendered HTML blob
    hash_digest: Mapped[str] = mapped_column(Text, default="")  # SHA256 of canonical snapshot JSON
    public_token: Mapped[str] = mapped_column(Text, unique=True, nullable=False)  # unauthenticated access
    locked_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


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
