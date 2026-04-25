"""SQLAlchemy ORM models."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import Boolean, Date, DateTime, Integer, Text
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
    """Hashed refresh token records — rotated on every /auth/refresh call.

    All tokens in a rotation chain share the same ``family_id``.  Presenting a
    revoked token from a known family triggers family-wide revocation (stolen
    token detection).
    """
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    family_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, default=uuid.uuid4)
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
    expires: Mapped[date | None] = mapped_column(Date, nullable=True, default=None)
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
    expires: Mapped[date | None] = mapped_column(Date, nullable=True, default=None)
    accepted_at: Mapped[date | None] = mapped_column(Date, nullable=True, default=None)
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


class ProjectPassport(Base):
    """Per-project metadata record — editable by admin and architect only."""
    __tablename__ = "project_passports"

    project: Mapped[str] = mapped_column(Text, primary_key=True)
    display_name: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(Text, default="")
    owner_team: Mapped[str] = mapped_column(Text, default="")
    contact_email: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    criticality: Mapped[str] = mapped_column(Text, default="")      # critical|high|medium|low
    environment: Mapped[str] = mapped_column(Text, default="")       # production|staging|development|mixed
    cloud_provider: Mapped[str] = mapped_column(Text, default="")    # aws|azure|gcp|multi|other
    repository_url: Mapped[str] = mapped_column(Text, default="")
    documentation_url: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")
    image_url: Mapped[str] = mapped_column(Text, default="")
    updated_by: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class ProjectAchievement(Base):
    """Verified maturity achievement — a project reaching a tier milestone for the first time."""
    __tablename__ = "project_achievements"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    tier_level: Mapped[int] = mapped_column(Integer, nullable=False)         # 1–5
    tier_label: Mapped[str] = mapped_column(Text, nullable=False)            # Foundational|…|Excellence
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)   # score at achievement time
    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    verification_token: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    snapshot_jsonb: Mapped[dict] = mapped_column(JSONB, default=dict)        # pillar_scores snapshot
    achieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ComplianceAuditEvent(Base):
    """One row per compliance audit event emitted by the dashboard (waiver/risk/scan/finding)."""
    __tablename__ = "compliance_audit_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id: Mapped[str] = mapped_column(Text, default="", index=True)  # dashboard-local id (for dedup)
    actor: Mapped[str] = mapped_column(Text, nullable=False, default="")
    category: Mapped[str] = mapped_column(Text, nullable=False)            # waiver|risk|scan|finding
    action: Mapped[str] = mapped_column(Text, nullable=False)              # waiver_created|scan_received|etc.
    subject_id: Mapped[str] = mapped_column(Text, default="")
    subject_type: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    before: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    after: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)


class RunFinding(Base):
    """One row per finding — normalised out of runs.findings for indexed filtering."""
    __tablename__ = "run_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    check_id: Mapped[str] = mapped_column(Text, default="")
    check_title: Mapped[str] = mapped_column(Text, default="")
    control_id: Mapped[str] = mapped_column(Text, default="")
    pillar: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(Text, default="")
    resource: Mapped[str] = mapped_column(Text, default="")
    message: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    example: Mapped[dict | None] = mapped_column(JSONB, nullable=True)


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
