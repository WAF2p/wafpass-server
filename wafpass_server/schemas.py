"""Pydantic schemas for the API layer."""
from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

# Re-export control schema types from wafpass-core so callers only need one import.
from wafpass.control_schema import WizardCheck, WizardControl  # noqa: F401

# ── Generic response envelope ─────────────────────────────────────────────────

T = TypeVar("T")


class Meta(BaseModel):
    total: int | None = None
    page: int | None = None
    per_page: int | None = None
    next_cursor: str | None = None


class Envelope(BaseModel, Generic[T]):
    """Consistent API response wrapper used by all endpoints."""

    data: T
    meta: Meta = Field(default_factory=Meta)


class SecretFindingSchema(BaseModel):
    file: str
    line_no: int
    pattern_name: str
    severity: str
    matched_key: str
    masked_value: str
    suppressed: bool = False
    comment_count: int = Field(default=0, ge=0)


class FindingSchema(BaseModel):
    id: uuid.UUID | None = None  # Optional on ingestion; set by server on save
    check_id: str
    check_title: str
    control_id: str
    pillar: str = ""
    severity: str
    status: str
    resource: str
    message: str
    remediation: str
    example: dict[str, Any] | None = None
    regulatory_mapping: list[dict[str, Any]] = Field(default_factory=list)
    comment_count: int = Field(default=0, ge=0)

    model_config = ConfigDict(from_attributes=True)


class ControlCheckMetaSchema(BaseModel):
    id: str
    title: str
    severity: str
    remediation: str = ""
    example: dict[str, Any] | None = None


class ControlMetaSchema(BaseModel):
    id: str
    title: str
    pillar: str
    severity: str
    category: str = ""
    description: str = ""
    rationale: str = ""
    threat: list[str] = Field(default_factory=list)
    regulatory_mapping: list[dict[str, Any]] = Field(default_factory=list)
    checks: list[ControlCheckMetaSchema] = Field(default_factory=list)


class ControlPackOut(BaseModel):
    version: str
    description: str
    is_active: bool
    control_count: int
    imported_at: datetime
    imported_by: uuid.UUID | None
    activated_at: datetime | None
    activated_by: uuid.UUID | None

    model_config = ConfigDict(from_attributes=True)


class ControlPackSyncIn(BaseModel):
    version: str = Field(description="Semantic version string, e.g. v1.2.0")
    description: str = ""


def _coerce_date(v: object) -> date | None:
    """Accept a date object, ISO date string, or empty string; reject anything else."""
    if v is None or v == "":
        return None
    if isinstance(v, date):
        return v
    if isinstance(v, str):
        try:
            return date.fromisoformat(v)
        except ValueError as exc:
            raise ValueError(f"Invalid date format '{v}' — expected YYYY-MM-DD") from exc
    raise TypeError(f"Expected date string or None, got {type(v).__name__}")


class WaiverUpsert(BaseModel):
    reason: str = ""
    owner: str = ""
    expires: date | None = None
    project: str = ""

    @field_validator("expires", mode="before")
    @classmethod
    def _parse_expires(cls, v: object) -> date | None:
        return _coerce_date(v)


class WaiverOut(BaseModel):
    id: str
    reason: str
    owner: str
    expires: date | None
    project: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RiskAcceptanceUpsert(BaseModel):
    reason: str = ""
    approver: str = ""
    owner: str = ""
    rfc: str = ""
    jira_link: str = ""
    other_link: str = ""
    notes: str = ""
    risk_level: str = "accepted"
    residual_risk: str = "medium"
    expires: date | None = None
    accepted_at: date | None = None
    project: str = ""

    @field_validator("expires", "accepted_at", mode="before")
    @classmethod
    def _parse_dates(cls, v: object) -> date | None:
        return _coerce_date(v)


class RiskAcceptanceOut(BaseModel):
    id: str
    reason: str
    approver: str
    owner: str
    rfc: str
    jira_link: str
    other_link: str
    notes: str
    risk_level: str
    residual_risk: str
    expires: date | None
    accepted_at: date | None
    project: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProjectPassportUpsert(BaseModel):
    display_name: str = ""
    owner: str = ""
    owner_team: str = ""
    contact_email: str = ""
    description: str = ""
    criticality: str = ""
    environment: str = ""
    cloud_provider: str = ""  # aws|azure|gcp|alicloud|yandex|oci|ovh|hetzner|stackit|infomaniak|leafcloud|tcloud|seeweb|exoscale|cyso|numspot|plusserver|syselev|outscale|leaseweb|scaleway|ionos|upcloud|cleura|multi|other
    repository_url: str = ""
    documentation_url: str = ""
    tags: list[str] = Field(default_factory=list)
    notes: str = ""
    image_url: str = ""


class ProjectPassportOut(ProjectPassportUpsert):
    project: str
    updated_by: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RunCreate(BaseModel):
    """Payload accepted by POST /runs — matches wafpass-result.json schema."""
    schema_version: str = "1.1"
    project: str = ""
    branch: str = ""
    git_sha: str = ""
    triggered_by: str = "local"
    run: dict[str, Any] = Field(default_factory=dict, description="Run metadata including is_cicd flag")
    iac_framework: str = "terraform"
    stage: str = ""
    score: int = Field(default=0, ge=0, le=100)
    pillar_scores: dict[str, int] = Field(default_factory=dict)
    path: str = ""
    controls_loaded: int = 0
    controls_run: int = 0
    detected_regions: list[list[str | None]] = Field(default_factory=list, description="List of [region, provider, availability_zone] tuples. availability_zone may be null for regions without AZs (e.g., GCP multi-regions).")
    source_paths: list[str] = Field(default_factory=list)
    controls_meta: list[ControlMetaSchema] = Field(default_factory=list)
    findings: list[FindingSchema] = Field(default_factory=list)
    secret_findings: list[SecretFindingSchema] = Field(default_factory=list)
    plan_changes: dict[str, Any] | None = None
    source_snapshot: dict[str, str] = Field(default_factory=dict, description="Optional IaC source file contents uploaded by the CLI so the dashboard can render Local preview diffs. Keys are relative paths; values are file content strings.")


class RunSummary(BaseModel):
    id: uuid.UUID
    project: str
    branch: str
    git_sha: str
    triggered_by: str
    is_cicd: bool = Field(default=False)
    iac_framework: str
    stage: str
    score: int
    pillar_scores: dict[str, int]
    path: str
    controls_loaded: int
    controls_run: int
    created_at: datetime

    @classmethod
    def from_orm(cls, obj: "Run") -> "RunSummary":
        """Extract is_cicd from run_metadata dict if present."""
        run_metadata = getattr(obj, "run_metadata", {}) or {}
        is_cicd = run_metadata.get("is_cicd", False)
        return cls(
            id=obj.id,
            project=obj.project,
            branch=obj.branch,
            git_sha=obj.git_sha,
            triggered_by=obj.triggered_by,
            is_cicd=is_cicd,
            iac_framework=obj.iac_framework,
            stage=obj.stage,
            score=obj.score,
            pillar_scores=obj.pillar_scores,
            path=obj.path,
            controls_loaded=obj.controls_loaded,
            controls_run=obj.controls_run,
            created_at=obj.created_at,
        )

    model_config = {"from_attributes": True}


class RunDetail(RunSummary):
    findings: list[dict[str, Any]]
    detected_regions: list[list[str | None]]
    source_paths: list[str]
    controls_meta: list[dict[str, Any]]
    secret_findings: list[dict[str, Any]] = Field(default_factory=list)
    plan_changes: dict[str, Any] | None = None
    source_snapshot: dict[str, str] = Field(default_factory=dict)

    model_config = {"from_attributes": True}


# ── Achievement schemas ───────────────────────────────────────────────────────


class AchievementOut(BaseModel):
    id: uuid.UUID
    project: str
    tier_level: int
    tier_label: str
    score: int
    run_id: uuid.UUID
    verification_token: str
    snapshot_jsonb: dict[str, Any]
    achieved_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ── Compliance audit event schemas ───────────────────────────────────────────


class ComplianceAuditEventIn(BaseModel):
    client_id: str = ""
    actor: str = ""
    category: str          # waiver|risk|scan|finding
    action: str
    subject_id: str = ""
    subject_type: str = ""
    summary: str = ""
    timestamp: str = ""    # ISO 8601 — dashboard-provided event time; falls back to server now()
    before: Any | None = None
    after: Any | None = None


class ComplianceAuditEventOut(BaseModel):
    id: uuid.UUID
    client_id: str
    actor: str
    category: str
    action: str
    subject_id: str
    subject_type: str
    summary: str
    before: Any | None
    after: Any | None
    timestamp: datetime
    created_by: uuid.UUID | None

    model_config = ConfigDict(from_attributes=True)


# ── Finding comment schemas ───────────────────────────────────────────────────


class FindingCommentIn(BaseModel):
    """Request body for creating a comment on a finding."""
    message: str = Field(min_length=1, max_length=10000)


class FindingCommentOut(BaseModel):
    """Response schema for finding comments."""
    id: uuid.UUID
    finding_id: uuid.UUID
    run_id: uuid.UUID
    user_id: uuid.UUID
    message: str
    created_at: datetime
    username: str = ""
    display_name: str = ""
    image_url: str = ""

    model_config = ConfigDict(from_attributes=True)


# ── Secret finding comment schemas ────────────────────────────────────────────


class SecretFindingCommentIn(BaseModel):
    """Request body for creating a comment on a secret finding."""
    message: str = Field(min_length=1, max_length=10000)


class SecretFindingCommentOut(BaseModel):
    """Response schema for secret finding comments."""
    id: uuid.UUID
    secret_finding_id: uuid.UUID
    run_id: uuid.UUID
    user_id: uuid.UUID
    message: str
    created_at: datetime
    username: str = ""
    display_name: str = ""
    image_url: str = ""

    model_config = ConfigDict(from_attributes=True)


# ── Widget schemas ────────────────────────────────────────────────────────────


class WidgetConfig(BaseModel):
    """Widget display configuration."""

    widget_type: str = Field(default="compliance-tile", description="Type of widget to display")
    title: str = Field(default="WAF++ PASS")
    projects: list[str] = Field(default_factory=list, description="Projects to show (empty = all)")
    refresh_interval: int = Field(default=300, ge=60, le=3600, description="Refresh interval in seconds")
    show_score: bool = Field(default=True, description="Show overall score")
    show_pillars: bool = Field(default=True, description="Show pillar scores")
    show_trend: bool = Field(default=False, description="Show trend indicator")
    theme: str = Field(default="auto", description="Theme: auto, light, dark")
    layout: str = Field(default="horizontal", description="Layout: horizontal, vertical, grid")
    is_active: bool = Field(default=True, description="Is the widget active")


class WidgetCreate(BaseModel):
    """Request body for creating a widget."""

    name: str = Field(min_length=1, max_length=100)
    config: WidgetConfig = Field(default_factory=WidgetConfig)


class WidgetOut(BaseModel):
    """Response schema for widgets."""

    id: uuid.UUID
    name: str
    token: str
    config: dict[str, Any]
    is_active: bool
    last_accessed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ── Control schemas ───────────────────────────────────────────────────────────


class ControlIn(WizardControl):
    """Request body for POST /controls.

    Extends WizardControl (from wafpass-core) with an optional ``source``
    field indicating the authoring origin.
    """

    source: str = "wafpass"


class ControlOut(WizardControl):
    """Response schema for /controls endpoints.

    Extends WizardControl with server-managed timestamp fields.
    ``from_attributes=True`` enables construction from SQLAlchemy ORM rows.
    """

    source: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ── Notification schemas ──────────────────────────────────────────────────────


class NotificationBase(BaseModel):
    """Base schema for notifications."""
    title: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=2000)
    category: str = Field(default="info")  # info, warning, urgent, success
    target_role: str | None = Field(default=None)  # admin, clevel, architect, engineer, all


class NotificationCreate(NotificationBase):
    """Request body for creating a notification."""
    pass


class NotificationOut(NotificationBase):
    """Response schema for notifications."""
    id: str
    is_read: bool
    created_at: datetime
    triggered_by: str

    model_config = ConfigDict(from_attributes=True)


class NotificationTestIn(NotificationBase):
    """Request body for testing a notification."""
    pass


class NotificationTestOut(NotificationOut):
    """Response schema for test notifications."""
    pass


class NotificationUpdateRead(BaseModel):
    """Request body for updating notification read status."""
    is_read: bool = True


# ── Project Group schemas ─────────────────────────────────────────────────────

class ProjectGroupOut(BaseModel):
    """Response schema for project groups."""
    id: uuid.UUID
    project: str
    group_name: str
    created_at: datetime
    created_by: uuid.UUID | None = None

    model_config = ConfigDict(from_attributes=True)


class ProjectGroupCreate(BaseModel):
    """Request body for creating a project group."""
    project: str = Field(min_length=1, max_length=200)
    group_name: str = Field(min_length=1, max_length=200)


class ProjectGroupUpdate(BaseModel):
    """Request body for updating a project group."""
    group_name: str | None = Field(default=None, min_length=1, max_length=200)


# ── User Group schemas ────────────────────────────────────────────────────────

class UserGroupOut(BaseModel):
    """Response schema for user groups."""
    id: uuid.UUID
    user_id: uuid.UUID
    group_name: str
    provider: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserGroupCreate(BaseModel):
    """Request body for creating a user group (admin only, for manual assignment)."""
    user_id: uuid.UUID
    group_name: str = Field(min_length=1, max_length=200)
    provider: str = "*"
