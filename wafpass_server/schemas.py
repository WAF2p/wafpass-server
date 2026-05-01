"""Pydantic schemas for the API layer."""
from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

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


class FindingSchema(BaseModel):
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
    cloud_provider: str = ""
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
    schema_version: str = "1.0"
    project: str = ""
    branch: str = ""
    git_sha: str = ""
    triggered_by: str = "local"
    iac_framework: str = "terraform"
    stage: str = ""
    score: int = Field(default=0, ge=0, le=100)
    pillar_scores: dict[str, int] = Field(default_factory=dict)
    path: str = ""
    controls_loaded: int = 0
    controls_run: int = 0
    detected_regions: list[list[str]] = Field(default_factory=list)
    source_paths: list[str] = Field(default_factory=list)
    controls_meta: list[ControlMetaSchema] = Field(default_factory=list)
    findings: list[FindingSchema] = Field(default_factory=list)
    secret_findings: list[SecretFindingSchema] = Field(default_factory=list)
    plan_changes: dict[str, Any] | None = None


class RunSummary(BaseModel):
    id: uuid.UUID
    project: str
    branch: str
    git_sha: str
    triggered_by: str
    iac_framework: str
    stage: str
    score: int
    pillar_scores: dict[str, int]
    path: str
    controls_loaded: int
    controls_run: int
    created_at: datetime

    model_config = {"from_attributes": True}


class RunDetail(RunSummary):
    findings: list[dict[str, Any]]
    detected_regions: list[list[str]]
    source_paths: list[str]
    controls_meta: list[dict[str, Any]]
    secret_findings: list[dict[str, Any]] = Field(default_factory=list)
    plan_changes: dict[str, Any] | None = None

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
