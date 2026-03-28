"""Pydantic schemas for the API layer."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


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


class RunCreate(BaseModel):
    """Payload accepted by POST /runs — matches wafpass-result.json schema."""
    schema_version: str = "1.0"
    project: str = ""
    branch: str = ""
    git_sha: str = ""
    triggered_by: str = "local"
    iac_framework: str = "terraform"
    score: int = Field(default=0, ge=0, le=100)
    pillar_scores: dict[str, int] = Field(default_factory=dict)
    path: str = ""
    controls_loaded: int = 0
    controls_run: int = 0
    detected_regions: list[list[str]] = Field(default_factory=list)
    source_paths: list[str] = Field(default_factory=list)
    controls_meta: list[ControlMetaSchema] = Field(default_factory=list)
    findings: list[FindingSchema] = Field(default_factory=list)
    plan_changes: dict[str, Any] | None = None


class RunSummary(BaseModel):
    id: uuid.UUID
    project: str
    branch: str
    git_sha: str
    triggered_by: str
    iac_framework: str
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
    plan_changes: dict[str, Any] | None = None

    model_config = {"from_attributes": True}
