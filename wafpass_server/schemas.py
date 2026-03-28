"""Pydantic schemas for the API layer.

The result schema (FindingSchema, WafpassResultSchema) is the contract
owned by wafpass-core. The types below mirror that schema exactly.

Once wafpass-core is installed as a dependency, replace the local
definitions with:

    from wafpass.schema import FindingSchema, WafpassResultSchema
"""
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
    findings: list[FindingSchema] = Field(default_factory=list)


class RunSummary(BaseModel):
    id: uuid.UUID
    project: str
    branch: str
    git_sha: str
    triggered_by: str
    iac_framework: str
    score: int
    pillar_scores: dict[str, int]
    created_at: datetime

    model_config = {"from_attributes": True}


class RunDetail(RunSummary):
    findings: list[dict[str, Any]]

    model_config = {"from_attributes": True}
