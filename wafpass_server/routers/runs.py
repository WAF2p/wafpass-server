"""POST/GET /runs endpoints."""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.database import get_db
from wafpass_server.models import Run
from wafpass_server.schemas import FindingSchema, RunCreate, RunDetail, RunSummary

router = APIRouter(prefix="/runs", tags=["runs"])


@router.post("", response_model=RunSummary, status_code=201)
async def create_run(
    payload: RunCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Run:
    """Ingest a wafpass-result.json payload and persist it."""
    run = Run(
        project=payload.project,
        branch=payload.branch,
        git_sha=payload.git_sha,
        triggered_by=payload.triggered_by,
        iac_framework=payload.iac_framework,
        score=payload.score,
        pillar_scores=payload.pillar_scores,
        findings=[f.model_dump() for f in payload.findings],
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    return run


@router.get("", response_model=list[RunSummary])
async def list_runs(
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    project: str | None = Query(default=None, description="Filter by project name"),
) -> list[Run]:
    """List runs with pagination, optionally filtered by project."""
    stmt = select(Run).order_by(Run.created_at.desc()).limit(limit).offset(offset)
    if project:
        stmt = stmt.where(Run.project == project)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/{run_id}", response_model=RunDetail)
async def get_run(
    run_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Run:
    """Fetch a single run by ID including all findings."""
    run = await db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@router.get("/{run_id}/findings", response_model=list[FindingSchema])
async def get_findings(
    run_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    severity: str | None = Query(default=None, description="CRITICAL | HIGH | MEDIUM | LOW"),
    pillar: str | None = Query(default=None, description="SEC | OPS | REL | COST | PERF | SUS | SOV"),
    status: str | None = Query(default=None, description="PASS | FAIL | SKIP | WAIVED"),
) -> list[dict]:
    """Return findings for a run, filterable by severity, pillar, and status."""
    run = await db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    findings: list[dict] = run.findings or []
    if severity:
        findings = [f for f in findings if f.get("severity", "").upper() == severity.upper()]
    if pillar:
        findings = [f for f in findings if f.get("pillar", "").upper() == pillar.upper()]
    if status:
        findings = [f for f in findings if f.get("status", "").upper() == status.upper()]

    return findings
