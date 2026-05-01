"""POST/GET /runs endpoints."""
from __future__ import annotations

import base64
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request

logger = logging.getLogger(__name__)
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import IngestAuth, get_current_user, require_ingest, require_role
from wafpass_server.database import get_db
from wafpass_server.models import ApiKeyUsageLog, Run, RunFinding, User, UserAuditLog
from wafpass_server.routers.achievements import evaluate_and_record_achievements
from wafpass_server.schemas import ControlMetaSchema, Envelope, FindingSchema, Meta, RunCreate, RunDetail, RunSummary, SecretFindingSchema

router = APIRouter(prefix="/runs", tags=["runs"])


def _encode_cursor(run: Run) -> str:
    raw = f"{run.created_at.isoformat()}|{run.id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    raw = base64.urlsafe_b64decode(cursor.encode()).decode()
    ts_str, id_str = raw.split("|", 1)
    ts = datetime.fromisoformat(ts_str)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts, uuid.UUID(id_str)


def _finding_rows(run_id: uuid.UUID, findings: list[FindingSchema]) -> list[RunFinding]:
    """Build RunFinding ORM rows from a list of FindingSchema objects."""
    return [
        RunFinding(
            run_id=run_id,
            check_id=f.check_id,
            check_title=f.check_title,
            control_id=f.control_id,
            pillar=f.pillar,
            severity=f.severity,
            status=f.status,
            resource=f.resource,
            message=f.message,
            remediation=f.remediation,
            example=f.example,
            regulatory_mapping=f.regulatory_mapping,
        )
        for f in findings
    ]


@router.post("", response_model=Envelope[RunSummary], status_code=201)
async def create_run(
    request: Request,
    payload: RunCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    auth: Annotated[IngestAuth, Depends(require_ingest)],
) -> Envelope[RunSummary]:
    """Ingest a wafpass-result.json payload.

    Accepts either a Bearer JWT (any role) or the ``X-Api-Key`` header so that
    CI/CD pipelines can push results without a user account.
    """
    # Log incoming findings for debugging
    logger.info("=== RUN PUSH DEBUG ===")
    logger.info("Project: %s", payload.project)
    logger.info("Branch: %s", payload.branch)
    logger.info("Findings count: %d", len(payload.findings))
    if payload.findings:
        statuses = [f.status for f in payload.findings]
        status_counts = {}
        for s in statuses:
            status_counts[s] = status_counts.get(s, 0) + 1
        logger.info("Status counts: %s", status_counts)
        # Log first 5 findings
        for i, f in enumerate(payload.findings[:5]):
            logger.info("  Finding[%d]: check_id=%s, status=%s, resource=%s", i, f.check_id, f.status, f.resource)
    logger.info("=== END RUN PUSH DEBUG ===")

    run = Run(
        project=payload.project,
        branch=payload.branch,
        git_sha=payload.git_sha,
        triggered_by=payload.triggered_by,
        iac_framework=payload.iac_framework,
        stage=payload.stage,
        score=payload.score,
        pillar_scores=payload.pillar_scores,
        findings=[f.model_dump() for f in payload.findings],
        path=payload.path,
        controls_loaded=payload.controls_loaded,
        controls_run=payload.controls_run,
        detected_regions=payload.detected_regions,
        source_paths=payload.source_paths,
        controls_meta=[c.model_dump() for c in payload.controls_meta],
        secret_findings=[sf.model_dump() for sf in payload.secret_findings],
        plan_changes=payload.plan_changes,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    # Log stored findings
    logger.info("=== STORED RUN DEBUG ===")
    logger.info("Run ID: %s", run.id)
    logger.info("Stored findings count: %d", len(run.findings or []))
    if run.findings:
        stored_statuses = [f.get("status") for f in run.findings]
        stored_status_counts = {}
        for s in stored_statuses:
            stored_status_counts[s] = stored_status_counts.get(s, 0) + 1
        logger.info("Stored status counts: %s", stored_status_counts)
        # Log first 5 stored findings
        for i, f in enumerate(run.findings[:5]):
            logger.info("  Stored[%d]: check_id=%s, status=%s", i, f.get("check_id", "N/A"), f.get("status", "N/A"))
    logger.info("=== END STORED RUN DEBUG ===")

    if payload.findings:
        db.add_all(_finding_rows(run.id, payload.findings))
        await db.commit()

    await evaluate_and_record_achievements(db, run)

    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "")

    if auth.api_key_id is not None:
        # DB-tracked API key path
        db.add(ApiKeyUsageLog(
            api_key_id=auth.api_key_id,
            endpoint="POST /runs",
            run_id=run.id,
            project=run.project,
            branch=run.branch,
            score=run.score,
            ip=client_ip,
        ))
        await db.commit()
    elif auth.user is not None:
        # JWT user path — write a user audit log entry
        db.add(UserAuditLog(
            actor_id=auth.user.id,
            action="run.push",
            detail={
                "run_id": str(run.id),
                "project": run.project,
                "branch": run.branch,
                "score": run.score,
                "endpoint": "POST /runs",
            },
            ip=client_ip,
        ))
        await db.commit()

    return Envelope(data=RunSummary.model_validate(run, from_attributes=True))


@router.get("", response_model=Envelope[list[RunSummary]])
async def list_runs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    project: str | None = Query(default=None),
    stage: str | None = Query(default=None),
) -> Envelope[list[RunSummary]]:
    """Return a page of runs ordered by created_at DESC.

    Pass the ``cursor`` value from ``meta.next_cursor`` to retrieve the next
    page.  When ``meta.next_cursor`` is null there are no more pages.
    """
    stmt = select(Run).order_by(Run.created_at.desc(), Run.id.desc()).limit(limit)

    if project:
        stmt = stmt.where(Run.project == project)
    if stage:
        stmt = stmt.where(Run.stage == stage)

    if cursor:
        try:
            cursor_ts, cursor_id = _decode_cursor(cursor)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid cursor") from exc
        stmt = stmt.where(
            or_(
                Run.created_at < cursor_ts,
                and_(Run.created_at == cursor_ts, Run.id < cursor_id),
            )
        )

    result = await db.execute(stmt)
    rows = list(result.scalars().all())

    next_cursor = _encode_cursor(rows[-1]) if len(rows) == limit else None
    return Envelope(
        data=[RunSummary.model_validate(r, from_attributes=True) for r in rows],
        meta=Meta(next_cursor=next_cursor),
    )


@router.get("/{run_id}", response_model=Envelope[RunDetail])
async def get_run(
    run_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
) -> Envelope[RunDetail]:
    run = await db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    # Log findings for debugging
    logger.info("=== GET RUN DEBUG ===")
    logger.info("Run ID: %s", run.id)
    logger.info("Run project: %s", run.project)
    logger.info("Run findings count: %d", len(run.findings or []))
    if run.findings:
        statuses = [f.get("status") for f in run.findings]
        status_counts = {}
        for s in statuses:
            status_counts[s] = status_counts.get(s, 0) + 1
        logger.info("Run status counts: %s", status_counts)
        for i, f in enumerate(run.findings[:3]):
            logger.info("  Run.Finding[%d]: check_id=%s, status=%s", i, f.get("check_id", "N/A"), f.get("status", "N/A"))
    logger.info("=== END GET RUN DEBUG ===")

    return Envelope(data=RunDetail.model_validate(run, from_attributes=True))


@router.get("/{run_id}/controls", response_model=Envelope[list[ControlMetaSchema]])
async def get_controls(
    run_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
) -> Envelope[list[dict]]:
    run = await db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return Envelope(data=run.controls_meta or [])


@router.get("/{run_id}/findings", response_model=Envelope[list[FindingSchema]])
async def get_findings(
    run_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
    severity: str | None = Query(default=None),
    pillar: str | None = Query(default=None),
    status: str | None = Query(default=None),
) -> Envelope[list[FindingSchema]]:
    run_exists = await db.get(Run, run_id)
    if run_exists is None:
        raise HTTPException(status_code=404, detail="Run not found")

    logger.info("=== GET FINDINGS DEBUG ===")
    logger.info("Run ID: %s", run_id)
    logger.info("Filter - severity: %s, pillar: %s, status: %s", severity, pillar, status)

    stmt = select(RunFinding).where(RunFinding.run_id == run_id)
    if severity:
        stmt = stmt.where(func.lower(RunFinding.severity) == severity.lower())
    if pillar:
        stmt = stmt.where(func.lower(RunFinding.pillar) == pillar.lower())
    if status:
        stmt = stmt.where(func.lower(RunFinding.status) == status.lower())

    result = await db.execute(stmt)
    findings = list(result.scalars().all())
    logger.info("Found %d findings", len(findings))
    if findings:
        statuses = [f.status for f in findings]
        status_counts = {}
        for s in statuses:
            status_counts[s] = status_counts.get(s, 0) + 1
        logger.info("Return status counts: %s", status_counts)
        for i, f in enumerate(findings[:3]):
            logger.info("  Return[%d]: check_id=%s, status=%s, resource=%s", i, f.check_id, f.status, f.resource)
    logger.info("=== END GET FINDINGS DEBUG ===")
    return Envelope(data=findings)
