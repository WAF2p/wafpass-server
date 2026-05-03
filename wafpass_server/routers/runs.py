"""POST/GET /runs endpoints."""
from __future__ import annotations

import base64
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

logger = logging.getLogger(__name__)
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import IngestAuth, get_current_user, require_ingest, require_role
from wafpass_server.database import get_db
from wafpass_server.models import (
    ApiKeyUsageLog,
    FindingComment,
    Run,
    RunFinding,
    RunSecretFinding,
    SecretFindingComment,
    User,
    UserAuditLog,
)
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

    # Fetch findings from run_findings table (normalized, with IDs)
    stmt = select(RunFinding).where(RunFinding.run_id == run_id)
    result = await db.execute(stmt)
    finding_rows = list(result.scalars().all())

    # Fetch comment counts per finding_id for this run (regular findings)
    stmt_comments = (
        select(FindingComment.finding_id, func.count().label("count"))
        .where(FindingComment.run_id == run_id)
        .group_by(FindingComment.finding_id)
    )
    result_comments = await db.execute(stmt_comments)
    comment_counts = {row.finding_id: row.count for row in result_comments.all()}

    # Fetch comment counts per secret_finding_id for this run (secret findings)
    stmt_secret_comments = (
        select(SecretFindingComment.secret_finding_id, func.count().label("count"))
        .where(SecretFindingComment.run_id == run_id)
        .group_by(SecretFindingComment.secret_finding_id)
    )
    result_secret_comments = await db.execute(stmt_secret_comments)
    secret_comment_counts = {row.secret_finding_id: row.count for row in result_secret_comments.all()}

    # Log findings for debugging
    logger.info("=== GET RUN DEBUG ===")
    logger.info("Run ID: %s", run.id)
    logger.info("Run project: %s", run.project)
    logger.info("Run findings count (from run_findings): %d", len(finding_rows))
    if finding_rows:
        statuses = [f.status for f in finding_rows]
        status_counts = {}
        for s in statuses:
            status_counts[s] = status_counts.get(s, 0) + 1
        logger.info("Run status counts: %s", status_counts)
        for i, f in enumerate(finding_rows[:3]):
            logger.info("  Run.Finding[%d]: id=%s, check_id=%s, status=%s", i, f.id, f.check_id, f.status)
    logger.info("=== END GET RUN DEBUG ===")

    # Add comment_count to each finding row before converting to schema
    findings_with_comments = []
    for f in finding_rows:
        # Convert SQLAlchemy ORM to dict manually
        f_dict = {c.name: getattr(f, c.name) for c in f.__table__.columns}
        finding_id = f_dict.get("id")
        if finding_id and finding_id in comment_counts:
            f_dict["comment_count"] = comment_counts[finding_id]
        else:
            f_dict["comment_count"] = 0
        findings_with_comments.append(f_dict)

    # Process secret findings - add comment counts
    # First, fetch all run_secret_findings for this run to get the mapping
    stmt_secret_findings = select(RunSecretFinding).where(RunSecretFinding.run_id == run_id)
    result_secret_findings = await db.execute(stmt_secret_findings)
    secret_finding_rows = list(result_secret_findings.scalars().all())

    # Create a lookup from secret_finding_id to comment count
    # (secret_comment_counts already contains the counts keyed by secret_finding_id)
    secret_findings_with_counts = []
    for sf in run.secret_findings or []:
        sf_copy = dict(sf)

        # Find the matching run_secret_finding record
        # Match by file, line_no, and pattern_name to find the corresponding run_secret_finding.id
        secret_finding_id = None
        for rsf in secret_finding_rows:
            if rsf.file == sf.get("file") and rsf.line_no == sf.get("line_no") and rsf.pattern_name == sf.get("pattern_name"):
                secret_finding_id = rsf.id
                break

        if secret_finding_id and secret_finding_id in secret_comment_counts:
            sf_copy["comment_count"] = secret_comment_counts[secret_finding_id]
        else:
            sf_copy["comment_count"] = 0

        secret_findings_with_counts.append(sf_copy)

    return Envelope(
        data=RunDetail(
            id=run.id,
            project=run.project,
            branch=run.branch,
            git_sha=run.git_sha,
            triggered_by=run.triggered_by,
            iac_framework=run.iac_framework,
            stage=run.stage,
            score=run.score,
            pillar_scores=run.pillar_scores,
            path=run.path,
            controls_loaded=run.controls_loaded,
            controls_run=run.controls_run,
            created_at=run.created_at,
            findings=findings_with_comments,
            detected_regions=run.detected_regions,
            source_paths=run.source_paths,
            controls_meta=run.controls_meta,
            secret_findings=secret_findings_with_counts,
            plan_changes=run.plan_changes,
        )
    )


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


# ── Remediation Sprint Export Endpoints ───────────────────────────────────────


def _build_sprint_controls(run: Run, sprint_ids: list[str]) -> list[dict]:
    """Build sprint control data for export formats."""
    meta_by_id = {c['id']: c for c in (run.controls_meta or [])}

    # Build a lookup from run_findings table
    # Findings are stored in run.findings as a list of dicts
    findings_by_control: dict[str, list[dict]] = {}
    for f in (run.findings or []):
        if f.get('status', '').upper() == 'FAIL' and f.get('control_id'):
            cid = f['control_id']
            if cid not in findings_by_control:
                findings_by_control[cid] = []
            findings_by_control[cid].append(f)

    controls = []
    for cid in sprint_ids:
        meta = meta_by_id.get(cid, {})
        ff = findings_by_control.get(cid, [])

        frameworks = list({m['framework'] for m in (meta.get('regulatory_mapping') or [])})
        remediations = list({f.get('remediation') for f in ff if f.get('remediation')})[:3]

        controls.append({
            'id': cid,
            'title': meta.get('title') or (ff[0].get('check_title') if ff else cid),
            'pillar': meta.get('pillar', ''),
            'severity': meta.get('severity', (ff[0].get('severity') if ff else 'low')).upper(),
            'category': meta.get('category', ''),
            'description': meta.get('description', ''),
            'frameworks': frameworks,
            'frameworkMappings': meta.get('regulatory_mapping', []),
            'effort': 'Low' if len(ff) <= 3 else 'Medium' if len(ff) <= 9 else 'High',
            'pointsGain': 0,  # Will be calculated in frontend
            'remediations': remediations,
            'resourceCount': len(set(f.get('resource') for f in ff if f.get('resource'))),
            'checkCount': len(set(f.get('check_id') for f in ff if f.get('check_id'))),
        })

    # Sort by severity then framework count
    sev_rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    controls.sort(key=lambda c: (sev_rank.get(c['severity'], 4), -len(c['frameworks'])))
    return controls


@router.get("/{run_id}/export/csv", response_class=StreamingResponse)
async def export_sprint_csv(
    run_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
    sprint: str = Query(..., description="Comma-separated list of control IDs in sprint"),
) -> StreamingResponse:
    """Export sprint controls as CSV for Excel."""
    run = await db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    sprint_ids = [s.strip() for s in sprint.split(',') if s.strip()]
    controls = _build_sprint_controls(run, sprint_ids)

    # Build CSV content
    csv_lines = [
        "Control ID,Title,Pillar,Severity,Category,Framework,Remediation,Resources,Checks"
    ]
    for ctrl in controls:
        frameworks = ';'.join(ctrl['frameworks']) if ctrl['frameworks'] else ''
        remediations = ';'.join(ctrl['remediations']) if ctrl['remediations'] else ''
        csv_lines.append(
            f'{ctrl["id"]},{ctrl["title"]},{ctrl["pillar"]},{ctrl["severity"]},'
            f'{ctrl["category"]},{frameworks},{remediations},{ctrl["resourceCount"]},{ctrl["checkCount"]}'
        )

    csv_content = '\n'.join(csv_lines)
    csv_buffer = io.StringIO(csv_content)

    return StreamingResponse(
        csv_buffer,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="remediation_sprint_{run.project.replace(" ", "_")}_{run.created_at.strftime("%Y%m%d")}.csv"',
        },
    )


@router.get("/{run_id}/export/jira", response_class=StreamingResponse)
async def export_sprint_jira(
    request: Request,
    run_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
    sprint: str = Query(..., description="Comma-separated list of control IDs in sprint"),
) -> StreamingResponse:
    """Export sprint controls as Jira issue bulk-create CSV."""
    run = await db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    sprint_ids = [s.strip() for s in sprint.split(',') if s.strip()]
    controls = _build_sprint_controls(run, sprint_ids)

    # Jira CSV format: Summary,Description,Priority,Project,IssueType
    # Optional: Labels,Components,Assignee
    csv_lines = [
        "Summary,Description,Priority,Project,IssueType,Labels,Components,Assignee"
    ]
    for ctrl in controls:
        severity = ctrl['severity']
        priority = {'CRITICAL': 'High', 'HIGH': 'High', 'MEDIUM': 'Medium', 'LOW': 'Low'}.get(severity, 'Low')
        frameworks = ';'.join(ctrl['frameworks']) if ctrl['frameworks'] else ''
        description = (
            f"**Control:** {ctrl['title']} ({ctrl['id']})\n"
            f"**Pillar:** {ctrl['pillar']}\n"
            f"**Severity:** {severity}\n"
            f"**Category:** {ctrl['category']}\n"
            f"**Frameworks:** {frameworks}\n"
            f"**Resources affected:** {ctrl['resourceCount']}\n"
            f"**Checks failing:** {ctrl['checkCount']}\n"
            f"**Description:** {ctrl['description']}\n"
            f"**Remediation:** {ctrl['remediations'][0] if ctrl['remediations'] else ''}"
        )
        summary = f"[{ctrl['id']}] {ctrl['title'][:80]}"
        csv_lines.append(
            f'"{summary}","{description}","{priority}","WAF",Task,"WAF++,{ctrl["pillar"].lower()}",'
        )

    csv_content = '\n'.join(csv_lines)
    csv_buffer = io.StringIO(csv_content)

    return StreamingResponse(
        csv_buffer,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="jira_issues_{run.project.replace(" ", "_")}_{run.created_at.strftime("%Y%m%d")}.csv"',
        },
    )


@router.post("/{run_id}/export/slack", status_code=200)
async def export_sprint_slack(
    run_id: uuid.UUID,
    payload: dict[str, object],
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
) -> dict[str, str]:
    """Export sprint controls as Slack/MS Teams message payload."""
    run = await db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    sprint = payload.get('sprint', '')
    sprint_ids = [s.strip() for s in str(sprint).split(',') if s.strip()]
    controls = _build_sprint_controls(run, sprint_ids)

    # Build Slack/MS Teams message payload
    # Use Adaptive Cards for rich formatting in both platforms
    message_text = f"Remediation Sprint for *{run.project}* (run {run.id.hex[:8]})\n"
    message_text += f"Current score: {run.score} | Controls in sprint: {len(controls)}\n\n"

    if controls:
        for ctrl in controls[:5]:  # Limit to first 5 controls
            severity = ctrl['severity']
            sev_color = {'CRITICAL': '#DA2C38', 'HIGH': '#f97316', 'MEDIUM': '#eab308', 'LOW': '#22c55e'}.get(severity, '#64748b')
            frameworks = ', '.join(ctrl['frameworks'][:3]) if ctrl['frameworks'] else 'N/A'

            message_text += (
                f"*{ctrl['title']}* ({ctrl['id']})\n"
                f"  Severity: {severity} | Pillar: {ctrl['pillar']} | Frameworks: {frameworks}\n"
                f"  Resources: {ctrl['resourceCount']} | Checks: {ctrl['checkCount']}\n"
                f"  Remediation: {ctrl['remediations'][0][:60]}..." if ctrl['remediations'] and len(ctrl['remediations'][0]) > 60 else ctrl['remediations'][0] if ctrl['remediations'] else 'N/A'
            ) + "\n\n"

        if len(controls) > 5:
            message_text += f"...and {len(controls) - 5} more controls\n"
    else:
        message_text += "No controls in sprint.\n"

    # Return message payload for external processing
    return {
        "type": "message",
        "text": message_text,
        "preview": message_text[:200],
        "control_count": str(len(controls)),
        "project": run.project,
        "run_id": str(run_id),
    }
