"""GET /pipelines/metrics and /pipelines/trends endpoints."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import AuthContext, bypasses_group_scoping, get_auth_context, get_scoped_db
from wafpass_server.models import ProjectGroup, Run, User, UserGroup
from wafpass_server.schemas import (
    DurationStats,
    Envelope,
    PipelineMetrics,
    PipelineTrends,
    ProjectRunSummary,
    RunsByDay,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/pipelines", tags=["pipelines"])


def _format_duration(ms: int) -> str:
    """Render a millisecond duration as a compact human-readable label."""
    if ms <= 0:
        return "—"
    total_seconds = max(1, round(ms / 1000))
    if total_seconds >= 3600:
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    if total_seconds >= 60:
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        return f"{minutes}m {seconds}s" if seconds else f"{minutes}m"
    return f"{total_seconds}s"


def _run_duration_ms(run: Run) -> int:
    """Positive scan duration in milliseconds, falling back to 0."""
    start = run.created_at
    end = run.completed_at or start
    if end is None or start is None:
        return 0
    delta = end - start
    return max(0, int(delta.total_seconds() * 1000))


async def _accessible_projects(db: AsyncSession, user: User, auth: AuthContext) -> set[str] | None:
    """Return the projects a non-admin user can see, or None for admins."""
    if bypasses_group_scoping(user, auth):
        return None

    result = await db.execute(
        select(UserGroup.group_name).where(UserGroup.user_id == user.id)
    )
    user_groups = result.scalars().all()
    if not user_groups:
        return set()

    result = await db.execute(
        select(ProjectGroup.project).where(ProjectGroup.group_name.in_(user_groups))
    )
    return set(result.scalars().all())


async def _base_run_query(
    db: AsyncSession,
    user: User,
    auth: AuthContext,
    project: str | None = None,
    since: datetime | None = None,
    is_cicd: bool | None = None,
) -> list[Run]:
    """Fetch runs visible to the caller, optionally filtered by project, date and CI/CD flag."""
    accessible = await _accessible_projects(db, user, auth)
    if accessible is not None and not accessible:
        return []

    stmt = select(Run).order_by(Run.created_at.desc())
    if project:
        stmt = stmt.where(Run.project == project)
    if since:
        stmt = stmt.where(Run.created_at >= since)
    if is_cicd is not None:
        stmt = stmt.where(Run.run_metadata["is_cicd"].as_boolean() == is_cicd)
    if accessible is not None:
        stmt = stmt.where(Run.project.in_(accessible))

    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/metrics", response_model=Envelope[PipelineMetrics])
async def pipeline_metrics(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    project: str | None = Query(default=None),
    is_cicd: bool | None = Query(default=None),
) -> Envelope[PipelineMetrics]:
    """High-level pipeline health metrics across accessible projects.

    Non-admin users only see runs for projects they have group access to.
    """
    runs = await _base_run_query(db, auth.user, auth, project=project, is_cicd=is_cicd)

    if not runs:
        return Envelope(
            data=PipelineMetrics(
                totalRuns=0,
                passRate=0,
                avgScore=0,
                projects=0,
                recentRuns=0,
                failedRuns=0,
                skippedRuns=0,
                projectsList=[],
            )
        )

    total_runs = len(runs)
    pass_count = sum(1 for r in runs if r.score >= 80)
    avg_score = round(sum(r.score for r in runs) / total_runs)
    projects = {r.project for r in runs}

    one_week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent_runs = sum(1 for r in runs if r.created_at and r.created_at >= one_week_ago)

    skipped_runs = sum(
        max(0, (r.controls_loaded or 0) - (r.controls_run or 0)) for r in runs
    )

    project_map: dict[str, list[Run]] = {}
    for r in runs:
        project_map.setdefault(r.project, []).append(r)

    projects_list = [
        ProjectRunSummary(
            project=p,
            avgScore=round(sum(r.score for r in rr) / len(rr)),
            latestScore=max(rr, key=lambda r: r.created_at or datetime.min).score,
            runCount=len(rr),
            lastRunAt=max((r.created_at for r in rr if r.created_at), default=datetime.min),
        )
        for p, rr in project_map.items()
    ]
    projects_list.sort(key=lambda x: x.avgScore, reverse=True)

    return Envelope(
        data=PipelineMetrics(
            totalRuns=total_runs,
            passRate=round(pass_count / total_runs * 100),
            avgScore=avg_score,
            projects=len(projects),
            recentRuns=recent_runs,
            failedRuns=total_runs - pass_count,
            skippedRuns=skipped_runs,
            projectsList=projects_list,
        )
    )


@router.get("/trends", response_model=Envelope[PipelineTrends])
async def pipeline_trends(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    project: str | None = Query(default=None),
    days: int = Query(default=30, ge=1, le=90),
    is_cicd: bool | None = Query(default=None),
) -> Envelope[PipelineTrends]:
    """Daily run volume and duration trends for the last N days.

    Non-admin users only see runs for projects they have group access to.
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)
    runs = await _base_run_query(db, auth.user, auth, project=project, since=since, is_cicd=is_cicd)

    by_day: dict[str, list[Run]] = {}
    for r in runs:
        if r.created_at is None:
            continue
        day_key = r.created_at.strftime("%Y-%m-%d")
        by_day.setdefault(day_key, []).append(r)

    runs_by_day: list[RunsByDay] = []
    for i in range(days - 1, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
        day_runs = by_day.get(day, [])
        pass_count = sum(1 for r in day_runs if r.score >= 80)
        runs_by_day.append(
            RunsByDay(
                day=day,
                count=len(day_runs),
                passCount=pass_count,
                failCount=len(day_runs) - pass_count,
            )
        )

    durations = [_run_duration_ms(r) for r in runs if _run_duration_ms(r) > 0]
    if durations:
        avg_ms = round(sum(durations) / len(durations))
        min_ms = min(durations)
        max_ms = max(durations)
    else:
        avg_ms = min_ms = max_ms = 0

    return Envelope(
        data=PipelineTrends(
            runsByDay=runs_by_day,
            durationStats=DurationStats(
                avg=avg_ms,
                min=min_ms,
                max=max_ms,
                avgLabel=_format_duration(avg_ms),
                minLabel=_format_duration(min_ms),
                maxLabel=_format_duration(max_ms),
            ),
        )
    )
