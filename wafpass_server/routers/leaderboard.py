"""Hall of Fame leaderboard — top sovereign and most improved projects."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select

from wafpass_server.schemas import Envelope
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import AuthContext, bypasses_group_scoping, get_auth_context, get_scoped_db, require_role
from wafpass_server.models import ProjectAchievement, ProjectGroup, ProjectPassport, User, UserGroup

router = APIRouter(tags=["leaderboard"])


async def _accessible_projects(db: AsyncSession, user: User, auth: AuthContext) -> set[str] | None:
    """Return the projects a group-scoped user can see, or None when no group filter applies."""
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

TIER_LABELS: dict[int, str] = {
    1: "Foundational", 2: "Operational", 3: "Governed", 4: "Optimized", 5: "Excellence"
}


class LeaderboardEntry(BaseModel):
    project: str
    display_name: str | None = None
    owner: str | None = None
    owner_team: str | None = None
    score: int
    tier_level: int
    tier_label: str
    achieved_at: datetime
    days_held: int
    tiers_gained: int | None = None


class LeaderboardOut(BaseModel):
    top_sovereign: list[LeaderboardEntry]
    most_improved: list[LeaderboardEntry]


@router.get("/leaderboard", response_model=Envelope[LeaderboardOut])
async def get_leaderboard(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    user: Annotated[User, Depends(require_role("clevel"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> Envelope[LeaderboardOut]:
    now = datetime.now(timezone.utc)
    thirty_days_ago = now - timedelta(days=30)

    accessible = await _accessible_projects(db, user, auth)
    if accessible is not None and not accessible:
        return Envelope(data=LeaderboardOut(top_sovereign=[], most_improved=[]))

    # ── Top Sovereign: projects holding Tier 5 the longest ───────────────────
    sovereign_stmt = (
        select(ProjectAchievement)
        .where(ProjectAchievement.tier_level == 5)
        .order_by(ProjectAchievement.achieved_at.asc())
        .limit(10)
    )
    if accessible is not None:
        sovereign_stmt = sovereign_stmt.where(ProjectAchievement.project.in_(accessible))
    sovereign_result = await db.execute(sovereign_stmt)
    sovereign_rows = list(sovereign_result.scalars().all())

    # ── Most Improved: projects gaining most tiers in last 30 days ───────────
    improved_counts_stmt = (
        select(ProjectAchievement.project, func.count(ProjectAchievement.id).label("cnt"))
        .where(ProjectAchievement.achieved_at >= thirty_days_ago)
        .group_by(ProjectAchievement.project)
        .order_by(func.count(ProjectAchievement.id).desc())
        .limit(10)
    )
    if accessible is not None:
        improved_counts_stmt = improved_counts_stmt.where(ProjectAchievement.project.in_(accessible))
    improved_counts_result = await db.execute(improved_counts_stmt)
    improved_counts = improved_counts_result.all()  # [(project, cnt), ...]
    improved_project_names = {r[0] for r in improved_counts}

    # ── Bulk-load passports ───────────────────────────────────────────────────
    all_projects = {r.project for r in sovereign_rows} | improved_project_names
    passports: dict[str, ProjectPassport] = {}
    if all_projects:
        pp_result = await db.execute(
            select(ProjectPassport).where(ProjectPassport.project.in_(all_projects))
        )
        passports = {pp.project: pp for pp in pp_result.scalars().all()}

    # ── Highest achievement per improved project (single query) ──────────────
    top_ach_per_project: dict[str, ProjectAchievement] = {}
    if improved_project_names:
        max_tier_subq = (
            select(
                ProjectAchievement.project,
                func.max(ProjectAchievement.tier_level).label("max_tier"),
            )
            .where(ProjectAchievement.project.in_(improved_project_names))
            .group_by(ProjectAchievement.project)
            .subquery()
        )
        top_ach_result = await db.execute(
            select(ProjectAchievement).join(
                max_tier_subq,
                (ProjectAchievement.project == max_tier_subq.c.project)
                & (ProjectAchievement.tier_level == max_tier_subq.c.max_tier),
            )
        )
        top_ach_per_project = {a.project: a for a in top_ach_result.scalars().all()}

    # ── Build top_sovereign ───────────────────────────────────────────────────
    top_sovereign: list[LeaderboardEntry] = []
    for row in sovereign_rows:
        pp = passports.get(row.project)
        achieved = row.achieved_at
        if achieved.tzinfo is None:
            achieved = achieved.replace(tzinfo=timezone.utc)
        top_sovereign.append(LeaderboardEntry(
            project=row.project,
            display_name=pp.display_name if pp else None,
            owner=pp.owner if pp else None,
            owner_team=pp.owner_team if pp else None,
            score=row.score,
            tier_level=row.tier_level,
            tier_label=row.tier_label,
            achieved_at=row.achieved_at,
            days_held=(now - achieved).days,
        ))

    # ── Build most_improved ───────────────────────────────────────────────────
    improved_count_map = {r[0]: r[1] for r in improved_counts}
    most_improved: list[LeaderboardEntry] = []
    for project, _ in improved_counts:
        ach = top_ach_per_project.get(project)
        if not ach:
            continue
        pp = passports.get(project)
        achieved = ach.achieved_at
        if achieved.tzinfo is None:
            achieved = achieved.replace(tzinfo=timezone.utc)
        most_improved.append(LeaderboardEntry(
            project=project,
            display_name=pp.display_name if pp else None,
            owner=pp.owner if pp else None,
            owner_team=pp.owner_team if pp else None,
            score=ach.score,
            tier_level=ach.tier_level,
            tier_label=ach.tier_label,
            achieved_at=ach.achieved_at,
            days_held=(now - achieved).days,
            tiers_gained=improved_count_map[project],
        ))

    return Envelope(data=LeaderboardOut(top_sovereign=top_sovereign, most_improved=most_improved))
