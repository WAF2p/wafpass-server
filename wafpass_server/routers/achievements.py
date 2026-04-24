"""Verified achievement endpoints — maturity tier milestones with public verification."""
from __future__ import annotations

import secrets
from textwrap import dedent
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import require_role
from wafpass_server.database import get_db
from wafpass_server.models import ProjectAchievement, Run, User
from wafpass_server.schemas import AchievementOut

router = APIRouter(tags=["achievements"])

# ── Tier definitions (must match UI thresholds in SettingsPage.tsx) ───────────

TIER_THRESHOLDS: list[tuple[int, int, str]] = [
    (1,  0, "Foundational"),
    (2, 40, "Operational"),
    (3, 60, "Governed"),
    (4, 75, "Optimized"),
    (5, 90, "Excellence"),
]

TIER_COLORS: dict[int, str] = {
    1: "#d97706",
    2: "#0094FF",
    3: "#0891b2",
    4: "#7c3aed",
    5: "#059669",
}


def tier_for_score(score: int) -> int:
    """Return the highest tier level the score qualifies for (1–5)."""
    level = 1
    for lvl, threshold, _ in TIER_THRESHOLDS:
        if score >= threshold:
            level = lvl
    return level


# ── Achievement evaluation (called from POST /runs) ───────────────────────────


async def evaluate_and_record_achievements(db: AsyncSession, run: Run) -> list[ProjectAchievement]:
    """Create achievement records for any tier the project reaches for the first time."""
    if not run.project:
        return []

    # Which tiers does this run qualify for?
    qualifying_levels = {lvl for lvl, threshold, _ in TIER_THRESHOLDS if run.score >= threshold}

    # Which tiers already have records for this project?
    existing = await db.execute(
        select(ProjectAchievement.tier_level).where(ProjectAchievement.project == run.project)
    )
    already_achieved = {row[0] for row in existing.all()}

    new_levels = qualifying_levels - already_achieved
    if not new_levels:
        return []

    new_achievements: list[ProjectAchievement] = []
    for lvl in sorted(new_levels):
        _, _, label = next(t for t in TIER_THRESHOLDS if t[0] == lvl)
        achievement = ProjectAchievement(
            project=run.project,
            tier_level=lvl,
            tier_label=label,
            score=run.score,
            run_id=run.id,
            verification_token=secrets.token_urlsafe(32),
            snapshot_jsonb=run.pillar_scores or {},
        )
        db.add(achievement)
        new_achievements.append(achievement)

    await db.commit()
    for a in new_achievements:
        await db.refresh(a)

    return new_achievements


# ── Authenticated endpoints ───────────────────────────────────────────────────


@router.get("/achievements", response_model=list[AchievementOut])
async def list_achievements(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
    project: str | None = Query(default=None),
) -> list[ProjectAchievement]:
    stmt = select(ProjectAchievement).order_by(
        ProjectAchievement.project, ProjectAchievement.tier_level
    )
    if project:
        stmt = stmt.where(ProjectAchievement.project == project)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/achievements/{project}", response_model=list[AchievementOut])
async def list_project_achievements(
    project: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
) -> list[ProjectAchievement]:
    result = await db.execute(
        select(ProjectAchievement)
        .where(ProjectAchievement.project == project)
        .order_by(ProjectAchievement.tier_level)
    )
    return list(result.scalars().all())


# ── Public verification endpoint ──────────────────────────────────────────────


@router.get("/public/achievements/{token}", response_class=HTMLResponse)
async def verify_achievement(
    token: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> HTMLResponse:
    result = await db.execute(
        select(ProjectAchievement).where(ProjectAchievement.verification_token == token)
    )
    achievement: ProjectAchievement | None = result.scalar_one_or_none()
    if achievement is None:
        raise HTTPException(status_code=404, detail="Achievement not found")

    color = TIER_COLORS.get(achievement.tier_level, "#0094FF")
    achieved_date = achievement.achieved_at.strftime("%B %d, %Y at %H:%M UTC")

    pillar_rows = ""
    for pillar, score in (achievement.snapshot_jsonb or {}).items():
        bar_color = "#059669" if score >= 80 else "#d97706" if score >= 60 else "#DA2C38"
        pillar_rows += f"""
        <tr>
          <td style="padding:0.5rem 1rem;color:#94a3b8;text-transform:capitalize">{pillar}</td>
          <td style="padding:0.5rem 1rem">
            <div style="display:flex;align-items:center;gap:0.75rem">
              <div style="flex:1;height:8px;background:#1e293b;border-radius:999px;overflow:hidden">
                <div style="height:100%;width:{score}%;background:{bar_color};border-radius:999px"></div>
              </div>
              <span style="font-size:0.8rem;font-weight:700;color:{bar_color};min-width:2.5rem;text-align:right">{score}</span>
            </div>
          </td>
        </tr>"""

    html = dedent(f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
          <title>WAF++ PASS — Verified Achievement · {achievement.tier_label}</title>
          <style>
            *{{box-sizing:border-box;margin:0;padding:0}}
            body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0b1220;color:#e2e8f0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:2rem 1rem}}
            .card{{background:#111827;border:1px solid {color}44;border-radius:20px;padding:2.5rem 2rem;max-width:600px;width:100%;box-shadow:0 0 60px {color}18}}
            .badge{{width:80px;height:80px;border-radius:50%;background:{color}18;border:3px solid {color};display:flex;align-items:center;justify-content:center;font-size:1.5rem;font-weight:900;color:{color};margin:0 auto 1.5rem;letter-spacing:-1px}}
            .tier-label{{text-align:center;font-size:1.5rem;font-weight:900;color:{color};margin-bottom:0.4rem}}
            .project-name{{text-align:center;font-size:1rem;color:#94a3b8;margin-bottom:0.25rem}}
            .achieved-date{{text-align:center;font-size:0.78rem;color:#64748b;margin-bottom:2rem}}
            .score-circle{{width:70px;height:70px;border-radius:50%;background:{color}14;border:2.5px solid {color};display:flex;flex-direction:column;align-items:center;justify-content:center;margin:0 auto 2rem}}
            .score-value{{font-size:1.4rem;font-weight:900;color:{color};line-height:1}}
            .score-sub{{font-size:0.55rem;color:#64748b;text-transform:uppercase;letter-spacing:0.05em}}
            table{{width:100%;border-collapse:collapse;margin-bottom:1.5rem}}
            .section-title{{font-size:0.65rem;text-transform:uppercase;letter-spacing:0.08em;color:#64748b;font-weight:700;margin-bottom:0.75rem}}
            .token-box{{background:#0b1220;border:1px solid #1e293b;border-radius:10px;padding:0.75rem 1rem;font-family:monospace;font-size:0.72rem;color:#64748b;word-break:break-all;margin-bottom:1.5rem}}
            .footer{{text-align:center;font-size:0.68rem;color:#334155;margin-top:1.5rem}}
            .verified-pill{{display:inline-flex;align-items:center;gap:0.4rem;background:{color}12;border:1px solid {color}35;border-radius:999px;padding:0.3rem 0.75rem;font-size:0.72rem;font-weight:700;color:{color};margin:0 auto 1.75rem;display:flex;width:fit-content}}
          </style>
        </head>
        <body>
          <div class="card">
            <div class="badge">L{achievement.tier_level}</div>
            <div class="tier-label">{achievement.tier_label}</div>
            <div class="project-name">{achievement.project}</div>
            <div class="achieved-date">Achieved on {achieved_date}</div>

            <div class="verified-pill">
              <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5"
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0
                  01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622
                  5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
              </svg>
              Cryptographically Verified · WAF++ PASS
            </div>

            <div class="score-circle">
              <span class="score-value">{achievement.score}</span>
              <span class="score-sub">score</span>
            </div>

            <div class="section-title">Pillar Scores at Achievement</div>
            <table>{pillar_rows}</table>

            <div class="section-title">Verification Token</div>
            <div class="token-box">{token}</div>

            <div class="footer">
              This page is publicly accessible and serves as proof of excellence.<br/>
              Generated by <strong style="color:#475569">WAF++ PASS</strong> · Infrastructure Security Posture Platform
            </div>
          </div>
        </body>
        </html>
    """).strip()

    return HTMLResponse(content=html)
