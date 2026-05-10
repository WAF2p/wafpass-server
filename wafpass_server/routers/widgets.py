"""Widget management endpoints — create and manage dashboards for compliance data display.

Widgets allow you to create authenticated endpoints that feed data to displays,
computers, TVs, or web pages. Each widget has a unique token for authentication
and can be configured to show specific projects, data types, and refresh intervals.

Public endpoints (no auth required):
  GET /widget/p/{token}.json      → JSON data for the widget
  GET /widget/p/{token}/badge.svg → SVG badge for the widget

Authenticated endpoints (admin or engineer role required):
  POST /widgets                     → Create a new widget
  GET /widgets                      → List all widgets
  GET /widgets/{id}                 → Get widget details
  PUT /widgets/{id}                 → Update a widget
  DELETE /widgets/{id}              → Delete a widget
  GET /widget/{id}/data             → Get widget data (internal use)
"""
from __future__ import annotations

import secrets
import uuid
from typing import Any, Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import require_role
from wafpass_server.database import get_db
from wafpass_server.models import Widget, User, Run
from wafpass_server.schemas import WidgetConfig, WidgetCreate, WidgetOut

router = APIRouter(tags=["widgets"])

# ── Tier metadata for badges ──────────────────────────────────────────────────

_TIER_COLORS: dict[int, str] = {
    5: "#059669",  # Excellence
    4: "#7c3aed",  # Optimized
    3: "#0891b2",  # Governed
    2: "#0094FF",  # Operational
    1: "#d97706",  # Foundational
}

_TIER_LABELS: dict[int, str] = {
    5: "Excellence",
    4: "Optimized",
    3: "Governed",
    2: "Operational",
    1: "Foundational",
}


def _tier_for_score(score: int) -> tuple[int, str, str]:
    """Return tier level, label, and color for a score."""
    if score >= 90:
        return 5, _TIER_LABELS[5], _TIER_COLORS[5]
    if score >= 75:
        return 4, _TIER_LABELS[4], _TIER_COLORS[4]
    if score >= 60:
        return 3, _TIER_LABELS[3], _TIER_COLORS[3]
    if score >= 40:
        return 2, _TIER_LABELS[2], _TIER_COLORS[2]
    if score >= 0:
        return 1, _TIER_LABELS[1], _TIER_COLORS[1]
    return 0, "No Data", "#64748b"


# ── SVG generation helpers ────────────────────────────────────────────────────

_CHAR_W = 6.2
_PAD = 10


def _text_width(text: str) -> int:
    return int(len(text) * _CHAR_W + _PAD * 2)


def _make_svg(value_text: str, color: str, label: str = "WAF++ PASS") -> str:
    lw = _text_width(label)
    vw = _text_width(value_text)
    tw = lw + vw
    lcx = lw // 2
    vcx = lw + vw // 2

    def _esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    return f"""\
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"\
 width="{tw}" height="20" role="img" aria-label="{_esc(label)}">
  <title>{_esc(label)}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="{tw}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{lw}" height="20" fill="#555"/>
    <rect x="{lw}" width="{vw}" height="20" fill="{color}"/>
    <rect width="{tw}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle"\
 font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{lcx}" y="15" fill="#010101" fill-opacity=".3">{_esc(label)}</text>
    <text x="{lcx}" y="14">{_esc(label)}</text>
    <text x="{vcx}" y="15" fill="#010101" fill-opacity=".3">{_esc(value_text)}</text>
    <text x="{vcx}" y="14">{_esc(value_text)}</text>
  </g>
</svg>"""


# ── Public widget endpoints (no auth required) ────────────────────────────────


@router.get("/widget/p/{token}.json")
async def widget_public_data(
    token: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    projects: Annotated[list[str] | None, Query(description="Limit results to these project names")] = None,
) -> JSONResponse:
    """Return JSON data for a public widget. No authentication required.

    Use this endpoint to power dashboards on computers, TVs, or web pages.
    The widget token authenticates access to the data.

    By default all projects are returned (latest run per project). Pass one or
    more ``?projects=name`` query parameters to restrict the result.  The
    widget's own config ``projects`` list is used as a fallback filter when no
    query parameter is provided.

    Returns:
        {
            "token": "widget-token",
            "name": "Widget Name",
            "data": {
                "score": 85,
                "tier_level": 4,
                "tier_label": "Optimized",
                "projects": [...],
                "pillar_scores": {...},
                "last_run_at": "2026-01-15T10:30:00Z"
            }
        }
    """
    result = await db.execute(select(Widget).where(Widget.token == token))
    widget: Widget | None = result.scalar_one_or_none()

    if widget is None:
        raise HTTPException(status_code=404, detail="Widget not found")

    if not widget.is_active:
        raise HTTPException(status_code=403, detail="Widget is disabled")

    # Update last accessed timestamp
    widget.last_accessed_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    await db.commit()

    project_filter: list[str] = projects or []

    # Single query: latest run per project (optionally filtered)
    latest_sq = select(
        Run.project.label("project"),
        func.max(Run.created_at).label("max_created_at"),
    ).group_by(Run.project)
    if project_filter:
        latest_sq = latest_sq.where(Run.project.in_(project_filter))
    latest_sq = latest_sq.subquery()

    runs_result = await db.execute(
        select(Run.project, Run.score, Run.pillar_scores, Run.created_at)
        .join(latest_sq, (Run.project == latest_sq.c.project) & (Run.created_at == latest_sq.c.max_created_at))
        .order_by(Run.project)
    )
    runs = runs_result.all()

    score = 0
    pillar_scores: dict = {}
    last_run_at = None
    project_data = []

    for run in runs:
        project_data.append({
            "project": run.project,
            "score": run.score,
            "pillar_scores": run.pillar_scores,
            "last_run_at": run.created_at.isoformat() if run.created_at else None,
        })
        if run.score > score:
            score = run.score
            pillar_scores = run.pillar_scores
            last_run_at = run.created_at

    level, label, color = _tier_for_score(score)

    return JSONResponse(
        content={
            "token": token,
            "name": widget.name,
            "data": {
                "score": score,
                "tier_level": level,
                "tier_label": label,
                "tier_color": color,
                "projects": project_data,
                "pillar_scores": pillar_scores,
                "last_run_at": last_run_at.isoformat() if last_run_at else None,
            },
        },
        headers={"Cache-Control": "no-cache, max-age=300"},
    )


@router.get("/widget/p/{token}/badge.svg", response_class=Response)
async def widget_public_badge(
    token: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    projects: Annotated[list[str] | None, Query(description="Limit results to these project names")] = None,
) -> Response:
    """Return an SVG badge for a public widget. No authentication required.

    Use this in READMEs or dashboards:
        ![WAF++ PASS](https://your-server.com/widget/p/abc123.svg)

    The badge reflects the best score across all projects (or the filtered set).
    """
    result = await db.execute(select(Widget).where(Widget.token == token))
    widget: Widget | None = result.scalar_one_or_none()

    if widget is None:
        raise HTTPException(status_code=404, detail="Widget not found")

    if not widget.is_active:
        raise HTTPException(status_code=403, detail="Widget is disabled")

    project_filter: list[str] = projects or []

    latest_sq = select(
        Run.project.label("project"),
        func.max(Run.created_at).label("max_created_at"),
    ).group_by(Run.project)
    if project_filter:
        latest_sq = latest_sq.where(Run.project.in_(project_filter))
    latest_sq = latest_sq.subquery()

    scores_result = await db.execute(
        select(Run.score)
        .join(latest_sq, (Run.project == latest_sq.c.project) & (Run.created_at == latest_sq.c.max_created_at))
    )
    rows = scores_result.scalars().all()
    score = max(rows) if rows else 0

    level, label, color = _tier_for_score(score)
    value_text = f"L{level} · {label}" if level > 0 else "No Data"

    svg = _make_svg(value_text, color)
    return Response(
        content=svg,
        headers={
            "Content-Type": "image/svg+xml",
            "Cache-Control": "no-cache, max-age=300",
        },
    )


# ── Authenticated widget management endpoints ─────────────────────────────────


@router.post("/widgets", response_model=WidgetOut)
async def create_widget(
    payload: WidgetCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("engineer"))],
) -> WidgetOut:
    """Create a new widget.

    Creates a widget with a unique authentication token. The token can be used
    to fetch data via the public `/widget/p/{token}.json` endpoint.

    Roles: engineer, admin
    """
    widget = Widget(
        name=payload.name,
        token=secrets.token_urlsafe(32),
        config=payload.config.model_dump() if hasattr(payload.config, "model_dump") else payload.config,
        is_active=True,
    )
    db.add(widget)
    await db.commit()
    await db.refresh(widget)
    return widget


@router.get("/widgets", response_model=list[WidgetOut])
async def list_widgets(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("engineer"))],
    is_active: bool | None = Query(default=None, description="Filter by active status"),
) -> list[WidgetOut]:
    """List all widgets.

    Roles: engineer, admin

    Query params:
        is_active: Filter by active status (true/false)
    """
    stmt = select(Widget).order_by(Widget.created_at.desc())

    if is_active is not None:
        stmt = stmt.where(Widget.is_active == is_active)

    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/widgets/{id}", response_model=WidgetOut)
async def get_widget(
    id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("engineer"))],
) -> WidgetOut:
    """Get widget details by ID.

    Roles: engineer, admin
    """
    result = await db.execute(select(Widget).where(Widget.id == id))
    widget = result.scalar_one_or_none()

    if widget is None:
        raise HTTPException(status_code=404, detail="Widget not found")

    return widget


@router.put("/widgets/{id}", response_model=WidgetOut)
async def update_widget(
    id: uuid.UUID,
    payload: WidgetCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("engineer"))],
) -> WidgetOut:
    """Update a widget.

    Roles: engineer, admin
    """
    result = await db.execute(select(Widget).where(Widget.id == id))
    widget = result.scalar_one_or_none()

    if widget is None:
        raise HTTPException(status_code=404, detail="Widget not found")

    widget.name = payload.name
    widget.config = payload.config.model_dump() if hasattr(payload.config, "model_dump") else payload.config
    widget.is_active = widget.config.get("is_active", widget.is_active) if isinstance(widget.config, dict) else widget.is_active

    await db.commit()
    await db.refresh(widget)
    return widget


@router.delete("/widgets/{id}")
async def delete_widget(
    id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("admin"))],
) -> dict[str, str]:
    """Delete a widget.

    Roles: admin only
    """
    result = await db.execute(select(Widget).where(Widget.id == id))
    widget = result.scalar_one_or_none()

    if widget is None:
        raise HTTPException(status_code=404, detail="Widget not found")

    await db.delete(widget)
    await db.commit()

    return {"message": "Widget deleted successfully"}


@router.get("/widget/{id}/data")
async def get_widget_data(
    id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("engineer"))],
) -> dict[str, Any]:
    """Get widget data for internal use (with full project details).

    Roles: engineer, admin
    """
    result = await db.execute(select(Widget).where(Widget.id == id))
    widget = result.scalar_one_or_none()

    if widget is None:
        raise HTTPException(status_code=404, detail="Widget not found")

    project_filter: list[str] = widget.config.get("projects", []) if isinstance(widget.config, dict) else []

    latest_sq = select(
        Run.project.label("project"),
        func.max(Run.created_at).label("max_created_at"),
    ).group_by(Run.project)
    if project_filter:
        latest_sq = latest_sq.where(Run.project.in_(project_filter))
    latest_sq = latest_sq.subquery()

    runs_result = await db.execute(
        select(Run.project, Run.score, Run.pillar_scores, Run.created_at)
        .join(latest_sq, (Run.project == latest_sq.c.project) & (Run.created_at == latest_sq.c.max_created_at))
        .order_by(Run.project)
    )
    runs = runs_result.all()

    score = 0
    pillar_scores: dict = {}
    last_run_at = None
    project_data = []

    for run in runs:
        project_data.append({
            "project": run.project,
            "score": run.score,
            "pillar_scores": run.pillar_scores,
            "last_run_at": run.created_at.isoformat() if run.created_at else None,
        })
        if run.score > score:
            score = run.score
            pillar_scores = run.pillar_scores
            last_run_at = run.created_at

    level, label, color = _tier_for_score(score)

    return {
        "token": widget.token,
        "name": widget.name,
        "data": {
            "score": score,
            "tier_level": level,
            "tier_label": label,
            "tier_color": color,
            "projects": project_data,
            "pillar_scores": pillar_scores,
            "last_run_at": last_run_at.isoformat() if last_run_at else None,
        },
    }
