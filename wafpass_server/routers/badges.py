"""Live status badge endpoints — SVG badges for READMEs and external dashboards.

Live (public, no auth):
  GET /public/badge/{project}.svg          → dynamic SVG reflecting latest run
  GET /public/badge/{project}/download     → same SVG with Content-Disposition: attachment
  GET /public/badge/{project}/json         → JSON status for custom integrations
  GET /public/badge/static/{tier}.svg      → pre-rendered static badge by tier level
                                             (for air-gapped / non-public deployments)
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.database import get_db
from wafpass_server.models import Run

router = APIRouter(tags=["badges"])

# ── Tier metadata ─────────────────────────────────────────────────────────────

_TIERS: list[tuple[int, int, str, str]] = [
    # (level, min_score, label, hex_color)
    (5, 90, "Excellence", "#059669"),
    (4, 75, "Optimized",  "#7c3aed"),
    (3, 60, "Governed",   "#0891b2"),
    (2, 40, "Operational","#0094FF"),
    (1,  0, "Foundational","#d97706"),
]

_NO_DATA = (0, 0, "No Data", "#64748b")


def _tier_for_score(score: int) -> tuple[int, int, str, str]:
    for tier in _TIERS:
        if score >= tier[1]:
            return tier
    return _TIERS[-1]


# ── SVG generation ────────────────────────────────────────────────────────────

# Approximate per-character width in px for Verdana 11 (used for badge sizing).
_CHAR_W = 6.2
_PAD = 10  # horizontal padding per side


def _text_width(text: str) -> int:
    return int(len(text) * _CHAR_W + _PAD * 2)


def _make_svg(
    value_text: str,
    color: str,
    label: str = "WAF++ PASS",
    accessible_title: str | None = None,
) -> str:
    lw = _text_width(label)
    vw = _text_width(value_text)
    tw = lw + vw
    lcx = lw // 2
    vcx = lw + vw // 2
    title = accessible_title or f"{label}: {value_text}"

    # Encode special chars in SVG text
    def _esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    return f"""\
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"\
 width="{tw}" height="20" role="img" aria-label="{_esc(title)}">
  <title>{_esc(title)}</title>
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


# ── Cache headers ─────────────────────────────────────────────────────────────

_LIVE_HEADERS = {
    "Content-Type": "image/svg+xml",
    "Cache-Control": "no-cache, max-age=300",  # 5-minute TTL
    # Prevent GitHub's camo proxy from caching stale badges
    "Surrogate-Control": "no-store",
    "Pragma": "no-cache",
}

_STATIC_HEADERS = {
    "Content-Type": "image/svg+xml",
    "Cache-Control": "public, max-age=31536000, immutable",
}


# ── Live badge ────────────────────────────────────────────────────────────────


@router.get("/public/badge/{project}.svg", response_class=Response)
async def live_badge(
    project: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    style: str = Query(default="flat"),
) -> Response:
    """Return a shields.io-style SVG badge reflecting the project's latest maturity tier."""
    result = await db.execute(
        select(Run.score)
        .where(Run.project == project)
        .order_by(Run.created_at.desc())
        .limit(1)
    )
    row = result.scalar_one_or_none()

    if row is None:
        level, _, label, color = _NO_DATA
        value_text = "No Data"
    else:
        level, _, label, color = _tier_for_score(row)
        value_text = f"L{level} · {label}"

    svg = _make_svg(value_text, color)
    return Response(content=svg, headers=_LIVE_HEADERS)


@router.get("/public/badge/{project}/download", response_class=Response)
async def download_badge(
    project: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    """Same as the live badge but served with Content-Disposition: attachment.

    Use this when the WAF++ server is not publicly accessible — download the
    SVG and commit it alongside your README.
    """
    result = await db.execute(
        select(Run.score)
        .where(Run.project == project)
        .order_by(Run.created_at.desc())
        .limit(1)
    )
    row = result.scalar_one_or_none()

    if row is None:
        level, _, label, color = _NO_DATA
        value_text = "No Data"
    else:
        level, _, label, color = _tier_for_score(row)
        value_text = f"L{level} · {label}"

    svg = _make_svg(value_text, color)
    filename = f"wafpass-badge-{project.replace('/', '_')}.svg"
    headers = {
        "Content-Type": "image/svg+xml",
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
    }
    return Response(content=svg, headers=headers)


@router.get("/public/badge/{project}/json")
async def badge_json(
    project: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> JSONResponse:
    """JSON status endpoint — useful for custom badge renderers or CI scripts."""
    result = await db.execute(
        select(Run.score, Run.created_at)
        .where(Run.project == project)
        .order_by(Run.created_at.desc())
        .limit(1)
    )
    row = result.first()

    if row is None:
        return JSONResponse(
            content={
                "project": project, "tier_level": 0, "tier_label": "No Data",
                "score": None, "color": "#64748b", "updated_at": None,
                # shields.io endpoint badge schema (https://shields.io/endpoint)
                "schemaVersion": 1, "label": "WAF++ PASS",
                "message": "no data", "namedLogo": "amazonaws",
            },
            headers={"Cache-Control": "no-cache, max-age=300"},
        )

    score, updated_at = row
    level, _, label, color = _tier_for_score(score)
    return JSONResponse(
        content={
            "project": project,
            "tier_level": level,
            "tier_label": label,
            "score": score,
            "color": color,
            "badge_url": f"/public/badge/{project}.svg",
            "updated_at": updated_at.isoformat() if updated_at else None,
            # shields.io endpoint badge schema (https://shields.io/endpoint)
            "schemaVersion": 1,
            "label": "WAF++ PASS",
            "message": f"L{level} · {label}",
            "color": color.lstrip("#"),
        },
        headers={"Cache-Control": "no-cache, max-age=300"},
    )


# ── Static per-tier badges (for offline / air-gapped use) ────────────────────

_STATIC_TIERS: dict[int, tuple[str, str]] = {
    1: ("L1 · Foundational", "#d97706"),
    2: ("L2 · Operational",  "#0094FF"),
    3: ("L3 · Governed",     "#0891b2"),
    4: ("L4 · Optimized",    "#7c3aed"),
    5: ("L5 · Excellence",   "#059669"),
}


@router.get("/public/badge/static/{tier_level}.svg", response_class=Response)
async def static_badge(tier_level: int) -> Response:
    """Pre-rendered badge for a specific tier level — no database query.

    Download these and commit to your repo when the WAF++ server is
    not publicly accessible (CI systems, air-gapped environments, etc.).
    """
    meta = _STATIC_TIERS.get(tier_level)
    if meta is None:
        svg = _make_svg("Unknown", "#64748b")
    else:
        value_text, color = meta
        svg = _make_svg(value_text, color)
    return Response(content=svg, headers=_STATIC_HEADERS)
