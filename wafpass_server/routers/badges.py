"""Live status badge endpoints — SVG badges for READMEs and external dashboards.

Live (public, no auth):
  GET /public/badge/{project}.svg                     → dynamic SVG, single-tenant mode only
  GET /public/badge/{project}/download                → same, as an attachment
  GET /public/badge/{project}/json                     → JSON status
  GET /public/badge/m/{mandant_slug}/{project}.svg      → dynamic SVG, multi-mandant mode
  GET /public/badge/m/{mandant_slug}/{project}/download → same, as an attachment
  GET /public/badge/m/{mandant_slug}/{project}/json     → JSON status
  GET /public/badge/static/{tier}.svg                   → pre-rendered static badge by tier level
                                                          (for air-gapped / non-public deployments)

Multi-mandant decision (Phase 4 — was tracked as unresolved through
Phases 1-3, decided here): the bare `{project}` routes are keyed by
project *name*, not a secret token, so they can't use the same
public_lookup_token RLS carve-out as evidence/widgets/validations (that
pattern only works for an unguessable secret — a project name is
guessable by design, these badges are meant to be linked from a public
README). Once multi-mandant mode is active, a bare project name has no
way to say *which* mandate's "my-app" to show if more than one has a
project with that name — so the bare routes become a clear, actionable
error in multi-mandant mode (never a silent 404 or misleading "No Data"),
and the new `/m/{mandant_slug}/{project}...` routes are the one correct
way to embed a badge once multi-mandant mode is active. A mandate's slug
is not a secret (same trust model single-tenant badges already had: these
URLs are meant to be publicly embeddable, nothing about multi-mandant mode
makes that worse) — it's resolved via `mandants` (never RLS-protected,
same as `controls`/`control_packs`) and then the *same* generic `runs`
policy already handles isolation once the resolved mandate is adopted
into the session (the same pattern already used in widgets.py).

The `/m/` segment is a deliberate, permanent disambiguator — not just an
ordering trick against the existing `static` route below. A holding_admin
could legitimately name a mandate "static" (MandantCreate doesn't forbid
it), which would otherwise collide with `/public/badge/static/{tier}.svg`.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import adopt_mandate_of, get_instance_mode
from wafpass_server.database import get_db
from wafpass_server.models import Mandant, Run

router = APIRouter(tags=["badges"])


_MULTI_MANDANT_BARE_ROUTE_ERROR = (
    "This instance is in multi-mandant mode. A bare project-name badge URL can no "
    "longer say which mandate's project to show. Use "
    "/public/badge/m/{{mandant_slug}}/{project}.svg instead."
)


async def _require_single_tenant_or_explain(db: AsyncSession, project: str) -> None:
    mode = await get_instance_mode(db)
    if mode == "multi_mandant":
        raise HTTPException(status_code=409, detail=_MULTI_MANDANT_BARE_ROUTE_ERROR.format(project=project))


async def _resolve_mandant_slug_or_404(db: AsyncSession, mandant_slug: str) -> None:
    """Resolve *mandant_slug* and adopt it into this session's RLS context.

    404s on an unknown/inactive slug rather than distinguishing "no such
    mandate" from "no such project" — same reasoning as every other public
    lookup in this codebase: don't give an anonymous caller a way to probe
    which slugs exist.
    """
    result = await db.execute(select(Mandant).where(Mandant.slug == mandant_slug, Mandant.is_active.is_(True)))
    mandant = result.scalar_one_or_none()
    if mandant is None:
        raise HTTPException(status_code=404, detail="Not found.")
    await adopt_mandate_of(db, mandant.id)

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


async def _latest_score(db: AsyncSession, project: str) -> int | None:
    result = await db.execute(
        select(Run.score)
        .where(Run.project == project)
        .order_by(Run.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


def _svg_for_score(score: int | None) -> str:
    if score is None:
        _, _, label, color = _NO_DATA
        value_text = "No Data"
    else:
        level, _, label, color = _tier_for_score(score)
        value_text = f"L{level} · {label}"
    return _make_svg(value_text, color)


@router.get("/public/badge/{project}.svg", response_class=Response)
async def live_badge(
    project: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    style: str = Query(default="flat"),
) -> Response:
    """Return a shields.io-style SVG badge reflecting the project's latest maturity tier.

    Single-tenant mode only — see module docstring for the multi-mandant
    `/m/{mandant_slug}/...` routes below.
    """
    await _require_single_tenant_or_explain(db, project)
    score = await _latest_score(db, project)
    return Response(content=_svg_for_score(score), headers=_LIVE_HEADERS)


@router.get("/public/badge/m/{mandant_slug}/{project}.svg", response_class=Response)
async def live_badge_scoped(
    mandant_slug: str,
    project: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    style: str = Query(default="flat"),
) -> Response:
    """Mandate-qualified equivalent of `live_badge`, for multi-mandant mode."""
    await _resolve_mandant_slug_or_404(db, mandant_slug)
    score = await _latest_score(db, project)
    return Response(content=_svg_for_score(score), headers=_LIVE_HEADERS)


@router.get("/public/badge/{project}/download", response_class=Response)
async def download_badge(
    project: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    """Same as the live badge but served with Content-Disposition: attachment.

    Use this when the WAF++ server is not publicly accessible — download the
    SVG and commit it alongside your README. Single-tenant mode only.
    """
    await _require_single_tenant_or_explain(db, project)
    score = await _latest_score(db, project)
    return Response(content=_svg_for_score(score), headers=_download_headers(project))


@router.get("/public/badge/m/{mandant_slug}/{project}/download", response_class=Response)
async def download_badge_scoped(
    mandant_slug: str,
    project: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    """Mandate-qualified equivalent of `download_badge`, for multi-mandant mode."""
    await _resolve_mandant_slug_or_404(db, mandant_slug)
    score = await _latest_score(db, project)
    return Response(content=_svg_for_score(score), headers=_download_headers(project))


def _download_headers(project: str) -> dict[str, str]:
    filename = f"wafpass-badge-{project.replace('/', '_')}.svg"
    return {
        "Content-Type": "image/svg+xml",
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
    }


async def _badge_json_payload(db: AsyncSession, project: str, badge_url: str) -> dict:
    result = await db.execute(
        select(Run.score, Run.created_at)
        .where(Run.project == project)
        .order_by(Run.created_at.desc())
        .limit(1)
    )
    row = result.first()

    if row is None:
        return {
            "project": project, "tier_level": 0, "tier_label": "No Data",
            "score": None, "color": "#64748b", "updated_at": None,
            # shields.io endpoint badge schema (https://shields.io/endpoint)
            "schemaVersion": 1, "label": "WAF++ PASS",
            "message": "no data", "namedLogo": "amazonaws",
        }

    score, updated_at = row
    level, _, label, color = _tier_for_score(score)
    return {
        "project": project,
        "tier_level": level,
        "tier_label": label,
        "score": score,
        "color": color,
        "badge_url": badge_url,
        "updated_at": updated_at.isoformat() if updated_at else None,
        # shields.io endpoint badge schema (https://shields.io/endpoint)
        "schemaVersion": 1,
        "label": "WAF++ PASS",
        "message": f"L{level} · {label}",
        "color": color.lstrip("#"),
    }


@router.get("/public/badge/{project}/json")
async def badge_json(
    project: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> JSONResponse:
    """JSON status endpoint — useful for custom badge renderers or CI scripts.

    Single-tenant mode only.
    """
    await _require_single_tenant_or_explain(db, project)
    payload = await _badge_json_payload(db, project, f"/public/badge/{project}.svg")
    return JSONResponse(content=payload, headers={"Cache-Control": "no-cache, max-age=300"})


@router.get("/public/badge/m/{mandant_slug}/{project}/json")
async def badge_json_scoped(
    mandant_slug: str,
    project: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> JSONResponse:
    """Mandate-qualified equivalent of `badge_json`, for multi-mandant mode."""
    await _resolve_mandant_slug_or_404(db, mandant_slug)
    payload = await _badge_json_payload(db, project, f"/public/badge/m/{mandant_slug}/{project}.svg")
    return JSONResponse(content=payload, headers={"Cache-Control": "no-cache, max-age=300"})


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
