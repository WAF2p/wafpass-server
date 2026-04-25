"""Evidence Locker — locked, immutable evidence packages for audit handouts."""
from __future__ import annotations

import hashlib
import io
import json
import secrets
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import require_role
from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import Evidence, Run, User
from wafpass_server.schemas import Envelope

router = APIRouter(tags=["evidence"])

# ── Optional QR code library ──────────────────────────────────────────────────

try:
    import segno
    _QR_AVAILABLE = True
except ImportError:
    _QR_AVAILABLE = False


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class EvidenceCreate(BaseModel):
    run_id: str
    title: str = ""
    note: str = ""
    prepared_by: str = ""
    organization: str = ""
    audit_period: str = ""
    frameworks: list[str] = []
    snapshot: dict = {}        # full frozen data sent by client
    report_html: str | None = None  # pre-rendered HTML (optional)


class EvidenceOut(BaseModel):
    id: str
    run_id: str
    title: str
    note: str
    project: str
    prepared_by: str
    organization: str
    audit_period: str
    frameworks: list[str]
    hash_digest: str
    public_token: str
    locked_by: str | None
    created_at: datetime | None = None

    model_config = {"from_attributes": True}

    @classmethod
    def from_row(cls, row: Evidence) -> "EvidenceOut":
        return cls(
            id=str(row.id),
            run_id=str(row.run_id),
            title=row.title,
            note=row.note,
            project=row.project,
            prepared_by=row.prepared_by,
            organization=row.organization,
            audit_period=row.audit_period,
            frameworks=row.frameworks or [],
            hash_digest=row.hash_digest,
            public_token=row.public_token,
            locked_by=str(row.locked_by) if row.locked_by else None,
            created_at=row.created_at,
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_base_url(request: Request) -> str:
    """Return the public base URL for building absolute links in QR codes.

    Uses WAFPASS_PUBLIC_URL if configured, otherwise falls back to the
    scheme + host of the incoming request (works for local dev; may differ
    behind a reverse proxy without WAFPASS_PUBLIC_URL set).
    """
    if settings.wafpass_public_url:
        return settings.wafpass_public_url.rstrip("/")
    # Build from request: respect X-Forwarded-Proto / X-Forwarded-Host if present
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or str(request.base_url.netloc)
    return f"{scheme}://{host}"


def _canonical_hash(snapshot: dict) -> str:
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _generate_token() -> str:
    return secrets.token_urlsafe(24)  # 32-char URL-safe string


def _qr_svg(url: str) -> bytes:
    if not _QR_AVAILABLE:
        return _fallback_qr_svg(url)
    buf = io.BytesIO()
    qr = segno.make(url, error="M")
    qr.save(buf, kind="svg", scale=3, border=2)
    return buf.getvalue()


def _fallback_qr_svg(url: str) -> bytes:
    """Return a plain SVG placeholder when segno is not installed."""
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">'
        '<rect width="200" height="200" fill="#f8fafc" stroke="#e2e8f0" stroke-width="2" rx="8"/>'
        '<text x="100" y="90" text-anchor="middle" font-family="monospace" font-size="11" fill="#64748b">QR unavailable</text>'
        '<text x="100" y="108" text-anchor="middle" font-family="monospace" font-size="9" fill="#94a3b8">pip install segno</text>'
        '</svg>'
    )
    return svg.encode()


_PUBLIC_HTML_WRAPPER = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{title} — WAF++ Evidence Package</title>
<style>
  :root {{ font-family: system-ui, sans-serif; --blue:#2563eb; }}
  body {{ margin:0; background:#f8fafc; }}
  .locker-banner {{
    background: linear-gradient(135deg,#1e293b 0%,#0f172a 100%);
    color:#f1f5f9; padding:16px 32px; display:flex; align-items:center; gap:16px;
    border-bottom:3px solid #2563eb;
  }}
  .locker-banner .badge {{
    display:inline-flex; align-items:center; gap:6px; padding:4px 12px;
    background:rgba(37,99,235,.3); border:1px solid rgba(37,99,235,.5);
    border-radius:999px; font-size:11px; font-weight:700; letter-spacing:.04em;
    color:#93c5fd; text-transform:uppercase;
  }}
  .locker-banner h1 {{ margin:0; font-size:15px; font-weight:700; color:#e2e8f0; }}
  .locker-banner .meta {{ font-size:11px; color:#94a3b8; margin-top:2px; }}
  .hash-strip {{
    background:#1e293b; color:#64748b; font-family:monospace; font-size:10px;
    padding:6px 32px; letter-spacing:.06em; border-bottom:1px solid #334155;
  }}
  .hash-strip strong {{ color:#94a3b8; }}
  .content {{ max-width:1100px; margin:0 auto; padding:24px 32px; }}
  @media print {{ .locker-banner,.hash-strip {{ display:none; }} }}
</style>
</head>
<body>
<div class="locker-banner">
  <svg width="24" height="24" fill="none" stroke="#60a5fa" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
      d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
  </svg>
  <div>
    <div class="badge">&#x1F512; Locked Evidence Package</div>
    <h1>{title}</h1>
    <div class="meta">Locked {locked_at} &nbsp;·&nbsp; {organization} &nbsp;·&nbsp; Prepared by {prepared_by}</div>
  </div>
</div>
<div class="hash-strip">
  <strong>SHA-256:</strong>&nbsp;{hash_digest} &nbsp;&nbsp;
  <strong>Package ID:</strong>&nbsp;{evidence_id}
</div>
<div class="content">
{body}
</div>
</body>
</html>
"""


# ── CRUD endpoints ────────────────────────────────────────────────────────────

@router.post("/evidence", response_model=Envelope[EvidenceOut], status_code=201)
async def create_evidence(
    payload: EvidenceCreate,
    acting_user: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> EvidenceOut:
    """Lock a run's evidence. The snapshot is frozen and cannot be modified later."""
    try:
        run_uuid = uuid.UUID(payload.run_id)
    except ValueError:
        raise HTTPException(400, detail="Invalid run_id format.")

    # Verify the run exists
    run_result = await db.execute(select(Run).where(Run.id == run_uuid))
    run = run_result.scalar_one_or_none()
    if run is None:
        raise HTTPException(404, detail="Run not found.")

    # Check for duplicate evidence for this run (allow multiple per run but warn via response code)
    hash_digest = _canonical_hash(payload.snapshot)

    row = Evidence(
        run_id=run_uuid,
        title=payload.title or f"Evidence — {run.project or 'unnamed'} {run.created_at.strftime('%Y-%m-%d') if run.created_at else ''}".strip(),
        note=payload.note,
        project=run.project,
        prepared_by=payload.prepared_by,
        organization=payload.organization,
        audit_period=payload.audit_period,
        frameworks=payload.frameworks,
        snapshot=payload.snapshot,
        report_html=payload.report_html,
        hash_digest=hash_digest,
        public_token=_generate_token(),
        locked_by=acting_user.id,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return Envelope(data=EvidenceOut.from_row(row))


@router.get("/evidence", response_model=Envelope[list[EvidenceOut]])
async def list_evidence(
    _: Annotated[User, Depends(require_role("clevel"))],
    db: Annotated[AsyncSession, Depends(get_db)],
    project: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Envelope[list[EvidenceOut]]:
    stmt = select(Evidence).order_by(Evidence.created_at.desc()).limit(limit).offset(offset)
    if project:
        stmt = stmt.where(Evidence.project == project)
    result = await db.execute(stmt)
    return Envelope(data=[EvidenceOut.from_row(r) for r in result.scalars().all()])


@router.get("/evidence/{evidence_id}", response_model=Envelope[EvidenceOut])
async def get_evidence(
    evidence_id: str,
    _: Annotated[User, Depends(require_role("clevel"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Envelope[EvidenceOut]:
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(404, detail="Evidence package not found.")
    return Envelope(data=EvidenceOut.from_row(row))


@router.get("/evidence/{evidence_id}/snapshot")
async def get_evidence_snapshot(
    evidence_id: str,
    _: Annotated[User, Depends(require_role("clevel"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Return the raw frozen snapshot for a locked evidence package."""
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(404, detail="Evidence package not found.")
    return row.snapshot


@router.get("/evidence/{evidence_id}/report.html", response_class=HTMLResponse)
async def get_evidence_report_html(
    evidence_id: str,
    _: Annotated[User, Depends(require_role("clevel"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> HTMLResponse:
    """Download the locked HTML report for authenticated users."""
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(404, detail="Evidence package not found.")
    return _build_html_response(row)


@router.get("/evidence/{evidence_id}/qr.svg")
async def get_evidence_qr(
    evidence_id: str,
    request: Request,
    _: Annotated[User, Depends(require_role("clevel"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    """Return a QR code SVG linking to the public auditor URL for this evidence package."""
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(404, detail="Evidence package not found.")
    public_url = f"{_resolve_base_url(request)}/evidence/p/{row.public_token}"
    return Response(content=_qr_svg(public_url), media_type="image/svg+xml")


@router.delete("/evidence/{evidence_id}", status_code=204)
async def delete_evidence(
    evidence_id: str,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    row = result.scalar_one_or_none()
    if row:
        await db.delete(row)
        await db.commit()


# ── Public (unauthenticated) auditor endpoints ────────────────────────────────

@router.get("/evidence/p/{token}", response_class=HTMLResponse)
async def public_evidence_view(
    token: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> HTMLResponse:
    """Public, unauthenticated view of a locked evidence package — for auditors."""
    result = await db.execute(select(Evidence).where(Evidence.public_token == token))
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(404, detail="Evidence package not found or link has expired.")
    return _build_html_response(row)


@router.get("/evidence/p/{token}/qr.svg")
async def public_evidence_qr(
    token: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    """Return QR SVG for a public evidence token (no auth required — used in PDF embedding)."""
    result = await db.execute(select(Evidence).where(Evidence.public_token == token))
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(404, detail="Evidence package not found.")
    public_url = f"{_resolve_base_url(request)}/evidence/p/{token}"
    return Response(content=_qr_svg(public_url), media_type="image/svg+xml")


@router.get("/evidence/p/{token}/meta")
async def public_evidence_meta(
    token: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> EvidenceOut:
    """Return evidence metadata by public token (no auth — used by CLI)."""
    result = await db.execute(select(Evidence).where(Evidence.public_token == token))
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(404, detail="Evidence package not found.")
    return EvidenceOut.from_row(row)


# ── HTML builder ─────────────────────────────────────────────────────────────

def _build_html_response(row: Evidence) -> HTMLResponse:
    if row.report_html:
        body = row.report_html
    else:
        body = _snapshot_to_html(row.snapshot)

    locked_at = row.created_at.strftime("%Y-%m-%d %H:%M UTC") if row.created_at else "unknown"
    html = _PUBLIC_HTML_WRAPPER.format(
        title=row.title or "Evidence Package",
        locked_at=locked_at,
        organization=row.organization or "—",
        prepared_by=row.prepared_by or "—",
        hash_digest=row.hash_digest,
        evidence_id=str(row.id),
        body=body,
    )
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'inline; filename="evidence-{str(row.id)[:8]}.html"'},
    )


def _snapshot_to_html(snapshot: dict) -> str:
    """Minimal server-side HTML from a JSON snapshot (used when no pre-rendered HTML is stored)."""
    run = snapshot.get("run", {})
    findings = snapshot.get("findings", [])
    waivers = snapshot.get("waivers", [])
    risks = snapshot.get("risks", [])

    score = run.get("score", 0)
    score_color = "#059669" if score >= 80 else "#d97706" if score >= 60 else "#dc2626"
    failing = [f for f in findings if (f.get("status") or "").upper() == "FAIL"]
    passing = [f for f in findings if (f.get("status") or "").upper() == "PASS"]

    rows_html = ""
    for f in failing[:200]:
        rows_html += (
            f'<tr style="border-top:1px solid #f1f5f9">'
            f'<td style="padding:6px 8px;font-size:11px;font-family:monospace;color:#dc2626">{_esc(f.get("control_id",""))}</td>'
            f'<td style="padding:6px 8px;font-size:11px">{_esc(f.get("check_title",""))}</td>'
            f'<td style="padding:6px 8px;font-size:11px;color:#475569">{_esc(f.get("resource",""))}</td>'
            f'<td style="padding:6px 8px;font-size:11px;color:#6b7280">{_esc(f.get("severity",""))}</td>'
            f'</tr>'
        )

    return f"""
<div style="font-family:system-ui,sans-serif;color:#1e293b">
  <div style="display:flex;align-items:center;gap:24px;padding:24px 0;border-bottom:1px solid #e2e8f0;margin-bottom:24px">
    <div style="text-align:center">
      <div style="font-size:48px;font-weight:800;color:{score_color};line-height:1">{score}</div>
      <div style="font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em">/100</div>
    </div>
    <div>
      <div style="font-size:18px;font-weight:700">{_esc(run.get('project','unnamed'))}</div>
      <div style="font-size:12px;color:#64748b">{_esc(run.get('branch',''))} &nbsp;·&nbsp; {_esc(run.get('git_sha','')[:8])} &nbsp;·&nbsp; {_esc(run.get('created_at','')[:10])}</div>
      <div style="font-size:12px;color:#94a3b8;margin-top:4px">
        {len(passing)} passing &nbsp;·&nbsp; {len(failing)} failing &nbsp;·&nbsp; {len(waivers)} waivers &nbsp;·&nbsp; {len(risks)} risk acceptances
      </div>
    </div>
  </div>
  <h3 style="font-size:13px;font-weight:700;color:#374151;margin:0 0 8px">Failing Controls ({len(failing)})</h3>
  <table style="width:100%;border-collapse:collapse;font-size:12px">
    <thead>
      <tr style="background:#f8fafc;border-bottom:2px solid #e2e8f0">
        <th style="padding:8px;text-align:left;font-size:11px;color:#64748b">Control</th>
        <th style="padding:8px;text-align:left;font-size:11px;color:#64748b">Check</th>
        <th style="padding:8px;text-align:left;font-size:11px;color:#64748b">Resource</th>
        <th style="padding:8px;text-align:left;font-size:11px;color:#64748b">Severity</th>
      </tr>
    </thead>
    <tbody>{rows_html if rows_html else '<tr><td colspan="4" style="padding:20px;text-align:center;color:#94a3b8">No failing controls</td></tr>'}</tbody>
  </table>
  <details style="margin-top:24px">
    <summary style="font-size:12px;color:#64748b;cursor:pointer">Raw JSON manifest</summary>
    <pre style="font-size:10px;color:#64748b;background:#f8fafc;padding:12px;border-radius:6px;overflow:auto;max-height:400px">{_esc(json.dumps(snapshot, indent=2))}</pre>
  </details>
</div>
"""


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
