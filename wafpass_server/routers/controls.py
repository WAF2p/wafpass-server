"""POST/GET/DELETE /controls endpoints."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.database import get_db
from wafpass_server.models import Control, _now
from wafpass_server.schemas import ControlIn, ControlOut, Envelope, Meta

router = APIRouter(prefix="/controls", tags=["controls"])


# ── Helpers ───────────────────────────────────────────────────────────────────


def _to_out(ctrl: Control) -> ControlOut:
    return ControlOut.model_validate(ctrl, from_attributes=True)


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=Envelope[ControlOut], status_code=200)
async def upsert_control(
    payload: ControlIn,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Envelope[ControlOut]:
    """Create or update a control (idempotent upsert on ``id``)."""
    ctrl = await db.get(Control, payload.id)

    if ctrl is None:
        ctrl = Control(
            id=payload.id,
            pillar=payload.pillar,
            severity=payload.severity,
            type=list(payload.type),
            description=payload.description,
            checks=[c.model_dump() for c in payload.checks],
            source=payload.source,
        )
        db.add(ctrl)
    else:
        ctrl.pillar = payload.pillar
        ctrl.severity = payload.severity
        ctrl.type = list(payload.type)
        ctrl.description = payload.description
        ctrl.checks = [c.model_dump() for c in payload.checks]
        ctrl.source = payload.source
        ctrl.updated_at = _now()

    await db.commit()
    await db.refresh(ctrl)
    return Envelope(data=_to_out(ctrl))


@router.get("", response_model=Envelope[list[ControlOut]])
async def list_controls(
    db: Annotated[AsyncSession, Depends(get_db)],
    pillar: str | None = Query(default=None, description="Filter by pillar name."),
    severity: str | None = Query(default=None, description="Filter by severity level."),
    page: int = Query(default=1, ge=1, description="1-based page number."),
    per_page: int = Query(default=50, ge=1, le=200, description="Results per page."),
) -> Envelope[list[ControlOut]]:
    """List controls, optionally filtered by pillar and/or severity."""
    base = select(Control)
    count_base = select(func.count()).select_from(Control)

    if pillar:
        base = base.where(Control.pillar == pillar.lower())
        count_base = count_base.where(Control.pillar == pillar.lower())
    if severity:
        base = base.where(Control.severity == severity.lower())
        count_base = count_base.where(Control.severity == severity.lower())

    total: int = (await db.execute(count_base)).scalar() or 0

    offset = (page - 1) * per_page
    stmt = base.order_by(Control.created_at.desc()).limit(per_page).offset(offset)
    result = await db.execute(stmt)
    controls = list(result.scalars().all())

    return Envelope(
        data=[_to_out(c) for c in controls],
        meta=Meta(total=total, page=page, per_page=per_page),
    )


@router.get("/{control_id}", response_model=Envelope[ControlOut])
async def get_control(
    control_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Envelope[ControlOut]:
    """Return a single control by ID."""
    ctrl = await db.get(Control, control_id.upper())
    if ctrl is None:
        # Also try as-provided (case-sensitive stored IDs)
        ctrl = await db.get(Control, control_id)
    if ctrl is None:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found")
    return Envelope(data=_to_out(ctrl))


@router.delete("/{control_id}", status_code=204)
async def delete_control(
    control_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Remove a control by ID."""
    ctrl = await db.get(Control, control_id.upper())
    if ctrl is None:
        ctrl = await db.get(Control, control_id)
    if ctrl is None:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found")
    await db.delete(ctrl)
    await db.commit()
