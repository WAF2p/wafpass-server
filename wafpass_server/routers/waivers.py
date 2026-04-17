"""CRUD endpoints for waivers (team-shared, server-persisted)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import require_role
from wafpass_server.database import get_db
from wafpass_server.models import User, Waiver
from wafpass_server.schemas import WaiverOut, WaiverUpsert

router = APIRouter(prefix="/waivers", tags=["waivers"])


@router.get("", response_model=list[WaiverOut])
async def list_waivers(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
    project: str | None = Query(default=None),
) -> list[Waiver]:
    stmt = select(Waiver).order_by(Waiver.id)
    if project is not None:
        # Return global waivers (project="") plus project-specific ones
        stmt = stmt.where((Waiver.project == "") | (Waiver.project == project))
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.put("/{waiver_id}", response_model=WaiverOut)
async def upsert_waiver(
    waiver_id: str,
    payload: WaiverUpsert,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("ciso"))],
) -> Waiver:
    existing = await db.get(Waiver, waiver_id)
    if existing is None:
        waiver = Waiver(
            id=waiver_id,
            reason=payload.reason,
            owner=payload.owner,
            expires=payload.expires,
            project=payload.project,
        )
        db.add(waiver)
    else:
        existing.reason = payload.reason
        existing.owner = payload.owner
        existing.expires = payload.expires
        existing.project = payload.project
        waiver = existing
    await db.commit()
    await db.refresh(waiver)
    return waiver


@router.delete("/{waiver_id}", status_code=204)
async def delete_waiver(
    waiver_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("ciso"))],
) -> None:
    waiver = await db.get(Waiver, waiver_id)
    if waiver is None:
        raise HTTPException(status_code=404, detail="Waiver not found")
    await db.delete(waiver)
    await db.commit()
