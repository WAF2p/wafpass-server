"""CRUD endpoints for waivers (team-shared, server-persisted)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import AuthContext, get_auth_context, get_scoped_db, require_role
from wafpass_server.models import User, Waiver
from wafpass_server.schemas import Envelope, WaiverOut, WaiverUpsert

router = APIRouter(prefix="/waivers", tags=["waivers"])

# waivers' real PK is now composite (mandant_id, id) — see .plan.md and
# migration 0047/activate_multi_mandant_ddl.py. Single-item lookups below
# are explicitly scoped by auth.mandant_id for the same reason as
# projects.py's passport endpoints: harmless no-op for an ordinary
# RLS-scoped user (RLS already hid any other mandate's same-id row), but
# avoids a MultipleResultsFound crash for a non-narrowed holding_admin
# once two mandates genuinely waive the same control_id — "the waiver for
# control X" now means "in the mandate I'm currently viewing as," the
# same semantic the Global Context Switcher already gives everywhere else.


@router.get("", response_model=Envelope[list[WaiverOut]])
async def list_waivers(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
    project: str | None = Query(default=None),
) -> Envelope[list[WaiverOut]]:
    stmt = select(Waiver).order_by(Waiver.id)
    if project is not None:
        # Return global waivers (project="") plus project-specific ones
        stmt = stmt.where((Waiver.project == "") | (Waiver.project == project))
    result = await db.execute(stmt)
    return Envelope(data=list(result.scalars().all()))


async def _get_waiver(db: AsyncSession, auth: AuthContext, waiver_id: str) -> Waiver | None:
    return (
        await db.execute(
            select(Waiver).where(Waiver.id == waiver_id, Waiver.mandant_id == auth.mandant_id)
        )
    ).scalar_one_or_none()


@router.put("/{waiver_id}", response_model=Envelope[WaiverOut])
async def upsert_waiver(
    waiver_id: str,
    payload: WaiverUpsert,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    _: Annotated[User, Depends(require_role("ciso"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> Envelope[WaiverOut]:
    existing = await _get_waiver(db, auth, waiver_id)
    if existing is None:
        waiver = Waiver(
            id=waiver_id,
            reason=payload.reason,
            owner=payload.owner,
            expires=payload.expires,
            project=payload.project,
            mandant_id=auth.mandant_id,
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
    return Envelope(data=waiver)


@router.delete("/{waiver_id}", status_code=204)
async def delete_waiver(
    waiver_id: str,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    _: Annotated[User, Depends(require_role("ciso"))],
) -> None:
    waiver = await _get_waiver(db, auth, waiver_id)
    if waiver is None:
        raise HTTPException(status_code=404, detail="Waiver not found")
    await db.delete(waiver)
    await db.commit()
