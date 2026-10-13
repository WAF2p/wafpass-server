"""CRUD endpoints for risk acceptances (team-shared, server-persisted)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import AuthContext, get_auth_context, get_scoped_db, require_role
from wafpass_server.models import RiskAcceptance, User
from wafpass_server.schemas import Envelope, RiskAcceptanceOut, RiskAcceptanceUpsert

router = APIRouter(prefix="/risks", tags=["risks"])

# risk_acceptances' real PK is now composite (mandant_id, id) — same
# fix, same reasoning as waivers.py (see that file's own comment).


@router.get("", response_model=Envelope[list[RiskAcceptanceOut]])
async def list_risks(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
    project: str | None = Query(default=None),
) -> Envelope[list[RiskAcceptanceOut]]:
    stmt = select(RiskAcceptance).order_by(RiskAcceptance.id)
    if project is not None:
        stmt = stmt.where((RiskAcceptance.project == "") | (RiskAcceptance.project == project))
    result = await db.execute(stmt)
    return Envelope(data=list(result.scalars().all()))


async def _get_risk(db: AsyncSession, auth: AuthContext, risk_id: str) -> RiskAcceptance | None:
    return (
        await db.execute(
            select(RiskAcceptance).where(RiskAcceptance.id == risk_id, RiskAcceptance.mandant_id == auth.mandant_id)
        )
    ).scalar_one_or_none()


@router.put("/{risk_id}", response_model=Envelope[RiskAcceptanceOut])
async def upsert_risk(
    risk_id: str,
    payload: RiskAcceptanceUpsert,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    _: Annotated[User, Depends(require_role("ciso"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> Envelope[RiskAcceptanceOut]:
    existing = await _get_risk(db, auth, risk_id)
    if existing is None:
        risk = RiskAcceptance(
            id=risk_id,
            reason=payload.reason,
            approver=payload.approver,
            owner=payload.owner,
            rfc=payload.rfc,
            jira_link=payload.jira_link,
            other_link=payload.other_link,
            notes=payload.notes,
            risk_level=payload.risk_level,
            residual_risk=payload.residual_risk,
            expires=payload.expires,
            accepted_at=payload.accepted_at,
            project=payload.project,
            mandant_id=auth.mandant_id,
        )
        db.add(risk)
    else:
        existing.reason = payload.reason
        existing.approver = payload.approver
        existing.owner = payload.owner
        existing.rfc = payload.rfc
        existing.jira_link = payload.jira_link
        existing.other_link = payload.other_link
        existing.notes = payload.notes
        existing.risk_level = payload.risk_level
        existing.residual_risk = payload.residual_risk
        existing.expires = payload.expires
        existing.accepted_at = payload.accepted_at
        existing.project = payload.project
        risk = existing
    await db.commit()
    await db.refresh(risk)
    return Envelope(data=risk)


@router.delete("/{risk_id}", status_code=204)
async def delete_risk(
    risk_id: str,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    _: Annotated[User, Depends(require_role("ciso"))],
) -> None:
    risk = await _get_risk(db, auth, risk_id)
    if risk is None:
        raise HTTPException(status_code=404, detail="Risk acceptance not found")
    await db.delete(risk)
    await db.commit()
