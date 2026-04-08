"""CRUD endpoints for risk acceptances (team-shared, server-persisted)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.database import get_db
from wafpass_server.models import RiskAcceptance
from wafpass_server.schemas import RiskAcceptanceOut, RiskAcceptanceUpsert

router = APIRouter(prefix="/risks", tags=["risks"])


@router.get("", response_model=list[RiskAcceptanceOut])
async def list_risks(
    db: Annotated[AsyncSession, Depends(get_db)],
    project: str | None = Query(default=None),
) -> list[RiskAcceptance]:
    stmt = select(RiskAcceptance).order_by(RiskAcceptance.id)
    if project is not None:
        stmt = stmt.where((RiskAcceptance.project == "") | (RiskAcceptance.project == project))
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.put("/{risk_id}", response_model=RiskAcceptanceOut)
async def upsert_risk(
    risk_id: str,
    payload: RiskAcceptanceUpsert,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> RiskAcceptance:
    existing = await db.get(RiskAcceptance, risk_id)
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
    return risk


@router.delete("/{risk_id}", status_code=204)
async def delete_risk(
    risk_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    risk = await db.get(RiskAcceptance, risk_id)
    if risk is None:
        raise HTTPException(status_code=404, detail="Risk acceptance not found")
    await db.delete(risk)
    await db.commit()
