"""Compliance audit event endpoints — server-side persistence for dashboard audit log."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import require_role
from wafpass_server.database import get_db
from wafpass_server.models import ComplianceAuditEvent, User
from wafpass_server.schemas import ComplianceAuditEventIn, ComplianceAuditEventOut, Envelope

router = APIRouter(prefix="/audit/events", tags=["audit"])


@router.post("", response_model=Envelope[ComplianceAuditEventOut], status_code=201)
async def create_audit_event(
    payload: ComplianceAuditEventIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_role("engineer"))],
) -> Envelope[ComplianceAuditEventOut]:
    ts: datetime | None = None
    if payload.timestamp:
        try:
            ts = datetime.fromisoformat(payload.timestamp.replace("Z", "+00:00"))
        except ValueError:
            pass

    kwargs: dict = {}
    if ts is not None:
        kwargs["timestamp"] = ts

    event = ComplianceAuditEvent(
        client_id=payload.client_id,
        actor=payload.actor or current_user.username,
        category=payload.category,
        action=payload.action,
        subject_id=payload.subject_id,
        subject_type=payload.subject_type,
        summary=payload.summary,
        before=payload.before,
        after=payload.after,
        created_by=current_user.id,
        **kwargs,
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return Envelope(data=event)


@router.get("", response_model=Envelope[list[ComplianceAuditEventOut]])
async def list_audit_events(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("ciso"))],
    limit: int = Query(default=500, le=2000),
    category: str | None = Query(default=None),
) -> Envelope[list[ComplianceAuditEventOut]]:
    stmt = (
        select(ComplianceAuditEvent)
        .order_by(ComplianceAuditEvent.timestamp.desc())
        .limit(limit)
    )
    if category:
        stmt = stmt.where(ComplianceAuditEvent.category == category)
    result = await db.execute(stmt)
    return Envelope(data=list(result.scalars().all()))
