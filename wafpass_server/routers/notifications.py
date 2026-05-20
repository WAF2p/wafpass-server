"""CRUD endpoints for notifications."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import require_role
from wafpass_server.database import get_db
from wafpass_server.models import Notification, User
from wafpass_server.schemas import (
    Envelope,
    NotificationCreate,
    NotificationOut,
    NotificationTestIn,
    NotificationTestOut,
    NotificationUpdateRead,
)

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("", response_model=Envelope[list[NotificationOut]])
async def list_notifications(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role("admin"))],
) -> Envelope[list[NotificationOut]]:
    """List all notifications. Admin users see all notifications."""
    stmt = select(Notification).order_by(Notification.created_at.desc())
    result = await db.execute(stmt)
    notifications = list(result.scalars().all())
    return Envelope(data=notifications)


@router.post("", response_model=Envelope[NotificationOut])
async def create_notification(
    payload: NotificationCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role("admin"))],
) -> Envelope[NotificationOut]:
    """Create a new notification."""
    notification = Notification(
        title=payload.title,
        message=payload.message,
        category=payload.category,
        triggered_by=user.username,
        target_role=payload.target_role,
    )
    db.add(notification)
    await db.commit()
    await db.refresh(notification)
    return Envelope(data=notification)


@router.post("/trigger", response_model=Envelope[NotificationOut])
async def trigger_notification(
    payload: NotificationCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role("admin"))],
) -> Envelope[NotificationOut]:
    """Trigger a new notification (alias for POST /notifications)."""
    notification = Notification(
        title=payload.title,
        message=payload.message,
        category=payload.category,
        triggered_by=user.username,
        target_role=payload.target_role,
    )
    db.add(notification)
    await db.commit()
    await db.refresh(notification)
    return Envelope(data=notification)


@router.post("/test", response_model=Envelope[NotificationTestOut])
async def test_notification(
    payload: NotificationTestIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role("admin"))],
) -> Envelope[NotificationTestOut]:
    """Send a test notification. Returns the notification that would be created."""
    notification = Notification(
        title=payload.title,
        message=payload.message,
        category=payload.category,
        triggered_by=user.username,
        target_role=payload.target_role,
    )
    db.add(notification)
    await db.commit()
    await db.refresh(notification)
    return Envelope(
        data=NotificationTestOut(
            id=notification.id,
            title=notification.title,
            message=notification.message,
            category=notification.category,
            is_read=notification.is_read,
            created_at=notification.created_at,
            triggered_by=notification.triggered_by,
            target_role=notification.target_role,
        )
    )


@router.put("/{notification_id}/read", response_model=Envelope[NotificationOut])
async def mark_as_read(
    notification_id: str,
    payload: NotificationUpdateRead,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role("admin"))],
) -> Envelope[NotificationOut]:
    """Mark a notification as read."""
    notification = await db.get(Notification, notification_id)
    if notification is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    notification.is_read = payload.is_read
    await db.commit()
    await db.refresh(notification)
    return Envelope(data=notification)


@router.put("/read-all", response_model=Envelope[dict])
async def mark_all_as_read(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role("admin"))],
) -> Envelope[dict]:
    """Mark all notifications as read."""
    stmt = update(Notification).values(is_read=True)
    await db.execute(stmt)
    await db.commit()
    return Envelope(data={"success": True})


@router.delete("/{notification_id}", status_code=204)
async def delete_notification(
    notification_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role("admin"))],
) -> None:
    """Delete a notification."""
    notification = await db.get(Notification, notification_id)
    if notification is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    await db.delete(notification)
    await db.commit()
