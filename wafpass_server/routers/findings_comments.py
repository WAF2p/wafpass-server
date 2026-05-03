"""CRUD endpoints for findings comments — team collaboration on findings."""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from wafpass_server.auth.deps import require_role
from wafpass_server.database import get_db
from wafpass_server.models import FindingComment, RunFinding, User
from wafpass_server.schemas import Envelope, FindingCommentIn, FindingCommentOut

router = APIRouter(prefix="/findings/{finding_id}/comments", tags=["findings-comments"])


@router.get("", response_model=Envelope[list[FindingCommentOut]])
async def list_finding_comments(
    finding_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
) -> Envelope[list[FindingCommentOut]]:
    """List all comments on a finding."""
    finding = await db.get(RunFinding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    stmt = (
        select(FindingComment)
        .where(FindingComment.finding_id == finding_id)
        .order_by(FindingComment.created_at.asc())
        .options(joinedload(FindingComment.user))
    )
    result = await db.execute(stmt)
    comments = list(result.scalars().all())

    # Extract user info for each comment - the user relationship may not be
    # copied by Pydantic's from_attributes, so we populate username/display_name/image_url explicitly
    comment_outs = []
    for comment in comments:
        username = comment.user.username if comment.user else ""
        display_name = comment.user.display_name if comment.user else ""
        image_url = comment.user.image_url if comment.user else ""
        comment_outs.append(
            FindingCommentOut(
                id=comment.id,
                finding_id=comment.finding_id,
                run_id=comment.run_id,
                user_id=comment.user_id,
                message=comment.message,
                created_at=comment.created_at,
                username=username,
                display_name=display_name,
                image_url=image_url,
            )
        )

    return Envelope(data=comment_outs)


@router.post("", response_model=Envelope[FindingCommentOut], status_code=201)
async def create_finding_comment(
    finding_id: uuid.UUID,
    payload: FindingCommentIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_role("clevel"))],
) -> Envelope[FindingCommentOut]:
    """Create a comment on a finding."""
    finding = await db.get(RunFinding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    comment = FindingComment(
        finding_id=finding_id,
        run_id=finding.run_id,
        user_id=current_user.id,
        message=payload.message,
    )
    db.add(comment)
    await db.commit()
    await db.refresh(comment)

    # Populate username, display_name, and image_url explicitly
    comment_out = FindingCommentOut(
        id=comment.id,
        finding_id=comment.finding_id,
        run_id=comment.run_id,
        user_id=comment.user_id,
        message=comment.message,
        created_at=comment.created_at,
        username=current_user.username,
        display_name=current_user.display_name,
        image_url=current_user.image_url,
    )

    return Envelope(data=comment_out)


@router.delete("/{comment_id}", status_code=204)
async def delete_finding_comment(
    finding_id: uuid.UUID,
    comment_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_role("clevel"))],
) -> None:
    """Delete a comment on a finding.

    Users can only delete their own comments, unless they are admins.
    """
    comment = await db.get(FindingComment, comment_id)
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")

    if comment.finding_id != finding_id:
        raise HTTPException(status_code=404, detail="Comment does not belong to this finding")

    # Check ownership - only owners or admins can delete
    if comment.user_id != current_user.id and current_user.role not in ["clevel", "ciso"]:
        raise HTTPException(status_code=403, detail="You can only delete your own comments")

    await db.delete(comment)
    await db.commit()
