"""CRUD endpoints for secret findings comments — team collaboration on hardcoded secrets."""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from wafpass_server.auth.deps import AuthContext, get_auth_context, get_scoped_db, require_group_access, require_role
from wafpass_server.models import Run, RunSecretFinding, SecretFindingComment, User
from wafpass_server.schemas import Envelope, SecretFindingCommentIn, SecretFindingCommentOut

router = APIRouter(prefix="/secret-findings/{secret_finding_id}/comments", tags=["secret-findings-comments"])


@router.get("", response_model=Envelope[list[SecretFindingCommentOut]])
async def list_secret_finding_comments(
    secret_finding_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    user: Annotated[User, Depends(require_role("clevel"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> Envelope[list[SecretFindingCommentOut]]:
    """List all comments on a secret finding."""
    secret_finding = await db.get(RunSecretFinding, secret_finding_id)
    if secret_finding is None:
        raise HTTPException(status_code=404, detail="Secret finding not found")

    run = await db.get(Run, secret_finding.run_id)
    if run is not None:
        await require_group_access(run.project, db, user, auth)

    stmt = (
        select(SecretFindingComment)
        .where(SecretFindingComment.secret_finding_id == secret_finding_id)
        .order_by(SecretFindingComment.created_at.asc())
        .options(joinedload(SecretFindingComment.user))
    )
    result = await db.execute(stmt)
    comments = list(result.scalars().all())

    comment_outs = []
    for comment in comments:
        username = comment.user.username if comment.user else ""
        display_name = comment.user.display_name if comment.user else ""
        image_url = comment.user.image_url if comment.user else ""
        comment_outs.append(
            SecretFindingCommentOut(
                id=comment.id,
                secret_finding_id=comment.secret_finding_id,
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


@router.post("", response_model=Envelope[SecretFindingCommentOut], status_code=201)
async def create_secret_finding_comment(
    secret_finding_id: uuid.UUID,
    payload: SecretFindingCommentIn,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    current_user: Annotated[User, Depends(require_role("clevel"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> Envelope[SecretFindingCommentOut]:
    """Create a comment on a secret finding."""
    secret_finding = await db.get(RunSecretFinding, secret_finding_id)
    if secret_finding is None:
        raise HTTPException(status_code=404, detail="Secret finding not found")

    run = await db.get(Run, secret_finding.run_id)
    if run is not None:
        await require_group_access(run.project, db, current_user, auth)

    comment = SecretFindingComment(
        secret_finding_id=secret_finding_id,
        run_id=secret_finding.run_id,
        user_id=current_user.id,
        message=payload.message,
        mandant_id=auth.mandant_id,
    )
    db.add(comment)
    await db.commit()
    await db.refresh(comment)

    # Populate username, display_name, and image_url explicitly
    comment_out = SecretFindingCommentOut(
        id=comment.id,
        secret_finding_id=comment.secret_finding_id,
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
async def delete_secret_finding_comment(
    secret_finding_id: uuid.UUID,
    comment_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    current_user: Annotated[User, Depends(require_role("clevel"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> None:
    """Delete a comment on a secret finding.

    Users can only delete their own comments.
    """
    comment = await db.get(SecretFindingComment, comment_id)
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")

    if comment.secret_finding_id != secret_finding_id:
        raise HTTPException(status_code=404, detail="Comment does not belong to this secret finding")

    run = await db.get(Run, comment.run_id)
    if run is not None:
        await require_group_access(run.project, db, current_user, auth)

    # Check ownership - only owners can delete (no admin override for secret findings)
    if comment.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own comments")

    await db.delete(comment)
    await db.commit()
