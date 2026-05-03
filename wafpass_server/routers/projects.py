"""Project passport endpoints — per-project metadata, editable by admin and architect."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import require_role
from wafpass_server.database import get_db
from wafpass_server.models import ProjectPassport, Run, User
from wafpass_server.schemas import Envelope, ProjectPassportOut, ProjectPassportUpsert

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("/passports", response_model=Envelope[list[ProjectPassportOut]])
async def list_passports(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
) -> Envelope[list[ProjectPassportOut]]:
    result = await db.execute(select(ProjectPassport).order_by(ProjectPassport.project))
    return Envelope(data=list(result.scalars().all()))


@router.get("/{project}/passport", response_model=Envelope[ProjectPassportOut])
async def get_passport(
    project: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
) -> Envelope[ProjectPassportOut]:
    row = await db.get(ProjectPassport, project)
    if row is None:
        raise HTTPException(status_code=404, detail="Passport not found")
    return Envelope(data=row)


@router.put("/{project}/passport", response_model=Envelope[ProjectPassportOut])
async def upsert_passport(
    project: str,
    payload: ProjectPassportUpsert,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_role("architect"))],
) -> Envelope[ProjectPassportOut]:
    row = await db.get(ProjectPassport, project)
    if row is None:
        row = ProjectPassport(project=project)
        db.add(row)
    row.display_name = payload.display_name
    row.owner = payload.owner
    row.owner_team = payload.owner_team
    row.contact_email = payload.contact_email
    row.description = payload.description
    row.criticality = payload.criticality
    row.environment = payload.environment
    row.cloud_provider = payload.cloud_provider
    row.repository_url = payload.repository_url
    row.documentation_url = payload.documentation_url
    row.tags = payload.tags
    row.notes = payload.notes
    row.image_url = payload.image_url
    row.updated_by = current_user.username
    await db.commit()
    await db.refresh(row)
    return Envelope(data=row)


@router.delete("/{project}/passport", status_code=204)
async def delete_passport(
    project: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("admin"))],
) -> None:
    row = await db.get(ProjectPassport, project)
    if row is None:
        raise HTTPException(status_code=404, detail="Passport not found")
    await db.delete(row)
    await db.commit()


@router.delete("/{project:path}/delete", status_code=204)
async def delete_project(
    project: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("admin"))],
) -> None:
    """Delete a project and all its runs and related data."""
    # Check if project exists
    passport = await db.get(ProjectPassport, project)
    if passport is None:
        # Check if there are any runs for this project
        run_check = await db.execute(select(Run).where(Run.project == project).limit(1))
        if run_check.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Project not found")

    # Delete runs first (cascades to run_findings, run_secret_findings, etc.)
    await db.execute(delete(Run).where(Run.project == project))

    # Delete passport
    if passport is not None:
        await db.delete(passport)

    await db.commit()
