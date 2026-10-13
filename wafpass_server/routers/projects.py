"""Project passport endpoints — per-project metadata, editable by admin and architect."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import AuthContext, get_auth_context, get_scoped_db, require_role
from wafpass_server.models import ProjectPassport, Run, User
from wafpass_server.schemas import Envelope, ProjectPassportOut, ProjectPassportUpsert

router = APIRouter(prefix="/projects", tags=["projects"])

# project_passports' real PK is now composite (mandant_id, project) — see
# .plan.md and migration 0046/activate_multi_mandant_ddl.py. Every
# single-item lookup below is explicitly scoped by auth.mandant_id rather
# than a bare db.get(ProjectPassport, project) (which only filters on
# `project`): for an ordinary RLS-scoped user this is a no-op in effect
# (RLS already hid any other mandate's same-named row), but for a
# non-narrowed holding_admin — whose RLS bypass means both rows are
# genuinely visible once two mandates share a project name — db.get()'s
# implicit single-row assumption would raise MultipleResultsFound instead
# of resolving to either. Scoping to auth.mandant_id makes "the passport
# for project X" mean "in the mandate I'm currently viewing as," exactly
# the same semantic the Global Context Switcher (X-Mandant-Context)
# already gives every other single-item lookup in this app — a
# holding-only account (auth.mandant_id is None) gets a clean 404 here
# unless narrowed into one specific mandate first, same as it would for
# any other mandate-scoped resource.
#
# list_passports() below is unchanged: a holding_admin seeing every
# mandate's passports in one list, same project name included more than
# once, is correct for a *list* endpoint — no single-row ambiguity there.


@router.get("/passports", response_model=Envelope[list[ProjectPassportOut]])
async def list_passports(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
) -> Envelope[list[ProjectPassportOut]]:
    result = await db.execute(select(ProjectPassport).order_by(ProjectPassport.project))
    return Envelope(data=list(result.scalars().all()))


async def _get_passport(db: AsyncSession, auth: AuthContext, project: str) -> ProjectPassport | None:
    return (
        await db.execute(
            select(ProjectPassport).where(
                ProjectPassport.project == project,
                ProjectPassport.mandant_id == auth.mandant_id,
            )
        )
    ).scalar_one_or_none()


@router.get("/{project}/passport", response_model=Envelope[ProjectPassportOut])
async def get_passport(
    project: str,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    _: Annotated[User, Depends(require_role("clevel"))],
) -> Envelope[ProjectPassportOut]:
    row = await _get_passport(db, auth, project)
    if row is None:
        raise HTTPException(status_code=404, detail="Passport not found")
    return Envelope(data=row)


@router.put("/{project}/passport", response_model=Envelope[ProjectPassportOut])
async def upsert_passport(
    project: str,
    payload: ProjectPassportUpsert,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    current_user: Annotated[User, Depends(require_role("architect"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> Envelope[ProjectPassportOut]:
    row = await _get_passport(db, auth, project)
    if row is None:
        row = ProjectPassport(project=project, mandant_id=auth.mandant_id)
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
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    _: Annotated[User, Depends(require_role("admin"))],
) -> None:
    row = await _get_passport(db, auth, project)
    if row is None:
        raise HTTPException(status_code=404, detail="Passport not found")
    await db.delete(row)
    await db.commit()


@router.delete("/{project:path}/delete", status_code=204)
async def delete_project(
    project: str,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    _: Annotated[User, Depends(require_role("admin"))],
) -> None:
    """Delete a project and all its runs and related data.

    Scoped to ``auth.mandant_id`` — "the project named X" means "in the
    mandate I'm currently viewing as," the same semantic ``_get_passport``
    already gives every other single-item lookup in this router. Before
    this fix, the `DELETE FROM runs WHERE project = ...` below had no
    mandate filter in application code at all: for an ordinary RLS-scoped
    user that was a no-op in effect (RLS already hid every other mandate's
    rows), but a non-narrowed holding_admin calling this genuinely deleted
    *every* mandate's runs for a shared project name, not just one — found
    as a side effect of the project_passports composite-key fix. Narrow via
    X-Mandant-Context first to target one specific mandate; a holding-only
    admin with no mandate deletes nothing (``mandant_id IS NULL`` matches
    no tagged run) and gets a clean 404 below, same as every other
    mandate-scoped lookup.
    """
    # Check if project exists
    passport = await _get_passport(db, auth, project)
    if passport is None:
        # Check if there are any runs for this project, in this mandate
        run_check = await db.execute(
            select(Run).where(Run.project == project, Run.mandant_id == auth.mandant_id).limit(1)
        )
        if run_check.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Project not found")

    # Delete runs first (cascades to run_findings, run_secret_findings, etc.)
    await db.execute(delete(Run).where(Run.project == project, Run.mandant_id == auth.mandant_id))

    # Delete passport
    if passport is not None:
        await db.delete(passport)

    await db.commit()
