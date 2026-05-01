"""POST/GET/DELETE /controls endpoints."""
from __future__ import annotations

import io
import yaml
import zipfile
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import require_role
from wafpass_server.database import get_db
from wafpass_server.models import Control, ControlPack, User, _now
from wafpass_server.schemas import ControlIn, ControlOut, Envelope, Meta

router = APIRouter(prefix="/controls", tags=["controls"])


# ── Helpers ───────────────────────────────────────────────────────────────────


def _normalize_check(check: dict) -> dict:
    """Normalize a check dict to the ControlOut/WizardCheck format.

    Handles both old check structure (from legacy imports) and new structure.
    Old structure had: id, title, severity, remediation, example
    New structure (WizardCheck) requires: id, engine, description, expected

    For checks without assertions, we use "true" as a default expected value
    for common patterns like is_true, is_false, equals.

    Preserves full check structure when available: scope, assertions, title,
    provider, remediation, example, on_fail.
    """
    # If check already has required fields, return as-is (includes full structure)
    if check.get("engine") and check.get("description"):
        return check

    # Old structure - map available fields and create defaults for missing ones
    assertions = check.get("assertions", [])
    expected = ""
    if assertions and isinstance(assertions, list):
        first_assertion = assertions[0] if assertions else {}
        expected = str(first_assertion.get("expected", "") or "")
        if not expected:
            # Try to derive expected from the assertion op
            op = first_assertion.get("op", "")
            if op == "is_true":
                expected = "true"
            elif op == "is_false":
                expected = "false"

    # Default to "true" if still no expected value (common for boolean checks)
    if not expected:
        expected = "true"

    return {
        "id": check.get("id", ""),
        "engine": check.get("engine", "terraform"),  # Default engine
        "description": check.get("description", check.get("title", "")),  # Fallback to title
        "expected": expected,
        "automated": True,  # All wizard checks are automated
        # Preserve optional fields if present
        "title": check.get("title"),
        "provider": check.get("provider"),
        "scope": check.get("scope"),
        "assertions": check.get("assertions"),
        "remediation": check.get("remediation"),
        "example": check.get("example"),
        "on_fail": check.get("on_fail"),
    }


def _to_out(ctrl: Control) -> ControlOut:
    """Convert a Control ORM object to ControlOut schema.

    Normalizes checks to ensure compatibility with WizardCheck schema requirements.
    """
    # Normalize checks before validation
    checks = ctrl.checks or []
    normalized_checks = [_normalize_check(c) for c in checks if isinstance(c, dict)]

    # Build a dict that matches the ControlOut model
    ctrl_dict = {
        "id": ctrl.id,
        "pillar": ctrl.pillar,
        "severity": ctrl.severity,
        "type": ctrl.type,
        "description": ctrl.description,
        "checks": normalized_checks,
        "regulatory_mapping": ctrl.regulatory_mapping or [],
        "source": ctrl.source,
        "created_at": ctrl.created_at,
        "updated_at": ctrl.updated_at,
    }

    return ControlOut.model_validate(ctrl_dict, from_attributes=False)


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=Envelope[ControlOut], status_code=200)
async def upsert_control(
    payload: ControlIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("architect"))],
) -> Envelope[ControlOut]:
    """Create or update a control (idempotent upsert on ``id``)."""
    ctrl = await db.get(Control, payload.id)

    if ctrl is None:
        ctrl = Control(
            id=payload.id,
            pillar=payload.pillar,
            severity=payload.severity,
            type=list(payload.type),
            description=payload.description,
            checks=[c.model_dump() for c in payload.checks],
            regulatory_mapping=payload.regulatory_mapping or [],
            source=payload.source,
        )
        db.add(ctrl)
    else:
        ctrl.pillar = payload.pillar
        ctrl.severity = payload.severity
        ctrl.type = list(payload.type)
        ctrl.description = payload.description
        ctrl.checks = [c.model_dump() for c in payload.checks]
        ctrl.regulatory_mapping = payload.regulatory_mapping or []
        ctrl.source = payload.source
        ctrl.updated_at = _now()

    await db.commit()
    await db.refresh(ctrl)
    return Envelope(data=_to_out(ctrl))


@router.get("", response_model=Envelope[list[ControlOut]])
async def list_controls(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
    pillar: str | None = Query(default=None, description="Filter by pillar name."),
    severity: str | None = Query(default=None, description="Filter by severity level."),
    page: int = Query(default=1, ge=1, description="1-based page number."),
    per_page: int = Query(default=50, ge=1, le=200, description="Results per page."),
) -> Envelope[list[ControlOut]]:
    """List controls, optionally filtered by pillar and/or severity."""
    base = select(Control)
    count_base = select(func.count()).select_from(Control)

    if pillar:
        base = base.where(Control.pillar == pillar.lower())
        count_base = count_base.where(Control.pillar == pillar.lower())
    if severity:
        base = base.where(Control.severity == severity.lower())
        count_base = count_base.where(Control.severity == severity.lower())

    total: int = (await db.execute(count_base)).scalar() or 0

    offset = (page - 1) * per_page
    stmt = base.order_by(Control.created_at.desc()).limit(per_page).offset(offset)
    result = await db.execute(stmt)
    controls = list(result.scalars().all())

    return Envelope(
        data=[_to_out(c) for c in controls],
        meta=Meta(total=total, page=page, per_page=per_page),
    )


@router.get("/{control_id}", response_model=Envelope[ControlOut])
async def get_control(
    control_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
) -> Envelope[ControlOut]:
    """Return a single control by ID."""
    ctrl = await db.get(Control, control_id.upper())
    if ctrl is None:
        # Also try as-provided (case-sensitive stored IDs)
        ctrl = await db.get(Control, control_id)
    if ctrl is None:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found")
    return Envelope(data=_to_out(ctrl))


@router.delete("/{control_id}", status_code=204)
async def delete_control(
    control_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("architect"))],
) -> None:
    """Remove a control by ID."""
    ctrl = await db.get(Control, control_id.upper())
    if ctrl is None:
        ctrl = await db.get(Control, control_id)
    if ctrl is None:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found")
    await db.delete(ctrl)
    await db.commit()


# ── Export all controls as ZIP pack ───────────────────────────────────────────

def _control_to_yaml(ctrl: Control) -> str:
    """Convert a Control ORM object to WAF++ YAML format.

    Uses PyYAML dumper to properly handle string quoting (single vs double quotes,
    escaped characters, etc.) to avoid YAML parsing errors.
    """
    # Build the control as a dict, then dump with PyYAML
    control_dict: dict[str, object] = {
        "id": ctrl.id,
        "pillar": ctrl.pillar,
        "severity": ctrl.severity,
        "type": ctrl.type or [],
        "description": ctrl.description or "",
        "source": ctrl.source,
    }

    # Regulatory mapping
    if ctrl.regulatory_mapping:
        control_dict["regulatory_mapping"] = ctrl.regulatory_mapping

    # Checks
    if checks := ctrl.checks:
        control_dict["checks"] = []
        for ch in checks:
            if isinstance(ch, dict):
                check_dict: dict[str, object] = {
                    "id": ch.get("id", ""),
                    "engine": ch.get("engine", "terraform"),
                    "automated": True,
                }
                if title := ch.get("title"):
                    check_dict["title"] = title
                if provider := ch.get("provider"):
                    check_dict["provider"] = provider
                if desc := ch.get("description"):
                    check_dict["description"] = desc
                if expected := ch.get("expected"):
                    check_dict["expected"] = expected
                if remediation := ch.get("remediation"):
                    check_dict["remediation"] = remediation
                if example := ch.get("example"):
                    check_dict["example"] = example
                if scope := ch.get("scope"):
                    check_dict["scope"] = scope
                if assertions := ch.get("assertions"):
                    check_dict["assertions"] = assertions
                if on_fail := ch.get("on_fail"):
                    check_dict["on_fail"] = on_fail
                control_dict["checks"].append(check_dict)

    # Convert to YAML using PyYAML which handles quoting properly
    yaml_output = yaml.dump(
        control_dict,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=1000,  # Prevent line wrapping
    )

    # Remove trailing newline if present
    if yaml_output.endswith("\n"):
        yaml_output = yaml_output[:-1]

    return yaml_output


@router.get("/export", response_class=StreamingResponse)
async def export_controls(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
) -> StreamingResponse:
    """Download all controls as a ZIP archive of YAML files.

    This endpoint exports all controls from the database as individual YAML files
    in a ZIP archive, matching the format expected by WAF++ CLI controls directory.
    """
    result = await db.execute(select(Control).order_by(Control.id))
    controls = list(result.scalars().all())

    if not controls:
        raise HTTPException(status_code=404, detail="No controls found in database")

    # Create in-memory ZIP
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for ctrl in controls:
            yaml_content = _control_to_yaml(ctrl)
            filename = f"{ctrl.id}.yml"
            zf.writestr(filename, yaml_content)

    zip_buffer.seek(0)

    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="wafpass_controls_{_now().strftime("%Y%m%d")}.zip"',
        },
    )


@router.get("/active-pack", response_model=Envelope[dict | None])
async def get_active_pack_info(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
) -> Envelope[dict | None]:
    """Return metadata about the currently active control pack.

    Includes version, description, control count, and timestamps.
    Useful for displaying pack context in the controls catalogue.
    """
    result = await db.execute(
        select(ControlPack).where(ControlPack.is_active.is_(True)).limit(1)
    )
    pack = result.scalar_one_or_none()
    if pack is None:
        return Envelope(data=None)

    return Envelope(data={
        "version": pack.version,
        "description": pack.description,
        "control_count": pack.control_count,
        "imported_at": pack.imported_at.isoformat(),
        "activated_at": pack.activated_at.isoformat() if pack.activated_at else None,
    })
