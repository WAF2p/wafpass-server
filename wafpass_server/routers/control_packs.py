"""Control pack management — versioned snapshots of the WAF++ control catalogue.

A *control pack* is an immutable, versioned snapshot of all WAF++ YAML control
files.  On sync the server reads the current controls directory, stores a full
copy in ``control_packs.controls_snapshot``, upserts every control into the
``controls`` table, and marks this pack as the active one.

Activating a historical pack re-applies its stored snapshot without touching
the filesystem, enabling rollback to any previously imported version.
"""
from __future__ import annotations

import io
import tempfile
import zipfile
import yaml
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile, File
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import require_role
from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import Control, ControlPack, User, _now
from wafpass_server.schemas import ControlPackOut, ControlPackSyncIn, Envelope, Meta

router = APIRouter(prefix="/control-packs", tags=["control-packs"])


# ── YAML helpers ──────────────────────────────────────────────────────────────

def _load_yamls_from_dir(directory: Path) -> list[dict]:
    """Read all *.yml files from *directory* and return the valid ones as dicts."""
    controls: list[dict] = []
    for yml_file in sorted(directory.glob("*.yml")):
        try:
            data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "id" in data:
                controls.append(data)
        except Exception:
            pass
    return controls


# Valid type values for WAF++ controls
_VALID_TYPES = frozenset({"governance", "configuration", "iac", "network", "identity", "data", "cost"})

# Valid pillar values (matching the schema)
_VALID_PILLARS = frozenset({"security", "cost", "performance", "reliability", "operational", "sustainability", "sovereign"})

# Pillar name mapping (YAML -> schema)
_PILLAR_MAPPING = {
    "operations": "operational",
}


def _raw_to_db_fields(raw: dict) -> dict:
    """Extract the subset of fields that maps to the ``controls`` table.

    This preserves the full check structure from YAML for compatibility with
    the ControlOut schema which requires: id, engine, description, expected.
    """
    checks = raw.get("checks") or []
    # Filter type list to only valid values
    raw_types = raw.get("type") or []
    valid_types = [t for t in raw_types if t in _VALID_TYPES]
    # Ensure at least one type for validation
    if not valid_types:
        valid_types = ["configuration"]  # Default type for general controls

    # Normalize pillar name if needed
    pillar = str(raw.get("pillar") or "")
    pillar = _PILLAR_MAPPING.get(pillar, pillar)

    # Parse regulatory_mapping: list of {framework, controls} dicts
    regulatory_mapping: list[dict] = []
    for entry in raw.get("regulatory_mapping", []):
        if isinstance(entry, dict) and "framework" in entry:
            regulatory_mapping.append({
                "framework": str(entry["framework"]),
                "controls": [str(c) for c in entry.get("controls", [])],
            })

    return {
        "id": raw["id"],
        "pillar": pillar,
        "severity": str(raw.get("severity") or ""),
        "type": valid_types,
        "description": str(raw.get("description") or ""),
        "checks": [
            {
                "id": c.get("id", ""),
                "engine": c.get("engine", ""),
                "provider": c.get("provider", ""),
                "automated": c.get("automated", False),
                "severity": c.get("severity", ""),
                "title": c.get("title", ""),
                "description": str(c.get("description") or ""),
                "scope": c.get("scope", {}),
                "assertions": c.get("assertions", []),
                "on_fail": c.get("on_fail", "violation"),
                "remediation": str(c.get("remediation") or ""),
                "example": c.get("example"),
            }
            for c in checks if isinstance(c, dict)
        ],
        "regulatory_mapping": regulatory_mapping,
        "source": "wafpass",
    }


async def _apply_snapshot(db: AsyncSession, snapshot: list[dict]) -> None:
    """Upsert every control from *snapshot* into the controls table."""
    for raw in snapshot:
        fields = _raw_to_db_fields(raw)
        ctrl = await db.get(Control, fields["id"])
        if ctrl is None:
            db.add(Control(**fields))
        else:
            for k, v in fields.items():
                if k != "id":
                    setattr(ctrl, k, v)
            ctrl.updated_at = _now()


def _pack_to_out(pack: ControlPack) -> ControlPackOut:
    return ControlPackOut.model_validate(pack, from_attributes=True)


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("", response_model=Envelope[list[ControlPackOut]])
async def list_packs(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("architect"))],
) -> Envelope[list[ControlPackOut]]:
    """List all control packs ordered by import date (newest first)."""
    result = await db.execute(
        select(ControlPack).order_by(ControlPack.imported_at.desc())
    )
    packs = list(result.scalars().all())
    return Envelope(data=[_pack_to_out(p) for p in packs], meta=Meta(total=len(packs)))


@router.get("/active", response_model=Envelope[ControlPackOut | None])
async def get_active_pack(
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
) -> Envelope[ControlPackOut | None]:
    """Return the currently active control pack, or null if none has been synced."""
    result = await db.execute(
        select(ControlPack).where(ControlPack.is_active.is_(True)).limit(1)
    )
    pack = result.scalar_one_or_none()
    return Envelope(data=_pack_to_out(pack) if pack else None)


@router.post("/sync", response_model=Envelope[ControlPackOut], status_code=201)
async def sync_pack(
    payload: ControlPackSyncIn,
    db: Annotated[AsyncSession, Depends(get_db)],
    actor: Annotated[User, Depends(require_role("admin"))],
) -> Envelope[ControlPackOut]:
    """Import controls from WAFPASS_CONTROLS_DIR as a new versioned pack and activate it.

    The full raw YAML content is stored in ``controls_snapshot`` so the pack
    can be re-activated later without filesystem access (rollback).
    """
    if await db.get(ControlPack, payload.version):
        raise HTTPException(
            400,
            detail=f"Control pack '{payload.version}' already exists. Choose a different version string.",
        )

    controls_dir = Path(settings.wafpass_controls_dir)
    if not controls_dir.is_dir():
        raise HTTPException(
            503,
            detail=f"Controls directory '{controls_dir}' is not accessible on this server.",
        )

    snapshot = _load_yamls_from_dir(controls_dir)
    if not snapshot:
        raise HTTPException(
            422,
            detail="No *.yml control files found in the controls directory.",
        )

    await _apply_snapshot(db, snapshot)

    # Deactivate all existing packs before marking the new one active
    await db.execute(update(ControlPack).values(is_active=False))

    now = _now()
    pack = ControlPack(
        version=payload.version,
        description=payload.description,
        is_active=True,
        control_count=len(snapshot),
        controls_snapshot=snapshot,
        imported_at=now,
        imported_by=actor.id,
        activated_at=now,
        activated_by=actor.id,
    )
    db.add(pack)
    await db.commit()
    await db.refresh(pack)
    return Envelope(data=_pack_to_out(pack))


@router.post("/upload", response_model=Envelope[ControlPackOut], status_code=201)
async def upload_pack(
    db: Annotated[AsyncSession, Depends(get_db)],
    actor: Annotated[User, Depends(require_role("admin"))],
    file: Annotated[UploadFile, File(description="ZIP archive containing *.yml control files and an optional manifest.json")],
    version: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
) -> Envelope[ControlPackOut]:
    """Upload a ZIP archive of WAF++ control YAML files as a new versioned pack and activate it.

    The ZIP may contain a flat list of ``*.yml`` files or a single top-level
    subdirectory (e.g. the output of ``pack_controls.py``).  A ``manifest.json``
    inside the archive is ignored — version and description come from the form
    fields so the caller is always explicit.
    """
    if not version.strip():
        raise HTTPException(422, detail="version field is required.")
    version = version.strip()

    if await db.get(ControlPack, version):
        raise HTTPException(
            400,
            detail=f"Control pack '{version}' already exists. Choose a different version string.",
        )

    if file.content_type not in ("application/zip", "application/x-zip-compressed", "application/octet-stream"):
        # Be lenient — browsers may send different MIME types for the same .zip
        if not (file.filename or "").lower().endswith(".zip"):
            raise HTTPException(415, detail="Uploaded file must be a .zip archive.")

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(422, detail="Uploaded file is empty.")

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_bytes))
    except zipfile.BadZipFile:
        raise HTTPException(422, detail="Uploaded file is not a valid ZIP archive.")

    # Extract YAML files — handle both flat archives and single-subdir archives
    snapshot: list[dict] = []
    with zf:
        yml_members = [m for m in zf.namelist() if m.endswith(".yml") and not m.startswith("__MACOSX")]
        if not yml_members:
            raise HTTPException(422, detail="No *.yml files found inside the ZIP archive.")

        for member in sorted(yml_members):
            try:
                content = zf.read(member).decode("utf-8")
                data = yaml.safe_load(content)
                if isinstance(data, dict) and "id" in data:
                    snapshot.append(data)
            except Exception:
                pass

    if not snapshot:
        raise HTTPException(422, detail="No valid WAF++ control definitions found in the ZIP archive.")

    await _apply_snapshot(db, snapshot)
    await db.execute(update(ControlPack).values(is_active=False))

    now = _now()
    pack = ControlPack(
        version=version,
        description=description.strip(),
        is_active=True,
        control_count=len(snapshot),
        controls_snapshot=snapshot,
        imported_at=now,
        imported_by=actor.id,
        activated_at=now,
        activated_by=actor.id,
    )
    db.add(pack)
    await db.commit()
    await db.refresh(pack)
    return Envelope(data=_pack_to_out(pack))


@router.post("/{version}/activate", response_model=Envelope[ControlPackOut])
async def activate_pack(
    version: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    actor: Annotated[User, Depends(require_role("admin"))],
) -> Envelope[ControlPackOut]:
    """Re-apply a stored pack's snapshot and mark it as the active version (rollback)."""
    pack = await db.get(ControlPack, version)
    if pack is None:
        raise HTTPException(404, detail=f"Control pack '{version}' not found.")

    await _apply_snapshot(db, pack.controls_snapshot)

    await db.execute(update(ControlPack).values(is_active=False))
    pack.is_active = True
    pack.activated_at = _now()
    pack.activated_by = actor.id

    await db.commit()
    await db.refresh(pack)
    return Envelope(data=_pack_to_out(pack))
