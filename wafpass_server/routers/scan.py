"""POST /scan — run the WAF++ engine against a server-side IaC path and persist as a Run.

Unlike /sandbox (ephemeral, HCL-snippet only), this endpoint:
  1. Accepts a filesystem path accessible to the server process
  2. Runs the full wafpass engine (same controls as the CLI)
  3. Persists the result as a Run record in the database
  4. Returns a RunSummary identical to what POST /runs would return

Security
--------
If WAFPASS_SCAN_BASE_DIR is set, all paths are resolved and checked to be
within that directory — preventing path-traversal to arbitrary filesystem
locations.  If unset, any path accessible to the server process is allowed
(suitable for local / dev deployments only).

The endpoint can be disabled entirely by setting WAFPASS_SCAN_ENABLED=false.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import Run
from wafpass_server.schemas import RunSummary

router = APIRouter(prefix="/scan", tags=["scan"])

# Lazy-checked once per process startup
_wafpass_available: bool | None = None


def _check_wafpass() -> bool:
    global _wafpass_available
    if _wafpass_available is None:
        try:
            import wafpass  # noqa: F401
            _wafpass_available = True
        except ImportError:
            _wafpass_available = False
    return _wafpass_available


# ── Request schema ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    path: str
    iac: str = "terraform"
    project: str = ""
    branch: str = ""
    stage: str = ""
    triggered_by: str = "ui"


# ── Path validation ───────────────────────────────────────────────────────────

def _resolve_and_validate(raw: str) -> Path:
    """Resolve *raw* to an absolute Path and enforce WAFPASS_SCAN_BASE_DIR if set."""
    p = Path(raw)

    # If a base-dir is configured and the supplied path is relative, anchor it.
    base_raw = (settings.wafpass_scan_base_dir or "").strip()
    if base_raw and not p.is_absolute():
        p = Path(base_raw) / p

    resolved = p.resolve()

    if base_raw:
        base_resolved = Path(base_raw).resolve()
        try:
            resolved.relative_to(base_resolved)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Path '{raw}' is outside the allowed scan base directory "
                    f"({base_resolved}). Set WAFPASS_SCAN_BASE_DIR to permit broader access."
                ),
            )

    if not resolved.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist on the server: {resolved}")
    if not (resolved.is_dir() or resolved.is_file()):
        raise HTTPException(status_code=400, detail=f"Path is not a file or directory: {resolved}")

    return resolved


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/status")
async def scan_status() -> dict:
    """Check whether server-side scanning is available."""
    controls_dir = Path(settings.wafpass_controls_dir)
    base_raw = (settings.wafpass_scan_base_dir or "").strip()
    return {
        "enabled": getattr(settings, "wafpass_scan_enabled", True),
        "engine_available": _check_wafpass(),
        "controls_dir": str(controls_dir.resolve()),
        "controls_dir_exists": controls_dir.exists(),
        "scan_base_dir": base_raw or None,
    }


@router.post("", response_model=RunSummary, status_code=201)
async def trigger_scan(
    payload: ScanRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Run:
    """Trigger a WAF++ scan on a server-side path and persist the result."""

    if not getattr(settings, "wafpass_scan_enabled", True):
        raise HTTPException(status_code=503, detail="Server-side scanning is disabled (WAFPASS_SCAN_ENABLED=false).")

    if not _check_wafpass():
        raise HTTPException(
            status_code=503,
            detail=(
                "wafpass-core is not importable on this server. "
                "Reinstall with: pip install wafpass-core"
            ),
        )

    # Validate & resolve scan target path
    scan_path = _resolve_and_validate(payload.path)

    # Validate controls directory
    controls_dir = Path(settings.wafpass_controls_dir)
    if not controls_dir.exists():
        raise HTTPException(
            status_code=503,
            detail=(
                f"Controls directory not found: {controls_dir.resolve()}. "
                "Set WAFPASS_CONTROLS_DIR to the path containing your WAF++ YAML files."
            ),
        )

    # All wafpass imports are lazy so the server starts without wafpass-core
    from wafpass.engine import run_controls  # type: ignore[import]
    from wafpass.iac import registry  # type: ignore[import]
    from wafpass.loader import load_controls  # type: ignore[import]
    from wafpass.schema import (  # type: ignore[import]
        ControlCheckMetaSchema,
        ControlMetaSchema,
        FindingSchema,
    )

    # Load controls
    try:
        controls = load_controls(controls_dir)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load controls: {exc}") from exc

    if not controls:
        raise HTTPException(status_code=503, detail=f"No controls found in {controls_dir.resolve()}.")

    # Resolve IaC plugin
    plugin = registry.get(payload.iac.lower())
    if plugin is None:
        available = ", ".join(registry.available) or "(none)"
        raise HTTPException(status_code=400, detail=f"Unknown IaC framework '{payload.iac}'. Available: {available}")

    # Parse IaC files
    try:
        state = plugin.parse(scan_path)
        regions: list[tuple[str, str]] = plugin.extract_regions(state)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Failed to parse IaC at '{scan_path}': {exc}") from exc

    # Run controls
    try:
        results = run_controls(controls, state, engine_name=payload.iac.lower())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Engine error: {exc}") from exc

    # Build findings list (mirrors cli.py --output json logic)
    findings: list[FindingSchema] = []
    for cr in results:
        for chk in cr.results:
            findings.append(FindingSchema(
                check_id=chk.check_id,
                check_title=chk.check_title,
                control_id=chk.control_id,
                pillar=cr.control.pillar,
                severity=chk.severity,
                status=chk.status,
                resource=chk.resource or "",
                message=chk.message or "",
                remediation=chk.remediation or "",
                example=chk.example,
            ))
        # Waived controls with no individual check results
        if cr.status == "WAIVED" and not cr.results:
            findings.append(FindingSchema(
                check_id=f"{cr.control.id}-WAIVED",
                check_title=cr.control.title,
                control_id=cr.control.id,
                pillar=cr.control.pillar,
                severity=cr.control.severity,
                status="WAIVED",
                resource="",
                message=getattr(cr, "waived_reason", "") or "",
                remediation="",
            ))

    # Compute pillar scores and overall score
    pillar_totals: dict[str, list[int]] = {}
    for cr in results:
        pillar_totals.setdefault(cr.control.pillar or "unknown", []).append(
            1 if cr.status == "PASS" else 0
        )
    pillar_scores: dict[str, int] = {
        p: int(sum(v) / len(v) * 100) if v else 0
        for p, v in pillar_totals.items()
    }
    score = int(sum(pillar_scores.values()) / len(pillar_scores)) if pillar_scores else 0

    # Build controls metadata
    controls_meta: list[ControlMetaSchema] = []
    for ctrl in controls:
        ctrl_checks = [
            ControlCheckMetaSchema(
                id=chk.id,
                title=chk.title,
                severity=chk.severity,
                remediation=chk.remediation or "",
                example=chk.example,
            )
            for chk in ctrl.checks
        ]
        controls_meta.append(ControlMetaSchema(
            id=ctrl.id,
            title=ctrl.title,
            pillar=ctrl.pillar,
            severity=ctrl.severity,
            category=getattr(ctrl, "category", ""),
            description=getattr(ctrl, "description", ""),
            rationale=getattr(ctrl, "rationale", ""),
            threat=getattr(ctrl, "threat", []),
            regulatory_mapping=getattr(ctrl, "regulatory_mapping", []),
            checks=ctrl_checks,
        ))

    # Persist as a Run record
    run = Run(
        id=uuid.uuid4(),
        project=payload.project,
        branch=payload.branch,
        git_sha="",
        triggered_by=payload.triggered_by,
        iac_framework=payload.iac.lower(),
        stage=payload.stage,
        score=score,
        pillar_scores=pillar_scores,
        findings=[f.model_dump() for f in findings],
        path=str(scan_path),
        controls_loaded=len(controls),
        controls_run=len(results),
        detected_regions=[[r, p] for r, p in regions],
        source_paths=[str(scan_path)],
        controls_meta=[c.model_dump() for c in controls_meta],
        secret_findings=[],
        plan_changes=None,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    return run
