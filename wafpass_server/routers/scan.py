"""POST /scan — run the WAF++ engine against a server-side IaC path and persist as a Run.

Unlike /sandbox (ephemeral, IaC-snippet only), this endpoint:
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

import logging
import uuid
from pathlib import Path
from typing import Annotated, Union

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import IngestAuth, require_ingest, require_role
from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import ApiKeyUsageLog, Run, User
from wafpass_server.schemas import Envelope, FindingSchema, RunSummary

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan", tags=["scan"])

# Valid pillar values (matching the schema and dashboard)
_VALID_PILLARS = ["security", "cost", "operations", "performance", "reliability", "sovereign", "sustainability", "agentic"]

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
async def scan_status(
    _: Annotated[User, Depends(require_role("clevel"))],
) -> dict:
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


@router.post("", response_model=Envelope[RunSummary], status_code=201)
async def trigger_scan(
    request: Request,
    payload: ScanRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    auth: Annotated[IngestAuth, Depends(require_ingest)],
) -> Envelope[RunSummary]:
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
    from wafpass.runner import ScanConfig, run_scan  # type: ignore[import]

    try:
        _report, result = run_scan(ScanConfig(
            paths=[scan_path],
            controls_dir=controls_dir,
            iac=payload.iac,
            project=payload.project,
            branch=payload.branch,
            stage=payload.stage,
            triggered_by=payload.triggered_by,
            upload_source=True,
        ))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc

    # Normalize pillar names: database may have "operational", use "operations" for consistency
    def normalize_pillar(p: str) -> str:
        if p == "operational":
            return "operations"
        return p

    # Ensure all valid pillars are represented (score 0 if missing)
    pillar_scores: dict[str, int] = {p: 0 for p in _VALID_PILLARS}
    for p, score in result.pillar_scores.items():
        normalized = normalize_pillar(p)
        if normalized in pillar_scores:
            pillar_scores[normalized] = score

    # Persist as a Run record
    run = Run(
        id=uuid.uuid4(),
        project=result.project,
        branch=result.branch,
        git_sha=result.git_sha,
        triggered_by=result.triggered_by,
        run_metadata=result.run,
        iac_framework=result.iac_framework,
        stage=result.stage,
        score=result.score,
        pillar_scores=pillar_scores,
        findings=[f.model_dump() for f in result.findings],
        path=result.path,
        controls_loaded=result.controls_loaded,
        controls_run=result.controls_run,
        detected_regions=result.detected_regions,
        source_paths=result.source_paths,
        controls_meta=[c.model_dump() for c in result.controls_meta],
        secret_findings=[sf.model_dump() for sf in result.secret_findings],
        plan_changes=result.plan_changes,
        source_snapshot=result.source_snapshot,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    from wafpass_server.routers.achievements import evaluate_and_record_achievements
    from wafpass_server.routers.runs import _finding_rows
    server_findings = [FindingSchema(**f.model_dump()) for f in result.findings]
    if server_findings:
        db.add_all(_finding_rows(run.id, server_findings))
        await db.commit()

    await evaluate_and_record_achievements(db, run)

    # Write a usage log row when a DB-tracked API key was used
    if auth.api_key_id is not None:
        client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "")
        db.add(ApiKeyUsageLog(
            api_key_id=auth.api_key_id,
            endpoint="POST /scan",
            run_id=run.id,
            project=run.project,
            branch=run.branch,
            score=run.score,
            ip=client_ip,
        ))
        await db.commit()

    return Envelope(data=RunSummary.model_validate(run, from_attributes=True))
