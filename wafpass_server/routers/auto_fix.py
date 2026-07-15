"""POST /api/auto-fix — preview or apply automated IaC remediations.

This router exposes the wafpass-core auto-fixer to the dashboard so users can
preview patches, apply them server-side, and roll back from backups.
"""
from __future__ import annotations

import logging
import tempfile
import uuid
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("wafpass_server")

from wafpass_server.auth.deps import require_role
from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import Run, User

router = APIRouter(prefix="/api/auto-fix", tags=["auto-fix"])

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


# ── Request/response schemas ──────────────────────────────────────────────────

class AutoFixRequest(BaseModel):
    path: str
    iac: str = "terraform"
    control_ids: list[str] | None = None
    apply: bool = False


class AutoFixRollbackRequest(BaseModel):
    path: str
    iac: str = "terraform"


class AutoFixFindingInput(BaseModel):
    control_id: str
    check_id: str
    resource: str | None = None
    message: str | None = None


class AutoFixClassifyRequest(BaseModel):
    iac: str = "terraform"
    findings: list[AutoFixFindingInput]
    control_ids: list[str] | None = None
    run_id: str | None = None  # optional run whose source_snapshot should be used for diffs


# ── Helpers ───────────────────────────────────────────────────────────────────

def _resolve_and_validate(raw: str) -> Path:
    """Resolve raw path and enforce WAFPASS_SCAN_BASE_DIR when configured."""
    p = Path(raw)
    base_raw = (settings.wafpass_scan_base_dir or "").strip()
    if base_raw and not p.is_absolute():
        p = Path(base_raw) / p
    resolved = p.resolve()
    if base_raw:
        base_resolved = Path(base_raw).resolve()
        try:
            resolved.relative_to(base_resolved)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Path '{raw}' is outside the allowed scan base directory "
                    f"({base_resolved})."
                ),
            ) from exc
    if not resolved.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist on the server: {resolved}")
    if not (resolved.is_dir() or resolved.is_file()):
        raise HTTPException(status_code=400, detail=f"Path is not a file or directory: {resolved}")
    return resolved


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("")
async def api_auto_fix(
    req: AutoFixRequest,
    _: Annotated[User, Depends(require_role("clevel"))],
) -> dict[str, Any]:
    """Build (and optionally apply) a fix plan for failing checks."""
    if not _check_wafpass():
        raise HTTPException(
            status_code=503,
            detail="wafpass-core is not importable on this server.",
        )

    path = _resolve_and_validate(req.path)
    controls_dir = Path(settings.wafpass_controls_dir)
    if not controls_dir.exists():
        raise HTTPException(
            status_code=503,
            detail=f"Controls directory not found: {controls_dir.resolve()}.",
        )

    from wafpass.engine import run_controls  # type: ignore[import]
    from wafpass.fixer import (  # type: ignore[import]
        FixApplyResult,
        make_locator,
        apply_fix_plan,
        build_fix_plan,
        compute_fix_delta,
        render_diff,
    )
    from wafpass.iac import registry  # type: ignore[import]
    from wafpass.loader import load_controls  # type: ignore[import]
    from wafpass.waivers import apply_waivers, load_waivers  # type: ignore[import]

    try:
        controls = load_controls(controls_dir, ids=req.control_ids)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load controls: {exc}") from exc
    if not controls:
        raise HTTPException(status_code=422, detail="No controls loaded.")

    plugin = registry.get(req.iac.lower())
    if plugin is None:
        available = ", ".join(registry.available) or "(none)"
        raise HTTPException(
            status_code=400,
            detail=f"Unknown IaC framework '{req.iac}'. Available: {available}",
        )

    state = plugin.parse(path)
    results = run_controls(controls, state, engine_name=req.iac.lower())

    waivers_data = []
    waivers_file = Path(settings.wafpass_waivers_file or "")
    if waivers_file.exists():
        waivers_data = load_waivers(waivers_file)
    apply_waivers(results, waivers_data)

    source_paths = [path] if path.is_file() else [
        f
        for ext in plugin.file_extensions
        for f in path.rglob(f"*{ext}")
    ]
    locator = make_locator(req.iac.lower(), source_paths).build()
    plan = build_fix_plan(results, state, controls, locator, framework=req.iac.lower())

    base = path if path.is_dir() else path.parent

    patches_data = [
        {
            "file": str(p.file_path.relative_to(base)),
            "address": p.address,
            "attribute": p.attribute_path,
            "kind": p.patch_kind.name,
            "new_value": p.hcl_value,
            "description": p.description,
            "check_id": p.check_id,
            "control_id": p.control_id,
        }
        for p in plan.active_patches
    ]

    skipped_data = [
        {
            "check_id": s.check_id,
            "control_id": s.control_id,
            "address": s.address,
            "attribute": s.attribute,
            "op": s.op,
            "reason": s.reason,
        }
        for s in plan.skipped
    ]

    apply_result = apply_fix_plan(plan, locator, dry_run=not req.apply, backup=req.apply)
    assert isinstance(apply_result, FixApplyResult)

    diff_preview: dict[str, list[str]] = {}
    for fp, (orig, patched) in apply_result.diffs.items():
        diff_lines = render_diff(orig, patched, fp)
        if diff_lines:
            try:
                rel = str(fp.relative_to(base))
            except ValueError:
                rel = fp.name
            diff_preview[rel] = diff_lines

    files_modified = sorted(diff_preview.keys())

    response: dict[str, Any] = {
        "patches_count": len(plan.active_patches),
        "skipped_count": len(plan.skipped),
        "files_modified": files_modified,
        "applied": req.apply,
        "patches": patches_data,
        "skipped": skipped_data,
        "diff_preview": diff_preview,
        "warnings": apply_result.warnings,
        "delta": None,
    }

    if req.apply:
        new_state = plugin.parse(path)
        new_results = run_controls(controls, new_state, engine_name=req.iac.lower())
        apply_waivers(new_results, waivers_data)
        delta = compute_fix_delta(results, new_results)
        response["delta"] = {
            "resolved": delta.resolved,
            "still_failing": delta.still_failing,
            "regressions": delta.regressions,
        }

    return response


async def _build_diff_preview_from_snapshot(
    run_id: str,
    plan,
    framework: str,
    db: AsyncSession,
    user: User,
) -> tuple[dict[str, list[str]], list[str], dict[str, str]]:
    """Generate unified diffs by applying a fix plan to a stored source snapshot.

    The snapshot is written to a temporary directory, the resource locator is
    rebuilt from it, patch file paths are corrected, and the plan is applied in
    dry-run mode to produce per-file unified diffs.

    Returns ``(diff_preview, warnings, address_to_file)`` where ``address_to_file``
    maps a resource address to the relative IaC file path it lives in.
    """
    warnings: list[str] = []
    try:
        run_uuid = uuid.UUID(run_id)
    except ValueError:
        return {}, [f"Invalid run_id '{run_id}' — cannot look up source snapshot."], {}

    run = await db.get(Run, run_uuid)
    if run is None:
        return {}, [f"Run {run_id} not found — cannot generate diffs from snapshot."], {}

    # Enforce project-group access for non-admin users.
    if user.role != "admin":
        from wafpass_server.auth.deps import require_group_access
        await require_group_access(run.project, db, user)

    snapshot = run.source_snapshot or {}
    logger.info(
        "=== CLASSIFY SNAPSHOT DEBUG === run_id=%s snapshot_keys=%d run_path=%s triggered_by=%s",
        run_id, len(snapshot), run.path, run.triggered_by
    )
    if not snapshot:
        reason = (
            "This run was pushed from a CI/CD pipeline (POST /runs), so the source files were never uploaded."
            if run.triggered_by in {"cicd", "ci", "pipeline"}
            else "No source snapshot is stored for this run, so unified diffs cannot be generated in Local preview."
        )
        return {}, [reason], {}

    from wafpass.fixer import make_locator, apply_fix_plan, render_diff  # type: ignore[import]
    from wafpass.iac import registry  # type: ignore[import]

    plugin = registry.get(framework.lower())
    if plugin is None:
        return {}, [f"Unknown IaC framework '{framework}' — cannot render snapshot diffs."], {}

    with tempfile.TemporaryDirectory(prefix="wafpass-snapshot-") as tmp:
        tmp_path = Path(tmp)
        ext_set = set(plugin.file_extensions)
        for rel_path, content in snapshot.items():
            dest = tmp_path / rel_path
            if dest.suffix not in ext_set:
                continue
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8")
            except OSError as exc:
                warnings.append(f"Could not write snapshot file {rel_path}: {exc}")
                continue

        try:
            locator = make_locator(framework.lower(), [tmp_path]).build()
        except Exception as exc:
            return {}, [f"Could not build resource locator from snapshot: {exc}"]

        # Correct patch file paths and drop patches for resources not present in
        # the snapshot (e.g. module-generated addresses, provider/framework blocks).
        locatable_patches: list = []
        for p in plan.active_patches:
            loc = locator.get(p.address)
            if loc is not None:
                p.file_path = loc.file_path
                locatable_patches.append(p)
            else:
                # Only warn for resource-shaped addresses; provider/framework
                # blocks are not represented in the snapshot locator.
                if "." in p.address or "[" in p.address:
                    warnings.append(
                        f"Could not locate {p.address} in the source snapshot — diff omitted."
                    )

        # Build a temporary plan containing only locatable patches so
        # apply_fix_plan never tries to read Path("unknown").
        temp_plan = type(plan)(
            patches=locatable_patches,
            skipped=plan.skipped,
        )

        try:
            apply_result = apply_fix_plan(temp_plan, locator, dry_run=True, backup=False)
        except Exception as exc:
            return {}, [f"Could not apply fix plan to snapshot: {exc}"]

        warnings.extend(apply_result.warnings)

        diff_preview: dict[str, list[str]] = {}
        address_to_file: dict[str, str] = {}
        for fp, (orig, patched) in apply_result.diffs.items():
            diff_lines = render_diff(orig, patched, fp)
            if diff_lines:
                try:
                    rel = str(fp.relative_to(tmp_path))
                except ValueError:
                    rel = fp.name
                diff_preview[rel] = diff_lines

        # Record which relative file each address was patched in so the dashboard
        # can match a clicked patch row to its diff.
        for p in locatable_patches:
            try:
                rel = str(p.file_path.relative_to(tmp_path))
            except ValueError:
                continue
            address_to_file[p.address] = rel

        return diff_preview, warnings, address_to_file


@router.post("/classify")
async def api_auto_fix_classify(
    req: AutoFixClassifyRequest,
    user: Annotated[User, Depends(require_role("clevel"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, Any]:
    """Classify stored findings as fixable or manual and optionally render diffs.

    Uses the same provider registry and assertion logic as the full auto-fix
    endpoint, but does not read or write the real IaC files.  When a
    ``run_id`` is supplied and the run has a stored ``source_snapshot``, the
    endpoint writes the snapshot to a temp directory, rebuilds the resource
    locator, and returns real unified diffs for the dashboard local preview.
    """
    if not _check_wafpass():
        raise HTTPException(
            status_code=503,
            detail="wafpass-core is not importable on this server.",
        )

    from wafpass.fixer import (  # type: ignore[import]
        FindingInput,
        classify_findings,
    )
    from wafpass.loader import load_controls  # type: ignore[import]

    controls_dir = Path(settings.wafpass_controls_dir)
    if not controls_dir.exists():
        raise HTTPException(
            status_code=503,
            detail=f"Controls directory not found: {controls_dir.resolve() }.",
        )

    try:
        controls = load_controls(controls_dir, ids=req.control_ids)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load controls: {exc}") from exc
    if not controls:
        raise HTTPException(status_code=422, detail="No controls loaded.")

    inputs = [
        FindingInput(
            control_id=f.control_id,
            check_id=f.check_id,
            resource=f.resource,
            message=f.message,
        )
        for f in req.findings
    ]

    plan = classify_findings(inputs, controls, framework=req.iac.lower())

    diff_preview: dict[str, list[str]] = {}
    warnings: list[str] = []
    address_to_file: dict[str, str] = {}
    if req.run_id:
        diff_preview, snapshot_warnings, address_to_file = await _build_diff_preview_from_snapshot(
            req.run_id, plan, req.iac.lower(), db, user
        )
        warnings.extend(snapshot_warnings)
    else:
        warnings.append(
            "Local preview mode: no run_id was provided, so unified diffs are not generated. "
            "Use Server preview or run the CLI locally to see file-level changes."
        )

    patches_data = [
        {
            "file": address_to_file.get(p.address) or f"{p.address} resource",
            "address": p.address,
            "attribute": p.attribute_path,
            "kind": p.patch_kind.name,
            "new_value": p.hcl_value,
            "description": p.description,
            "check_id": p.check_id,
            "control_id": p.control_id,
        }
        for p in plan.active_patches
    ]

    skipped_data = [
        {
            "check_id": s.check_id,
            "control_id": s.control_id,
            "address": s.address,
            "attribute": s.attribute,
            "op": s.op,
            "reason": s.reason,
        }
        for s in plan.skipped
    ]

    files_modified = sorted(diff_preview.keys()) or (
        plan.active_patches and ["Preview derived from scan findings"] or []
    )

    return {
        "patches_count": len(plan.active_patches),
        "skipped_count": len(plan.skipped),
        "files_modified": files_modified,
        "applied": False,
        "patches": patches_data,
        "skipped": skipped_data,
        "diff_preview": diff_preview,
        "warnings": warnings,
        "delta": None,
    }


@router.post("/rollback")
async def api_auto_fix_rollback(
    req: AutoFixRollbackRequest,
    _: Annotated[User, Depends(require_role("clevel"))],
) -> dict[str, list[str]]:
    """Restore IaC source files from their `.bak` backups created by `wafpass fix --apply`."""
    if not _check_wafpass():
        raise HTTPException(
            status_code=503,
            detail="wafpass-core is not importable on this server.",
        )

    from wafpass.fixer import restore_backup  # type: ignore[import]
    from wafpass.iac import registry  # type: ignore[import]

    path = _resolve_and_validate(req.path)
    plugin = registry.get(req.iac.lower())
    if plugin is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown IaC framework '{req.iac}'.",
        )

    ext_set = set(plugin.file_extensions)
    if path.is_file():
        files = [path]
    else:
        files = sorted({
            f
            for ext in plugin.file_extensions
            for f in path.rglob(f"*{ext}")
        })

    restored: list[str] = []
    missing: list[str] = []
    for source_file in files:
        if source_file.suffix not in ext_set:
            continue
        if restore_backup(source_file):
            restored.append(str(source_file))
        else:
            missing.append(str(source_file))
    return {"restored": restored, "missing": missing}
