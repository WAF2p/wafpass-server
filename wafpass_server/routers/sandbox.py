"""POST /sandbox — run the real WAF++ engine against user-supplied HCL."""
from __future__ import annotations

import tempfile
from pathlib import Path

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

from wafpass_server.auth.deps import require_role
from wafpass_server.config import settings
from wafpass_server.models import User

router = APIRouter(prefix="/sandbox", tags=["sandbox"])

# Lazily resolved so the server starts even if wafpass-core is not installed.
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


class SandboxRequest(BaseModel):
    hcl: str
    filename: str = "main.tf"
    iac: str = "terraform"


class SandboxCheckResult(BaseModel):
    check_id: str
    check_title: str
    control_id: str
    severity: str
    status: str
    resource: str
    message: str
    remediation: str


class SandboxControlResult(BaseModel):
    control_id: str
    control_title: str
    pillar: str
    severity: str
    status: str
    check_results: list[SandboxCheckResult]


class SandboxResponse(BaseModel):
    engine: str  # "real" | "unavailable"
    controls_dir: str
    controls_loaded: int
    score: int
    total_pass: int
    total_fail: int
    total_skip: int
    results: list[SandboxControlResult]


@router.post("", response_model=SandboxResponse)
async def run_sandbox(
    payload: SandboxRequest,
    _: Annotated[User, Depends(require_role("architect"))],
) -> SandboxResponse:
    if not _check_wafpass():
        raise HTTPException(
            status_code=503,
            detail=(
                "wafpass-core is not installed on this server. "
                "Install it with: pip install wafpass-core  "
                "and set WAFPASS_CONTROLS_DIR to the path of your control YAML files."
            ),
        )

    controls_dir = Path(settings.wafpass_controls_dir)
    if not controls_dir.exists():
        raise HTTPException(
            status_code=503,
            detail=(
                f"Controls directory not found: {controls_dir.resolve()}. "
                "Set the WAFPASS_CONTROLS_DIR environment variable to the path "
                "containing your WAF++ YAML control files."
            ),
        )

    # Import here so the module loads even when wafpass is absent
    from wafpass.engine import run_controls  # type: ignore[import]
    from wafpass.iac import registry  # type: ignore[import]
    from wafpass.loader import load_controls  # type: ignore[import]

    try:
        controls = load_controls(controls_dir)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load controls: {exc}") from exc

    if not controls:
        raise HTTPException(
            status_code=503,
            detail=f"No controls found in {controls_dir.resolve()}.",
        )

    # Write HCL to a temp directory and parse it
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            hcl_file = Path(tmpdir) / payload.filename
            hcl_file.write_text(payload.hcl, encoding="utf-8")

            try:
                plugin = registry.get(payload.iac.lower())
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Unknown IaC engine: {payload.iac}") from exc

            try:
                state = plugin.parse(Path(tmpdir))
            except Exception as exc:
                raise HTTPException(status_code=422, detail=f"Failed to parse HCL: {exc}") from exc

            try:
                raw_results = run_controls(controls, state, engine_name=payload.iac.lower())
            except Exception as exc:
                raise HTTPException(status_code=500, detail=f"Engine error: {exc}") from exc

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    # Convert to response schema
    out_results: list[SandboxControlResult] = []
    total_pass = total_fail = total_skip = 0

    for cr in raw_results:
        if not cr.results:
            out_results.append(SandboxControlResult(
                control_id=cr.control.id,
                control_title=cr.control.title,
                pillar=cr.control.pillar,
                severity=cr.control.severity,
                status="SKIP",
                check_results=[],
            ))
            total_skip += 1
            continue

        check_results: list[SandboxCheckResult] = [
            SandboxCheckResult(
                check_id=r.check_id,
                check_title=r.check_title,
                control_id=r.control_id,
                severity=r.severity,
                status=r.status.upper(),
                resource=r.resource or "",
                message=r.message or "",
                remediation=r.remediation or "",
            )
            for r in cr.results
        ]

        statuses = [r.status.upper() for r in cr.results]
        if "FAIL" in statuses:
            ctrl_status = "FAIL"
            total_fail += 1
        elif all(s == "PASS" for s in statuses):
            ctrl_status = "PASS"
            total_pass += 1
        else:
            ctrl_status = "SKIP"
            total_skip += 1

        out_results.append(SandboxControlResult(
            control_id=cr.control.id,
            control_title=cr.control.title,
            pillar=cr.control.pillar,
            severity=cr.control.severity,
            status=ctrl_status,
            check_results=check_results,
        ))

    scored = total_pass + total_fail
    score = round(total_pass / scored * 100) if scored else 100

    return SandboxResponse(
        engine="real",
        controls_dir=str(controls_dir.resolve()),
        controls_loaded=len(controls),
        score=score,
        total_pass=total_pass,
        total_fail=total_fail,
        total_skip=total_skip,
        results=out_results,
    )


@router.get("/status")
async def sandbox_status(
    _: Annotated[User, Depends(require_role("clevel"))],
) -> dict:
    """Check whether the real engine is available."""
    available = _check_wafpass()
    controls_dir = Path(settings.wafpass_controls_dir)
    return {
        "engine_available": available,
        "controls_dir": str(controls_dir.resolve()),
        "controls_dir_exists": controls_dir.exists(),
    }
