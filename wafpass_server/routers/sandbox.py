"""POST /sandbox — run the real WAF++ engine against user-supplied HCL."""
from __future__ import annotations

import tempfile
from pathlib import Path

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from pydantic import BaseModel

import secrets

from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import IngestAuth, require_role
from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import User
from wafpass_server.routers.runs import _persist_run
from wafpass_server.schemas import Envelope, RunCreate, RunSummary

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


_DEMO_MAIN_TF = """\
# WAF++ PASS demo file — intentionally contains a public S3 bucket.
# This file is generated for local scanning only; do not deploy it to AWS.

resource "aws_s3_bucket" "example" {{
  bucket = "{bucket_name}"
}}

resource "aws_s3_bucket_public_access_block" "example" {{
  bucket = aws_s3_bucket.example.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}}
"""


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


def _build_demo_result(
    raw_results: list,
    controls: list,
    scan_dir: str,
    bucket_name: str,
) -> "WafpassResultSchema":
    """Turn raw engine output into a full wafpass-result.json schema for persistence."""
    from wafpass.schema import (
        ControlCheckMetaSchema,
        ControlMetaSchema,
        FindingSchema,
        WafpassResultSchema,
    )

    findings: list[FindingSchema] = []
    pillar_bucket: dict[str, list[int]] = {}
    total_pass = total_fail = total_skip = 0

    for cr in raw_results:
        if not cr.results:
            total_skip += 1
            continue

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

        pillar_bucket.setdefault(cr.control.pillar, []).append(
            1 if ctrl_status == "PASS" else 0
        )

        for r in cr.results:
            findings.append(
                FindingSchema(
                    check_id=r.check_id,
                    check_title=r.check_title,
                    control_id=r.control_id,
                    pillar=cr.control.pillar,
                    severity=r.severity,
                    status=r.status.upper(),
                    resource=r.resource or "",
                    message=r.message or "",
                    remediation=r.remediation or "",
                    example=r.example,
                    regulatory_mapping=cr.control.regulatory_mapping,
                )
            )

    scored = total_pass + total_fail
    score = round(total_pass / scored * 100) if scored else 100
    pillar_scores = {
        p: int(sum(v) / len(v) * 100) for p, v in pillar_bucket.items() if v
    }

    controls_meta: list[ControlMetaSchema] = []
    for ctrl in controls:
        checks = [
            ControlCheckMetaSchema(
                id=chk.id,
                title=chk.title,
                severity=chk.severity,
                remediation=chk.remediation,
                example=chk.example,
            )
            for chk in ctrl.checks
        ]
        controls_meta.append(
            ControlMetaSchema(
                id=ctrl.id,
                title=ctrl.title,
                pillar=ctrl.pillar,
                severity=ctrl.severity,
                category=ctrl.category,
                description=ctrl.description,
                rationale=ctrl.rationale,
                threat=ctrl.threat,
                regulatory_mapping=ctrl.regulatory_mapping,
                checks=checks,
            )
        )

    source_snapshot = {"main.tf": _DEMO_MAIN_TF.format(bucket_name=bucket_name)}

    return WafpassResultSchema(
        schema_version="1.1",
        project="wafpass-demo",
        branch="main",
        git_sha="",
        triggered_by="local",
        run={"is_cicd": False},
        iac_framework="terraform",
        stage="demo",
        score=score,
        pillar_scores=pillar_scores,
        path=scan_dir,
        controls_loaded=len(controls),
        controls_run=len(raw_results),
        detected_regions=[],
        source_paths=[scan_dir],
        controls_meta=controls_meta,
        findings=findings,
        secret_findings=[],
        source_snapshot=source_snapshot,
    )


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


@router.post("/demo-run", response_model=Envelope[RunSummary], status_code=201)
async def create_demo_run(
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role("clevel"))],
) -> Envelope[RunSummary]:
    """Seed the dashboard with a one-click demo scan result.

    Runs the real WAF++ engine against an intentionally non-compliant S3 bucket
    snippet and persists the result as a normal run so the empty-state dashboard
    immediately shows a populated report.
    """
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

    bucket_name = f"wafpass-demo-{secrets.token_hex(4)}"

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            hcl_file = Path(tmpdir) / "main.tf"
            hcl_file.write_text(
                _DEMO_MAIN_TF.format(bucket_name=bucket_name),
                encoding="utf-8",
            )

            try:
                plugin = registry.get("terraform")
            except Exception as exc:
                raise HTTPException(status_code=400, detail=f"Unknown IaC engine: terraform") from exc

            try:
                state = plugin.parse(Path(tmpdir))
            except Exception as exc:
                raise HTTPException(status_code=422, detail=f"Failed to parse HCL: {exc}") from exc

            try:
                raw_results = run_controls(controls, state, engine_name="terraform")
            except Exception as exc:
                raise HTTPException(status_code=500, detail=f"Engine error: {exc}") from exc

            result = _build_demo_result(raw_results, controls, tmpdir, bucket_name)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    payload = RunCreate(**result.model_dump())
    summary = await _persist_run(db, payload, IngestAuth(user=user), None)
    return Envelope(data=summary)


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
