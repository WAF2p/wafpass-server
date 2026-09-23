"""WAF++ PASS server entry point."""
from __future__ import annotations

import asyncio
import logging
import os
import uvicorn
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import Validation
from wafpass_server.routers.auth import router as auth_router
from wafpass_server.routers.controls import router as controls_router
from wafpass_server.routers.control_packs import router as control_packs_router
from wafpass_server.routers.evidence import router as evidence_router
from wafpass_server.routers.risks import router as risks_router
from wafpass_server.routers.runs import router as runs_router
from wafpass_server.routers.sandbox import router as sandbox_router
from wafpass_server.routers.scan import router as scan_router
from wafpass_server.routers.achievements import router as achievements_router
from wafpass_server.routers.badges import router as badges_router
from wafpass_server.routers.leaderboard import router as leaderboard_router
from wafpass_server.routers.projects import router as projects_router
from wafpass_server.routers.sso import router as sso_router
from wafpass_server.routers.compliance_audit import router as compliance_audit_router
from wafpass_server.routers.waivers import router as waivers_router
from wafpass_server.routers.findings_comments import router as findings_comments_router
from wafpass_server.routers.secret_findings_comments import router as secret_findings_comments_router
from wafpass_server.routers.widgets import router as widgets_router
from wafpass_server.routers.notifications import router as notifications_router
from wafpass_server.routers.update_checker import router as update_router
from wafpass_server.routers.auto_fix import router as auto_fix_router
from wafpass_server.routers.validations import router as validations_router
from wafpass_server.validation_service import ValidationService, load_validation_service

# Framework update info path - configurable via environment variable
_FRAMEWORK_UPDATE_INFO_PATH = os.environ.get(
    "WAFPASS_UPDATE_INFO_PATH", "/app/framework-update-info.yml"
)

app = FastAPI(
    title="wafpass-server",
    version="1.0.0",
    description="REST API for persisting and querying WAF++ PASS scan results.",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_tags=[
        {"name": "auth", "description": "Login, token refresh, logout, user management."},
        {"name": "runs", "description": "Scan run results ingestion and retrieval."},
        {"name": "controls", "description": "WAF++ control catalogue management."},
        {"name": "control-packs", "description": "Versioned control pack import, activation and rollback."},
        {"name": "waivers", "description": "Team-shared waiver records."},
        {"name": "risks", "description": "Team-shared risk acceptance records."},
        {"name": "sandbox", "description": "Run the real WAF++ engine against arbitrary IaC snippets (currently HCL)."},
        {"name": "scan", "description": "Run the WAF++ engine against a server-side IaC path and persist the result."},
        {"name": "auto-fix", "description": "Preview, apply, and roll back automated IaC remediations."},
        {"name": "sso", "description": "SSO configuration and login flows (OIDC, SAML2)."},
        {"name": "evidence", "description": "Locked, immutable evidence packages for audit handouts with QR codes."},
        {"name": "projects", "description": "Project passport — per-project metadata, editable by admin and architect."},
        {"name": "achievements", "description": "Verified maturity achievements with public proof-of-excellence pages."},
        {"name": "badges", "description": "Live SVG status badges for READMEs — shields.io-style, no auth required."},
        {"name": "leaderboard", "description": "Hall of Fame — top sovereign and most improved projects."},
        {"name": "audit", "description": "Server-side compliance audit log — waiver, risk, scan, and finding events."},
        {"name": "findings-comments", "description": "Team collaboration on findings — comments, notifications, and remediation tracking."},
        {"name": "widgets", "description": "Widget management — create dashboards for compliance data display on computers, TVs, or web pages."},
        {"name": "validations", "description": "Official cryptographic validation of WAF++ PASS runs — certificate chain and badges."},
    ],
)

# In local development, allow any localhost/private-network origin so the Vite
# dev server (or a dashboard served from any local port/host) can call the API
# without manually maintaining CORS_ORIGINS. Production keeps the strict list.
_LOCAL_ORIGIN_REGEX = (
    r"https?://([a-zA-Z0-9.-]+|localhost|127\.0\.0\.1|192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?$"
    if settings.wafpass_env == "local"
    else None
)

# Local development: allow any localhost/cloud.waf2p origin regardless of port,
# so the dashboard works whether served through docker host networking, a custom
# DNS entry in /etc/hosts, or a Vite dev server on any port.
_cors_origins = settings.cors_origins_list
_cors_origin_regex = None
if settings.wafpass_env == "local":
    _cors_origin_regex = r"^http://(localhost|cloud\.waf2p)(:\d+)?$"

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_origin_regex=_LOCAL_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[],
)

app.include_router(auth_router, prefix="/api/v1")
app.include_router(compliance_audit_router, prefix="/api/v1")
app.include_router(sso_router, prefix="/api/v1")
app.include_router(achievements_router, prefix="/api/v1")
app.include_router(badges_router, prefix="/api/v1")
app.include_router(leaderboard_router, prefix="/api/v1")
app.include_router(runs_router, prefix="/api/v1")
app.include_router(controls_router, prefix="/api/v1")
app.include_router(control_packs_router, prefix="/api/v1")
app.include_router(waivers_router, prefix="/api/v1")
app.include_router(risks_router, prefix="/api/v1")
app.include_router(evidence_router, prefix="/api/v1")
app.include_router(projects_router, prefix="/api/v1")
app.include_router(findings_comments_router, prefix="/api/v1")
app.include_router(secret_findings_comments_router, prefix="/api/v1")
app.include_router(sandbox_router, prefix="/api/v1")
app.include_router(scan_router, prefix="/api/v1")
app.include_router(widgets_router, prefix="/api/v1")
app.include_router(notifications_router, prefix="/api/v1")
app.include_router(update_router, prefix="/api/v1")
app.include_router(auto_fix_router, prefix="/api/v1")


# Module-level validation service singleton for public trust endpoints.
_validation_service: ValidationService | None = None


def _get_validation_service() -> ValidationService:
    global _validation_service
    if _validation_service is None:
        keys_dir = settings.wafpass_validation_keys_dir or None
        subca_cert_path = settings.wafpass_server_subca_cert or None
        _validation_service = load_validation_service(
            keys_dir=keys_dir,
            subca_cert_path=subca_cert_path,
        )
    return _validation_service


@app.get("/api/v1/validations/root.crt", tags=["validations"])
async def get_root_certificate() -> Response:
    """Publish the WAF++ root CA certificate (public trust anchor)."""
    service = _get_validation_service()
    return Response(
        content=service.root_cert_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="wafpass-root.crt"'},
    )


@app.get("/api/v1/validations/server.crt", tags=["validations"])
async def get_server_certificate() -> Response:
    """Publish this wafpass-server's gateway-issued sub-CA certificate.

    The dashboard and CLI include this certificate when submitting validation
    runs to the central WAF++ gateway so the gateway can verify the server's
    identity against its registered certificate registry.
    """
    service = _get_validation_service()
    cert_pem = service.server_subca_certificate_pem
    return Response(
        content=cert_pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": 'attachment; filename="wafpass-server.crt"'},
    )


@app.get("/api/v1/revocations", tags=["validations"])
async def get_revocation_list(
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return a signed list of all revoked validation IDs (public).

    The list is signed by the WAF++ server intermediate key so verifiers can
    check it offline against the published root certificate.
    """
    result = await db.execute(select(Validation.validation_id).where(Validation.status == "revoked"))
    revoked_ids = sorted(row[0] for row in result.all())

    service = _get_validation_service()
    return service.sign_revocation_list(revoked_validation_ids=revoked_ids)


app.include_router(validations_router, prefix="/api/v1")


@app.get("/framework-update-info.yml", tags=["updates"])
async def get_framework_update_info() -> FileResponse:
    """Serve the framework update information YAML file.

    This endpoint returns the auto-generated update info file that contains
    version information from the public WAF++ framework repository on GitHub.
    """
    if not os.path.exists(_FRAMEWORK_UPDATE_INFO_PATH):
        raise HTTPException(status_code=404, detail="Update info not available yet")
    return FileResponse(
        _FRAMEWORK_UPDATE_INFO_PATH, media_type="text/yaml", filename="framework-update-info.yml"
    )


@app.get("/health", tags=["health"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/version", tags=["health"])
async def version() -> dict[str, str]:
    """Return version information for the server and wafpass-core."""
    from wafpass_server import __version__ as server_version
    try:
        from importlib.metadata import version as _pkg_version
        core_version = _pkg_version("wafpass-core")
    except Exception:
        core_version = "unknown"
    return {
        "server_version": server_version,
        "core_version": core_version,
        "wafpass_server": server_version,
        "wafpass_core": core_version,
    }


# Background task for hourly update checking
_update_checker_task: asyncio.Task | None = None


async def _hourly_update_checker() -> None:
    """Background task that runs hourly update checks."""
    import asyncio
    from wafpass_server.update_checker import generate_update_info

    while True:
        try:
            # Run the update check using configurable path
            await generate_update_info(_FRAMEWORK_UPDATE_INFO_PATH)
            logging.getLogger("wafpass_server").info("Framework update check completed")
        except Exception as e:
            logging.getLogger("wafpass_server").error(f"Framework update check failed: {e}")

        # Sleep for 1 hour (3600 seconds)
        await asyncio.sleep(3600)


def _validate_startup_config() -> None:
    """Fail fast if required secrets are missing or still placeholders."""
    import sys

    logger = logging.getLogger("wafpass_server")
    try:
        # Force the Pydantic model to validate; this catches placeholder JWT secrets.
        settings.model_validate(settings.model_dump())
    except ValueError as exc:
        logger.error("Invalid server configuration: %s", exc)
        sys.exit(1)

    required = ["WAFPASS_JWT_SECRET"]
    missing = [k for k in required if not getattr(settings, k.lower(), None)]
    if missing:
        logger.error(
            "Missing required environment variables: %s. "
            "Run 'wafpass init --mode dashboard' to generate a valid .env file.",
            ", ".join(missing),
        )
        sys.exit(1)


@app.on_event("startup")
async def _configure_logging_and_seed_admin() -> None:
    """Configure logging, validate config, and create the bootstrap admin user if no users exist."""
    global _update_checker_task

    # Configure logging to show DEBUG level messages
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )
    logger = logging.getLogger("wafpass_server")
    logger.info("=== WAF++ Server starting ===")

    # Validate configuration before attempting database connections.
    _validate_startup_config()

    # Generate initial update info on startup (always run, regardless of seeding)
    logger.info("Generating initial framework update info...")
    try:
        from wafpass_server.update_checker import generate_update_info
        await generate_update_info(_FRAMEWORK_UPDATE_INFO_PATH)
        logging.getLogger("wafpass_server").info("Initial framework update info generated successfully")
    except Exception as e:
        logging.getLogger("wafpass_server").error(f"Failed to generate initial update info: {e}")
        import traceback
        logging.getLogger("wafpass_server").error(f"Traceback: {traceback.format_exc()}")

    if not settings.wafpass_admin_password:
        return  # seeding disabled

    from sqlalchemy import select, func
    from wafpass_server.database import AsyncSessionLocal
    from wafpass_server.models import User
    from wafpass_server.auth.providers.local import hash_password

    async with AsyncSessionLocal() as db:
        count = (await db.execute(select(func.count()).select_from(User))).scalar_one()
        if count > 0:
            logger.info("Users already exist — skipping admin seeding")
            return  # users already exist — don't overwrite anything

        admin = User(
            username=settings.wafpass_admin_username,
            display_name="Administrator",
            role=settings.wafpass_admin_role,
            auth_provider="local",
            password_hash=hash_password(settings.wafpass_admin_password),
        )
        db.add(admin)
        await db.commit()
        print(
            f"[wafpass-server] Seeded admin user '{settings.wafpass_admin_username}' "
            f"with role '{settings.wafpass_admin_role}'."
        )

    logger.info("=== WAF++ Server ready ===")

    # Start the hourly update checker task
    _update_checker_task = asyncio.create_task(_hourly_update_checker())


def start() -> None:
    uvicorn.run("wafpass_server.main:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    start()
