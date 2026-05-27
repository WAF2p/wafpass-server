"""WAF++ PASS server entry point."""
from __future__ import annotations

import asyncio
import logging
import os
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer

from wafpass_server.config import settings
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

# Framework update info path - configurable via environment variable
_FRAMEWORK_UPDATE_INFO_PATH = os.environ.get(
    "WAFPASS_UPDATE_INFO_PATH", "/app/framework-update-info.yml"
)

app = FastAPI(
    title="wafpass-server",
    version="1.0.0",
    description="REST API for persisting and querying WAF++ PASS scan results.",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_tags=[
        {"name": "auth", "description": "Login, token refresh, logout, user management."},
        {"name": "runs", "description": "Scan run results ingestion and retrieval."},
        {"name": "controls", "description": "WAF++ control catalogue management."},
        {"name": "control-packs", "description": "Versioned control pack import, activation and rollback."},
        {"name": "waivers", "description": "Team-shared waiver records."},
        {"name": "risks", "description": "Team-shared risk acceptance records."},
        {"name": "sandbox", "description": "Run the real WAF++ engine against arbitrary HCL snippets."},
        {"name": "scan", "description": "Run the WAF++ engine against a server-side IaC path and persist the result."},
        {"name": "sso", "description": "SSO configuration and login flows (OIDC, SAML2)."},
        {"name": "evidence", "description": "Locked, immutable evidence packages for audit handouts with QR codes."},
        {"name": "projects", "description": "Project passport — per-project metadata, editable by admin and architect."},
        {"name": "achievements", "description": "Verified maturity achievements with public proof-of-excellence pages."},
        {"name": "badges", "description": "Live SVG status badges for READMEs — shields.io-style, no auth required."},
        {"name": "leaderboard", "description": "Hall of Fame — top sovereign and most improved projects."},
        {"name": "audit", "description": "Server-side compliance audit log — waiver, risk, scan, and finding events."},
        {"name": "findings-comments", "description": "Team collaboration on findings — comments, notifications, and remediation tracking."},
        {"name": "widgets", "description": "Widget management — create dashboards for compliance data display on computers, TVs, or web pages."},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[],
)

app.include_router(auth_router)
app.include_router(compliance_audit_router)
app.include_router(sso_router)
app.include_router(achievements_router)
app.include_router(badges_router)
app.include_router(leaderboard_router)
app.include_router(runs_router)
app.include_router(controls_router)
app.include_router(control_packs_router)
app.include_router(waivers_router)
app.include_router(risks_router)
app.include_router(evidence_router)
app.include_router(projects_router)
app.include_router(findings_comments_router)
app.include_router(secret_findings_comments_router)
app.include_router(sandbox_router)
app.include_router(scan_router)
app.include_router(widgets_router)
app.include_router(notifications_router)
app.include_router(update_router)


@app.get("/framework-update-info.yml", tags=["updates"])
async def get_framework_update_info() -> FileResponse:
    """Serve the framework update information YAML file.

    This endpoint returns the auto-generated update info file that contains
    version information from both the German and English WAF++ framework repositories.
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


@app.on_event("startup")
async def _configure_logging_and_seed_admin() -> None:
    """Configure logging and create the bootstrap admin user if no users exist."""
    global _update_checker_task

    # Configure logging to show DEBUG level messages
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )
    logger = logging.getLogger("wafpass_server")
    logger.info("=== WAF++ Server starting ===")

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
