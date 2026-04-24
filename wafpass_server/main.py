"""WAF++ PASS server entry point."""
from __future__ import annotations

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer

from wafpass_server.config import settings
from wafpass_server.routers.auth import router as auth_router
from wafpass_server.routers.controls import router as controls_router
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
from wafpass_server.routers.waivers import router as waivers_router

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
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(sso_router)
app.include_router(achievements_router)
app.include_router(badges_router)
app.include_router(leaderboard_router)
app.include_router(runs_router)
app.include_router(controls_router)
app.include_router(waivers_router)
app.include_router(risks_router)
app.include_router(evidence_router)
app.include_router(projects_router)
app.include_router(sandbox_router)
app.include_router(scan_router)


@app.get("/health", tags=["health"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.on_event("startup")
async def _seed_admin() -> None:
    """Create the bootstrap admin user if no users exist and credentials are configured."""
    if not settings.wafpass_admin_password:
        return  # seeding disabled

    from sqlalchemy import select, func
    from wafpass_server.database import AsyncSessionLocal
    from wafpass_server.models import User
    from wafpass_server.auth.providers.local import hash_password

    async with AsyncSessionLocal() as db:
        count = (await db.execute(select(func.count()).select_from(User))).scalar_one()
        if count > 0:
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


def start() -> None:
    uvicorn.run("wafpass_server.main:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    start()
