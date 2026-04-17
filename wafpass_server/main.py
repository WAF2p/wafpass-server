"""WAF++ PASS server entry point."""
from __future__ import annotations

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from wafpass_server.config import settings
from wafpass_server.routers.controls import router as controls_router
from wafpass_server.routers.risks import router as risks_router
from wafpass_server.routers.runs import router as runs_router
from wafpass_server.routers.sandbox import router as sandbox_router
from wafpass_server.routers.scan import router as scan_router
from wafpass_server.routers.waivers import router as waivers_router

app = FastAPI(
    title="wafpass-server",
    version="0.3.0",
    description="REST API for persisting and querying WAF++ PASS scan results.",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_tags=[
        {"name": "runs", "description": "Scan run results ingestion and retrieval."},
        {"name": "controls", "description": "WAF++ control catalogue management."},
        {"name": "waivers", "description": "Team-shared waiver records."},
        {"name": "risks", "description": "Team-shared risk acceptance records."},
        {"name": "sandbox", "description": "Run the real WAF++ engine against arbitrary HCL snippets."},
        {"name": "scan", "description": "Run the WAF++ engine against a server-side IaC path and persist the result."},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(runs_router)
app.include_router(controls_router)
app.include_router(waivers_router)
app.include_router(risks_router)
app.include_router(sandbox_router)
app.include_router(scan_router)


@app.get("/health", tags=["health"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


def start() -> None:
    uvicorn.run("wafpass_server.main:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    start()
