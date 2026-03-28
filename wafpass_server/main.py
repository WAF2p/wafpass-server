"""WAF++ PASS server entry point."""
from __future__ import annotations

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from wafpass_server.config import settings
from wafpass_server.routers.runs import router as runs_router

app = FastAPI(
    title="wafpass-server",
    version="0.3.0",
    description="REST API for persisting and querying WAF++ PASS scan results.",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(runs_router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


def start() -> None:
    uvicorn.run("wafpass_server.main:app", host="0.0.0.0", port=8000, reload=False)


if __name__ == "__main__":
    start()
