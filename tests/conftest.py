"""Shared fixtures for the multi-mandant integration test suite (Phase 5).

These tests exercise real PostgreSQL row-level security end to end — RLS
cannot be meaningfully approximated with SQLite or a mocked session, and
most of what this suite checks (isolation, the one-way activation DDL,
bootstrap carve-outs) only exists at the database layer. See
decisions/adrs/ADR-003-multi-mandant-tenancy.md and .plan.md, Phase 5.

They require a real, reachable Postgres *server* (not a specific database —
each test creates and drops its own) and are skipped automatically,
module-wide, when none is configured. CI has no Postgres service today, so
this keeps the existing suite green there without one; set
WAFPASS_TEST_DATABASE_URL to actually run them, locally or in a future CI
job with a Postgres service container:

    docker run -d --rm --name wafpass-pg-test \\
        -e POSTGRES_PASSWORD=postgres -p 55432:5432 postgres:16-alpine
    export WAFPASS_TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:55432/postgres
    pytest tests/test_mandants.py

Each test function gets its own freshly-migrated, uniquely-named database
(created before the test, dropped after), never a shared one — multi-mandant
activation is one-way by design (ADR-003), so tests that activate it cannot
share state with tests that need single-tenant mode.
"""
from __future__ import annotations

import os

# Must be set before any `wafpass_server.*` import below triggers
# Settings() validation — see config.py, which rejects its own default.
os.environ.setdefault("WAFPASS_JWT_SECRET", "test-only-secret-not-for-any-real-deployment-at-all")

import asyncio
import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from pathlib import Path

import asyncpg
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

_REPO_ROOT = Path(__file__).resolve().parent.parent
_APP_ROLE = "wafpass_app"
_APP_PASSWORD = "wafpass_app_test_password"


def _server_dsn() -> str | None:
    return os.environ.get("WAFPASS_TEST_DATABASE_URL")


async def _run_migrations(database_async_url: str) -> None:
    def _upgrade() -> None:
        cfg = Config(str(_REPO_ROOT / "alembic.ini"))
        cfg.set_main_option("script_location", str(_REPO_ROOT / "alembic"))
        cfg.set_main_option("sqlalchemy.url", database_async_url)
        # env.py unconditionally prefers DATABASE_URL over sqlalchemy.url
        # when the env var is set — mirror the real deployment/entrypoint.sh
        # path exactly rather than fight it.
        old = os.environ.get("DATABASE_URL")
        os.environ["DATABASE_URL"] = database_async_url
        try:
            command.upgrade(cfg, "head")
        finally:
            if old is None:
                os.environ.pop("DATABASE_URL", None)
            else:
                os.environ["DATABASE_URL"] = old

    # alembic's command.upgrade() calls asyncio.run() internally — invoking
    # it directly from inside pytest-asyncio's already-running event loop
    # would raise "cannot be called from a running event loop". Running it
    # in a worker thread sidesteps that entirely.
    await asyncio.to_thread(_upgrade)


async def _ensure_app_role(owner_dsn: asyncpg.Connection, db_name: str) -> None:
    """Idempotently (re)create wafpass_app and grant it access to *db_name*.

    Same approach as entrypoint.sh's ensure_runtime_role() and
    db-init/02-wafpass-app-role.sql — duplicated here (not imported) since
    entrypoint.sh is a standalone shell+heredoc script, not an importable
    module, and the SQL itself is only a handful of idempotent statements.
    """
    password_literal = "'" + _APP_PASSWORD.replace("'", "''") + "'"
    exists = await owner_dsn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", _APP_ROLE)
    if exists:
        await owner_dsn.execute(f'ALTER ROLE "{_APP_ROLE}" WITH LOGIN PASSWORD {password_literal} NOSUPERUSER NOBYPASSRLS')
    else:
        await owner_dsn.execute(f'CREATE ROLE "{_APP_ROLE}" WITH LOGIN PASSWORD {password_literal} NOSUPERUSER NOBYPASSRLS')
    await owner_dsn.execute(f'GRANT CONNECT ON DATABASE "{db_name}" TO "{_APP_ROLE}"')
    await owner_dsn.execute(f'GRANT USAGE ON SCHEMA public TO "{_APP_ROLE}"')
    await owner_dsn.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "{_APP_ROLE}"')
    await owner_dsn.execute(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{_APP_ROLE}"')
    await owner_dsn.execute(f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "{_APP_ROLE}"')
    await owner_dsn.execute(f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO "{_APP_ROLE}"')


@dataclass
class MandantTestDb:
    """Everything a test needs to talk to its own isolated Postgres database.

    ``owner_engine``/``owner_sessionmaker`` connect as the migration/DDL
    superuser (bypasses RLS, same role Alembic and the activation endpoint
    use) — for seeding fixture data and asserting on raw state.
    ``app_engine``/``app_sessionmaker`` connect as the non-superuser
    ``wafpass_app`` role — the one RLS is actually enforced against,
    exactly like ordinary runtime traffic.
    """
    owner_engine: AsyncEngine
    app_engine: AsyncEngine
    owner_sessionmaker: async_sessionmaker
    app_sessionmaker: async_sessionmaker
    db_name: str
    app_role: str = _APP_ROLE
    app_password: str = _APP_PASSWORD


@pytest_asyncio.fixture
async def mandant_db() -> AsyncGenerator[MandantTestDb, None]:
    server_dsn = _server_dsn()
    if not server_dsn:
        pytest.skip(
            "Set WAFPASS_TEST_DATABASE_URL to a reachable Postgres server "
            "(e.g. postgresql://postgres:postgres@localhost:55432/postgres) "
            "to run the multi-mandant integration suite. See tests/conftest.py."
        )

    server_url = make_url(server_dsn)
    db_name = f"wafpass_test_{uuid.uuid4().hex[:16]}"

    maintenance_db = server_url.database or "postgres"
    admin_conn = await asyncpg.connect(
        user=server_url.username, password=server_url.password,
        host=server_url.host, port=server_url.port or 5432, database=maintenance_db,
    )
    try:
        await admin_conn.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        await admin_conn.close()

    owner_async_url = (
        f"postgresql+asyncpg://{server_url.username}:{server_url.password}"
        f"@{server_url.host}:{server_url.port or 5432}/{db_name}"
    )
    app_async_url = (
        f"postgresql+asyncpg://{_APP_ROLE}:{_APP_PASSWORD}"
        f"@{server_url.host}:{server_url.port or 5432}/{db_name}"
    )

    try:
        await _run_migrations(owner_async_url)

        owner_conn = await asyncpg.connect(
            user=server_url.username, password=server_url.password,
            host=server_url.host, port=server_url.port or 5432, database=db_name,
        )
        try:
            await _ensure_app_role(owner_conn, db_name)
        finally:
            await owner_conn.close()

        owner_engine = create_async_engine(owner_async_url, pool_pre_ping=True)
        app_engine = create_async_engine(app_async_url, pool_pre_ping=True)

        try:
            yield MandantTestDb(
                owner_engine=owner_engine,
                app_engine=app_engine,
                owner_sessionmaker=async_sessionmaker(owner_engine, expire_on_commit=False),
                app_sessionmaker=async_sessionmaker(app_engine, expire_on_commit=False),
                db_name=db_name,
            )
        finally:
            await owner_engine.dispose()
            await app_engine.dispose()
    finally:
        admin_conn = await asyncpg.connect(
            user=server_url.username, password=server_url.password,
            host=server_url.host, port=server_url.port or 5432, database=maintenance_db,
        )
        try:
            await admin_conn.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = $1 AND pid <> pg_backend_pid()",
                db_name,
            )
            await admin_conn.execute(f'DROP DATABASE IF EXISTS "{db_name}"')
        finally:
            await admin_conn.close()


@pytest_asyncio.fixture
async def app_client(mandant_db: MandantTestDb):
    """An httpx client against the real FastAPI app (wafpass_server.main:app),
    with its two database entry points redirected to this test's isolated
    database instead of whatever `settings.*_database_url` happens to
    default to.

    - `get_db` (and therefore `get_scoped_db`, which depends on it, and
      every ordinary request path) is swapped via FastAPI's own
      `dependency_overrides` — the idiomatic mechanism, safe here because
      `get_db` is *only* ever used via `Depends(get_db)` in this codebase
      (confirmed by grep), never called directly.
    - `get_owner_connection` is used differently: `admin.py` calls it
      directly inside the handler body (`async with get_owner_connection()
      as conn:`), not through `Depends()`, so `dependency_overrides` cannot
      intercept it at all. Pre-seeding `wafpass_server.database._owner_engine`
      with our own engine works instead: `_get_owner_engine()`'s lazy-init
      (`if _owner_engine is None: ...`) then never fires, and the
      unmodified `get_owner_connection()` uses our engine without any
      patch to its own code.
    """
    import httpx

    from wafpass_server import database as _database
    from wafpass_server.database import get_db
    from wafpass_server.main import app

    async def _override_get_db():
        async with mandant_db.app_sessionmaker() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    previous_owner_engine = _database._owner_engine
    _database._owner_engine = mandant_db.owner_engine

    try:
        # raise_app_exceptions=False: an unhandled exception becomes an
        # ordinary 500 response, same as a real deployed server — tests
        # that assert on status codes (e.g. the atomicity-on-failure test)
        # shouldn't need a try/except just to observe that.
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
    finally:
        app.dependency_overrides.pop(get_db, None)
        _database._owner_engine = previous_owner_engine
