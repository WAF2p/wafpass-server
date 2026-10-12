"""Async SQLAlchemy engine and session factory.

Two separate engines, deliberately:

- ``engine`` / ``AsyncSessionLocal`` / ``get_db()`` — the pooled, ordinary
  runtime connection every request handler uses. Connects as
  ``runtime_database_url`` (the non-superuser ``wafpass_app`` role) so that
  row-level security policies are actually enforced for it. See
  decisions/adrs/ADR-003-multi-mandant-tenancy.md and .plan.md, Phase 1.
- ``owner_engine`` / ``get_owner_connection()`` — the superuser/owner
  connection (``database_url``). Reserved for the one-time multi-mandant
  activation DDL (Phase 2); never used for ordinary request traffic.
  Alembic migrations connect independently (alembic/env.py reads
  DATABASE_URL directly) and are unaffected by either engine here.
"""
from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from wafpass_server.config import settings

engine = create_async_engine(settings.runtime_database_url, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

# Lazily created: most processes (web requests, background jobs) never need
# the owner connection at all, so there's no reason to open a pool for it
# until something actually asks for one (Phase 2's activation endpoint).
_owner_engine = None


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


def _get_owner_engine():
    global _owner_engine
    if _owner_engine is None:
        _owner_engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
    return _owner_engine


@asynccontextmanager
async def get_owner_connection() -> AsyncGenerator[AsyncConnection, None]:
    """Yield a raw connection on the owner/superuser role.

    Only for schema-altering DDL that an ordinary request can never trigger —
    today that means exactly one caller: the multi-mandant activation
    endpoint (Phase 2), running ``apply_multi_mandant_ddl()``.

    Called directly as ``async with get_owner_connection() as conn:`` (never
    via FastAPI's ``Depends()``), so it must actually be an async context
    manager — a plain async-generator function has no ``__aenter__``/
    ``__aexit__`` at all. Confirmed broken (``TypeError: 'async_generator'
    object does not support the asynchronous context manager protocol``)
    the first time the real activation endpoint was driven over HTTP rather
    than by calling ``_activate()`` directly with a hand-built connection —
    every prior "verified over HTTP" claim for this endpoint had not
    actually exercised this line. See .plan.md, Phase 5.
    """
    async with _get_owner_engine().connect() as conn:
        yield conn
