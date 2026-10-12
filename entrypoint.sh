#!/bin/sh
set -e

echo "DATABASE_URL: $DATABASE_URL"

python - <<'EOF'
import asyncio
import os
import sys

import asyncpg
from alembic.config import Config
from alembic import command
from sqlalchemy.engine.url import make_url

url = os.environ.get("DATABASE_URL")
if not url:
    print("ERROR: DATABASE_URL is not set", file=sys.stderr)
    sys.exit(1)


async def ensure_runtime_role() -> None:
    """Idempotently (re)create the non-superuser wafpass_app role and its
    grants, on every startup — not just on a brand-new Postgres volume.

    docker-entrypoint-initdb.d scripts (db-init/02-wafpass-app-role.sql)
    only ever run once, against a *fresh* data volume. Any existing
    deployment upgrading through this change has an already-initialized
    volume that script never touches, so the role would otherwise simply
    not exist — the app fails to start with "password authentication
    failed for user wafpass_app", not because of a wrong password but
    because the role was never created. Found exactly this way against a
    real running deployment; fixed here so it can't recur on any upgrade,
    not just patched once by hand. See decisions/adrs/ADR-003-multi-mandant-tenancy.md
    and .plan.md, Phase 1.
    """
    runtime_url = os.environ.get("RUNTIME_DATABASE_URL")
    if not runtime_url:
        print("RUNTIME_DATABASE_URL not set — skipping wafpass_app role check (pre-Phase-1 deployment?).")
        return

    owner = make_url(url)
    runtime = make_url(runtime_url)
    role, password = runtime.username, runtime.password
    # CREATE/ALTER ROLE is DDL — Postgres's grammar does not accept a bind
    # parameter ($1) for the PASSWORD clause at all (confirmed by actually
    # trying it: "syntax error at or near $1"). The password is
    # operator-supplied (a docker-compose env var), not external input, so
    # a plain standard-SQL string-literal escape (doubling embedded single
    # quotes) is both correct and sufficient here.
    password_literal = "'" + password.replace("'", "''") + "'"

    conn = await asyncpg.connect(
        user=owner.username, password=owner.password,
        host=owner.host, port=owner.port or 5432, database=owner.database,
    )
    try:
        exists = await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", role)
        if exists:
            # Keep the password in sync in case it was rotated via env var.
            await conn.execute(f'ALTER ROLE "{role}" WITH LOGIN PASSWORD {password_literal} NOSUPERUSER NOBYPASSRLS')
        else:
            await conn.execute(f'CREATE ROLE "{role}" WITH LOGIN PASSWORD {password_literal} NOSUPERUSER NOBYPASSRLS')
            print(f"Created runtime role '{role}'.")

        await conn.execute(f'GRANT CONNECT ON DATABASE "{owner.database}" TO "{role}"')
        await conn.execute(f'GRANT USAGE ON SCHEMA public TO "{role}"')
        await conn.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "{role}"')
        await conn.execute(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{role}"')
        await conn.execute(
            f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "{role}"'
        )
        await conn.execute(
            f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO "{role}"'
        )
        print(f"Runtime role '{role}' is up to date.")
    finally:
        await conn.close()


asyncio.run(ensure_runtime_role())

cfg = Config("alembic.ini")
cfg.set_main_option("sqlalchemy.url", url)
command.upgrade(cfg, "head")
print("Migrations complete.")
EOF

exec uvicorn wafpass_server.main:app --host 0.0.0.0 --port 8000
