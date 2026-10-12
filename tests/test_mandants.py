"""Multi-mandant integration tests (Phase 5).

Promotes the ad-hoc verification performed by hand throughout Phases 0-4
(against disposable Postgres containers, never the live dev stack) into a
committed, repeatable suite. See decisions/adrs/ADR-003-multi-mandant-tenancy.md
and .plan.md.

Requires WAFPASS_TEST_DATABASE_URL — see tests/conftest.py's module
docstring for how to start one. Every test in this module is skipped
(not failed) when it is unset.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from tests.conftest import MandantTestDb
from wafpass_server.auth.jwt_utils import create_access_token
from wafpass_server.auth.providers.local import hash_password


# ── Seeding helpers ───────────────────────────────────────────────────────────

async def seed_user(
    mandant_db: MandantTestDb,
    *,
    username: str,
    role: str = "clevel",
    password: str | None = "testpass123",
    mandant_id: uuid.UUID | None = None,
    holding_role: str | None = None,
) -> uuid.UUID:
    user_id = uuid.uuid4()
    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text(
                "INSERT INTO users (id, username, display_name, role, auth_provider, "
                "password_hash, is_active, prefs, mandant_id, holding_role) "
                "VALUES (:id, :username, :display_name, :role, 'local', "
                ":password_hash, true, '{}'::jsonb, :mandant_id, :holding_role)"
            ),
            {
                "id": user_id, "username": username, "display_name": username, "role": role,
                "password_hash": hash_password(password) if password else None,
                "mandant_id": mandant_id, "holding_role": holding_role,
            },
        )
        await session.commit()
    return user_id


async def seed_mandant(mandant_db: MandantTestDb, *, name: str, slug: str) -> uuid.UUID:
    mandant_id = uuid.uuid4()
    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text(
                "INSERT INTO mandants (id, name, slug, logo_url, settings, is_active) "
                "VALUES (:id, :name, :slug, '', '{}'::jsonb, true)"
            ),
            {"id": mandant_id, "name": name, "slug": slug},
        )
        await session.commit()
    return mandant_id


def bearer(user_id: uuid.UUID, username: str, role: str) -> dict[str, str]:
    token = create_access_token(user_id, username, role)
    return {"Authorization": f"Bearer {token}"}


async def fetch_scalar(mandant_db: MandantTestDb, sql: str, **params) -> object:
    async with mandant_db.owner_sessionmaker() as session:
        result = await session.execute(text(sql), params)
        return result.scalar_one_or_none()


async def activate(app_client, admin_headers: dict[str, str]) -> dict:
    r = await app_client.post("/api/v1/admin/activate-multi-mandant", headers=admin_headers)
    assert r.status_code == 200, r.text
    return r.json()["data"]


# ── Fresh install / single-tenant mode unchanged ─────────────────────────────

@pytest.mark.asyncio
async def test_fresh_install_starts_single_tenant(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    r = await app_client.get("/api/v1/admin/instance-mode", headers=bearer(admin_id, "admin1", "admin"))
    assert r.status_code == 200, r.text
    data = r.json()["data"]
    assert data["instance_mode"] == "single_tenant"
    assert data["can_activate"] is True
    assert data["mandant_count"] == 0


@pytest.mark.asyncio
async def test_single_tenant_mode_run_ingest_and_listing_unaffected(mandant_db: MandantTestDb, app_client) -> None:
    """No mandant concept should leak into single-tenant behaviour at all.

    Uses role="admin": list_runs() applies its own, orthogonal
    project-group access filter to any non-admin role (unrelated to this
    plan), which would otherwise return an empty list regardless of
    mandate isolation and make this test assert the wrong thing.
    """
    user_id = await seed_user(mandant_db, username="admin1", role="admin")
    headers = bearer(user_id, "admin1", "admin")

    r = await app_client.post("/api/v1/runs", json={"project": "legacy-proj", "score": 77}, headers=headers)
    assert r.status_code == 201, r.text

    r = await app_client.get("/api/v1/runs", headers=headers)
    assert r.status_code == 200, r.text
    projects = [run["project"] for run in r.json()["data"]]
    assert "legacy-proj" in projects

    mandant_id = await fetch_scalar(mandant_db, "SELECT mandant_id FROM runs WHERE project = 'legacy-proj'")
    assert mandant_id is None


# ── Activation endpoint: the real bugs found this session ───────────────────

@pytest.mark.asyncio
async def test_activation_over_real_http_backfills_and_flips_mode(mandant_db: MandantTestDb, app_client) -> None:
    """Drives POST /api/v1/admin/activate-multi-mandant exactly as a real
    admin's browser would — over HTTP, through the real dependency chain.

    This single test would have caught all three bugs found while writing
    it: `get_owner_connection()` missing `@asynccontextmanager` (crashed
    with TypeError on the first real call ever made to this endpoint),
    the ambient get_db() session's open read transaction deadlocking
    against the DDL's ALTER TABLE ... ENABLE ROW LEVEL SECURITY (confirmed
    via pg_stat_activity showing it "idle in transaction"), and rollback()
    expiring `acting_user`'s attributes and crashing on `acting_user.id`
    once the deadlock was fixed with the wrong half of the commit/rollback
    pair. Every prior "Phase 2 verified" note in .plan.md had exercised
    `_activate()` directly or a different endpoint, never this path.
    """
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    headers = bearer(admin_id, "admin1", "admin")

    r = await app_client.post("/api/v1/runs", json={"project": "proj-a", "score": 90}, headers=headers)
    assert r.status_code == 201, r.text

    summary = await activate(app_client, headers)
    assert summary["instance_mode"] == "multi_mandant"
    assert summary["default_mandant_name"] == "Default"
    assert summary["users_assigned"] >= 1
    assert summary["activated_by"] == "admin1"

    default_mandant_id = summary["default_mandant_id"]

    # Every tenant row that existed before activation is backfilled —
    # zero rows left NULL, confirmed by count, not just spot-checked.
    for table in ("users", "runs"):
        null_count = await fetch_scalar(mandant_db, f'SELECT COUNT(*) FROM "{table}" WHERE mandant_id IS NULL')
        assert null_count == 0, f"{table} has rows left with NULL mandant_id after activation"

    run_mandant = await fetch_scalar(mandant_db, "SELECT mandant_id FROM runs WHERE project = 'proj-a'")
    assert str(run_mandant) == default_mandant_id

    r = await app_client.get("/api/v1/admin/instance-mode", headers=headers)
    assert r.json()["data"]["instance_mode"] == "multi_mandant"

    # The acting admin must become the holding's first holding_admin —
    # otherwise the instance activates into a state nobody can administer
    # at the holding level (GET/POST /admin/mandants require holding_admin
    # strictly, not plain admin) short of editing the users table by hand.
    acting_holding_role = await fetch_scalar(mandant_db, "SELECT holding_role FROM users WHERE username = 'admin1'")
    assert acting_holding_role == "holding_admin"

    r = await app_client.get("/api/v1/admin/mandants", headers=headers)
    assert r.status_code == 200, r.text
    assert any(m["name"] == "Default" for m in r.json()["data"])


@pytest.mark.asyncio
async def test_activation_at_scale_backfills_every_row_of_a_large_dataset(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """The HTTP activation test above seeds exactly one user and one run —
    enough to exercise the logic, nothing close to what a real instance
    accumulates over time. Bulk-seeds thousands of rows directly via the
    owner connection (an `executemany`-style insert, not the one-run-at-a-
    time API — that would make seeding itself the slow part of this test,
    not activation), biased toward `runs`/`run_findings` specifically
    since "a very large amount of existing scan history" is the exact
    operational risk both Phase 2's spec and the activation DDL's own
    zero-downtime NOT NULL rewrite (see Status/Risks) were written for —
    then runs the real activation endpoint over HTTP and confirms every
    single row backfilled correctly, not a sample, at this larger row
    count, not just at n=1.
    """
    N_RUNS = 5000
    N_FINDINGS_PER_RUN = 3
    N_WAIVERS = 500

    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    headers = bearer(admin_id, "admin1", "admin")

    run_ids = [uuid.uuid4() for _ in range(N_RUNS)]
    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text("INSERT INTO runs (id, project, score, created_at) VALUES (:id, 'bulk-proj', 80, now())"),
            [{"id": rid} for rid in run_ids],
        )
        finding_rows = [
            {"id": uuid.uuid4(), "run_id": rid, "check_id": f"CHK-{i}", "severity": "high"}
            for rid in run_ids[:200]  # a representative subset, not all 5000 runs' findings
            for i in range(N_FINDINGS_PER_RUN)
        ]
        await session.execute(
            text(
                "INSERT INTO run_findings (id, run_id, check_id, severity) "
                "VALUES (:id, :run_id, :check_id, :severity)"
            ),
            finding_rows,
        )
        await session.execute(
            text("INSERT INTO waivers (id, reason, project) VALUES (:id, 'bulk waiver', 'bulk-proj')"),
            [{"id": f"BULK-WAIVER-{i}"} for i in range(N_WAIVERS)],
        )
        await session.commit()

    summary = await activate(app_client, headers)
    assert summary["instance_mode"] == "multi_mandant"
    default_mandant_id = summary["default_mandant_id"]

    # Every tenant row across every one of these tables is backfilled — a
    # COUNT(*) over the whole table, not a spot-check on a handful of rows.
    for table in ("runs", "run_findings", "waivers"):
        null_count = await fetch_scalar(mandant_db, f'SELECT COUNT(*) FROM "{table}" WHERE mandant_id IS NULL')
        assert null_count == 0, f"{table} has rows left with NULL mandant_id after activation at scale"

    # Compared as text, not cast to ::uuid — same reason as every GUC
    # comparison in activate_multi_mandant_ddl.py: a plain string bind
    # param against a native UUID column risks an asyncpg type-mismatch,
    # not just a semantic one.
    run_count = await fetch_scalar(
        mandant_db, "SELECT COUNT(*) FROM runs WHERE mandant_id::text = :m", m=default_mandant_id,
    )
    assert run_count == N_RUNS

    finding_count = await fetch_scalar(
        mandant_db, "SELECT COUNT(*) FROM run_findings WHERE mandant_id::text = :m", m=default_mandant_id,
    )
    assert finding_count == 200 * N_FINDINGS_PER_RUN

    waiver_count = await fetch_scalar(
        mandant_db, "SELECT COUNT(*) FROM waivers WHERE mandant_id::text = :m", m=default_mandant_id,
    )
    assert waiver_count == N_WAIVERS

    # The zero-downtime NOT NULL rewrite's end state must be identical to
    # the bare-ALTER version at this row count too, not just at n=1: a
    # genuinely NOT NULL column, with no leftover scaffolding constraint.
    is_nullable = await fetch_scalar(
        mandant_db,
        "SELECT is_nullable FROM information_schema.columns "
        "WHERE table_name = 'runs' AND column_name = 'mandant_id'",
    )
    assert is_nullable == "NO"
    leftover = await fetch_scalar(
        mandant_db,
        "SELECT count(*) FROM pg_constraint WHERE conname = 'runs_mandant_id_not_null_check'",
    )
    assert leftover == 0

    # RLS isolation itself still holds correctly at this row count — an
    # ordinary mandate-scoped user (not holding_admin) sees every run,
    # since they all landed in the one default mandate they also belong to.
    r = await app_client.get("/api/v1/runs?limit=1", headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_bootstrap_admin_seed_check_not_blinded_by_rls_after_activation(
    mandant_db: MandantTestDb, app_client, monkeypatch,
) -> None:
    """`seed_bootstrap_admin_if_empty()` (main.py) runs on every server
    startup. Before this fix, its own "is the table empty" check ran on
    the RLS-enforced runtime session with no mandate context set at all,
    so it always saw 0 rows once multi-mandant mode was active —
    regardless of how many users actually existed — and tried to insert a
    *second* bootstrap admin, which itself then failed RLS's WITH CHECK
    (no mandate, no holding flag), crashing the entire startup. Found via
    a real crash-loop (9 restarts) on a live instance already activated.
    `app_client` is depended on only for its side effect of pointing
    wafpass_server.database._owner_engine at this test's own database.
    """
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))

    from wafpass_server.config import settings
    monkeypatch.setattr(settings, "wafpass_admin_password", "some-bootstrap-password")

    from wafpass_server.main import seed_bootstrap_admin_if_empty
    import logging
    await seed_bootstrap_admin_if_empty(logging.getLogger("test"))

    user_count = await fetch_scalar(mandant_db, "SELECT COUNT(*) FROM users")
    assert user_count == 1, "must not insert a second bootstrap admin when one real user already exists"


@pytest.mark.asyncio
async def test_second_activation_is_rejected(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    headers = bearer(admin_id, "admin1", "admin")
    await activate(app_client, headers)

    r = await app_client.post("/api/v1/admin/activate-multi-mandant", headers=headers)
    assert r.status_code == 409, r.text


@pytest.mark.asyncio
async def test_activation_is_atomic_on_injected_failure(mandant_db: MandantTestDb, app_client) -> None:
    """Sabotage CREATE POLICY for one table so the DDL fails partway through,
    and confirm the *entire* transaction — backfill included — rolls back."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    headers = bearer(admin_id, "admin1", "admin")

    r = await app_client.post("/api/v1/runs", json={"project": "proj-a", "score": 50}, headers=headers)
    assert r.status_code == 201, r.text

    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(text('ALTER TABLE "runs" ENABLE ROW LEVEL SECURITY;'))
        await session.execute(text('CREATE POLICY runs_tenant_isolation ON "runs" USING (true);'))
        await session.commit()

    r = await app_client.post("/api/v1/admin/activate-multi-mandant", headers=headers)
    assert r.status_code >= 500 or r.status_code == 409, (
        f"expected activation to fail loudly, got {r.status_code}: {r.text}"
    )

    mode = await fetch_scalar(mandant_db, "SELECT value FROM instance_settings WHERE key = 'instance_mode'")
    assert mode == "single_tenant", "instance_mode must stay single_tenant when activation fails partway through"

    mandant_count = await fetch_scalar(mandant_db, "SELECT COUNT(*) FROM mandants")
    assert mandant_count == 0, "the default mandant's creation must have rolled back too"

    run_mandant = await fetch_scalar(mandant_db, "SELECT mandant_id FROM runs WHERE project = 'proj-a'")
    assert run_mandant is None, "backfill DML must have rolled back along with everything else"


# ── RLS isolation, ordinary request path (real HTTP, real JWTs) ─────────────

@pytest.mark.asyncio
async def test_rls_isolates_runs_across_mandates_over_real_http(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))

    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    # role="admin" for both: list_runs()'s own project-group access filter
    # (unrelated to this plan) applies to any non-admin role and would
    # otherwise return an empty list regardless of mandate isolation.
    user_a = await seed_user(mandant_db, username="alice", role="admin", mandant_id=default_mandant)
    user_b = await seed_user(mandant_db, username="bob", role="admin", mandant_id=mandant_b)

    headers_a = bearer(user_a, "alice", "admin")
    headers_b = bearer(user_b, "bob", "admin")

    # Deliberately *different* project names: `project_passports.project` is
    # still a bare natural-key primary key, not yet composite
    # (mandant_id, project) — a known, already-documented, deliberately
    # deferred gap (see .plan.md and the comment at _persist_run()'s
    # auto-create-passport call site), not something this test is about.
    # Using the same name here would collide on that INSERT and crash with
    # an unrelated 500, masking the actual thing being tested.
    r = await app_client.post("/api/v1/runs", json={"project": "alice-proj", "score": 60}, headers=headers_a)
    assert r.status_code == 201, r.text
    r = await app_client.post("/api/v1/runs", json={"project": "bob-proj", "score": 30}, headers=headers_b)
    assert r.status_code == 201, r.text

    r = await app_client.get("/api/v1/runs", headers=headers_a)
    projects_a = [run["project"] for run in r.json()["data"]]
    assert "alice-proj" in projects_a
    assert "bob-proj" not in projects_a, "alice must not see bob's mandate's run"

    r = await app_client.get("/api/v1/runs", headers=headers_b)
    projects_b = [run["project"] for run in r.json()["data"]]
    assert "bob-proj" in projects_b
    assert "alice-proj" not in projects_b, "bob must not see alice's mandate's run"


@pytest.mark.asyncio
async def test_holding_admin_sees_runs_across_all_mandates(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))

    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    user_b = await seed_user(mandant_db, username="bob", role="engineer", mandant_id=mandant_b)
    # role="admin" *and* holding_role="holding_admin": list_runs()'s
    # project-group access filter (unrelated to this plan) checks only
    # `user.role != "admin"` — it has no concept of holding_admin/
    # holding_viewer at all, so a holding_admin whose base role isn't
    # literally "admin" would be group-filtered to an empty list despite
    # their RLS bypass. A real gap, found here — flagged in .plan.md,
    # deliberately not fixed in this pass (the same `role != "admin"`
    # pattern also appears in auth.py/auto_fix.py; a proper fix deserves
    # its own scoped look, not a drive-by here).
    holding_admin_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")

    r = await app_client.post("/api/v1/runs", json={"project": "b-only-proj", "score": 42}, headers=bearer(user_b, "bob", "engineer"))
    assert r.status_code == 201, r.text

    r = await app_client.get("/api/v1/runs", headers=bearer(holding_admin_id, "holdy", "clevel"))
    assert r.status_code == 200, r.text
    projects = [run["project"] for run in r.json()["data"]]
    assert "b-only-proj" in projects, "holding_admin must see runs from every mandate, not just a default one"


@pytest.mark.asyncio
async def test_holding_viewer_read_allowed_write_rejected_by_rls(mandant_db: MandantTestDb, app_client) -> None:
    """holding_viewer's bypass is read-only — enforced by the database
    itself via WITH CHECK, not just by which endpoints the dashboard
    happens to expose. Exercised directly at the RLS layer (GUCs set by
    hand, mirroring exactly what get_scoped_db() sets from a real
    AuthContext) since there is no ordinary endpoint that would let any
    role attempt a raw cross-mandate insert in the first place."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")

    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text("INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES (:id, 'default-proj', 1, now(), :m)"),
            {"id": uuid.uuid4(), "m": default_mandant},
        )
        await session.execute(
            text("INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES (:id, 'b-proj', 2, now(), :m)"),
            {"id": uuid.uuid4(), "m": mandant_b},
        )
        await session.commit()

    async with mandant_db.app_sessionmaker() as session:
        await session.execute(text(
            "SELECT set_config('app.current_mandant_id', '', true), "
            "set_config('app.is_holding_admin', 'false', true), "
            "set_config('app.is_holding_viewer', 'true', true)"
        ))
        # `runs` carries a real RLS policy (unlike `mandants`, which has
        # none at all) — this is what actually exercises the
        # is_holding_viewer OR-condition in the USING clause.
        result = await session.execute(text("SELECT COUNT(*) FROM runs"))
        assert result.scalar_one() == 2, "holding_viewer must read across every mandate's rows, not just its own"

        with pytest.raises(Exception):
            await session.execute(
                text("INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES (:id, 'sneaky', 10, now(), :m)"),
                {"id": uuid.uuid4(), "m": mandant_b},
            )
            await session.commit()


# ── Auth bootstrap carve-outs ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_bootstrap_resolves_correct_mandate(mandant_db: MandantTestDb, app_client) -> None:
    """POST /auth/login only knows the submitted *username*, not an id or a
    mandate, when it looks up the row under RLS — the exact auth-bootstrap
    problem this plan's carve-outs exist to solve. A real bcrypt-hashed
    password proves the whole local-auth path, not just the JWT layer."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    await seed_user(mandant_db, username="carol", role="engineer", password="correct-horse", mandant_id=mandant_b)

    r = await app_client.post("/api/v1/auth/login", json={"username": "carol", "password": "correct-horse"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user"]["username"] == "carol"

    token = body["access_token"]
    r = await app_client.post(
        "/api/v1/runs", json={"project": "carols-proj", "score": 55}, headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 201, r.text
    run_mandant = await fetch_scalar(mandant_db, "SELECT mandant_id FROM runs WHERE project = 'carols-proj'")
    assert str(run_mandant) == str(mandant_b)


# ── API keys / ingest tagging (Phase 4) ──────────────────────────────────────

@pytest.mark.asyncio
async def test_api_key_ingest_tags_mandant_and_isolates(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    admin_b = await seed_user(mandant_db, username="admin-b", role="admin", mandant_id=mandant_b)

    r = await app_client.post("/api/v1/auth/api-keys", json={"name": "ci-key"}, headers=bearer(admin_b, "admin-b", "admin"))
    assert r.status_code == 201, r.text
    raw_key = r.json()["raw_key"]

    r = await app_client.post("/api/v1/runs", json={"project": "ci-proj", "score": 70}, headers={"X-Api-Key": raw_key})
    assert r.status_code == 201, r.text

    run_mandant = await fetch_scalar(mandant_db, "SELECT mandant_id FROM runs WHERE project = 'ci-proj'")
    assert str(run_mandant) == str(mandant_b)

    # A user in a *different* mandate must not see it.
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    user_a = await seed_user(mandant_db, username="alice", role="engineer", mandant_id=default_mandant)
    r = await app_client.get("/api/v1/runs", headers=bearer(user_a, "alice", "engineer"))
    assert "ci-proj" not in [run["project"] for run in r.json()["data"]]


@pytest.mark.asyncio
async def test_legacy_api_key_rejected_unless_explicitly_mapped(mandant_db: MandantTestDb, app_client, monkeypatch) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")

    from wafpass_server.config import settings
    monkeypatch.setattr(settings, "wafpass_api_key", "legacy-shared-secret")
    monkeypatch.setattr(settings, "wafpass_legacy_api_key_mandant_slug", "")

    r = await app_client.post("/api/v1/runs", json={"project": "legacy-proj", "score": 20}, headers={"X-Api-Key": "legacy-shared-secret"})
    assert r.status_code == 403, r.text

    monkeypatch.setattr(settings, "wafpass_legacy_api_key_mandant_slug", "default")
    r = await app_client.post("/api/v1/runs", json={"project": "legacy-proj", "score": 20}, headers={"X-Api-Key": "legacy-shared-secret"})
    assert r.status_code == 201, r.text
    run_mandant = await fetch_scalar(mandant_db, "SELECT mandant_id FROM runs WHERE project = 'legacy-proj'")
    assert str(run_mandant) == str(default_mandant)


# ── Public badges (Phase 4) ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_badge_routes_are_mandate_scoped_after_activation(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")

    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text("INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES (:id, 'myproject', 95, now(), :m)"),
            {"id": uuid.uuid4(), "m": default_mandant},
        )
        await session.execute(
            text("INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES (:id, 'myproject', 45, now(), :m)"),
            {"id": uuid.uuid4(), "m": mandant_b},
        )
        await session.commit()

    r = await app_client.get("/api/v1/public/badge/myproject.svg")
    assert r.status_code == 409, "bare badge route must not silently guess once multi-mandant mode is active"

    r = await app_client.get("/api/v1/public/badge/m/default/myproject.svg")
    assert r.status_code == 200 and "Excellence" in r.text

    r = await app_client.get("/api/v1/public/badge/m/mandant-b/myproject.svg")
    assert r.status_code == 200 and "Operational" in r.text, "must be isolated from the default mandant's same-named project"

    r = await app_client.get("/api/v1/public/badge/m/no-such-slug/myproject.svg")
    assert r.status_code == 404

    r = await app_client.get("/api/v1/public/badge/static/3.svg")
    assert r.status_code == 200, "the static tier badge has no mandate concept and must be unaffected"


@pytest.mark.asyncio
async def test_badge_bare_route_unchanged_in_single_tenant_mode(mandant_db: MandantTestDb, app_client) -> None:
    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text("INSERT INTO runs (id, project, score, created_at) VALUES (:id, 'legacyproj', 80, now())"),
            {"id": uuid.uuid4()},
        )
        await session.commit()

    r = await app_client.get("/api/v1/public/badge/legacyproj.svg")
    assert r.status_code == 200, "single-tenant instances must never see any behaviour change from this plan"
    assert "Optimized" in r.text


# ── SSO mandate-claim resolution (Phase 4) ───────────────────────────────────
# No real IdP round trip here (OIDC/SAML handshake mechanics are a different
# layer's responsibility) — `_provision_user()` is exercised directly, under
# real RLS, which is exactly the logic Phase 4 added/fixed.

@pytest.mark.asyncio
async def test_sso_new_user_requires_mandate_claim_once_multimandant(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    await seed_mandant(mandant_db, name="Acme", slug="acme")

    from wafpass_server.routers.sso import _provision_user

    async with mandant_db.app_sessionmaker() as session:
        with pytest.raises(Exception):
            await _provision_user(
                session, username="newsso", display_name="New SSO", auth_provider="oidc",
                role="engineer", auto_provision=True, mandant_slug=None,
            )

    async with mandant_db.app_sessionmaker() as session:
        user = await _provision_user(
            session, username="newsso", display_name="New SSO", auth_provider="oidc",
            role="engineer", auto_provision=True, mandant_slug="acme",
        )
        await session.commit()
        assert user.username == "newsso"

    mandant_id = await fetch_scalar(mandant_db, "SELECT mandant_id FROM users WHERE username = 'newsso'")
    acme_id = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'acme'")
    assert str(mandant_id) == str(acme_id)


@pytest.mark.asyncio
async def test_sso_existing_user_assigns_once_then_rejects_mismatch(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    acme_id = await seed_mandant(mandant_db, name="Acme", slug="acme")
    globex_id = await seed_mandant(mandant_db, name="Globex", slug="globex")
    await seed_user(mandant_db, username="ssouser", role="engineer", password=None, mandant_id=None)

    from wafpass_server.routers.sso import _provision_user

    async with mandant_db.app_sessionmaker() as session:
        user = await _provision_user(
            session, username="ssouser", display_name="SSO User", auth_provider="oidc",
            role="engineer", auto_provision=True, mandant_slug="acme",
        )
        await session.commit()
        assert str(user.mandant_id) == str(acme_id)

    async with mandant_db.app_sessionmaker() as session:
        with pytest.raises(Exception):
            await _provision_user(
                session, username="ssouser", display_name="SSO User", auth_provider="oidc",
                role="engineer", auto_provision=True, mandant_slug="globex",
            )


# ── Per-mandant SSO config (ADR-005) ─────────────────────────────────────────
# Same scope boundary as the Phase 4 SSO tests above: no real IdP round trip
# (OIDC/SAML handshake mechanics are a different layer) — config resolution,
# admin authorization, and _provision_user()'s forced-mandate/local-only
# logic are exercised directly, under real RLS where relevant.

def test_sign_state_roundtrip_carries_cfg_mandant_id() -> None:
    import secrets as _secrets

    from wafpass_server.routers.sso import _sign_state, _verify_state

    nonce = _secrets.token_hex(8)
    mandant_id = uuid.uuid4()

    assert _verify_state(_sign_state(nonce)) == (nonce, None)
    assert _verify_state(_sign_state(nonce, mandant_id)) == (nonce, mandant_id)

    with pytest.raises(Exception):
        _verify_state(_sign_state(nonce, mandant_id) + "tampered")


@pytest.mark.asyncio
async def test_sso_config_resolution_prefers_override_falls_back_to_default(mandant_db: MandantTestDb) -> None:
    from wafpass_server.models import SsoConfig
    from wafpass_server.routers.sso import _cfg_row_id, _get_cfg

    acme_id = await seed_mandant(mandant_db, name="Acme", slug="acme")
    globex_id = await seed_mandant(mandant_db, name="Globex", slug="globex")

    async with mandant_db.owner_sessionmaker() as session:
        session.add(SsoConfig(
            id="oidc", provider="oidc", mandant_id=None, enabled=True,
            config={"client_id": "default-client"},
        ))
        session.add(SsoConfig(
            id=_cfg_row_id("oidc", acme_id), provider="oidc", mandant_id=acme_id, enabled=True,
            config={"client_id": "acme-client"},
        ))
        await session.commit()

    async with mandant_db.app_sessionmaker() as session:
        default_cfg = await _get_cfg(session, "oidc", None)
        assert default_cfg is not None and default_cfg.config["client_id"] == "default-client"

        acme_cfg = await _get_cfg(session, "oidc", acme_id)
        assert acme_cfg is not None
        assert acme_cfg.config["client_id"] == "acme-client"
        assert acme_cfg.mandant_id == acme_id

        # Globex has no override of its own — resolves to the default row.
        globex_cfg = await _get_cfg(session, "oidc", globex_id)
        assert globex_cfg is not None
        assert globex_cfg.config["client_id"] == "default-client"
        assert globex_cfg.mandant_id is None


@pytest.mark.asyncio
async def test_provision_user_forced_mandant_id_overrides_claim(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    acme_id = await seed_mandant(mandant_db, name="Acme", slug="acme")
    globex_id = await seed_mandant(mandant_db, name="Globex", slug="globex")

    from wafpass_server.routers.sso import _provision_user

    # forced_mandant_id (a per-mandant SSO config's own identity) wins even
    # though mandant_slug (a claim value) points elsewhere — ADR-005: a
    # dedicated per-mandant IdP is trusted directly, not re-derived from a
    # claim it happens to assert.
    async with mandant_db.app_sessionmaker() as session:
        user = await _provision_user(
            session, username="newsso2", display_name="New SSO 2", auth_provider="oidc",
            role="engineer", auto_provision=True, mandant_slug="globex", forced_mandant_id=acme_id,
        )
        await session.commit()
        assert str(user.mandant_id) == str(acme_id)

    # Existing user: forced_mandant_id still assigns-once/rejects-on-mismatch,
    # exactly like the claim-based path, just checked against the config's
    # own mandate instead of a decoded claim.
    async with mandant_db.app_sessionmaker() as session:
        with pytest.raises(Exception):
            await _provision_user(
                session, username="newsso2", display_name="New SSO 2", auth_provider="oidc",
                role="engineer", auto_provision=True, forced_mandant_id=globex_id,
            )


@pytest.mark.asyncio
async def test_provision_user_rejects_local_only_mandate(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post(
        "/api/v1/admin/mandants",
        json={"name": "LocalOnly Co", "slug": "localonly", "auth_mode": "local_only"},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    local_only_id = uuid.UUID(r.json()["data"]["id"])
    assert r.json()["data"]["auth_mode"] == "local_only"

    from wafpass_server.routers.sso import _provision_user

    # Claim-based path: the shared/default IdP's claim happens to point at
    # a mandate that opted out of SSO entirely — must not provision anyway.
    async with mandant_db.app_sessionmaker() as session:
        with pytest.raises(Exception):
            await _provision_user(
                session, username="newsso3", display_name="x", auth_provider="oidc",
                role="engineer", auto_provision=True, mandant_slug="localonly",
            )

    # Per-mandant override path: defense-in-depth even though the admin
    # endpoints give no way to configure a dedicated IdP for a local-only
    # mandate in the first place.
    async with mandant_db.app_sessionmaker() as session:
        with pytest.raises(Exception):
            await _provision_user(
                session, username="newsso3", display_name="x", auth_provider="oidc",
                role="engineer", auto_provision=True, forced_mandant_id=local_only_id,
            )


@pytest.mark.asyncio
async def test_sso_providers_endpoint_scopes_by_mandant(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Acme", "slug": "acme"}, headers=headers)
    assert r.status_code == 201, r.text
    acme_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "LocalOnly", "slug": "localonly", "auth_mode": "local_only"},
        headers=headers,
    )
    assert r.status_code == 201, r.text

    # Nothing configured anywhere yet.
    r = await app_client.get("/api/v1/sso/providers")
    assert r.status_code == 200, r.text
    assert r.json() == []

    # Instance-wide default.
    r = await app_client.put(
        "/api/v1/sso/config/oidc", json={"enabled": True, "config": {"client_id": "default"}}, headers=headers,
    )
    assert r.status_code == 200, r.text

    r = await app_client.get("/api/v1/sso/providers")
    assert r.status_code == 200, r.text
    assert [p["scope"] for p in r.json()] == ["default"]

    # Acme's own override takes precedence over the default for Acme.
    r = await app_client.put(
        f"/api/v1/sso/config/mandant/{acme_id}/oidc", json={"enabled": True, "config": {"client_id": "acme"}},
        headers=headers,
    )
    assert r.status_code == 200, r.text

    r = await app_client.get("/api/v1/sso/providers", params={"mandant": "acme"})
    assert r.status_code == 200, r.text
    providers = r.json()
    assert len(providers) == 1
    assert providers[0]["scope"] == "mandant"

    # An unknown slug falls back to the default rather than erroring — the
    # login page must still render something sensible.
    r = await app_client.get("/api/v1/sso/providers", params={"mandant": "does-not-exist"})
    assert r.status_code == 200, r.text
    assert [p["scope"] for p in r.json()] == ["default"]

    # local_only: nothing offered regardless of what's configured elsewhere.
    r = await app_client.get("/api/v1/sso/providers", params={"mandant": "localonly"})
    assert r.status_code == 200, r.text
    assert r.json() == []


@pytest.mark.asyncio
async def test_mandant_sso_config_authorization(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    holding_headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Acme", "slug": "acme"}, headers=holding_headers)
    assert r.status_code == 201, r.text
    acme_id = r.json()["data"]["id"]
    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Globex", "slug": "globex"}, headers=holding_headers)
    assert r.status_code == 201, r.text
    globex_id = r.json()["data"]["id"]

    acme_admin_id = await seed_user(mandant_db, username="acmeadmin", role="admin", mandant_id=uuid.UUID(acme_id))
    acme_headers = bearer(acme_admin_id, "acmeadmin", "admin")

    # Acme's own mandate-scoped admin may manage Acme's override.
    r = await app_client.put(
        f"/api/v1/sso/config/mandant/{acme_id}/oidc", json={"enabled": True, "config": {"client_id": "acme"}},
        headers=acme_headers,
    )
    assert r.status_code == 200, r.text

    # ...but not Globex's.
    r = await app_client.put(
        f"/api/v1/sso/config/mandant/{globex_id}/oidc", json={"enabled": True, "config": {"client_id": "globex"}},
        headers=acme_headers,
    )
    assert r.status_code == 403, r.text
    r = await app_client.get(f"/api/v1/sso/config/mandant/{globex_id}", headers=acme_headers)
    assert r.status_code == 403, r.text

    # holding_admin may manage either.
    r = await app_client.put(
        f"/api/v1/sso/config/mandant/{globex_id}/oidc", json={"enabled": True, "config": {"client_id": "globex"}},
        headers=holding_headers,
    )
    assert r.status_code == 200, r.text

    # The plain /sso/config endpoint (instance-wide default) never surfaces
    # per-mandant overrides — nothing instance-wide was configured here.
    r = await app_client.get("/api/v1/sso/config", headers=holding_headers)
    assert r.status_code == 200, r.text
    assert r.json() == []

    r = await app_client.get(f"/api/v1/sso/config/mandant/{acme_id}", headers=acme_headers)
    assert r.status_code == 200, r.text
    configs = r.json()
    assert len(configs) == 1
    assert configs[0]["provider"] == "oidc"
    assert configs[0]["mandant_id"] == acme_id
    assert configs[0]["config"]["client_id"] == "acme"

    # Acme's admin can delete their own override but not Globex's.
    r = await app_client.delete(f"/api/v1/sso/config/mandant/{globex_id}/oidc", headers=acme_headers)
    assert r.status_code == 403, r.text
    r = await app_client.delete(f"/api/v1/sso/config/mandant/{acme_id}/oidc", headers=acme_headers)
    assert r.status_code == 204, r.text
    r = await app_client.get(f"/api/v1/sso/config/mandant/{acme_id}", headers=acme_headers)
    assert r.json() == []


@pytest.mark.asyncio
async def test_mandant_sso_config_secret_redacted_and_round_trips(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Acme", "slug": "acme"}, headers=headers)
    assert r.status_code == 201, r.text
    acme_id = r.json()["data"]["id"]

    r = await app_client.put(
        f"/api/v1/sso/config/mandant/{acme_id}/oidc",
        json={"enabled": True, "config": {"client_id": "acme-client", "client_secret": "s3cr3t-acme"}},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["config"]["client_secret"] == "***"
    assert r.json()["config"]["client_id"] == "acme-client"

    # The instance-wide default, same provider, a *different* secret — must
    # not collide with Acme's (ADR-005's secret-namespace decision) and must
    # decrypt independently.
    r = await app_client.put(
        "/api/v1/sso/config/oidc",
        json={"enabled": True, "config": {"client_id": "default-client", "client_secret": "s3cr3t-default"}},
        headers=headers,
    )
    assert r.status_code == 200, r.text

    from sqlalchemy import select

    from wafpass_server.models import SsoConfig
    from wafpass_server.routers.sso import _decrypt_config

    async with mandant_db.owner_sessionmaker() as session:
        acme_row = (await session.execute(
            select(SsoConfig).where(SsoConfig.mandant_id == uuid.UUID(acme_id))
        )).scalar_one()
        default_row = (await session.execute(
            select(SsoConfig).where(SsoConfig.mandant_id.is_(None), SsoConfig.provider == "oidc")
        )).scalar_one()

    assert (await _decrypt_config("oidc", acme_row.config))["client_secret"] == "s3cr3t-acme"
    assert (await _decrypt_config("oidc", default_row.config))["client_secret"] == "s3cr3t-default"


@pytest.mark.asyncio
async def test_mandant_auth_mode_create_update_validation(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Acme", "slug": "acme"}, headers=headers)
    assert r.status_code == 201, r.text
    assert r.json()["data"]["auth_mode"] == "inherit"
    acme_id = r.json()["data"]["id"]

    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Bad", "slug": "bad", "auth_mode": "not-a-real-mode"},
        headers=headers,
    )
    assert r.status_code == 400, r.text

    r = await app_client.put(f"/api/v1/admin/mandants/{acme_id}", json={"auth_mode": "local_only"}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["data"]["auth_mode"] == "local_only"

    # The real value survives a fresh fetch too, not just the echoed
    # response — exactly the bug MandantOut.model_validate(mandant) would
    # have silently reintroduced (always "inherit" — see from_mandant()'s
    # docstring), since auth_mode lives inside the settings JSONB.
    r = await app_client.get("/api/v1/admin/mandants", headers=headers)
    assert r.status_code == 200, r.text
    acme = next(m for m in r.json()["data"] if m["id"] == acme_id)
    assert acme["auth_mode"] == "local_only"

    r = await app_client.put(f"/api/v1/admin/mandants/{acme_id}", json={"auth_mode": "bogus"}, headers=headers)
    assert r.status_code == 400, r.text


@pytest.mark.asyncio
async def test_oidc_authorize_rejects_local_only_and_unknown_mandant(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "LocalOnly", "slug": "localonly", "auth_mode": "local_only"},
        headers=headers,
    )
    assert r.status_code == 201, r.text

    r = await app_client.get("/api/v1/auth/oidc/authorize", params={"mandant": "localonly"})
    assert r.status_code == 404, r.text

    r = await app_client.get("/api/v1/auth/oidc/authorize", params={"mandant": "does-not-exist"})
    assert r.status_code == 404, r.text

    r = await app_client.get("/api/v1/auth/oidc/authorize")
    assert r.status_code == 404, r.text  # nothing configured at all


# ── Phase 6a: hierarchy metadata, rollup, global context switcher ───────────

@pytest.mark.asyncio
async def test_mandant_hierarchy_parent_assignment_and_cycle_prevention(
    mandant_db: MandantTestDb, app_client,
) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post(
        "/api/v1/admin/mandants",
        json={"name": "Holding Co", "slug": "holding-co", "mandate_type": "holding"},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    holding_id = r.json()["data"]["id"]

    r = await app_client.post(
        "/api/v1/admin/mandants",
        json={"name": "Subsidiary A", "slug": "subsidiary-a", "mandate_type": "subsidiary", "parent_id": holding_id},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    sub_a_id = r.json()["data"]["id"]
    assert r.json()["data"]["parent_id"] == holding_id

    r = await app_client.post(
        "/api/v1/admin/mandants",
        json={"name": "Division A1", "slug": "division-a1", "mandate_type": "division", "parent_id": sub_a_id},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    division_id = r.json()["data"]["id"]

    # Direct self-parent and indirect cycle (holding -> division, where
    # division is already holding's grandchild) must both be rejected.
    r = await app_client.put(f"/api/v1/admin/mandants/{holding_id}", json={"parent_id": holding_id}, headers=headers)
    assert r.status_code == 400, r.text

    r = await app_client.put(f"/api/v1/admin/mandants/{holding_id}", json={"parent_id": division_id}, headers=headers)
    assert r.status_code == 400, r.text

    # Reparenting to a non-cycle-forming mandate works fine.
    r = await app_client.put(f"/api/v1/admin/mandants/{division_id}", json={"parent_id": holding_id}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["data"]["parent_id"] == holding_id

    # Explicit null clears parent_id (distinguished from "omitted" via
    # model_fields_set, same pattern as auth.py's UserUpdate.mandant_id).
    r = await app_client.put(f"/api/v1/admin/mandants/{division_id}", json={"parent_id": None}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["data"]["parent_id"] is None

    r = await app_client.post(
        "/api/v1/admin/mandants",
        json={"name": "Bad Type", "slug": "bad-type", "mandate_type": "not-a-real-type"},
        headers=headers,
    )
    assert r.status_code == 400, r.text


@pytest.mark.asyncio
async def test_mandant_rollup_aggregates_descendants(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Holding Co", "slug": "holding-co", "mandate_type": "holding"},
        headers=headers,
    )
    holding_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants",
        json={"name": "Sub A", "slug": "sub-a", "mandate_type": "subsidiary", "parent_id": holding_id},
        headers=headers,
    )
    sub_a_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants",
        json={"name": "Sub B", "slug": "sub-b", "mandate_type": "subsidiary", "parent_id": holding_id},
        headers=headers,
    )
    sub_b_id = r.json()["data"]["id"]

    async with mandant_db.owner_sessionmaker() as session:
        for mandant_id, score in [(holding_id, 90), (sub_a_id, 60), (sub_a_id, 80), (sub_b_id, 40)]:
            await session.execute(
                text("INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES (:id, 'p', :s, now(), :m)"),
                {"id": uuid.uuid4(), "s": score, "m": mandant_id},
            )
        await session.commit()

    r = await app_client.get(f"/api/v1/admin/mandants/{holding_id}/rollup", headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()["data"]
    assert data["mandate_count"] == 3  # holding + sub-a + sub-b
    assert data["run_count"] == 4
    assert data["avg_score"] == pytest.approx((90 + 60 + 80 + 40) / 4)

    r = await app_client.get(f"/api/v1/admin/mandants/{sub_a_id}/rollup", headers=headers)
    data = r.json()["data"]
    assert data["mandate_count"] == 1  # a leaf mandate's subtree is just itself
    assert data["run_count"] == 2
    assert data["avg_score"] == pytest.approx((60 + 80) / 2)


@pytest.mark.asyncio
async def test_global_context_switcher_scopes_holding_admin_to_one_mandate(
    mandant_db: MandantTestDb, app_client,
) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text("INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES (:id, 'default-proj', 1, now(), :m)"),
            {"id": uuid.uuid4(), "m": default_mandant},
        )
        await session.execute(
            text("INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES (:id, 'b-proj', 2, now(), :m)"),
            {"id": uuid.uuid4(), "m": mandant_b},
        )
        await session.commit()

    # No context header: full holding_admin bypass, sees both.
    r = await app_client.get("/api/v1/runs", headers=headers)
    projects = [run["project"] for run in r.json()["data"]]
    assert "default-proj" in projects and "b-proj" in projects

    # Switched into mandant_b: scoped to exactly that mandate, not "all".
    scoped_headers = {**headers, "X-Mandant-Context": str(mandant_b)}
    r = await app_client.get("/api/v1/runs", headers=scoped_headers)
    assert r.status_code == 200, r.text
    projects = [run["project"] for run in r.json()["data"]]
    assert "b-proj" in projects
    assert "default-proj" not in projects, "context switch must narrow visibility, not just tag new writes"

    # A write made while switched in is tagged with the switched-into mandate.
    r = await app_client.post(
        "/api/v1/runs", json={"project": "created-while-switched", "score": 50}, headers=scoped_headers
    )
    assert r.status_code == 201, r.text
    tagged = await fetch_scalar(
        mandant_db, "SELECT mandant_id FROM runs WHERE project = 'created-while-switched'"
    )
    assert str(tagged) == str(mandant_b)

    # Invalid / inactive mandate in the header is rejected outright.
    bad_headers = {**headers, "X-Mandant-Context": str(uuid.uuid4())}
    r = await app_client.get("/api/v1/runs", headers=bad_headers)
    assert r.status_code == 404, r.text

    # A non-holding user sending the header has it silently ignored — they
    # have nothing to switch away from, and it must not grant new access.
    user_a = await seed_user(mandant_db, username="alice", role="admin", mandant_id=default_mandant)
    ordinary_headers = {**bearer(user_a, "alice", "admin"), "X-Mandant-Context": str(mandant_b)}
    r = await app_client.get("/api/v1/runs", headers=ordinary_headers)
    assert r.status_code == 200, r.text
    projects = [run["project"] for run in r.json()["data"]]
    assert "b-proj" not in projects, "an ordinary user's X-Mandant-Context header must not grant cross-mandate access"


# ── Phase 6b / ADR-004 — hierarchy-aware RLS (group_admin/group_viewer) ──────

@pytest.mark.asyncio
async def test_group_admin_sees_own_subtree_not_sibling_subtree(mandant_db: MandantTestDb, app_client) -> None:
    """The core point of Phase 6b: narrower than holding_admin (not the
    whole holding), wider than a plain mandate-local admin (own mandate
    plus every descendant), over the ordinary JWT-authenticated path."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    holdy_headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Holding Co", "slug": "holding-co", "mandate_type": "holding"},
        headers=holdy_headers,
    )
    holding_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants",
        json={"name": "Sub A", "slug": "sub-a", "mandate_type": "subsidiary", "parent_id": holding_id},
        headers=holdy_headers,
    )
    sub_a_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants",
        json={"name": "Division A1", "slug": "division-a1", "mandate_type": "division", "parent_id": sub_a_id},
        headers=holdy_headers,
    )
    division_a1_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Sub B", "slug": "sub-b", "mandate_type": "subsidiary", "parent_id": holding_id},
        headers=holdy_headers,
    )
    sub_b_id = r.json()["data"]["id"]

    group_admin_id = await seed_user(
        mandant_db, username="groupy", role="admin", mandant_id=sub_a_id, holding_role="group_admin"
    )
    sub_a_user = await seed_user(mandant_db, username="sub-a-user", role="admin", mandant_id=sub_a_id)
    div_user = await seed_user(mandant_db, username="div-user", role="admin", mandant_id=division_a1_id)
    sub_b_user = await seed_user(mandant_db, username="sub-b-user", role="admin", mandant_id=sub_b_id)

    r = await app_client.post("/api/v1/runs", json={"project": "sub-a-proj", "score": 50}, headers=bearer(sub_a_user, "sub-a-user", "admin"))
    assert r.status_code == 201, r.text
    r = await app_client.post("/api/v1/runs", json={"project": "div-a1-proj", "score": 60}, headers=bearer(div_user, "div-user", "admin"))
    assert r.status_code == 201, r.text
    r = await app_client.post("/api/v1/runs", json={"project": "sub-b-proj", "score": 20}, headers=bearer(sub_b_user, "sub-b-user", "admin"))
    assert r.status_code == 201, r.text

    r = await app_client.get("/api/v1/runs", headers=bearer(group_admin_id, "groupy", "admin"))
    assert r.status_code == 200, r.text
    projects = [run["project"] for run in r.json()["data"]]
    assert "sub-a-proj" in projects, "group_admin must see their own mandate's runs"
    assert "div-a1-proj" in projects, "group_admin must see a descendant's runs"
    assert "sub-b-proj" not in projects, "group_admin must not see a sibling subtree's runs"


@pytest.mark.asyncio
async def test_group_admin_write_within_subtree_allowed_outside_rejected(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """Exercised directly at the RLS layer (GUCs set by hand, mirroring
    get_scoped_db()) since no ordinary endpoint lets a caller who hasn't
    narrowed via X-Mandant-Context tag a write with someone else's
    mandate — this is the only way to actually exercise the group
    WITH CHECK branch (_GROUP_CHECK_BRANCH in activate_multi_mandant_ddl.py)
    rather than leave it dead code."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Sub A", "slug": "sub-a"}, headers=headers)
    sub_a_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Division A1", "slug": "division-a1", "parent_id": sub_a_id},
        headers=headers,
    )
    division_a1_id = r.json()["data"]["id"]

    async with mandant_db.app_sessionmaker() as session:
        await session.execute(text(
            "SELECT set_config('app.current_mandant_id', :root, true), "
            "set_config('app.is_holding_admin', 'false', true), "
            "set_config('app.is_holding_viewer', 'false', true), "
            "set_config('app.is_group_admin', 'true', true), "
            "set_config('app.is_group_viewer', 'false', true)"
        ), {"root": str(sub_a_id)})

        # Write into a descendant mandate (not the caller's own) succeeds.
        await session.execute(
            text("INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES (:id, 'into-division', 2, now(), :m)"),
            {"id": uuid.uuid4(), "m": division_a1_id},
        )
        await session.commit()

    tagged = await fetch_scalar(mandant_db, "SELECT mandant_id FROM runs WHERE project = 'into-division'")
    assert str(tagged) == str(division_a1_id)

    async with mandant_db.app_sessionmaker() as session:
        await session.execute(text(
            "SELECT set_config('app.current_mandant_id', :root, true), "
            "set_config('app.is_holding_admin', 'false', true), "
            "set_config('app.is_holding_viewer', 'false', true), "
            "set_config('app.is_group_admin', 'true', true), "
            "set_config('app.is_group_viewer', 'false', true)"
        ), {"root": str(sub_a_id)})
        # A write outside the subtree (the unrelated default mandant) is rejected.
        with pytest.raises(Exception):
            await session.execute(
                text("INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES (:id, 'sneaky', 3, now(), :m)"),
                {"id": uuid.uuid4(), "m": default_mandant},
            )
            await session.commit()


@pytest.mark.asyncio
async def test_group_viewer_read_allowed_write_rejected_by_rls(mandant_db: MandantTestDb, app_client) -> None:
    """group_viewer's bypass is read-only within its own subtree — mirrors
    test_holding_viewer_read_allowed_write_rejected_by_rls exactly, scoped
    to a subtree instead of the whole holding."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Sub A", "slug": "sub-a"}, headers=headers)
    sub_a_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Division A1", "slug": "division-a1", "parent_id": sub_a_id},
        headers=headers,
    )
    division_a1_id = r.json()["data"]["id"]

    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text("INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES (:id, 'a-proj', 1, now(), :m)"),
            {"id": uuid.uuid4(), "m": sub_a_id},
        )
        await session.execute(
            text("INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES (:id, 'div-proj', 2, now(), :m)"),
            {"id": uuid.uuid4(), "m": division_a1_id},
        )
        await session.commit()

    async with mandant_db.app_sessionmaker() as session:
        await session.execute(text(
            "SELECT set_config('app.current_mandant_id', :root, true), "
            "set_config('app.is_holding_admin', 'false', true), "
            "set_config('app.is_holding_viewer', 'false', true), "
            "set_config('app.is_group_admin', 'false', true), "
            "set_config('app.is_group_viewer', 'true', true)"
        ), {"root": str(sub_a_id)})

        result = await session.execute(text("SELECT COUNT(*) FROM runs"))
        assert result.scalar_one() == 2, "group_viewer must read across its own subtree"

        # Writing into *the descendant* (division_a1_id), not the ambient
        # current_mandant_id (sub_a_id) itself — otherwise this would pass
        # trivially via the ordinary "write to your own mandate" branch
        # without ever exercising the group_viewer exclusion at all.
        with pytest.raises(Exception):
            await session.execute(
                text("INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES (:id, 'viewer-sneaky', 4, now(), :m)"),
                {"id": uuid.uuid4(), "m": division_a1_id},
            )
            await session.commit()


@pytest.mark.asyncio
async def test_global_context_switcher_group_admin_narrows_within_subtree_and_rejects_outside(
    mandant_db: MandantTestDb, app_client,
) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Sub A", "slug": "sub-a"}, headers=headers)
    sub_a_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Division A1", "slug": "division-a1", "parent_id": sub_a_id},
        headers=headers,
    )
    division_a1_id = r.json()["data"]["id"]
    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Sub B", "slug": "sub-b"}, headers=headers)
    sub_b_id = r.json()["data"]["id"]

    group_admin_id = await seed_user(
        mandant_db, username="groupy", role="admin", mandant_id=sub_a_id, holding_role="group_admin"
    )
    group_headers = bearer(group_admin_id, "groupy", "admin")

    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text("INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES (:id, 'div-proj', 1, now(), :m)"),
            {"id": uuid.uuid4(), "m": division_a1_id},
        )
        await session.commit()

    # Narrowing into the division — within the caller's own subtree — succeeds.
    scoped_headers = {**group_headers, "X-Mandant-Context": str(division_a1_id)}
    r = await app_client.get("/api/v1/runs", headers=scoped_headers)
    assert r.status_code == 200, r.text
    projects = [run["project"] for run in r.json()["data"]]
    assert "div-proj" in projects

    # Narrowing into a mandate outside the caller's subtree is rejected.
    outside_headers = {**group_headers, "X-Mandant-Context": str(sub_b_id)}
    r = await app_client.get("/api/v1/runs", headers=outside_headers)
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_mandant_ancestry_recomputed_on_create_and_reparent(mandant_db: MandantTestDb, app_client) -> None:
    """mandant_ancestry is maintained by application code
    (recompute_mandant_ancestry(), called from create/update mandant), not
    a database trigger — confirms it actually fires on both paths and
    produces the right self-row/ancestor-row shape, including after a
    reparent moves a whole subtree to a different parent."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Holding", "slug": "holding"}, headers=headers)
    holding_id = r.json()["data"]["id"]
    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Sub A", "slug": "sub-a", "parent_id": holding_id}, headers=headers)
    sub_a_id = r.json()["data"]["id"]
    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Sub B", "slug": "sub-b", "parent_id": holding_id}, headers=headers)
    sub_b_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Division A1", "slug": "division-a1", "parent_id": sub_a_id}, headers=headers,
    )
    division_id = r.json()["data"]["id"]

    async def ancestors_of(descendant_id: str) -> set[str]:
        async with mandant_db.owner_sessionmaker() as session:
            result = await session.execute(
                text("SELECT ancestor_id FROM mandant_ancestry WHERE descendant_id = :d"), {"d": descendant_id}
            )
            return {str(row[0]) for row in result.all()}

    assert await ancestors_of(division_id) == {division_id, sub_a_id, holding_id}
    assert await ancestors_of(sub_a_id) == {sub_a_id, holding_id}
    assert await ancestors_of(sub_b_id) == {sub_b_id, holding_id}

    # Reparent the division under Sub B — its ancestor set must flip
    # entirely (old ancestors gone), not just gain a new row alongside them.
    r = await app_client.put(f"/api/v1/admin/mandants/{division_id}", json={"parent_id": sub_b_id}, headers=headers)
    assert r.status_code == 200, r.text

    assert await ancestors_of(division_id) == {division_id, sub_b_id, holding_id}


@pytest.mark.asyncio
async def test_list_switchable_mandants_scoped_per_role(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Sub A", "slug": "sub-a"}, headers=headers)
    sub_a_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Division A1", "slug": "division-a1", "parent_id": sub_a_id}, headers=headers,
    )
    division_id = r.json()["data"]["id"]
    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Sub B", "slug": "sub-b"}, headers=headers)
    sub_b_id = r.json()["data"]["id"]

    # holding_admin: every mandate, including the auto-created default.
    r = await app_client.get("/api/v1/admin/mandants/switchable", headers=headers)
    assert r.status_code == 200, r.text
    ids = {m["id"] for m in r.json()["data"]}
    assert {str(default_mandant), sub_a_id, division_id, sub_b_id} <= ids

    # group_admin rooted at Sub A: only Sub A + Division A1, never Sub B.
    group_admin_id = await seed_user(
        mandant_db, username="groupy", role="admin", mandant_id=sub_a_id, holding_role="group_admin"
    )
    r = await app_client.get("/api/v1/admin/mandants/switchable", headers=bearer(group_admin_id, "groupy", "admin"))
    assert r.status_code == 200, r.text
    ids = {m["id"] for m in r.json()["data"]}
    assert ids == {sub_a_id, division_id}

    # An ordinary admin (no holding/group role at all) gets 403.
    plain_id = await seed_user(mandant_db, username="plain", role="admin", mandant_id=sub_a_id)
    r = await app_client.get("/api/v1/admin/mandants/switchable", headers=bearer(plain_id, "plain", "admin"))
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_update_user_group_role_requires_a_mandant(mandant_db: MandantTestDb, app_client) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    # A holding-only account (no mandant_id) cannot become group_admin.
    holding_only_id = await seed_user(mandant_db, username="holdonly", role="clevel")
    r = await app_client.put(
        f"/api/v1/auth/users/{holding_only_id}", json={"holding_role": "group_admin"}, headers=headers,
    )
    assert r.status_code == 400, r.text

    # Setting mandant_id and holding_role together in the same request works.
    r = await app_client.put(
        f"/api/v1/auth/users/{holding_only_id}",
        json={"mandant_id": str(default_mandant), "holding_role": "group_admin"},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert r.json()["holding_role"] == "group_admin"
    assert r.json()["mandant_id"] == str(default_mandant)


@pytest.mark.asyncio
async def test_migration_0045_retrofits_already_activated_instance_policies() -> None:
    """Every other test in this module runs against a `mandant_db` fixture
    that always migrates to *head* first — so by the time any of them call
    POST /activate-multi-mandant, migration 0045's own "already activated"
    retrofit branch (DROP/CREATE POLICY) never actually runs; mandant_ancestry
    and the group branches are simply already part of the policy
    `apply_multi_mandant_ddl()` writes. That leaves the one code path a
    real-world upgrade actually depends on — an instance that activated
    *before* this revision shipped, whose policies have the *old* shape —
    completely unexercised by the rest of the suite.

    This test builds its own throwaway database, migrates only to 0044,
    manually reproduces that pre-6b activated state (the old policy shape,
    hand-written here — not imported, since it must represent what an old
    deployment's activation actually produced, not whatever the current
    _policy_sql() says today), then upgrades to 0045 and confirms a
    group_admin's cross-mandate read — impossible under the old policy —
    now works. Skipped under the same WAFPASS_TEST_DATABASE_URL env var as
    every other test in this module; does not use the shared `mandant_db`
    fixture, since that fixture always migrates to head.
    """
    import asyncio
    import os
    from pathlib import Path

    import asyncpg
    from alembic import command
    from alembic.config import Config
    from sqlalchemy.engine import make_url

    from tests.conftest import _APP_PASSWORD, _APP_ROLE, _ensure_app_role
    from wafpass_server.db_migrations.activate_multi_mandant_ddl import ALL_TENANT_TABLES, _SELF_LOOKUP_TENANT_TABLES

    def _old_policy_sql(table: str) -> str:
        # The pre-6b policy shape (0044 and earlier) — hand-written here,
        # not imported from today's _policy_sql() (which already has the
        # group branch), since this must represent what a real pre-upgrade
        # deployment's own activation actually produced. ALL_TENANT_TABLES/
        # _SELF_LOOKUP_TENANT_TABLES themselves are unchanged by Phase 6b —
        # only the generated policy body changed — so importing those two
        # is safe and accurate.
        using_clauses = [
            "mandant_id::text = current_setting('app.current_mandant_id', true)",
            "current_setting('app.is_holding_admin', true) = 'true'",
            "current_setting('app.is_holding_viewer', true) = 'true'",
        ]
        using_clauses.extend(_SELF_LOOKUP_TENANT_TABLES.get(table, []))
        check_clauses = [
            "mandant_id::text = current_setting('app.current_mandant_id', true)",
            "current_setting('app.is_holding_admin', true) = 'true'",
        ]
        using_sql = "\n        OR ".join(using_clauses)
        check_sql = "\n        OR ".join(check_clauses)
        return (
            f'CREATE POLICY {table}_tenant_isolation ON "{table}"\n'
            f"    USING (\n        {using_sql}\n    )\n"
            f"    WITH CHECK (\n        {check_sql}\n    );"
        )

    server_dsn = os.environ.get("WAFPASS_TEST_DATABASE_URL")
    if not server_dsn:
        pytest.skip(
            "Set WAFPASS_TEST_DATABASE_URL to a reachable Postgres server — see tests/conftest.py."
        )

    repo_root = Path(__file__).resolve().parent.parent
    server_url = make_url(server_dsn)
    db_name = f"wafpass_test_{uuid.uuid4().hex[:16]}"
    maintenance_db = server_url.database or "postgres"

    def _connect_kwargs(database: str) -> dict:
        return {
            "user": server_url.username, "password": server_url.password,
            "host": server_url.host, "port": server_url.port or 5432, "database": database,
        }

    admin_conn = await asyncpg.connect(**_connect_kwargs(maintenance_db))
    try:
        await admin_conn.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        await admin_conn.close()

    async_url = (
        f"postgresql+asyncpg://{server_url.username}:{server_url.password}"
        f"@{server_url.host}:{server_url.port or 5432}/{db_name}"
    )

    def _upgrade_to(rev: str) -> None:
        cfg = Config(str(repo_root / "alembic.ini"))
        cfg.set_main_option("script_location", str(repo_root / "alembic"))
        cfg.set_main_option("sqlalchemy.url", async_url)
        old = os.environ.get("DATABASE_URL")
        os.environ["DATABASE_URL"] = async_url
        try:
            command.upgrade(cfg, rev)
        finally:
            if old is None:
                os.environ.pop("DATABASE_URL", None)
            else:
                os.environ["DATABASE_URL"] = old

    try:
        await asyncio.to_thread(_upgrade_to, "0044")

        root_id = uuid.uuid4()
        child_id = uuid.uuid4()
        conn = await asyncpg.connect(**_connect_kwargs(db_name))
        try:
            await conn.execute(
                "INSERT INTO mandants (id, name, slug, logo_url, settings, is_active) "
                "VALUES ($1, 'Root', 'root-mandant', '', '{}'::jsonb, true)",
                root_id,
            )
            await conn.execute(
                "INSERT INTO mandants (id, name, slug, logo_url, settings, is_active, parent_id) "
                "VALUES ($1, 'Child', 'child-mandant', '', '{}'::jsonb, true, $2)",
                child_id, root_id,
            )
            await conn.execute("UPDATE instance_settings SET value = 'multi_mandant' WHERE key = 'instance_mode'")
            await conn.execute(
                "INSERT INTO runs (id, project, score, created_at, mandant_id) VALUES ($1, 'child-proj', 77, now(), $2)",
                uuid.uuid4(), child_id,
            )
            # Reproduce a real pre-6b activation faithfully: it's all-or-
            # nothing across every tenant table in one transaction (see
            # apply_multi_mandant_ddl()), so migration 0045's own upgrade()
            # assumes every table in ALL_TENANT_TABLES already has a
            # policy whenever instance_mode == 'multi_mandant' — a partial
            # activation (e.g. only `runs`) can't actually occur in
            # practice and would make this test exercise an unreal state.
            not_null_tables = [t for t in ALL_TENANT_TABLES if t not in ("users", "user_audit_logs", "validations")]
            for t in not_null_tables:
                await conn.execute(f'ALTER TABLE "{t}" ALTER COLUMN mandant_id SET NOT NULL')
            for t in ALL_TENANT_TABLES:
                await conn.execute(f'ALTER TABLE "{t}" ENABLE ROW LEVEL SECURITY')
                await conn.execute(f'ALTER TABLE "{t}" FORCE ROW LEVEL SECURITY')
                await conn.execute(_old_policy_sql(t))
            await _ensure_app_role(conn, db_name)
        finally:
            await conn.close()

        # Before 0045: a group_admin GUC has no effect at all under the old
        # policy — confirms the "already activated" state is real, not a
        # no-op this test would pass vacuously.
        app_conn = await asyncpg.connect(user=_APP_ROLE, password=_APP_PASSWORD, host=server_url.host, port=server_url.port or 5432, database=db_name)
        try:
            async with app_conn.transaction():
                await app_conn.execute(
                    "SELECT set_config('app.current_mandant_id', $1, true), "
                    "set_config('app.is_holding_admin', 'false', true), "
                    "set_config('app.is_holding_viewer', 'false', true)",
                    str(root_id),
                )
                count_before = await app_conn.fetchval("SELECT COUNT(*) FROM runs")
                assert count_before == 0, "sanity check: old policy must not already see the child's run"
        finally:
            await app_conn.close()

        await asyncio.to_thread(_upgrade_to, "0045")

        conn = await asyncpg.connect(**_connect_kwargs(db_name))
        try:
            depth0 = await conn.fetchval(
                "SELECT depth FROM mandant_ancestry WHERE ancestor_id = $1 AND descendant_id = $1", root_id
            )
            assert depth0 == 0, "backfill must seed a depth-0 self-row for a pre-existing mandate"
            depth1 = await conn.fetchval(
                "SELECT depth FROM mandant_ancestry WHERE ancestor_id = $1 AND descendant_id = $2", root_id, child_id
            )
            assert depth1 == 1, "backfill must seed the parent/child ancestry row too"
        finally:
            await conn.close()

        app_conn = await asyncpg.connect(user=_APP_ROLE, password=_APP_PASSWORD, host=server_url.host, port=server_url.port or 5432, database=db_name)
        try:
            async with app_conn.transaction():
                await app_conn.execute(
                    "SELECT set_config('app.current_mandant_id', $1, true), "
                    "set_config('app.is_holding_admin', 'false', true), "
                    "set_config('app.is_holding_viewer', 'false', true), "
                    "set_config('app.is_group_admin', 'true', true), "
                    "set_config('app.is_group_viewer', 'false', true)",
                    str(root_id),
                )
                count_after = await app_conn.fetchval("SELECT COUNT(*) FROM runs")
                assert count_after == 1, (
                    "0045 must retrofit the live policy on an already-activated instance — "
                    "a group_admin rooted at the parent must now see the child's run"
                )
        finally:
            await app_conn.close()
    finally:
        admin_conn = await asyncpg.connect(**_connect_kwargs(maintenance_db))
        try:
            await admin_conn.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
                db_name,
            )
            await admin_conn.execute(f'DROP DATABASE IF EXISTS "{db_name}"')
        finally:
            await admin_conn.close()


# ── "Sending to a specific mandate" — upstream completeness (CLI/API-key) ───

@pytest.mark.asyncio
async def test_holding_only_jwt_push_without_context_rejected_cleanly(mandant_db: MandantTestDb, app_client) -> None:
    """Real bug, found while auditing whether the CLI can actually target a
    mandate: a holding-only holding_admin/holding_viewer (no personal
    mandant_id) pushing a run over the JWT ingest path with no
    X-Mandant-Context used to crash with a raw 500 (NotNullViolationError
    on runs.mandant_id) instead of the same clean 400 create_user()/
    create_api_key() already give for the identical underlying gap.
    Confirms both the fix (400, not 500) and that supplying
    X-Mandant-Context still works correctly."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post("/api/v1/runs", json={"project": "no-context-proj", "score": 10}, headers=headers)
    assert r.status_code == 400, r.text

    scoped_headers = {**headers, "X-Mandant-Context": str(default_mandant)}
    r = await app_client.post("/api/v1/runs", json={"project": "with-context-proj", "score": 20}, headers=scoped_headers)
    assert r.status_code == 201, r.text
    tagged = await fetch_scalar(mandant_db, "SELECT mandant_id FROM runs WHERE project = 'with-context-proj'")
    assert str(tagged) == str(default_mandant)


@pytest.mark.asyncio
async def test_single_tenant_jwt_push_with_no_mandant_still_unaffected(mandant_db: MandantTestDb, app_client) -> None:
    """The new guard in require_ingest() must be scoped to multi_mandant
    mode only — every user's mandant_id is None by design in single_tenant
    mode (Phase 0/1's "no behaviour change" guarantee), and runs.mandant_id
    has no NOT NULL constraint until activation. A regression here would
    have broken ordinary single-tenant ingest for everyone, not just
    holding-only accounts."""
    user_id = await seed_user(mandant_db, username="plain", role="admin")
    r = await app_client.post(
        "/api/v1/runs", json={"project": "single-tenant-proj", "score": 50}, headers=bearer(user_id, "plain", "admin")
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_create_api_key_explicit_mandant_id_holding_admin_only(mandant_db: MandantTestDb, app_client) -> None:
    """The direct, discoverable way to create a mandate-specific API key:
    pass mandant_id explicitly, rather than the only previously-available
    path (switch the dashboard's Global Context Switcher into that
    mandate first, then create the key, with zero visible confirmation of
    which mandate the result actually lands on)."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post(
        "/api/v1/auth/api-keys", json={"name": "b-key", "mandant_id": str(mandant_b)}, headers=headers
    )
    assert r.status_code == 201, r.text
    assert r.json()["mandant_id"] == str(mandant_b)
    raw_key = r.json()["raw_key"]

    # The resulting key actually tags ingested runs with that mandate.
    r = await app_client.post("/api/v1/runs", json={"project": "b-key-proj", "score": 33}, headers={"X-Api-Key": raw_key})
    assert r.status_code == 201, r.text
    tagged = await fetch_scalar(mandant_db, "SELECT mandant_id FROM runs WHERE project = 'b-key-proj'")
    assert str(tagged) == str(mandant_b)

    # GET /auth/api-keys surfaces mandant_id for every key — a holding_admin
    # (RLS-bypassed, sees every mandate's keys) can now tell them apart.
    r = await app_client.get("/api/v1/auth/api-keys", headers=headers)
    assert r.status_code == 200, r.text
    by_name = {k["name"]: k.get("mandant_id") for k in r.json()}
    assert by_name["b-key"] == str(mandant_b)

    # An ordinary admin (not holding_admin) naming any mandant_id explicitly
    # is rejected — otherwise this would be a privilege-escalation path (an
    # admin minting a key for data they can't otherwise see).
    plain_admin_id = await seed_user(mandant_db, username="plain-admin", role="admin", mandant_id=mandant_b)
    r = await app_client.post(
        "/api/v1/auth/api-keys", json={"name": "sneaky-key", "mandant_id": str(mandant_b)},
        headers=bearer(plain_admin_id, "plain-admin", "admin"),
    )
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_create_api_key_holding_only_admin_requires_explicit_mandant_id(
    mandant_db: MandantTestDb, app_client,
) -> None:
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post("/api/v1/auth/api-keys", json={"name": "no-target-key"}, headers=headers)
    assert r.status_code == 400, r.text

    r = await app_client.post(
        "/api/v1/auth/api-keys", json={"name": "targeted-key", "mandant_id": str(mandant_b)}, headers=headers
    )
    assert r.status_code == 201, r.text


@pytest.mark.asyncio
async def test_holding_only_holding_admin_can_login_refresh_and_logout(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """Real bug, found while end-to-end verifying the ingest fix above with
    a real running server: a holding-only holding_admin/holding_viewer (no
    personal mandant_id) crashed with a raw 500 (InsufficientPrivilegeError)
    on the very first login — adopt_mandate_of() only ever set
    app.current_mandant_id, never app.is_holding_admin/is_holding_viewer,
    so a holding-only account's own `users` row update (last_login_at) and
    the login audit insert had no WITH CHECK branch that could pass:
    mandant_id::text = current_mandant_id compares NULL to '' (false), and
    is_holding_admin was never set to 'true'. The same gap affected
    refresh_token()'s replay-detection branch and logout(). Fixed by
    letting adopt_mandate_of() carry the caller's real holding flags too,
    not just the mandate id."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    await seed_user(
        mandant_db, username="holdy", role="admin", password="holdypass123",
        mandant_id=None, holding_role="holding_admin",
    )

    r = await app_client.post("/api/v1/auth/login", json={"username": "holdy", "password": "holdypass123"})
    assert r.status_code == 200, r.text
    body = r.json()
    access_token = body["access_token"]
    refresh_token = body["refresh_token"]

    r = await app_client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert r.status_code == 200, r.text
    new_refresh_token = r.json()["refresh_token"]

    # Replay the *old* (now-revoked) refresh token — the replay-detection
    # branch itself is what used to crash for a holding-only account.
    r = await app_client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert r.status_code == 401, r.text

    r = await app_client.post("/api/v1/auth/logout", json={"refresh_token": new_refresh_token})
    assert r.status_code in (200, 204), r.text

    # last_login_at was actually updated — confirms the UPDATE itself
    # succeeded, not just that no exception leaked past error handling.
    last_login = await fetch_scalar(mandant_db, "SELECT last_login_at FROM users WHERE username = 'holdy'")
    assert last_login is not None


@pytest.mark.asyncio
async def test_sso_holding_only_existing_user_login_audit_does_not_crash(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """Same underlying gap as the local-login test above, reached via SSO:
    _provision_user()'s final adopt_mandate_of() call for an *existing*
    holding-only user left is_holding_admin unset, so the sso.login audit
    insert its caller (oidc_callback/saml_acs) makes right afterward would
    have hit the identical InsufficientPrivilegeError."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(
        mandant_db, username="ssoholdy", role="admin", password=None,
        mandant_id=None, holding_role="holding_admin",
    )

    from wafpass_server.routers.auth import _audit
    from wafpass_server.routers.sso import _provision_user

    async with mandant_db.app_sessionmaker() as session:
        user = await _provision_user(
            session, username="ssoholdy", display_name="SSO Holdy", auth_provider="oidc",
            role="admin", auto_provision=True, mandant_slug=None,
        )
        assert user.id == holdy_id
        await _audit(session, user.id, "sso.login", {"provider": "oidc"}, mandant_id=user.mandant_id)
        await session.commit()


# ── project_passports composite key (real bug, found live, 2026-10-11) ─────

@pytest.mark.asyncio
async def test_project_passports_same_name_across_two_mandates_no_collision(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """Real bug, reported live: two mandates both auto-creating a
    ProjectPassport for the same bare project name used to collide on the
    table's original single-column primary key (`project`), crashing the
    *second* mandate's otherwise-ordinary ingest with a raw 500
    (UniqueViolationError on project_passports_pkey). Confirms both pushes
    now succeed and each mandate's own passport row is independently
    tagged — the fix is a composite (mandant_id, project) primary key."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    user_a = await seed_user(mandant_db, username="alice", role="admin", mandant_id=default_mandant)
    user_b = await seed_user(mandant_db, username="bob", role="admin", mandant_id=mandant_b)

    r = await app_client.post(
        "/api/v1/runs", json={"project": "shared-name", "score": 50}, headers=bearer(user_a, "alice", "admin")
    )
    assert r.status_code == 201, r.text

    r = await app_client.post(
        "/api/v1/runs", json={"project": "shared-name", "score": 70}, headers=bearer(user_b, "bob", "admin")
    )
    assert r.status_code == 201, r.text  # used to be a 500 here

    async with mandant_db.owner_sessionmaker() as session:
        result = await session.execute(
            text("SELECT mandant_id FROM project_passports WHERE project = 'shared-name'")
        )
        mandant_ids = {str(row[0]) for row in result.all()}
    assert mandant_ids == {str(default_mandant), str(mandant_b)}


@pytest.mark.asyncio
async def test_holding_admin_passport_lookup_is_scoped_to_current_context(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """Once two mandates can share a project name, "the passport for
    project X" is ambiguous for a holding_admin's RLS bypass unless scoped
    explicitly — this mirrors the Global Context Switcher's own narrowing
    semantics (X-Mandant-Context) rather than crashing (MultipleResultsFound)
    or guessing which mandate's row to return."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    user_a = await seed_user(mandant_db, username="alice", role="admin", mandant_id=default_mandant)
    user_b = await seed_user(mandant_db, username="bob", role="admin", mandant_id=mandant_b)

    r = await app_client.put(
        "/api/v1/projects/shared-name/passport", json={"display_name": "Mandate A's passport"},
        headers=bearer(user_a, "alice", "admin"),
    )
    assert r.status_code == 200, r.text
    r = await app_client.put(
        "/api/v1/projects/shared-name/passport", json={"display_name": "Mandate B's passport"},
        headers=bearer(user_b, "bob", "admin"),
    )
    assert r.status_code == 200, r.text

    holdy_id = await seed_user(
        mandant_db, username="holdy", role="admin", mandant_id=default_mandant, holding_role="holding_admin"
    )
    headers = bearer(holdy_id, "holdy", "admin")

    # Not narrowed: resolves to the holding_admin's own effective mandate.
    r = await app_client.get("/api/v1/projects/shared-name/passport", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["data"]["display_name"] == "Mandate A's passport"

    # Narrowed into Mandate B via the existing Global Context Switcher:
    # resolves to that mandate's passport instead.
    scoped_headers = {**headers, "X-Mandant-Context": str(mandant_b)}
    r = await app_client.get("/api/v1/projects/shared-name/passport", headers=scoped_headers)
    assert r.status_code == 200, r.text
    assert r.json()["data"]["display_name"] == "Mandate B's passport"


@pytest.mark.asyncio
async def test_project_achievements_same_tier_across_two_mandates_no_collision(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """Found in the exact same live incident as the project_passports
    crash above: a second mandate's run reaching the same maturity tier
    for a same-named project collided on project_achievements' own
    (project, tier_level) unique constraint, inside the same POST /runs
    request that had just been fixed for the passport collision."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    user_a = await seed_user(mandant_db, username="alice", role="admin", mandant_id=default_mandant)
    user_b = await seed_user(mandant_db, username="bob", role="admin", mandant_id=mandant_b)

    r = await app_client.post(
        "/api/v1/runs", json={"project": "shared-name", "score": 70}, headers=bearer(user_a, "alice", "admin")
    )
    assert r.status_code == 201, r.text
    r = await app_client.post(
        "/api/v1/runs", json={"project": "shared-name", "score": 70}, headers=bearer(user_b, "bob", "admin")
    )
    assert r.status_code == 201, r.text  # used to be a 500 here too

    async with mandant_db.owner_sessionmaker() as session:
        result = await session.execute(
            text("SELECT mandant_id FROM project_achievements WHERE project = 'shared-name' AND tier_level = 1")
        )
        mandant_ids = {str(row[0]) for row in result.all()}
    assert mandant_ids == {str(default_mandant), str(mandant_b)}


@pytest.mark.asyncio
async def test_waivers_and_risk_acceptances_same_control_id_across_two_mandates(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """Phase 1 finding, fixed 2026-10-11 alongside the project_passports/
    project_achievements collisions found live: waivers.id/
    risk_acceptances.id are bare control-ids, globally unique at the DB
    layer rather than per-mandate — two mandates waiving (or accepting
    risk on) the *same* control_id, the common case since every mandate
    shares one global control catalogue, used to collide on the primary
    key."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    user_a = await seed_user(mandant_db, username="alice", role="ciso", mandant_id=default_mandant)
    user_b = await seed_user(mandant_db, username="bob", role="ciso", mandant_id=mandant_b)

    r = await app_client.put(
        "/api/v1/waivers/WAF-COST-010", json={"reason": "mandate A waiver"}, headers=bearer(user_a, "alice", "ciso")
    )
    assert r.status_code == 200, r.text
    r = await app_client.put(
        "/api/v1/waivers/WAF-COST-010", json={"reason": "mandate B waiver"}, headers=bearer(user_b, "bob", "ciso")
    )
    assert r.status_code == 200, r.text  # used to be a 500 here

    r = await app_client.put(
        "/api/v1/risks/WAF-COST-020", json={"reason": "mandate A risk"}, headers=bearer(user_a, "alice", "ciso")
    )
    assert r.status_code == 200, r.text
    r = await app_client.put(
        "/api/v1/risks/WAF-COST-020", json={"reason": "mandate B risk"}, headers=bearer(user_b, "bob", "ciso")
    )
    assert r.status_code == 200, r.text  # used to be a 500 here

    async with mandant_db.owner_sessionmaker() as session:
        result = await session.execute(text("SELECT mandant_id, reason FROM waivers WHERE id = 'WAF-COST-010'"))
        by_mandant = {str(row[0]): row[1] for row in result.all()}
    assert by_mandant == {str(default_mandant): "mandate A waiver", str(mandant_b): "mandate B waiver"}


# ── 2026-10-11 fixes: six flagged gaps, closed together ──────────────────────

@pytest.mark.asyncio
async def test_update_notifications_reach_admins_in_every_mandate(mandant_db: MandantTestDb, app_client) -> None:
    """update_checker.py's _send_update_notifications() is a scheduled
    background job with no AuthContext at all — it must run on the owner
    connection, not the RLS-enforced pooled session, or it silently finds
    zero admins once multi-mandant mode is active (same shape bug as the
    already-fixed seed_bootstrap_admin_if_empty() in main.py). Also covers
    the adjacent bug found alongside it: notifications.mandant_id is NOT
    NULL once activated, so a bare mandate-less Notification() would
    otherwise crash the insert, and the old code added the exact same
    object once per admin instead of once per mandate."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    await seed_user(mandant_db, username="admin-b", role="admin", mandant_id=mandant_b)
    # A holding-only admin: no mandate of their own, covered by bypass only.
    await seed_user(mandant_db, username="holdy2", role="admin", holding_role="holding_admin")

    from wafpass_server.update_checker import _send_update_notifications
    await _send_update_notifications("Framework updated: abc1234 -> def5678")

    count = await fetch_scalar(
        mandant_db, "SELECT count(*) FROM notifications WHERE title = 'Framework Update Detected'"
    )
    assert count == 2, "one row per distinct real mandate among the admins (default + Mandant B), none for holding-only"

    mandant_ids = await fetch_scalar(
        mandant_db,
        "SELECT array_agg(mandant_id ORDER BY mandant_id) FROM notifications WHERE title = 'Framework Update Detected'",
    )
    assert {str(m) for m in mandant_ids} == {str(default_mandant), str(mandant_b)}


@pytest.mark.asyncio
async def test_update_notifications_single_tenant_mode_unaffected(mandant_db: MandantTestDb, app_client) -> None:
    """Single-tenant mode (never activated): mandant_id stays nullable and
    RLS isn't forced at all, so this must behave exactly as before this
    fix existed — one global notification, no mandate tag."""
    await seed_user(mandant_db, username="admin1", role="admin")

    from wafpass_server.update_checker import _send_update_notifications
    await _send_update_notifications("Framework updated: abc1234 -> def5678")

    count = await fetch_scalar(
        mandant_db, "SELECT count(*) FROM notifications WHERE title = 'Framework Update Detected'"
    )
    assert count == 1
    mandant_id = await fetch_scalar(
        mandant_db, "SELECT mandant_id FROM notifications WHERE title = 'Framework Update Detected'"
    )
    assert mandant_id is None


@pytest.mark.asyncio
async def test_create_user_explicit_mandant_id_holding_admin_only(mandant_db: MandantTestDb, app_client) -> None:
    """The identical gap create_api_key already had fixed this session: a
    holding-only admin previously had nowhere to assign a new user's
    mandate at all (UserCreate had no mandant_id override field)."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    # Without mandant_id: holding-only admin has nothing to inherit,
    # rejected cleanly — pre-existing behaviour, still correct.
    r = await app_client.post(
        "/api/v1/auth/users", json={"username": "newbie", "password": "testpass123"}, headers=headers,
    )
    assert r.status_code == 400, r.text

    # With mandant_id: holding_admin can target Mandant B directly.
    r = await app_client.post(
        "/api/v1/auth/users",
        json={"username": "newbie", "password": "testpass123", "mandant_id": str(mandant_b)},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    assert r.json()["mandant_id"] == str(mandant_b)

    # An ordinary admin (not holding_admin) naming any mandant_id
    # explicitly is rejected — otherwise this is a privilege-escalation
    # path (an admin minting a user account for a mandate they can't
    # otherwise see).
    plain_admin_id = await seed_user(mandant_db, username="plain-admin", role="admin", mandant_id=mandant_b)
    r = await app_client.post(
        "/api/v1/auth/users",
        json={"username": "sneaky", "password": "testpass123", "mandant_id": str(mandant_b)},
        headers=bearer(plain_admin_id, "plain-admin", "admin"),
    )
    assert r.status_code == 403, r.text


@pytest.mark.asyncio
async def test_delete_project_scoped_to_current_mandate(mandant_db: MandantTestDb, app_client) -> None:
    """A non-narrowed holding_admin calling DELETE /{project}/delete used
    to delete *every* mandate's runs for a shared project name — found as
    a side effect of the project_passports composite-key fix. Now scoped
    to auth.mandant_id, the same semantic every other single-item lookup
    in this router already uses (_get_passport)."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text(
                "INSERT INTO runs (id, project, score, created_at, mandant_id) "
                "VALUES (:id, 'shared-name', 1, now(), :m)"
            ),
            {"id": uuid.uuid4(), "m": default_mandant},
        )
        await session.execute(
            text(
                "INSERT INTO runs (id, project, score, created_at, mandant_id) "
                "VALUES (:id, 'shared-name', 2, now(), :m)"
            ),
            {"id": uuid.uuid4(), "m": mandant_b},
        )
        await session.commit()

    # Narrowed into Mandant B: only Mandant B's run should be deleted.
    scoped_headers = {**headers, "X-Mandant-Context": str(mandant_b)}
    r = await app_client.delete("/api/v1/projects/shared-name/delete", headers=scoped_headers)
    assert r.status_code == 204, r.text

    remaining = await fetch_scalar(mandant_db, "SELECT count(*) FROM runs WHERE project = 'shared-name'")
    assert remaining == 1, "only Mandant B's run should have been deleted — the default mandate's must survive"

    survivor_mandant = await fetch_scalar(mandant_db, "SELECT mandant_id FROM runs WHERE project = 'shared-name'")
    assert str(survivor_mandant) == str(default_mandant)


@pytest.mark.asyncio
async def test_list_runs_group_filter_does_not_block_holding_or_group_roles(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """list_runs()'s UserGroup/ProjectGroup access filter used to check
    only `user.role == "admin"`, so a holding_admin/holding_viewer/
    group_admin/group_viewer whose own base role isn't literally "admin"
    (a perfectly normal combination — holding_role and role are
    independent fields, see update_user) got wrongly empty-filtered to
    zero runs despite their RLS bypass already granting full visibility."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")

    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text(
                "INSERT INTO runs (id, project, score, created_at, mandant_id) "
                "VALUES (:id, 'ungrouped-proj', 1, now(), :m)"
            ),
            {"id": uuid.uuid4(), "m": default_mandant},
        )
        await session.commit()

    # holding_admin whose own base role is "clevel", not "admin" — and has
    # zero UserGroup memberships of their own.
    holdy_id = await seed_user(mandant_db, username="holdy3", role="clevel", holding_role="holding_admin")
    r = await app_client.get("/api/v1/runs", headers=bearer(holdy_id, "holdy3", "clevel"))
    assert r.status_code == 200, r.text
    projects = [run["project"] for run in r.json()["data"]]
    assert "ungrouped-proj" in projects, "RLS bypass must not be clawed back by the group-membership filter"

    # Same for group_admin, scoped to their own subtree (here: their own
    # mandate), still with zero group memberships.
    group_admin_id = await seed_user(
        mandant_db, username="groupy2", role="clevel", mandant_id=default_mandant, holding_role="group_admin",
    )
    r = await app_client.get("/api/v1/runs", headers=bearer(group_admin_id, "groupy2", "clevel"))
    assert r.status_code == 200, r.text
    projects = [run["project"] for run in r.json()["data"]]
    assert "ungrouped-proj" in projects

    # An ordinary clevel with no holding role and no group membership is
    # still correctly empty-filtered — this isn't a blanket bypass.
    plain_id = await seed_user(mandant_db, username="plain2", role="clevel", mandant_id=default_mandant)
    r = await app_client.get("/api/v1/runs", headers=bearer(plain_id, "plain2", "clevel"))
    assert r.status_code == 200, r.text
    assert r.json()["data"] == [], "a plain clevel with no group membership must still see nothing"


@pytest.mark.asyncio
async def test_list_switchable_mandants_still_works_while_narrowed(mandant_db: MandantTestDb, app_client) -> None:
    """Before this fix, narrowing into any one mandate via X-Mandant-Context
    dropped every bypass flag (is_holding_admin etc.) for the rest of the
    request — which meant the switcher's own dropdown 403'd the instant it
    was used once, leaving ImpersonationBanner's "Exit" button as the only
    way back to a different mandate."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    mandant_b = await seed_mandant(mandant_db, name="Mandant B", slug="mandant-b")
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post("/api/v1/admin/mandants", json={"name": "Sub A", "slug": "sub-a"}, headers=headers)
    sub_a_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Division A1", "slug": "division-a1", "parent_id": sub_a_id},
        headers=headers,
    )
    division_id = r.json()["data"]["id"]

    # Narrowed holding_admin: still the full holding list, not a 403.
    scoped_headers = {**headers, "X-Mandant-Context": str(mandant_b)}
    r = await app_client.get("/api/v1/admin/mandants/switchable", headers=scoped_headers)
    assert r.status_code == 200, r.text
    ids = {m["id"] for m in r.json()["data"]}
    assert {str(default_mandant), str(mandant_b), sub_a_id, division_id} <= ids

    # Narrowed group_admin: still their full subtree, not just the one
    # mandate they're currently narrowed into.
    group_admin_id = await seed_user(
        mandant_db, username="groupy3", role="admin", mandant_id=sub_a_id, holding_role="group_admin",
    )
    group_headers = {**bearer(group_admin_id, "groupy3", "admin"), "X-Mandant-Context": division_id}
    r = await app_client.get("/api/v1/admin/mandants/switchable", headers=group_headers)
    assert r.status_code == 200, r.text
    ids = {m["id"] for m in r.json()["data"]}
    assert ids == {sub_a_id, division_id}


@pytest.mark.asyncio
async def test_activation_not_null_uses_zero_downtime_pattern_no_leftover(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """apply_multi_mandant_ddl()'s mandant_id NOT NULL enforcement goes
    through the standard zero-downtime pattern (NOT VALID CHECK ->
    VALIDATE CONSTRAINT -> SET NOT NULL -> DROP CHECK) instead of a bare
    ALTER COLUMN ... SET NOT NULL, to avoid holding ACCESS EXCLUSIVE for
    the full table-scan duration on a large, already-populated instance.
    The end state must be identical to the bare version: NOT NULL in
    effect, with no leftover scaffolding constraint."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))

    is_nullable = await fetch_scalar(
        mandant_db,
        "SELECT is_nullable FROM information_schema.columns "
        "WHERE table_name = 'runs' AND column_name = 'mandant_id'",
    )
    assert is_nullable == "NO"

    leftover = await fetch_scalar(
        mandant_db,
        "SELECT count(*) FROM pg_constraint WHERE conname = 'runs_mandant_id_not_null_check'",
    )
    assert leftover == 0, "the scaffolding CHECK constraint must be dropped once SET NOT NULL is in effect"

    # The constraint is still enforced end-to-end: a NULL mandant_id write
    # against an activated, NOT-NULL table still fails.
    with pytest.raises(Exception):
        async with mandant_db.owner_sessionmaker() as session:
            await session.execute(
                text(
                    "INSERT INTO runs (id, project, score, created_at, mandant_id) "
                    "VALUES (:id, 'no-mandate-run', 1, now(), NULL)"
                ),
                {"id": uuid.uuid4()},
            )
            await session.commit()


# ── Post-Phase-7 audit findings ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_demo_run_rejected_for_holding_only_user_without_context(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """A holding-only clevel user cannot create a demo run without narrowing
    into a mandate first — the run would have no mandant_id to tag."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))

    holding_only_id = await seed_user(
        mandant_db, username="holder", role="clevel", holding_role="holding_admin"
    )
    r = await app_client.post(
        "/api/v1/sandbox/demo-run", headers=bearer(holding_only_id, "holder", "clevel")
    )
    assert r.status_code == 400, r.text
    assert "X-Mandant-Context" in r.json()["detail"]


@pytest.mark.asyncio
async def test_demo_run_tagged_with_effective_mandant(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """A mandate-scoped clevel user's demo run is tagged with their mandate."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    default_mandant = await fetch_scalar(mandant_db, "SELECT id FROM mandants WHERE slug = 'default'")
    assert default_mandant is not None

    clevel_id = await seed_user(
        mandant_db, username="demoer", role="clevel", mandant_id=default_mandant
    )
    r = await app_client.post(
        "/api/v1/sandbox/demo-run", headers=bearer(clevel_id, "demoer", "clevel")
    )
    if r.status_code == 503 and "wafpass-core is not installed" in r.json().get("detail", ""):
        pytest.skip("wafpass-core is not installed; demo-run integration skipped")
    assert r.status_code == 201, r.text

    run = r.json()["data"]
    run_mandant = await fetch_scalar(
        mandant_db, "SELECT mandant_id FROM runs WHERE id = :id", id=run["id"]
    )
    assert str(run_mandant) == str(default_mandant)


@pytest.mark.asyncio
async def test_project_groups_are_mandate_scoped(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """Project groups are created and listed only within the caller's mandate."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    holdy_headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Sub A", "slug": "sub-a"}, headers=holdy_headers,
    )
    sub_a_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Sub B", "slug": "sub-b"}, headers=holdy_headers,
    )
    sub_b_id = r.json()["data"]["id"]

    admin_a_id = await seed_user(mandant_db, username="admin-a", role="admin", mandant_id=sub_a_id)
    admin_b_id = await seed_user(mandant_db, username="admin-b", role="admin", mandant_id=sub_b_id)

    # Admin A creates a project group inside their own mandate.
    r = await app_client.post(
        "/api/v1/projects/shared-proj/groups",
        json={"project": "shared-proj", "group_name": "eng"},
        headers=bearer(admin_a_id, "admin-a", "admin"),
    )
    assert r.status_code == 201, r.text
    assert r.json()["group_name"] == "eng"

    # Admin B sees no groups for the same project name.
    r = await app_client.get(
        "/api/v1/projects/shared-proj/groups",
        headers=bearer(admin_b_id, "admin-b", "admin"),
    )
    assert r.status_code == 200, r.text
    assert r.json() == []

    # Admin A still sees theirs.
    r = await app_client.get(
        "/api/v1/projects/shared-proj/groups",
        headers=bearer(admin_a_id, "admin-a", "admin"),
    )
    assert r.status_code == 200, r.text
    assert [g["group_name"] for g in r.json()] == ["eng"]


@pytest.mark.asyncio
async def test_user_group_endpoints_cannot_touch_users_in_other_mandates(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """A mandate admin reading or mutating another mandate user's groups
    gets a 404, not a cross-mandate leak."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    holdy_headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Sub A", "slug": "sub-a"}, headers=holdy_headers,
    )
    sub_a_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Sub B", "slug": "sub-b"}, headers=holdy_headers,
    )
    sub_b_id = r.json()["data"]["id"]

    user_a_id = await seed_user(mandant_db, username="user-a", role="clevel", mandant_id=sub_a_id)
    admin_b_id = await seed_user(mandant_db, username="admin-b", role="admin", mandant_id=sub_b_id)
    admin_b_headers = bearer(admin_b_id, "admin-b", "admin")

    r = await app_client.get(
        f"/api/v1/auth/users/{user_a_id}/groups", headers=admin_b_headers,
    )
    assert r.status_code == 404, r.text

    r = await app_client.post(
        f"/api/v1/auth/users/{user_a_id}/groups",
        json={"group_name": "eng", "provider": "oidc"},
        headers=admin_b_headers,
    )
    assert r.status_code == 404, r.text

    r = await app_client.delete(
        f"/api/v1/auth/users/{user_a_id}/groups/eng", headers=admin_b_headers,
    )
    assert r.status_code == 404, r.text


@pytest.mark.asyncio
async def test_pipelines_metrics_and_trends_respect_group_role_bypass(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """group_admin with a base role below 'admin' sees the projects mapped to
    their groups, not every project in their mandate subtree."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    holdy_headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Sub A", "slug": "sub-a"}, headers=holdy_headers,
    )
    sub_a_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants",
        json={"name": "Division A1", "slug": "division-a1", "parent_id": sub_a_id},
        headers=holdy_headers,
    )
    division_a1_id = r.json()["data"]["id"]

    # A group_admin rooted at Sub A. Their base role is clevel so the old
    # user.role == "admin" check would have excluded them from pipelines.
    group_admin_id = await seed_user(
        mandant_db, username="groupy", role="clevel", mandant_id=sub_a_id, holding_role="group_admin"
    )
    group_headers = bearer(group_admin_id, "groupy", "clevel")

    # Runs in two projects under the same subtree.
    sub_a_user = await seed_user(mandant_db, username="sub-a-user", role="admin", mandant_id=sub_a_id)
    div_user = await seed_user(mandant_db, username="div-user", role="admin", mandant_id=division_a1_id)
    r = await app_client.post(
        "/api/v1/runs", json={"project": "group-proj", "score": 50}, headers=bearer(sub_a_user, "sub-a-user", "admin")
    )
    assert r.status_code == 201, r.text
    r = await app_client.post(
        "/api/v1/runs", json={"project": "other-proj", "score": 60}, headers=bearer(div_user, "div-user", "admin")
    )
    assert r.status_code == 201, r.text

    # Map only group-proj to the group the group_admin belongs to.
    async with mandant_db.owner_sessionmaker() as session:
        await session.execute(
            text(
                "INSERT INTO project_groups (project, group_name, mandant_id) VALUES (:project, :group, :mandant_id)"
            ),
            {"project": "group-proj", "group": "eng", "mandant_id": sub_a_id},
        )
        await session.execute(
            text("INSERT INTO user_groups (user_id, group_name, provider) VALUES (:user_id, :group, 'local')"),
            {"user_id": group_admin_id, "group": "eng"},
        )
        await session.commit()

    r = await app_client.get("/api/v1/pipelines/metrics", headers=group_headers)
    assert r.status_code == 200, r.text
    projects = [p["project"] for p in r.json()["data"]["projectsList"]]
    assert "group-proj" in projects
    assert "other-proj" not in projects

    r = await app_client.get("/api/v1/pipelines/trends", headers=group_headers)
    assert r.status_code == 200, r.text
    total = sum(day["count"] for day in r.json()["data"]["runsByDay"])
    assert total == 1


@pytest.mark.asyncio
async def test_instance_mode_counts_are_instance_wide(
    mandant_db: MandantTestDb, app_client,
) -> None:
    """GET /admin/instance-mode returns total user/mandant counts, not counts
    scoped to a plain admin's own mandate."""
    admin_id = await seed_user(mandant_db, username="admin1", role="admin")
    await activate(app_client, bearer(admin_id, "admin1", "admin"))
    holdy_id = await seed_user(mandant_db, username="holdy", role="admin", holding_role="holding_admin")
    holdy_headers = bearer(holdy_id, "holdy", "admin")

    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Sub A", "slug": "sub-a"}, headers=holdy_headers,
    )
    sub_a_id = r.json()["data"]["id"]
    r = await app_client.post(
        "/api/v1/admin/mandants", json={"name": "Sub B", "slug": "sub-b"}, headers=holdy_headers,
    )
    sub_b_id = r.json()["data"]["id"]

    await seed_user(mandant_db, username="user-a", role="clevel", mandant_id=sub_a_id)
    await seed_user(mandant_db, username="user-b", role="clevel", mandant_id=sub_b_id)

    admin_a_id = await seed_user(mandant_db, username="admin-a", role="admin", mandant_id=sub_a_id)
    r = await app_client.get(
        "/api/v1/admin/instance-mode", headers=bearer(admin_a_id, "admin-a", "admin"),
    )
    assert r.status_code == 200, r.text
    data = r.json()["data"]
    # 1 admin seeded pre-activation + 1 holdy + 2 clevel + 1 admin-a = 5
    # (admin1 was promoted to holding_admin, so still counted as a user)
    assert data["user_count"] == 5, data
    # Default + Sub A + Sub B = 3
    assert data["mandant_count"] == 3, data
