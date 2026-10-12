"""Multi-mandant activation DDL — deliberately *not* an Alembic revision.

See .plan.md, Phase 1 ("Decided (revised 2026-10-09): `0044` is not an
Alembic revision at all") for why: this DDL is a one-time, state-gated
admin action, not ordinary schema evolution. Modelling it as an Alembic
revision would mean either a second, permanently-unmerged Alembic head
(conflicts with tests/test_alembic_versions.py's single-head invariant) or
risking an accidental activation via a routine ``alembic upgrade head``.

This module is the single source of truth for that DDL. Its only callers:

- the Phase 2 admin endpoint (``POST /api/v1/admin/activate-multi-mandant``),
  on the owner/superuser connection (``wafpass_server.database.get_owner_connection``),
  inside the same transaction as its default-mandant-creation + backfill DML;
- a small manual CLI entry point, for an operator who needs to (re-)apply
  it outside the API.

Every table name below must stay in sync with
``wafpass-server/alembic/versions/0043_add_mandants_and_mandant_id_columns.py``
and ``decisions/adrs/ADR-003-multi-mandant-tenancy.md``.

Policy design notes
--------------------
Every comparison against a session GUC is done as ``column::text = ...``,
never ``current_setting(...)::uuid = column``. Postgres does not guarantee
left-to-right short-circuit evaluation of ``OR`` — an unset or empty GUC
cast to ``::uuid`` can raise ``invalid input syntax for type uuid`` at
runtime depending on how the planner orders the boolean expression.
Comparing as text instead means an unset/empty GUC just compares unequal
(safely false) against any real column value, with no cast risk at all.

Some tables get one extra ``OR`` branch in ``USING`` beyond the generic
mandant/holding-role check — the "auth-bootstrap problem": you cannot know
a principal's mandate until you've loaded the one row that states it, but
RLS would otherwise block loading that very row before any mandate context
exists. The fix is the same shape every time: let a principal (or anonymous
caller holding the right secret) find *exactly the one row proving its own
identity*, regardless of mandate, via a session variable set from something
already known before the query runs (a JWT's ``sub`` claim, a raw API key,
a public URL token) — never a blanket bypass of the table.
"""
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

# Every tenant-scoped table that gets only the generic policy.
_GENERIC_TENANT_TABLES = [
    "project_passports",
    "runs",
    "run_findings",
    "run_secret_findings",
    "waivers",
    "risk_acceptances",
    "project_groups",
    "notifications",
    "user_audit_logs",
    "compliance_audit_events",
    "findings_comments",
    "secret_findings_comments",
]

# table -> extra USING() OR-branch SQL (one or more), for tables that need
# the auth-bootstrap self-lookup carve-out described above.
_SELF_LOOKUP_TENANT_TABLES: dict[str, list[str]] = {
    # `users` needs *two* separate bootstrap carve-outs, because the two
    # places a user's own row is looked up before any mandate is known
    # don't know the same thing in advance:
    #   - JWT validation (get_current_user / require_ingest) already knows
    #     the user's id, from the token's `sub` claim.
    #   - POST /auth/login knows only the submitted username — the id is
    #     exactly what this query is trying to discover.
    "users": [
        "id::text = current_setting('app.current_user_id', true)",
        "username = current_setting('app.login_username', true)",
    ],
    # An API key is looked up by its hash before its mandant is known.
    # Not consumed until Phase 4 wires up the ingest path, but the policy
    # shouldn't need to change again when that lands.
    "api_keys": ["key_hash = current_setting('app.current_api_key_hash', true)"],
    # Public, unauthenticated lookups by an unguessable secret token.
    # All four reuse the same session variable — a given anonymous request
    # only ever resolves one of these tables.
    "evidence": ["public_token = current_setting('app.public_lookup_token', true)"],
    "widgets": ["token = current_setting('app.public_lookup_token', true)"],
    "validations": ["validation_id = current_setting('app.public_lookup_token', true)"],
    "project_achievements": ["verification_token = current_setting('app.public_lookup_token', true)"],
    # ADR-005: public SSO endpoints need to read the instance-wide default
    # config row (mandant_id IS NULL) before any user is authenticated.
    # The boolean GUC app.allow_default_sso gates that branch.
    "sso_configs": [
        "(mandant_id IS NULL AND current_setting('app.allow_default_sso', true) = 'true')"
    ],
}

ALL_TENANT_TABLES: list[str] = [*_GENERIC_TENANT_TABLES, *_SELF_LOOKUP_TENANT_TABLES.keys()]

# Every tenant table's mandant_id becomes NOT NULL after activation —
# except `users` and `user_audit_logs`. A holding_admin/holding_viewer
# account may legitimately have no personal/home mandant at all (ADR-003's
# role table: a holding admin administers the *holding*, not necessarily
# any one company inside it). RLS isolation still fully applies to such a
# row — NULL never matches the mandant-equality branch of the policy below,
# it just means "only visible via a holding flag or the self-lookup
# carve-out," never via the mandant match.
#
# `user_audit_logs` has the same exemption for the same underlying reason,
# found the hard way: a holding-only account (mandant_id=NULL) performing
# *any* audited action — logging in, editing a user, anything that calls
# auth.py's `_audit()` — would otherwise raise a real NotNullViolationError
# the instant one exists, because there is no single mandate to tag a
# holding-level action with. A NULL row here is the correct outcome, not a
# gap: it's visible only to holding_admin/holding_viewer, exactly matching
# that the action itself was holding-level, not mandate-level.
#
# `validations` is exempted for a different reason (Phase 4): the official
# countersignature flow round-trips through the *external* validation
# gateway (a separate repository, `wafpass-validation`, out of scope for
# this plan) — wafpass-server signs a local attestation carrying
# `mandant_id`, the dashboard forwards it to the gateway, the gateway
# forwards it back to `POST /validations/internal/sign`. Until that
# external repo is updated to pass the field through untouched, it will
# arrive as `None`. Forcing NOT NULL here would mean every official
# (gateway-countersigned) validation hard-fails until a repo this plan
# doesn't control is updated — a worse outcome than degrading gracefully:
# a validation with `mandant_id=NULL` still signs and verifies correctly
# (its own public verify/badge endpoints use the validation_id self-lookup
# carve-out, unaffected by mandate), it's simply invisible from an ordinary
# mandate-scoped user's own registry list until the gateway catches up.
#
# `sso_configs` is exempted for ADR-005: it must keep a row with
# mandant_id IS NULL as the instance-wide default SSO configuration, even
# after activation. Per-mandant overrides are tagged normally.
#
# Confirmed by actually running this DDL and the full request path against
# a real seeded holding-only account; forcing NOT NULL on either table
# raises a real NotNullViolationError the moment one exists.
_NOT_NULL_TABLES: list[str] = [
    t for t in ALL_TENANT_TABLES if t not in ("users", "user_audit_logs", "validations", "sso_configs")
]


#  Phase 6b / ADR-004 — group_admin/group_viewer see their own mandate plus
# every descendant in `mandant_ancestry` (a closure table over
# mandants.parent_id, kept in sync by wafpass_server.mandant_ancestry.
# recompute_mandant_ancestry() — see that module and the ADR for why a
# closure table instead of a recursive CTE here: the per-row RLS cost of a
# recursive CTE embedded directly in the policy would be a tree-walk on
# every row of every query, forever; an indexed join against a closure
# table is not). Deliberately reuses app.current_mandant_id as "the
# subtree root" rather than adding a new GUC — a group_admin/viewer's
# subtree root is always their own mandate, never a different one.
_GROUP_USING_BRANCH = (
    "(current_setting('app.is_group_admin', true) = 'true' "
    "OR current_setting('app.is_group_viewer', true) = 'true') "
    "AND mandant_id IN (SELECT descendant_id FROM mandant_ancestry "
    "WHERE ancestor_id::text = current_setting('app.current_mandant_id', true))"
)
_GROUP_CHECK_BRANCH = (
    "current_setting('app.is_group_admin', true) = 'true' "
    "AND mandant_id IN (SELECT descendant_id FROM mandant_ancestry "
    "WHERE ancestor_id::text = current_setting('app.current_mandant_id', true))"
)


def _policy_sql(table: str) -> str:
    using_clauses = [
        "mandant_id::text = current_setting('app.current_mandant_id', true)",
        "current_setting('app.is_holding_admin', true) = 'true'",
        "current_setting('app.is_holding_viewer', true) = 'true'",
        _GROUP_USING_BRANCH,
    ]
    using_clauses.extend(_SELF_LOOKUP_TENANT_TABLES.get(table, []))

    # holding_viewer/group_viewer are deliberately excluded here: they only
    # ever bypass the read (USING) side, so cross-mandate "read-only" is
    # enforced by the database itself, not just the API layer.
    check_clauses = [
        "mandant_id::text = current_setting('app.current_mandant_id', true)",
        "current_setting('app.is_holding_admin', true) = 'true'",
        _GROUP_CHECK_BRANCH,
    ]

    using_sql = "\n        OR ".join(using_clauses)
    check_sql = "\n        OR ".join(check_clauses)
    return (
        f'CREATE POLICY {table}_tenant_isolation ON "{table}"\n'
        f"    USING (\n        {using_sql}\n    )\n"
        f"    WITH CHECK (\n        {check_sql}\n    );"
    )


async def apply_multi_mandant_ddl(conn: AsyncConnection) -> None:
    """Alter every mandant_id column to NOT NULL and enable + force RLS.

    Callers must run this only once per instance, inside the same
    transaction as the default-mandant-creation + backfill DML, guarded by
    an ``instance_mode == "single_tenant"`` check — that guard lives in the
    Phase 2 endpoint, not here. Re-running it against an already-activated
    instance will fail on ``CREATE POLICY`` (name already exists), which is
    the intended fail-closed behaviour: it should never run twice.
    """
    for table in _NOT_NULL_TABLES:
        # A plain `ALTER COLUMN ... SET NOT NULL` on a nullable column
        # needs ACCESS EXCLUSIVE for the *entire* table-scan it does to
        # verify no NULLs exist — a real operational risk for activating an
        # already-populated instance with large tables, since that lock
        # blocks every ordinary read and write on the table for however
        # long the scan takes. Splitting it into the standard three-step
        # "zero-downtime NOT NULL" pattern instead: an unvalidated CHECK
        # constraint is metadata-only (brief ACCESS EXCLUSIVE), the actual
        # scan runs under VALIDATE CONSTRAINT's SHARE UPDATE EXCLUSIVE lock
        # (concurrent reads/writes stay unblocked, only other DDL waits),
        # and the final SET NOT NULL is metadata-only too — PostgreSQL 12+
        # skips re-scanning the table once a validated CHECK constraint
        # already proves no row can be NULL. The now-redundant CHECK is
        # dropped once SET NOT NULL is itself in effect. Same end state as
        # before (a NOT NULL column); only how long each lock is held
        # changes. Scoped to exactly what was flagged as a risk — the
        # composite-key PK/UNIQUE swaps below have no equivalent
        # incremental-validation mechanism and are left as they are.
        check_name = f"{table}_mandant_id_not_null_check"
        await conn.execute(
            text(f'ALTER TABLE "{table}" ADD CONSTRAINT "{check_name}" CHECK (mandant_id IS NOT NULL) NOT VALID;')
        )
        await conn.execute(text(f'ALTER TABLE "{table}" VALIDATE CONSTRAINT "{check_name}";'))
        await conn.execute(text(f'ALTER TABLE "{table}" ALTER COLUMN mandant_id SET NOT NULL;'))
        await conn.execute(text(f'ALTER TABLE "{table}" DROP CONSTRAINT "{check_name}";'))

    # project_passports' own PK was just `project` alone — a bare natural
    # key that collides the instant two mandates both want a row for the
    # same project name (a real UniqueViolationError on ingest, confirmed
    # against a live instance — see .plan.md and migration 0046, which
    # does this same swap for an instance that activated before this
    # existed). ADR-003's own "Key design decisions" already settled on
    # composite (mandant_id, project) uniqueness instead of a UUID
    # surrogate key; this is where that becomes real, now that mandant_id
    # is guaranteed NOT NULL by the loop above.
    await conn.execute(text('ALTER TABLE "project_passports" DROP CONSTRAINT project_passports_pkey;'))
    await conn.execute(
        text('ALTER TABLE "project_passports" ADD CONSTRAINT project_passports_pkey PRIMARY KEY (mandant_id, project);')
    )

    # Same gap, same fix, for the two tables Phase 1's own findings already
    # flagged as carrying it ("waivers.id / risk_acceptances.id are
    # globally-unique control-ids, not per-mandate... will surface loudly
    # as a 500 the first time two mandates waive the same control") — and
    # for project_achievements' own (project, tier_level) uniqueness,
    # found live in the same incident as project_passports above (a
    # second mandate's run reaching the same tier for a same-named
    # project collided too). See migration 0047, which does this same
    # swap for an instance that activated before this existed.
    await conn.execute(text('ALTER TABLE "waivers" DROP CONSTRAINT waivers_pkey;'))
    await conn.execute(text('ALTER TABLE "waivers" ADD CONSTRAINT waivers_pkey PRIMARY KEY (mandant_id, id);'))
    await conn.execute(text('ALTER TABLE "risk_acceptances" DROP CONSTRAINT risk_acceptances_pkey;'))
    await conn.execute(
        text('ALTER TABLE "risk_acceptances" ADD CONSTRAINT risk_acceptances_pkey PRIMARY KEY (mandant_id, id);')
    )
    await conn.execute(
        text('ALTER TABLE "project_achievements" DROP CONSTRAINT uq_project_achievements_project_tier;')
    )
    await conn.execute(
        text(
            'ALTER TABLE "project_achievements" ADD CONSTRAINT uq_project_achievements_project_tier '
            "UNIQUE (mandant_id, project, tier_level);"
        )
    )

    for table in ALL_TENANT_TABLES:
        await conn.execute(text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY;'))
        await conn.execute(text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY;'))
        await conn.execute(text(_policy_sql(table)))
