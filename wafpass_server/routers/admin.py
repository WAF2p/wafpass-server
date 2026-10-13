"""Multi-mandant activation — the one-way admin switch.

See decisions/adrs/ADR-003-multi-mandant-tenancy.md and .plan.md, Phase 2.

POST /api/v1/admin/activate-multi-mandant is the only place in the entire
server that ever writes a value other than "single_tenant" into
instance_settings.key="instance_mode", and the only caller of
db_migrations.activate_multi_mandant_ddl.apply_multi_mandant_ddl() other
than a manual operator CLI. It runs on the owner/superuser connection
(wafpass_server.database.get_owner_connection) — never the pooled
wafpass_app runtime engine, which has no DDL rights — and does everything
(backfill DML + the NOT NULL/RLS DDL + flipping instance_mode) inside one
transaction, so a failure partway through leaves the instance exactly as
it was: still "single_tenant", nothing half-migrated.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from wafpass_server.auth.deps import AuthContext, get_auth_context, get_current_user, get_scoped_db
from wafpass_server.database import get_db, get_owner_connection
from wafpass_server.db_migrations.activate_multi_mandant_ddl import ALL_TENANT_TABLES, apply_multi_mandant_ddl
from wafpass_server.mandant_ancestry import recompute_mandant_ancestry
from wafpass_server.models import InstanceSetting, Mandant, User
from wafpass_server.schemas import Envelope

router = APIRouter(prefix="/admin", tags=["admin"])


class ActivationSummary(BaseModel):
    instance_mode: str
    default_mandant_id: uuid.UUID
    default_mandant_name: str
    users_assigned: int
    activated_by: str


class InstanceModeOut(BaseModel):
    instance_mode: str
    changed_at: datetime | None = None
    changed_by_username: str | None = None
    can_activate: bool
    user_count: int
    mandant_count: int


class ActivationError(Exception):
    """Raised for an activation precondition failure (not a DB error)."""


# App-validated, not a DB CHECK constraint — see models.py's Mandant.mandate_type.
_VALID_MANDATE_TYPES = {"holding", "subsidiary", "division"}

# ADR-005: mandants.settings["auth_mode"] — app-validated, not a DB CHECK
# constraint, same convention as _VALID_MANDATE_TYPES above. "inherit" is
# the default and reproduces pre-ADR-005 behaviour exactly: SSO buttons
# shown if any config (default or per-mandant override) is enabled, local
# login always available. "local_only" is enforced (routers/sso.py hides
# every SSO entrypoint for the mandate and rejects any claim/override
# that would otherwise provision or reassign a user into it).
# "sso_optional" is reserved for future use and enforces nothing yet.
_VALID_AUTH_MODES = {"inherit", "sso_optional", "local_only"}


class MandantOut(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    logo_url: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    # Phase 6a — organizational/display metadata only, no RLS effect. See
    # .plan.md's "Phase 6a" section and Mandant model's docstring.
    parent_id: uuid.UUID | None = None
    mandate_type: str = "subsidiary"
    jurisdiction: str | None = None
    risk_tier: str | None = None
    data_residency: str | None = None
    inherit_parent_policies: bool = True
    # ADR-005 — see _VALID_AUTH_MODES above. Read from the settings JSONB,
    # not its own column (same "no schema change needed" convention as
    # instance_mode/mandate_type elsewhere in this plan).
    auth_mode: str = "inherit"

    model_config = {"from_attributes": True}

    @classmethod
    def from_mandant(cls, mandant: "Mandant | dict") -> "MandantOut":
        """Build from either a ``Mandant`` ORM row or a raw-SQL mapping
        (``result.mappings()``, used by list_switchable_mandants()'s
        group-role branch) — both shapes appear at existing call sites.
        Needed (not just stylistic) because ``auth_mode`` lives inside
        the ``settings`` JSONB, not its own attribute/column:
        ``MandantOut.model_validate(mandant)`` would silently always
        report the default ``"inherit"`` no matter what's actually
        stored, since there's no ``auth_mode`` attribute for
        ``from_attributes`` to find.
        """
        def _get(key: str):
            return mandant[key] if isinstance(mandant, dict) else getattr(mandant, key)

        return cls(
            id=_get("id"),
            name=_get("name"),
            slug=_get("slug"),
            logo_url=_get("logo_url"),
            is_active=_get("is_active"),
            created_at=_get("created_at"),
            updated_at=_get("updated_at"),
            parent_id=_get("parent_id"),
            mandate_type=_get("mandate_type"),
            jurisdiction=_get("jurisdiction"),
            risk_tier=_get("risk_tier"),
            data_residency=_get("data_residency"),
            inherit_parent_policies=_get("inherit_parent_policies"),
            auth_mode=(_get("settings") or {}).get("auth_mode", "inherit"),
        )


class MandantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$")
    logo_url: str = ""
    parent_id: uuid.UUID | None = None
    mandate_type: str = "subsidiary"
    jurisdiction: str | None = None
    risk_tier: str | None = None
    data_residency: str | None = None
    inherit_parent_policies: bool = True
    auth_mode: str = "inherit"


class MandantUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    logo_url: str | None = None
    is_active: bool | None = None
    # Use model_fields_set (checked at the call site) to tell "omitted" from
    # "explicitly null" for parent_id — null is itself meaningful ("make
    # this a top-level mandate"), the same pattern auth.py's UserUpdate
    # already uses for mandant_id, for the same reason.
    parent_id: uuid.UUID | None = None
    mandate_type: str | None = None
    jurisdiction: str | None = None
    risk_tier: str | None = None
    data_residency: str | None = None
    inherit_parent_policies: bool | None = None
    auth_mode: str | None = None


class MandantRollupOut(BaseModel):
    """Aggregated counts for one mandate plus all of its descendants
    (Phase 6a). holding_admin-only, same as the rest of mandant CRUD — the
    recursion here is pure data shape, not a new access boundary, since
    holding_admin already bypasses RLS on every table involved."""
    mandant_id: uuid.UUID
    mandate_count: int
    run_count: int
    avg_score: float | None = None


async def require_admin_or_holding_admin(
    user: Annotated[User, Depends(get_current_user)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> User:
    """"Requires admin or holding_admin" (Phase 2.1/3.1), checked against
    both the local role and the resolved holding flag — not just
    ``require_role("admin")``, because a holding_admin's own base ``role``
    can be anything. (For the activation endpoint specifically this always
    collapses to plain "admin": `is_holding_admin` is unconditionally False
    until *after* activation, by `get_auth_context()`'s own design, so the
    holding_admin branch is only ever live for GET /instance-mode once
    multi-mandant mode already exists.)
    """
    if user.role == "admin" or auth.is_holding_admin:
        return user
    raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Admin or holding_admin role required.")


async def require_holding_admin(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> AuthContext:
    """Strictly `holding_admin` — not plain `admin`. Mandant CRUD (Phase 3.2)
    is deliberately narrower than activation/instance-mode: a mandate-scoped
    `admin` manages their own company, not the list of companies in the
    holding. Unlike `require_admin_or_holding_admin`, this one is never
    unreachable — mandant CRUD only ever makes sense once multi-mandant mode
    (and therefore a real holding_admin) exists.
    """
    if not auth.is_holding_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="holding_admin role required.")
    return auth


async def require_switch_role(
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> AuthContext:
    """Any role whose Global Context Switcher (Phase 6a) has something to
    narrow: holding_admin, holding_viewer, or — Phase 6b / ADR-004 —
    group_admin/group_viewer. Deliberately broader than
    require_holding_admin: mandant *CRUD* (create/edit/reparent/rollup)
    stays holding_admin-only, a separate, bigger decision ADR-004 doesn't
    address — this dependency only gates "list the mandates I'm allowed to
    switch into," which every one of these four roles needs.

    Checked against ``auth.user.holding_role`` — the caller's *permanent*
    role — not ``auth.is_holding_admin``/etc. (the request's *effective*,
    possibly X-Mandant-Context-narrowed flags). Narrowing deliberately
    drops every bypass flag for the rest of the request (see
    get_auth_context), but that was only ever meant to scope RLS and
    resource tagging to "act like an ordinary admin of that one mandate" —
    not to also hide the switcher's own list of what you could switch to
    next. Before this fix, narrowing into any one mandate made this 403 for
    every switchable role, leaving ImpersonationBanner's "Exit" button as
    the only way back to a different mandate.
    """
    if auth.user.holding_role not in ("holding_admin", "holding_viewer", "group_admin", "group_viewer"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="A holding-wide or group role is required.")
    return auth


async def _activate(conn: AsyncConnection, acting_user_id: uuid.UUID, ip: str) -> dict:
    """The activation logic itself, operating on the owner connection.

    Kept separate from the route handler so it can be exercised directly
    (as it was during verification) without going through HTTP/FastAPI.
    """
    mode_result = await conn.execute(text("SELECT value FROM instance_settings WHERE key = 'instance_mode'"))
    current_mode = mode_result.scalar_one_or_none() or "single_tenant"
    if current_mode != "single_tenant":
        raise ActivationError(
            f"Instance is already in '{current_mode}' mode. Activation is one-way and cannot be repeated."
        )

    # Create the default mandant if none exists yet, else backfill into the
    # oldest existing one (an operator may have pre-created mandants by hand).
    count_result = await conn.execute(text("SELECT COUNT(*) FROM mandants"))
    if count_result.scalar_one() == 0:
        default_mandant_id = uuid.uuid4()
        await conn.execute(
            text(
                "INSERT INTO mandants (id, name, slug, logo_url, settings, is_active, created_at, updated_at) "
                "VALUES (:id, 'Default', 'default', '', '{}'::jsonb, true, now(), now())"
            ),
            {"id": default_mandant_id},
        )
    else:
        first_result = await conn.execute(text("SELECT id FROM mandants ORDER BY created_at LIMIT 1"))
        default_mandant_id = first_result.scalar_one()

    # Phase 6b / ADR-004 — mandant_ancestry didn't exist before this
    # mandant did (or before any mandate an operator pre-created by hand
    # did), so it needs seeding here too, not just from the ordinary
    # create/update-mandant endpoints. Rebuilds from whatever `mandants`
    # rows exist right now, including any pre-existing hierarchy an
    # operator already set up by hand before activation.
    await recompute_mandant_ancestry(conn)

    # Assign all users without a mandant_id to the default mandant.
    await conn.execute(
        text("UPDATE users SET mandant_id = :m WHERE mandant_id IS NULL"), {"m": default_mandant_id}
    )

    # The acting admin becomes the holding's first holding_admin.
    # GET/POST /admin/mandants require holding_admin strictly (never plain
    # admin — see require_holding_admin's docstring), and nothing else in
    # this codebase ever sets holding_role: without this, the instance
    # activates into a state nobody can administer at the holding level —
    # not even the person who just flipped the switch — short of editing
    # the users table by hand. Whoever performs this one-way action is the
    # natural first administrator of the holding it just created.
    await conn.execute(
        text("UPDATE users SET holding_role = 'holding_admin' WHERE id = :u"), {"u": acting_user_id}
    )

    # Backfill every other tenant-scoped table. `users` is handled above —
    # ALL_TENANT_TABLES includes it (it needs the self-lookup policy carve-outs
    # too), so skip it here to avoid redundant work, not because it's special.
    for table in ALL_TENANT_TABLES:
        if table == "users":
            continue
        await conn.execute(
            text(f'UPDATE "{table}" SET mandant_id = :m WHERE mandant_id IS NULL'), {"m": default_mandant_id}
        )

    # NOT NULL + ENABLE/FORCE ROW LEVEL SECURITY + CREATE POLICY for every
    # tenant table — the single source of truth, see that module.
    await apply_multi_mandant_ddl(conn)

    await conn.execute(
        text(
            "UPDATE instance_settings SET value = 'multi_mandant', changed_at = now(), "
            "changed_by_user_id = :u WHERE key = 'instance_mode'"
        ),
        {"u": acting_user_id},
    )

    await conn.execute(
        text(
            "INSERT INTO user_audit_logs (id, actor_id, action, detail, ip, timestamp, mandant_id) "
            "VALUES (:id, :actor, 'instance_mode_changed', :detail ::jsonb, :ip, now(), :m)"
        ),
        {
            "id": uuid.uuid4(),
            "actor": acting_user_id,
            "detail": json.dumps(
                {"from": "single_tenant", "to": "multi_mandant", "default_mandant_id": str(default_mandant_id)}
            ),
            "ip": ip,
            "m": default_mandant_id,
        },
    )

    users_assigned = (
        await conn.execute(text("SELECT COUNT(*) FROM users WHERE mandant_id = :m"), {"m": default_mandant_id})
    ).scalar_one()
    default_mandant_name = (
        await conn.execute(text("SELECT name FROM mandants WHERE id = :m"), {"m": default_mandant_id})
    ).scalar_one()

    return {
        "default_mandant_id": default_mandant_id,
        "default_mandant_name": default_mandant_name,
        "users_assigned": users_assigned,
    }


@router.post("/activate-multi-mandant", response_model=Envelope[ActivationSummary])
async def activate_multi_mandant(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    acting_user: Annotated[User, Depends(require_admin_or_holding_admin)],
) -> Envelope[ActivationSummary]:
    """Flip this instance from single-tenant to multi-mandant. One-way.

    Requires `admin` (or `holding_admin`, though see the note on
    `require_admin_or_holding_admin` — that branch is unreachable here).
    """
    # `db` is the same pooled wafpass_app session `require_admin_or_holding_admin`'s
    # own dependency chain (get_current_user/get_auth_context) already used to
    # read `users`/`instance_settings` — FastAPI caches Depends(get_db) per
    # request, so this is the identical session, not a fresh one. That read
    # leaves its transaction open (SQLAlchemy's AsyncSession does not
    # auto-commit), holding locks on exactly the tables this endpoint is
    # about to ALTER on a *second*, separate owner connection. Found as a
    # real deadlock — ALTER TABLE users ENABLE ROW LEVEL SECURITY blocked
    # indefinitely on `pg_stat_activity` showing this session "idle in
    # transaction" — the first time this endpoint was driven over real HTTP
    # with the get_owner_connection() bug above also fixed. Ending this
    # session's transaction first releases those locks before DDL needs them.
    # Deliberately commit(), not rollback(): rollback() unconditionally
    # expires every attribute on every object the session has loaded —
    # including `acting_user` — regardless of this sessionmaker's
    # expire_on_commit=False, which then crashes `acting_user.id` below
    # with a lazy-load attempted outside an async-aware context
    # (SQLAlchemy's MissingGreenlet). commit() respects expire_on_commit
    # and releases the same locks; nothing here has written anything, so
    # there is nothing it could lose.
    await db.commit()

    ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "")
    try:
        async with get_owner_connection() as conn:
            async with conn.begin():
                result = await _activate(conn, acting_user.id, ip)
    except ActivationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return Envelope(
        data=ActivationSummary(
            instance_mode="multi_mandant",
            default_mandant_id=result["default_mandant_id"],
            default_mandant_name=result["default_mandant_name"],
            users_assigned=result["users_assigned"],
            activated_by=acting_user.username,
        )
    )


@router.get("/my-mandate", response_model=Envelope[MandantOut | None])
async def get_my_mandate(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> Envelope[MandantOut | None]:
    """The caller's own mandate — any authenticated user, no holding_admin
    gate. `GET /mandants` deliberately can't serve this: an ordinary
    mandate-scoped user has only their own `mandant_id` (a bare UUID) on
    their own UserOut, with nothing to resolve it to a display name, and
    the full mandant list is holding_admin-only by design (Phase 3.2).
    Returns null for a holding-only account (no personal mandate) or in
    single_tenant mode.
    """
    if auth.mandant_id is None:
        return Envelope(data=None)
    mandant = await db.get(Mandant, auth.mandant_id)
    return Envelope(data=MandantOut.from_mandant(mandant) if mandant else None)


@router.get("/instance-mode", response_model=Envelope[InstanceModeOut])
async def get_instance_mode(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    _: Annotated[User, Depends(require_admin_or_holding_admin)],
) -> Envelope[InstanceModeOut]:
    """Current tenancy mode, for the dashboard's SettingsPage (Phase 3)."""
    result = await db.execute(select(InstanceSetting).where(InstanceSetting.key == "instance_mode"))
    row = result.scalar_one_or_none()
    mode = row.value if row and row.value else "single_tenant"

    changed_by_username: str | None = None
    if row is not None and row.changed_by_user_id is not None:
        username_result = await db.execute(select(User.username).where(User.id == row.changed_by_user_id))
        changed_by_username = username_result.scalar_one_or_none()

    # Counts are intentionally instance-wide. A scoped session would return
    # only the rows visible to the caller's mandate, which is misleading for a
    # settings page called "Instance mode". The endpoint is already protected
    # by `require_admin_or_holding_admin`, so a short-lived owner connection
    # for the two aggregate reads preserves the defense-in-depth boundary.
    async with get_owner_connection() as conn:
        user_count = (await conn.execute(select(func.count()).select_from(User))).scalar_one()
        mandant_count = (await conn.execute(select(func.count()).select_from(Mandant))).scalar_one()

    return Envelope(
        data=InstanceModeOut(
            instance_mode=mode,
            changed_at=row.changed_at if row else None,
            changed_by_username=changed_by_username,
            can_activate=(mode == "single_tenant"),
            user_count=user_count,
            mandant_count=mandant_count,
        )
    )


# ── Mandant CRUD (Phase 3.2) — holding_admin only ────────────────────────────
#
# `mandants` itself carries no RLS (it's the table every other tenant table's
# mandant_id references, same global-reference-table status as `controls`/
# `control_packs`) — these endpoints are the authorization boundary instead.

@router.get("/mandants", response_model=Envelope[list[MandantOut]])
async def list_mandants(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    _: Annotated[AuthContext, Depends(require_holding_admin)],
) -> Envelope[list[MandantOut]]:
    result = await db.execute(select(Mandant).order_by(Mandant.created_at))
    return Envelope(data=[MandantOut.from_mandant(m) for m in result.scalars().all()])


@router.get("/mandants/switchable", response_model=Envelope[list[MandantOut]])
async def list_switchable_mandants(
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(require_switch_role)],
) -> Envelope[list[MandantOut]]:
    """Mandates the caller's Global Context Switcher (TopNavigation's
    MandateIndicator) can narrow into.

    holding_admin/holding_viewer: every mandate in the holding — the same
    set `GET /mandants` returns for a holding_admin, but this is also the
    first endpoint holding_viewer itself can call for this purpose (`GET
    /mandants` is holding_admin-strict), closing a previously-documented
    gap (.plan.md) as a side effect of building this for group roles.

    group_admin/group_viewer (Phase 6b / ADR-004): only their own subtree
    — their own mandate (their permanent ``auth.user.mandant_id``,
    guaranteed non-null whenever either role is set — see
    get_auth_context()) plus every descendant in `mandant_ancestry`, which
    already includes a depth-0 self-row, so this query needs no separate
    "include myself" special case.

    Reads ``auth.user.holding_role``/``auth.user.mandant_id`` — the
    caller's permanent role/mandate — not the request's possibly-narrowed
    ``auth.is_holding_admin``/``auth.mandant_id``, so this list stays the
    full set the caller could switch to even while currently narrowed into
    one of them (see require_switch_role above). Safe to do unconditionally
    here: unlike RLS-governed tables, `mandants`/`mandant_ancestry` carry no
    row-level security at all, so this is a pure Python-level read with no
    RLS-bypass implications either way.
    """
    if auth.user.holding_role in ("holding_admin", "holding_viewer"):
        result = await db.execute(select(Mandant).order_by(Mandant.created_at))
        return Envelope(data=[MandantOut.from_mandant(m) for m in result.scalars().all()])

    result = await db.execute(
        text(
            "SELECT m.* FROM mandants m "
            "JOIN mandant_ancestry a ON a.descendant_id = m.id "
            "WHERE a.ancestor_id = :root "
            "ORDER BY m.created_at"
        ),
        {"root": auth.user.mandant_id},
    )
    rows = result.mappings().all()
    return Envelope(data=[MandantOut.from_mandant(dict(r)) for r in rows])


async def _validate_parent(db: AsyncSession, parent_id: uuid.UUID) -> None:
    parent = await db.get(Mandant, parent_id)
    if parent is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Parent mandant not found.")


async def _would_create_cycle(db: AsyncSession, mandant_id: uuid.UUID, candidate_parent_id: uuid.UUID) -> bool:
    """True if setting *mandant_id*'s parent to *candidate_parent_id* would
    create a cycle — i.e. candidate_parent_id is mandant_id itself, or
    already a descendant of it. Walks up from the candidate toward the
    root; the mandate count in practice is small, so a simple per-row loop
    is fine, no need for a recursive SQL query here."""
    if candidate_parent_id == mandant_id:
        return True
    current: uuid.UUID | None = candidate_parent_id
    seen: set[uuid.UUID] = set()
    while current is not None:
        if current == mandant_id:
            return True
        if current in seen:
            break  # defensive guard against already-corrupt data; shouldn't happen
        seen.add(current)
        result = await db.execute(select(Mandant.parent_id).where(Mandant.id == current))
        current = result.scalar_one_or_none()
    return False


@router.post("/mandants", response_model=Envelope[MandantOut], status_code=status.HTTP_201_CREATED)
async def create_mandant(
    payload: MandantCreate,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    _: Annotated[AuthContext, Depends(require_holding_admin)],
) -> Envelope[MandantOut]:
    existing = await db.execute(select(Mandant).where(Mandant.slug == payload.slug))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"Slug '{payload.slug}' is already in use.")
    if payload.mandate_type not in _VALID_MANDATE_TYPES:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"mandate_type must be one of {sorted(_VALID_MANDATE_TYPES)}.",
        )
    if payload.auth_mode not in _VALID_AUTH_MODES:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"auth_mode must be one of {sorted(_VALID_AUTH_MODES)}.",
        )
    if payload.parent_id is not None:
        await _validate_parent(db, payload.parent_id)
    mandant = Mandant(
        name=payload.name,
        slug=payload.slug,
        logo_url=payload.logo_url,
        settings={"auth_mode": payload.auth_mode},
        parent_id=payload.parent_id,
        mandate_type=payload.mandate_type,
        jurisdiction=payload.jurisdiction,
        risk_tier=payload.risk_tier,
        data_residency=payload.data_residency,
        inherit_parent_policies=payload.inherit_parent_policies,
    )
    db.add(mandant)
    await db.flush()
    # Phase 6b / ADR-004 — every mandant needs at least its own depth-0
    # self-row in mandant_ancestry (so e.g. list_switchable_mandants()
    # finds it), and a freshly-created child needs its new ancestor chain
    # too. Recomputed from scratch rather than incrementally inserted —
    # see recompute_mandant_ancestry()'s own docstring for why.
    await recompute_mandant_ancestry(db)
    await db.commit()
    await db.refresh(mandant)
    return Envelope(data=MandantOut.from_mandant(mandant))


@router.put("/mandants/{mandant_id}", response_model=Envelope[MandantOut])
async def update_mandant(
    mandant_id: uuid.UUID,
    payload: MandantUpdate,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    _: Annotated[AuthContext, Depends(require_holding_admin)],
) -> Envelope[MandantOut]:
    mandant = await db.get(Mandant, mandant_id)
    if mandant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Mandant not found.")
    if payload.name is not None:
        mandant.name = payload.name
    if payload.logo_url is not None:
        mandant.logo_url = payload.logo_url
    if payload.is_active is not None:
        mandant.is_active = payload.is_active
    if payload.mandate_type is not None:
        if payload.mandate_type not in _VALID_MANDATE_TYPES:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=f"mandate_type must be one of {sorted(_VALID_MANDATE_TYPES)}.",
            )
        mandant.mandate_type = payload.mandate_type
    reparented = "parent_id" in payload.model_fields_set
    if reparented:
        if payload.parent_id is not None:
            await _validate_parent(db, payload.parent_id)
            if await _would_create_cycle(db, mandant_id, payload.parent_id):
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    detail="That parent assignment would create a cycle in the mandate hierarchy.",
                )
        mandant.parent_id = payload.parent_id
    if "jurisdiction" in payload.model_fields_set:
        mandant.jurisdiction = payload.jurisdiction
    if "risk_tier" in payload.model_fields_set:
        mandant.risk_tier = payload.risk_tier
    if "data_residency" in payload.model_fields_set:
        mandant.data_residency = payload.data_residency
    if payload.inherit_parent_policies is not None:
        mandant.inherit_parent_policies = payload.inherit_parent_policies
    if payload.auth_mode is not None:
        if payload.auth_mode not in _VALID_AUTH_MODES:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=f"auth_mode must be one of {sorted(_VALID_AUTH_MODES)}.",
            )
        # ADR-005 — settings is otherwise-unused JSONB (Mandant's
        # docstring); update it in place rather than replacing it
        # wholesale, in case a future field joins auth_mode in there.
        mandant.settings = {**(mandant.settings or {}), "auth_mode": payload.auth_mode}
    if reparented:
        # Phase 6b / ADR-004 — the closure table must reflect the new
        # parent_id before this transaction commits, or a concurrent
        # request's RLS check against mandant_ancestry would briefly see
        # the old tree shape. Flush (not commit) first so this query sees
        # the pending parent_id change.
        await db.flush()
        await recompute_mandant_ancestry(db)
    await db.commit()
    await db.refresh(mandant)
    return Envelope(data=MandantOut.from_mandant(mandant))


@router.get("/mandants/{mandant_id}/rollup", response_model=Envelope[MandantRollupOut])
async def get_mandant_rollup(
    mandant_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    _: Annotated[AuthContext, Depends(require_holding_admin)],
) -> Envelope[MandantRollupOut]:
    """Aggregated run/score counts for *mandant_id* plus every descendant
    mandate (Phase 6a). See MandantRollupOut's docstring for why this needs
    no RLS-shaped reasoning at all.

    Phase 6b / ADR-004 — now reads the `mandant_ancestry` closure table
    instead of walking `parent_id` with a recursive CTE on every call,
    exactly the optimization the ADR's own "Positive consequences" section
    flagged as available once that table exists: an indexed join, not a
    tree walk, per request.
    """
    if await db.get(Mandant, mandant_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Mandant not found.")
    result = await db.execute(
        text(
            "SELECT (SELECT COUNT(*) FROM mandant_ancestry WHERE ancestor_id = :root) AS mandate_count, "
            "       COUNT(r.id) AS run_count, "
            "       AVG(r.score) AS avg_score "
            "FROM mandant_ancestry a LEFT JOIN runs r ON r.mandant_id = a.descendant_id "
            "WHERE a.ancestor_id = :root"
        ),
        {"root": mandant_id},
    )
    row = result.one()
    return Envelope(
        data=MandantRollupOut(
            mandant_id=mandant_id,
            mandate_count=row.mandate_count,
            run_count=row.run_count,
            avg_score=float(row.avg_score) if row.avg_score is not None else None,
        )
    )
