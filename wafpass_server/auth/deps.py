"""FastAPI dependency functions for authentication and role enforcement."""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import PyJWTError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.jwt_utils import decode_access_token
from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import ApiKey, InstanceSetting, Mandant, ProjectGroup, User, UserGroup


@dataclass
class IngestAuth:
    """Carries the authenticated principal for ingest endpoints.

    Exactly one of ``user`` or ``api_key_id`` is set. ``mandant_id``
    (Phase 4) is resolved for all three paths — JWT user, DB-stored API
    key, or the legacy env-var key (``None`` unless explicitly mapped via
    ``WAFPASS_LEGACY_API_KEY_MANDANT_SLUG``) — and the session this
    request's ``db`` uses has already had it adopted (``adopt_mandate_of``)
    by the time this is returned, so callers (``_persist_run``,
    ``trigger_scan``) only need to read ``auth.mandant_id`` to tag what
    they write; they don't need to touch RLS context themselves.
    """
    user: User | None = None
    api_key_id: uuid.UUID | None = None
    mandant_id: uuid.UUID | None = None


@dataclass
class AuthContext:
    """The resolved tenancy context for one request.

    - Single-tenant mode: ``mandant_id`` is always ``None`` and every
      holding/group flag is ``False`` — this is the "no behaviour change"
      guarantee from Phase 0/1.
    - Multi-mandant mode: ``mandant_id`` is the user's own mandate (may
      still be ``None`` for a holding-only account — never ``None`` for
      ``group_admin``/``group_viewer``, whose own mandate *is* their
      administered subtree's root), and the holding/group flags mirror
      ``user.holding_role``.

    ``is_group_admin``/``is_group_viewer`` are Phase 6b / ADR-004: unlike
    ``is_holding_admin``/``is_holding_viewer`` (bypass every mandate in the
    holding), a group role's bypass is scoped to ``mandant_id`` plus its
    descendants in ``mandant_ancestry`` — see
    db_migrations/activate_multi_mandant_ddl.py's ``_GROUP_USING_BRANCH``/
    ``_GROUP_CHECK_BRANCH`` for the actual policy clause.

    See wafpass_server.database.get_scoped_db, which sets the matching RLS
    session variables from exactly these fields, and
    db_migrations/activate_multi_mandant_ddl.py, which defines the policies
    that read them.
    """
    user: User
    mandant_id: uuid.UUID | None
    is_holding_admin: bool
    is_holding_viewer: bool
    is_group_admin: bool
    is_group_viewer: bool


# Role ordering — lower index = fewer permissions.  "admin" is the highest level.
ROLE_HIERARCHY: list[str] = ["clevel", "ciso", "architect", "engineer", "admin"]

_bearer = HTTPBearer(auto_error=False)


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


async def _set_current_user_id(db: AsyncSession, user_id: uuid.UUID) -> None:
    """Let RLS find exactly this user's own row before any mandant context
    is known — the auth-bootstrap problem (see
    db_migrations/activate_multi_mandant_ddl.py for the full explanation).
    Harmless no-op while instance_mode == "single_tenant": RLS isn't
    enabled on `users` until Phase 2 activation runs.
    """
    await db.execute(text("SELECT set_config('app.current_user_id', :v, true)"), {"v": str(user_id)})


async def load_user_by_id(db: AsyncSession, user_id: uuid.UUID) -> User | None:
    await _set_current_user_id(db, user_id)
    return await db.get(User, user_id)


async def set_login_username(db: AsyncSession, username: str) -> None:
    """Auth-bootstrap carve-out for POST /auth/login: at this point we know
    only the submitted username, not any id or mandate — this is a third
    distinct bootstrap case alongside the id-based one above (JWT) and the
    public-token one (public endpoints). See
    db_migrations/activate_multi_mandant_ddl.py.
    """
    await db.execute(text("SELECT set_config('app.login_username', :v, true)"), {"v": username})


async def adopt_mandate_of(
    db: AsyncSession,
    mandant_id: uuid.UUID | None,
    *,
    is_holding_admin: bool = False,
    is_holding_viewer: bool = False,
) -> None:
    """After finding an anchor row via one of the bootstrap carve-outs
    above (by id, by username, or — in a public router — by a secret
    token), scope every *other* write or cross-table read made for the
    rest of this request to that row's own mandate.

    ``is_holding_admin``/``is_holding_viewer`` default to False — every
    call site except login()/refresh_token()/logout() adopts the mandate
    of a non-user anchor row (an API key, a widget, an evidence package)
    that has no holding-role concept at all, so False is simply correct
    there. Those three callers *do* authenticate an actual user, and must
    pass the user's real holding flags: a holding-only account (no
    personal mandant_id) has no other branch of a tenant table's own
    WITH CHECK that can pass for a write to its *own* row (e.g. this
    login's ``last_login_at`` update, or the login/logout/replay audit
    insert) — found as a real crash (InsufficientPrivilegeError) the
    first time a holding-only holding_admin ever logged in, since mandate
    alone (current_mandant_id = '', row's own mandant_id = NULL) never
    satisfies ``mandant_id::text = current_setting(...)`` for either side.

    Wraps this session's own ``commit``/``rollback`` to reapply the GUCs
    afterward (same technique and same reason as ``get_scoped_db()``
    below): ``SET LOCAL`` is transaction-scoped, so a commit clears it,
    and the ingest path (``_persist_run()``) commits multiple times and
    keeps using the same session afterward (``db.refresh()``) — found via
    a real "Could not refresh instance" failure the first time a run was
    actually ingested through a mandate-scoped JWT after activation,
    despite this function's own docstring already saying "call this again
    after any intermediate commit"; nothing did. Fixed at the root instead
    of trusting every call site to remember, exactly as ``get_scoped_db()``
    was. Uses its own guard attribute (not ``get_scoped_db()``'s) since
    the two never wrap the same session in practice.
    """
    mandate_value = str(mandant_id) if mandant_id else ""
    db._wafpass_adopted_mandate_id = mandate_value  # type: ignore[attr-defined]
    db._wafpass_adopted_is_holding_admin = "true" if is_holding_admin else "false"  # type: ignore[attr-defined]
    db._wafpass_adopted_is_holding_viewer = "true" if is_holding_viewer else "false"  # type: ignore[attr-defined]

    async def _reapply() -> None:
        await db.execute(
            text(
                "SELECT set_config('app.current_mandant_id', :v, true), "
                "set_config('app.is_holding_admin', :ha, true), "
                "set_config('app.is_holding_viewer', :hv, true)"
            ),
            {
                "v": getattr(db, "_wafpass_adopted_mandate_id", ""),
                "ha": getattr(db, "_wafpass_adopted_is_holding_admin", "false"),
                "hv": getattr(db, "_wafpass_adopted_is_holding_viewer", "false"),
            },
        )

    if not getattr(db, "_wafpass_adopt_wrapped", False):
        original_commit = db.commit
        original_rollback = db.rollback

        async def _commit_and_reapply() -> None:
            await original_commit()
            await _reapply()

        async def _rollback_and_reapply() -> None:
            await original_rollback()
            await _reapply()

        db.commit = _commit_and_reapply  # type: ignore[method-assign]
        db.rollback = _rollback_and_reapply  # type: ignore[method-assign]
        db._wafpass_adopt_wrapped = True  # type: ignore[attr-defined]

    await _reapply()


async def get_instance_mode(db: AsyncSession) -> str:
    """Return the instance's current tenancy mode, defaulting to
    "single_tenant" if the row is somehow missing (e.g. an old DB that
    predates Phase 0's seed row)."""
    result = await db.execute(
        select(InstanceSetting.value).where(InstanceSetting.key == "instance_mode")
    )
    return result.scalar_one_or_none() or "single_tenant"


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Validate a Bearer JWT and return the matching active User."""
    if credentials is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(credentials.credentials)
        if payload.get("type") != "access":
            raise ValueError("not an access token")
    except (PyJWTError, ValueError):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await load_user_by_id(db, uuid.UUID(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive.")
    return user


async def _resolve_mandant_context_override(
    db: AsyncSession,
    own_mandant_id: uuid.UUID | None,
    is_holding_admin: bool,
    is_holding_viewer: bool,
    is_group_admin: bool,
    is_group_viewer: bool,
    mandant_context: str | None,
) -> uuid.UUID | None:
    """Validate an X-Mandant-Context header against one holding-wide or
    group-scoped principal, returning the mandate id to switch into, or
    None if the header is absent/blank or the caller has no bypass to
    narrow in the first place (nothing to switch away from, so silently
    ignored rather than rejected). Shared between get_auth_context()
    (ordinary JWT-authenticated routes) and require_ingest()'s JWT branch
    (POST /runs, POST /scan) so the switcher behaves consistently across
    both — found while testing that a run pushed while "switched into" a
    mandate wasn't actually tagged with it, since require_ingest() never
    calls get_auth_context() at all (its JWT branch resolves the user and
    mandate itself).

    Phase 6b / ADR-004: a holding_admin/holding_viewer may switch into any
    active mandate in the holding, exactly as before. A group_admin/
    group_viewer may only switch into a mandate within the subtree they
    administer (their own mandate — ``own_mandant_id`` — plus its
    descendants in ``mandant_ancestry``) — switching outside it would
    otherwise let them read/write a sibling subtree's data by simply
    asking for it, defeating the whole point of scoping their bypass.
    """
    if not mandant_context or not (is_holding_admin or is_holding_viewer or is_group_admin or is_group_viewer):
        return None
    try:
        context_id = uuid.UUID(mandant_context)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="X-Mandant-Context must be a valid mandant id.")
    context_mandant = await db.get(Mandant, context_id)
    if context_mandant is None or not context_mandant.is_active:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Unknown or inactive mandant in X-Mandant-Context.")
    if is_group_admin or is_group_viewer:
        if own_mandant_id is None:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail="Your account has no mandate to administer a subtree from."
            )
        member = await db.execute(
            text("SELECT 1 FROM mandant_ancestry WHERE ancestor_id = :a AND descendant_id = :d"),
            {"a": own_mandant_id, "d": context_id},
        )
        if member.first() is None:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail="X-Mandant-Context is outside the mandate subtree you administer.",
            )
    return context_id


async def get_auth_context(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    mandant_context: str | None = Header(default=None, alias="X-Mandant-Context"),
) -> AuthContext:
    """Resolve the tenancy context for the current user.

    In single-tenant mode this is always a no-op context. In multi-mandant
    mode, a user with neither a mandant_id nor a holding_role is a
    misconfigured account (e.g. created before activation finished) and is
    rejected rather than silently given global or no access.

    Phase 6a — Global Context Switcher: a holding_admin/holding_viewer can
    send X-Mandant-Context to view/act as one specific mandate instead of
    their default full cross-mandate bypass, for this one request. This
    doesn't *grant* new access (they could already read everything, via
    is_holding_admin/is_holding_viewer's unconditional OR-branch) — it
    *narrows* it: the bypass is dropped for the duration of the request and
    mandant_id is set to the requested mandate, so RLS scopes exactly like
    an ordinary admin of that mandate would see, and any resource tagged
    during the request (e.g. a created API key) is tagged with that
    mandate, not left mandate-less. Ignored for a non-holding user (they
    have nothing to switch away from) and ignored entirely in single-tenant
    mode (returned above, before this is ever read).

    Phase 6b / ADR-004 — group_admin/group_viewer: same shape as
    holding_admin/holding_viewer, but the bypass only covers ``mandant_id``
    (the user's own mandate) plus its descendants in ``mandant_ancestry``,
    not every mandate in the holding. A group role is *not* exempted from
    the "no mandant assigned" check below — their own mandate is the root
    of the subtree they administer, so unlike a holding-only account there
    is no meaningful group_admin/group_viewer without one.
    """
    mode = await get_instance_mode(db)
    if mode != "multi_mandant":
        return AuthContext(
            user=user, mandant_id=None,
            is_holding_admin=False, is_holding_viewer=False,
            is_group_admin=False, is_group_viewer=False,
        )

    is_holding_admin = user.holding_role == "holding_admin"
    is_holding_viewer = user.holding_role == "holding_viewer"
    is_group_admin = user.holding_role == "group_admin"
    is_group_viewer = user.holding_role == "group_viewer"

    if user.mandant_id is None and not (is_holding_admin or is_holding_viewer):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="Your account has no mandant assigned. Contact your administrator.",
        )
    if user.mandant_id is not None:
        mandant = await db.get(Mandant, user.mandant_id)
        if mandant is None or not mandant.is_active:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail="Your assigned mandant is missing or inactive.",
            )

    context_id = await _resolve_mandant_context_override(
        db, user.mandant_id, is_holding_admin, is_holding_viewer, is_group_admin, is_group_viewer, mandant_context
    )
    effective_mandant_id = context_id if context_id is not None else user.mandant_id
    effective_is_holding_admin = is_holding_admin and context_id is None
    effective_is_holding_viewer = is_holding_viewer and context_id is None
    effective_is_group_admin = is_group_admin and context_id is None
    effective_is_group_viewer = is_group_viewer and context_id is None

    return AuthContext(
        user=user,
        mandant_id=effective_mandant_id,
        is_holding_admin=effective_is_holding_admin,
        is_holding_viewer=effective_is_holding_viewer,
        is_group_admin=effective_is_group_admin,
        is_group_viewer=effective_is_group_viewer,
    )


async def get_scoped_db(
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
) -> AsyncSession:
    """The RLS-aware replacement for ``Depends(get_db)`` in every
    JWT-authenticated route. Sets the three session variables every tenant
    table's policy reads, via ``SET LOCAL`` (through ``set_config(..., true)``
    so it's one round trip instead of three), from the already-resolved
    ``AuthContext`` — never from anything the caller supplies directly.

    Deliberately does *not* cast ``mandant_id`` to ``::uuid`` here or in any
    policy — compared as text instead, so a holding-only user (no personal
    mandant) safely sets an empty string with no cast-error risk. See
    db_migrations/activate_multi_mandant_ddl.py for the full rationale.

    This is the only place these three variables are ever set from resolved
    identity; nothing else in the request path should set them directly.

    ``SET LOCAL`` does not survive a commit — it's transaction-scoped, and
    ``db.commit()`` ends the transaction. Several handlers legitimately
    commit and then keep using the same session (``db.refresh()``, a
    follow-up query) within the same request; found the hard way, via a
    real holding_admin reassigning a user's mandate and then failing to
    refresh it back, with "Could not refresh instance" — RLS was silently
    denying the post-commit SELECT because its session context had reset to
    nothing. Rather than require every call site to remember to re-apply
    context after its own commit (easy to forget, as this bug shows), this
    session's own ``commit``/``rollback`` are wrapped here to reapply it
    automatically — every existing ``await db.commit()`` call site keeps
    working with no changes needed.
    """
    async def _apply_rls_context() -> None:
        await db.execute(
            text(
                "SELECT set_config('app.current_mandant_id', :mandant_id, true), "
                "set_config('app.is_holding_admin', :is_holding_admin, true), "
                "set_config('app.is_holding_viewer', :is_holding_viewer, true), "
                "set_config('app.is_group_admin', :is_group_admin, true), "
                "set_config('app.is_group_viewer', :is_group_viewer, true)"
            ),
            {
                "mandant_id": str(auth.mandant_id) if auth.mandant_id else "",
                "is_holding_admin": "true" if auth.is_holding_admin else "false",
                "is_holding_viewer": "true" if auth.is_holding_viewer else "false",
                "is_group_admin": "true" if auth.is_group_admin else "false",
                "is_group_viewer": "true" if auth.is_group_viewer else "false",
            },
        )

    if not getattr(db, "_wafpass_rls_wrapped", False):
        original_commit = db.commit
        original_rollback = db.rollback

        async def _commit_and_reapply() -> None:
            await original_commit()
            await _apply_rls_context()

        async def _rollback_and_reapply() -> None:
            await original_rollback()
            await _apply_rls_context()

        db.commit = _commit_and_reapply  # type: ignore[method-assign]
        db.rollback = _rollback_and_reapply  # type: ignore[method-assign]
        db._wafpass_rls_wrapped = True  # type: ignore[attr-defined]

    await _apply_rls_context()
    return db


def require_role(minimum: str = "clevel"):
    """Return a FastAPI dependency that requires *minimum* role or higher in the hierarchy."""
    async def _dep(user: User = Depends(get_current_user)) -> User:
        try:
            if ROLE_HIERARCHY.index(user.role) < ROLE_HIERARCHY.index(minimum):
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{minimum}' or higher required. You have '{user.role}'.",
                )
        except ValueError:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Unknown role configuration.")
        return user
    return _dep


async def _resolve_legacy_api_key_mandant(db: AsyncSession) -> uuid.UUID | None:
    """The env-var pre-shared key has no DB row and therefore no natural
    mandate. In single-tenant mode that's a non-issue. In multi-mandant
    mode, fail closed unless an operator has explicitly opted in via
    WAFPASS_LEGACY_API_KEY_MANDANT_SLUG — same fail-closed philosophy as
    everywhere else in this plan (a missing SSO claim, a holding-only
    admin with no mandate to tag a new key with, etc.).
    """
    mode = await get_instance_mode(db)
    if mode != "multi_mandant":
        return None
    slug = settings.wafpass_legacy_api_key_mandant_slug
    if not slug:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=(
                "The legacy WAFPASS_API_KEY is disabled in multi-mandant mode. Use a "
                "DB-stored per-mandate API key, or set WAFPASS_LEGACY_API_KEY_MANDANT_SLUG "
                "to explicitly map it to one mandate."
            ),
        )
    result = await db.execute(select(Mandant).where(Mandant.slug == slug))
    mandant = result.scalar_one_or_none()
    if mandant is None or not mandant.is_active:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"WAFPASS_LEGACY_API_KEY_MANDANT_SLUG '{slug}' does not match an active mandant.",
        )
    return mandant.id


async def require_ingest(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    db: AsyncSession = Depends(get_db),
    mandant_context: str | None = Header(default=None, alias="X-Mandant-Context"),
) -> IngestAuth:
    """Accept a valid Bearer JWT (any role) OR an API key (env-var or DB-stored).

    Used by POST /runs and POST /scan so that CI/CD pipelines can push
    scan results without requiring a user account.

    The JWT branch honors X-Mandant-Context the same way get_auth_context()
    does (Phase 6a's Global Context Switcher), so a run pushed while a
    holding_admin/holding_viewer is "switched into" a mandate in the
    dashboard is tagged with that mandate, not left to their own (possibly
    nonexistent) personal one. The API-key branches ignore it — a key's
    mandate is a property of the key itself, not of whoever's browser
    session happens to be making the request.

    Returns an IngestAuth with either ``user`` set (JWT path) or
    ``api_key_id`` set (API key path), and ``mandant_id`` resolved for
    whichever path matched — see IngestAuth's docstring. In every branch
    below, the mandate is adopted into *this* session (``adopt_mandate_of``)
    before returning, since `db` here is the plain ``get_db()`` session —
    not ``get_scoped_db()``, which would hard-require a JWT and defeat the
    whole point of API-key-only ingest — so nothing else will ever set its
    RLS context otherwise.
    """
    # ── API key path (env-var pre-shared key, backward compat) ───────────────
    if x_api_key and settings.wafpass_api_key and x_api_key == settings.wafpass_api_key:
        mandant_id = await _resolve_legacy_api_key_mandant(db)
        await adopt_mandate_of(db, mandant_id)
        return IngestAuth(api_key_id=None, mandant_id=mandant_id)  # legacy key has no DB row

    # ── API key path (DB-stored per-service keys) ─────────────────────────────
    if x_api_key:
        key_hash = _hash(x_api_key)
        # Auth-bootstrap pattern (see load_user_by_id): the key's own
        # mandate isn't known until it's found, so let RLS find exactly
        # this one row by its hash regardless of mandate.
        await db.execute(text("SELECT set_config('app.current_api_key_hash', :v, true)"), {"v": key_hash})
        result = await db.execute(
            select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.is_active.is_(True))
        )
        api_key_row = result.scalar_one_or_none()
        if api_key_row is not None:
            # Adopt the mandate *before* touching last_used_at, not after:
            # the self-lookup carve-out above (key_hash = ...) only ever
            # appears in the policy's USING clause, never WITH CHECK (see
            # _policy_sql) — deliberately, since letting an anonymous
            # caller write a row just by presenting a hash it already
            # holds is a different, much weaker guarantee than letting it
            # write only *after* its own mandate has been established.
            # Updating last_used_at before adopting the mandate meant
            # WITH CHECK had no mandate match to allow it at all, and no
            # holding flag either — confirmed via a real
            # InsufficientPrivilegeError the first time an ingest API key
            # was actually used after activation.
            await adopt_mandate_of(db, api_key_row.mandant_id)
            api_key_row.last_used_at = datetime.now(timezone.utc)
            await db.commit()
            return IngestAuth(api_key_id=api_key_row.id, mandant_id=api_key_row.mandant_id)

    # ── JWT path ──────────────────────────────────────────────────────────────
    if credentials is not None:
        try:
            payload = decode_access_token(credentials.credentials)
            if payload.get("type") != "access":
                raise ValueError
        except (PyJWTError, ValueError):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token.")

        user = await load_user_by_id(db, uuid.UUID(payload["sub"]))
        if user and user.is_active:
            is_holding_admin = user.holding_role == "holding_admin"
            is_holding_viewer = user.holding_role == "holding_viewer"
            is_group_admin = user.holding_role == "group_admin"
            is_group_viewer = user.holding_role == "group_viewer"
            context_id = await _resolve_mandant_context_override(
                db, user.mandant_id, is_holding_admin, is_holding_viewer, is_group_admin, is_group_viewer,
                mandant_context,
            )
            effective_mandant_id = context_id if context_id is not None else user.mandant_id
            # A holding-only holding_admin/holding_viewer (no personal
            # mandant_id) with no X-Mandant-Context has nothing to tag this
            # ingest with — runs.mandant_id is NOT NULL once activated
            # (unlike users/user_audit_logs/validations, which are
            # deliberately exempted), so this would otherwise reach
            # _persist_run() and crash with a raw NotNullViolationError
            # instead of a clean error. Checked only in multi_mandant mode:
            # in single_tenant mode every user's mandant_id is legitimately
            # None by design (Phase 0/1's "no behaviour change" guarantee),
            # and runs.mandant_id has no NOT NULL constraint at all yet.
            # Mirrors the identical guard already used by admin.py's
            # create_user()/create_api_key() for the same underlying gap.
            if effective_mandant_id is None and await get_instance_mode(db) == "multi_mandant":
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "Your account has no mandant assigned. Send X-Mandant-Context "
                        "to say which mandate this run belongs to."
                    ),
                )
            await adopt_mandate_of(db, effective_mandant_id)
            return IngestAuth(user=user, mandant_id=effective_mandant_id)

    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        detail="Provide a Bearer token or X-Api-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def bypasses_group_scoping(user: User, auth: AuthContext) -> bool:
    """True when ``user`` already has elevated, RLS-level visibility that
    UserGroup/ProjectGroup's finer-grained, purely application-level filter
    must not claw back.

    UserGroup/ProjectGroup pre-dates multi-mandancy and is layered *within*
    whatever mandate scope RLS already resolved for this request — it was
    never meant to re-restrict a principal RLS already decided should see
    everything. Before this helper existed, every caller checked only
    ``user.role == "admin"``, so a holding_admin/holding_viewer/group_admin/
    group_viewer whose own base ``role`` wasn't literally "admin" (a
    perfectly normal combination — ``holding_role`` and ``role`` are
    independent fields, see ``update_user``) got wrongly empty-filtered to
    zero runs/projects despite their RLS bypass already granting full
    visibility. Uses the request's *effective* (possibly X-Mandant-Context-
    narrowed) flags, not the user's permanent holding_role, so narrowing
    into one mandate makes this behave exactly like an ordinary admin of
    that one mandate would — consistent with every other RLS-adjacent
    check in this module.
    """
    return (
        user.role == "admin"
        or auth.is_holding_admin
        or auth.is_holding_viewer
        or auth.is_group_admin
        or auth.is_group_viewer
    )


async def require_group_access(
    project: str,
    db: AsyncSession,
    user: User,
    auth: AuthContext,
) -> None:
    """Check if user has access to a project via group membership.

    Users can access a project if:
    1. ``bypasses_group_scoping(user, auth)`` is True, OR
    2. They belong to any group that is mapped to the project

    Raises HTTPException if access is denied.
    """
    if bypasses_group_scoping(user, auth):
        return

    # Get all groups the user belongs to
    result = await db.execute(
        select(UserGroup.group_name).where(UserGroup.user_id == user.id)
    )
    user_groups = set(result.scalars().all())

    # Get all groups that have access to this project
    result = await db.execute(
        select(ProjectGroup.group_name).where(ProjectGroup.project == project)
    )
    project_groups = set(result.scalars().all())

    # Check for intersection
    if user_groups & project_groups:
        return

    # No matching group found
    raise HTTPException(
        status.HTTP_403_FORBIDDEN,
        detail=f"You do not have access to project '{project}'. "
               f"Required group membership: {list(project_groups)}. "
               f"Your groups: {list(user_groups)}.",
    )
