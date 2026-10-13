"""SSO configuration management and login flows (OIDC + SAML2)."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import func, or_, select, text, distinct
from sqlalchemy.ext.asyncio import AsyncSession

import jwt as _jwt

from wafpass_server.auth.deps import (
    AuthContext,
    adopt_mandate_of,
    get_auth_context,
    get_instance_mode,
    get_scoped_db,
    require_role,
    set_login_username,
)
from wafpass_server.auth.jwt_utils import create_access_token
from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import (
    GroupRoleMapping,
    Mandant,
    ProjectGroup,
    RefreshToken,
    SsoConfig,
    User,
    UserAuditLog,
    UserGroup,
)
from wafpass_server.secret_enc import decrypt_field, encrypt_field, is_encrypted_blob

router = APIRouter(tags=["sso"])

# ── Sensitive field registry ──────────────────────────────────────────────────

# Fields encrypted at rest before writing to sso_configs.config.
_SENSITIVE: dict[str, list[str]] = {
    "oidc":  ["client_secret"],
    "saml2": ["sp_private_key"],
}


def _secret_scope(mandant_id: uuid.UUID | None) -> str:
    """Namespace segment for this config row's secrets in the external
    secret backend (ADR-005) — "default" for the instance-wide config,
    the mandant's own id for a per-mandant override, so two mandates'
    ``client_secret``/``sp_private_key`` for the same provider never
    collide under one ``aws_secret_name``.
    """
    return str(mandant_id) if mandant_id else "default"


async def _encrypt_config(
    provider: str, new_config: dict, existing_config: dict | None, mandant_id: uuid.UUID | None = None,
) -> dict:
    """Return a copy of *new_config* with sensitive fields encrypted.

    * Plaintext values are encrypted using the configured backend.
    * ``"***"`` means the admin left the field unchanged — the existing
      encrypted blob is preserved.
    * Already-encrypted blobs are kept as-is (idempotent).
    * Empty/missing values are removed from the stored config.
    """
    result = dict(new_config)
    for field in _SENSITIVE.get(provider, []):
        val = result.get(field, "")
        if not val or val == "***":
            if existing_config and existing_config.get(field):
                result[field] = existing_config[field]   # keep existing blob
            else:
                result.pop(field, None)
        elif is_encrypted_blob(val):
            pass  # already encrypted — leave unchanged
        else:
            result[field] = await encrypt_field(
                val,
                aws_secret_name=f"wafpass/sso/{provider}/{_secret_scope(mandant_id)}/{field}",
            )
    return result


async def _decrypt_config(provider: str, config: dict) -> dict:
    """Return a copy of *config* with sensitive fields decrypted for runtime use."""
    result = dict(config)
    for field in _SENSITIVE.get(provider, []):
        if result.get(field):
            result[field] = await decrypt_field(result[field])
    return result


def _redact_config(provider: str, config: dict) -> dict:
    """Return a copy of *config* with sensitive fields replaced by ``"***"``."""
    result = dict(config)
    for field in _SENSITIVE.get(provider, []):
        if result.get(field):
            result[field] = "***"
    return result


# ── Optional SAML2 import ─────────────────────────────────────────────────────

try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    SAML_AVAILABLE = True
except ImportError:
    SAML_AVAILABLE = False

# ── Helpers ───────────────────────────────────────────────────────────────────

def _ip(request: Request) -> str:
    return request.headers.get("x-forwarded-for", request.client.host if request.client else "")


async def _audit(
    db: AsyncSession, actor_id: uuid.UUID | None, action: str, detail: dict, ip: str = "",
    mandant_id: uuid.UUID | None = None,
) -> None:
    db.add(UserAuditLog(actor_id=actor_id, action=action, detail=detail, ip=ip, mandant_id=mandant_id))


def _cfg_row_id(provider: str, mandant_id: uuid.UUID | None) -> str:
    """The ``sso_configs.id`` for this (provider, scope) pair (ADR-005).

    The instance-wide default keeps its pre-ADR-005 id — ``provider``
    itself — so every row that existed before this ADR is addressed
    exactly as it always was. A per-mandant override gets a synthetic id
    that can never collide with a default row's id.
    """
    return provider if mandant_id is None else f"{provider}:{mandant_id}"


async def _get_cfg_exact(db: AsyncSession, provider: str, mandant_id: uuid.UUID | None) -> SsoConfig | None:
    """Fetch exactly the row for this (provider, scope) pair — no fallback.

    Used once a login flow already knows which row it started with (from
    the signed OIDC state / SAML RelayState) and must keep using that
    same row, not silently fall back to the default if it's gone missing
    between the authorize/login step and the callback.
    """
    result = await db.execute(
        select(SsoConfig).where(SsoConfig.id == _cfg_row_id(provider, mandant_id))
    )
    return result.scalar_one_or_none()


async def _get_cfg(db: AsyncSession, provider: str, mandant_id: uuid.UUID | None = None) -> SsoConfig | None:
    """Resolve the effective config for *provider*, preferring a
    per-mandant override over the instance-wide default (ADR-005).

    ``mandant_id=None`` (the pre-ADR-005 call shape, still used by every
    caller that has no mandate context — e.g. a single-tenant instance)
    resolves straight to the default row, unchanged.
    """
    if mandant_id is not None:
        override = await _get_cfg_exact(db, provider, mandant_id)
        if override is not None:
            return override
    return await _get_cfg_exact(db, provider, None)


async def _resolve_mandant_by_slug(db: AsyncSession, slug: str) -> Mandant:
    """Resolve a public-facing mandant slug to its row, failing closed on
    an unknown or inactive mandate — same convention as
    ``_provision_user()``'s existing claim-mapping lookup.
    """
    result = await db.execute(select(Mandant).where(Mandant.slug == slug))
    mandant = result.scalar_one_or_none()
    if mandant is None or not mandant.is_active:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Unknown or inactive mandant '{slug}'.")
    return mandant


def _auth_mode_of(mandant: Mandant) -> str:
    """``mandants.settings.auth_mode`` (ADR-005) — app-validated, not a DB
    CHECK constraint, same convention as ``mandate_type``/``instance_mode``
    elsewhere in this schema. Defaults to ``"inherit"``: no change from
    pre-ADR-005 behaviour for any mandate that hasn't set it.
    """
    return (mandant.settings or {}).get("auth_mode", "inherit")


async def _adopt_public_sso_context(db: AsyncSession, mandant_id: uuid.UUID | None = None) -> None:
    """Set the RLS session variables public SSO endpoints need.

    ``app.allow_default_sso`` allows unauthenticated callers to read the
    instance-wide default ``sso_configs`` rows (mandant_id IS NULL).  When
    a mandate is requested, ``app.current_mandant_id`` is also set so a
    per-mandant override is visible to the same query.
    """
    await adopt_mandate_of(db, mandant_id)
    await db.execute(
        text("SELECT set_config('app.allow_default_sso', :v, true)"), {"v": "true"}
    )


async def _resolve_role_from_groups(
    db: AsyncSession,
    provider: str,
    group_values: list[str],
) -> str | None:
    """Return the highest-priority mapped role for any of the given group values, or None."""
    if not group_values:
        return None
    result = await db.execute(
        select(GroupRoleMapping)
        .where(
            or_(GroupRoleMapping.provider == provider, GroupRoleMapping.provider == "*"),
            GroupRoleMapping.group_name.in_(group_values),
        )
        .order_by(GroupRoleMapping.priority.desc())
        .limit(1)
    )
    row = result.scalar_one_or_none()
    return row.role if row else None


async def _update_user_groups(
    db: AsyncSession,
    user_id: uuid.UUID,
    provider: str,
    group_values: list[str],
) -> None:
    """Update user's group memberships, removing old groups and adding new ones."""
    # Remove existing groups for this user/provider
    result = await db.execute(
        select(UserGroup).where(
            UserGroup.user_id == user_id,
            UserGroup.provider == provider,
        )
    )
    existing_groups = list(result.scalars().all())
    for group in existing_groups:
        await db.delete(group)

    # Add new groups
    for group_name in group_values:
        user_group = UserGroup(
            user_id=user_id,
            group_name=group_name,
            provider=provider,
        )
        db.add(user_group)


async def _issue_tokens(db: AsyncSession, user: User) -> tuple[str, str]:
    access_token = create_access_token(user.id, user.username, user.role)
    raw_refresh = secrets.token_urlsafe(48)
    rt = RefreshToken(
        user_id=user.id,
        token_hash=hashlib.sha256(raw_refresh.encode()).hexdigest(),
        family_id=uuid.uuid4(),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.wafpass_jwt_refresh_days),
    )
    db.add(rt)
    user.last_login_at = datetime.now(timezone.utc)
    return access_token, raw_refresh


def _frontend_redirect(frontend_url: str, access_token: str, refresh_token: str, user: User) -> str:
    user_dict = {
        "id": str(user.id),
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "auth_provider": user.auth_provider,
        "is_active": user.is_active,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
    }
    u_b64 = base64.urlsafe_b64encode(json.dumps(user_dict).encode()).decode()
    params = urlencode({"sso_ok": "1", "at": access_token, "rt": refresh_token, "u": u_b64})
    return f"{frontend_url.rstrip('/')}?{params}"


async def _provision_user(
    db: AsyncSession,
    username: str,
    display_name: str,
    auth_provider: str,
    role: str,
    auto_provision: bool,
    mandant_slug: str | None = None,
    forced_mandant_id: uuid.UUID | None = None,
) -> User:
    """Find-or-create the SSO-authenticated user, and resolve their
    mandate — either from the IdP's configured claim/attribute (Phase 4),
    or directly from a per-mandant SSO config (ADR-005).

    The ``select(User).where(User.username == ...)`` lookup below is the
    exact same auth-bootstrap problem as local login (see
    db_migrations/activate_multi_mandant_ddl.py and auth.py's login()) —
    found here only while adding Phase 4's mandant_claim, because sso.py
    wasn't touched in Phase 1 (its config-management endpoints have
    nothing mandate-scoped about them, but this login path does). Without
    `set_login_username()` here, this lookup would return nothing under
    active RLS, and every SSO login would either be wrongly rejected or
    attempt to create a duplicate username and crash on the unique
    constraint instead.

    ADR-005: *forced_mandant_id* is set when the login flow resolved a
    per-mandant SSO config row (not the instance-wide default) — that
    row's own mandate is the trusted mandate, used directly instead of
    decoding *mandant_slug* from a claim at all. This is strictly
    stronger than claim-based resolution: a dedicated per-mandant IdP
    cannot assert a different mandate's slug, by misconfiguration or
    otherwise, because it never gets a chance to assert one in the first
    place. *mandant_slug* keeps its pre-ADR-005 meaning and is only
    consulted when *forced_mandant_id* is None, i.e. the instance-wide
    default config resolved this login.
    """
    await set_login_username(db, username)
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()

    mode = await get_instance_mode(db)
    target_mandant_id: uuid.UUID | None = None
    if forced_mandant_id is not None and mode == "multi_mandant":
        mandant = await db.get(Mandant, forced_mandant_id)
        if mandant is None or not mandant.is_active:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail="This mandate's SSO configuration is no longer valid."
            )
        if _auth_mode_of(mandant) == "local_only":
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail="This mandate is configured for local accounts only."
            )
        target_mandant_id = mandant.id
    elif mode == "multi_mandant" and mandant_slug:
        mandant_result = await db.execute(select(Mandant).where(Mandant.slug == mandant_slug))
        mandant = mandant_result.scalar_one_or_none()
        if mandant is None or not mandant.is_active:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"Unknown or inactive mandant '{mandant_slug}'.")
        if _auth_mode_of(mandant) == "local_only":
            # The shared/default IdP's claim pointed at a mandate that
            # opted out of SSO entirely (ADR-005). The holding-wide IdP
            # must not be able to provision or reassign a user into a
            # local-only mandate just because its token happens to carry
            # that mandate's slug — same fail-closed instinct as every
            # other claim check in this function.
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail=f"Mandant '{mandant_slug}' does not accept SSO logins."
            )
        target_mandant_id = mandant.id

    if user is None:
        if not auto_provision:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="User not found and auto-provisioning is disabled.")
        if mode == "multi_mandant" and target_mandant_id is None:
            # Fail closed: "If the claim is missing while the instance is
            # in multi-mandant mode, login fails closed" (ADR-003).
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="SSO mandant claim is required in multi-mandant mode.")
        # Adopt the target mandate *before* flushing the INSERT, not after:
        # WITH CHECK requires mandant_id::text = current_setting(...) (or
        # a holding flag) for every write, and this session's
        # app.current_mandant_id has never been set yet at this point —
        # only app.login_username has, which (like every self-lookup
        # carve-out) only ever appears in the policy's USING clause, not
        # WITH CHECK. The INSERT below used to run before this function's
        # own adopt_mandate_of() call at the bottom, so the very first
        # multi-mandant SSO login for a brand-new user would always fail
        # with a real RLS InsufficientPrivilegeError — confirmed directly
        # against a real database, not just reasoned about.
        await adopt_mandate_of(db, target_mandant_id)
        user = User(
            username=username,
            display_name=display_name or username,
            role=role,
            auth_provider=auth_provider,
            password_hash=None,
            mandant_id=target_mandant_id,
        )
        db.add(user)
        await db.flush()
    else:
        if not user.is_active:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Account is disabled.")
        if display_name and user.display_name != display_name:
            user.display_name = display_name
        user.auth_provider = auth_provider
        if mode == "multi_mandant":
            if target_mandant_id is None and user.mandant_id is None and user.holding_role is None:
                raise HTTPException(status.HTTP_403_FORBIDDEN, detail="SSO mandant claim is required in multi-mandant mode.")
            if target_mandant_id is not None:
                if user.mandant_id is None:
                    user.mandant_id = target_mandant_id  # first-time assignment from the claim
                elif user.mandant_id != target_mandant_id:
                    # The claim now points at a *different* mandate than the
                    # one this account is already assigned to. Don't let the
                    # IdP silently move someone between tenants — that's a
                    # holding_admin's explicit call (Phase 3.4's UI), not a
                    # side effect of a claim value changing.
                    raise HTTPException(
                        status.HTTP_403_FORBIDDEN,
                        detail="Your IdP mandant claim does not match your assigned mandant. Contact your holding_admin.",
                    )

    # Carry the user's own holding flags, not just their mandate — a
    # holding-only account (mandant_id=None) has no other way to pass a
    # tenant table's WITH CHECK for the sso.login audit insert the caller
    # makes right after this returns. Same underlying gap as auth.py's
    # login()/refresh_token()/logout() — see adopt_mandate_of()'s docstring.
    await adopt_mandate_of(
        db, user.mandant_id,
        is_holding_admin=user.holding_role == "holding_admin",
        is_holding_viewer=user.holding_role == "holding_viewer",
    )
    return user


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class SsoConfigOut(BaseModel):
    id: str
    provider: str
    # ADR-005: None = the instance-wide default; set = a per-mandant override.
    mandant_id: uuid.UUID | None = None
    enabled: bool
    config: dict
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


class SsoConfigUpdate(BaseModel):
    enabled: bool = False
    config: dict = {}


class SsoProviderInfo(BaseModel):
    provider: str
    enabled: bool
    label: str
    # ADR-005: "mandant" when this came from a per-mandant override config,
    # "default" when it fell back to the instance-wide one.
    scope: str = "default"


class GroupRoleMappingOut(BaseModel):
    id: str
    provider: str
    group_name: str
    role: str
    description: str
    priority: int
    created_at: datetime | None = None
    created_by: str | None = None

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_row(cls, row: GroupRoleMapping) -> "GroupRoleMappingOut":
        return cls(
            id=str(row.id),
            provider=row.provider,
            group_name=row.group_name,
            role=row.role,
            description=row.description,
            priority=row.priority,
            created_at=row.created_at,
            created_by=str(row.created_by) if row.created_by else None,
        )


class GroupRoleMappingCreate(BaseModel):
    provider: str = "*"
    group_name: str
    role: str
    description: str = ""
    priority: int = 0


class GroupRoleMappingUpdate(BaseModel):
    provider: str | None = None
    group_name: str | None = None
    role: str | None = None
    description: str | None = None
    priority: int | None = None


# ── Config management (admin only) ────────────────────────────────────────────
#
# ADR-005: the plain /sso/config/* endpoints below manage only the
# instance-wide default (mandant_id IS NULL) — exactly what they always
# managed, made explicit rather than implicit. Per-mandant overrides have
# their own endpoints further down (/sso/config/mandant/...), authorized
# separately: a mandate-scoped admin may only touch their own mandate's
# override, a holding_admin may touch any.

async def _upsert_cfg(
    db: AsyncSession, provider: str, mandant_id: uuid.UUID | None, payload: SsoConfigUpdate, acting_user: User,
) -> SsoConfigOut:
    if provider not in ("oidc", "saml2"):
        raise HTTPException(400, detail="Provider must be 'oidc' or 'saml2'.")
    cfg = await _get_cfg_exact(db, provider, mandant_id)
    encrypted = await _encrypt_config(provider, payload.config, cfg.config if cfg else None, mandant_id)
    if cfg is None:
        cfg = SsoConfig(
            id=_cfg_row_id(provider, mandant_id),
            provider=provider,
            mandant_id=mandant_id,
            enabled=payload.enabled,
            config=encrypted,
            updated_by=acting_user.id,
        )
        db.add(cfg)
    else:
        cfg.enabled = payload.enabled
        cfg.config = encrypted
        cfg.updated_by = acting_user.id
    await db.commit()
    await db.refresh(cfg)
    return SsoConfigOut(
        id=cfg.id,
        provider=cfg.provider,
        mandant_id=cfg.mandant_id,
        enabled=cfg.enabled,
        config=_redact_config(cfg.provider, cfg.config),
        updated_at=cfg.updated_at,
    )


async def _delete_cfg(db: AsyncSession, provider: str, mandant_id: uuid.UUID | None) -> None:
    cfg = await _get_cfg_exact(db, provider, mandant_id)
    if cfg:
        await db.delete(cfg)
        await db.commit()


@router.get("/sso/config", response_model=list[SsoConfigOut])
async def list_sso_configs(
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> list[SsoConfigOut]:
    result = await db.execute(select(SsoConfig).where(SsoConfig.mandant_id.is_(None)))
    return [
        SsoConfigOut(
            id=row.id,
            provider=row.provider,
            mandant_id=row.mandant_id,
            enabled=row.enabled,
            config=_redact_config(row.provider, row.config),
            updated_at=row.updated_at,
        )
        for row in result.scalars().all()
    ]


@router.put("/sso/config/{provider}", response_model=SsoConfigOut)
async def upsert_sso_config(
    provider: str,
    payload: SsoConfigUpdate,
    acting_user: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> SsoConfigOut:
    """Upsert the instance-wide default config for *provider*. See
    /sso/config/mandant/{mandant_id}/{provider} for a per-mandant override.
    """
    return await _upsert_cfg(db, provider, None, payload, acting_user)


@router.delete("/sso/config/{provider}", status_code=204)
async def delete_sso_config(
    provider: str,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> None:
    await _delete_cfg(db, provider, None)


# ── Per-mandant SSO config overrides (ADR-005) ────────────────────────────────

async def _require_sso_scope_for_mandant(
    mandant_id: uuid.UUID,
    _user: Annotated[User, Depends(require_role("admin"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> AuthContext:
    """A holding_admin may manage any mandate's SSO override; a
    mandate-scoped admin may only manage their own mandate's — the same
    "holding_admin, or exactly your own mandate" boundary used elsewhere
    for this identical shape (e.g. auth.py's create_user() payload.mandant_id
    check). In single-tenant mode auth.mandant_id/is_holding_admin are
    always None/False (get_auth_context's own "no behaviour change"
    guarantee), so these endpoints are naturally unreachable until
    multi-mandant mode exists — nothing to special-case.
    """
    if auth.is_holding_admin or auth.mandant_id == mandant_id:
        return auth
    raise HTTPException(
        status.HTTP_403_FORBIDDEN, detail="You can only manage SSO configuration for your own mandate."
    )


@router.get("/sso/config/mandant/{mandant_id}", response_model=list[SsoConfigOut])
async def list_mandant_sso_configs(
    mandant_id: uuid.UUID,
    _: Annotated[AuthContext, Depends(_require_sso_scope_for_mandant)],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> list[SsoConfigOut]:
    result = await db.execute(select(SsoConfig).where(SsoConfig.mandant_id == mandant_id))
    return [
        SsoConfigOut(
            id=row.id,
            provider=row.provider,
            mandant_id=row.mandant_id,
            enabled=row.enabled,
            config=_redact_config(row.provider, row.config),
            updated_at=row.updated_at,
        )
        for row in result.scalars().all()
    ]


@router.put("/sso/config/mandant/{mandant_id}/{provider}", response_model=SsoConfigOut)
async def upsert_mandant_sso_config(
    mandant_id: uuid.UUID,
    provider: str,
    payload: SsoConfigUpdate,
    auth: Annotated[AuthContext, Depends(_require_sso_scope_for_mandant)],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> SsoConfigOut:
    if await db.get(Mandant, mandant_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Mandant not found.")
    return await _upsert_cfg(db, provider, mandant_id, payload, auth.user)


@router.delete("/sso/config/mandant/{mandant_id}/{provider}", status_code=204)
async def delete_mandant_sso_config(
    mandant_id: uuid.UUID,
    provider: str,
    _: Annotated[AuthContext, Depends(_require_sso_scope_for_mandant)],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> None:
    await _delete_cfg(db, provider, mandant_id)


# ── Group → Role mappings (admin only) ───────────────────────────────────────

_VALID_ROLES = {"clevel", "ciso", "architect", "engineer", "admin"}
_VALID_PROVIDERS = {"oidc", "saml2", "*"}


@router.get("/sso/group-mappings", response_model=list[GroupRoleMappingOut])
async def list_group_mappings(
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[GroupRoleMappingOut]:
    result = await db.execute(
        select(GroupRoleMapping).order_by(GroupRoleMapping.priority.desc(), GroupRoleMapping.group_name)
    )
    return [GroupRoleMappingOut.from_orm_row(r) for r in result.scalars().all()]


@router.post("/sso/group-mappings", response_model=GroupRoleMappingOut, status_code=201)
async def create_group_mapping(
    payload: GroupRoleMappingCreate,
    acting_user: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> GroupRoleMappingOut:
    if payload.role not in _VALID_ROLES:
        raise HTTPException(400, detail=f"Invalid role. Must be one of: {', '.join(sorted(_VALID_ROLES))}")
    if payload.provider not in _VALID_PROVIDERS:
        raise HTTPException(400, detail=f"Invalid provider. Must be one of: {', '.join(sorted(_VALID_PROVIDERS))}")
    row = GroupRoleMapping(
        provider=payload.provider,
        group_name=payload.group_name,
        role=payload.role,
        description=payload.description,
        priority=payload.priority,
        created_by=acting_user.id,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return GroupRoleMappingOut.from_orm_row(row)


@router.put("/sso/group-mappings/{mapping_id}", response_model=GroupRoleMappingOut)
async def update_group_mapping(
    mapping_id: str,
    payload: GroupRoleMappingUpdate,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> GroupRoleMappingOut:
    result = await db.execute(select(GroupRoleMapping).where(GroupRoleMapping.id == mapping_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(404, detail="Mapping not found.")
    if payload.role is not None:
        if payload.role not in _VALID_ROLES:
            raise HTTPException(400, detail=f"Invalid role. Must be one of: {', '.join(sorted(_VALID_ROLES))}")
        row.role = payload.role
    if payload.provider is not None:
        if payload.provider not in _VALID_PROVIDERS:
            raise HTTPException(400, detail=f"Invalid provider. Must be one of: {', '.join(sorted(_VALID_PROVIDERS))}")
        row.provider = payload.provider
    if payload.group_name is not None:
        row.group_name = payload.group_name
    if payload.description is not None:
        row.description = payload.description
    if payload.priority is not None:
        row.priority = payload.priority
    await db.commit()
    await db.refresh(row)
    return GroupRoleMappingOut.from_orm_row(row)


@router.delete("/sso/group-mappings/{mapping_id}", status_code=204)
async def delete_group_mapping(
    mapping_id: str,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    result = await db.execute(select(GroupRoleMapping).where(GroupRoleMapping.id == mapping_id))
    row = result.scalar_one_or_none()
    if row:
        await db.delete(row)
        await db.commit()


# ── Project Group API (admin only) ────────────────────────────────────────────


class ProjectGroupOut(BaseModel):
    """Response schema for project groups."""
    id: str
    project: str
    group_name: str
    created_at: datetime | None = None
    created_by: str | None = None

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_row(cls, row: ProjectGroup) -> "ProjectGroupOut":
        return cls(
            id=str(row.id),
            project=row.project,
            group_name=row.group_name,
            created_at=row.created_at,
            created_by=str(row.created_by) if row.created_by else None,
        )


class ProjectGroupCreate(BaseModel):
    """Request body for creating a project group."""
    project: str
    group_name: str


async def _require_mandant_for_group_write(
    db: AsyncSession, auth: AuthContext
) -> None:
    """Project groups are mandate-tagged; in multi-mandant mode a caller
    without an effective mandate (e.g. a holding-only admin that didn't send
    X-Mandant-Context) has no value to write into ``mandant_id``."""
    if await get_instance_mode(db) == "multi_mandant" and auth.mandant_id is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="X-Mandant-Context is required to tag this group with a mandate.",
        )


@router.get("/projects/{project}/groups", response_model=list[ProjectGroupOut])
async def list_project_groups(
    project: str,
    _: Annotated[User, Depends(require_role("admin"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> list[ProjectGroupOut]:
    """List all groups that have access to a project within the caller's mandate."""
    result = await db.execute(
        select(ProjectGroup).where(
            ProjectGroup.project == project,
            ProjectGroup.mandant_id == auth.mandant_id,
        ).order_by(ProjectGroup.group_name)
    )
    return [ProjectGroupOut.from_orm_row(r) for r in result.scalars().all()]


class GroupOut(BaseModel):
    """Response schema for a group (without project context)."""
    group_name: str
    projects: list[str]
    user_count: int
    created_at: datetime


@router.get("/groups", response_model=list[GroupOut])
async def list_all_groups(
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> list[GroupOut]:
    """List all groups across all projects within the caller's mandate scope.

    In multi-mandant mode ``get_scoped_db`` already narrows ``project_groups``
    to the effective mandate (or every mandate for a holding role), so this
    stays a pure mandate-scoped read.
    """
    # Get unique group names
    groups_result = await db.execute(
        select(ProjectGroup.group_name)
        .distinct()
        .order_by(ProjectGroup.group_name)
    )
    group_names = groups_result.scalars().all()

    # Fetch projects per group
    group_projects_result = await db.execute(
        select(ProjectGroup.group_name, ProjectGroup.project)
        .order_by(ProjectGroup.group_name, ProjectGroup.project)
    )
    group_projects_map: dict[str, list[str]] = {}
    for row in group_projects_result.all():
        if row[0] not in group_projects_map:
            group_projects_map[row[0]] = []
        if row[1] not in group_projects_map[row[0]]:
            group_projects_map[row[0]].append(row[1])

    # Count users per group, but only users visible through the current RLS
    # context (``users`` is tenant-scoped; ``user_groups`` is not). This keeps
    # the user count from leaking cross-mandate memberships for a group name
    # that happens to exist in multiple mandates.
    user_count_result = await db.execute(
        select(UserGroup.group_name, func.count(UserGroup.id).label("count"))
        .join(User, User.id == UserGroup.user_id)
        .group_by(UserGroup.group_name)
    )
    user_counts = {row[0]: row[1] for row in user_count_result.all()}

    # Get creation date per group (earliest creation date)
    created_result = await db.execute(
        select(ProjectGroup.group_name, func.min(ProjectGroup.created_at).label("min_created"))
        .group_by(ProjectGroup.group_name)
    )
    created_dates = {row[0]: row[1] for row in created_result.all()}

    return [
        GroupOut(
            group_name=group_name,
            projects=sorted(group_projects_map.get(group_name, [])),
            user_count=user_counts.get(group_name, 0),
            created_at=created_dates.get(group_name, datetime.now(timezone.utc)),
        )
        for group_name in group_names
    ]


@router.post("/projects/{project}/groups", response_model=ProjectGroupOut, status_code=201)
async def create_project_group(
    project: str,
    payload: ProjectGroupCreate,
    acting_user: Annotated[User, Depends(require_role("admin"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> ProjectGroupOut:
    """Add a group to a project's access list within the caller's mandate."""
    if payload.project != project:
        raise HTTPException(400, detail="Project in path and body must match.")
    await _require_mandant_for_group_write(db, auth)
    row = ProjectGroup(
        project=project,
        group_name=payload.group_name,
        created_by=acting_user.id,
        mandant_id=auth.mandant_id,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return ProjectGroupOut.from_orm_row(row)


@router.delete("/projects/{project}/groups/{group_name}", status_code=204)
async def delete_project_group(
    project: str,
    group_name: str,
    _: Annotated[User, Depends(require_role("admin"))],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> None:
    """Remove a group from a project's access list within the caller's mandate."""
    result = await db.execute(
        select(ProjectGroup).where(
            ProjectGroup.project == project,
            ProjectGroup.group_name == group_name,
            ProjectGroup.mandant_id == auth.mandant_id,
        )
    )
    row = result.scalar_one_or_none()
    if row:
        await db.delete(row)
        await db.commit()


# ── User Group API (admin only) ───────────────────────────────────────────────


class UserGroupOut(BaseModel):
    """Response schema for user groups."""
    id: str
    user_id: str
    group_name: str
    provider: str
    created_at: datetime | None = None

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_row(cls, row: UserGroup) -> "UserGroupOut":
        return cls(
            id=str(row.id),
            user_id=str(row.user_id),
            group_name=row.group_name,
            provider=row.provider,
            created_at=row.created_at,
        )


class UserGroupCreate(BaseModel):
    """Request body for creating a user group (manual assignment)."""
    group_name: str
    provider: str = "*"


async def _require_user_in_scope(db: AsyncSession, user_id: str) -> None:
    """Confirm the target user is visible in the caller's mandate scope.

    ``users`` is tenant-scoped, so ``db.get(User, ...)`` returns the row only
    if it belongs to the effective mandate (or the caller is a holding role).
    This prevents a mandate-scoped admin from reading or mutating group
    memberships of users in other mandates via the unscoped ``user_groups``
    table.
    """
    target = await db.get(User, uuid.UUID(user_id))
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found.")


@router.get("/auth/users/{user_id}/groups", response_model=list[UserGroupOut])
async def list_user_groups(
    user_id: str,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> list[UserGroupOut]:
    """List all groups a user belongs to within the caller's mandate scope."""
    await _require_user_in_scope(db, user_id)
    result = await db.execute(
        select(UserGroup).where(UserGroup.user_id == uuid.UUID(user_id)).order_by(UserGroup.group_name)
    )
    return [UserGroupOut.from_orm_row(r) for r in result.scalars().all()]


@router.post("/auth/users/{user_id}/groups", response_model=UserGroupOut, status_code=201)
async def create_user_group(
    user_id: str,
    payload: UserGroupCreate,
    acting_user: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> UserGroupOut:
    """Add a group to a user's membership (manual admin assignment)."""
    await _require_user_in_scope(db, user_id)
    row = UserGroup(
        user_id=uuid.UUID(user_id),
        group_name=payload.group_name,
        provider=payload.provider,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return UserGroupOut.from_orm_row(row)


@router.delete("/auth/users/{user_id}/groups/{group_name}", status_code=204)
async def delete_user_group(
    user_id: str,
    group_name: str,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> None:
    """Remove a group from a user's membership within the caller's mandate scope."""
    await _require_user_in_scope(db, user_id)
    result = await db.execute(
        select(UserGroup).where(
            UserGroup.user_id == uuid.UUID(user_id),
            UserGroup.group_name == group_name,
        )
    )
    row = result.scalar_one_or_none()
    if row:
        await db.delete(row)
        await db.commit()


# ── Public: list enabled providers for login page ─────────────────────────────

@router.get("/sso/providers", response_model=list[SsoProviderInfo])
async def list_enabled_providers(
    db: Annotated[AsyncSession, Depends(get_db)],
    mandant: str | None = None,
) -> list[dict]:
    """Providers to offer on the login page.

    ADR-005: with ``?mandant=<slug>``, prefers that mandate's own
    per-mandant override config over the instance-wide default, and
    returns nothing at all if the mandate is configured
    ``auth_mode: "local_only"``. Omitting ``mandant`` — or an unknown/
    inactive slug, since the login page must still render something
    sensible rather than error out — falls back to exactly today's
    behaviour: the instance-wide defaults only.
    """
    labels = {"oidc": "Sign in with OIDC", "saml2": "Sign in with SAML2"}
    mandant_row: Mandant | None = None
    if mandant:
        result = await db.execute(select(Mandant).where(Mandant.slug == mandant, Mandant.is_active.is_(True)))
        mandant_row = result.scalar_one_or_none()
        if mandant_row is not None and _auth_mode_of(mandant_row) == "local_only":
            return []

    await _adopt_public_sso_context(db, mandant_row.id if mandant_row is not None else None)

    providers: list[dict] = []
    for provider in ("oidc", "saml2"):
        cfg = await _get_cfg(db, provider, mandant_row.id if mandant_row is not None else None)
        if cfg is not None and cfg.enabled:
            providers.append({
                "provider": provider,
                "enabled": cfg.enabled,
                "label": labels.get(provider, provider),
                "scope": "mandant" if cfg.mandant_id is not None else "default",
            })
    return providers


# ── OIDC Flow ─────────────────────────────────────────────────────────────────

def _sign_state(nonce: str, cfg_mandant_id: uuid.UUID | None = None) -> str:
    """ADR-005: *cfg_mandant_id* records which sso_configs row
    ``oidc_authorize`` resolved — ``None`` for the instance-wide default,
    a mandant id for a per-mandant override — so ``oidc_callback`` keeps
    using that exact same row (via ``_get_cfg_exact``) instead of
    re-resolving and risking a mismatch if two mandates each have their
    own ``oidc`` row with different ``client_id``/certs.
    """
    return _jwt.encode(
        {
            "nonce": nonce,
            "cfg_mandant_id": str(cfg_mandant_id) if cfg_mandant_id else None,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
        },
        settings.wafpass_jwt_secret,
        algorithm="HS256",
    )


def _verify_state(state: str) -> tuple[str, uuid.UUID | None]:
    """Verify the signed state JWT and return ``(nonce, cfg_mandant_id)``."""
    try:
        payload = _jwt.decode(state, settings.wafpass_jwt_secret, algorithms=["HS256"])
        raw_mandant_id = payload.get("cfg_mandant_id")
        return payload["nonce"], (uuid.UUID(raw_mandant_id) if raw_mandant_id else None)
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid or expired SSO state.")


async def _oidc_discovery(discovery_url: str) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(discovery_url)
        resp.raise_for_status()
        return resp.json()


async def _oidc_exchange_code(token_endpoint: str, code: str, cfg: dict) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": cfg["redirect_uri"],
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
            },
        )
        resp.raise_for_status()
        return resp.json()


async def _oidc_fetch_signing_key(jwks_uri: str, token: str):
    """Fetch the JWKS and return the signing key matching the token's kid header."""
    import httpx
    header = _jwt.get_unverified_header(token)
    kid = header.get("kid")
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(jwks_uri)
        resp.raise_for_status()
        jwks = resp.json()
    for key_data in jwks.get("keys", []):
        if kid is None or key_data.get("kid") == kid:
            kty = key_data.get("kty", "")
            if kty == "RSA":
                return _jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data))
            if kty == "EC":
                return _jwt.algorithms.ECAlgorithm.from_jwk(json.dumps(key_data))
    raise ValueError(f"No matching JWKS key found for kid={kid!r}")


async def _oidc_userinfo(userinfo_endpoint: str, access_token: str) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"})
        resp.raise_for_status()
        return resp.json()


@router.get("/auth/oidc/authorize")
async def oidc_authorize(
    db: Annotated[AsyncSession, Depends(get_db)],
    mandant: str | None = None,
) -> RedirectResponse:
    """Initiate OIDC Authorization Code flow — redirects to the configured IdP.

    ADR-005: ``?mandant=<slug>`` prefers that mandate's own per-mandant
    OIDC config, falling back to the instance-wide default if none
    exists. Omitting it reproduces pre-ADR-005 behaviour exactly.
    """
    requested_mandant_id: uuid.UUID | None = None
    if mandant:
        mandant_row = await _resolve_mandant_by_slug(db, mandant)
        if _auth_mode_of(mandant_row) == "local_only":
            raise HTTPException(404, detail="OIDC SSO is not enabled.")
        requested_mandant_id = mandant_row.id

    await _adopt_public_sso_context(db, requested_mandant_id)

    cfg_row = await _get_cfg(db, "oidc", requested_mandant_id)
    if not cfg_row or not cfg_row.enabled:
        raise HTTPException(404, detail="OIDC SSO is not enabled.")
    cfg = cfg_row.config

    discovery = await _oidc_discovery(cfg["discovery_url"])
    nonce = secrets.token_hex(16)
    # cfg_row.mandant_id (not requested_mandant_id): the row actually used
    # may have fallen back to the default even when a mandate was
    # requested (no override configured for it) — the callback must keep
    # using whichever row this authorize step really used.
    state = _sign_state(nonce, cfg_row.mandant_id)
    scopes = cfg.get("scopes", ["openid", "profile", "email"])
    params = urlencode({
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "scope": " ".join(scopes),
        "state": state,
        "nonce": nonce,
    })
    # Allow overriding the browser-facing authorization endpoint separately from
    # the discovery URL — needed when the server reaches the IdP via an internal
    # hostname (e.g. "keycloak:8080") but the browser must use a public one
    # (e.g. "localhost:8080").
    auth_endpoint = cfg.get("authorization_endpoint") or discovery["authorization_endpoint"]
    return RedirectResponse(f"{auth_endpoint}?{params}", status_code=302)


@router.get("/auth/oidc/callback")
async def oidc_callback(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    """Handle OIDC callback — exchange code, provision user, issue JWT, redirect to frontend."""
    # ADR-005: the signed `state` carries which sso_configs row
    # oidc_authorize actually resolved (None = instance-wide default).
    # Decoded here, before anything else, so every step below —
    # including which row's frontend_url an early error redirects to —
    # uses the exact same row the authorize step used, not a fresh
    # (and possibly different, for a different mandate) resolution.
    # A missing/invalid/expired state leaves verified_nonce None, which
    # is itself checked below (own error branch), after the `error`/
    # `missing_params` short-circuits that don't need it at all.
    cfg_mandant_id: uuid.UUID | None = None
    verified_nonce: str | None = None
    if state:
        try:
            verified_nonce, cfg_mandant_id = _verify_state(state)
        except HTTPException:
            pass

    await _adopt_public_sso_context(db, cfg_mandant_id)

    cfg_row = await _get_cfg_exact(db, "oidc", cfg_mandant_id) if verified_nonce else await _get_cfg(db, "oidc")
    if not cfg_row or not cfg_row.enabled:
        raise HTTPException(404, detail="OIDC SSO is not enabled.")
    cfg = await _decrypt_config("oidc", cfg_row.config)
    frontend_url = cfg.get("frontend_url", "http://localhost:5173")

    if error:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error={error}", status_code=302)
    if not code or not state:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error=missing_params", status_code=302)
    if verified_nonce is None:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error=invalid_state", status_code=302)
    nonce = verified_nonce

    try:
        discovery = await _oidc_discovery(cfg["discovery_url"])
        tokens = await _oidc_exchange_code(discovery["token_endpoint"], code, cfg)
    except Exception:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error=token_exchange_failed", status_code=302)

    claims: dict = {}
    if "id_token" in tokens:
        jwks_uri = discovery.get("jwks_uri", "")
        if jwks_uri:
            try:
                signing_key = await _oidc_fetch_signing_key(jwks_uri, tokens["id_token"])
                algs = discovery.get("id_token_signing_alg_values_supported", ["RS256"])
                claims = _jwt.decode(
                    tokens["id_token"],
                    signing_key,
                    algorithms=algs,
                    audience=cfg["client_id"],
                )
                if claims.get("nonce") != nonce:
                    return RedirectResponse(
                        f"{frontend_url.rstrip('/')}?sso_error=invalid_nonce", status_code=302
                    )
            except Exception:
                return RedirectResponse(
                    f"{frontend_url.rstrip('/')}?sso_error=token_verification_failed", status_code=302
                )
        # No JWKS URI in discovery doc — fall through to userinfo

    if not claims and "userinfo_endpoint" in discovery:
        try:
            claims = await _oidc_userinfo(discovery["userinfo_endpoint"], tokens.get("access_token", ""))
        except Exception:
            pass

    username_claim = cfg.get("username_claim", "email")
    username = claims.get(username_claim) or claims.get("sub", "")
    if not username:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error=no_username_claim", status_code=302)

    display_name = claims.get(cfg.get("display_name_claim", "name")) or claims.get("preferred_username") or username

    role = cfg.get("default_role", "clevel")
    role_claim = cfg.get("role_claim")
    claim_val = claims.get(role_claim) if role_claim else None
    candidates = claim_val if isinstance(claim_val, list) else ([claim_val] if claim_val else [])
    candidates = [v for v in candidates if v]

    mapped = await _resolve_role_from_groups(db, "oidc", candidates)
    if mapped:
        role = mapped
    else:
        role_mapping: dict = cfg.get("role_mapping", {})
        for v in candidates:
            if v in role_mapping:
                role = role_mapping[v]
                break

    # Phase 4 — maps an IdP claim to a mandant slug, same config convention
    # as username_claim/role_claim/group_claim above.
    mandant_claim = cfg.get("mandant_claim")
    mandant_slug = claims.get(mandant_claim) if mandant_claim else None

    try:
        user = await _provision_user(
            db, username, display_name, "oidc", role, cfg.get("auto_provision", True),
            mandant_slug, forced_mandant_id=cfg_row.mandant_id,
        )
    except HTTPException as exc:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error=access_denied&detail={exc.detail}", status_code=302)

    # Update user's group memberships
    group_claim = cfg.get("group_claim")
    group_values = []
    if group_claim:
        groups = claims.get(group_claim)
        if isinstance(groups, list):
            group_values = [g for g in groups if g]
        elif groups:
            group_values = [groups] if isinstance(groups, str) else list(groups)
    await _update_user_groups(db, user.id, "oidc", group_values)

    access_token, raw_refresh = await _issue_tokens(db, user)
    await _audit(db, user.id, "sso.login", {"provider": "oidc"}, ip=_ip(request), mandant_id=user.mandant_id)
    await db.commit()
    await db.refresh(user)

    return RedirectResponse(_frontend_redirect(frontend_url, access_token, raw_refresh, user), status_code=302)


# ── SAML2 Flow ────────────────────────────────────────────────────────────────

def _saml_settings_dict(cfg: dict) -> dict:
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": cfg["entity_id"],
            "assertionConsumerService": {
                "url": cfg["acs_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "x509cert": cfg.get("sp_certificate", ""),
            "privateKey": cfg.get("sp_private_key", ""),
        },
        "idp": {
            "entityId": cfg["idp_entity_id"],
            "singleSignOnService": {
                "url": cfg["idp_sso_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": cfg["idp_certificate"],
        },
    }


def _saml_req(request: Request, post_data: dict | None = None) -> dict:
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.headers.get("host", "localhost"),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": post_data or {},
    }


@router.get("/auth/saml/metadata")
async def saml_metadata(
    db: Annotated[AsyncSession, Depends(get_db)],
    mandant: str | None = None,
) -> HTMLResponse:
    """Return SP metadata XML for registering with the IdP.

    ADR-005: ``?mandant=<slug>`` returns the per-mandant override's own
    SP metadata (its own entity id / ACS URL / cert) if one is
    configured, falling back to the instance-wide default otherwise —
    an IdP admin registering a dedicated SAML app for one mandate needs
    that mandate's metadata, not the shared one.
    """
    if not SAML_AVAILABLE:
        raise HTTPException(501, detail="python3-saml is not installed on this server.")
    requested_mandant_id: uuid.UUID | None = None
    if mandant:
        mandant_row = await _resolve_mandant_by_slug(db, mandant)
        requested_mandant_id = mandant_row.id
    await _adopt_public_sso_context(db, requested_mandant_id)
    cfg_row = await _get_cfg(db, "saml2", requested_mandant_id)
    if not cfg_row:
        raise HTTPException(404, detail="SAML2 is not configured.")
    saml_cfg = OneLogin_Saml2_Settings(
        _saml_settings_dict(await _decrypt_config("saml2", cfg_row.config)), sp_validation_only=True
    )
    metadata = saml_cfg.get_sp_metadata()
    return HTMLResponse(content=metadata, media_type="application/xml")


@router.get("/auth/saml/login")
async def saml_login(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    mandant: str | None = None,
) -> RedirectResponse:
    """Initiate SAML2 SP-initiated SSO.

    ADR-005: ``?mandant=<slug>`` prefers that mandate's own per-mandant
    SAML2 config, falling back to the instance-wide default otherwise.
    The resolved row's own mandate — which may be the default even when
    a mandate was requested, if no override exists for it — is signed
    into RelayState (same convention as OIDC's `state`) so `saml_acs`
    uses the exact same row, not a fresh/possibly different resolution.
    """
    if not SAML_AVAILABLE:
        raise HTTPException(501, detail="python3-saml is not installed on this server.")
    requested_mandant_id: uuid.UUID | None = None
    if mandant:
        mandant_row = await _resolve_mandant_by_slug(db, mandant)
        if _auth_mode_of(mandant_row) == "local_only":
            raise HTTPException(404, detail="SAML2 SSO is not enabled.")
        requested_mandant_id = mandant_row.id

    await _adopt_public_sso_context(db, requested_mandant_id)

    cfg_row = await _get_cfg(db, "saml2", requested_mandant_id)
    if not cfg_row or not cfg_row.enabled:
        raise HTTPException(404, detail="SAML2 SSO is not enabled.")
    relay_state = _sign_state(secrets.token_hex(16), cfg_row.mandant_id)
    auth = OneLogin_Saml2_Auth(_saml_req(request), _saml_settings_dict(await _decrypt_config("saml2", cfg_row.config)))
    return RedirectResponse(auth.login(return_to=relay_state), status_code=302)


@router.post("/auth/saml/acs")
async def saml_acs(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> RedirectResponse:
    """SAML2 Assertion Consumer Service — validate IdP response and issue JWT."""
    if not SAML_AVAILABLE:
        raise HTTPException(501, detail="python3-saml is not installed on this server.")

    form = await request.form()

    # ADR-005: RelayState carries which sso_configs row saml_login
    # resolved (same signed-state convention as OIDC's `state`), read
    # before anything else so even an early error redirect goes to the
    # right mandate's frontend_url, and the real processing below uses
    # the exact same row saml_login used.
    cfg_mandant_id: uuid.UUID | None = None
    relay_state = form.get("RelayState")
    if relay_state:
        try:
            _, cfg_mandant_id = _verify_state(relay_state)
        except HTTPException:
            pass

    await _adopt_public_sso_context(db, cfg_mandant_id)

    cfg_row = await _get_cfg_exact(db, "saml2", cfg_mandant_id) if relay_state else await _get_cfg(db, "saml2")
    if not cfg_row or not cfg_row.enabled:
        raise HTTPException(404, detail="SAML2 SSO is not enabled.")
    cfg = await _decrypt_config("saml2", cfg_row.config)
    frontend_url = cfg.get("frontend_url", "http://localhost:5173")

    auth = OneLogin_Saml2_Auth(_saml_req(request, dict(form)), _saml_settings_dict(cfg))
    auth.process_response()
    errors = auth.get_errors()

    if errors or not auth.is_authenticated():
        err_str = "_".join(errors) if errors else "not_authenticated"
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error={err_str}", status_code=302)

    attrs = auth.get_attributes()
    name_id = auth.get_nameid()

    username_attr = cfg.get("username_attribute")
    username = (attrs.get(username_attr, [None])[0] if username_attr else None) or name_id
    if not username:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error=no_username", status_code=302)

    dn_attr = cfg.get("display_name_attribute")
    display_name = (attrs.get(dn_attr, [None])[0] if dn_attr else None) or username

    role = cfg.get("default_role", "clevel")
    role_attr = cfg.get("role_attribute")
    saml_candidates = [v for v in attrs.get(role_attr, []) if v] if role_attr else []

    saml_mapped = await _resolve_role_from_groups(db, "saml2", saml_candidates)
    if saml_mapped:
        role = saml_mapped
    else:
        role_mapping: dict = cfg.get("role_mapping", {})
        for v in saml_candidates:
            if v in role_mapping:
                role = role_mapping[v]
                break

    # Phase 4 — maps an IdP attribute to a mandant slug, same convention as
    # username_attribute/role_attribute/group_attribute above.
    mandant_attr = cfg.get("mandant_attribute")
    mandant_slug = (attrs.get(mandant_attr, [None])[0] if mandant_attr else None)

    try:
        user = await _provision_user(
            db, username, display_name, "saml2", role, cfg.get("auto_provision", True),
            mandant_slug, forced_mandant_id=cfg_row.mandant_id,
        )
    except HTTPException as exc:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error=access_denied&detail={exc.detail}", status_code=302)

    # Update user's group memberships
    group_attr = cfg.get("group_attribute")
    group_values = []
    if group_attr:
        groups = attrs.get(group_attr)
        if isinstance(groups, list):
            group_values = [g for g in groups if g]
        elif groups:
            group_values = [groups] if isinstance(groups, str) else list(groups)
    await _update_user_groups(db, user.id, "saml2", group_values)

    access_token, raw_refresh = await _issue_tokens(db, user)
    await _audit(db, user.id, "sso.login", {"provider": "saml2"}, ip=_ip(request), mandant_id=user.mandant_id)
    await db.commit()
    await db.refresh(user)

    return RedirectResponse(_frontend_redirect(frontend_url, access_token, raw_refresh, user), status_code=302)
