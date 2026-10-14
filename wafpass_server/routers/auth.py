"""Authentication endpoints: login, refresh, logout, /me, and user management."""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import (
    ROLE_HIERARCHY,
    AuthContext,
    adopt_mandate_of,
    get_auth_context,
    get_current_user,
    get_scoped_db,
    load_user_by_id,
    require_role,
    set_login_username,
)
from wafpass_server.auth.jwt_utils import create_access_token
from wafpass_server.auth.providers.local import authenticate_local, hash_password
from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import ApiKey, ApiKeyUsageLog, Mandant, RefreshToken, User, UserAuditLog, UserGroup
from wafpass_server.syslog import emit_admin_audit_event

router = APIRouter(prefix="/auth", tags=["auth"])

# App-validated, not a DB CHECK constraint — same convention as admin.py's
# _VALID_MANDATE_TYPES. group_admin/group_viewer are Phase 6b / ADR-004.
_VALID_HOLDING_ROLES = {"holding_admin", "holding_viewer", "group_admin", "group_viewer"}


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _ip(request: Request) -> str:
    return request.headers.get("x-forwarded-for", request.client.host if request.client else "")


async def _audit(
    db: AsyncSession,
    actor_id: uuid.UUID | None,
    action: str,
    detail: dict,
    ip: str = "",
    mandant_id: uuid.UUID | None = None,
) -> None:
    db.add(UserAuditLog(actor_id=actor_id, action=action, detail=detail, ip=ip, mandant_id=mandant_id))
    emit_admin_audit_event(
        action=action,
        detail=detail,
        ip=ip,
        mandant_id=str(mandant_id) if mandant_id else None,
        actor_id=str(actor_id) if actor_id else None,
    )
    # caller is responsible for commit


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    display_name: str
    image_url: str = ""
    role: str
    auth_provider: str
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    mandant_id: uuid.UUID | None = None
    holding_role: str | None = None  # None | "holding_admin" | "holding_viewer" | "group_admin" | "group_viewer"

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut


class RefreshRequest(BaseModel):
    refresh_token: str


class AccessTokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    username: str
    password: str = Field(min_length=8)
    display_name: str = ""
    image_url: str = ""
    role: str = "clevel"
    group: str | None = None  # Optional group name to assign to user
    # Explicit target mandate — holding_admin only (see create_user).
    # Omitted (the common case): falls back to the acting user's own
    # effective mandate, same as before this field existed. Mirrors
    # ApiKeyCreate.mandant_id's identical pattern below — a holding-only
    # admin creating a user previously had nowhere to assign a mandate at
    # all (the identical gap for API keys was fixed first).
    mandant_id: uuid.UUID | None = None


class UserUpdate(BaseModel):
    display_name: str | None = None
    image_url: str | None = None
    role: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8)
    group: str | None = None  # Optional group name to add to user
    # Phase 3.4 — only ever applied when the acting user is holding_admin
    # (enforced in update_user below, not by the schema).
    mandant_id: uuid.UUID | None = None
    holding_role: str | None = None  # "" clears it; None leaves it unchanged. See _VALID_HOLDING_ROLES.


# ── Auth endpoints ────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    payload: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Exchange username + password for an access token and a refresh token."""
    # Auth-bootstrap carve-out: at this point we know only the submitted
    # username, not the user's id or mandate — see
    # db_migrations/activate_multi_mandant_ddl.py and auth/deps.py.
    await set_login_username(db, payload.username)
    record = await authenticate_local(db, payload.username, payload.password)
    if record is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

    user = await db.get(User, record.id)
    # Now that the user's own row is found, adopt its mandate for the rest
    # of this request — RefreshToken isn't mandate-scoped, but UserAuditLog
    # (via _audit below) is, and its WITH CHECK needs this set. Also carry
    # the user's own holding flags: a holding-only account (mandant_id=
    # None) has no other way to pass the users-table WITH CHECK for the
    # last_login_at update just below — see adopt_mandate_of()'s docstring.
    await adopt_mandate_of(
        db, user.mandant_id,
        is_holding_admin=user.holding_role == "holding_admin",
        is_holding_viewer=user.holding_role == "holding_viewer",
    )
    access_token = create_access_token(user.id, user.username, user.role)

    raw_refresh = secrets.token_urlsafe(48)
    rt = RefreshToken(
        user_id=user.id,
        token_hash=_hash(raw_refresh),
        family_id=uuid.uuid4(),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.wafpass_jwt_refresh_days),
    )
    db.add(rt)

    user.last_login_at = datetime.now(timezone.utc)
    await _audit(db, user.id, "login", {}, ip=_ip(request), mandant_id=user.mandant_id)
    await db.commit()

    return {
        "access_token": access_token,
        "refresh_token": raw_refresh,
        "token_type": "bearer",
        "user": user,
    }


@router.post("/refresh", response_model=AccessTokenResponse)
async def refresh_token(
    request: Request,
    payload: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Rotate a refresh token: revoke the presented one, issue a fresh one.

    If a revoked token is presented it indicates a replay attack — every token
    in the same family is immediately revoked, forcing re-authentication on all
    devices that shared this token chain.
    """
    token_hash = _hash(payload.refresh_token)
    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    rt = result.scalar_one_or_none()

    if rt is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    if rt.revoked:
        # Replay of an already-rotated token — assume theft, invalidate the whole family.
        # RefreshToken itself isn't mandate-scoped, but the UserAuditLog
        # entry below is — load the user (known id, bootstrap carve-out)
        # and adopt its mandate so that insert's WITH CHECK passes.
        replay_user = await load_user_by_id(db, rt.user_id)
        await adopt_mandate_of(
            db, replay_user.mandant_id if replay_user else None,
            is_holding_admin=bool(replay_user and replay_user.holding_role == "holding_admin"),
            is_holding_viewer=bool(replay_user and replay_user.holding_role == "holding_viewer"),
        )
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == rt.family_id)
            .values(revoked=True)
        )
        await _audit(db, rt.user_id, "token.family_revoked",
                     {"family_id": str(rt.family_id), "reason": "revoked_token_replay"},
                     ip=_ip(request), mandant_id=replay_user.mandant_id if replay_user else None)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            detail="Refresh token already used — all sessions invalidated. Please log in again.")

    if rt.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        rt.revoked = True
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired.")

    # Bootstrap carve-out: rt.user_id is already known, same shape as JWT
    # validation — see auth/deps.py.
    user = await load_user_by_id(db, rt.user_id)
    if user is None or not user.is_active:
        rt.revoked = True
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive.")

    # Rotate: revoke the old token, issue a new one in the same family.
    rt.revoked = True
    raw_new = secrets.token_urlsafe(48)
    db.add(RefreshToken(
        user_id=user.id,
        token_hash=_hash(raw_new),
        family_id=rt.family_id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.wafpass_jwt_refresh_days),
    ))
    await db.commit()

    return {
        "access_token": create_access_token(user.id, user.username, user.role),
        "refresh_token": raw_new,
        "token_type": "bearer",
    }


@router.post("/logout", status_code=204)
async def logout(
    request: Request,
    payload: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Revoke the supplied refresh token."""
    token_hash = _hash(payload.refresh_token)
    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    rt = result.scalar_one_or_none()
    if rt:
        rt.revoked = True
        logout_user = await load_user_by_id(db, rt.user_id)
        await adopt_mandate_of(
            db, logout_user.mandant_id if logout_user else None,
            is_holding_admin=bool(logout_user and logout_user.holding_role == "holding_admin"),
            is_holding_viewer=bool(logout_user and logout_user.holding_role == "holding_viewer"),
        )
        await _audit(db, rt.user_id, "logout", {}, ip=_ip(request), mandant_id=logout_user.mandant_id if logout_user else None)
        await db.commit()


@router.get("/me", response_model=UserOut)
async def me(
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Return the authenticated user's profile."""
    return user


@router.get("/me/prefs")
async def get_my_prefs(
    user: Annotated[User, Depends(get_current_user)],
) -> dict[str, Any]:
    """Return the current user's stored UI preferences."""
    return user.prefs or {}


@router.put("/me/prefs", status_code=204)
async def put_my_prefs(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    payload: dict[str, Any] = Body(...),
) -> None:
    """Persist the current user's UI preferences (full replace)."""
    await db.execute(update(User).where(User.id == user.id).values(prefs=payload))
    await db.commit()


class ProfileUpdate(BaseModel):
    display_name: str | None = None
    image_url: str | None = None


@router.put("/me/profile", response_model=UserOut)
async def update_my_profile(
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
    payload: ProfileUpdate = Body(...),
) -> User:
    """Update the authenticated user's profile (display_name, image_url)."""
    changed_fields: list[str] = []
    if payload.display_name is not None:
        user.display_name = payload.display_name
        changed_fields.append("display_name")
    if payload.image_url is not None:
        user.image_url = payload.image_url
        changed_fields.append("image_url")
    if not changed_fields:
        return user
    await _audit(db, user.id, "user.update_profile", {
        "fields": changed_fields,
    }, ip=_ip(request), mandant_id=auth.mandant_id)
    await db.commit()
    await db.refresh(user)
    return user


# ── User management (requires engineer role) ─────────────────────────────────

@router.get("/users", response_model=list[UserOut])
async def list_users(
    _: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> list[User]:
    result = await db.execute(select(User).order_by(User.created_at))
    return list(result.scalars().all())


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    request: Request,
    payload: UserCreate,
    acting_user: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> User:
    if payload.role not in ROLE_HIERARCHY:
        raise HTTPException(400, detail=f"Invalid role. Choose from: {', '.join(ROLE_HIERARCHY)}")
    # A holding_admin outranks any single mandate's own "admin" — their
    # bypass is already full cross-mandate RLS access, so gating this on
    # the literal base role alone would wrongly block them (holding_role
    # and role are independent fields; see update_user below). Checked via
    # the request's *effective* flag, not the permanent holding_role, so a
    # holding_admin who has narrowed into one mandate via X-Mandant-Context
    # is held to that mandate's own admin requirement, same as everywhere
    # else narrowing applies.
    if payload.role == "admin" and acting_user.role != "admin" and not auth.is_holding_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Only an admin can assign the 'admin' role.")
    existing = await db.execute(select(User).where(User.username == payload.username))
    if existing.scalar_one_or_none():
        raise HTTPException(409, detail=f"Username '{payload.username}' already exists.")

    # New users join the creating admin's own mandate by default.
    # payload.mandant_id (mirrors create_api_key's identical pattern) lets
    # a holding_admin target a *specific* mandate directly instead — an
    # ordinary admin explicitly naming a mandate other than their own would
    # be a privilege-escalation path, not a convenience.
    target_mandant_id = auth.mandant_id
    if payload.mandant_id is not None:
        if not auth.is_holding_admin:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail="Only a holding_admin can target a specific mandant_id when creating a user.",
            )
        target_mandant = await db.get(Mandant, payload.mandant_id)
        if target_mandant is None or not target_mandant.is_active:
            raise HTTPException(400, detail="Unknown or inactive mandant_id.")
        target_mandant_id = payload.mandant_id
    elif auth.is_holding_admin and auth.mandant_id is None:
        # A holding-only admin (no personal mandate) has nothing to
        # inherit — unlike create_api_key, this wouldn't crash
        # (users.mandant_id is nullable) but would silently create a
        # dead-end account with no mandate-scoped or holding access at
        # all. Reject cleanly instead, unless they named a target above.
        raise HTTPException(
            400,
            detail="A holding-only admin has no mandate to assign this user to. "
                   "Switch to a mandate-scoped account, or pass mandant_id explicitly.",
        )
    user = User(
        username=payload.username,
        display_name=payload.display_name,
        image_url=payload.image_url,
        role=payload.role,
        auth_provider="local",
        password_hash=hash_password(payload.password),
        mandant_id=target_mandant_id,
    )
    db.add(user)
    await db.flush()   # get user.id before audit row

    # Assign group to user if specified
    if payload.group:
        existing_group = await db.execute(
            select(UserGroup).where(
                UserGroup.user_id == user.id,
                UserGroup.group_name == payload.group
            )
        )
        if existing_group.scalar_one_or_none() is None:
            user_group = UserGroup(
                user_id=user.id,
                group_name=payload.group,
                provider="*"
            )
            db.add(user_group)

    # Tag with the *target's* own mandate, not the actor's — same reasoning
    # as update_user/delete_user below: a holding_admin creating a user in
    # mandate X while themselves unnarrowed should still produce an audit
    # row that mandate X's own admin can see.
    await _audit(db, acting_user.id, "user.create", {
        "target_id": str(user.id),
        "target_username": user.username,
        "target_role": user.role,
        "target_group": payload.group,
    }, ip=_ip(request), mandant_id=target_mandant_id)
    await db.commit()
    await db.refresh(user)
    return user


@router.put("/users/{user_id}", response_model=UserOut)
async def update_user(
    request: Request,
    user_id: uuid.UUID,
    payload: UserUpdate,
    acting_user: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, detail="User not found.")
    # Same holding_admin bypass as create_user above.
    if (user.role == "admin" or payload.role == "admin") and acting_user.role != "admin" and not auth.is_holding_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Only an admin can modify an admin account or grant the 'admin' role.")
    changed_fields: list[str] = []
    if payload.display_name is not None:
        user.display_name = payload.display_name
        changed_fields.append("display_name")
    if payload.image_url is not None:
        user.image_url = payload.image_url
        changed_fields.append("image_url")
    if payload.role is not None:
        if payload.role not in ROLE_HIERARCHY:
            raise HTTPException(400, detail=f"Invalid role. Choose from: {', '.join(ROLE_HIERARCHY)}")
        user.role = payload.role
        changed_fields.append("role")
    if payload.is_active is not None:
        user.is_active = payload.is_active
        changed_fields.append("is_active")
    if payload.password is not None:
        user.password_hash = hash_password(payload.password)
        changed_fields.append("password")
    if payload.group is not None:
        # Add user to specified group
        existing_group = await db.execute(
            select(UserGroup).where(
                UserGroup.user_id == user.id,
                UserGroup.group_name == payload.group
            )
        )
        if existing_group.scalar_one_or_none() is None:
            user_group = UserGroup(
                user_id=user.id,
                group_name=payload.group,
                provider="*"
            )
            db.add(user_group)
            changed_fields.append("group")

    # Phase 3.4 — mandate/holding_role assignment, holding_admin only.
    # Uses model_fields_set (not `is not None`) for mandant_id specifically,
    # because None is itself a valid, meaningful value here (a holding-only
    # account with no personal mandate) — "the field was sent" and "the
    # field was sent as null" are different things a plain None default
    # can't distinguish.
    wants_mandant_change = "mandant_id" in payload.model_fields_set
    wants_holding_role_change = payload.holding_role is not None
    if wants_mandant_change or wants_holding_role_change:
        if not auth.is_holding_admin:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail="Only a holding_admin can reassign a user's mandant or holding role."
            )
        if wants_mandant_change:
            if payload.mandant_id is not None:
                target_mandant = await db.get(Mandant, payload.mandant_id)
                if target_mandant is None:
                    raise HTTPException(400, detail="Mandant not found.")
            user.mandant_id = payload.mandant_id
            changed_fields.append("mandant_id")
        if wants_holding_role_change:
            new_holding_role = payload.holding_role or None  # "" clears it
            if new_holding_role is not None and new_holding_role not in _VALID_HOLDING_ROLES:
                raise HTTPException(
                    400,
                    detail=f"holding_role must be one of {sorted(_VALID_HOLDING_ROLES)}, or empty to clear.",
                )
            user.holding_role = new_holding_role
            changed_fields.append("holding_role")

        # Phase 6b / ADR-004 — group_admin/group_viewer administer the
        # subtree rooted at their *own* mandant_id; unlike holding_admin/
        # holding_viewer (who administer the whole holding and may
        # legitimately have no personal mandate), a group role with no
        # mandate at all has no subtree to administer. Checked once here,
        # after both possible mutations above, so it catches every path to
        # that state: setting the role with no mandate ever assigned,
        # clearing mandant_id while the role is already a group one, or
        # (defensively) both in the same request.
        if user.holding_role in ("group_admin", "group_viewer") and user.mandant_id is None:
            raise HTTPException(
                400,
                detail="group_admin/group_viewer requires the user to already have a mandant assigned — "
                       "their own mandant is the root of the subtree they administer.",
            )

    # Tag with the *target's* mandate, not the actor's — a holding_admin
    # (who may have no personal mandate at all) editing a mandate-scoped
    # user should still produce an audit row that user's own mandate admin
    # can see, not one that's only visible at the holding level. Falls back
    # to NULL (holding-level-only visibility) only if the target also has
    # none — e.g. editing another holding-only account.
    await _audit(db, acting_user.id, "user.update", {
        "target_id": str(user.id),
        "target_username": user.username,
        "fields": changed_fields,
    }, ip=_ip(request), mandant_id=user.mandant_id)
    await db.commit()
    await db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    request: Request,
    user_id: uuid.UUID,
    acting_user: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> None:
    if acting_user.id == user_id:
        raise HTTPException(400, detail="Cannot delete your own account.")
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, detail="User not found.")
    # Same holding_admin bypass as create_user above.
    if user.role == "admin" and acting_user.role != "admin" and not auth.is_holding_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Only an admin can delete an admin account.")
    # Same reasoning as update_user: tag with the target's own mandate.
    await _audit(db, acting_user.id, "user.delete", {
        "target_id": str(user.id),
        "target_username": user.username,
        "target_role": user.role,
    }, ip=_ip(request), mandant_id=user.mandant_id)
    await db.delete(user)
    await db.commit()


@router.get("/users/{user_id}", response_model=UserOut)
async def get_user(
    user_id: uuid.UUID,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> User:
    """Return full profile for a single user (admin only)."""
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, detail="User not found.")
    return user


class UserAuditLogOut(BaseModel):
    id: uuid.UUID
    actor_id: uuid.UUID | None
    action: str
    detail: dict
    ip: str
    timestamp: datetime

    model_config = {"from_attributes": True}


@router.get("/users/{user_id}/logs", response_model=list[UserAuditLogOut])
async def get_user_logs(
    user_id: uuid.UUID,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    limit: int = 100,
) -> list[UserAuditLog]:
    """Return the most recent audit log entries where the actor is this user (admin only)."""
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, detail="User not found.")
    result = await db.execute(
        select(UserAuditLog)
        .where(UserAuditLog.actor_id == user_id)
        .order_by(UserAuditLog.timestamp.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


# ── API key management (admin only) ──────────────────────────────────────────

class ApiKeyOut(BaseModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    created_by: uuid.UUID | None
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None = None
    # Which mandate this key's ingested runs get tagged with — None only in
    # single_tenant mode. Exposed so a holding_admin (who can see every
    # mandate's keys, via RLS bypass) can actually tell them apart; this was
    # a real gap before — the dashboard's API key list had no way to show,
    # or let anyone audit, which mandate an existing key belonged to.
    mandant_id: uuid.UUID | None = None

    model_config = {"from_attributes": True}


class ApiKeyCreateResponse(ApiKeyOut):
    """Returned only on creation — includes the raw key (shown once)."""
    raw_key: str


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    # Explicit target mandate — holding_admin only (see create_api_key).
    # Omitted (the common case): falls back to the acting user's own
    # effective mandate, same as before this field existed. Lets a
    # holding_admin create a mandate-specific key directly, instead of the
    # only previously-available path (switch the dashboard's Global Context
    # Switcher into that mandate first, *then* create the key, with no
    # indication anywhere of which mandate the result would actually get).
    mandant_id: uuid.UUID | None = None


@router.get("/api-keys", response_model=list[ApiKeyOut])
async def list_api_keys(
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> list[ApiKey]:
    """List all DB-stored API keys (admin only)."""
    result = await db.execute(select(ApiKey).order_by(ApiKey.created_at))
    return list(result.scalars().all())


@router.post("/api-keys", response_model=ApiKeyCreateResponse, status_code=201)
async def create_api_key(
    payload: ApiKeyCreate,
    acting_user: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    auth: Annotated[AuthContext, Depends(get_auth_context)],
) -> dict:
    """Generate a new API key (admin only). The raw key is returned once — store it securely.

    ``payload.mandant_id`` lets a holding_admin target a *specific* mandate
    directly, rather than the only previously-available path (switch the
    dashboard's Global Context Switcher into that mandate, then create the
    key with no visible confirmation of which mandate it would land on).
    Holding_admin-only: an ordinary admin explicitly naming a mandate other
    than their own would be a privilege-escalation path (minting a key for
    data they can't otherwise see), not a convenience.
    """
    target_mandant_id = auth.mandant_id
    if payload.mandant_id is not None:
        if not auth.is_holding_admin:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail="Only a holding_admin can target a specific mandant_id when creating an API key.",
            )
        target_mandant = await db.get(Mandant, payload.mandant_id)
        if target_mandant is None or not target_mandant.is_active:
            raise HTTPException(400, detail="Unknown or inactive mandant_id.")
        target_mandant_id = payload.mandant_id
    # Unlike users/user_audit_logs, api_keys.mandant_id is NOT exempted from
    # NOT NULL once activated (Phase 1) — a mandate-less key would have no
    # mandate to tag ingested runs with, which defeats its purpose. A
    # holding-only admin (no personal mandate) with no explicit
    # payload.mandant_id has nothing sensible to fall back to; reject
    # cleanly rather than crash with a raw NotNullViolationError.
    if target_mandant_id is None:
        raise HTTPException(
            400, detail="A holding-only admin has no mandate to tag this key with. Pass mandant_id explicitly."
        )
    raw_key = "wafpass_" + secrets.token_hex(24)
    key_hash = _hash(raw_key)
    key_prefix = raw_key[:16]

    api_key = ApiKey(
        name=payload.name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        created_by=acting_user.id,
        is_active=True,
        mandant_id=target_mandant_id,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return {
        "id": api_key.id,
        "name": api_key.name,
        "key_prefix": api_key.key_prefix,
        "created_by": api_key.created_by,
        "is_active": api_key.is_active,
        "created_at": api_key.created_at,
        "last_used_at": api_key.last_used_at,
        "mandant_id": api_key.mandant_id,
        "raw_key": raw_key,
    }


@router.delete("/api-keys/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: uuid.UUID,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
) -> None:
    """Revoke (deactivate) a DB-stored API key (admin only)."""
    api_key = await db.get(ApiKey, key_id)
    if api_key is None:
        raise HTTPException(404, detail="API key not found.")
    api_key.is_active = False
    await db.commit()


class ApiKeyUsageLogOut(BaseModel):
    id: uuid.UUID
    used_at: datetime
    endpoint: str
    run_id: uuid.UUID | None
    project: str
    branch: str
    score: int | None
    ip: str

    model_config = {"from_attributes": True}


@router.get("/api-keys/{key_id}/logs", response_model=list[ApiKeyUsageLogOut])
async def get_api_key_logs(
    key_id: uuid.UUID,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_scoped_db)],
    limit: int = 50,
) -> list[ApiKeyUsageLog]:
    """Return the most recent usage log entries for a specific API key (admin only)."""
    api_key = await db.get(ApiKey, key_id)
    if api_key is None:
        raise HTTPException(404, detail="API key not found.")
    result = await db.execute(
        select(ApiKeyUsageLog)
        .where(ApiKeyUsageLog.api_key_id == key_id)
        .order_by(ApiKeyUsageLog.used_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())
