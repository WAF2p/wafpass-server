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

from wafpass_server.auth.deps import ROLE_HIERARCHY, get_current_user, require_role
from wafpass_server.auth.jwt_utils import create_access_token
from wafpass_server.auth.providers.local import authenticate_local, hash_password
from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import ApiKey, ApiKeyUsageLog, RefreshToken, User, UserAuditLog

router = APIRouter(prefix="/auth", tags=["auth"])


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
) -> None:
    db.add(UserAuditLog(actor_id=actor_id, action=action, detail=detail, ip=ip))
    # caller is responsible for commit


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    display_name: str
    role: str
    auth_provider: str
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

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
    role: str = "clevel"


class UserUpdate(BaseModel):
    display_name: str | None = None
    role: str | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8)


# ── Auth endpoints ────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    payload: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Exchange username + password for an access token and a refresh token."""
    record = await authenticate_local(db, payload.username, payload.password)
    if record is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

    user = await db.get(User, record.id)
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
    await _audit(db, user.id, "login", {}, ip=_ip(request))
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
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == rt.family_id)
            .values(revoked=True)
        )
        await _audit(db, rt.user_id, "token.family_revoked",
                     {"family_id": str(rt.family_id), "reason": "revoked_token_replay"},
                     ip=_ip(request))
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            detail="Refresh token already used — all sessions invalidated. Please log in again.")

    if rt.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        rt.revoked = True
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired.")

    user = await db.get(User, rt.user_id)
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
        await _audit(db, rt.user_id, "logout", {}, ip=_ip(request))
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
    db: Annotated[AsyncSession, Depends(get_db)],
    payload: dict[str, Any] = Body(...),
) -> None:
    """Persist the current user's UI preferences (full replace)."""
    await db.execute(update(User).where(User.id == user.id).values(prefs=payload))
    await db.commit()


# ── User management (requires engineer role) ─────────────────────────────────

@router.get("/users", response_model=list[UserOut])
async def list_users(
    _: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[User]:
    result = await db.execute(select(User).order_by(User.created_at))
    return list(result.scalars().all())


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    request: Request,
    payload: UserCreate,
    acting_user: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    if payload.role not in ROLE_HIERARCHY:
        raise HTTPException(400, detail=f"Invalid role. Choose from: {', '.join(ROLE_HIERARCHY)}")
    if payload.role == "admin" and acting_user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Only an admin can assign the 'admin' role.")
    existing = await db.execute(select(User).where(User.username == payload.username))
    if existing.scalar_one_or_none():
        raise HTTPException(409, detail=f"Username '{payload.username}' already exists.")
    user = User(
        username=payload.username,
        display_name=payload.display_name,
        role=payload.role,
        auth_provider="local",
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    await db.flush()   # get user.id before audit row
    await _audit(db, acting_user.id, "user.create", {
        "target_id": str(user.id),
        "target_username": user.username,
        "target_role": user.role,
    }, ip=_ip(request))
    await db.commit()
    await db.refresh(user)
    return user


@router.put("/users/{user_id}", response_model=UserOut)
async def update_user(
    request: Request,
    user_id: uuid.UUID,
    payload: UserUpdate,
    acting_user: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, detail="User not found.")
    if (user.role == "admin" or payload.role == "admin") and acting_user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Only an admin can modify an admin account or grant the 'admin' role.")
    changed_fields: list[str] = []
    if payload.display_name is not None:
        user.display_name = payload.display_name
        changed_fields.append("display_name")
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
    await _audit(db, acting_user.id, "user.update", {
        "target_id": str(user.id),
        "target_username": user.username,
        "fields": changed_fields,
    }, ip=_ip(request))
    await db.commit()
    await db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    request: Request,
    user_id: uuid.UUID,
    acting_user: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    if acting_user.id == user_id:
        raise HTTPException(400, detail="Cannot delete your own account.")
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, detail="User not found.")
    if user.role == "admin" and acting_user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Only an admin can delete an admin account.")
    await _audit(db, acting_user.id, "user.delete", {
        "target_id": str(user.id),
        "target_username": user.username,
        "target_role": user.role,
    }, ip=_ip(request))
    await db.delete(user)
    await db.commit()


@router.get("/users/{user_id}", response_model=UserOut)
async def get_user(
    user_id: uuid.UUID,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
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
    db: Annotated[AsyncSession, Depends(get_db)],
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

    model_config = {"from_attributes": True}


class ApiKeyCreateResponse(ApiKeyOut):
    """Returned only on creation — includes the raw key (shown once)."""
    raw_key: str


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


@router.get("/api-keys", response_model=list[ApiKeyOut])
async def list_api_keys(
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[ApiKey]:
    """List all DB-stored API keys (admin only)."""
    result = await db.execute(select(ApiKey).order_by(ApiKey.created_at))
    return list(result.scalars().all())


@router.post("/api-keys", response_model=ApiKeyCreateResponse, status_code=201)
async def create_api_key(
    payload: ApiKeyCreate,
    acting_user: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Generate a new API key (admin only). The raw key is returned once — store it securely."""
    raw_key = "wafpass_" + secrets.token_hex(24)
    key_hash = _hash(raw_key)
    key_prefix = raw_key[:16]

    api_key = ApiKey(
        name=payload.name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        created_by=acting_user.id,
        is_active=True,
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
        "raw_key": raw_key,
    }


@router.delete("/api-keys/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: uuid.UUID,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
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
    db: Annotated[AsyncSession, Depends(get_db)],
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
