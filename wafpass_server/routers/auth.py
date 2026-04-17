"""Authentication endpoints: login, refresh, logout, /me, and user management."""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.deps import ROLE_HIERARCHY, get_current_user, require_role
from wafpass_server.auth.jwt_utils import create_access_token
from wafpass_server.auth.providers.local import authenticate_local, hash_password
from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import RefreshToken, User

router = APIRouter(prefix="/auth", tags=["auth"])


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


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
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.wafpass_jwt_refresh_days),
    )
    db.add(rt)
    await db.commit()

    return {
        "access_token": access_token,
        "refresh_token": raw_refresh,
        "token_type": "bearer",
        "user": user,
    }


@router.post("/refresh", response_model=AccessTokenResponse)
async def refresh_token(
    payload: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Exchange a valid refresh token for a new access token."""
    token_hash = _hash(payload.refresh_token)
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked.is_(False),
        )
    )
    rt = result.scalar_one_or_none()

    if rt is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found or revoked.")

    if rt.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        rt.revoked = True
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired.")

    user = await db.get(User, rt.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive.")

    return {
        "access_token": create_access_token(user.id, user.username, user.role),
        "token_type": "bearer",
    }


@router.post("/logout", status_code=204)
async def logout(
    payload: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Revoke the supplied refresh token."""
    token_hash = _hash(payload.refresh_token)
    result = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
    rt = result.scalar_one_or_none()
    if rt:
        rt.revoked = True
        await db.commit()


@router.get("/me", response_model=UserOut)
async def me(
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Return the authenticated user's profile."""
    return user


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
    payload: UserCreate,
    acting_user: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    if payload.role not in ROLE_HIERARCHY:
        raise HTTPException(400, detail=f"Invalid role. Choose from: {', '.join(ROLE_HIERARCHY)}")
    # Only an admin can create another admin
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
    await db.commit()
    await db.refresh(user)
    return user


@router.put("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    acting_user: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, detail="User not found.")
    # Only an admin can modify an admin account or promote to admin
    if (user.role == "admin" or payload.role == "admin") and acting_user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Only an admin can modify an admin account or grant the 'admin' role.")
    if payload.display_name is not None:
        user.display_name = payload.display_name
    if payload.role is not None:
        if payload.role not in ROLE_HIERARCHY:
            raise HTTPException(400, detail=f"Invalid role. Choose from: {', '.join(ROLE_HIERARCHY)}")
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.password is not None:
        user.password_hash = hash_password(payload.password)
    await db.commit()
    await db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: uuid.UUID,
    acting_user: Annotated[User, Depends(require_role("engineer"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    if acting_user.id == user_id:
        raise HTTPException(400, detail="Cannot delete your own account.")
    user = await db.get(User, user_id)
    if user is None:
        raise HTTPException(404, detail="User not found.")
    # Only an admin can delete another admin account
    if user.role == "admin" and acting_user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Only an admin can delete an admin account.")
    await db.delete(user)
    await db.commit()
