"""FastAPI dependency functions for authentication and role enforcement."""
from __future__ import annotations

import hashlib
import uuid

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import PyJWTError
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.auth.jwt_utils import decode_access_token
from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import User

# Role ordering — lower index = fewer permissions.  "admin" is the highest level.
ROLE_HIERARCHY: list[str] = ["clevel", "ciso", "architect", "engineer", "admin"]

_bearer = HTTPBearer(auto_error=False)


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


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

    user = await db.get(User, uuid.UUID(payload["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive.")
    return user


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


async def require_ingest(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    x_api_key: str | None = Header(default=None, alias="X-Api-Key"),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """Accept a valid Bearer JWT (any role) OR the pre-shared API key.

    Used by POST /runs and POST /scan so that CI/CD pipelines can push
    scan results without requiring a user account.

    Returns the User on JWT auth, or None when the API key was used.
    """
    # ── API key path ──────────────────────────────────────────────────────────
    if x_api_key and settings.wafpass_api_key and x_api_key == settings.wafpass_api_key:
        return None

    # ── JWT path ──────────────────────────────────────────────────────────────
    if credentials is not None:
        try:
            payload = decode_access_token(credentials.credentials)
            if payload.get("type") != "access":
                raise ValueError
        except (PyJWTError, ValueError):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token.")

        user = await db.get(User, uuid.UUID(payload["sub"]))
        if user and user.is_active:
            return user

    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        detail="Provide a Bearer token or X-Api-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )
