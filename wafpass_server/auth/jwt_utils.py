"""JWT creation and verification.

Access tokens are short-lived HS256 JWTs signed with WAFPASS_JWT_SECRET.
Refresh tokens are opaque random strings stored hashed in the database.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import jwt
from jwt.exceptions import PyJWTError

from wafpass_server.config import settings

_ALGORITHM = "HS256"


def create_access_token(user_id: uuid.UUID, username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.wafpass_jwt_expire_minutes),
    }
    return jwt.encode(payload, settings.wafpass_jwt_secret, algorithm=_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and verify an access token.  Raises ``PyJWTError`` on failure."""
    return jwt.decode(token, settings.wafpass_jwt_secret, algorithms=[_ALGORITHM])
