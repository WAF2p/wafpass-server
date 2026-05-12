"""Local password authentication — bcrypt hashing."""
from __future__ import annotations

import bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.models import User

from .base import UserRecord


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


async def authenticate_local(
    db: AsyncSession,
    username: str,
    password: str,
) -> UserRecord | None:
    """Return a UserRecord if *username* + *password* match a local user, else None."""
    result = await db.execute(
        select(User).where(
            User.username == username,
            User.auth_provider == "local",
            User.is_active.is_(True),
        )
    )
    user = result.scalar_one_or_none()
    if user is None or user.password_hash is None:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return UserRecord(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        role=user.role,
        auth_provider=user.auth_provider,
    )
