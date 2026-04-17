"""Abstract auth-provider protocol — shared by local, LDAP, and OIDC providers."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Protocol


@dataclass
class UserRecord:
    """Minimal user representation returned by every provider."""
    id: uuid.UUID
    username: str
    display_name: str
    role: str
    auth_provider: str


class AuthProvider(Protocol):
    """Interface every concrete provider must satisfy."""

    async def authenticate(self, username: str, password: str) -> UserRecord | None:
        """Return a UserRecord on success, None on bad credentials."""
        ...
