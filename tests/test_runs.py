"""Smoke tests for the /runs endpoints.

Integration tests require a running PostgreSQL instance. Set DATABASE_URL
in the environment or .env file before running.
"""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_placeholder() -> None:
    """Placeholder — replace with real integration tests once DB is available."""
    assert True
