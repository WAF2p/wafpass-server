"""Tests for the admin/security audit log endpoint and syslog helper."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.models import SyslogConfig, User, UserAuditLog
from wafpass_server.syslog import build_syslog_message


async def _seed_admin_user(db: AsyncSession, role: str = "admin") -> User:
    user = User(
        id=uuid.uuid4(),
        username=f"{role}-tester",
        display_name="Test",
        role=role,
        auth_provider="local",
        password_hash="x",
    )
    db.add(user)
    await db.commit()
    return user


async def _seed_log(db: AsyncSession, actor: User | None, action: str) -> UserAuditLog:
    log = UserAuditLog(
        id=uuid.uuid4(),
        actor_id=actor.id if actor else None,
        action=action,
        detail={"foo": "bar"},
        ip="127.0.0.1",
        timestamp=datetime.now(timezone.utc),
    )
    db.add(log)
    await db.commit()
    return log


@pytest.mark.asyncio
async def test_admin_logs_require_admin(app_client: AsyncClient, db: AsyncSession) -> None:
    user = await _seed_admin_user(db, role="engineer")
    app_client.headers["Authorization"] = f"Bearer {user.username}"
    resp = await app_client.get("/api/v1/admin/logs")
    assert resp.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_admin_logs_lists_events(app_client: AsyncClient, db: AsyncSession) -> None:
    admin = await _seed_admin_user(db, role="admin")
    app_client.headers["Authorization"] = f"Bearer {admin.username}"
    await _seed_log(db, admin, "login")
    await _seed_log(db, admin, "user.create")

    resp = await app_client.get("/api/v1/admin/logs")
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()["data"]
    assert len(data) == 2
    actions = {e["action"] for e in data}
    assert actions == {"login", "user.create"}
    # actor username resolved
    assert data[0]["actor_username"] == admin.username


@pytest.mark.asyncio
async def test_admin_logs_action_filter(app_client: AsyncClient, db: AsyncSession) -> None:
    admin = await _seed_admin_user(db, role="admin")
    app_client.headers["Authorization"] = f"Bearer {admin.username}"
    await _seed_log(db, admin, "login")
    await _seed_log(db, admin, "logout")

    resp = await app_client.get("/api/v1/admin/logs?action=login")
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()["data"]
    assert len(data) == 1
    assert data[0]["action"] == "login"


@pytest.mark.asyncio
async def test_admin_logs_limit(app_client: AsyncClient, db: AsyncSession) -> None:
    admin = await _seed_admin_user(db, role="admin")
    app_client.headers["Authorization"] = f"Bearer {admin.username}"
    for _ in range(5):
        await _seed_log(db, admin, "login")

    resp = await app_client.get("/api/v1/admin/logs?limit=2")
    assert resp.status_code == status.HTTP_200_OK
    assert len(resp.json()["data"]) == 2


@pytest.mark.asyncio
async def test_syslog_config_requires_admin(app_client: AsyncClient, db: AsyncSession) -> None:
    user = await _seed_admin_user(db, role="engineer")
    app_client.headers["Authorization"] = f"Bearer {user.username}"
    resp = await app_client.get("/api/v1/admin/syslog-config")
    assert resp.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_syslog_config_crud(app_client: AsyncClient, db: AsyncSession) -> None:
    admin = await _seed_admin_user(db, role="admin")
    app_client.headers["Authorization"] = f"Bearer {admin.username}"

    resp = await app_client.get("/api/v1/admin/syslog-config")
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()["data"]
    assert data["enabled"] is False
    assert data["host"] == ""

    payload = {
        "enabled": True,
        "host": "syslog.example.com",
        "port": 514,
        "protocol": "tcp",
        "syslog_format": "rfc5424",
        "facility": 13,
        "tls_enabled": True,
        "program_tag": "wafpass-admin",
        "severity_overrides": {"login_success": 3},
    }
    resp = await app_client.put("/api/v1/admin/syslog-config", json=payload)
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()["data"]
    assert data["enabled"] is True
    assert data["host"] == "syslog.example.com"
    assert data["protocol"] == "tcp"
    assert data["tls_enabled"] is True
    assert data["severity_overrides"] == {"login_success": 3}

    resp = await app_client.get("/api/v1/admin/syslog-config")
    assert resp.json()["data"]["host"] == "syslog.example.com"


@pytest.mark.asyncio
async def test_syslog_config_test_endpoint_no_host(app_client: AsyncClient, db: AsyncSession) -> None:
    admin = await _seed_admin_user(db, role="admin")
    app_client.headers["Authorization"] = f"Bearer {admin.username}"
    resp = await app_client.post("/api/v1/admin/syslog-config/test")
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["data"]["success"] is False


def test_build_syslog_message_rfc5424() -> None:
    config = SyslogConfig(facility=13, syslog_format="rfc5424", program_tag="wafpass-admin")
    msg = build_syslog_message(
        config,
        action="login",
        detail={"user": "alice"},
        ip="10.0.0.1",
        actor_id=str(uuid.uuid4()),
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
    )
    assert msg.startswith(b"<110>1 2026-01-01T12:00:00+00:00")
    assert b'"action":"login"' in msg


def test_build_syslog_message_rfc3164() -> None:
    config = SyslogConfig(facility=13, syslog_format="rfc3164", program_tag="wafpass-admin")
    msg = build_syslog_message(config, action="logout", detail={}, ip="")
    assert msg.startswith(b"<110>")
    assert b"wafpass-admin" in msg


def test_build_syslog_message_severity_override() -> None:
    config = SyslogConfig(
        facility=13,
        syslog_format="rfc5424",
        program_tag="wafpass-admin",
        severity_overrides={"login": 3},
    )
    msg = build_syslog_message(config, action="login", detail={}, ip="")
    # facility 13, severity 3 => PRI = 13*8 + 3 = 107
    assert msg.startswith(b"<107>")
