"""Database-backed remote syslog/SIEM forwarding for admin/security audit events.

The singleton ``SyslogConfig`` row (table ``syslog_configs``) drives every
setting, including per-action severity overrides. Forwarding is always
fire-and-forget so syslog/SIEM unavailability never blocks an API request.
"""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass_server.database import AsyncSessionLocal
from wafpass_server.models import SyslogConfig

logger = logging.getLogger(__name__)

# Standard syslog severity levels
SEVERITY_EMERGENCY = 0
SEVERITY_ALERT = 1
SEVERITY_CRITICAL = 2
SEVERITY_ERROR = 3
SEVERITY_WARNING = 4
SEVERITY_NOTICE = 5
SEVERITY_INFO = 6
SEVERITY_DEBUG = 7


def _default_severity_for_action(action: str) -> int:
    """Map an audit action to a syslog severity when no override is set."""
    lower = action.lower()
    if any(k in lower for k in ("delete", "revoke", "failed", "fail")):
        return SEVERITY_WARNING
    if any(k in lower for k in ("error", "denied", "unauthorized")):
        return SEVERITY_ERROR
    return SEVERITY_INFO


def _severity_for_action(action: str, overrides: dict[str, Any]) -> int:
    """Resolve severity using per-action overrides, falling back to defaults."""
    if action in overrides:
        return int(overrides[action])
    return _default_severity_for_action(action)


def _build_rfc3164(
    facility: int,
    severity: int,
    hostname: str,
    timestamp: datetime,
    program_tag: str,
    msg: str,
) -> bytes:
    """Build a classic RFC 3164 syslog message."""
    pri = facility * 8 + severity
    ts = timestamp.strftime("%b %d %H:%M:%S")
    # Truncate long hostnames and append the program tag per convention.
    return f"<{pri}>{ts} {hostname} {program_tag} {msg}".encode("utf-8")


def _build_rfc5424(
    facility: int,
    severity: int,
    hostname: str,
    timestamp: datetime,
    program_tag: str,
    msg: str,
    structured_data: str = "-",
) -> bytes:
    """Build a structured RFC 5424 syslog message."""
    pri = facility * 8 + severity
    ts = timestamp.isoformat()
    return f"<{pri}>1 {ts} {hostname} {program_tag} - - {structured_data} {msg}".encode("utf-8")


def build_syslog_message(
    config: SyslogConfig,
    action: str,
    detail: dict,
    ip: str = "",
    mandant_id: str | None = None,
    actor_id: str | None = None,
    timestamp: datetime | None = None,
) -> bytes:
    """Serialize one audit event into a syslog payload."""
    ts = timestamp or datetime.now(timezone.utc)
    hostname = socket.gethostname()
    severity = _severity_for_action(action, config.severity_overrides or {})
    payload = {
        "action": action,
        "actor_id": str(actor_id) if actor_id else None,
        "ip": ip,
        "mandant_id": str(mandant_id) if mandant_id else None,
        "detail": detail,
    }
    msg = json.dumps(payload, separators=(",", ":"), default=str)

    if config.syslog_format == "rfc3164":
        return _build_rfc3164(config.facility, severity, hostname, ts, config.program_tag, msg)
    return _build_rfc5424(
        config.facility,
        severity,
        hostname,
        ts,
        config.program_tag,
        msg,
        structured_data=f'[wafpass@1 action="{action}"]',
    )


async def _ensure_config(session: AsyncSession) -> SyslogConfig:
    """Return the singleton syslog config row, creating defaults if necessary."""
    result = await session.execute(select(SyslogConfig).where(SyslogConfig.id == 1))
    config = result.scalar_one_or_none()
    if config is None:
        config = SyslogConfig()
        session.add(config)
        await session.commit()
    return config


async def get_syslog_config(session: AsyncSession) -> SyslogConfig:
    """Read the singleton syslog configuration from the database."""
    return await _ensure_config(session)


async def update_syslog_config(session: AsyncSession, data: dict[str, Any]) -> SyslogConfig:
    """Replace the singleton syslog configuration row with ``data``."""
    config = await _ensure_config(session)
    for key, value in data.items():
        if hasattr(config, key):
            setattr(config, key, value)
    await session.commit()
    await session.refresh(config)
    return config


async def _try_send(
    config: SyslogConfig,
    action: str,
    detail: dict,
    ip: str = "",
    mandant_id: str | None = None,
    actor_id: str | None = None,
    timestamp: datetime | None = None,
) -> tuple[bool, str]:
    """Build and send one packet; return (success, message)."""
    if not config.host:
        return False, "No syslog host configured"
    try:
        message = build_syslog_message(
            config, action, detail, ip, mandant_id, actor_id, timestamp
        )
        await send_syslog(
            message,
            config.host,
            config.port,
            config.protocol,
            tls_enabled=config.tls_enabled,
        )
        return True, f"Sent {len(message)} bytes to {config.host}:{config.port}"
    except Exception as exc:
        return False, str(exc)


async def send_syslog(
    message: bytes,
    host: str,
    port: int,
    protocol: str = "udp",
    tls_enabled: bool = False,
    timeout: float = 5.0,
) -> None:
    """Send a single syslog datagram/message to the configured endpoint."""
    if protocol.lower() == "tcp":
        ssl_context: ssl.SSLContext | None = None
        if tls_enabled:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context),
            timeout=timeout,
        )
        try:
            writer.write(message + b"\n")
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    else:
        loop = asyncio.get_running_loop()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setblocking(False)
            await asyncio.wait_for(
                loop.sock_sendto(sock, message, (host, port)),
                timeout=timeout,
            )


def emit_admin_audit_event(
    action: str,
    detail: dict,
    ip: str = "",
    mandant_id: str | None = None,
    actor_id: str | None = None,
    timestamp: datetime | None = None,
) -> None:
    """Forward an admin audit event to syslog if enabled.

    The actual database read and network I/O are scheduled as a separate
    asyncio task so request handlers never wait on syslog.
    """

    async def _forward() -> None:
        async with AsyncSessionLocal() as session:
            try:
                config = await _ensure_config(session)
                if not config.enabled or not config.host:
                    return
                success, message = await _try_send(
                    config, action, detail, ip, mandant_id, actor_id, timestamp
                )
                if not success:
                    logger.warning("Failed to forward admin audit event to syslog: %s", message)
            except Exception as exc:
                logger.warning("Could not forward admin audit event to syslog: %s", exc)

    try:
        asyncio.create_task(_forward())
    except Exception as exc:
        logger.warning("Could not schedule syslog forward: %s", exc)


async def test_syslog_config(session: AsyncSession) -> tuple[bool, str]:
    """Send a single test message using the configured singleton settings."""
    config = await _ensure_config(session)
    return await _try_send(
        config,
        "syslog_test",
        {"message": "WAF++ PASS syslog test event"},
    )
