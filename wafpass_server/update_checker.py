"""Update checker module for WAF++ framework versions.

Fetches version and commit information for the WAF++ framework directly from its
public GitHub repository.  The previous implementation required a local clone
of both German and English framework repos; this version needs no local clone
and only tracks the single canonical ``framework`` repository.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml
from pydantic import BaseModel

from wafpass_server.config import settings

logger = logging.getLogger("wafpass_server")


class CommitInfo(BaseModel):
    """Information about the latest commit."""

    hash: str
    author: str
    date: str
    message: str


class VersionInfo(BaseModel):
    """Version information for a framework."""

    current: str
    display: str
    prerelease: bool


class FrameworkInfo(BaseModel):
    """Information about the framework."""

    repo_url: str
    git_branch: str
    last_commit: CommitInfo
    version: VersionInfo


class UpdateInfo(BaseModel):
    """Complete update information."""

    version: str
    generated_at: str
    service: str
    framework: FrameworkInfo
    checks: dict[str, Any]


def _github_api(repo_url: str, path: str, branch: str) -> dict[str, Any]:
    """Call the GitHub API for a repo-relative path.

    Supports both ``https://github.com/owner/repo`` URLs and existing
    GitHub API URLs.  Returns the parsed JSON response.
    """
    parsed = urlparse(repo_url)
    if parsed.netloc == "github.com" and parsed.path.strip("/"):
        owner_repo = parsed.path.strip("/").removesuffix(".git")
        api_base = f"https://api.github.com/repos/{owner_repo}"
    else:
        api_base = repo_url.rstrip("/")

    url = f"{api_base}{path}"
    headers: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    resp = httpx.get(url, headers=headers, timeout=30, follow_redirects=True)
    resp.raise_for_status()
    return resp.json()


def get_latest_commit_info(repo_url: str, branch: str) -> CommitInfo:
    """Get the latest commit information from a GitHub repository."""
    data = _github_api(repo_url, f"/commits/{branch}", branch)
    commit = data.get("commit", {})
    committer = commit.get("committer", {})
    author = commit.get("author", {})

    return CommitInfo(
        hash=data.get("sha", ""),
        author=author.get("name", committer.get("name", "unknown")),
        date=committer.get("date", "unknown"),
        message=commit.get("message", "").split("\n", 1)[0],
    )


async def get_latest_commit_info_async(repo_url: str, branch: str) -> CommitInfo:
    """Async wrapper for get_latest_commit_info."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, get_latest_commit_info, repo_url, branch)


def get_version_info(repo_url: str, branch: str) -> VersionInfo:
    """Get version information from the latest GitHub release tag.

    Falls back to the framework's antora.yml file if no releases exist.
    """
    try:
        data = _github_api(repo_url, "/releases/latest", branch)
        tag = str(data.get("tag_name", "")).strip()
        if tag:
            return VersionInfo(
                current=tag,
                display=tag,
                prerelease=bool(data.get("prerelease", False)),
            )
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code != 404:
            raise
        # No releases yet — fall through to antora.yml

    # Fallback: read version from antora.yml on the configured branch
    data = _github_api(
        repo_url,
        f"/contents/antora.yml?ref={branch}",
        branch,
    )

    content_b64 = data.get("content", "")
    if data.get("encoding") == "base64":
        content = base64.b64decode(content_b64).decode("utf-8")
    else:
        content = content_b64

    antora_data = yaml.safe_load(content) or {}

    return VersionInfo(
        current=str(antora_data.get("version", "unknown")),
        display=str(antora_data.get("display_version", "Unknown")),
        prerelease=bool(antora_data.get("prerelease", False)),
    )


async def get_version_info_async(repo_url: str, branch: str) -> VersionInfo:
    """Async wrapper for get_version_info."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, get_version_info, repo_url, branch)


def load_existing_update_info(yaml_path: str) -> UpdateInfo:
    """Load existing update info from YAML file."""
    path = Path(yaml_path)
    if not path.exists():
        raise FileNotFoundError(f"Update info file not found: {yaml_path}")

    with open(path, "r") as f:
        data = yaml.safe_load(f)

    return UpdateInfo(**data)


def save_update_info(info: UpdateInfo, yaml_path: str) -> None:
    """Save update info to YAML file."""
    path = Path(yaml_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as f:
        f.write(yaml.dump(info.model_dump(), default_flow_style=False, sort_keys=False))


async def run_git_update_check(repo_url: str, branch: str) -> tuple[CommitInfo, VersionInfo]:
    """Run remote update check for the framework repo."""
    loop = asyncio.get_event_loop()

    # Run blocking HTTP operations in thread pool
    commit_info = await loop.run_in_executor(
        None, get_latest_commit_info, repo_url, branch
    )
    version_info = await loop.run_in_executor(
        None, get_version_info, repo_url, branch
    )

    return commit_info, version_info


async def generate_update_info(
    yaml_path: str = "/app/framework-update-info.yml",
    send_notifications: bool = True,
) -> UpdateInfo:
    """Generate complete update information from the remote framework repo.

    Args:
        yaml_path: Path to the update info YAML file
        send_notifications: Whether to send admin notifications for updates

    Returns:
        Complete UpdateInfo object with information from the framework repo
    """
    from wafpass_server.database import AsyncSessionLocal
    from wafpass_server.models import Notification

    repo_url = os.environ.get(
        "WAFPASS_FRAMEWORK_REPO_URL", settings.wafpass_framework_repo_url
    )
    branch = os.environ.get("WAFPASS_FRAMEWORK_BRANCH", settings.wafpass_framework_branch)

    now = datetime.now(timezone.utc)
    now_str = now.isoformat()

    commit, version = await run_git_update_check(repo_url, branch)

    # Check for updates by comparing with previously stored hash
    update_msg = ""
    try:
        old_info = load_existing_update_info(yaml_path)
        old_hash = old_info.framework.last_commit.hash
        if old_hash != commit.hash:
            update_msg = f"Framework updated: {old_hash[:8]} -> {commit.hash[:8]}"
    except FileNotFoundError:
        pass

    update_info = UpdateInfo(
        version=version.current,
        generated_at=now_str,
        service="wafpass-server",
        framework=FrameworkInfo(
            repo_url=repo_url,
            git_branch=branch,
            last_commit=commit,
            version=version,
        ),
        checks={
            "last_run": now_str,
            "next_run": "",
            "status": "success",
            "error": None,
        },
    )

    save_update_info(update_info, yaml_path)

    if send_notifications and update_msg:
        await _send_update_notifications(update_msg)

    return update_info


async def _send_update_notifications(message: str) -> None:
    """Send notifications to all admin users about framework updates."""
    try:
        from wafpass_server.database import AsyncSessionLocal
        from wafpass_server.models import User

        async with AsyncSessionLocal() as db:
            from sqlalchemy import select

            stmt = select(User).where(User.role == "admin", User.is_active == True)
            result = await db.execute(stmt)
            admins = list(result.scalars().all())

            if not admins:
                return

            notification = Notification(
                title="Framework Update Detected",
                message=f"Framework update detected\n\n{message}",
                category="urgent",
                triggered_by="system",
                target_role="admin",
            )
            for _ in admins:
                db.add(notification)

            await db.commit()
            logger.info(f"Sent {len(admins)} framework update notifications")
    except Exception as e:
        logger.error(f"Failed to send update notifications: {e}")


async def check_for_updates() -> dict[str, Any]:
    """Check for updates and return the update information.

    This is the main entry point for the update checker.
    """
    yaml_path = "/app/framework-update-info.yml"

    try:
        info = await generate_update_info(yaml_path)
        return {
            "success": True,
            "framework": info.framework.model_dump(),
            "generated_at": info.generated_at,
        }
    except Exception as e:
        logger.error(f"Update check failed: {e}")
        return {
            "success": False,
            "error": str(e),
        }
