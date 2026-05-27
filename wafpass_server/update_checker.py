"""Update checker module for WAF++ framework versions.

This module provides functionality to check for framework updates from
the German and English GitHub repositories and generate update information.
"""
import asyncio
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

from wafpass_server.config import settings


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
    """Information about a single framework (DE or EN)."""
    repo_path: str
    git_branch: str
    last_commit: CommitInfo
    version: VersionInfo


class UpdateInfo(BaseModel):
    """Complete update information."""
    version: str
    generated_at: str
    service: str
    framework_de: FrameworkInfo
    framework_en: FrameworkInfo
    checks: dict[str, Any]


def get_latest_commit_info(repo_path: str, branch: str) -> CommitInfo:
    """Get the latest commit information from a git repository."""
    repo_full_path = Path(repo_path)

    if not repo_full_path.exists():
        raise ValueError(f"Repository path does not exist: {repo_path}")

    # Get the latest commit details
    result = subprocess.run(
        ["git", "-C", repo_path, "log", "-1", "--format=%H|%an|%ai|%s"],
        capture_output=True,
        text=True,
        check=True,
    )

    parts = result.stdout.strip().split("|", 3)
    if len(parts) != 4:
        raise ValueError(f"Failed to parse git log output: {result.stdout}")

    return CommitInfo(
        hash=parts[0],
        author=parts[1],
        date=parts[2],
        message=parts[3],
    )


async def get_latest_commit_info_async(repo_path: str, branch: str) -> CommitInfo:
    """Async wrapper for get_latest_commit_info."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, get_latest_commit_info, repo_path, branch)


def get_version_info(repo_path: str) -> VersionInfo:
    """Get version information from the framework's antora.yml file."""
    antora_path = Path(repo_path) / "antora.yml"

    with open(antora_path, "r") as f:
        antora_data = yaml.safe_load(f)

    return VersionInfo(
        current=antora_data.get("version", "unknown"),
        display=antora_data.get("display_version", "Unknown"),
        prerelease=antora_data.get("prerelease", False),
    )


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


async def run_git_update_check(framework_path: str, branch: str) -> tuple[CommitInfo, VersionInfo]:
    """Run git update check for a single framework.

    This function is designed to be run in an asyncio context.
    """
    loop = asyncio.get_event_loop()

    # Run blocking git operations in thread pool
    commit_info = await loop.run_in_executor(
        None, get_latest_commit_info, framework_path, branch
    )
    version_info = await loop.run_in_executor(
        None, get_version_info, framework_path
    )

    return commit_info, version_info


async def generate_update_info(
    yaml_path: str = "/app/framework-update-info.yml",
    send_notifications: bool = True,
) -> UpdateInfo:
    """Generate complete update information from both frameworks.

    Args:
        yaml_path: Path to the update info YAML file
        send_notifications: Whether to send admin notifications for updates

    Returns:
        Complete UpdateInfo object with information from both frameworks
    """
    from wafpass_server.database import AsyncSessionLocal
    from wafpass_server.models import Notification
    from wafpass_server.schemas import Envelope

    # Get base path from settings or environment
    from wafpass_server.config import settings

    base_path = os.environ.get("WAFPASS_BASE_PATH", settings.wafpass_base_path)
    base = Path(base_path)

    # Paths to framework repositories
    framework_de_path = str(base / "framework")
    framework_en_path = str(base / "framework-en")

    # Get current timestamp
    now = datetime.now(timezone.utc)
    now_str = now.isoformat()

    # Get commit and version info for both frameworks
    commit_de, version_de = await run_git_update_check(framework_de_path, "main-de")
    commit_en, version_en = await run_git_update_check(framework_en_path, "main-en")

    # Check for updates by comparing with previously stored hashes
    updates_detected = False
    de_update_msg = ""
    en_update_msg = ""

    try:
        old_info = load_existing_update_info(yaml_path)
        old_de_hash = old_info.framework_de.last_commit.hash
        old_en_hash = old_info.framework_en.last_commit.hash

        if old_de_hash != commit_de.hash:
            updates_detected = True
            de_update_msg = f"DE framework updated: {old_de_hash[:8]} -> {commit_de.hash[:8]}"
        if old_en_hash != commit_en.hash:
            updates_detected = True
            en_update_msg = f"EN framework updated: {old_en_hash[:8]} -> {commit_en.hash[:8]}"
    except FileNotFoundError:
        # First run - no old info exists
        pass

    # Build the update info object
    update_info = UpdateInfo(
        version="1.1",
        generated_at=now_str,
        service="wafpass-server",
        framework_de=FrameworkInfo(
            repo_path=framework_de_path,
            git_branch="main-de",
            last_commit=commit_de,
            version=version_de,
        ),
        framework_en=FrameworkInfo(
            repo_path=framework_en_path,
            git_branch="main-en",
            last_commit=commit_en,
            version=version_en,
        ),
        checks={
            "last_run": now_str,
            "status": "success",
            "error": None,
        },
    )

    # Save to YAML file
    save_update_info(update_info, yaml_path)

    # Send notifications to admins if updates were detected
    if send_notifications and updates_detected:
        await _send_update_notifications(de_update_msg, en_update_msg)

    return update_info


async def _send_update_notifications(de_msg: str, en_msg: str) -> None:
    """Send notifications to all admin users about framework updates."""
    try:
        from wafpass_server.database import AsyncSessionLocal
        from wafpass_server.models import User

        async with AsyncSessionLocal() as db:
            # Fetch all admin users
            from sqlalchemy import select
            stmt = select(User).where(User.role == "admin", User.is_active == True)
            result = await db.execute(stmt)
            admins = list(result.scalars().all())

            if not admins:
                return

            # Build notification message
            parts = []
            if de_msg:
                parts.append(f"**DE**: {de_msg}")
            if en_msg:
                parts.append(f"**EN**: {en_msg}")

            message = "Framework update detected\\n\\n" + "\\n".join(parts)

            # Create notification for each admin
            for admin in admins:
                notification = Notification(
                    title="Framework Update Detected",
                    message=message,
                    category="urgent",
                    triggered_by="system",
                    target_role="admin",
                )
                db.add(notification)

            await db.commit()
            logging.getLogger("wafpass_server").info(
                f"Sent {len(admins)} framework update notifications"
            )
    except Exception as e:
        logging.getLogger("wafpass_server").error(
            f"Failed to send update notifications: {e}"
        )


async def check_for_updates() -> dict[str, Any]:
    """Check for updates and return the update information.

    This is the main entry point for the update checker.
    """
    yaml_path = "/app/framework-update-info.yml"

    try:
        info = await generate_update_info(yaml_path)
        return {
            "success": True,
            "framework_de": info.framework_de.model_dump(),
            "framework_en": info.framework_en.model_dump(),
            "generated_at": info.generated_at,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }
