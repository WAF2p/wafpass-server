"""Update checker API router for WAF++ framework versions."""
import asyncio
import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from wafpass_server.update_checker import check_for_updates, generate_update_info

router = APIRouter(prefix="/updates", tags=["updates"])

# Update info path - configurable via environment variable
# Default path used when WAFPASS_UPDATE_INFO_PATH is not set
_FRAMEWORK_UPDATE_INFO_PATH = "/app/framework-update-info.yml"


class UpdateCheckResult(BaseModel):
    """Result of an update check."""

    success: bool
    error: str | None = None
    framework: dict | None = None
    generated_at: str | None = None


@router.get("", response_model=UpdateCheckResult)
async def get_update_status() -> UpdateCheckResult:
    """Get the current update status and latest framework information.

    This endpoint returns the cached update information from the last check.
    The update checker runs hourly to fetch the latest commit information
    from the public WAF++ framework repository on GitHub.
    """
    try:
        result = await check_for_updates()
        if result["success"]:
            return UpdateCheckResult(
                success=True,
                framework=result.get("framework"),
                generated_at=result.get("generated_at"),
            )
        return UpdateCheckResult(
            success=False,
            error=result.get("error", "Unknown error"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/check", response_model=UpdateCheckResult)
async def force_update_check() -> UpdateCheckResult:
    """Force an immediate update check.

    This endpoint triggers an immediate check for framework updates,
    bypassing the hourly schedule.
    """
    try:
        result = await check_for_updates()
        if result["success"]:
            return UpdateCheckResult(
                success=True,
                framework=result.get("framework"),
                generated_at=result.get("generated_at"),
            )
        return UpdateCheckResult(
            success=False,
            error=result.get("error", "Unknown error"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/trigger", response_model=UpdateCheckResult)
async def trigger_update_check() -> UpdateCheckResult:
    """Trigger an immediate update check and save to file.

    This endpoint runs a full update check and saves the results
    to the framework-update-info.yml file. Unlike /check, this also
    updates the YAML file for persistence.

    The path to the YAML file can be configured via WAFPASS_UPDATE_INFO_PATH
    environment variable (default: /app/framework-update-info.yml).
    """
    try:
        info = await generate_update_info(_FRAMEWORK_UPDATE_INFO_PATH)
        return UpdateCheckResult(
            success=True,
            framework=info.framework.model_dump(),
            generated_at=info.generated_at,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
