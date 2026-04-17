"""Application configuration via environment variables."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://wafpass:wafpass@localhost:5432/wafpass"
    wafpass_env: str = "local"

    # CORS origins (comma-separated)
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # Path to WAF++ YAML control files used by the sandbox engine.
    # Defaults to a "controls" directory next to the server's working directory.
    wafpass_controls_dir: str = "controls"

    # ── Authentication ────────────────────────────────────────────────────────
    # IMPORTANT: set a strong random value in production.
    wafpass_jwt_secret: str = "change-me-in-production-wafpass-secret-key"
    # Access token lifetime in minutes (default 60 min).
    wafpass_jwt_expire_minutes: int = 60
    # Refresh token lifetime in days (default 7 days).
    wafpass_jwt_refresh_days: int = 7

    # Bootstrap admin user — created once on first startup if users table is empty.
    # Leave wafpass_admin_password empty to disable auto-seeding.
    wafpass_admin_username: str = "admin"
    wafpass_admin_password: str = ""
    wafpass_admin_role: str = "admin"

    # Pre-shared API key for machine-to-machine access (CI/CD --push workflow).
    # Empty = disabled.  Set X-Api-Key header to this value on POST /runs / POST /scan.
    wafpass_api_key: str = ""

    # Server-side scan settings
    # Set WAFPASS_SCAN_ENABLED=false to disable POST /scan entirely.
    wafpass_scan_enabled: bool = True
    # If set, all scan paths must resolve within this directory (path-traversal guard).
    # Leave empty to allow any path accessible to the server process (dev/local only).
    wafpass_scan_base_dir: str = ""

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
