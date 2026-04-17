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
