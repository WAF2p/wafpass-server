"""Application configuration via environment variables."""
from __future__ import annotations

import os
import secrets

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEFAULT_JWT_SECRET = "change-me-in-production-wafpass-secret-key"
_JWT_SECRET_PLACEHOLDERS = {_DEFAULT_JWT_SECRET, "", "change-me-in-production"}


def _generate_random_secret() -> str:
    """Return a URL-safe random secret suitable for JWT signing."""
    return secrets.token_urlsafe(32)


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
    wafpass_jwt_secret: str = _DEFAULT_JWT_SECRET
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

    # Public base URL used to build absolute links in QR codes and audit reports.
    # Set this to the externally reachable address of the server, e.g.
    # https://wafpass.example.com  (no trailing slash).
    # Falls back to the Host header of the incoming request when left empty.
    wafpass_public_url: str = ""

    # Server-side scan settings
    # Set WAFPASS_SCAN_ENABLED=false to disable POST /scan entirely.
    wafpass_scan_enabled: bool = True
    # If set, all scan paths must resolve within this directory (path-traversal guard).
    # Leave empty to allow any path accessible to the server process (dev/local only).
    wafpass_scan_base_dir: str = ""

    # Optional waivers file used by the auto-fixer to skip waived checks.
    wafpass_waivers_file: str = ""

    # Base path for WAF++ framework repositories.
    # Legacy: used by the update checker to locate a local framework clone.
    # Defaults to /app for containerized deployments.
    wafpass_base_path: str = "/app"

    # Public Git URL for the WAF++ framework repository.
    # The update checker fetches version and commit information from this repo.
    wafpass_framework_repo_url: str = "https://github.com/WAF2p/framework"

    # Branch to read framework version/commit information from.
    wafpass_framework_branch: str = "main"

    # ── At-rest encryption for SSO secrets ───────────────────────────────────
    # Backend: "local" (default) | "aws_sm" | "vault_transit"
    wafpass_secrets_backend: str = "local"

    # Local backend — provide a Fernet-compatible key (32 bytes, URL-safe base64)
    # or any passphrase (PBKDF2-derived).  Defaults to derivation from
    # WAFPASS_JWT_SECRET when empty — set this explicitly in production.
    wafpass_encryption_key: str = ""

    # AWS Secrets Manager backend
    aws_region: str = "us-east-1"

    # HashiCorp Vault Transit backend
    vault_addr: str = "http://127.0.0.1:8200"
    vault_token: str = ""
    vault_transit_key: str = "wafpass"
    vault_transit_mount: str = "transit"

    @model_validator(mode="after")
    def _validate_secrets(self) -> "Settings":
        """Enforce strong secrets on every explicit Settings() construction."""
        if self.wafpass_jwt_secret in _JWT_SECRET_PLACEHOLDERS:
            raise ValueError(
                "WAFPASS_JWT_SECRET must be set to a strong random value. "
                "The default / placeholder value is not allowed in any environment. "
                "Generate a random 32-byte secret and set it via the WAFPASS_JWT_SECRET "
                "environment variable. If you are running locally, use 'wafpass init --mode dashboard' "
                "to generate a valid .env file."
            )
        if self.wafpass_env != "local" and not self.wafpass_encryption_key:
            raise ValueError(
                "WAFPASS_ENCRYPTION_KEY must be set in non-local environments. "
                "Without it, SSO secrets are derived from WAFPASS_JWT_SECRET, "
                "which is insecure if that secret is ever rotated or leaked."
            )
        return self

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


def validate_runtime_settings() -> None:
    """Validate that the running server has production-grade secrets.

    Called once during application startup. Import-time construction of the
    global `settings` singleton is intentionally permissive for tests/CI.
    """
    if settings.wafpass_env == "local":
        return
    if settings.wafpass_jwt_secret in _JWT_SECRET_PLACEHOLDERS:
        raise ValueError(
            "WAFPASS_JWT_SECRET must be set to a strong random value. "
            "The default / placeholder value is not allowed in any environment. "
            "Generate a random 32-byte secret and set it via the WAFPASS_JWT_SECRET "
            "environment variable."
        )
    if not settings.wafpass_encryption_key:
        raise ValueError(
            "WAFPASS_ENCRYPTION_KEY must be set in non-local environments. "
            "Without it, SSO secrets are derived from WAFPASS_JWT_SECRET, "
            "which is insecure if that secret is ever rotated or leaked."
        )


def _load_settings() -> Settings:
    """Load settings safely for import-time use.

    In local/test environments we auto-generate a random JWT secret if none is
    configured, so that importing the package never raises during pytest
    collection. Explicit Settings() construction still enforces strong secrets.
    """
    # When the environment explicitly requests a non-local profile, let pydantic
    # run normally so misconfiguration surfaces immediately.
    explicit_env = os.environ.get("WAFPASS_ENV", "local")
    if explicit_env != "local":
        return Settings()

    # Local mode: if the secret is still the placeholder, use a generated value.
    env_secret = os.environ.get("WAFPASS_JWT_SECRET", _DEFAULT_JWT_SECRET)
    if env_secret in _JWT_SECRET_PLACEHOLDERS:
        return Settings(wafpass_jwt_secret=_generate_random_secret(), wafpass_env="local")
    return Settings()


settings = _load_settings()
