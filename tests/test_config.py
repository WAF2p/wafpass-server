"""Tests for wafpass_server.config startup validation."""

from __future__ import annotations

import pytest

from wafpass_server.config import Settings


class TestSettingsValidation:
    def test_accepts_strong_jwt_secret_in_local(self) -> None:
        settings = Settings(
            wafpass_jwt_secret="a-very-strong-random-secret-key-32-bytes",
            wafpass_admin_password="admin",
        )
        assert settings.wafpass_jwt_secret != "change-me-in-production"

    def test_rejects_default_jwt_secret(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            Settings(
                wafpass_jwt_secret="change-me-in-production-wafpass-secret-key",
                wafpass_admin_password="admin",
            )
        assert "WAFPASS_JWT_SECRET" in str(exc_info.value)

    def test_rejects_empty_jwt_secret(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            Settings(
                wafpass_jwt_secret="",
                wafpass_admin_password="admin",
            )
        assert "WAFPASS_JWT_SECRET" in str(exc_info.value)

    def test_rejects_change_me_placeholder(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            Settings(
                wafpass_jwt_secret="change-me-in-production",
                wafpass_admin_password="admin",
            )
        assert "WAFPASS_JWT_SECRET" in str(exc_info.value)

    def test_requires_encryption_key_in_non_local(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            Settings(
                wafpass_env="staging",
                wafpass_jwt_secret="a-very-strong-random-secret-key-32-bytes",
                wafpass_admin_password="admin",
            )
        assert "WAFPASS_ENCRYPTION_KEY" in str(exc_info.value)

    def test_allows_non_local_with_encryption_key(self) -> None:
        settings = Settings(
            wafpass_env="staging",
            wafpass_jwt_secret="a-very-strong-random-secret-key-32-bytes",
            wafpass_admin_password="admin",
            wafpass_encryption_key="a" * 32,
        )
        assert settings.wafpass_env == "staging"
