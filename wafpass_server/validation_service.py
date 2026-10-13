"""Server-side cryptographic validation service for WAF++ PASS.

This module loads the WAF++ root CA and server intermediate keys, signs
validation records, and provides the trust anchor needed by verifiers.

Key material is loaded from the file system. In production these files
should be mounted as secrets (e.g. Kubernetes secret, AWS KMS-backed PEM,
HashiCorp Vault).
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wafpass.attestation import (
    build_server_validation,
    compute_run_hash,
    generate_root_certificate,
    generate_server_certificate,
    load_signing_key,
    sign_revocation_list,
    sign_run,
    verify_local_attestation,
)
from wafpass.schema import LocalAttestationSchema, ServerValidationSchema, WafpassResultSchema


class ValidationService:
    """Holds the server's signing keys and exposes countersign operations."""

    def __init__(
        self,
        keys_dir: str | None = None,
        subca_cert_path: str | None = None,
    ) -> None:
        self.keys_dir = Path(keys_dir) if keys_dir else Path.home() / ".wafpass" / "server-keys"
        self._subca_cert_path = Path(subca_cert_path) if subca_cert_path else None
        self._root_key: Ed25519PrivateKey | None = None
        self._root_cert_pem: str | None = None
        self._server_key: Ed25519PrivateKey | None = None
        self._server_cert_pem: str | None = None
        self._server_subca_cert_pem: str | None = None

    def _init_keys(self) -> None:
        """Load keys from disk, or generate and persist them if absent."""
        if self._root_key is not None:
            return

        self.keys_dir.mkdir(parents=True, exist_ok=True)
        root_key_path = self.keys_dir / "root.key"
        root_cert_path = self.keys_dir / "root.crt"
        server_key_path = self.keys_dir / "server.key"
        server_cert_path = self.keys_dir / "server.crt"

        if (
            root_key_path.exists()
            and root_cert_path.exists()
            and server_key_path.exists()
            and server_cert_path.exists()
        ):
            self._root_key = load_signing_key(root_key_path)
            self._root_cert_pem = root_cert_path.read_text(encoding="ascii")
            self._server_key = load_signing_key(server_key_path)
            self._server_cert_pem = server_cert_path.read_text(encoding="ascii")
            return

        # Generate a fresh root/server key pair.
        self._root_key, self._root_cert_pem = generate_root_certificate()
        self._server_key = Ed25519PrivateKey.generate()
        self._server_cert_pem = generate_server_certificate(
            self._server_key,
            self._root_key,
            self._root_cert_pem,
        )

        _persist_private_key(self._root_key, root_key_path)
        _persist_private_key(self._server_key, server_key_path)
        root_cert_path.write_text(self._root_cert_pem, encoding="ascii")
        server_cert_path.write_text(self._server_cert_pem, encoding="ascii")

    @property
    def root_cert_pem(self) -> str:
        self._init_keys()
        assert self._root_cert_pem is not None
        return self._root_cert_pem

    @property
    def server_cert_pem(self) -> str:
        self._init_keys()
        assert self._server_cert_pem is not None
        return self._server_cert_pem

    @property
    def server_subca_certificate_pem(self) -> str:
        """Return the gateway-issued sub-CA certificate for this server.

        In the central validation architecture the gateway root CA issues a
        sub-CA certificate for each wafpass-server. The dashboard/CLI include
        this certificate when submitting a validation run to the gateway so the
        gateway can verify the server's identity and check it against the
        registered certificate registry.

        If ``subca_cert_path`` was provided explicitly, that file is returned.
        Otherwise the legacy ``server.crt`` in the keys directory is used as a
        fallback (dev/local deployments that still use self-generated material).
        """
        self._init_keys()
        if self._server_subca_cert_pem is not None:
            return self._server_subca_cert_pem
        if self._subca_cert_path and self._subca_cert_path.exists():
            self._server_subca_cert_pem = self._subca_cert_path.read_text(encoding="ascii")
            return self._server_subca_cert_pem
        assert self._server_cert_pem is not None
        return self._server_cert_pem

    def sign_local_attestation(
        self,
        result: WafpassResultSchema | dict[str, Any],
        signer_kind: str = "server",
    ) -> LocalAttestationSchema:
        """Sign a run result with the server's Ed25519 attestation key.

        The returned local attestation is what the dashboard/CLI forwards to
        the validation gateway together with the server sub-CA certificate.
        """
        self._init_keys()
        assert self._server_key is not None
        return sign_run(result, self._server_key, signer_kind=signer_kind)

    def verify_local_attestation(
        self,
        result: WafpassResultSchema | dict[str, Any],
        attestation: LocalAttestationSchema,
    ) -> tuple[bool, str]:
        """Recompute the canonical hash and verify the local signature."""
        canonical_hash = compute_run_hash(result)
        if canonical_hash != attestation.canonical_hash:
            return False, "canonical hash mismatch"
        return verify_local_attestation(result, attestation)

    def countersign(
        self,
        canonical_hash: str,
        base_url: str,
        validation_id: str | None = None,
        validated_at: str | None = None,
        expires_at: str | None = None,
    ) -> ServerValidationSchema:
        """Return an official server countersignature for a validated run hash."""
        self._init_keys()
        assert self._server_key is not None
        assert self._root_cert_pem is not None

        server_validation = build_server_validation(
            canonical_hash=canonical_hash,
            server_private_key=self._server_key,
            server_certificate_pem=self._server_cert_pem,
            root_certificate_pem=self._root_cert_pem,
            badge_url=f"{base_url}/api/v1/validations/{validation_id or ''}/badge.svg",
            verification_url=f"{base_url}/api/v1/validations/{validation_id or ''}/verify",
            validation_id=validation_id,
            validated_at=validated_at,
            expires_at=expires_at,
        )
        return server_validation

    def sign_revocation_list(
        self,
        revoked_validation_ids: list[str],
        issued_at: str | None = None,
    ) -> dict:
        """Return a signed, self-contained revocation list."""
        self._init_keys()
        assert self._server_key is not None
        assert self._server_cert_pem is not None
        assert self._root_cert_pem is not None
        return sign_revocation_list(
            revoked_validation_ids=revoked_validation_ids,
            private_key=self._server_key,
            server_certificate_pem=self._server_cert_pem,
            root_certificate_pem=self._root_cert_pem,
            issued_at=issued_at,
        )

    def public_key_pem(self) -> str:
        """Return the PEM-encoded server intermediate public key."""
        self._init_keys()
        assert self._server_key is not None
        return self._server_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")


def _persist_private_key(key: Ed25519PrivateKey, path: Path) -> None:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass


def load_validation_service(
    keys_dir: str | None = None,
    subca_cert_path: str | None = None,
) -> ValidationService:
    """Factory for the singleton-like validation service."""
    return ValidationService(keys_dir=keys_dir, subca_cert_path=subca_cert_path)
