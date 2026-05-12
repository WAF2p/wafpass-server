"""At-rest encryption for SSO sensitive fields (client secrets, SP private keys).

Backend is selected by WAFPASS_SECRETS_BACKEND (default: "local").

  local          Fernet symmetric AES-128-CBC+HMAC.  Key is taken from
                 WAFPASS_ENCRYPTION_KEY (Fernet key or passphrase, PBKDF2-
                 derived).  Falls back to WAFPASS_JWT_SECRET with a warning
                 when WAFPASS_ENCRYPTION_KEY is not set.

  aws_sm         AWS Secrets Manager.  Each secret is stored as a named SM
                 secret; only its ARN is persisted in the database.
                 Requires: pip install wafpass-server[secrets-aws]

  vault_transit  HashiCorp Vault Transit engine.  Vault encrypts/decrypts;
                 the opaque ciphertext is persisted in the database.
                 Requires: pip install wafpass-server[secrets-vault]

Blobs are JSON envelopes {"v": 1, "b": "<backend>", ...} so the correct
backend is always resolved at decrypt time, enabling zero-downtime rotation.

Existing plaintext values are returned unchanged by decrypt_field() (detected
by the absence of the JSON envelope) — this provides a seamless migration path.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging

log = logging.getLogger(__name__)

# Fixed application salt — prevents rainbow tables, does NOT need to be secret.
_DERIVE_SALT = b"wafpass-sso-secret-enc-v1"


# ── Key derivation ────────────────────────────────────────────────────────────

def _fernet_key() -> bytes:
    """Return a Fernet-ready 32-byte key (base64url-encoded bytes object)."""
    from wafpass_server.config import settings

    raw = settings.wafpass_encryption_key
    if raw:
        try:
            candidate = base64.urlsafe_b64decode(raw + "==")
            if len(candidate) == 32:
                return base64.urlsafe_b64encode(candidate)
        except Exception:
            pass
        # Treat as passphrase — derive deterministically
        derived = hashlib.pbkdf2_hmac("sha256", raw.encode(), _DERIVE_SALT, iterations=260_000, dklen=32)
        return base64.urlsafe_b64encode(derived)

    log.warning(
        "WAFPASS_ENCRYPTION_KEY is not set. "
        "Deriving SSO encryption key from WAFPASS_JWT_SECRET — "
        "set a dedicated WAFPASS_ENCRYPTION_KEY in production."
    )
    derived = hashlib.pbkdf2_hmac(
        "sha256", settings.wafpass_jwt_secret.encode(), _DERIVE_SALT, iterations=260_000, dklen=32
    )
    return base64.urlsafe_b64encode(derived)


# ── Local backend ─────────────────────────────────────────────────────────────

def _local_encrypt(plaintext: str) -> str:
    from cryptography.fernet import Fernet
    token = Fernet(_fernet_key()).encrypt(plaintext.encode()).decode()
    return json.dumps({"v": 1, "b": "local", "ct": token})


def _local_decrypt(blob: dict) -> str:
    from cryptography.fernet import Fernet
    return Fernet(_fernet_key()).decrypt(blob["ct"].encode()).decode()


# ── AWS Secrets Manager backend ───────────────────────────────────────────────

async def _aws_sm_encrypt(plaintext: str, secret_name: str) -> str:
    try:
        import boto3
        import botocore.exceptions
    except ImportError as exc:
        raise RuntimeError(
            "boto3 is required for the aws_sm backend: "
            "pip install wafpass-server[secrets-aws]"
        ) from exc

    from wafpass_server.config import settings
    client = boto3.client("secretsmanager", region_name=settings.aws_region)

    def _put() -> str:
        try:
            resp = client.create_secret(Name=secret_name, SecretString=plaintext)
            return resp["ARN"]
        except client.exceptions.ResourceExistsException:
            client.put_secret_value(SecretId=secret_name, SecretString=plaintext)
            return client.describe_secret(SecretId=secret_name)["ARN"]

    arn = await asyncio.get_event_loop().run_in_executor(None, _put)
    return json.dumps({"v": 1, "b": "aws_sm", "arn": arn})


async def _aws_sm_decrypt(blob: dict) -> str:
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError(
            "boto3 is required for the aws_sm backend: "
            "pip install wafpass-server[secrets-aws]"
        ) from exc

    from wafpass_server.config import settings
    client = boto3.client("secretsmanager", region_name=settings.aws_region)

    def _get() -> str:
        resp = client.get_secret_value(SecretId=blob["arn"])
        return resp["SecretString"]

    return await asyncio.get_event_loop().run_in_executor(None, _get)


# ── HashiCorp Vault Transit backend ──────────────────────────────────────────

async def _vault_encrypt(plaintext: str) -> str:
    try:
        import hvac
    except ImportError as exc:
        raise RuntimeError(
            "hvac is required for the vault_transit backend: "
            "pip install wafpass-server[secrets-vault]"
        ) from exc

    from wafpass_server.config import settings

    def _enc() -> str:
        client = hvac.Client(url=settings.vault_addr, token=settings.vault_token)
        pt_b64 = base64.b64encode(plaintext.encode()).decode()
        resp = client.secrets.transit.encrypt_data(
            name=settings.vault_transit_key,
            plaintext=pt_b64,
            mount_point=settings.vault_transit_mount,
        )
        return resp["data"]["ciphertext"]

    ct = await asyncio.get_event_loop().run_in_executor(None, _enc)
    return json.dumps({"v": 1, "b": "vault_transit", "ct": ct})


async def _vault_decrypt(blob: dict) -> str:
    try:
        import hvac
    except ImportError as exc:
        raise RuntimeError(
            "hvac is required for the vault_transit backend: "
            "pip install wafpass-server[secrets-vault]"
        ) from exc

    from wafpass_server.config import settings

    def _dec() -> str:
        client = hvac.Client(url=settings.vault_addr, token=settings.vault_token)
        resp = client.secrets.transit.decrypt_data(
            name=settings.vault_transit_key,
            ciphertext=blob["ct"],
            mount_point=settings.vault_transit_mount,
        )
        return base64.b64decode(resp["data"]["plaintext"]).decode()

    return await asyncio.get_event_loop().run_in_executor(None, _dec)


# ── Public API ────────────────────────────────────────────────────────────────

def is_encrypted_blob(value: str) -> bool:
    """Return True if *value* is an encrypted blob produced by this module."""
    try:
        obj = json.loads(value)
        return isinstance(obj, dict) and obj.get("v") == 1 and "b" in obj
    except Exception:
        return False


async def encrypt_field(plaintext: str, *, aws_secret_name: str = "") -> str:
    """Encrypt *plaintext* using the configured backend and return an opaque blob."""
    from wafpass_server.config import settings
    backend = settings.wafpass_secrets_backend

    if backend == "aws_sm":
        if not aws_secret_name:
            raise ValueError("aws_secret_name must be provided for the aws_sm backend")
        return await _aws_sm_encrypt(plaintext, aws_secret_name)
    if backend == "vault_transit":
        return await _vault_encrypt(plaintext)
    return _local_encrypt(plaintext)


async def decrypt_field(blob_or_plaintext: str) -> str:
    """Decrypt an opaque blob, or return *blob_or_plaintext* unchanged if it is
    not a blob (transparent migration path for existing plaintext values)."""
    if not is_encrypted_blob(blob_or_plaintext):
        return blob_or_plaintext

    blob = json.loads(blob_or_plaintext)
    backend = blob.get("b", "local")

    if backend == "local":
        return _local_decrypt(blob)
    if backend == "aws_sm":
        return await _aws_sm_decrypt(blob)
    if backend == "vault_transit":
        return await _vault_decrypt(blob)
    raise ValueError(f"Unknown encryption backend: {backend!r}")
