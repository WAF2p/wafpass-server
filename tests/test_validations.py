"""Tests for the validation authority service and schemas.

Full endpoint integration tests require a PostgreSQL database with the
``validations`` table. This module tests the pure cryptographic/service layer
so it can run in CI without a running DB.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from wafpass.attestation import (
    compute_run_hash,
    generate_signing_key,
    sign_revocation_list,
    sign_run,
    verify_certificate_chain,
    verify_envelope,
    verify_revocation_list,
    verify_server_signature,
)
from wafpass.schema import WafpassResultSchema

from wafpass_server.routers.validations import _map_status
from wafpass_server.validation_service import ValidationService


@pytest.fixture
def service(tmp_path: Path) -> ValidationService:
    return ValidationService(keys_dir=str(tmp_path / "keys"))


@pytest.fixture
def org_key(tmp_path: Path) -> Path:
    key_path = tmp_path / "org.key"
    generate_signing_key(key_path)
    return key_path


@pytest.fixture
def sample_result() -> WafpassResultSchema:
    return WafpassResultSchema(
        project="demo",
        branch="main",
        git_sha="abc1234",
        score=88,
        findings=[],
    )


def test_service_generates_keys_on_first_use(service: ValidationService) -> None:
    assert service.server_cert_pem
    assert service.root_cert_pem
    assert "BEGIN CERTIFICATE" in service.server_cert_pem
    assert "BEGIN CERTIFICATE" in service.root_cert_pem


def test_service_reuses_persisted_keys(tmp_path: Path) -> None:
    keys_dir = tmp_path / "keys"
    svc1 = ValidationService(keys_dir=str(keys_dir))
    _ = svc1.server_cert_pem  # trigger generation

    svc2 = ValidationService(keys_dir=str(keys_dir))
    assert svc2.server_cert_pem == svc1.server_cert_pem
    assert svc2.root_cert_pem == svc1.root_cert_pem


def test_countersign_produces_verifiable_signature(
    service: ValidationService,
    org_key: Path,
    sample_result: WafpassResultSchema,
) -> None:
    attestation = sign_run(sample_result, org_key)
    ok, reason = service.verify_local_attestation(sample_result, attestation)
    assert ok, reason

    canonical_hash = attestation.canonical_hash
    server_validation = service.countersign(
        canonical_hash=canonical_hash,
        base_url="https://wafpass.example.com",
        validation_id="test-id-123",
    )

    ok, reason = verify_server_signature(canonical_hash, server_validation)
    assert ok, reason


def test_certificate_chain_verifies(service: ValidationService) -> None:
    server_validation = service.countersign(
        canonical_hash="any-hash",
        base_url="https://wafpass.example.com",
        validation_id="test-id-123",
    )
    root_cert = server_validation.certificate_chain[-1]
    ok, reason = verify_certificate_chain(server_validation.certificate_chain, root_cert)
    assert ok, reason


def test_verify_envelope_against_root_cert(
    service: ValidationService,
    org_key: Path,
    sample_result: WafpassResultSchema,
) -> None:
    from wafpass.schema import (
        LocalAttestationSchema,
        ServerValidationSchema,
        ValidationEnvelopeSchema,
    )

    local = sign_run(sample_result, org_key)
    server_validation = service.countersign(
        canonical_hash=local.canonical_hash,
        base_url="https://wafpass.example.com",
        validation_id="test-id-123",
    )
    envelope = ValidationEnvelopeSchema(
        schema_version="1.0",
        run_hash=local.canonical_hash,
        status="official",
        result=sample_result,
        local_attestation=local,
        server_validation=server_validation,
    )
    root_cert = server_validation.certificate_chain[-1]
    ok, reason = verify_envelope(envelope, root_public_key_or_cert=root_cert)
    assert ok, reason


def test_tampered_result_fails_local_verification(
    service: ValidationService,
    org_key: Path,
    sample_result: WafpassResultSchema,
) -> None:
    attestation = sign_run(sample_result, org_key)
    tampered = sample_result.model_dump()
    tampered["score"] = 99
    ok, reason = service.verify_local_attestation(tampered, attestation)
    assert not ok
    assert "hash mismatch" in reason.lower()


def test_map_status_active_to_official() -> None:
    assert _map_status("active") == "official"
    assert _map_status("revoked") == "revoked"


def test_service_root_certificate_is_pem(service: ValidationService) -> None:
    assert "BEGIN CERTIFICATE" in service.root_cert_pem


def test_service_signs_revocation_list(service: ValidationService) -> None:
    revoked = ["val-2", "val-1"]
    revocation_list = service.sign_revocation_list(revoked)
    assert revocation_list["revoked_validation_ids"] == ["val-1", "val-2"]
    assert revocation_list["schema_version"] == "1.0"
    assert revocation_list["signature"]
    assert len(revocation_list["certificate_chain"]) == 2

    ok, reason = verify_revocation_list(revocation_list, service.root_cert_pem)
    assert ok, reason


def test_tampered_revocation_list_fails_verification(service: ValidationService) -> None:
    revocation_list = service.sign_revocation_list(["val-1"])
    revocation_list["revoked_validation_ids"].append("val-2")
    ok, reason = verify_revocation_list(revocation_list, service.root_cert_pem)
    assert not ok
