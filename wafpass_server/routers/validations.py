"""Official WAF++ validation endpoints.

Authenticated (API key or JWT):
  POST /api/v1/validations
  GET  /api/v1/validations/{validation_id}
  POST /api/v1/validations/{validation_id}/revoke

Public (no auth):
  GET /api/v1/validations/{validation_id}/verify
  GET /api/v1/validations/{validation_id}/badge.svg
  GET /api/v1/validations/{validation_id}/badge.json
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import FileResponse, Response
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from wafpass.attestation import (
    verify_certificate_chain,
    verify_envelope,
    verify_server_signature,
)
from wafpass.badge import generate_badge_svg
from wafpass.schema import (
    LocalAttestationSchema,
    ServerValidationSchema,
    ValidationEnvelopeSchema,
    WafpassResultSchema,
)
from wafpass.validation_cli import _build_badge_json

try:
    from wafpass.pdf_reporter import generate_validation_certificate
    _PDF_CERTIFICATE_AVAILABLE = True
except Exception:  # pragma: no cover - reportlab may not be installed
    _PDF_CERTIFICATE_AVAILABLE = False
    generate_validation_certificate = None  # type: ignore[misc, assignment]

from wafpass_server.auth.deps import require_role
from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import Run, User, UserAuditLog, Validation
from wafpass_server.schemas import (
    Envelope,
    InternalValidationSubmit,
    ValidationBadge,
    ValidationRecord,
    ValidationSubmit,
    ValidationVerify,
)
from wafpass_server.validation_service import load_validation_service

router = APIRouter(prefix="/validations", tags=["validations"])


# Module-level singleton. Created lazily on first request so the app can start
# even if key files are mounted later.
_validation_service: ValidationService | None = None


def _get_validation_service() -> ValidationService:
    global _validation_service
    if _validation_service is None:
        keys_dir = settings.wafpass_validation_keys_dir or None
        _validation_service = load_validation_service(keys_dir)
    return _validation_service


def _base_url(request: Request, override: str | None = None) -> str:
    """Build the externally reachable base URL for verification/badge links."""
    if override:
        return override.rstrip("/")
    if settings.wafpass_public_url:
        return settings.wafpass_public_url.rstrip("/")
    return str(request.base_url).rstrip("/")


def _require_internal_key(x_internal_api_key: str | None = Header(default=None, alias="X-Internal-Api-Key")) -> str:
    expected = settings.wafpass_internal_api_key
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Internal signing endpoint is disabled (no WAFPASS_INTERNAL_API_KEY configured).",
        )
    if not x_internal_api_key or x_internal_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Internal-Api-Key header.",
        )
    return x_internal_api_key


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _map_status(db_status: str) -> str:
    """Map internal DB status to the public envelope/verify status."""
    return "official" if db_status == "active" else db_status


def _to_validation_record(v: Validation) -> ValidationRecord:
    return ValidationRecord(
        validation_id=v.validation_id,
        canonical_hash=v.canonical_hash,
        project=v.project,
        branch=v.branch,
        git_sha=v.git_sha,
        status=v.status,
        validated_at=v.validated_at or v.created_at,
        server_public_key=v.server_public_key,
        server_signature=v.server_signature,
        certificate_chain=v.certificate_chain or [],
        badge_url=v.badge_url,
        verification_url=v.verification_url,
        expires_at=v.expires_at,
        metadata=v.validation_metadata or None,
    )


def _to_validation_verify(v: Validation) -> ValidationVerify:
    return ValidationVerify(
        validation_id=v.validation_id,
        canonical_hash=v.canonical_hash,
        status=_map_status(v.status),
        validated_at=v.validated_at or v.created_at,
        server_public_key=v.server_public_key,
        server_signature=v.server_signature,
        certificate_chain=v.certificate_chain or [],
        expires_at=v.expires_at,
        metadata=v.validation_metadata or None,
    )


def _to_validation_envelope(v: Validation) -> ValidationEnvelopeSchema:
    validated_at = v.validated_at or v.created_at
    return ValidationEnvelopeSchema(
        schema_version="1.0",
        run_hash=v.canonical_hash,
        status=_map_status(v.status),
        result=v.run_snapshot,
        local_attestation=LocalAttestationSchema(
            public_key=v.local_public_key or "",
            signature=v.local_signature or "",
            canonical_hash=v.canonical_hash,
            signed_at=v.local_signed_at or "",
            signer_kind=v.local_signer_kind or "organization",
        ),
        server_validation=ServerValidationSchema(
            validation_id=v.validation_id,
            validated_at=validated_at.isoformat() if validated_at else "",
            server_public_key=v.server_public_key,
            server_signature=v.server_signature,
            certificate_chain=v.certificate_chain or [],
            badge_url=v.badge_url,
            verification_url=v.verification_url,
            expires_at=v.expires_at.isoformat() if v.expires_at else None,
            metadata=v.validation_metadata or None,
        ),
        metadata=v.validation_metadata or None,
    )


@router.post("/internal/sign", response_model=Envelope[ServerValidationSchema], status_code=201)
async def submit_validation_internal(
    request: Request,
    payload: InternalValidationSubmit,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[str, Depends(_require_internal_key)],
) -> Envelope[ServerValidationSchema]:
    """Gateway-only endpoint to countersign a validated WAF++ run.

    This endpoint is not reachable from the public internet. The validation
    gateway authenticates callers with a pre-shared X-Internal-Api-Key and
    forwards only verified local attestations. The server recomputes the
    canonical hash, verifies the local attestation, persists an immutable
    validation record, and returns the countersignature to the gateway.
    """
    try:
        result = WafpassResultSchema.model_validate(payload.result)
        attestation = LocalAttestationSchema.model_validate(payload.attestation)
    except PydanticValidationError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid payload: {exc}") from exc

    service = _get_validation_service()
    # Verify against the exact submitted run dict. Re-serialising through the
    # Pydantic schema may drop or coerce fields that were present when the
    # local attestation was computed, which would break hash verification.
    ok, reason = service.verify_local_attestation(payload.result, attestation)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Local attestation verification failed: {reason}")

    canonical_hash = attestation.canonical_hash

    # Use the gateway's validation ID so both stores share the same identifier.
    validation_id = payload.gateway_request_id or str(uuid.uuid4())
    base_url = _base_url(request)

    # The gateway is the trust anchor for the official validation timestamp.
    # Parse the ISO timestamps it forwards so the server record matches exactly.
    def _parse_iso(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    validated_at_dt = _parse_iso(payload.validated_at)
    expires_at_dt = _parse_iso(payload.expires_at)

    server_validation = service.countersign(
        canonical_hash=canonical_hash,
        base_url=base_url,
        validation_id=validation_id,
        validated_at=payload.validated_at or None,
        expires_at=payload.expires_at or None,
    )

    validation = Validation(
        validation_id=server_validation.validation_id,
        canonical_hash=canonical_hash,
        project=result.project,
        branch=result.branch,
        git_sha=result.git_sha,
        status="active",
        run_snapshot=payload.result,
        server_public_key=server_validation.server_public_key,
        server_signature=server_validation.server_signature,
        certificate_chain=server_validation.certificate_chain,
        badge_url=server_validation.badge_url,
        verification_url=server_validation.verification_url,
        local_public_key=attestation.public_key,
        local_signature=attestation.signature,
        local_signed_at=attestation.signed_at,
        local_signer_kind=attestation.signer_kind or "organization",
        validated_at=validated_at_dt,
        expires_at=expires_at_dt,
        validation_metadata=payload.metadata or {},
    )
    db.add(validation)
    await db.commit()
    await db.refresh(validation)

    # Audit log — the gateway is the actor here; we record its request id if provided.
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "")
    db.add(UserAuditLog(
        actor_id=None,
        action="validation.created",
        detail={
            "validation_id": validation.validation_id,
            "canonical_hash": canonical_hash,
            "project": result.project,
            "branch": result.branch,
            "gateway_request_id": payload.gateway_request_id,
            "metadata": payload.metadata or {},
        },
        ip=client_ip,
    ))
    await db.commit()

    return Envelope(data=server_validation)


@router.get("/{validation_id}", response_model=Envelope[ValidationRecord])
async def get_validation(
    validation_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[User, Depends(require_role("clevel"))],
) -> Envelope[ValidationRecord]:
    """Return the full validation record (authenticated)."""
    result = await db.execute(select(Validation).where(Validation.validation_id == validation_id))
    validation = result.scalar_one_or_none()
    if validation is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    return Envelope(data=_to_validation_record(validation))


@router.get("/{validation_id}/verify", response_model=Envelope[ValidationVerify])
async def verify_validation(
    validation_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Envelope[ValidationVerify]:
    """Public endpoint to retrieve the signed validation record."""
    result = await db.execute(select(Validation).where(Validation.validation_id == validation_id))
    validation = result.scalar_one_or_none()
    if validation is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    return Envelope(data=_to_validation_verify(validation))


@router.get("/{validation_id}/badge.svg")
async def get_badge_svg(
    validation_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    """Return an embeddable SVG badge for the validation (public)."""
    result = await db.execute(select(Validation).where(Validation.validation_id == validation_id))
    validation = result.scalar_one_or_none()
    if validation is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    envelope = _to_validation_envelope(validation)
    svg = generate_badge_svg(envelope)
    return Response(content=svg.encode("utf-8"), media_type="image/svg+xml")


@router.get("/{validation_id}/badge.json", response_model=Envelope[ValidationBadge])
async def get_badge_json(
    validation_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Envelope[ValidationBadge]:
    """Return the portable badge JSON for the validation (public)."""
    result = await db.execute(select(Validation).where(Validation.validation_id == validation_id))
    validation = result.scalar_one_or_none()
    if validation is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    envelope = _to_validation_envelope(validation)
    badge = _build_badge_json(envelope)
    badge["validated_at"] = validation.validated_at or validation.created_at
    badge["metadata"] = validation.validation_metadata or None
    return Envelope(data=ValidationBadge(**badge))


@router.get("/{validation_id}/certificate.pdf")
async def get_validation_certificate_pdf(
    validation_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> FileResponse:
    """Return a printable PDF certificate for the validation (public)."""
    result = await db.execute(select(Validation).where(Validation.validation_id == validation_id))
    validation = result.scalar_one_or_none()
    if validation is None:
        raise HTTPException(status_code=404, detail="Validation not found")

    if not _PDF_CERTIFICATE_AVAILABLE or generate_validation_certificate is None:
        raise HTTPException(
            status_code=503,
            detail="PDF certificate rendering is not available (reportlab not installed)",
        )

    envelope = _to_validation_envelope(validation)
    tmp_dir = tempfile.mkdtemp(prefix="wafpass-cert-")
    pdf_path = Path(tmp_dir) / f"wafpass-certificate-{validation_id[:8]}.pdf"
    generate_validation_certificate(envelope, pdf_path)

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"wafpass-certificate-{validation_id[:8]}.pdf",
    )


@router.post("/{validation_id}/revoke")
async def revoke_validation(
    validation_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    user: Annotated[User, Depends(require_role("admin"))],
) -> dict[str, str]:
    """Revoke a validation (admin only)."""
    result = await db.execute(select(Validation).where(Validation.validation_id == validation_id))
    validation = result.scalar_one_or_none()
    if validation is None:
        raise HTTPException(status_code=404, detail="Validation not found")
    validation.status = "revoked"
    validation.revoked_at = _now()
    await db.commit()
    return {"status": "revoked", "validation_id": validation_id}
