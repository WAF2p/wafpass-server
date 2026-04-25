"""SSO configuration management and login flows (OIDC + SAML2)."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

import jwt as _jwt

from wafpass_server.auth.deps import require_role
from wafpass_server.auth.jwt_utils import create_access_token
from wafpass_server.config import settings
from wafpass_server.database import get_db
from wafpass_server.models import GroupRoleMapping, RefreshToken, SsoConfig, User, UserAuditLog
from wafpass_server.secret_enc import decrypt_field, encrypt_field, is_encrypted_blob

router = APIRouter(tags=["sso"])

# ── Sensitive field registry ──────────────────────────────────────────────────

# Fields encrypted at rest before writing to sso_configs.config.
_SENSITIVE: dict[str, list[str]] = {
    "oidc":  ["client_secret"],
    "saml2": ["sp_private_key"],
}


async def _encrypt_config(provider: str, new_config: dict, existing_config: dict | None) -> dict:
    """Return a copy of *new_config* with sensitive fields encrypted.

    * Plaintext values are encrypted using the configured backend.
    * ``"***"`` means the admin left the field unchanged — the existing
      encrypted blob is preserved.
    * Already-encrypted blobs are kept as-is (idempotent).
    * Empty/missing values are removed from the stored config.
    """
    result = dict(new_config)
    for field in _SENSITIVE.get(provider, []):
        val = result.get(field, "")
        if not val or val == "***":
            if existing_config and existing_config.get(field):
                result[field] = existing_config[field]   # keep existing blob
            else:
                result.pop(field, None)
        elif is_encrypted_blob(val):
            pass  # already encrypted — leave unchanged
        else:
            result[field] = await encrypt_field(
                val,
                aws_secret_name=f"wafpass/sso/{provider}/{field}",
            )
    return result


async def _decrypt_config(provider: str, config: dict) -> dict:
    """Return a copy of *config* with sensitive fields decrypted for runtime use."""
    result = dict(config)
    for field in _SENSITIVE.get(provider, []):
        if result.get(field):
            result[field] = await decrypt_field(result[field])
    return result


def _redact_config(provider: str, config: dict) -> dict:
    """Return a copy of *config* with sensitive fields replaced by ``"***"``."""
    result = dict(config)
    for field in _SENSITIVE.get(provider, []):
        if result.get(field):
            result[field] = "***"
    return result


# ── Optional SAML2 import ─────────────────────────────────────────────────────

try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    SAML_AVAILABLE = True
except ImportError:
    SAML_AVAILABLE = False

# ── Helpers ───────────────────────────────────────────────────────────────────

def _ip(request: Request) -> str:
    return request.headers.get("x-forwarded-for", request.client.host if request.client else "")


async def _audit(db: AsyncSession, actor_id: uuid.UUID | None, action: str, detail: dict, ip: str = "") -> None:
    db.add(UserAuditLog(actor_id=actor_id, action=action, detail=detail, ip=ip))


async def _get_cfg(db: AsyncSession, provider: str) -> SsoConfig | None:
    result = await db.execute(select(SsoConfig).where(SsoConfig.id == provider))
    return result.scalar_one_or_none()


async def _resolve_role_from_groups(
    db: AsyncSession,
    provider: str,
    group_values: list[str],
) -> str | None:
    """Return the highest-priority mapped role for any of the given group values, or None."""
    if not group_values:
        return None
    result = await db.execute(
        select(GroupRoleMapping)
        .where(
            or_(GroupRoleMapping.provider == provider, GroupRoleMapping.provider == "*"),
            GroupRoleMapping.group_name.in_(group_values),
        )
        .order_by(GroupRoleMapping.priority.desc())
        .limit(1)
    )
    row = result.scalar_one_or_none()
    return row.role if row else None


async def _issue_tokens(db: AsyncSession, user: User) -> tuple[str, str]:
    access_token = create_access_token(user.id, user.username, user.role)
    raw_refresh = secrets.token_urlsafe(48)
    rt = RefreshToken(
        user_id=user.id,
        token_hash=hashlib.sha256(raw_refresh.encode()).hexdigest(),
        family_id=uuid.uuid4(),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.wafpass_jwt_refresh_days),
    )
    db.add(rt)
    user.last_login_at = datetime.now(timezone.utc)
    return access_token, raw_refresh


def _frontend_redirect(frontend_url: str, access_token: str, refresh_token: str, user: User) -> str:
    user_dict = {
        "id": str(user.id),
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "auth_provider": user.auth_provider,
        "is_active": user.is_active,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
    }
    u_b64 = base64.urlsafe_b64encode(json.dumps(user_dict).encode()).decode()
    params = urlencode({"sso_ok": "1", "at": access_token, "rt": refresh_token, "u": u_b64})
    return f"{frontend_url.rstrip('/')}?{params}"


async def _provision_user(
    db: AsyncSession,
    username: str,
    display_name: str,
    auth_provider: str,
    role: str,
    auto_provision: bool,
) -> User:
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user is None:
        if not auto_provision:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="User not found and auto-provisioning is disabled.")
        user = User(
            username=username,
            display_name=display_name or username,
            role=role,
            auth_provider=auth_provider,
            password_hash=None,
        )
        db.add(user)
        await db.flush()
    else:
        if not user.is_active:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Account is disabled.")
        if display_name and user.display_name != display_name:
            user.display_name = display_name
        user.auth_provider = auth_provider
    return user


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class SsoConfigOut(BaseModel):
    id: str
    enabled: bool
    config: dict
    updated_at: datetime | None = None

    model_config = {"from_attributes": True}


class SsoConfigUpdate(BaseModel):
    enabled: bool = False
    config: dict = {}


class SsoProviderInfo(BaseModel):
    provider: str
    enabled: bool
    label: str


class GroupRoleMappingOut(BaseModel):
    id: str
    provider: str
    group_name: str
    role: str
    description: str
    priority: int
    created_at: datetime | None = None
    created_by: str | None = None

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_row(cls, row: GroupRoleMapping) -> "GroupRoleMappingOut":
        return cls(
            id=str(row.id),
            provider=row.provider,
            group_name=row.group_name,
            role=row.role,
            description=row.description,
            priority=row.priority,
            created_at=row.created_at,
            created_by=str(row.created_by) if row.created_by else None,
        )


class GroupRoleMappingCreate(BaseModel):
    provider: str = "*"
    group_name: str
    role: str
    description: str = ""
    priority: int = 0


class GroupRoleMappingUpdate(BaseModel):
    provider: str | None = None
    group_name: str | None = None
    role: str | None = None
    description: str | None = None
    priority: int | None = None


# ── Config management (admin only) ────────────────────────────────────────────

@router.get("/sso/config", response_model=list[SsoConfigOut])
async def list_sso_configs(
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[SsoConfigOut]:
    result = await db.execute(select(SsoConfig))
    return [
        SsoConfigOut(
            id=row.id,
            enabled=row.enabled,
            config=_redact_config(row.id, row.config),
            updated_at=row.updated_at,
        )
        for row in result.scalars().all()
    ]


@router.put("/sso/config/{provider}", response_model=SsoConfigOut)
async def upsert_sso_config(
    provider: str,
    payload: SsoConfigUpdate,
    acting_user: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> SsoConfigOut:
    if provider not in ("oidc", "saml2"):
        raise HTTPException(400, detail="Provider must be 'oidc' or 'saml2'.")
    cfg = await _get_cfg(db, provider)
    encrypted = await _encrypt_config(provider, payload.config, cfg.config if cfg else None)
    if cfg is None:
        cfg = SsoConfig(id=provider, enabled=payload.enabled, config=encrypted, updated_by=acting_user.id)
        db.add(cfg)
    else:
        cfg.enabled = payload.enabled
        cfg.config = encrypted
        cfg.updated_by = acting_user.id
    await db.commit()
    await db.refresh(cfg)
    return SsoConfigOut(
        id=cfg.id,
        enabled=cfg.enabled,
        config=_redact_config(cfg.id, cfg.config),
        updated_at=cfg.updated_at,
    )


@router.delete("/sso/config/{provider}", status_code=204)
async def delete_sso_config(
    provider: str,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    cfg = await _get_cfg(db, provider)
    if cfg:
        await db.delete(cfg)
        await db.commit()


# ── Group → Role mappings (admin only) ───────────────────────────────────────

_VALID_ROLES = {"clevel", "ciso", "architect", "engineer", "admin"}
_VALID_PROVIDERS = {"oidc", "saml2", "*"}


@router.get("/sso/group-mappings", response_model=list[GroupRoleMappingOut])
async def list_group_mappings(
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[GroupRoleMappingOut]:
    result = await db.execute(
        select(GroupRoleMapping).order_by(GroupRoleMapping.priority.desc(), GroupRoleMapping.group_name)
    )
    return [GroupRoleMappingOut.from_orm_row(r) for r in result.scalars().all()]


@router.post("/sso/group-mappings", response_model=GroupRoleMappingOut, status_code=201)
async def create_group_mapping(
    payload: GroupRoleMappingCreate,
    acting_user: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> GroupRoleMappingOut:
    if payload.role not in _VALID_ROLES:
        raise HTTPException(400, detail=f"Invalid role. Must be one of: {', '.join(sorted(_VALID_ROLES))}")
    if payload.provider not in _VALID_PROVIDERS:
        raise HTTPException(400, detail=f"Invalid provider. Must be one of: {', '.join(sorted(_VALID_PROVIDERS))}")
    row = GroupRoleMapping(
        provider=payload.provider,
        group_name=payload.group_name,
        role=payload.role,
        description=payload.description,
        priority=payload.priority,
        created_by=acting_user.id,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return GroupRoleMappingOut.from_orm_row(row)


@router.put("/sso/group-mappings/{mapping_id}", response_model=GroupRoleMappingOut)
async def update_group_mapping(
    mapping_id: str,
    payload: GroupRoleMappingUpdate,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> GroupRoleMappingOut:
    result = await db.execute(select(GroupRoleMapping).where(GroupRoleMapping.id == mapping_id))
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(404, detail="Mapping not found.")
    if payload.role is not None:
        if payload.role not in _VALID_ROLES:
            raise HTTPException(400, detail=f"Invalid role. Must be one of: {', '.join(sorted(_VALID_ROLES))}")
        row.role = payload.role
    if payload.provider is not None:
        if payload.provider not in _VALID_PROVIDERS:
            raise HTTPException(400, detail=f"Invalid provider. Must be one of: {', '.join(sorted(_VALID_PROVIDERS))}")
        row.provider = payload.provider
    if payload.group_name is not None:
        row.group_name = payload.group_name
    if payload.description is not None:
        row.description = payload.description
    if payload.priority is not None:
        row.priority = payload.priority
    await db.commit()
    await db.refresh(row)
    return GroupRoleMappingOut.from_orm_row(row)


@router.delete("/sso/group-mappings/{mapping_id}", status_code=204)
async def delete_group_mapping(
    mapping_id: str,
    _: Annotated[User, Depends(require_role("admin"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    result = await db.execute(select(GroupRoleMapping).where(GroupRoleMapping.id == mapping_id))
    row = result.scalar_one_or_none()
    if row:
        await db.delete(row)
        await db.commit()


# ── Public: list enabled providers for login page ─────────────────────────────

@router.get("/sso/providers", response_model=list[SsoProviderInfo])
async def list_enabled_providers(
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[dict]:
    result = await db.execute(select(SsoConfig).where(SsoConfig.enabled.is_(True)))
    labels = {"oidc": "Sign in with OIDC", "saml2": "Sign in with SAML2"}
    return [
        {"provider": c.id, "enabled": c.enabled, "label": labels.get(c.id, c.id)}
        for c in result.scalars().all()
    ]


# ── OIDC Flow ─────────────────────────────────────────────────────────────────

def _sign_state(nonce: str) -> str:
    return _jwt.encode(
        {"nonce": nonce, "exp": datetime.now(timezone.utc) + timedelta(minutes=10)},
        settings.wafpass_jwt_secret,
        algorithm="HS256",
    )


def _verify_state(state: str) -> None:
    try:
        _jwt.decode(state, settings.wafpass_jwt_secret, algorithms=["HS256"])
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid or expired SSO state.")


async def _oidc_discovery(discovery_url: str) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(discovery_url)
        resp.raise_for_status()
        return resp.json()


async def _oidc_exchange_code(token_endpoint: str, code: str, cfg: dict) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": cfg["redirect_uri"],
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
            },
        )
        resp.raise_for_status()
        return resp.json()


async def _oidc_userinfo(userinfo_endpoint: str, access_token: str) -> dict:
    import httpx
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"})
        resp.raise_for_status()
        return resp.json()


@router.get("/auth/oidc/authorize")
async def oidc_authorize(
    db: Annotated[AsyncSession, Depends(get_db)],
) -> RedirectResponse:
    """Initiate OIDC Authorization Code flow — redirects to the configured IdP."""
    cfg_row = await _get_cfg(db, "oidc")
    if not cfg_row or not cfg_row.enabled:
        raise HTTPException(404, detail="OIDC SSO is not enabled.")
    cfg = cfg_row.config

    discovery = await _oidc_discovery(cfg["discovery_url"])
    state = _sign_state(secrets.token_hex(16))
    scopes = cfg.get("scopes", ["openid", "profile", "email"])
    params = urlencode({
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "scope": " ".join(scopes),
        "state": state,
    })
    # Allow overriding the browser-facing authorization endpoint separately from
    # the discovery URL — needed when the server reaches the IdP via an internal
    # hostname (e.g. "keycloak:8080") but the browser must use a public one
    # (e.g. "localhost:8080").
    auth_endpoint = cfg.get("authorization_endpoint") or discovery["authorization_endpoint"]
    return RedirectResponse(f"{auth_endpoint}?{params}", status_code=302)


@router.get("/auth/oidc/callback")
async def oidc_callback(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    """Handle OIDC callback — exchange code, provision user, issue JWT, redirect to frontend."""
    cfg_row = await _get_cfg(db, "oidc")
    if not cfg_row or not cfg_row.enabled:
        raise HTTPException(404, detail="OIDC SSO is not enabled.")
    cfg = await _decrypt_config("oidc", cfg_row.config)
    frontend_url = cfg.get("frontend_url", "http://localhost:5173")

    if error:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error={error}", status_code=302)
    if not code or not state:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error=missing_params", status_code=302)

    try:
        _verify_state(state)
        discovery = await _oidc_discovery(cfg["discovery_url"])
        tokens = await _oidc_exchange_code(discovery["token_endpoint"], code, cfg)
    except HTTPException:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error=invalid_state", status_code=302)
    except Exception:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error=token_exchange_failed", status_code=302)

    claims: dict = {}
    if "id_token" in tokens:
        try:
            claims = _jwt.decode(tokens["id_token"], options={"verify_signature": False})
        except Exception:
            pass
    if not claims and "userinfo_endpoint" in discovery:
        try:
            claims = await _oidc_userinfo(discovery["userinfo_endpoint"], tokens.get("access_token", ""))
        except Exception:
            pass

    username_claim = cfg.get("username_claim", "email")
    username = claims.get(username_claim) or claims.get("sub", "")
    if not username:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error=no_username_claim", status_code=302)

    display_name = claims.get(cfg.get("display_name_claim", "name")) or claims.get("preferred_username") or username

    role = cfg.get("default_role", "clevel")
    role_claim = cfg.get("role_claim")
    claim_val = claims.get(role_claim) if role_claim else None
    candidates = claim_val if isinstance(claim_val, list) else ([claim_val] if claim_val else [])
    candidates = [v for v in candidates if v]

    mapped = await _resolve_role_from_groups(db, "oidc", candidates)
    if mapped:
        role = mapped
    else:
        role_mapping: dict = cfg.get("role_mapping", {})
        for v in candidates:
            if v in role_mapping:
                role = role_mapping[v]
                break

    try:
        user = await _provision_user(db, username, display_name, "oidc", role, cfg.get("auto_provision", True))
    except HTTPException as exc:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error=access_denied&detail={exc.detail}", status_code=302)

    access_token, raw_refresh = await _issue_tokens(db, user)
    await _audit(db, user.id, "sso.login", {"provider": "oidc"}, ip=_ip(request))
    await db.commit()
    await db.refresh(user)

    return RedirectResponse(_frontend_redirect(frontend_url, access_token, raw_refresh, user), status_code=302)


# ── SAML2 Flow ────────────────────────────────────────────────────────────────

def _saml_settings_dict(cfg: dict) -> dict:
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": cfg["entity_id"],
            "assertionConsumerService": {
                "url": cfg["acs_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "x509cert": cfg.get("sp_certificate", ""),
            "privateKey": cfg.get("sp_private_key", ""),
        },
        "idp": {
            "entityId": cfg["idp_entity_id"],
            "singleSignOnService": {
                "url": cfg["idp_sso_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": cfg["idp_certificate"],
        },
    }


def _saml_req(request: Request, post_data: dict | None = None) -> dict:
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.headers.get("host", "localhost"),
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": post_data or {},
    }


@router.get("/auth/saml/metadata")
async def saml_metadata(
    db: Annotated[AsyncSession, Depends(get_db)],
) -> HTMLResponse:
    """Return SP metadata XML for registering with the IdP."""
    if not SAML_AVAILABLE:
        raise HTTPException(501, detail="python3-saml is not installed on this server.")
    cfg_row = await _get_cfg(db, "saml2")
    if not cfg_row:
        raise HTTPException(404, detail="SAML2 is not configured.")
    saml_cfg = OneLogin_Saml2_Settings(
        _saml_settings_dict(await _decrypt_config("saml2", cfg_row.config)), sp_validation_only=True
    )
    metadata = saml_cfg.get_sp_metadata()
    return HTMLResponse(content=metadata, media_type="application/xml")


@router.get("/auth/saml/login")
async def saml_login(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> RedirectResponse:
    """Initiate SAML2 SP-initiated SSO."""
    if not SAML_AVAILABLE:
        raise HTTPException(501, detail="python3-saml is not installed on this server.")
    cfg_row = await _get_cfg(db, "saml2")
    if not cfg_row or not cfg_row.enabled:
        raise HTTPException(404, detail="SAML2 SSO is not enabled.")
    auth = OneLogin_Saml2_Auth(_saml_req(request), _saml_settings_dict(await _decrypt_config("saml2", cfg_row.config)))
    return RedirectResponse(auth.login(), status_code=302)


@router.post("/auth/saml/acs")
async def saml_acs(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> RedirectResponse:
    """SAML2 Assertion Consumer Service — validate IdP response and issue JWT."""
    if not SAML_AVAILABLE:
        raise HTTPException(501, detail="python3-saml is not installed on this server.")
    cfg_row = await _get_cfg(db, "saml2")
    if not cfg_row or not cfg_row.enabled:
        raise HTTPException(404, detail="SAML2 SSO is not enabled.")
    cfg = await _decrypt_config("saml2", cfg_row.config)
    frontend_url = cfg.get("frontend_url", "http://localhost:5173")

    form = await request.form()
    auth = OneLogin_Saml2_Auth(_saml_req(request, dict(form)), _saml_settings_dict(cfg))
    auth.process_response()
    errors = auth.get_errors()

    if errors or not auth.is_authenticated():
        err_str = "_".join(errors) if errors else "not_authenticated"
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error={err_str}", status_code=302)

    attrs = auth.get_attributes()
    name_id = auth.get_nameid()

    username_attr = cfg.get("username_attribute")
    username = (attrs.get(username_attr, [None])[0] if username_attr else None) or name_id
    if not username:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error=no_username", status_code=302)

    dn_attr = cfg.get("display_name_attribute")
    display_name = (attrs.get(dn_attr, [None])[0] if dn_attr else None) or username

    role = cfg.get("default_role", "clevel")
    role_attr = cfg.get("role_attribute")
    saml_candidates = [v for v in attrs.get(role_attr, []) if v] if role_attr else []

    saml_mapped = await _resolve_role_from_groups(db, "saml2", saml_candidates)
    if saml_mapped:
        role = saml_mapped
    else:
        role_mapping: dict = cfg.get("role_mapping", {})
        for v in saml_candidates:
            if v in role_mapping:
                role = role_mapping[v]
                break

    try:
        user = await _provision_user(db, username, display_name, "saml2", role, cfg.get("auto_provision", True))
    except HTTPException as exc:
        return RedirectResponse(f"{frontend_url.rstrip('/')}?sso_error=access_denied&detail={exc.detail}", status_code=302)

    access_token, raw_refresh = await _issue_tokens(db, user)
    await _audit(db, user.id, "sso.login", {"provider": "saml2"}, ip=_ip(request))
    await db.commit()
    await db.refresh(user)

    return RedirectResponse(_frontend_redirect(frontend_url, access_token, raw_refresh, user), status_code=302)
