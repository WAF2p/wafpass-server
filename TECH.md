# wafpass-server — Technical Reference

This document covers internal architecture, design decisions, technical debt, and contribution guidance for `wafpass-server`. For user-facing documentation see `README.md`.

---

## Directory structure

```
wafpass-server/
├── wafpass_server/
│   ├── main.py          # FastAPI app factory, middleware, router registration, /health, startup seeding
│   ├── config.py        # Settings via pydantic-settings (env var parsing)
│   ├── database.py      # SQLAlchemy async engine + session factory
│   ├── models.py        # ORM models: User, RefreshToken, SsoConfig, Run, Control, Waiver, RiskAcceptance,
│   │                    #             ApiKey, Evidence, ProjectPassport, ProjectAchievement, …
│   ├── schemas.py       # Pydantic response/input schemas (AchievementOut, ProjectPassportOut, …)
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── jwt_utils.py          # create_access_token, decode_access_token (HS256)
│   │   ├── deps.py               # get_current_user, require_role(), require_ingest()
│   │   └── providers/
│   │       ├── base.py           # AuthProvider protocol + UserRecord dataclass
│   │       └── local.py          # bcrypt password verify
│   └── routers/
│       ├── auth.py          # POST/GET /auth/login, /refresh, /logout, /me, /users, /api-keys
│       ├── sso.py           # GET/PUT/DELETE /sso/config, OIDC + SAML2 login flows
│       ├── runs.py          # POST/GET /runs (auth-gated); triggers achievement evaluation on ingest
│       ├── controls.py      # CRUD /controls (auth-gated)
│       ├── waivers.py       # PUT/GET/DELETE /waivers (auth-gated)
│       ├── risks.py         # PUT/GET/DELETE /risks (auth-gated)
│       ├── sandbox.py       # POST /sandbox, GET /sandbox/status (auth-gated)
│       ├── scan.py          # POST /scan, GET /scan/status (auth-gated)
│       ├── evidence.py      # Evidence Locker — locked audit packages with QR codes and public tokens
│       ├── achievements.py  # Maturity tier milestones + public verification page
│       ├── leaderboard.py   # Hall of Fame — top sovereign + most improved rankings
│       ├── badges.py        # Live SVG badges and shields.io-compatible JSON endpoint
│       ├── projects.py      # Project Passport CRUD
│       ├── findings_comments.py       # Team collaboration on regular findings
│       └── secret_findings_comments.py # Team collaboration on secret findings
├── alembic/
│   ├── env.py           # Alembic environment (async-compatible)
│   └── versions/
│       ├── 0001_create_runs.py
│       ├── 0002_add_run_metadata.py
│       ├── 0003_add_controls_meta.py
│       ├── 0004_add_plan_changes.py
│       ├── 0005_add_controls.py
│       ├── 0006_add_secret_findings.py
│       ├── 0007_add_waivers_risks.py
│       ├── 0008_add_stage_to_runs.py
│       ├── 0009_add_auth_tables.py
│       ├── 0010_add_api_keys.py
│       ├── 0011_add_api_key_usage_logs.py
│       ├── 0012_add_user_audit_logs.py
│       ├── 0013_add_sso_config.py
│       ├── 0014_add_group_role_mappings.py
│       ├── 0015_add_evidence.py
│       ├── 0016_add_project_passports.py
│       ├── 0017_add_passport_image_url.py
│       ├── 0018_add_achievements.py
│       ├── 0019_add_findings_comments.py
│       └── 0020_add_secret_findings_comments.py
├── alembic.ini
├── entrypoint.sh        # Runs migrations then starts uvicorn
├── Dockerfile
└── pyproject.toml
```

---

## Architecture

### Request lifecycle

```
HTTP request
    │
    ▼
CORS middleware (CORSMiddleware)
    │
    ▼
FastAPI router (path matching, input validation via Pydantic)
    │
    ▼
Auth dependency (get_current_user / require_role / require_ingest)
    │  ├─ HTTPBearer extracts token from Authorization header
    │  ├─ PyJWT verifies signature + expiry
    │  └─ User looked up from DB — 401/403 if invalid
    ▼
Dependency injection: get_db() → AsyncSession
    │
    ▼
Router handler (async function)
    │
    ▼
SQLAlchemy async ORM operations
    │
    ▼
await session.commit() / refresh()
    │
    ▼
Pydantic response model serialization
    │
    ▼
JSON response
```

### Database session management (`database.py`)

```python
# Engine is created once at startup
engine = create_async_engine(settings.database_url, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

# Dependency injected into every route handler
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
```

`expire_on_commit=False` is intentional: it prevents SQLAlchemy from expiring ORM attributes after commit, which would cause lazy-load errors in async context (async SQLAlchemy does not support lazy loading).

### JSONB storage strategy

Several large columns (`findings`, `controls_meta`, `secret_findings`, `plan_changes`, `pillar_scores`) are stored as PostgreSQL JSONB. The column type in SQLAlchemy is `JSONB` (`sqlalchemy.dialects.postgresql`), not `JSON` — JSONB is stored compressed and indexed, and allows GIN indexes for future filtering.

**Design tradeoff:** JSONB is fast to write and flexible to evolve, but querying inside JSONB from SQLAlchemy requires raw SQL or jsonpath expressions. Currently all filtering (`severity`, `pillar`, `status` on findings) is done in Python after fetching, not in SQL. This is fine for datasets of ~thousands of findings per run but becomes a bottleneck at scale.

**Technical debt:** Findings are fetched in full and filtered in Python. For runs with 10k+ findings this causes unnecessary memory allocation. The fix is a `jsonb_array_elements` SQL expression or a separate `findings` table.

---

## Authentication architecture (`auth/`)

### Token flows

**Local login:**
```
Browser / CLI
    │  POST /auth/login {username, password}
    ▼
auth/providers/local.py  ─── bcrypt verify ──▶  users table
    │  success: issue tokens
    ▼
jwt_utils.py
    ├─ create_access_token()  →  HS256 JWT (sub, username, role, exp)
    └─ secrets.token_urlsafe()  →  opaque refresh token (stored hashed in refresh_tokens)
    │  {access_token, refresh_token, user}
    ▼
Browser stores both in localStorage
```

**OIDC login:**
```
Browser
    │  GET /auth/oidc/authorize
    ▼
routers/sso.py  ─── fetch discovery doc ──▶  IdP /.well-known/openid-configuration
    │  generate nonce=random_hex(16), state=HS256_JWT{nonce, exp}
    │  302 redirect with state + nonce params
    ▼
IdP authentication page  (IdP binds nonce into id_token)
    │  302 redirect back  ?code=…&state=…
    ▼
GET /auth/oidc/callback
    ├─ verify JWT state (signed with WAFPASS_JWT_SECRET, 10 min TTL) → extract nonce
    ├─ POST token_endpoint  →  id_token + access_token
    ├─ fetch JWKS from discovery["jwks_uri"]
    ├─ verify id_token signature (RS256/EC) using IdP public key
    ├─ validate aud == client_id and nonce claim matches state nonce
    │  (returns sso_error=token_verification_failed on any mismatch)
    ├─ provision/update User row (auth_provider="oidc")
    └─ issue WAF++ JWT + refresh token
    │  302 redirect  {frontend_url}?sso_ok=1&at=…&rt=…&u=BASE64_USER
    ▼
Dashboard: AuthContext detects sso_ok=1 query param on mount → stores tokens
```

**SAML2 login:**
```
Browser
    │  GET /auth/saml/login
    ▼
routers/sso.py  ─── python3-saml AuthnRequest ──▶  302 redirect to IdP SSO URL
    ▼
IdP authentication + consent
    │  POST /auth/saml/acs  {SAMLResponse=…}
    ▼
routers/sso.py
    ├─ python3-saml process_response()  ──▶  validate XML signature with IdP cert
    ├─ extract NameID + configured attributes
    ├─ provision/update User row (auth_provider="saml2")
    └─ issue WAF++ JWT + refresh token
    │  302 redirect  {frontend_url}?sso_ok=1&at=…&rt=…&u=BASE64_USER
    ▼
Dashboard: AuthContext detects sso_ok=1 query param on mount → stores tokens
```

### JWT claims

```json
{
  "sub":      "user-uuid",
  "username": "s.lewandowski",
  "role":     "engineer",
  "type":     "access",
  "iat":      1234567890,
  "exp":      1234571490
}
```

### Role hierarchy

```python
ROLE_HIERARCHY = ["clevel", "ciso", "architect", "engineer", "admin"]
```

`require_role("ciso")` accepts any user with index ≥ 1 (ciso, architect, engineer, admin).

### SSO configuration storage

SSO provider settings are stored in the `sso_configs` table (one row per provider: `oidc` or `saml2`). The `config` column is JSONB and holds all provider-specific fields (discovery URL, client credentials, certificate PEM, role mapping, etc.). This allows runtime reconfiguration without restarting the server.

Sensitive values (OIDC `client_secret`, SAML2 `sp_private_key`) are encrypted at rest before being written to the database by `secret_enc.py`. Three backends are supported:

| Backend | `WAFPASS_SECRETS_BACKEND` | Key source |
|---------|--------------------------|-----------|
| Local Fernet (default) | `local` | `WAFPASS_ENCRYPTION_KEY` (32-byte base64 or passphrase → PBKDF2) |
| AWS Secrets Manager | `aws_sm` | ARN stored in DB; secret value in AWS |
| HashiCorp Vault Transit | `vault_transit` | Opaque ciphertext in DB; Vault holds the key |

In non-local environments (`WAFPASS_ENV != local`) the server refuses to start unless `WAFPASS_ENCRYPTION_KEY` is explicitly set — falling back to derivation from `WAFPASS_JWT_SECRET` is blocked by a startup validator in `config.py`.

### Machine-to-machine (CI/CD)

`require_ingest` on `POST /runs` and `POST /scan` accepts **either** a valid Bearer JWT **or** the `X-Api-Key` header matching `WAFPASS_API_KEY`. This lets `wafpass check --push` work from CI pipelines without a user account.

### Provider abstraction

`auth/providers/base.py` defines an `AuthProvider` Protocol. `local.py` handles bcrypt passwords. SSO flows (OIDC, SAML2) live in `routers/sso.py` — they bypass the provider protocol entirely and provision users directly after validating the IdP response. LDAP is planned for a future release.

### Bootstrap admin seeding

On startup, if `WAFPASS_ADMIN_PASSWORD` is set and the `users` table is empty, the server creates one admin user. This runs exactly once — subsequent restarts skip it because the table is no longer empty.

---

## ORM models (`models.py`)

### User / RefreshToken / SsoConfig

```
users
├── id             UUID   PK
├── username       TEXT   UNIQUE NOT NULL
├── display_name   TEXT
├── role           TEXT   (clevel | ciso | architect | engineer | admin)
├── auth_provider  TEXT   (local | oidc | saml2)
├── password_hash  TEXT   NULL for SSO users
├── is_active      BOOL
├── last_login_at  TIMESTAMPTZ  NULL
├── created_at     TIMESTAMPTZ
└── updated_at     TIMESTAMPTZ

refresh_tokens
├── id             UUID   PK
├── user_id        UUID   FK → users.id  ON DELETE CASCADE
├── token_hash     TEXT   UNIQUE  (SHA-256 of raw token)
├── expires_at     TIMESTAMPTZ
├── revoked        BOOL
└── created_at     TIMESTAMPTZ

sso_configs                         # one row per provider ("oidc" | "saml2")
├── id             TEXT   PK
├── enabled        BOOL
├── config         JSONB   # all provider-specific settings (see below)
├── updated_at     TIMESTAMPTZ
└── updated_by     UUID   NULL  (FK to users.id — not enforced)
```

**OIDC `config` keys:** `discovery_url`, `client_id`, `client_secret`, `redirect_uri`, `frontend_url`, `scopes` (list), `username_claim`, `display_name_claim`, `default_role`, `role_claim`, `role_mapping` (object), `auto_provision`.

**SAML2 `config` keys:** `entity_id`, `acs_url`, `sp_certificate`, `sp_private_key`, `idp_entity_id`, `idp_sso_url`, `idp_certificate`, `frontend_url`, `username_attribute`, `display_name_attribute`, `default_role`, `role_attribute`, `role_mapping` (object), `auto_provision`.

### Run

```
runs
├── id             UUID   PK (server_default = gen_random_uuid())
├── project        TEXT
├── branch         TEXT
├── git_sha        TEXT
├── triggered_by   TEXT
├── iac_framework  TEXT
├── score          INTEGER
├── pillar_scores  JSONB
├── findings       JSONB   # list[FindingSchema]
├── controls_meta  JSONB   # list[ControlMetaSchema]
├── secret_findings JSONB  # list[SecretFindingSchema]
├── plan_changes   JSONB   # PlanChanges | null
├── path           TEXT
├── controls_loaded INTEGER
├── controls_run    INTEGER
├── detected_regions JSONB # list[list[str]] — [[region, provider], ...]
├── source_paths   JSONB   # list[str]
└── created_at     TIMESTAMPTZ server_default=now()
```

### Control (catalogue)

```
controls
├── id             TEXT   PK  (e.g. "WAF-SEC-010")
├── pillar         TEXT
├── severity       TEXT
├── type           JSONB  # list[str]
├── description    TEXT
├── checks         JSONB  # list[WizardCheck]
├── source         TEXT   # "builtin" | "custom" | user-defined
├── created_at     TIMESTAMPTZ
└── updated_at     TIMESTAMPTZ (onupdate=func.now())
```

### Waiver

```
waivers
├── id             TEXT   PK  (control ID used as key)
├── reason         TEXT
├── owner          TEXT
├── expires        TEXT   (ISO date string — not a date column; see tech debt)
├── project        TEXT   ("" = global)
├── created_at     TIMESTAMPTZ
└── updated_at     TIMESTAMPTZ
```

### RiskAcceptance

```
risk_acceptances
├── id             TEXT   PK
├── reason         TEXT
├── approver       TEXT
├── owner          TEXT
├── rfc            TEXT
├── jira_link      TEXT
├── other_link     TEXT
├── notes          TEXT
├── risk_level     TEXT   ("accepted" | "mitigated" | user-defined)
├── residual_risk  TEXT   ("low" | "medium" | "high")
├── expires        TEXT   (ISO date string)
├── accepted_at    TEXT   (ISO datetime string)
├── project        TEXT
├── created_at     TIMESTAMPTZ
└── updated_at     TIMESTAMPTZ
```

### Evidence

Immutable, locked audit package. The `snapshot` JSONB column is written once and never mutated. The SHA-256 hash of the canonical snapshot (`json.dumps(snapshot, sort_keys=True)`) is stored in `hash_digest` and serves as the integrity proof handed to auditors. `public_token` is a 32-character URL-safe random string that lets unauthenticated viewers access the evidence report (`/evidence/p/{token}`) and QR code without a login.

```
evidence
├── id             UUID   PK  (server_default = gen_random_uuid())
├── run_id         UUID   FK → runs.id
├── title          TEXT
├── note           TEXT
├── project        TEXT   (copied from the run at lock time)
├── prepared_by    TEXT
├── organization   TEXT
├── audit_period   TEXT
├── frameworks     JSONB  list[str]  (e.g. ["ISO 27001", "SOC2"])
├── snapshot       JSONB  (frozen payload — run, findings, waivers, risks, audit log)
├── report_html    TEXT   NULL  (optional pre-rendered HTML)
├── hash_digest    TEXT   (SHA-256 of canonical snapshot)
├── public_token   TEXT   UNIQUE  (URL-safe random 32-char token)
├── locked_by      UUID   FK → users.id  NULL
└── created_at     TIMESTAMPTZ  server_default=now()
```

**QR code generation:** Requires the optional `segno` library (`pip install segno`). If unavailable, a plain SVG placeholder is returned. The QR code URL embeds `WAFPASS_PUBLIC_URL` (from env) as the base; falls back to the incoming request's `X-Forwarded-Proto` / `X-Forwarded-Host` headers.

### ProjectPassport

Per-project metadata used by the Leaderboard, Dashboard, and Badge pages to enrich project listings. Upserted by architects; readable by all roles.

```
project_passports
├── project        TEXT   PK
├── display_name   TEXT
├── owner          TEXT
├── owner_team     TEXT
├── contact_email  TEXT
├── description    TEXT
├── criticality    TEXT   (e.g. "critical", "high", "medium", "low")
├── environment    TEXT   (e.g. "production", "staging")
├── cloud_provider TEXT   (e.g. "aws", "azure", "gcp")
├── repository_url TEXT
├── documentation_url TEXT
├── image_url      TEXT   (logo / avatar URL)
├── tags           JSONB  list[str]
├── notes          TEXT
├── updated_by     TEXT   (username of last editor)
├── created_at     TIMESTAMPTZ
└── updated_at     TIMESTAMPTZ
```

### ProjectAchievement

Maturity tier milestone records. One row per `(project, tier_level)` pair — a project can hold at most one achievement per tier (lower tiers are never revoked when a higher tier is reached). `verification_token` is a 44-character URL-safe random string that serves as the publicly-shareable proof of achievement at `/public/achievements/{token}`.

```
project_achievements
├── id                  UUID   PK
├── project             TEXT   NOT NULL
├── tier_level          INTEGER  (1–5)
├── tier_label          TEXT   ("Foundational" | "Operational" | "Governed" | "Optimized" | "Excellence")
├── score               INTEGER  (score at the time of achievement)
├── run_id              UUID   FK → runs.id  NULL
├── verification_token  TEXT   UNIQUE  (44-char URL-safe random token)
├── snapshot_jsonb      JSONB  (pillar_scores at achievement time)
└── achieved_at         TIMESTAMPTZ  server_default=now()
```

**Achievement evaluation flow:** `POST /runs` calls `evaluate_and_record_achievements(db, run)` after persisting the run. The function checks which tier thresholds the run's score qualifies for and creates `ProjectAchievement` rows only for tiers the project has not previously held.

---

## Router patterns

### Upsert pattern (waivers and risks)

Both waivers and risk acceptances use PUT for both create and update (true upsert). The handler checks for an existing row by ID and adds or updates accordingly:

```python
@router.put("/{waiver_id}", response_model=WaiverOut)
async def upsert_waiver(waiver_id: str, payload: WaiverUpsert, db: AsyncSession = Depends(get_db)):
    existing = await db.get(Waiver, waiver_id)
    if existing is None:
        db.add(Waiver(id=waiver_id, **payload.model_dump()))
    else:
        for k, v in payload.model_dump().items():
            setattr(existing, k, v)
    await db.commit()
    waiver = await db.get(Waiver, waiver_id)
    return waiver
```

This avoids a race condition from SELECT-then-INSERT and is idempotent — the dashboard can call PUT on every save without worrying about duplicates.

### Envelope pattern (controls catalogue)

The controls catalogue wraps responses in `{data, meta}`:

```python
class Envelope(BaseModel, Generic[T]):
    data: T
    meta: Meta = Meta()   # {total, page, per_page}
```

This allows pagination metadata without breaking the response contract when `data` is a list. Only the controls router uses this pattern; the runs router returns lists directly (technical inconsistency — see tech debt).

### Sandbox: lazy import + temp directory

The sandbox router avoids importing `wafpass-core` at startup:

```python
_wafpass_available: bool | None = None

def _check_wafpass() -> bool:
    global _wafpass_available
    if _wafpass_available is None:
        try:
            import wafpass.engine  # noqa: F401
            _wafpass_available = True
        except ImportError:
            _wafpass_available = False
    return _wafpass_available
```

This lets the server start cleanly even when `wafpass-core` is not installed — all other endpoints work normally. The sandbox router checks availability on every request and returns `503` if unavailable.

HCL evaluation uses a temporary directory:

```python
with tempfile.TemporaryDirectory() as tmpdir:
    hcl_file = Path(tmpdir) / payload.filename
    hcl_file.write_text(payload.hcl, encoding="utf-8")
    plugin = registry.get(payload.iac.lower())
    state = plugin.parse(Path(tmpdir))
    results = run_controls(controls, state, engine_name=payload.iac.lower())
```

The temp directory is cleaned up automatically by the context manager, even on exceptions.

---

## Configuration (`config.py`)

Uses `pydantic-settings` to read environment variables:

```python
class Settings(BaseSettings):
    database_url: str
    wafpass_env: str = "local"
    cors_origins: str = "http://localhost:3000"
    wafpass_controls_dir: str = "controls"
    wafpass_jwt_secret: str = _DEFAULT_JWT_SECRET
    wafpass_encryption_key: str = ""

    @model_validator(mode="after")
    def _require_non_default_secrets_in_production(self) -> "Settings":
        if self.wafpass_env == "local":
            return self
        if self.wafpass_jwt_secret == _DEFAULT_JWT_SECRET:
            raise ValueError("WAFPASS_JWT_SECRET must be changed from the default value.")
        if not self.wafpass_encryption_key:
            raise ValueError("WAFPASS_ENCRYPTION_KEY must be set in non-local environments.")
        return self

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

settings = Settings()  # Module-level singleton, read once at startup
```

All environment variables are read once at process start. There is no hot-reload of configuration.

**Startup enforcement:** When `WAFPASS_ENV` is anything other than `local`, the `model_validator` aborts startup (raises `ValidationError`) if `WAFPASS_JWT_SECRET` is still the shipped default or `WAFPASS_ENCRYPTION_KEY` is unset. Local development is unaffected.

**`.env.example`** (in the `wafpass-server/` directory) documents all variables with their defaults and usage notes. Copy it to `.env` for local development:

```bash
cp .env.example .env
export $(grep -v '^#' .env | xargs)
```

For Docker Compose, the root `.env.example` is used instead — docker compose reads `.env` from the monorepo root automatically.

---

## Alembic migrations

`alembic/env.py` is configured for async SQLAlchemy. Migrations run synchronously via `run_sync()`:

```python
with connectable.connect() as connection:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()
```

**Conventions:**
- Filename prefix: `NNNN_description.py` (sequential, no gaps)
- `server_default` instead of `default` for timestamps (database-level default, not SQLAlchemy-level)
- `server_default=""` for new text columns (ensures NOT NULL without Python-side population)
- Always set `down_revision` to the previous migration's revision ID

---

## Docker build

The Dockerfile uses the **monorepo root** as build context (not `wafpass-server/`) because it needs to COPY `pass/` to install `wafpass-core`:

```dockerfile
# Build context: repo root (.)
COPY pass/ /tmp/wafpass-core/
RUN pip install --no-cache-dir /tmp/wafpass-core && rm -rf /tmp/wafpass-core

# Controls YAMLs must be copied separately — they're data, not installed by pip
COPY pass/controls/ /app/controls/
ENV WAFPASS_CONTROLS_DIR=/app/controls
```

`pass/controls/` was initially forgotten after the pip install deleted `/tmp/wafpass-core/`. The separate `COPY pass/controls/` step was added in v0.4.0 to fix the sandbox router.

---

## Technical debt

### No LDAP (Phase 3+)

OIDC and SAML2 are live. LDAP / Kerberos bind against Active Directory is planned for a future release. The `auth/providers/base.py` protocol is ready for an `ldap.py` implementation.

---

## Development

```bash
pip install -e ".[dev]"

# Run tests
pytest

# Check types
mypy wafpass_server/

# Lint
ruff check wafpass_server/
```

### Adding a new endpoint

1. Create or edit a file in `routers/`
2. Add the router to `main.py` with `app.include_router(...)`
3. Add Pydantic schemas to `schemas.py`
4. If new tables are needed: edit `models.py` and generate a migration with `alembic revision --autogenerate -m "description"`
5. Update `README.md` API reference table
