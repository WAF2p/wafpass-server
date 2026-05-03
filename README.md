# wafpass-server

REST API for persisting and querying WAF++ PASS scan results. Part of the [WAF++ framework](https://waf2p.dev) monorepo.

| Component | Role |
|-----------|------|
| `pass/` · `wafpass-core` | Compliance engine, CLI, IaC parsers ← produces results |
| `wafpass-server/` · **this package** | FastAPI + PostgreSQL · stores results, exposes APIs |
| `wafpass-dashboard/` · React SPA | Consumes this API · visualises compliance posture |

---

## Quick start

### Docker Compose (recommended)

From the **repo root**:

```bash
cp .env.example .env        # fill in passwords
docker compose up --build
```

- API: `http://localhost:8000`
- Swagger UI: `http://localhost:8000/api/docs`
- Dashboard: `http://localhost:3000`

### Local development

```bash
# Prerequisites: PostgreSQL running locally
pip install -e ".[dev]"

# Copy and edit the environment file
cp .env.example .env
# Edit .env — at minimum set DATABASE_URL to point at your local PostgreSQL instance

# Export variables into your shell (or use direnv)
export $(grep -v '^#' .env | xargs)

# Apply database migrations
alembic upgrade head

# Start server with auto-reload
uvicorn wafpass_server.main:app --reload --port 8000
```

---

## Environment variables

Copy `.env.example` to `.env` for local development — it contains all variables with documented defaults.

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | PostgreSQL async DSN, e.g. `postgresql+asyncpg://user:pass@host:5432/db` |
| `WAFPASS_ENV` | `local` | Environment tag (`local`, `staging`, `production`) |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed CORS origins |
| `WAFPASS_CONTROLS_DIR` | `controls` | Path to WAF++ control YAML files (used by Sandbox endpoint) |
| `WAFPASS_JWT_SECRET` | `change-me-…` | HS256 signing key for access tokens. **Required in non-local environments** — the server refuses to start with the default value when `WAFPASS_ENV != local`. Generate with `openssl rand -hex 32`. |
| `WAFPASS_JWT_EXPIRE_MINUTES` | `60` | Access token lifetime in minutes |
| `WAFPASS_JWT_REFRESH_DAYS` | `7` | Refresh token lifetime in days |
| `WAFPASS_ENCRYPTION_KEY` | *(empty)* | At-rest encryption key for SSO secrets (OIDC client secret, SAML2 private key). Fernet-compatible 32-byte base64 key or any passphrase (PBKDF2-derived). **Required in non-local environments** — without it the server derives the key from `WAFPASS_JWT_SECRET`, which is insecure. Generate with `openssl rand -base64 32`. |
| `WAFPASS_SECRETS_BACKEND` | `local` | Encryption backend for SSO secrets: `local` (Fernet AES), `aws_sm` (AWS Secrets Manager), `vault_transit` (HashiCorp Vault Transit) |
| `WAFPASS_ADMIN_USERNAME` | `admin` | Username for the bootstrap admin user (seeded once on first startup) |
| `WAFPASS_ADMIN_PASSWORD` | *(empty)* | Password for the bootstrap admin — **set this** to enable auto-seeding |
| `WAFPASS_ADMIN_ROLE` | `engineer` | Role for the bootstrap admin (`clevel` \| `ciso` \| `architect` \| `engineer`) |
| `WAFPASS_API_KEY` | *(empty)* | Pre-shared key for CI/CD pushes — pass as `X-Api-Key` header on `POST /runs` / `POST /scan` |

> **Local dev tip:** When running the dashboard dev server alongside the API, add `http://localhost:5173` to `CORS_ORIGINS` so Vite's dev server can reach the API without CORS errors.

---

## Authentication

All API endpoints require a valid Bearer JWT except `POST /auth/login`, the SSO flow endpoints, and `GET /health`.

### Local accounts

```bash
# 1. Set admin credentials in .env (first-run only — auto-seeds one user)
WAFPASS_ADMIN_USERNAME=admin
WAFPASS_ADMIN_PASSWORD=changeme123
WAFPASS_ADMIN_ROLE=admin

# 2. Obtain a token
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme123"}' | jq -r .access_token)

# 3. Use it on any request
curl http://localhost:8000/runs -H "Authorization: Bearer $TOKEN"
```

### SSO (OIDC / SAML2)

SSO is configured through the dashboard **SSO Settings** page (admin only) or directly via the API. Configuration is stored in the database — no server restart required.

**OIDC flow:**
1. Admin configures discovery URL, client ID/secret, redirect URI, and role mapping in SSO Settings.
2. Users click "Sign in with OIDC" on the login page → redirect to IdP → callback → JWT issued.
3. `GET /auth/oidc/authorize` initiates the Authorization Code flow. A cryptographically random nonce is embedded in the signed state JWT and also sent to the IdP as the `nonce` parameter so the IdP includes it in the `id_token`.
4. `GET /auth/oidc/callback` exchanges the code, then:
   - Verifies the state JWT (CSRF protection).
   - Fetches the IdP's public JWKS from `jwks_uri` and verifies the `id_token` signature (RS256/EC).
   - Validates the `aud` claim equals `client_id` and the `nonce` claim matches the state JWT.
   - Provisions the user and issues a WAF++ JWT, then redirects to the dashboard.

**SAML2 flow:**
1. Admin configures SP/IdP entity IDs, ACS URL, IdP certificate, and role mapping.
2. Register the SP using the metadata endpoint: `GET /auth/saml/metadata`.
3. `GET /auth/saml/login` initiates the SP-initiated SSO redirect.
4. `POST /auth/saml/acs` validates the assertion, provisions the user, issues a JWT, and redirects.

> SAML2 requires the optional `python3-saml` system dependency: `pip install "wafpass-server[saml]"` (also needs `libxmlsec1` on the host).

### CI/CD (no user account needed)

Set `WAFPASS_API_KEY=some-secret` on the server and pass it as a header:

```bash
wafpass check ./terraform --output json | \
  curl -s -X POST http://localhost:8000/runs \
       -H "Content-Type: application/json" \
       -H "X-Api-Key: some-secret" \
       -d @-
```

### Role hierarchy

| Role | Inherits | Permitted operations |
|------|----------|---------------------|
| `clevel` | — | Read: all run data, waivers, risks, controls |
| `ciso` | clevel | + Create/update/delete waivers and risk acceptances |
| `architect` | ciso | + Create/delete controls catalogue entries, run sandbox |
| `engineer` | architect | + Trigger scans (`POST /scan`), user management |
| `admin` | engineer | + User lifecycle, API key management, SSO configuration |

---

## API reference

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/auth/login` | None | Exchange credentials for access + refresh tokens |
| `POST` | `/auth/refresh` | None | Exchange refresh token for new access token |
| `POST` | `/auth/logout` | None | Revoke a refresh token |
| `GET` | `/auth/me` | Any | Return current user profile |
| `GET` | `/auth/users` | engineer | List all users |
| `POST` | `/auth/users` | engineer | Create a user |
| `PUT` | `/auth/users/{id}` | engineer | Update user role / password / status |
| `DELETE` | `/auth/users/{id}` | engineer | Delete a user |

### SSO

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/sso/providers` | None | List enabled SSO providers (for login page) |
| `GET` | `/sso/config` | admin | List all SSO configurations |
| `PUT` | `/sso/config/{provider}` | admin | Upsert OIDC or SAML2 configuration |
| `DELETE` | `/sso/config/{provider}` | admin | Remove an SSO configuration |
| `GET` | `/sso/group-mappings` | admin | List all group → role mappings |
| `POST` | `/sso/group-mappings` | admin | Create a group → role mapping |
| `PUT` | `/sso/group-mappings/{id}` | admin | Update a group → role mapping |
| `DELETE` | `/sso/group-mappings/{id}` | admin | Delete a group → role mapping |
| `GET` | `/auth/oidc/authorize` | None | Initiate OIDC Authorization Code flow |
| `GET` | `/auth/oidc/callback` | None | OIDC callback — issue JWT, redirect to dashboard |
| `GET` | `/auth/saml/metadata` | None | SP metadata XML (register with IdP) |
| `GET` | `/auth/saml/login` | None | Initiate SAML2 SP-initiated SSO |
| `POST` | `/auth/saml/acs` | None | SAML2 Assertion Consumer Service |

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check → `{"status": "ok"}` |

### Runs

Ingest and retrieve compliance scan results produced by `wafpass check --output json`.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/runs` | Ingest a `wafpass-result.json` payload |
| `GET` | `/runs` | List runs (`limit`, `offset`, `project`) |
| `GET` | `/runs/{id}` | Full run with findings, controls metadata, secret findings |
| `GET` | `/runs/{id}/controls` | Controls metadata for a run |
| `GET` | `/runs/{id}/findings` | Filtered findings (`severity`, `pillar`, `status`) |

**Push a result from CI:**

```bash
wafpass check ./infra --output json | \
  curl -s -X POST http://localhost:8000/runs \
       -H "Content-Type: application/json" \
       -d @-
```

**Set metadata before posting:**

```python
import json, httpx

result = json.loads(open("wafpass-result.json").read())
result.update({"project": "my-infra", "branch": "main", "git_sha": "abc1234"})
httpx.post("http://localhost:8000/runs", json=result)
```

### Controls catalogue

Browse and manage WAF++ controls independently of scan runs.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/controls` | Upsert a control (returns `{data, meta}` envelope) |
| `GET` | `/controls` | List controls (`pillar`, `severity`, `page`, `per_page`) |
| `GET` | `/controls/{id}` | Get a single control |
| `DELETE` | `/controls/{id}` | Delete a control |

### Waivers

Team-shared waiver records. Suppresses a control from failing in the dashboard, shared across all team members.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/waivers` | List waivers (`project` filter — returns global + project-specific) |
| `PUT` | `/waivers/{id}` | Upsert a waiver (idempotent — create or update by control ID) |
| `DELETE` | `/waivers/{id}` | Delete a waiver |

```json
{
  "reason": "Covered by external quarterly IAM review — SEC-1234",
  "owner": "platform-team",
  "expires": "2026-09-30",
  "project": ""
}
```

### Risk acceptances

Formally accepted residual risks with approver sign-off, RFC, and traceability links.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/risks` | List risk acceptances |
| `PUT` | `/risks/{id}` | Upsert a risk acceptance |
| `DELETE` | `/risks/{id}` | Delete a risk acceptance |

```json
{
  "reason": "Legacy system — migration planned Q3 2026",
  "approver": "Jane Smith",
  "owner": "platform-team",
  "rfc": "RFC-0042",
  "jira_link": "https://jira.example.com/browse/SEC-100",
  "risk_level": "high",
  "residual_risk": "medium",
  "expires": "2026-09-30",
  "accepted_at": "2026-01-15T09:00:00Z",
  "project": ""
}
```

### Architect Sandbox

Run the real WAF++ engine against arbitrary HCL snippets in-process. Requires `wafpass-core` and a populated `WAFPASS_CONTROLS_DIR`.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/sandbox` | Evaluate HCL against all loaded controls |
| `GET` | `/sandbox/status` | Check engine availability |

```bash
# Check if engine is ready
curl http://localhost:8000/sandbox/status

# Run HCL snippet
curl -X POST http://localhost:8000/sandbox \
  -H "Content-Type: application/json" \
  -d '{"hcl": "resource \"aws_s3_bucket\" \"b\" {}", "iac": "terraform"}'
```

Without `wafpass-core`, the server starts normally and all other endpoints remain available. Sandbox returns `503` with a descriptive message.

### Evidence Locker

Cryptographically-locked, immutable audit packages. Locking freezes a run snapshot at the moment of creation, computes a SHA-256 hash of the canonical payload, and generates a shareable public token so auditors can view the package without a login.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/evidence` | engineer | Lock a run as an immutable evidence package |
| `GET` | `/evidence` | clevel | List evidence packages (`project`, `limit`, `offset`) |
| `GET` | `/evidence/{id}` | clevel | Get evidence metadata |
| `GET` | `/evidence/{id}/snapshot` | clevel | Return the raw frozen JSON snapshot |
| `GET` | `/evidence/{id}/report.html` | clevel | Download the locked HTML report |
| `GET` | `/evidence/{id}/qr.svg` | clevel | QR code SVG linking to the public auditor URL |
| `DELETE` | `/evidence/{id}` | admin | Delete an evidence package |
| `GET` | `/evidence/p/{token}` | None | Public auditor view (unauthenticated) |
| `GET` | `/evidence/p/{token}/qr.svg` | None | Public QR code (for PDF embedding) |
| `GET` | `/evidence/p/{token}/meta` | None | Public metadata (used by CLI) |

Each locked package includes: title, prepared-by, organization, audit period, regulatory frameworks, SHA-256 hash digest, a public token, and the locking user. The `WAFPASS_PUBLIC_URL` env var controls the base URL embedded in QR codes (defaults to the incoming request's scheme + host).

### Achievements

Maturity tier milestones. Achievements are awarded automatically when a project reaches a new compliance score threshold for the first time. The public verification page is unauthenticated, making achievements shareable on READMEs and external dashboards.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/achievements` | clevel | List all achievements (`project` filter) |
| `GET` | `/achievements/{project}` | clevel | List achievements for a project |
| `GET` | `/public/achievements/{token}` | None | Public cryptographic verification page |

Tier thresholds:

| Level | Label | Min Score |
|-------|-------|-----------|
| L1 | Foundational | 0 |
| L2 | Operational | 40 |
| L3 | Governed | 60 |
| L4 | Optimized | 75 |
| L5 | Excellence | 90 |

Achievements are evaluated automatically on every `POST /runs`. A new achievement is recorded only when the project reaches a tier level it has not previously held.

### Leaderboard

Hall of Fame — top sovereign and most improved projects across the organisation.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/leaderboard` | clevel | Top-sovereign and most-improved project rankings |

Returns two ranked lists:
- **Top Sovereign** — projects that have held Tier 5 the longest (by `achieved_at` ascending).
- **Most Improved** — projects that gained the most tier levels in the last 30 days.

Both lists include project display name, owner, team, current score, tier, and days held (from `ProjectPassport` if configured).

### Live Status Badges

Shields.io-style SVG badges for READMEs and external dashboards. Live badges reflect the latest run score; static tier badges are pre-rendered for air-gapped environments.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/public/badge/{project}.svg` | None | Dynamic SVG badge (latest run → tier label) |
| `GET` | `/public/badge/{project}/download` | None | Same badge with `Content-Disposition: attachment` |
| `GET` | `/public/badge/{project}/json` | None | JSON status (shields.io endpoint-badge compatible) |
| `GET` | `/public/badge/static/{tier_level}.svg` | None | Pre-rendered static badge (1–5) |

Embed a live badge in your README:

```markdown
![WAF++ PASS](https://wafpass.example.com/public/badge/my-project.svg)
```

For air-gapped environments: download via `/download` and commit the SVG.

### Project Passports

Per-project metadata — display name, owner, team, contact, description, criticality, environment, cloud provider, and repository/documentation URLs. Used by the Leaderboard and Dashboard pages to enrich project listings.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/projects/passports` | clevel | List all project passports |
| `GET` | `/projects/{project}/passport` | clevel | Get a project's passport |
| `PUT` | `/projects/{project}/passport` | architect | Upsert a project passport |
| `DELETE` | `/projects/{project}/passport` | admin | Delete a project passport |

### Findings Comments

Team collaboration on findings — comments, notifications, and remediation tracking. Comments can be added to regular findings or secret findings.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/findings-comments` | clevel | List comments for a run (`finding_id` or `secret_finding_id` filter) |
| `POST` | `/findings-comments` | clevel | Create a comment on a finding |
| `GET` | `/findings-comments/count` | clevel | Comment count per finding (aggregated) |

---

## Database migrations

Migrations use [Alembic](https://alembic.sqlalchemy.org/).

```bash
alembic upgrade head                           # apply all migrations
alembic downgrade -1                           # roll back one step
alembic revision --autogenerate -m "my change" # generate migration after editing models.py
alembic current                                # show applied revision
```

**Migration history:**

| Revision | Change |
|----------|--------|
| `0001_create_runs` | Initial runs table |
| `0002_add_run_metadata` | path, controls_loaded, controls_run, regions, source_paths |
| `0003_add_controls_meta` | controls_meta JSONB |
| `0004_add_plan_changes` | plan_changes JSONB |
| `0005_add_controls` | controls catalogue table |
| `0006_add_secret_findings` | secret_findings JSONB |
| `0007_add_waivers_risks` | waivers and risk_acceptances tables |
| `0008_add_stage_to_runs` | stage column on runs |
| `0009_add_auth_tables` | users and refresh_tokens tables |
| `0010_add_api_keys` | api_keys table |
| `0011_add_api_key_usage_logs` | api_key_usage_logs table |
| `0012_add_user_audit_logs` | user_audit_logs table |
| `0013_add_sso_config` | sso_configs table (OIDC + SAML2 configuration) |
| `0014_add_group_role_mappings` | group_role_mappings table (centralized IdP group → role resolution) |
| `0015_add_evidence` | evidence table (locked audit packages with SHA-256 hash and public token) |
| `0016_add_project_passports` | project_passports table (per-project metadata) |
| `0017_add_passport_image_url` | image_url column on project_passports |
| `0018_add_achievements` | project_achievements table (maturity tier milestones with verification tokens) |
| `0019_add_findings_comments` | findings_comments table (team collaboration on findings) |
| `0020_add_secret_findings_comments` | secret_findings_comments table (comments on secret findings) |

---

## Docker

The build context is the **monorepo root** because the Dockerfile copies `pass/` first to install `wafpass-core`:

```bash
# From repo root
docker build -t wafpass-server -f wafpass-server/Dockerfile .

docker run \
  -e DATABASE_URL=postgresql+asyncpg://wafpass:wafpass@host.docker.internal/wafpass \
  -e CORS_ORIGINS=http://localhost:3000 \
  -e WAFPASS_CONTROLS_DIR=/app/controls \
  -p 8000:8000 \
  wafpass-server
```

The entrypoint (`entrypoint.sh`) runs `alembic upgrade head` automatically before starting uvicorn — no manual migration step needed in production.

**Custom controls directory:**

```yaml
# docker-compose.yml — wafpass-server service
volumes:
  - ./my-controls:/app/controls:ro
environment:
  WAFPASS_CONTROLS_DIR: /app/controls
```

---

## Interactive docs

| URL | Description |
|-----|-------------|
| `http://localhost:8000/api/docs` | Swagger UI — try requests in browser |
| `http://localhost:8000/api/redoc` | ReDoc — read-only reference |

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

See `TECH.md` for architecture details, database schema, and contribution guidance.
