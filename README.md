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

# Apply database migrations
alembic upgrade head

# Start server with auto-reload
uvicorn wafpass_server.main:app --reload --port 8000
```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | PostgreSQL URL, e.g. `postgresql+asyncpg://user:pass@host/db` |
| `WAFPASS_ENV` | `local` | Environment tag (`local`, `staging`, `production`) |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed CORS origins |
| `WAFPASS_CONTROLS_DIR` | `controls` | Path to WAF++ control YAML files (used by Sandbox endpoint) |

---

## API reference

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
