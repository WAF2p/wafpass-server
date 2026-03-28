# wafpass-server

REST API for persisting and querying WAF++ PASS scan results.

Receives `wafpass-result.json` payloads from `wafpass check --output json`,
stores them in PostgreSQL, and exposes them to the dashboard and CI tooling.

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/runs` | Ingest a `wafpass-result.json` payload |
| `GET` | `/runs` | List runs (query: `limit`, `offset`, `project`) |
| `GET` | `/runs/{id}` | Single run with all findings |
| `GET` | `/runs/{id}/findings` | Findings only (query: `severity`, `pillar`, `status`) |
| `GET` | `/health` | Health check |
| `GET` | `/api/docs` | Swagger UI |

## Setup

### Environment variables

Copy `.env.example` from the repo root:

```
DATABASE_URL=postgresql+asyncpg://wafpass:changeme@localhost:5432/wafpass
WAFPASS_ENV=local
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
```

### Run locally

```bash
pip install -e ".[dev]"
alembic upgrade head
uvicorn wafpass_server.main:app --reload --port 8000
```

### Run migrations

```bash
alembic upgrade head       # apply all migrations
alembic downgrade -1       # roll back one step
alembic revision --autogenerate -m "add column"  # generate new migration
```

### Docker

```bash
docker build -t wafpass-server .
docker run -e DATABASE_URL=... -p 8000:8000 wafpass-server
```

### docker-compose (full stack)

From the repo root:

```bash
cp .env.example .env   # fill in passwords
docker compose up
```

## Posting a scan result

```bash
wafpass check infra/ --output json > result.json
curl -X POST http://localhost:8000/runs \
     -H "Content-Type: application/json" \
     -d @result.json
```

Or set metadata fields before posting:

```python
import json, httpx

result = json.load(open("result.json"))
result.update({"project": "my-infra", "branch": "main", "git_sha": "abc1234"})
httpx.post("http://localhost:8000/runs", json=result)
```

## Result schema

The payload shape is defined by `WafpassResultSchema` in `wafpass-core`
(`wafpass/schema.py`). `wafpass-server` mirrors that schema in
`wafpass_server/schemas.py` (`RunCreate`). Once `wafpass-core` is published
to PyPI, replace the local definition with a direct import.

Key fields stored per run:

| Column | Type | Description |
|--------|------|-------------|
| `id` | uuid | Auto-generated primary key |
| `project` | text | Repo / project name |
| `branch` | text | VCS branch |
| `git_sha` | text | Commit SHA |
| `triggered_by` | text | `local` \| `github-actions` \| `gitlab-ci` \| … |
| `iac_framework` | text | `terraform` \| `cdk` \| … |
| `score` | int | Overall compliance score (0–100) |
| `pillar_scores` | jsonb | Per-pillar scores `{"SEC": 90, …}` |
| `findings` | jsonb | Array of check results |
| `created_at` | timestamptz | Inserted at |

## Development

```bash
pip install -e ".[dev]"
pytest
```
