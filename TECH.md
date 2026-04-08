# wafpass-server — Technical Reference

This document covers internal architecture, design decisions, technical debt, and contribution guidance for `wafpass-server`. For user-facing documentation see `README.md`.

---

## Directory structure

```
wafpass-server/
├── wafpass_server/
│   ├── main.py          # FastAPI app factory, middleware, router registration, /health
│   ├── config.py        # Settings via pydantic-settings (env var parsing)
│   ├── database.py      # SQLAlchemy async engine + session factory
│   ├── models.py        # ORM models: Run, Control, Waiver, RiskAcceptance
│   ├── schemas.py       # Pydantic request/response models
│   └── routers/
│       ├── runs.py      # POST/GET /runs, /runs/{id}, /runs/{id}/findings, /runs/{id}/controls
│       ├── controls.py  # CRUD /controls (catalogue management)
│       ├── waivers.py   # PUT/GET/DELETE /waivers
│       ├── risks.py     # PUT/GET/DELETE /risks
│       └── sandbox.py   # POST /sandbox, GET /sandbox/status
├── alembic/
│   ├── env.py           # Alembic environment (async-compatible)
│   └── versions/
│       ├── 0001_create_runs.py
│       ├── 0002_add_run_metadata.py
│       ├── 0003_add_controls_meta.py
│       ├── 0004_add_plan_changes.py
│       ├── 0005_add_controls.py
│       ├── 0006_add_secret_findings.py
│       └── 0007_add_waivers_risks.py
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

## ORM models (`models.py`)

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

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

settings = Settings()  # Module-level singleton, read once at startup
```

All environment variables are read once at process start. There is no hot-reload of configuration.

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

### Findings stored as JSONB, filtered in Python

Filtering findings by `severity`, `pillar`, and `status` via `GET /runs/{id}/findings` loads the entire `findings` JSONB column and filters in Python. For large runs this is wasteful.

**Fix:** Either a separate `findings` table (one row per finding, with indexed columns) or PostgreSQL `jsonb_array_elements` for server-side filtering.

### Date/time fields as TEXT

`expires`, `accepted_at` in waivers and risk acceptances are stored as TEXT (ISO date strings) rather than `DATE`/`TIMESTAMPTZ`. This was intentional for flexibility (the dashboard sends whatever string the user typed) but means no database-level date validation or expiry querying.

**Fix:** Add a proper date column + migration. For now, expiry checks are done in the dashboard by comparing date strings.

### Inconsistent response envelope

The runs router returns raw lists; the controls router wraps in `{data, meta}`. This should be unified but is a breaking API change.

### No authentication

There is no authentication or authorisation. The API is designed for internal/team use behind a VPN or private network. Adding auth (API keys or OIDC) is the primary missing enterprise feature.

### No pagination on runs list

`GET /runs` supports `limit` and `offset` but the dashboard fetches `limit=100` and paginates in the browser. At large scale (10k+ runs) this wastes bandwidth. A cursor-based pagination scheme would be more robust.

### `wafpass_server.main` version string

The FastAPI app has `version="0.3.0"` hardcoded in `main.py`. This was not bumped in v0.4.0 and is inconsistent with `pyproject.toml` and `VERSION`. Fix: read from `importlib.metadata.version("wafpass-server")`.

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
