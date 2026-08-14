# Contributing to wafpass-server

Thank you for contributing to WAF++ PASS Server — the REST API that persists and queries WAF++ compliance scan results.

This document is intentionally short and points to existing files in the repository. When in doubt, check `README.md` for the user-facing API reference and `TECH.md` for architecture and internal conventions.

---

## What this project is

`wafpass-server` is a FastAPI application backed by PostgreSQL. It stores scan runs produced by the `wafpass` CLI / `wafpass-core` package, exposes CRUD endpoints, and provides authentication (local JWT, OIDC, SAML2), user management, evidence locking, project passports, and public badges.

Source layout:

```
wafpass-server/
├── wafpass_server/          # Application code
│   ├── main.py              # FastAPI factory, middleware, startup seeding
│   ├── config.py            # pydantic-settings environment parsing
│   ├── database.py          # Async SQLAlchemy engine + session factory
│   ├── models.py            # ORM models
│   ├── schemas.py           # Pydantic request/response schemas
│   ├── secret_enc.py        # SSO secret encryption backends
│   ├── auth/                # JWT utilities, dependencies, local provider
│   └── routers/             # Endpoint modules (runs, controls, sso, ...)
├── alembic/                 # Database migrations
├── tests/                   # pytest suite
├── Dockerfile
├── entrypoint.sh
├── pyproject.toml
├── .env.example
├── README.md
└── TECH.md
```

---

## Local development setup

1. Start PostgreSQL locally (or use the root `docker-compose.yml`).
2. Copy the environment template:

   ```bash
   cp .env.example .env
   # Edit .env — at minimum set DATABASE_URL
   export $(grep -v '^#' .env | xargs)
   ```

3. Install the package and dev dependencies:

   ```bash
   pip install -e ".[dev]"
   ```

4. Apply migrations:

   ```bash
   alembic upgrade head
   ```

5. Start the server with auto-reload:

   ```bash
   uvicorn wafpass_server.main:app --reload --port 8000
   ```

See `README.md` for the full quick-start and environment variable reference.

---

## Running checks

Before opening a pull request, run the same checks used in CI:

```bash
pytest
mypy wafpass_server/
ruff check wafpass_server/
```

`pytest` runs the test suite under `tests/`. `mypy` and `ruff` cover the application code in `wafpass_server/`.

---

## Adding a new endpoint

Follow the five-step process used throughout the codebase (also documented in `TECH.md`):

1. Create or edit a router in `wafpass_server/routers/`.
2. Register the router in `wafpass_server/main.py` with `app.include_router(...)`.
3. Add Pydantic schemas to `wafpass_server/schemas.py`.
4. If new tables are needed, edit `wafpass_server/models.py` and generate a migration:

   ```bash
   alembic revision --autogenerate -m "description"
   ```

5. Update `README.md` API reference tables.

### Migration conventions

- Filename prefix: `NNNN_description.py` (sequential, no gaps).
- Use `server_default` for timestamps and new `NOT NULL` text columns.
- Always set `down_revision` to the previous migration's revision ID.

See `TECH.md` for the full migration guide.

---

## Pull request expectations

- Open PRs against the `main` branch.
- Keep changes focused on one concern per PR.
- Ensure `pytest`, `mypy wafpass_server/`, and `ruff check wafpass_server/` pass locally.
- Update `README.md` and `TECH.md` if you add or change user-facing behavior, API endpoints, or internal architecture.
- Write clear commit messages that explain the *why*, not just the *what*.

---

## License and conduct

By contributing, you agree that your contributions will be licensed under the Apache License 2.0 (see `LICENSE`).

Please read and follow our `CODE_OF_CONDUCT.md` and `SECURITY.md`.
