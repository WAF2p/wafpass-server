# Security policy for wafpass-server

This document covers how to report security issues in `wafpass-server`, what is in scope, and how to configure the server securely.

For operational architecture and internal security design details, see `TECH.md`.

---

## Supported versions

Only the current `main` branch and the latest published release are actively supported with security fixes. Releases are published automatically to PyPI from the `release.yml` workflow.

| Version | Supported |
|---------|-----------|
| Latest release on PyPI | Yes |
| `main` branch | Yes |
| Older releases | No |

---

## Reporting a vulnerability

If you discover a security vulnerability in `wafpass-server`, please report it privately rather than opening a public issue or pull request.

Options:

- Open a [GitHub Security Advisory](https://github.com/WAF2p/wafpass-server/security/advisories/new) if private vulnerability reporting is enabled for the repository.
- Otherwise, send a direct message to one of the maintainers listed in `pyproject.toml` under `authors`.

Please include:

- A clear description of the vulnerability
- Steps to reproduce, or a minimal proof of concept
- The affected version or commit
- Any suggested mitigation

We aim to acknowledge reports within 5 business days and will keep you informed during investigation.

---

## Scope

The following are in scope for vulnerability reports:

- The `wafpass-server` Python package (`wafpass_server/`)
- The published Docker image (`wafpass-server/Dockerfile`)
- The REST API surface documented in `README.md`
- Authentication and authorization logic in `wafpass_server/auth/`
- SSO/OIDC/SAML2 flows in `wafpass_server/routers/sso.py`
- Encryption of SSO secrets in `wafpass_server/secret_enc.py`

Out of scope:

- The `wafpass` CLI / `wafpass-core` scanning engine (report in the `pass` repository)
- The `wafpass-dashboard` React UI (report in the `wafpass-dashboard` repository)
- Generic dependency vulnerabilities unless they are exploitable through this server's own code

---

## Security-sensitive configuration

The server refuses to start in non-local environments unless critical secrets are configured. This is enforced in `wafpass_server/config.py`.

### Required in production

| Environment variable | Purpose | Guidance |
|----------------------|---------|----------|
| `WAFPASS_JWT_SECRET` | HS256 signing key for access tokens | Must be changed from the shipped default. Generate with `openssl rand -hex 32`. |
| `WAFPASS_ENCRYPTION_KEY` | At-rest encryption key for SSO secrets | Generate with `openssl rand -base64 32`. Required when `WAFPASS_ENV != local`. |

Never commit these values. Use Docker secrets, a secret manager, or environment injection instead of plain `.env` files in production.

### Optional secrets backends

`wafpass_server/secret_enc.py` supports three backends for storing IdP secrets:

| Backend | `WAFPASS_SECRETS_BACKEND` | Notes |
|---------|--------------------------|-------|
| Local Fernet (default) | `local` | Uses `WAFPASS_ENCRYPTION_KEY` directly. |
| AWS Secrets Manager | `aws_sm` | Secret value is held in AWS; the DB stores an ARN. |
| HashiCorp Vault Transit | `vault_transit` | Vault holds the key; the DB stores ciphertext. |

Prefer `aws_sm` or `vault_transit` in production over the local Fernet backend.

### Other security-relevant settings

- `WAFPASS_ENV`: Set to `production` in production so the startup validators run.
- `WAFPASS_API_KEY`: Use a long random value for CI/CD ingestion. Rotate it regularly.
- `CORS_ORIGINS`: Restrict to known origins; do not use `*` in production.
- `WAFPASS_PUBLIC_URL`: Controls the base URL in public evidence/achievement/badge links. Set it to the public-facing HTTPS endpoint.

---

## Security design highlights

- Access tokens are short-lived HS256 JWTs (default 60 minutes).
- Refresh tokens are opaque, hashed with SHA-256, and stored in the `refresh_tokens` table.
- SSO `id_token` signatures are verified against the IdP's JWKS; `aud` and `nonce` claims are validated.
- SAML2 assertions are validated with the configured IdP certificate.
- SSO client secrets and SAML2 private keys are encrypted at rest before being written to PostgreSQL.
- Bootstrap admin seeding runs only once when the `users` table is empty.

---

## Disclosure policy

We follow a coordinated disclosure approach. Once a fix is available, we will:

1. Merge the fix and publish a new release.
2. Create a GitHub Security Advisory and/or release notes describing the issue without unnecessary detail.
3. Credit the reporter if they wish to be named.

Thank you for helping keep WAF++ PASS secure.
