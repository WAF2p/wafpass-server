# Software Bill of Materials and License Overview

This document summarizes the software components used by **wafpass-server**
and their licenses. It is generated for CNCF submission readiness.

## Project metadata

- **Project:** wafpass-server
- **Own license:** Apache-2.0
- **License file present:** yes

## SBOM artifacts

Every build produces the following artifacts (uploaded to GitHub Actions):

- `sbom.cyclonedx.json` — CycloneDX 1.6 JSON
- `sbom.spdx.json` — SPDX 2.3 JSON
- `licenses.json` — License report (JSON)

Release builds also attach the CycloneDX and SPDX files to the GitHub release.

## Dependency summary

- **Total detected packages:** 47

### License distribution

| License | Count |
|---------|-------|
| MIT | 25 |
| BSD-3-Clause | 10 |
| Apache-2.0 | 7 |
| MPL-2.0 | 1 |
| MIT-0 | 1 |
| BSD-2-Clause | 1 |
| ISC | 1 |
| PSF-2.0 | 1 |

## Package list

| Package | Version | License |
|---------|---------|---------|
| alembic | 1.20.0 | MIT |
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| asyncpg | 0.31.0 | Apache-2.0 |
| bcrypt | 5.0.0 | Apache-2.0 OR License :: OSI Approved :: Apache Software License |
| certifi | 2026.7.22 | MPL-2.0 OR License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0) |
| cffi | 2.1.1 | MIT-0 |
| click | 8.5.0 | BSD-3-Clause |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| fastapi | 0.142.2 | MIT |
| greenlet | 3.5.6 | MIT AND PSF-2.0 |
| h11 | 0.16.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httptools | 0.8.0 | MIT |
| httpx | 0.28.1 | BSD-3-Clause OR License :: OSI Approved :: BSD License |
| idna | 3.20 | BSD-3-Clause |
| lark | 1.3.1 | MIT |
| Mako | 1.4.3 | MIT |
| markdown-it-py | 4.2.0 | MIT |
| MarkupSafe | 3.0.4 | BSD-3-Clause |
| mdurl | 0.1.2 | MIT |
| opentelemetry-api | 1.45.0 | Apache-2.0 |
| pip | 26.2.1 | MIT |
| pycparser | 3.0 | BSD-3-Clause |
| pydantic | 2.13.5 | MIT |
| pydantic-settings | 2.15.0 | MIT |
| pydantic_core | 2.46.5 | MIT |
| Pygments | 2.21.0 | BSD-2-Clause |
| PyJWT | 2.15.1 | MIT |
| python-dotenv | 1.2.4 | BSD-3-Clause |
| python-hcl2 | 8.1.4 | MIT |
| python-multipart | 0.0.32 | Apache-2.0 |
| PyYAML | 6.0.3 | MIT |
| regex | 2026.9.29 | Apache-2.0 AND CNRI-Python |
| rich | 15.0.0 | MIT |
| shellingham | 1.5.4 | ISC |
| SQLAlchemy | 2.1.3 | MIT |
| starlette | 1.7.0 | BSD-3-Clause |
| typer | 0.27.2 | MIT |
| typing-inspection | 0.4.4 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |
| uvicorn | 0.54.0 | BSD-3-Clause |
| uvloop | 0.23.0 | MIT OR License :: OSI Approved :: Apache Software License |
| wafpass-core | 1.1.2 | Apache-2.0 OR License :: OSI Approved :: Apache Software License |
| watchfiles | 1.3.0 | MIT |
| websockets | 17.2 | BSD-3-Clause |

---

*Generated automatically from SBOM and license scan data.*