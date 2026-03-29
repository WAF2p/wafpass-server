FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir hatchling build

# Install wafpass-core from the local sibling package (pass/).
# This must happen before wafpass-server is installed so that
# `from wafpass.control_schema import WizardControl` resolves correctly.
COPY pass/ /tmp/wafpass-core/
RUN pip install --no-cache-dir /tmp/wafpass-core && rm -rf /tmp/wafpass-core

COPY wafpass-server/pyproject.toml wafpass-server/VERSION wafpass-server/README.md ./
COPY wafpass-server/wafpass_server/ wafpass_server/
COPY wafpass-server/alembic/ alembic/
COPY wafpass-server/alembic.ini wafpass-server/entrypoint.sh ./

RUN pip install --no-cache-dir . && chmod +x entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]
