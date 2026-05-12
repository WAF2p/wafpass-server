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

RUN pip install --no-cache-dir ".[qr]" && chmod +x entrypoint.sh

# Copy WAF++ control YAML files so the sandbox engine can find them.
# The pass/ directory was already used to install wafpass-core above, but the
# controls/ subdirectory is data (not Python code) and is not installed by pip.
COPY pass/controls/ /app/controls/

# Default controls path — override with WAFPASS_CONTROLS_DIR if you mount your
# own controls volume (e.g. for custom/enterprise controls).
ENV WAFPASS_CONTROLS_DIR=/app/controls

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]
