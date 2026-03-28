FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir hatchling build

COPY pyproject.toml VERSION README.md ./
COPY wafpass_server/ wafpass_server/
COPY alembic/ alembic/
COPY alembic.ini entrypoint.sh ./

RUN pip install --no-cache-dir . && chmod +x entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]
