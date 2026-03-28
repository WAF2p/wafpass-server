FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir hatchling build

COPY pyproject.toml VERSION README.md ./
COPY wafpass_server/ wafpass_server/
COPY alembic/ alembic/
COPY alembic.ini ./

RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["uvicorn", "wafpass_server.main:app", "--host", "0.0.0.0", "--port", "8000"]
