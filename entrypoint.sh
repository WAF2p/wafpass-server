#!/bin/sh
set -e

echo "DATABASE_URL: $DATABASE_URL"

python - <<'EOF'
import os, sys
from alembic.config import Config
from alembic import command

url = os.environ.get("DATABASE_URL")
if not url:
    print("ERROR: DATABASE_URL is not set", file=sys.stderr)
    sys.exit(1)

cfg = Config("alembic.ini")
cfg.set_main_option("sqlalchemy.url", url)
command.upgrade(cfg, "head")
print("Migrations complete.")
EOF

exec uvicorn wafpass_server.main:app --host 0.0.0.0 --port 8000
