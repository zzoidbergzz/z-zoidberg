#!/usr/bin/env bash
# install.sh — one-shot bootstrap for security-knowledge on a fresh machine.
#
# What it does:
#   1. checks/installs system deps (postgres-client, redis-tools, python3.14, uv/pip)
#   2. creates DB role + database (idempotent)
#   3. creates a venv and installs requirements
#   4. restores a pg_dump archive if --dump <file> is given (FAST PATH for cloning prod)
#      or runs `alembic upgrade head` + minimal seeds for an empty install
#   5. starts on loopback (127.0.0.1:8000)
#
# Usage:
#   ./install.sh                          # empty install (migrations only)
#   ./install.sh --dump db_2026-05-08.dump  # restore from prod dump
#   ./install.sh --dump db.dump --no-start  # restore but don't launch
#
# Env overrides (all optional):
#   PG_USER=sk PG_PASS=sk PG_DB=sk PG_HOST=127.0.0.1 PG_PORT=5432
#   REDIS_URL=redis://localhost:6379
#   BIND_ADDR=127.0.0.1 BIND_PORT=8000
set -euo pipefail

DUMP=""
START=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dump)     DUMP="$2"; shift 2 ;;
    --no-start) START=0; shift ;;
    -h|--help)  sed -n '1,30p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

PG_USER="${PG_USER:-sk}"
PG_PASS="${PG_PASS:-sk}"
PG_DB="${PG_DB:-sk}"
PG_HOST="${PG_HOST:-127.0.0.1}"
PG_PORT="${PG_PORT:-5432}"
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
BIND_PORT="${BIND_PORT:-8000}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

log() { printf '\033[1;36m[install]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[install:error]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 1. system deps ---------------------------------------------------------
log "Checking system deps…"
need=()
command -v psql      >/dev/null 2>&1 || need+=(postgresql-client)
command -v pg_restore >/dev/null 2>&1 || true
command -v redis-cli >/dev/null 2>&1 || need+=(redis-tools)
command -v python3.14 >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1 || need+=(python3)
if [[ ${#need[@]} -gt 0 ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    log "Installing: ${need[*]}"
    sudo apt-get update -qq
    sudo apt-get install -y "${need[@]}"
  else
    die "Missing tools (${need[*]}) and no apt-get. Install manually."
  fi
fi

PYTHON="$(command -v python3.14 || command -v python3)"
log "Python: $PYTHON ($($PYTHON --version))"

# --- 2. DB role + database --------------------------------------------------
log "Ensuring postgres role '$PG_USER' and DB '$PG_DB' exist on $PG_HOST:$PG_PORT…"
PSQL_ADMIN="psql -h $PG_HOST -p $PG_PORT -U postgres -v ON_ERROR_STOP=1"
$PSQL_ADMIN -tAc "SELECT 1 FROM pg_roles WHERE rolname='$PG_USER'" | grep -q 1 \
  || $PSQL_ADMIN -c "CREATE ROLE $PG_USER LOGIN PASSWORD '$PG_PASS'"
$PSQL_ADMIN -tAc "SELECT 1 FROM pg_database WHERE datname='$PG_DB'" | grep -q 1 \
  || $PSQL_ADMIN -c "CREATE DATABASE $PG_DB OWNER $PG_USER"
$PSQL_ADMIN -d "$PG_DB" -c "CREATE EXTENSION IF NOT EXISTS pg_trgm; CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";" >/dev/null

# --- 3. venv + python deps --------------------------------------------------
log "Creating venv .venv and installing requirements…"
[[ -d .venv ]] || "$PYTHON" -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt

# --- 4. .env ---------------------------------------------------------------
if [[ ! -f .env ]]; then
  log "Writing .env"
  cat >.env <<EOF
DATABASE_URL=postgresql+asyncpg://$PG_USER:$PG_PASS@$PG_HOST:$PG_PORT/$PG_DB
REDIS_URL=$REDIS_URL
SECRET_KEY=$(openssl rand -base64 32 | tr -d '/+=' | head -c 48)
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
SESSION_COOKIE_NAME=sk_session
EOF
fi

# --- 5. data import ---------------------------------------------------------
if [[ -n "$DUMP" ]]; then
  [[ -f "$DUMP" ]] || die "dump file not found: $DUMP"
  log "Restoring DB from $DUMP — this can take a while for full prod (~400k rows + payloads)…"
  PGPASSWORD="$PG_PASS" pg_restore -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" \
    -d "$PG_DB" --no-owner --no-acl --clean --if-exists --jobs=4 "$DUMP"
  log "Restore complete. Stamping alembic head."
  # Override alembic URL so it talks to the DB we just populated (sync driver).
  SQLA_URL="postgresql+psycopg://$PG_USER:$PG_PASS@$PG_HOST:$PG_PORT/$PG_DB" \
    .venv/bin/alembic -c alembic.ini -x url="$SQLA_URL" stamp head || \
    log "(alembic stamp skipped — restored dump already contains alembic_version)"
else
  log "No --dump given. Running alembic migrations on empty DB."
  SQLA_URL="postgresql+psycopg://$PG_USER:$PG_PASS@$PG_HOST:$PG_PORT/$PG_DB" \
    .venv/bin/alembic -c alembic.ini -x url="$SQLA_URL" upgrade head
  log "Seeding research pack + entity catalog…"
  .venv/bin/python -m seed.seed_research_pack || log "(seed skipped — non-fatal)"
  .venv/bin/python scripts/backfill_kg_entities.py --apply || true
fi

# --- 6. start --------------------------------------------------------------
if [[ "$START" -eq 1 ]]; then
  log "Starting on $BIND_ADDR:$BIND_PORT (Ctrl-C to stop). For background, run with --no-start and use systemd."
  exec .venv/bin/uvicorn app.main:app --host "$BIND_ADDR" --port "$BIND_PORT"
else
  log "Done. Start with:"
  echo "  cd $ROOT && .venv/bin/uvicorn app.main:app --host $BIND_ADDR --port $BIND_PORT"
fi
