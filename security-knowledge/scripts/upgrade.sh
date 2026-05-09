#!/usr/bin/env bash
# upgrade.sh — Upgrade z.je security-knowledge to latest from mzje/z-zoidberg
#
# This script:
#   1. Pulls latest code from GitHub
#   2. Restores the latest portable DB dump
#   3. Runs Alembic migrations (for any schema changes)
#   4. Restarts the service
#
# Usage:
#   ./scripts/upgrade.sh                    # full upgrade with DB restore
#   ./scripts/upgrade.sh --skip-db          # code only, keep existing DB
#   ./scripts/upgrade.sh --dump PATH        # restore specific dump file
#
# Prerequisites:
#   - PostgreSQL running (docker compose or system)
#   - Python 3.12+ with venv
#   - Git
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  🦞 Zoidberg Security Knowledge — Upgrade Script    ║"
echo "╚══════════════════════════════════════════════════════╝"

SKIP_DB=false
CUSTOM_DUMP=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-db)  SKIP_DB=true; shift ;;
    --dump)     CUSTOM_DUMP="$2"; shift 2 ;;
    -h|--help)  sed -n '1,15p' "$0"; exit 0 ;;
    *)          echo "unknown arg: $1"; exit 2 ;;
  esac
done

# ── Step 1: Pull latest code ────────────────────────────────────
echo ""
echo "[1/5] 📦 Pulling latest code from GitHub..."
git fetch origin main
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)
if [ "$LOCAL" != "$REMOTE" ]; then
    git pull origin main
    echo "  ✓ Updated: ${LOCAL:0:8} → ${REMOTE:0:8}"
else
    echo "  ✓ Already up to date"
fi

# ── Step 2: Update Python dependencies ──────────────────────────
echo ""
echo "[2/5] 🐍 Updating Python environment..."
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
.venv/bin/pip install -e ".[dev]" --quiet 2>&1 | tail -1
echo "  ✓ Dependencies updated"

# ── Step 3: Database restore ────────────────────────────────────
if [ "$SKIP_DB" = true ]; then
    echo ""
    echo "[3/5] 🗄️  Skipping DB restore (--skip-db)"
else
    echo ""
    echo "[3/5] 🗄️  Restoring database..."

    # Find dump file
    DUMP_FILE="${CUSTOM_DUMP}"
    if [ -z "$DUMP_FILE" ]; then
        # Find latest portable dump
        DUMP_FILE=$(ls -t dumps/sk_portable*.dump.bz2 2>/dev/null | head -1)
        if [ -z "$DUMP_FILE" ]; then
            DUMP_FILE=$(ls -t dumps/sk_portable*.dump 2>/dev/null | head -1)
        fi
    fi

    if [ -z "$DUMP_FILE" ]; then
        echo "  ⚠️  No dump file found. Run 'make dump' on the source machine first."
        echo "  Continuing with existing database..."
    else
        echo "  Using: $DUMP_FILE"

        # Detect DB connection
        PG_HOST="${PG_HOST:-127.0.0.1}"
        PG_PORT="${PG_PORT:-5433}"
        PG_USER="${PG_USER:-sk}"
        PG_PASS="${PG_PASS:-sk}"
        PG_DB="${PG_DB:-sk}"

        # Decompress if needed
        if [[ "$DUMP_FILE" == *.bz2 ]]; then
            echo "  Decompressing..."
            DUMP_RAW="${DUMP_FILE%.bz2}"
            bzip2 -dk "$DUMP_FILE" 2>/dev/null || true
        else
            DUMP_RAW="$DUMP_FILE"
        fi

        # Drop and recreate
        echo "  Recreating database..."
        PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d postgres \
            -c "DROP DATABASE IF EXISTS $PG_DB;" 2>/dev/null || true
        PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d postgres \
            -c "CREATE DATABASE $PG_DB;" 2>/dev/null || true

        # Enable extensions
        PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
            -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";" 2>/dev/null || true
        PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
            -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;" 2>/dev/null || true

        # Restore
        echo "  Restoring data..."
        PGPASSWORD="$PG_PASS" pg_restore \
            -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" \
            --no-owner --no-acl --if-exists \
            "$DUMP_RAW" 2>&1 | grep -v "ERROR.*already exists" || true

        # Stats
        TOTAL=$(PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" -tAc "SELECT count(*) FROM entities" 2>/dev/null || echo "?")
        CLAIMS=$(PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" -tAc "SELECT count(*) FROM claims" 2>/dev/null || echo "?")
        RELS=$(PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" -tAc "SELECT count(*) FROM relationships" 2>/dev/null || echo "?")
        echo "  ✓ Restored: $TOTAL entities, $CLAIMS claims, $RELS relationships"

        # Clean up decompressed file
        if [[ "$DUMP_FILE" == *.bz2 ]]; then
            rm -f "$DUMP_RAW"
        fi
    fi
fi

# ── Step 4: Run migrations ──────────────────────────────────────
echo ""
echo "[4/5] 🔄 Running database migrations..."
.venv/bin/alembic upgrade head 2>/dev/null || echo "  ⚠️  Migration skipped (alembic not configured or already current)"
echo "  ✓ Migrations complete"

# ── Step 5: Restart service ─────────────────────────────────────
echo ""
echo "[5/5] 🚀 Restarting service..."
pkill -f "uvicorn app.main" 2>/dev/null || true
sleep 2

# Ensure .env exists
if [ ! -f .env ] && [ -f .env.example ]; then
    cp .env.example .env
    echo "  ⚠️  Created .env from .env.example — update with your keys!"
fi

nohup .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8010 --workers 2 > /tmp/sk.log 2>&1 &
sleep 5

# Verify
if curl -s http://localhost:8010/health | grep -q "ok"; then
    echo "  ✓ Service running on :8010"
else
    echo "  ⚠️  Service may not have started — check /tmp/sk.log"
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  🦞 Upgrade complete! Woop woop.                    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  API:    http://localhost:8010"
echo "  Docs:   http://localhost:8010/docs"
echo "  Health: http://localhost:8010/health"
echo ""
