#!/usr/bin/env bash
# export_db.sh — Create a portable pg_dump of the Security Knowledge database.
#
# Usage:
#   ./scripts/export_db.sh                    # saves to dumps/sk_YYYY-MM-DD.dump
#   ./scripts/export_db.sh --output my.dump   # custom path
#   ./scripts/export_db.sh --compress 6       # compression level (0-9, default 6)
#
# The resulting .dump file can be restored with:
#   ./scripts/install.sh --dump dumps/sk_2026-05-09.dump
#
# Env overrides:
#   PG_USER=sk PG_PASS=sk PG_DB=sk PG_HOST=127.0.0.1 PG_PORT=5433
set -euo pipefail

PG_USER="${PG_USER:-sk}"
PG_PASS="${PG_PASS:-sk}"
PG_DB="${PG_DB:-sk}"
PG_HOST="${PG_HOST:-127.0.0.1}"
PG_PORT="${PG_PORT:-5433}"
COMPRESS="${COMPRESS:-6}"

OUTPUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)   OUTPUT="$2"; shift 2 ;;
    --compress) COMPRESS="$2"; shift 2 ;;
    -h|--help)  sed -n '1,15p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DATE=$(date +%Y-%m-%d)
OUTPUT="${OUTPUT:-dumps/sk_${DATE}.dump}"
mkdir -p "$(dirname "$OUTPUT")"

echo "[export] Dumping $PG_DB from $PG_HOST:$PG_PORT → $OUTPUT (compress=$COMPRESS)"

# Stats before dump
TOTAL=$(PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" -tAc "SELECT count(*) FROM entities" 2>/dev/null || echo "?")
CLAIMS=$(PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" -tAc "SELECT count(*) FROM claims" 2>/dev/null || echo "?")
RELS=$(PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" -tAc "SELECT count(*) FROM relationships" 2>/dev/null || echo "?")
echo "[export] Entities: $TOTAL | Claims: $CLAIMS | Relationships: $RELS"

# Custom dump: exclude large corpus_documents table, include all core tables
PGPASSWORD="$PG_PASS" pg_dump \
  -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" \
  -d "$PG_DB" \
  --format=custom \
  --compress="$COMPRESS" \
  --verbose \
  --no-owner --no-acl \
  -T 'corpus_documents' \
  -T 'enrichment_cache' \
  -T 'pingback' \
  -T 'audit_log' \
  -T 'jobs' \
  -T 'digests' \
  -T 'webhooks' \
  -T 'documents' \
  -T 'evidence' \
  -T 'changes' \
  --file="$OUTPUT"

SIZE=$(du -h "$OUTPUT" | cut -f1)
echo "[export] Done! $OUTPUT ($SIZE)"
echo "[export] Restore with: ./scripts/install.sh --dump $OUTPUT"
