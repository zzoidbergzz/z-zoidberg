#!/usr/bin/env bash
# dump_db.sh — pg_dump the live security-knowledge DB into a portable archive
# suitable for `install.sh --dump <file>`.
#
# Usage:
#   ./dump_db.sh                          # → ./dumps/sk_<utc>.dump (custom format, parallel)
#   ./dump_db.sh /var/backups/sk.dump     # explicit path
#
# Reads DATABASE_URL from .env (or env). Strips the "+asyncpg" driver suffix.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="${1:-dumps/sk_$(date -u +%Y%m%dT%H%M%SZ).dump}"
mkdir -p "$(dirname "$OUT")"

# Source DATABASE_URL
if [[ -z "${DATABASE_URL:-}" && -f .env ]]; then
  DATABASE_URL=$(grep -E '^DATABASE_URL=' .env | head -1 | cut -d= -f2-)
fi
[[ -n "${DATABASE_URL:-}" ]] || { echo "DATABASE_URL not set"; exit 2; }

# postgresql+asyncpg://user:pass@host:port/db  →  postgresql://user:pass@host:port/db
RAW_URL="${DATABASE_URL//+asyncpg/}"
RAW_URL="${RAW_URL//+psycopg/}"

echo "[dump] Source: $RAW_URL"
echo "[dump] Dest:   $OUT"
echo "[dump] Starting pg_dump (custom format, jobs=4) — full DB including corpus_documents (~400k rows)…"

# --format=directory + --jobs gives parallel dump; we tar it after for portability.
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
pg_dump --dbname="$RAW_URL" --format=directory --jobs=4 \
        --file="$TMPDIR/d" --no-owner --no-acl --verbose 2>&1 | tail -30

echo "[dump] Packing to single file…"
tar -C "$TMPDIR" -cf "$OUT.tar" d
# Convert to single-file custom-format dump for `install.sh --dump`.
# Restore the directory dump locally to a transient db, then re-dump as custom.
# Simpler: just use single-file custom from the start.
rm -rf "$TMPDIR/d" "$OUT.tar"
pg_dump --dbname="$RAW_URL" --format=custom --compress=9 \
        --file="$OUT" --no-owner --no-acl --verbose 2>&1 | tail -10

ls -lh "$OUT"
echo "[dump] Done. To restore on another machine:"
echo "       scp $OUT new-host:/tmp/"
echo "       ssh new-host '/path/to/security-knowledge/scripts/install.sh --dump /tmp/$(basename $OUT)'"
