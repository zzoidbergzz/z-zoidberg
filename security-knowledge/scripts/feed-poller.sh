#!/usr/bin/env bash
# feed-poller.sh — runs the SK feed poller continuously
# Syncs NVD, CISA KEV, GitHub Advisories every 4 hours
set -euo pipefd

cd /home/openclaw/.openclaw/workspace/repos/z-zoidberg/security-knowledge
. .venv/bin/activate

export DATABASE_URL="postgresql+asyncpg://sk:sk@localhost:5433/sk"

echo "[$(date)] Feed poller starting..."

while true; do
    echo "[$(date)] === Polling feeds ==="

    # Sync NVD (recent changes)
    echo "[$(date)] Syncing NVD..."
    python -m app.cli.sync_nvd 2>&1 || echo "NVD sync failed"

    # Sync CISA KEV
    echo "[$(date)] Syncing KEV..."
    python -m app.cli.sync_kev 2>&1 || echo "KEV sync failed"

    # Refresh CVE corpus (incremental)
    echo "[$(date)] Refreshing CVE corpus..."
    python scripts/import_cvelist.py --batch-size 1000 2>&1 || echo "CVE refresh failed"

    # Refresh Exploit-DB
    echo "[$(date)] Refreshing Exploit-DB..."
    python scripts/import_exploitdb.py 2>&1 || echo "Exploit-DB refresh failed"

    echo "[$(date)] === Poll complete. Next in 4h ==="
    sleep 14400
done
