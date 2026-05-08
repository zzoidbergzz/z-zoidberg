#!/usr/bin/env bash
# Idempotent refresh of historical security corpora.
# Pulls latest from upstream git, then runs importers (which upsert).
# Safe to run from cron — locks via flock.
set -euo pipefail

ROOT="/home/z/z-zoidberg/security-knowledge"
DATA="${ROOT}/data/corpora"
PY="${ROOT}/.venv/bin/python"
LOCK="/tmp/sk-corpus-refresh.lock"
LOG="/tmp/sk-corpus-refresh.log"

exec 9>"${LOCK}"
flock -n 9 || { echo "[refresh_corpora] another run in progress, skipping" >> "${LOG}"; exit 0; }

echo "=== $(date -u +%FT%TZ) refresh_corpora start ===" >> "${LOG}"

cd "${ROOT}"

for repo in cvelistv5 gcve exploitdb; do
  d="${DATA}/${repo}"
  if [ -d "${d}/.git" ]; then
    echo "[refresh_corpora] git pull ${repo}" >> "${LOG}"
    git -C "${d}" pull --ff-only --quiet >> "${LOG}" 2>&1 || echo "[refresh_corpora] pull failed ${repo}" >> "${LOG}"
  else
    echo "[refresh_corpora] skip ${repo} (not cloned yet)" >> "${LOG}"
  fi
done

# Importers are idempotent (unique key on (corpus, external_id)). Run only those whose script exists.
for script in import_cvelist.py import_gcve.py import_exploitdb.py; do
  if [ -f "${ROOT}/scripts/${script}" ]; then
    echo "[refresh_corpora] running ${script}" >> "${LOG}"
    "${PY}" "${ROOT}/scripts/${script}" >> "${LOG}" 2>&1 || echo "[refresh_corpora] ${script} failed" >> "${LOG}"
  fi
done

echo "=== $(date -u +%FT%TZ) refresh_corpora done ===" >> "${LOG}"
