.PHONY: install dev test lint fmt migrate run worker

install:
pip install -e ".[dev]"

dev:
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
pytest -q

lint:
ruff check app tests

fmt:
ruff format app tests

migrate:
alembic upgrade head

worker:
python -m arq app.worker.WorkerSettings

docker-up:
docker compose up -d

docker-down:
docker compose down

seed:
python -m seed.seed_data

seed-knowledge:
python -m seed.seed_knowledge --all

seed-mitre:
python -m seed.seed_knowledge --mitre

seed-reverse-shells:
python -m seed.seed_knowledge --reverse-shells

# ── Export / Restore ────────────────────────────────────────────
dump:
	@bash scripts/export_db.sh

dump-restore: ## Restore latest dump (usage: make dump-restore DUMP=path/to/file.dump)
	@bash scripts/install.sh --dump $(DUMP)

# ── Enrichment pipelines ───────────────────────────────────────
enrich-kev:
	@python3 scripts/enrichment_pipeline.py --phase kev

enrich-nvd:
	@python3 scripts/enrichment_pipeline.py --phase nvd

enrich-mitre:
	@python3 scripts/enrichment_pipeline.py --phase mitre

enrich-misp:
	@python3 scripts/enrichment_pipeline.py --phase misp

enrich-sigma:
	@python3 scripts/enrichment_pipeline.py --phase sigma

enrich-epss:
	@python3 scripts/enrichment_pipeline.py --phase epss

enrich-all:
	@python3 scripts/enrichment_pipeline.py --phase all

enrich-malware:
	@python3 scripts/ingest_malware.py --phase all

enrich-tir:
	@python3 scripts/ingest_tir.py

deep-research:
	@echo "Running full deep research pipeline (6 tasks)..."
	@python3 scripts/task1_actors.py
	@python3 scripts/task3_frameworks.py
	@python3 scripts/task5_detections_tools.py
	@python3 scripts/task6_relationships.py
	@echo "Deep research complete"
