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
