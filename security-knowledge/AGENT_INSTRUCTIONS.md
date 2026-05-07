# Security Knowledge — Agent Instructions

## Overview
This is a security intelligence knowledge base service built with FastAPI + PostgreSQL.

## Key entry points
- `app/main.py` — FastAPI application
- `app/worker.py` — ARQ background worker
- `app/routers/` — All HTTP route handlers
- `app/models/` — SQLAlchemy ORM models
- `app/enrichment/` — Enrichment providers and service

## Development
```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
```

## Enrichment providers
Providers self-register via `@register` decorator in `app/enrichment/registry.py`.
Import all providers in `app/enrichment/providers/__init__.py`.

## Adding a new entity kind
1. Add to `EntityKind` enum in `app/models/entities.py`
2. Add to `ENTITY_KIND_TO_STIX_TYPE` in `app/stix/mapping.py`
3. Add enrichment triggers in `app/enrichment/triggers.py`
