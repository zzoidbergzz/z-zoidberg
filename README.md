# z-zoidberg

Security Knowledge is a multi-tenant threat-intelligence API and analyst workspace that ingests security sources, enriches indicators, and serves searchable graph-backed intelligence over REST, GraphQL, TAXII, and MCP.

## What this repository contains

This repository hosts the **Security Knowledge** service implementation under `security-knowledge/`, plus supporting docs, ops artifacts, and research assets.

Primary runtime components:
- **FastAPI API** (`security-knowledge/app/main.py`)
- **ARQ worker** (`security-knowledge/app/worker.py`)
- **PostgreSQL + pgvector**
- **Redis** (job queue)
- Optional **SearXNG** (web fallback) and **Tor proxy** (onion scraping)

## Architecture

- **API layer**: FastAPI routers for ingestion, search, entities/claims/evidence, auth/admin, watchlists, export, MCP, GraphQL, and more.
- **Data layer**: PostgreSQL stores tenants, entities, claims, evidence, relationships, watchlists, enrichment cache, corpus docs, jobs, and audit data.
- **Async processing**: ARQ worker handles ingestion, enrichment, feed polling, digest dispatch, EUVD sync, lifecycle expiry, and embedding jobs.
- **Search**:
  - PostgreSQL full-text search (default)
  - Optional semantic search with pgvector embeddings (`SEARCH_USE_SEMANTIC=true`)
  - Optional SearXNG fallback when DB results are sparse
- **Integrations**: pluggable enrichment providers (BYOK/system keys), MISP/OpenCTI hooks, STIX/TAXII, and MCP tool dispatch.

## Repository layout

- `security-knowledge/app/` — application code (routers, services, models, worker)
- `security-knowledge/alembic/` — DB migrations
- `security-knowledge/tests/` — pytest test suite
- `security-knowledge/seed/` — seed scripts
- `security-knowledge/ops/` — operational configs (including SearXNG settings)
- `openclaw/README.md` — MCP/OpenClaw integration notes

## Setup

### Prerequisites

- Python **3.11+**
- Docker + Docker Compose (recommended for local stack)
- Make

### Option A: run full local stack with Docker

From repo root:

```bash
make up
```

This brings up API, worker, Postgres, Redis, Tor, and SearXNG from `security-knowledge/docker-compose.yml`.

### Option B: run API/worker locally against your own services

```bash
cd security-knowledge
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
make migrate
make dev
```

In a second shell:

```bash
cd security-knowledge
source .venv/bin/activate
make worker
```

## Configuration / environment

Configuration is loaded from `security-knowledge/.env` via `app/config.py`.

Required baseline variables:
- `DATABASE_URL`
- `REDIS_URL`
- `SECRET_KEY`

Commonly used optional variables:
- Auth/bootstrap: `BOOTSTRAP_ADMIN_EMAIL`, `BOOTSTRAP_ADMIN_PASSWORD`, `BOOTSTRAP_ADMIN_TENANT`
- Search: `SEARXNG_BASE_URL`, `SEARCH_WEB_FALLBACK_ENABLED`, `SEARCH_WEB_FALLBACK_MIN_DB_RESULTS`, `SEARCH_USE_SEMANTIC`
- Embeddings: `EMBEDDING_PROVIDER`, `EMBEDDING_MODEL`, `EMBEDDING_DIMENSION`
- Integrations: provider keys (`VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`, `IPINFO_TOKEN`, etc.)
- BYOK encryption: `BYOK_ENCRYPTION_KEY` (falls back to key derivation from `SECRET_KEY`)
- Session cookie: `SESSION_COOKIE_NAME`, `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_DOMAIN`

## Running API and worker

From repo root:

```bash
make dev       # FastAPI (uvicorn app.main:app)
make worker    # ARQ worker
```

Other useful commands:

```bash
make migrate
make seed
make seed-knowledge
make test
make lint
make fmt
```

## Authentication model

Authentication resolution order (`app/auth/dependencies.py`):
1. `X-API-Key`
2. `Authorization: Bearer <JWT>`
3. Session cookie (`sk_session` by default)

Authorization uses scopes:
`read`, `write`, `review`, `admin`, `enrichment`, `watch`, `contact`, `export`, `superadmin`.

Key auth flows:
- `POST /api/v1/auth/register` creates user accounts (pending approval unless invited)
- `POST /api/v1/auth/login` sets httpOnly session cookie and returns bearer token
- `POST /api/v1/auth/token` exchanges a user-bound API key for JWT bearer token
- `/api/v1/auth/api-keys*` manages personal API keys (create/list/rotate/revoke)
- `/api/v1/auth/provider-keys*` manages encrypted BYOK provider credentials

## Key endpoints

Health and observability:
- `GET /health`
- `GET /metrics`
- `GET /api/v1/health/embeddings`

Core API:
- `POST /api/v1/ingest/` and `GET /api/v1/ingest/jobs`
- `GET /api/v1/search` (FTS + optional web fallback)
- `POST /api/v1/search/semantic` (requires semantic search enabled)
- `POST /api/v1/lookup`, `POST /api/v1/lookup/extract`, `POST /api/v1/bulk-lookup`
- `GET /api/v1/entities` (+ entity changes/provenance/diamond/assessment routes)
- `GET /api/v1/euvd/search`

Interoperability:
- `GET /graphql` (GraphQL router)
- `GET /taxii2/*` (TAXII 2.1 watchlist collections)
- `GET /api/v1/export/stix` and `GET /api/v1/stix/bundle`
- `GET /api/v1/mcp/tools`, `POST /api/v1/mcp/call`

Admin and operations:
- `GET /api/v1/admin/*` (user/tenant/watchlist/admin functions)
- `GET /api/v1/capabilities` (admin scope required; live endpoint/tool/provider inventory)

## Testing and quality checks

From repo root:

```bash
make test
make lint
make fmt
```

From `security-knowledge/` directly:

```bash
PYTHONPATH=. pytest -q
ruff check app tests
ruff format app tests
```

## Operations

- Start/stop stack: `make up` / `make down`
- Apply migrations: `make migrate`
- Seed data: `make seed`, `make seed-knowledge`
- Export/restore DB: `cd security-knowledge && make dump` / `make dump-restore DUMP=...`
- Enrichment pipelines: `make enrich-*` targets in `security-knowledge/Makefile`

Worker cron jobs include feed polling, onion scraping, digest dispatch, entity expiry, URLScan polling, embedding maintenance, corpus refresh, and EUVD sync.

## Current limitations / caveats

- `POST /api/v1/ingest/` persists jobs even if queue enqueue fails; without a running worker, jobs will not process automatically.
- Semantic search endpoint returns `503` unless `SEARCH_USE_SEMANTIC=true` and embeddings are available.
- Many enrichments require external provider credentials (system or user BYOK) to return non-empty results.
- Session cookie defaults (`SESSION_COOKIE_SECURE=true`, domain `.z.je`) may need local-dev overrides.

## Related docs

- `openclaw/README.md` — MCP/OpenClaw usage
- `AGENT_QUICKSTART.md` — contributor/agent bootstrap
- `security-knowledge/ops/README.md` — ops artifacts
