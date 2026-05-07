# Zoidberg Workspace

Reviewed 2026-05-07. This repository is a Zoidberg agent workspace plus a
large `security-knowledge/` FastAPI service scaffold for cyber-security
knowledge ingestion, enrichment, search, graph export, and MCP-assisted agent
queries.

The old README and `TODO.md` claimed that all 22 roadmap items were fully
implemented. The codebase does contain broad scaffolding for most roadmap
areas, but several important paths are still stubs or partial implementations.
Treat the code as the source of truth over roadmap status prose.

## Project Files

| File | Purpose |
| --- | --- |
| `AGENTS.md` | Local agent operating rules: startup reads, memory, safety, heartbeat behavior. |
| `SOUL.md`, `USER.md`, `IDENTITY.md` | Agent persona and user identity context. |
| `TOOLS.md` | Local SearXNG and gh-pages publishing notes. |
| `HEARTBEAT.md` | Empty heartbeat checklist means no heartbeat API calls. |
| `TODO.md` | Consolidated roadmap. Useful for intent, but overstates completion. |
| `prompt.md` | Older downstream implementation prompt for the roadmap. |
| `deep-research-prompt.md` | Detailed prompt for producing an import-ready cybersecurity research corpus. |
| `bootstrap.md` | Handoff for another LLM host to run MCP-aware corpus ingestion. |

## Security Knowledge Service

- **Location:** `security-knowledge/`
- **Nominal port:** `8000`
- **Stack:** FastAPI, SQLAlchemy async, PostgreSQL, pgvector migration support, Redis/ARQ, Alembic, Jinja/HTMX templates, Strawberry GraphQL.

### What Has Been Achieved

The service has a substantial application skeleton:

- FastAPI app wiring in `app/main.py` with health, metrics, auth, entities,
  claims, evidence, search, ingest, enrichment, graph, STIX export, webhooks,
  audit, digests, detections, sources, MCP, admin, pingback, sectors, MITRE,
  TAXII, GraphQL, and UI routers.
- Alembic migrations `0001` through `0012` for extensions, auth/RLS, core
  knowledge tables, search indexes, webhooks, enrichment, pingback, sectors,
  MITRE cache, and remaining support tables.
- SQLAlchemy models for sources, raw objects, parsed documents, sections,
  evidence, embeddings, entities, aliases, claims, claim versions,
  relationships, jobs, audit events, webhooks, enrichment cache/usage/diffs,
  graph cache, sync state, TAXII collections, digests, sectors, and IOC
  pingback.
- Tenant-aware API-key and bearer-token auth dependencies with scoped access
  checks, plus registration, profile, admin approval, and seed-data support.
- Source-policy-aware fetcher with deny rules for private/local addresses,
  fixed-window Redis rate limiting, optional Playwright browser fetches, and
  CAPTCHA/challenge detection.
- Deterministic extractors for common security indicators and security
  entities, including CVEs, CWEs, CPEs, tactics, techniques, hashes, domains,
  IP addresses, URLs, actors, malware, NVD CVEs, EUVD, and GitHub advisories.
- MITRE ATT&CK integration is the most complete feature set: REST endpoints,
  cached STIX loading, seed command, tests, docs, and runtime MCP dispatch for
  30+ MITRE query tools.
- STIX bundle export, TAXII server scaffolding, graph export helpers, detection
  rule schemas/templates, webhook models/routes, digest models/scheduler
  helpers, enrichment cache/diff helpers, and IOC pingback flows.
- Test files exist for most modules. A read-only count found 134 test functions
  across the test suite.

### Partial Or Stale Roadmap Claims

The following claims in `TODO.md` and the previous README are not fully true in
the current code:

- Ingestion currently creates an `ingestion_jobs` row and enqueues an ARQ job,
  but `process_ingest_job` is a stub and does not fetch, parse, chunk, extract,
  embed, or persist evidence.
- Search has FTS/trigram migrations, but `app/services/search.py` still uses
  `ILIKE` queries rather than ranked Postgres FTS.
- The MCP manifest file declares only `enrich_entity`; the live
  `/api/v1/mcp/tools` endpoint exposes `enrich_entity` plus the MITRE tool set.
  The `enrich_entity` MCP tool itself returns empty enrichment data.
- Enrichment provider modules exist for VirusTotal, Shodan, NVD, MITRE, MISP,
  and OpenCTI, but `app/enrichment/providers/__init__.py` does not import them,
  so the registry is not populated automatically. IPinfo, GreyNoise, and
  CrowdStrike provider modules are missing.
- GraphQL resolvers currently return `None` or empty lists.
- Several integration and CLI modules are normalizers or thin clients only.
  Some CLI methods reference client methods that do not exist yet.
- Most files under `security-knowledge/docs/` are still `TBD`; the MITRE docs
  are the useful exception.
- Provider-complete MISP/OpenCTI bidirectional sync, full PDF/local-file
  ingestion, context-pack generation, and production-grade bulk corpus import
  are not present.

### Main Endpoints

Current implemented route prefixes are:

| Area | Endpoint |
| --- | --- |
| Health and metrics | `GET /health`, `GET /health/db`, `GET /metrics` |
| Auth | `POST /api/v1/auth/token`, `POST /api/v1/auth/register`, `GET/PATCH /api/v1/auth/me` |
| Knowledge CRUD | `GET/POST /api/v1/entities/`, `GET /api/v1/entities/{id}`, `GET/POST /api/v1/claims/`, `GET/POST /api/v1/evidence/`, `GET /api/v1/sources/` |
| Search and ingest | `GET /api/v1/search/`, `POST /api/v1/ingest/` |
| Enrichment | `POST /api/v1/enrich/{entity_id}`, `GET /api/v1/enrich/{kind}/{value}/stream`, `POST /api/v1/enrich/{kind}/{value}/refresh` |
| MCP | `GET /api/v1/mcp/tools`, `POST /api/v1/mcp/call` |
| MITRE ATT&CK | `GET /api/v1/mitre/...` |
| Export and graph | `GET /api/v1/export/stix`, `GET /api/v1/stix/bundle`, `GET /api/v1/graph/`, `GET/POST /graphql` |
| Other modules | webhooks, digests, detections, audit, admin, sectors, pingback, TAXII |

Use `GET /api/v1/mcp/tools` at runtime instead of relying only on
`security-knowledge/mcp-tool-manifest.json`.

### Setup

```bash
cd security-knowledge
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
cp .env.example .env
docker compose up -d
alembic upgrade head
python -m seed.seed_data
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
python -m arq app.worker.WorkerSettings
```

The seed command prints an admin API key once. Agent hosts should prefer
`X-API-Key: <key>` for API calls.

### MCP Examples

List runtime tools:

```bash
curl -H "X-API-Key: $SK_API_KEY" http://localhost:8000/api/v1/mcp/tools
```

Call a MITRE tool:

```bash
curl -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool":"get_object_by_attack_id","args":{"attack_id":"T1059"}}' \
  http://localhost:8000/api/v1/mcp/call
```

Queue an ingestion job:

```bash
curl -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"source_url":"https://example.com/report.html","source_type":"generic"}' \
  http://localhost:8000/api/v1/ingest/
```

## Research Corpus Ingestion

`deep-research-prompt.md` defines the intended package format:

- `sources.jsonl`
- `documents.jsonl`
- `sections.jsonl`
- `entities.jsonl`
- `facts.jsonl`
- `relationships.jsonl`
- `learning_units.jsonl`
- `context_packs.md`
- `sysinternals-pack.md`
- `pdf-ingestion-playbook.md`
- `import-plan.md`
- `quality-report.md`

Current usable ingestion paths are:

1. Use REST CRUD endpoints to add entities, claims, and evidence manually.
2. Use `POST /api/v1/ingest/` to create an async job record, knowing the worker
   pipeline still needs real fetch/parse/extract/embed implementation.
3. Add a dedicated importer that maps the research JSONL artifacts directly to
   the SQLAlchemy models while preserving source IDs, hashes, evidence spans,
   and tenant IDs.

See `bootstrap.md` for a full MCP-aware handoff prompt and import sequence for
another LLM host.

## Verification

I attempted local verification during this review:

- `pytest -q`: not run; `pytest` is not installed on PATH.
- `python -m pytest -q`: not run; `pytest` module is not installed.
- `ruff check app tests`: not run; `ruff` is not installed on PATH.
- `python -m ruff check app tests`: not run; `ruff` module is not installed.

Install dev dependencies with `python -m pip install -e ".[dev]"` before
treating any test-pass claims as current.

---

## Local Tools

`TOOLS.md` records two local tools:

- SearXNG on `http://localhost:8888` when the `searx` container is running.
- gh-pages publishing for `mzje/z-zoidberg` on branch `gh-pages`.

Do not publish sensitive, personal, or high-risk content without explicit
approval.

## Next Engineering Priorities

1. Implement the real ingestion worker pipeline: fetch, parse, chunk, extract,
   upsert source/document/evidence/entity/claim/relationship records, then
   embed stable chunks.
2. Add a bulk research-corpus importer and tests for the JSONL artifacts in
   `deep-research-prompt.md`.
3. Make MCP registration consistent: import providers at startup, update
   `mcp-tool-manifest.json`, and connect `enrich_entity` to `EnrichmentService`.
4. Replace `ILIKE` search with the FTS/trigram path promised by migrations.
5. Fill the `docs/` TBD files or delete them until they contain operationally
   useful content.
