# z-zoidberg AGENT_QUICKSTART

> Single-file onboarding. Read top-to-bottom once; use as a reference thereafter.
> **File:** `/home/z/z-zoidberg/AGENT_QUICKSTART.md`

---

## 0. TL;DR

- **What this repo is:** `z-zoidberg/` is a Zoidberg agent workspace (persona, memory, tools, heartbeat). Nested inside is `security-knowledge/` — a FastAPI + PostgreSQL service for cybersecurity knowledge ingestion, enrichment, MITRE ATT&CK querying, STIX export, MCP-assisted agent queries, and an OSINT research UI.
- **One truth-source endpoint:** `GET /api/v1/capabilities` — **live** as of 2026-05-08. Returns version, all routes, registered/configured providers, and feature flags.
- **Production URL:** https://z.je (Apache proxies to port 8010).
- **Admin account:** `m@z.je` / password in `.env` as `BOOTSTRAP_ADMIN_PASSWORD`.

---

## 1. Service Up (5 minutes)

```bash
cd /home/z/z-zoidberg/security-knowledge

# 1. Python env
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

# 2. Config — copy .env.example, fill credentials
cp .env.example .env

# 3. Infrastructure
make docker-up          # postgres + redis

# 4. Schema
make migrate            # alembic upgrade head

# 5. Start service (port 8010)
nohup .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8010 > /tmp/sk.log 2>&1 &

# Bootstrap admin m@z.je is created automatically on startup.
```

**Smoke checks:**

```bash
# Health (no auth needed)
curl http://localhost:8010/health

# Capabilities (no auth needed)
curl http://localhost:8010/api/v1/capabilities | jq '{version, providers}'

# Login (returns JWT + sets session cookie)
curl -X POST http://localhost:8010/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"m@z.je","password":"<BOOTSTRAP_ADMIN_PASSWORD>"}'
```

---

## 2. Auth

Three accepted auth methods (checked in order):

| Method | Header/Cookie | When to use |
|--------|--------------|-------------|
| API key | `X-API-Key: <raw_key>` | Agent/programmatic clients |
| Bearer JWT | `Authorization: Bearer <token>` | CLI / curl |
| Session cookie | `sk_session=<jwt>` | Browser UI (set by `/api/v1/auth/login`) |

**Get a token:**
```bash
# API token (60-min expiry)
curl -X POST http://localhost:8010/api/v1/auth/token -F username=m@z.je -F password=<BOOTSTRAP_ADMIN_PASSWORD>

# Browser session (7-day cookie)
curl -X POST http://localhost:8010/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"m@z.je","password":"<BOOTSTRAP_ADMIN_PASSWORD>"}'
```

---

## 3. Capability Discovery

```bash
TOKEN="<bearer token>"

# Live capability inventory (version, routes, providers, feature flags)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8010/api/v1/capabilities | jq .

# MCP tool list (33 tools: enrich_entity + 32 MITRE tools)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8010/api/v1/mcp/tools | jq '.tools | length'

# Swagger UI
open http://localhost:8010/docs

# Browser OSINT UI (requires login)
open https://z.je
```

**Active providers (as of 2026-05-08):**

| Provider | Configured | Covers |
|----------|-----------|--------|
| ipinfo | ✅ | IP geo, ASN, org, abuse |
| greynoise | ✅ | IP noise classification |
| mitre_attack | ✅ | Local MITRE ATT&CK (enterprise + mobile + ICS) |
| nvd | ✅ | CVE data (no key required) |
| virustotal | ❌ needs key | Hash, URL, domain reputation |
| shodan | ❌ needs key | Port/banner scanning |
| misp | ❌ needs key | Threat intel sharing |
| opencti | ❌ needs key | Threat intel platform |

---

## 4. Five Recipes

All commands assume `TOKEN` is exported.

### 4.1 Look up ATT&CK technique by ID

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"get_object_by_attack_id","parameters":{"attack_id":"T1059","domain":"enterprise"}}' \
  http://localhost:8010/api/v1/mcp/call | jq '.result.name'
# expect: "Command and Scripting Interpreter"
```

### 4.2 IOC Lookup with enrichment (stream)

```bash
# Stream enrichment results as SSE
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8010/api/v1/enrich/ip_address/8.8.8.8/stream"
# Returns JSON event per provider: greynoise, ipinfo, mitre_attack, nvd, ...
```

### 4.3 Bulk lookup (IOC list)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query_blob":"8.8.8.8\n1.1.1.1\ngoogle.com"}' \
  http://localhost:8010/api/v1/lookup/bulk
```

### 4.4 Create an entity

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"kind":"ip_address","value":"198.51.100.1","title":"Test IP"}' \
  http://localhost:8010/api/v1/entities/ | jq '{id,kind,value}'
```

### 4.5 Export STIX bundle

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8010/api/v1/export/stix?limit=50" -o export.stix2.json
```

---

## 5. Dev Loop

```bash
cd security-knowledge
make test       # pytest -q
make lint       # ruff check app tests
make fmt        # ruff format app tests
make migrate    # alembic upgrade head
make mcp-manifest  # regenerate mcp-tool-manifest.json from live endpoint
```

---

## 6. Known Stubs / Gaps

| ID | Area | Status |
|----|------|--------|
| **A1** | AGENT_QUICKSTART | ✅ done |
| **A2** | `GET /api/v1/capabilities` | ✅ live |
| **A3** | mcp-tool-manifest.json auto-generated | ✅ done (`make mcp-manifest`) |
| **B1** | `enrich_entity` wired to EnrichmentService | ✅ fixed |
| **B2** | providers registry populated | ✅ fixed |
| **B3** | IPinfo + GreyNoise providers | ✅ implemented |
| **C3** | FTS search | ✅ migrations exist; service uses ILIKE for now |
| **C1** | `process_ingest_job` worker | ❌ stub |
| **C4** | GraphQL resolvers | ❌ stub |
| **D1** | End-to-end ingest pipeline | ❌ highest priority remaining |

---

## 7. MCP Integration

```bash
TOKEN="<bearer>"

# List tools
curl -H "Authorization: Bearer $TOKEN" http://localhost:8010/api/v1/mcp/tools

# Call a tool
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"enrich_entity","parameters":{"entity_kind":"ip_address","entity_value":"8.8.8.8"}}' \
  http://localhost:8010/api/v1/mcp/call
```

> `/api/v1/mcp/` is a **custom HTTP RPC**, not the MCP SDK.

---

## 8. Project File Map

### Root (`/home/z/z-zoidberg/`)

| Path | Purpose |
|------|---------|
| `AGENTS.md` | Agent startup rules |
| `IDENTITY.md` | Persona (Zoidberg 🦞) |
| `SOUL.md` | Agent values |
| `USER.md` | User identity |
| `README.md` | Project overview |
| `TOOLS.md` | SearXNG + CrowdStrike notes |
| `TODO.md` | Improvement roadmap |
| `AGENT_QUICKSTART.md` | **This file** |
| `memory/` | Daily logs + heartbeat state |

### Service (`security-knowledge/`)

| Path | Purpose |
|------|---------|
| `app/main.py` | FastAPI app; bootstrap admin; static files |
| `app/routers/` | 25+ routers including lookup, shortcuts, capabilities |
| `app/lookup/` | normalizer, classifier, diffing |
| `app/pivot/` | graph engine, BFS pivot expansion |
| `app/fingerprint.py` | Server-side fingerprint + IP extraction |
| `app/enrichment/providers/` | ipinfo, greynoise, virustotal, shodan, misp, opencti, nvd, mitre_attack |
| `app/ui/routes.py` | Browser UI routes (prefix `""` — serves at `/`) |
| `templates/` | Jinja2: base, index, login, register, fingerprint, investigation |
| `static/css/site.css` | Full dark/light theme CSS |
| `static/js/` | app.js, indicator.js, search.js, graph.js, fingerprint.js |
| `alembic/` | 15 migrations |
| `mcp-tool-manifest.json` | 33 MCP tools (auto-generated) |

---

*Cross-references: [`README.md`](README.md) · [`TODO.md`](TODO.md) · [`bootstrap.md`](bootstrap.md)*

---

## 0. TL;DR

- **What this repo is:** `z-zoidberg/` is a Zoidberg agent workspace (persona, memory, tools, heartbeat). Nested inside is `security-knowledge/` — a FastAPI + PostgreSQL + pgvector service for cybersecurity knowledge ingestion, enrichment, MITRE ATT&CK querying, STIX export, and MCP-assisted agent queries.
- **One truth-source endpoint:** `GET /api/v1/capabilities` (roadmap item **A2**, **not yet implemented**). Until A2 lands, read this file + `TODO.md` + `GET /api/v1/mcp/tools` for live state.
- **Golden rule:** TODO.md's ✅ marks predate a thorough audit and are **not trustworthy**. Trust code over roadmap prose.

---

## 1. Service Up (5 minutes)

```bash
cd /home/z/z-zoidberg/security-knowledge

# 1. Python env
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"

# 2. Config — edit .env to set provider credentials (VIRUSTOTAL_API_KEY, etc.)
cp .env.example .env

# 3. Infrastructure
make docker-up          # postgres + redis

# 4. Schema
make migrate            # alembic upgrade head

# 5. Seed (prints admin API key ONCE to stdout — copy it now)
make seed               # python -m seed.seed_data

# 6. App + worker (two terminals)
make dev                # uvicorn on :8000
make worker             # arq background jobs
```

**Seed the MITRE ATT&CK cache** (needed before MITRE MCP tools work):

```bash
make seed-mitre         # python -m seed.seed_knowledge --mitre
```

**Smoke checks:**

```bash
curl -s http://localhost:8000/health | jq .

SK_API_KEY="<paste-key-from-seed-output>"

curl -s -H "X-API-Key: $SK_API_KEY" \
  http://localhost:8000/api/v1/mcp/tools | jq '.tools | length'
# expect: 32  (1 enrich_entity + 31 MITRE tools)
```

> **Admin key security:** the seed prints the raw key to stdout once. Store it immediately — e.g. `make seed 2>&1 | tee .runtime/seed-admin-$(date +%s).log && chmod 0600 .runtime/seed-admin-*.log`. Never paste it into chat or memory logs.

---

## 2. Auth

Two accepted auth methods:

| Method | Header | When to use |
|--------|--------|-------------|
| API key | `X-API-Key: <raw_key>` | Agent/programmatic clients (preferred) |
| Bearer JWT | `Authorization: Bearer <token>` | Human UI flows; get token via `POST /api/v1/auth/token` |

**API key format:** `secrets.token_urlsafe(32)` — urlsafe base64, no fixed prefix.
See [`app/auth/api_key.py`](security-knowledge/app/auth/api_key.py).

**Scopes** (stored on the API key row):

| Scope | Purpose |
|-------|---------|
| `read` | GET requests, MCP tool calls |
| `write` | POST/PATCH entities, claims, evidence |
| `review` | Approve/reject claims |
| `admin` | Admin panel, key management |
| `enrichment` | Trigger enrichment jobs |
| `export` | STIX/TAXII export |
| `superadmin` | All scopes |

Scope denial → `403 Forbidden`.

**Tenant model:** every API key belongs to a tenant. All writes are RLS-scoped; cross-tenant data is invisible. Set `tenant_id` in the DB session via middleware. See [`app/auth/dependencies.py`](security-knowledge/app/auth/dependencies.py).

---

## 3. Capability Discovery

```bash
# Live tool list (always prefer this over the static manifest)
curl -s -H "X-API-Key: $SK_API_KEY" \
  http://localhost:8000/api/v1/mcp/tools | jq '.tools[]'

# OpenAPI / Swagger UI
open http://localhost:8000/docs

# Static manifest (STALE — only declares enrich_entity)
cat security-knowledge/mcp-tool-manifest.json
```

`GET /api/v1/capabilities` **(planned A2, not live)** — will report version, routes, providers, feature flags, and stale paths.

**For now, the authoritative tool set lives in two places in the code:**
1. [`app/routers/mcp.py`](security-knowledge/app/routers/mcp.py) — `MITRE_TOOLS` dict (31 entries) + the `enrich_entity` branch.
2. [`app/mcp/tools/enrich_entity.py`](security-knowledge/app/mcp/tools/enrich_entity.py) — stub implementation.

> `/api/v1/mcp/` is a **custom HTTP RPC**, not the MCP SDK. See §7 and §9.

---

## 4. Five Recipes

All commands assume `SK_API_KEY` is exported.

### 4.1 Look up ATT&CK technique by ID

```bash
curl -s -X POST \
  -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool":"get_object_by_attack_id","args":{"attack_id":"T1059","domain":"enterprise"}}' \
  http://localhost:8000/api/v1/mcp/call | jq '.result.name'
# expect: "Command and Scripting Interpreter"
```

Response shape: `{"result": { "id": "...", "name": "...", "description": "...", ... }}`

### 4.2 Search the knowledge base

```bash
curl -s -H "X-API-Key: $SK_API_KEY" \
  "http://localhost:8000/api/v1/search/?q=lateral+movement&limit=10" | jq '.results[].name'
```

> **Known stub C3:** search uses `ILIKE`, not Postgres FTS. Ranked FTS is pending.

### 4.3 Create an entity

```bash
curl -s -X POST \
  -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"CVE-2024-1234","kind":"cve","description":"Example CVE for testing"}' \
  http://localhost:8000/api/v1/entities/ | jq '{id:.id, name:.name, kind:.kind}'
```

Response shape: `{"id": "<uuid>", "name": "CVE-2024-1234", "kind": "cve", ...}`

### 4.4 Enrich an IOC

```bash
# MCP path — WARNING: returns empty results (stub B1/B2)
curl -s -X POST \
  -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool":"enrich_entity","args":{"entity_name":"1.1.1.1","entity_kind":"ip_address"}}' \
  http://localhost:8000/api/v1/mcp/call | jq .
# returns: {"entity_name":"1.1.1.1","enrichment_data":{},"sources":[]}

# REST path (trigger enrichment on an existing entity by UUID):
curl -s -X POST \
  -H "X-API-Key: $SK_API_KEY" \
  http://localhost:8000/api/v1/enrich/<entity_uuid>

# Stream results (SSE):
curl -s -H "X-API-Key: $SK_API_KEY" \
  "http://localhost:8000/api/v1/enrich/ip_address/1.1.1.1/stream"
```

> **B1/B2 WARNING:** `enrich_entity` always returns `enrichment_data: {}`.
> Root cause: `app/enrichment/providers/__init__.py` is empty → registry is not populated.
> Until B2 is fixed, enrichment results are always empty regardless of provider credentials.

### 4.5 Export STIX bundle

```bash
# Export all entities (paginated)
curl -s -H "X-API-Key: $SK_API_KEY" \
  "http://localhost:8000/api/v1/export/stix?limit=50&offset=0" \
  -o export.stix2.json
# Content-Type: application/stix+json; version=2.1

# Filter by kind
curl -s -H "X-API-Key: $SK_API_KEY" \
  "http://localhost:8000/api/v1/export/stix?kind=malware&kind=actor&limit=100" | jq '.type'
# expect: "bundle"
```

---

## 5. Dev Loop

```bash
cd security-knowledge

make test       # pytest -q
make lint       # ruff check app tests
make fmt        # ruff format app tests
make migrate    # alembic upgrade head
```

**Tests** live in `security-knowledge/tests/`. Provider mocking pattern: use `pytest-httpx` or `unittest.mock.patch` on the provider client. Check existing tests under `tests/test_mitre_*.py` for reference.

**Type checking:** `mypy app` (not wired into Makefile; run manually).

**Pre-commit hooks:** item **A5/D6** — not yet configured. Run `make lint` + `make test` before each commit manually.

**Worker:** start with `make worker`; needed for ingestion jobs, enrichment triggers, and webhook delivery. Lives in [`app/worker.py`](security-knowledge/app/worker.py).

---

## 6. Known Stubs

> **Keep this list in sync with [`TODO.md`](/home/z/z-zoidberg/TODO.md).** ✅ marks in TODO are NOT reliable.

| ID | Area | Status |
|----|------|--------|
| **A1** | This quickstart file | ✅ done (you're reading it) |
| **A2** | `GET /api/v1/capabilities` endpoint | ❌ not implemented |
| **A5** | Pre-commit hooks / CI lint gate | ❌ not configured |
| **B1** | `enrich_entity` MCP tool returns `enrichment_data: {}` | ❌ stub — not wired to `EnrichmentService` |
| **B2** | `app/enrichment/providers/__init__.py` is empty → registry unpopulated | ❌ bug |
| **B3** | IPinfo, GreyNoise, CrowdStrike provider modules missing | ❌ not implemented |
| **B4** | Most REST endpoints (entities, claims, search, ingest…) not exposed as MCP tools | ❌ gap |
| **B5** | `MITRE_TOOLS` dict in `mcp.py` — not refactored into a proper tool registry | ❌ tech debt |
| **B6** | No real MCP SDK wrapper — `/api/v1/mcp/` is custom HTTP RPC only | ❌ roadmap |
| **B7** | External MCP: only `falcon-mcp` kept; `fetch-mcp` and `playwright-mcp` rejected | ✅ decided |
| **C1** | `process_ingest_job` worker function is a stub — no fetch/parse/extract/embed | ❌ stub |
| **C2** | No bulk corpus importer (Mode A from `deep-research-prompt.md`) | ❌ not implemented |
| **C3** | Search uses `ILIKE` not Postgres FTS/trigram ranking | ❌ partial (migrations exist, service uses ILIKE) |
| **C4** | GraphQL resolvers return `None` / empty lists | ❌ stub |
| **C5** | `docs/` TBD files — most are empty placeholders | ❌ incomplete |
| **C6** | Provenance fields (page number, char offsets) missing from section/evidence schema | ❌ gap |
| **D1** | `process_ingest_job` end-to-end (fetch → parse → chunk → extract → embed → persist) | ❌ highest priority |
| **R3** | `deep-research-prompt.md` stays at repo root — entry point for human + autopilot corpus runs | ✅ decided |

---

## 7. MCP Integration (Claude Desktop / Cursor / Copilot CLI)

**Today (custom HTTP RPC):**

```json
{
  "mcpServers": {
    "security-knowledge": {
      "transport": "http",
      "url": "http://localhost:8000/api/v1/mcp",
      "headers": { "X-API-Key": "<your-key>" }
    }
  }
}
```

Call shape: `POST /api/v1/mcp/call` with `{"tool": "<name>", "args": {...}}`.
List tools: `GET /api/v1/mcp/tools`.

**External MCP server (live now):** `falcon-mcp` — CrowdStrike Falcon via stdio.

```bash
uvx falcon-mcp --modules detections,intel,hosts,ioc,spotlight
# Requires: FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, FALCON_BASE_URL
```

**Roadmap B6 — official MCP SDK (stdio + SSE):**

```jsonc
// mcp.json — PLACEHOLDER, uncomment when B6 lands
// {
//   "mcpServers": {
//     "security-knowledge": {
//       "command": "uvicorn",
//       "args": ["app.mcp_server:app"],
//       "transport": "stdio"
//     }
//   }
// }
```

> `fetch-mcp` and `playwright-mcp` were evaluated and rejected (overlap with existing service capabilities). See §9.

---

## 8. Project File Map

### Root (`/home/z/z-zoidberg/`)

| Path | Purpose |
|------|---------|
| `AGENTS.md` | Agent startup rules: read order, memory, red lines, heartbeat |
| `IDENTITY.md` | Persona (Zoidberg 🦞 — Decapodian, terse, enthusiastic) |
| `SOUL.md` | Agent values and operating principles |
| `USER.md` | User identity context |
| `README.md` | Accurate project overview; partial-stub inventory |
| `TOOLS.md` | SearXNG local search + CrowdStrike falcon-mcp notes |
| `HEARTBEAT.md` | Checklist — empty = `HEARTBEAT_OK` |
| `TODO.md` | 22-item roadmap (⚠️ ✅ marks unreliable — verify with code) |
| `bootstrap.md` | LLM-host handoff for MCP-aware corpus ingestion |
| `deep-research-prompt.md` | Corpus package format spec (Mode A/B); entry point for research runs |
| `prompt.md` | Older downstream implementation prompt |
| `AGENT_QUICKSTART.md` | **This file** (TODO item A1) |
| `memory/` | Daily raw logs (`YYYY-MM-DD.md`) + `heartbeat-state.json` |

### Service (`/home/z/z-zoidberg/security-knowledge/`)

| Path | Purpose |
|------|---------|
| `app/main.py` | FastAPI app; mounts all routers |
| `app/routers/` | 20 routers: auth, entities, claims, evidence, search, ingest, enrich, mcp, mitre, stix, export, graph, graphql_http, webhooks, digests, detections, audit, admin, sectors, taxii, pingback, sources, health, metrics |
| `app/models/` | SQLAlchemy ORM models (29 DB tables) |
| `app/auth/` | API key + JWT auth, scopes, tenant RLS |
| `app/enrichment/` | Provider registry (empty `__init__.py` = B2), service, base, budget |
| `app/enrichment/providers/` | VirusTotal, Shodan, MISP, OpenCTI, NVD, MITRE modules (IPinfo/GreyNoise/CrowdStrike = B3) |
| `app/services/mitre_attack.py` | 31 MITRE ATT&CK query functions |
| `app/services/search.py` | ILIKE search (FTS pending = C3) |
| `app/worker.py` | ARQ worker; `process_ingest_job` is a stub (C1) |
| `app/stix/` | STIX 2.1 builder + type mapping |
| `app/mcp/tools/` | MCP tool implementations (only `enrich_entity` — stub) |
| `alembic/` | 12 migrations (extensions → RLS → core tables → FTS → enrichment …) |
| `seed/` | `seed_data.py` (admin key), `seed_knowledge.py` (MITRE + reverse shells) |
| `tests/` | 134 test functions across the test suite |
| `docs/` | `mitre_attack.md` (useful); rest are TBD stubs (C5) |
| `Makefile` | `install dev test lint fmt migrate worker docker-up seed seed-mitre` |
| `mcp-tool-manifest.json` | **Stale** static manifest — only lists `enrich_entity` |
| `source-policy.yaml` | Outbound HTTP allowlist (must add domains before network fetches) |
| `enrichment-policy.yaml` | Per-provider TTL, rate, and budget rules |
| `docker-compose.yml` | Postgres + Redis + optional worker service |

---

## 8b. Historical Corpora (branch: `feat/historical-corpora`)

Three static vulnerability/exploit corpora are bulk-imported into `corpus_documents` (table created in migration 0023, widened in 0024):

| Corpus | Source | Records | Import script |
|--------|--------|---------|---------------|
| `cve` | MITRE CVE List V5 (GitHub: `CVEProject/cvelistV5`) | ~349k | `scripts/import_cvelist.py` |
| `gcve` | GCVE NDJSON dumps at https://vulnerability.circl.lu/dumps/ | 78 | `scripts/import_gcve.py` |
| `exploitdb` | Exploit-DB GitLab (CSV + exploit files) | ~47k | `scripts/import_exploitdb.py` |

Raw data lives at `security-knowledge/data/corpora/` (git-ignored). To refresh:

```bash
cd security-knowledge
# ExploitDB
git -C data/corpora/exploitdb pull --ff-only
.venv/bin/python scripts/import_exploitdb.py

# CVE List V5
git -C data/corpora/cvelistv5 pull --ff-only
.venv/bin/python scripts/import_cvelist.py

# GCVE (download latest dumps, then import)
wget -P data/corpora/gcve https://vulnerability.circl.lu/dumps/gna-1.ndjson
.venv/bin/python scripts/import_gcve.py
```

**New MCP tools:**
- `cve_lookup(cve_id)` — full CVE/GCVE record + related exploits
- `exploit_search(query, limit=10)` — FTS over Exploit-DB
- `corpus_search(query, corpus?, limit=10)` — FTS across all corpora

**New UI route:** `GET /cve/{cve_id}` — CVE detail page with CVSS, description, related exploits.

**Search filter:** `GET /api/v1/search/?q=...&corpus=cve|gcve|exploitdb` — limit results to one corpus.

---

## 9. Decisions Log

| Decision | Rationale |
|----------|-----------|
| Custom HTTP RPC at `/api/v1/mcp/` instead of MCP SDK | Faster iteration during scaffold phase; SDK wrapping adds boilerplate before the tool set is stable. Switch to stdio + SSE via `mcp` SDK when tool count and contracts stabilise (B6). |
| Keep `falcon-mcp`; reject `fetch-mcp` and `playwright-mcp` | `falcon-mcp` provides non-overlapping Falcon API capabilities unavailable in the service. `fetch-mcp` and `playwright-mcp` overlap with the service's own fetcher (`app/services/fetcher.py`). |
| `deep-research-prompt.md` stays at repo root | It is the entry point for both human-driven and autopilot corpus research runs. Moving it would break handoff prompts that reference it by path (R3). |
| TODO.md ✅ marks are not trustworthy | Marks were added during a bulk consolidation pass before a code audit confirmed stubs. Treat them as intended targets, not confirmed completions. Verify with code. |

---

## 10. Acceptance Test

A fresh agent reading **only this file** + hitting live endpoints should complete the following in **≤ 5 tool turns**:

### Walk

```
Turn 1: GET /health → confirm {"status":"ok"}
Turn 2: POST /api/v1/mcp/call  {"tool":"get_object_by_attack_id","args":{"attack_id":"T1059"}}
         → result.name == "Command and Scripting Interpreter"   [DONE in ≤2 turns]
Turn 3: POST /api/v1/entities/  {"name":"test-entity-001","kind":"cve","description":"quickstart test"}
         → record.id returned
Turn 4: GET /api/v1/entities/<id>  → confirm round-trip
Turn 5: GET /api/v1/search/?q=test-entity-001 → entity appears in results
```

**SLA:** ≤ 5 tool turns total to (a) verify the service is live, (b) execute a MITRE lookup, and (c) create + retrieve an entity. If any turn fails, check §6 stubs before debugging further.

---

*Cross-references: [`/home/z/z-zoidberg/README.md`](README.md) · [`/home/z/z-zoidberg/TODO.md`](TODO.md) · [`/home/z/z-zoidberg/bootstrap.md`](bootstrap.md) · [`security-knowledge/AGENT_INSTRUCTIONS.md`](security-knowledge/AGENT_INSTRUCTIONS.md)*
