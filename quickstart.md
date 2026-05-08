# z-zoidberg / security-knowledge — LLM Quickstart

> Point an LLM at this single file to get full operational context.
> **Last updated:** 2026-05-08
> **Truth-source endpoint:** `GET /api/v1/capabilities` (live, no auth needed at health level)

---

## 0. What This Is

`z-zoidberg/` is a Zoidberg agent workspace (persona, memory, tools).
Inside `security-knowledge/` is a **FastAPI + PostgreSQL + pgvector** service
for cybersecurity knowledge: threat intel ingestion, MITRE ATT&CK, enrichment,
STIX/TAXII export, and an MCP agent interface.

**Production URL:** https://z.je (Apache → port 8010)
**Admin account:** `m@z.je` / password in `.env` as `BOOTSTRAP_ADMIN_PASSWORD`

---

## 1. Service Up (5 minutes)

```bash
cd /home/z/z-zoidberg/security-knowledge

# 1. Python env
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

# 2. Config
cp .env.example .env
# Edit .env — set BOOTSTRAP_ADMIN_PASSWORD and any provider API keys

# 3. Infrastructure (Postgres + Redis)
make docker-up

# 4. Schema
make migrate          # alembic upgrade head

# 5. Seed base data (prints admin API key once — copy it now)
make seed             # python -m seed.seed_data

# 6. Seed MITRE ATT&CK (needed for all MITRE MCP tools)
make seed-mitre       # python -m seed.seed_knowledge --mitre

# 7. App
make dev              # uvicorn on :8000 (or port 8010 in production)

# 8. Background worker (separate terminal)
make worker           # arq worker for ingest/enrichment jobs
```

**Smoke checks:**
```bash
curl http://localhost:8000/health | jq .
SK_API_KEY="<paste-from-seed-output>"
curl -H "X-API-Key: $SK_API_KEY" http://localhost:8000/api/v1/mcp/tools | jq '.tools | length'
# expect: ≥32
```

> **Admin key security:** `make seed` prints the raw key once. Immediately:
> `make seed 2>&1 | tee .runtime/seed-admin-$(date +%s).log && chmod 0600 .runtime/seed-admin-*.log`
> Never paste into chat or memory logs.

---

## 2. Auth

| Method | Header | Use When |
|--------|--------|----------|
| API key | `X-API-Key: <key>` | All programmatic/agent access |
| Bearer JWT | `Authorization: Bearer <token>` | Human/curl flows |
| Session cookie | `sk_session=<jwt>` | Browser UI |

**Get a token:**
```bash
# API key (get from seed output or admin panel)
export SK_API_KEY="<raw_key>"

# Bearer JWT (60-min)
curl -X POST http://localhost:8000/api/v1/auth/token \
  -F username=m@z.je -F password=<BOOTSTRAP_ADMIN_PASSWORD>

# Session cookie (7-day)
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"m@z.je","password":"<BOOTSTRAP_ADMIN_PASSWORD>"}'
```

**Scopes:** `read`, `write`, `review`, `admin`, `enrichment`, `export`, `superadmin`

---

## 3. Five Canonical Recipes

### 3.1 ATT&CK technique — get everything

```bash
# All info about T1059.001
curl -X POST -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"get_object_by_attack_id","parameters":{"attack_id":"T1059.001","domain":"enterprise"}}' \
  http://localhost:8000/api/v1/mcp/call | jq .

# Who uses it
curl -X POST -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"get_groups_using_technique","parameters":{"attack_id":"T1059.001"}}' \
  http://localhost:8000/api/v1/mcp/call | jq '.result[].name'

# What data sources detect it
curl -X POST -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"get_datacomponents_detecting_technique","parameters":{"attack_id":"T1059.001"}}' \
  http://localhost:8000/api/v1/mcp/call | jq .
```

### 3.2 Enrich an indicator

```bash
# IP enrichment (greynoise + ipinfo)
curl -H "X-API-Key: $SK_API_KEY" \
  "http://localhost:8000/api/v1/enrich/ip_address/8.8.8.8" | jq .

# Streaming enrichment (SSE)
curl -H "X-API-Key: $SK_API_KEY" \
  "http://localhost:8000/api/v1/enrich/ip_address/8.8.8.8/stream"

# Hash lookup
curl -H "X-API-Key: $SK_API_KEY" \
  "http://localhost:8000/api/v1/enrich/hash/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" | jq .
```

### 3.3 Search the knowledge base

```bash
# Full-text search (SearXNG-powered via MCP — once P3-1 lands)
curl -X POST -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"search_knowledge","parameters":{"query":"Bangladesh Bank SWIFT heist Lazarus"}}' \
  http://localhost:8000/api/v1/mcp/call | jq .

# REST search
curl -H "X-API-Key: $SK_API_KEY" \
  "http://localhost:8000/api/v1/entities/?search=lazarus&kind=actor" | jq .

# SearXNG direct (local search engine, no auth needed)
curl -s "http://localhost:8888/search?q=Shadow+Brokers+EternalBlue&format=json&categories=it" \
  | jq '.results[] | {title, url, content}'
```

### 3.4 Import a corpus package

```bash
# Validate only
python -m app.cli.import_corpus --package ./corpus-output/ --validate

# Import
python -m app.cli.import_corpus \
  --tenant-id "$TENANT_ID" \
  --package ./corpus-output/ \
  --validate --import

# Remote (multipart upload)
curl -X POST -H "X-API-Key: $SK_API_KEY" \
  -F "file=@corpus.tar.zst" \
  http://localhost:8000/api/v1/import/corpus
```

### 3.5 Export STIX bundle

```bash
curl -H "X-API-Key: $SK_API_KEY" \
  "http://localhost:8000/api/v1/export/stix?limit=200" -o export.stix2.json

# TAXII discovery
curl -H "X-API-Key: $SK_API_KEY" \
  "http://localhost:8000/api/v1/taxii/discovery" | jq .
```

---

## 4. MCP Tool Reference

**Endpoint:** `POST /api/v1/mcp/call` with `{"tool_name":"...", "parameters":{...}}`
**List tools:** `GET /api/v1/mcp/tools`

### MITRE ATT&CK Tools (31)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `get_object_by_attack_id` | `attack_id`, `domain` | Full STIX object |
| `get_groups_using_technique` | `attack_id` | Groups list |
| `get_software_using_technique` | `attack_id` | Software list |
| `get_procedure_examples_by_technique` | `attack_id` | Procedure examples |
| `get_datacomponents_detecting_technique` | `attack_id` | Detection data components |
| `get_mitigations_for_technique` | `attack_id` | Mitigations |
| `get_techniques_by_group` | `group_id` | Technique list |
| `get_techniques_by_software` | `software_id` | Technique list |
| `list_all_groups` | — | All ATT&CK groups |
| `list_all_software` | — | All ATT&CK software |
| `list_all_techniques` | `domain?` | All techniques |
| `list_all_campaigns` | — | All campaigns |
| `get_group_by_name` | `name` | Group object |
| `get_software_by_name` | `name` | Software object |
| `get_campaign_by_name` | `name` | Campaign object |
| `get_subtechniques_of_technique` | `attack_id` | Subtechniques |
| `get_parent_technique` | `attack_id` | Parent technique |
| `get_techniques_by_tactic` | `tactic_name`, `domain?` | Techniques |
| `list_all_tactics` | `domain?` | Tactics |
| `get_relationships_by_object` | `object_id` | All relationships |
| *(+ 11 more)* | | |

### Enrichment Tools

| Tool | Parameters | Returns |
|------|-----------|---------|
| `enrich_entity` | `entity_kind`, `entity_value`, `providers?`, `force?` | Provider results + claim IDs |

### Planned Tools (in progress — see plan.md)

| Tool | Status | Phase |
|------|--------|-------|
| `search_knowledge` | planned | P3-3 |
| `searxng_search` | planned | P3-1 |
| `lookup_cve` | planned | P3-4 |
| `lookup_kev` | planned | P3-4 |
| `get_entity` / `list_entities` | planned | P3-4 |
| `create_entity` / `create_claim` | planned | P3-4 |
| `export_stix_bundle` | planned | P3-4 |
| `get_changes_since` | planned | P3-4 |

---

## 5. Threat Intelligence Seeding

### Autopilot Research Runner

Run the automated data collection pipeline:

```bash
# Full run (MITRE → KEV → NVD → EPSS → SearXNG discovery → GitHub Sigma/YARA)
python -m app.cli.research_runner \
  --tenant-id "$TENANT_ID" \
  --output ./corpus-output/

# Then import the results
python -m app.cli.import_corpus \
  --tenant-id "$TENANT_ID" \
  --package ./corpus-output/ \
  --validate --import
```

### Manual KEV + NVD sync

```bash
# Sync CISA KEV catalog
python -m app.cli.sync_kev --tenant-id "$TENANT_ID"

# Sync NVD for a specific CVE
python -m app.cli.sync_nvd --cve CVE-2021-44228 --tenant-id "$TENANT_ID"
```

### Named Incidents (pre-seeded or ingest manually)

The database should contain full profiles for these incidents. If missing, seed
them from public sources using the import workflow:

| Incident | Actor | Key CVEs | Status |
|----------|-------|----------|--------|
| Bangladesh Bank SWIFT heist (2016) | Lazarus Group | N/A | seed manually |
| Shadow Brokers / EternalBlue | (NSA tools leaked) | MS17-010 | seed manually |
| WannaCry (2017) | Lazarus Group | CVE-2017-0144 | seed manually |
| NotPetya (2017) | Sandworm | CVE-2017-0144 | seed manually |
| SolarWinds/SUNBURST (2020) | APT29 | N/A | seed manually |
| Hafnium/ProxyLogon (2021) | Hafnium | CVE-2021-26855 | seed manually |
| Log4Shell (2021) | Multiple | CVE-2021-44228 | seed via sync_nvd |
| MOVEit (2023) | Cl0p | CVE-2023-34362 | seed manually |

### Windows DLL / PE Artifacts

Query PE artifact data:
```bash
# Search for ntdll.dll
curl -H "X-API-Key: $SK_API_KEY" \
  "http://localhost:8000/api/v1/entities/?search=ntdll&kind=file_artifact" | jq .

# Get DLL exports
curl -H "X-API-Key: $SK_API_KEY" \
  "http://localhost:8000/api/v1/entities/<entity_id>/claims" | jq .
```

---

## 6. Dark Web / Onion Scraping

**Default: DISABLED.** Enable by setting `ONION_SCRAPING_ENABLED=true` in `.env`.
Requires Tor service running (added to `docker-compose.yml`).

```bash
# Start with Tor proxy
make docker-up   # includes tor container

# Test Tor connectivity
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip | jq .

# Onion scraper runs automatically as ARQ cron (every 4 hours when enabled)
# Manual trigger:
python -m app.cli.scrape_onion --tenant-id "$TENANT_ID" --dry-run
```

**Safety rules (non-negotiable):**
1. All `.onion` traffic routes via Tor only — never clearnet fallback.
2. No JavaScript execution on onion content.
3. No PII or victim identity data stored — sector + TTP mentions only.
4. No credentials, payment info, or private keys stored.
5. Rate limit: 1 request per 5 minutes per onion domain.
6. 30-second hard timeout per fetch.
7. Circuit rotation between domain batches.

---

## 7. Search Architecture

| Layer | Tool | Endpoint | Notes |
|-------|------|----------|-------|
| Local full-text | PostgreSQL FTS (tsvector) | `GET /api/v1/entities/?search=` | Fast, covers all entity types |
| Meta-search engine | SearXNG | `http://localhost:8888/search?q=&format=json` | Searches web + specialised engines |
| MCP search | `search_knowledge` tool | `POST /api/v1/mcp/call` | FTS + SearXNG combined (planned P3-3) |

**SearXNG categories for threat intel research:**
```bash
# CVE PoCs
curl "http://localhost:8888/search?q=CVE-2023-34362+poc+exploit&format=json&categories=it"

# Breach reports
curl "http://localhost:8888/search?q=site:thedfirreport.com+ransomware+2024&format=json"

# Sigma rules
curl "http://localhost:8888/search?q=site:github.com/SigmaHQ+T1059.001&format=json"

# Threat actor profiles
curl "http://localhost:8888/search?q=Lazarus+Group+TTPs+2024+analysis&format=json"
```

---

## 8. Provider Configuration

Set these env vars in `.env`:

| Provider | Env Var | Free Tier | Notes |
|----------|---------|-----------|-------|
| IPinfo | `IPINFO_TOKEN` | ✅ 50k/mo | IP geo, ASN, org |
| GreyNoise | `GREYNOISE_API_KEY` | ✅ Community | IP noise classification |
| VirusTotal | `VIRUSTOTAL_API_KEY` | ✅ 4 req/min | Hash, URL, domain |
| Shodan | `SHODAN_API_KEY` | ❌ paid | Port/banner scanning |
| NVD | `NVD_API_KEY` | ✅ optional | Faster rate limits |
| MISP | `MISP_URL`, `MISP_KEY` | self-hosted | Threat sharing |
| OpenCTI | `OPENCTI_URL`, `OPENCTI_TOKEN` | self-hosted | Threat intel platform |

---

## 9. Key File Map

### Workspace root (`/home/z/z-zoidberg/`)

| File | Purpose |
|------|---------|
| `AGENTS.md` | Agent startup rules + memory protocol |
| `SOUL.md` | Agent values and constraints |
| `USER.md` | User identity |
| `IDENTITY.md` | Persona (Zoidberg 🦞) |
| `TOOLS.md` | SearXNG + CrowdStrike + external tools |
| `MEMORY.md` | Long-term distilled memory |
| `quickstart.md` | **This file** |
| `deep-research-prompt.md` | Full corpus schema, JSONL contracts, query templates |
| `bootstrap.md` | Mode A import protocol for external LLM research output |
| `memory/` | Daily session logs + heartbeat state |

### Service (`security-knowledge/`)

| Path | Purpose |
|------|---------|
| `app/main.py` | FastAPI app, bootstrap admin, startup |
| `app/routers/` | 25+ REST routers |
| `app/enrichment/providers/` | ipinfo, greynoise, virustotal, shodan, misp, opencti, nvd, mitre_attack |
| `app/workers/feed_poller.py` | ARQ cron: RSS/Atom feed ingestion |
| `app/workers/onion_scraper.py` | ARQ cron: dark web scraper (planned P2-3) |
| `app/cli/import_corpus.py` | Bulk JSONL corpus importer |
| `app/cli/research_runner.py` | Autopilot threat intel data collection |
| `app/cli/sync_kev.py` | CISA KEV sync |
| `app/cli/sync_nvd.py` | NVD CVE sync |
| `app/fetcher.py` | 3-layer HTTP fetcher (httpx + Playwright + Tor) |
| `app/mcp/` | MCP tool registry and router |
| `source-policy.yaml` | Outbound fetch policy (all targets declared here) |
| `alembic/` | Database migrations |
| `seed/` | Seed scripts: base data + MITRE ATT&CK |
| `mcp-tool-manifest.json` | Auto-generated MCP manifest |

---

## 10. Dev Loop

```bash
cd security-knowledge

make test           # pytest -q
make lint           # ruff check app tests
make fmt            # ruff format app tests
make migrate        # alembic upgrade head
make mcp-manifest   # regenerate mcp-tool-manifest.json
make docker-up      # postgres + redis (+ tor when configured)
make docker-down    # stop containers
```

**Run specific test:**
```bash
pytest tests/test_search_api.py -v
pytest tests/ -k "enrich" -v
```

---

## 11. Known Stubs & Current Gaps

| ID | Area | Status | Plan Phase |
|----|------|--------|-----------|
| C1 | `process_ingest_job` worker end-to-end | ❌ stub | P4-1 |
| C4 | GraphQL resolvers | ❌ stub | P4-4 |
| P1-1 | research_runner autopilot CLI | ❌ planned | P1-1 |
| P1-2 | breach_reports/pocs/tools/cve_dossiers/procedures tables | ❌ planned | P1-2 |
| P1-3 | Named incidents (Bangladesh/ShadowBrokers/etc.) | ❌ planned | P1-3 |
| P2 | Dark web / onion scraper | ❌ planned | P2-1..4 |
| P3-1 | SearXNG MCP tool | ❌ planned | P3-1 |
| P3-2 | FTS wired (migrations exist) | ⚠️ partial | P3-2 |
| P3-3 | `search_knowledge` MCP tool | ❌ planned | P3-3 |
| P3-4 | MCP wrappers for DB data (lookup_cve, etc.) | ❌ planned | P3-4 |
| P4-3 | Real MCP SDK transport (stdio + SSE) | ❌ planned | P4-3 |

Full task list: `/home/z/.copilot/session-state/*/plan.md`

---

## 12. Answerable Questions (target state)

Once Phase 1–3 is complete, the following queries should return grounded answers:

```bash
# What does ntdll.dll export?
curl -H "X-API-Key: $SK_API_KEY" \
  "http://localhost:8000/api/v1/entities/?search=ntdll.dll&kind=file_artifact"

# Bangladesh Bank SWIFT heist — full profile
curl -X POST -H "X-API-Key: $SK_API_KEY" \
  -d '{"tool_name":"search_knowledge","parameters":{"query":"Bangladesh Bank SWIFT 2016 Lazarus"}}' \
  http://localhost:8000/api/v1/mcp/call

# Shadow Brokers — threat actor profile
curl -X POST -H "X-API-Key: $SK_API_KEY" \
  -d '{"tool_name":"search_knowledge","parameters":{"query":"Shadow Brokers EternalBlue NSA leak"}}' \
  http://localhost:8000/api/v1/mcp/call

# What groups use T1550.002 Pass-the-Hash?
curl -X POST -H "X-API-Key: $SK_API_KEY" \
  -d '{"tool_name":"get_groups_using_technique","parameters":{"attack_id":"T1550.002"}}' \
  http://localhost:8000/api/v1/mcp/call
```

---

*Cross-references: [`AGENTS.md`](AGENTS.md) · [`deep-research-prompt.md`](deep-research-prompt.md) · [`bootstrap.md`](bootstrap.md) · [`TODO.md`](TODO.md)*
