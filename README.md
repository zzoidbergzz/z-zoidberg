# Security Knowledge Service — Implementation Plan

## Prerequisites
- Running instance of the Security Knowledge Service (API + DB)
- PostgreSQL with pgvector extension enabled
- Redis (for async queue backend)
- LLM provider API keys (OpenAI/Anthropic)

---

## 1. Wire LLM Extraction (Real Provider)

### Goal
Replace stub LLM calls with real OpenAI/Anthropic invocations for: threat actor attribution, exploit chain extraction, ambiguous product/version normalisation, and report comparison. Schema-validate all outputs.

### Steps
1. **Define LLM output schemas** as Pydantic models:
   - `ThreatActorAttribution` (name, confidence, aliases, supporting_evidence)
   - `ExploitChain` (steps: list[ExploitStep], cves, techniques)
   - `NormalisedProduct` (vendor, product, versions, cpes)
   - `ReportComparison` (shared_claims, contradictions, new_info)
2. **Create `app/llm/client.py`** — thin wrapper around OpenAI/Anthropic SDK:
   - Configurable provider via env `LLM_PROVIDER` (openai | anthropic)
   - Structured output mode (JSON schema enforcement / tool calling)
   - Retry with exponential backoff (tenacity)
   - Token budget tracking
3. **Create `app/llm/prompts/`** — versioned prompt templates for each extraction task:
   - `attribution.j2`, `exploit_chain.j2`, `normalise_product.j2`, `compare_reports.j2`
   - Include few-shot examples in each template
4. **Wire into existing extractors** (replace stubs in `app/extraction/`):
   - Each extractor calls `llm.client.chat()` with prompt + schema
   - Raw response → Pydantic model parse → on validation error, log + skip (don't store unvalidated claims)
5. **Schema validation gate** — every LLM output must pass `model.model_validate()` before writing to DB:
   - Invalid outputs go to a `llm_rejection_log` table for debugging
   - Return candidate claims with `confidence` and `source_ref` for downstream review
6. **Tests**: unit tests with mocked LLM responses; integration test against a saved threat report

### Files
- `app/llm/client.py` (new)
- `app/llm/prompts/*.j2` (new)
- `app/llm/schemas.py` (new)
- `app/extraction/*.py` (modify — swap stubs for real calls)
- `tests/test_llm_extraction.py` (new)

---

## 2. Async Queue-Based Ingestion

### Goal
Move ingestion to background workers. Large PDFs no longer block the API. Use existing `IngestionJob` table for tracking.

### Steps
1. **Pick queue library** — Arq (Redis-backed, lightweight, Python-native):
   - Add `arq` to `requirements.txt`
   - Create `app/worker.py` with arq `Worker` and `RedisSettings`
2. **Define job functions** in `app/worker.py`:
   - `async def ingest_document(job_id: str, file_path: str, source_id: str)`
   - `async def ingest_url(job_id: str, url: str, source_id: str)`
   - Each updates `IngestionJob.status` (pending → running → completed/failed)
3. **Refactor API endpoints** (`app/routers/ingestion.py`):
   - `POST /ingest` → create `IngestionJob` row (status=pending) → enqueue arq job → return 202 + job_id
   - `GET /ingest/{job_id}` → return job status + progress
4. **Add job status fields** to `IngestionJob` (migration):
   - `error_message TEXT`, `started_at TIMESTAMPTZ`, `completed_at TIMESTAMPTZ`, `progress_pct INT`
5. **Worker process** — add `arq app.worker.Worker` to Docker Compose / supervisord
6. **Graceful failure**: catch all exceptions in worker, set status=failed + error_message
7. **Tests**: enqueue a small job, poll until complete, assert status

### Files
- `app/worker.py` (new)
- `app/routers/ingestion.py` (modify)
- `alembic/versions/xxx_add_job_status_fields.py` (new)
- `docker-compose.yml` (modify — add worker service)
- `tests/test_async_ingestion.py` (new)

---

## 3. Embedding Generation Pipeline

### Goal
Replace mock embeddings with real OpenAI `text-embedding-3-small`. Add caching, batching, and wire vector search into context packs + entity search.

### Steps
1. **Create `app/embeddings/generator.py`**:
   - Call OpenAI embeddings API with `text-embedding-3-small` (1536d)
   - Batch requests (up to 2048 inputs per call per OpenAI limits)
   - Respect rate limits (tenacity retry on 429)
2. **Add embedding cache table** (migration):
   - `embedding_cache (text_hash VARCHAR(64) PRIMARY KEY, embedding VECTOR(1536), created_at TIMESTAMPTZ)`
   - Hash input text (SHA-256) → cache hit = skip API call
3. **Hook into ingestion pipeline**:
   - After claim extraction, generate embedding for each claim's text
   - Store in `claim_embeddings` (already has vector column if pgvector is set up)
   - Same for entity descriptions
4. **Vector similarity search** — `app/embeddings/search.py`:
   - `search_similar_claims(query_text, limit, threshold)` → embed query → `SELECT ... ORDER BY embedding <=> $1`
   - `search_entities(query_text, limit)`
5. **Wire into context pack generation**:
   - When building a context pack for a topic, include top-K similar claims via vector search
   - When searching entities, fall back to vector similarity if text search misses
6. **Tests**: mock OpenAI; test cache hit/miss; test similarity ranking

### Files
- `app/embeddings/generator.py` (new)
- `app/embeddings/search.py` (new)
- `alembic/versions/xxx_add_embedding_cache.py` (new)
- `app/services/context_pack.py` (modify)
- `app/services/entity.py` (modify)
- `tests/test_embeddings.py` (new)

---

## 4. Integrate BugBountyScanner Results into Knowledge Base

### Goal
Pipe BBS output (subdomains, URLs, nuclei findings) into the knowledge service as entities, sources, and claims. One command: `bbs-ingest target.com`.

### Steps
1. **Define BBS output schema** — parse JSON output from BugBountyScanner:
   - Subdomains: `[{host, ip, status, ports}]`
   - URLs: `[{url, status, title, tech}]`
   - Nuclei findings: `[{template_id, severity, host, matched_at, name, description, reference}]`
2. **Create `app/integrations/bbs/ingest.py`**:
   - `ingest_bbs_results(target: str, results: BBSResults)`:
     - Subdomains → `Entity(kind="domain", name=sub.host, attributes={...})`
     - URLs → `Source(kind="url", url=..., metadata={...})`
     - Nuclei findings → `Claim(text=..., claim_type="vulnerability", severity=..., source_id=...)`
3. **Create CLI command** `bbs-ingest`:
   - Runs BBS against target → parses output → calls `ingest_bbs_results`
   - Progress logging to stdout
   - Returns summary: "Created X entities, Y sources, Z claims"
4. **Deduplication**: before creating entities/claims, check for existing records by name/text to avoid duplicates
5. **Tests**: fixture with sample BBS output → assert correct entities/sources/claims created

### Files
- `app/integrations/bbs/schemas.py` (new)
- `app/integrations/bbs/ingest.py` (new)
- `app/cli/bbs_ingest.py` (new)
- `tests/test_bbs_ingest.py` (new)
- `tests/fixtures/bbs_sample.json` (new)

---

## 5. PyGhidra ↔ Security Knowledge Bridge

### Goal
Extract function names, strings, imports, IOCs from PyGhidra binary analysis → feed as entities/claims. Source-backed, traceable.

### Steps
1. **Create `app/integrations/ghidra/bridge.py`**:
   - Accepts a binary file path → runs PyGhidra headless analysis
   - Extract: function names, imported libraries, string literals, identified patterns
2. **IOC extraction** from binary strings:
   - Regex patterns for IPs, domains, URLs, file paths, registry keys, mutex names
   - Map to entity kinds: `ip_address`, `domain`, `url`, `registry_key`, `mutex`
3. **Entity/claim creation**:
   - Each IOC → `Entity(kind=..., name=..., source_id=ghidra_source)`
   - Function signatures → `Claim(text="Binary contains function X matching Y pattern", claim_type="indicator")`
   - Imported libs → `Claim(text="Binary imports WinINet, Shell32 — consistent with downloader", claim_type="assessment")`
4. **Link to existing knowledge**:
   - After extraction, run entity dedup + similarity search (vector) to link with known threat actor infrastructure
   - E.g., "This binary contains C2 beacon strings matching known APT-EXAMPLE infrastructure" → auto-generate relationship
5. **API endpoint**: `POST /analyse/binary` → async job (reuses queue from #2) → returns source_id + summary
6. **Tests**: use a small test binary (e.g., compiled hello world); verify entity/claim extraction

### Files
- `app/integrations/ghidra/bridge.py` (new)
- `app/integrations/ghidra/ioc_patterns.py` (new)
- `app/routers/analysis.py` (new or modify)
- `tests/test_ghidra_bridge.py` (new)

---

## 6. Authentication & Authorisation

### Goal
API key auth (tenant-scoped), JWT for analyst UI, database-level RLS for tenant isolation.

### Steps
1. **API key auth** — `app/auth/api_key.py`:
   - `api_keys` table: `(id, key_hash, tenant_id, name, scopes, created_at, expires_at)`
   - Hash keys with bcrypt on storage, compare on request
   - FastAPI dependency: `get_current_tenant` → reads `X-API-Key` header → validates → returns tenant_id
2. **JWT auth** (for analyst UI) — `app/auth/jwt.py`:
   - `users` table: `(id, email, password_hash, tenant_id, role, created_at)`
   - `POST /auth/login` → validate credentials → return JWT (tenant_id + role in claims)
   - FastAPI dependency: `get_current_user` → validates JWT → returns user + tenant
3. **Row-Level Security** — Alembic migration:
   - `ALTER TABLE claims ENABLE ROW LEVEL SECURITY;`
   - `CREATE POLICY tenant_isolation ON claims USING (tenant_id = current_setting('app.tenant_id')::uuid);`
   - Repeat for all tenant-scoped tables (claims, entities, sources, ingestion_jobs, etc.)
   - App sets `app.tenant_id` session variable on each request: `SET LOCAL app.tenant_id = '...';`
4. **Apply auth to all routes**:
   - Public: `POST /auth/login`, health checks
   - API key required: ingestion, search, export
   - JWT required: claim review, analyst actions
5. **Scopes/roles**:
   - API key scopes: `read`, `write`, `admin`
   - User roles: `analyst`, `admin`
6. **Tests**: test API key validation, JWT flow, RLS enforcement (cross-tenant data invisible)

### Files
- `app/auth/api_key.py` (new)
- `app/auth/jwt.py` (new)
- `app/auth/dependencies.py` (new)
- `app/routers/auth.py` (new)
- `alembic/versions/xxx_add_auth_tables_rls.py` (new)
- `app/main.py` (modify — add auth middleware)
- `tests/test_auth.py` (new)

---

## 7. Proper Full-Text Search

### Goal
Replace ILIKE with Postgres FTS (tsvector) + trigram fuzzy matching.

### Steps
1. **Add tsvector columns** (migration):
   - `claims.search_vector TSVECTOR`
   - `entities.search_vector TSVECTOR`
   - GIN indexes on both
2. **Add trigram indexes**:
   - `CREATE EXTENSION IF NOT EXISTS pg_trgm;`
   - `CREATE INDEX idx_entities_name_trgm ON entities USING gin (name gin_trgm_ops);`
   - `CREATE INDEX idx_entities_alias_trgm ON entities USING gin (aliases gin_trgm_ops);` (if aliases is text[])
3. **Trigger for auto-updating search_vector**:
   ```sql
   CREATE FUNCTION claims_search_vector_update() RETURNS trigger AS $$
   BEGIN
     NEW.search_vector := setweight(to_tsvector('english', COALESCE(NEW.text, '')), 'A')
                       || setweight(to_tsvector('english', COALESCE(NEW.claim_type, '')), 'B');
     RETURN NEW;
   END $$ LANGUAGE plpgsql;
   ```
   Similar for entities (name + kind + description).
4. **Backfill** existing rows: `UPDATE claims SET search_vector = ...;`
5. **Replace search queries** in `app/services/`:
   - `search_claims(q)` → `SELECT *, ts_rank(search_vector, query) AS rank FROM claims, plainto_tsquery('english', $1) query WHERE search_vector @@ query ORDER BY rank DESC`
   - Fuzzy fallback: `SELECT * FROM entities WHERE name % $1` (trigram similarity)
   - Combine: FTS results + trigram results, deduplicated, ranked
6. **Tests**: seed test data, verify ranked search, fuzzy matching, and performance (query plan uses GIN index)

### Files
- `alembic/versions/xxx_add_fts_trgm.py` (new)
- `app/services/search.py` (new or modify)
- `app/routers/search.py` (modify — use new search service)
- `tests/test_search.py` (new)

---

## 8. TAXII/STIX + NVD + GitHub Advisory Adapters

### Goal
Implement real ingestion from NVD API v2, GitHub Advisory API, and TAXII 2.1. Each becomes a scheduled source.

### Steps
1. **NVD Adapter** — `app/integrations/nvd/adapter.py`:
   - Call NVD API v2: `GET https://services.nvd.nist.gov/rest/json/cves/2.0`
   - Parse CVE records → extract: CVE ID, description, CVSS scores, affected products (CPE), references
   - Map: CVE ID → `Entity(kind="cve")`, description → `Claim`, CPEs → `Entity(kind="software")`, CVSS → claim attribute
   - Incremental sync: store `last_modified` timestamp, query with `pubStartDate` on next run
2. **GitHub Advisory Adapter** — `app/integrations/github/adapter.py`:
   - Call GraphQL API: `securityVulnerabilities` query (or REST `/advisories`)
   - Parse: GHSA ID, severity, affected packages (ecosystem + version range), summary
   - Map: GHSA → `Entity(kind="advisory")`, packages → `Entity(kind="package")`, summary → `Claim`
   - Auth with GitHub token from env
3. **TAXII 2.1 Client** — `app/integrations/taxii/adapter.py`:
   - Connect to TAXII server (configurable URL + auth)
   - Discover API roots → collections → iterate objects
   - Parse STIX 2.1 bundles: extract `threat-actor`, `malware`, `indicator`, `vulnerability`, `attack-pattern` objects
   - Map each STIX object type → corresponding entity kind + claims
4. **Scheduled ingestion** — add to worker (from #2):
   - `async def scheduled_nvd_sync()` — runs daily
   - `async def scheduled_github_advisory_sync()` — runs daily
   - `async def scheduled_taxii_sync()` — runs on configurable cron
   - Track last sync time per source in `sync_state` table
5. **CLI commands**: `nvd-sync`, `ghsa-sync`, `taxii-sync` for manual runs
6. **Tests**: mock each external API; verify entity/claim creation; test incremental sync (no duplicates)

### Files
- `app/integrations/nvd/adapter.py` (new)
- `app/integrations/github/adapter.py` (new)
- `app/integrations/taxii/adapter.py` (new)
- `app/integrations/scheduler.py` (new)
- `alembic/versions/xxx_add_sync_state.py` (new)
- `tests/test_nvd_adapter.py` (new)
- `tests/test_ghsa_adapter.py` (new)
- `tests/test_taxii_adapter.py` (new)

---

## 9. Analyst Review UI

### Goal
Web dashboard for reviewing machine-extracted claims, resolving conflicts, verifying entities.

### Steps
1. **Choose stack** — HTMX + Jinja2 templates (keeps it in-process with FastAPI, no separate build):
   - `pip install htmx` not needed — just serve HTMX from CDN
   - Jinja2 already bundled with FastAPI via `fastapi.templating`
2. **Create `app/ui/` structure**:
   - `app/ui/routes.py` — FastAPI router for UI endpoints
   - `app/ui/templates/` — Jinja2 templates (base, claims, entities, review)
   - `app/ui/static/` — CSS, HTMX CDN fallback
3. **Views**:
   - **Claim Inbox** (`GET /ui/claims`): paginated list of unreviewed claims, sortable by severity/confidence/date. Each row: claim text, source, confidence, [Approve] [Reject] [Edit] buttons
   - **Claim Detail** (`GET /ui/claims/{id}`): full claim + source context + linked entities + conflicting claims. Inline edit form
   - **Entity Review** (`GET /ui/entities`): entities needing verification (no human review yet). Merge/dedup interface
   - **Dashboard** (`GET /ui/`): stats — claims by status, entities by kind, recent activity
4. **HTMX interactions**:
   - Approve/Reject: `hx-post="/claims/{id}/review"` → returns updated row fragment
   - Edit: inline form → `hx-put="/claims/{id}"` → returns updated detail
   - Merge entities: select two → `hx-post="/entities/merge"` → redirects
5. **Auth**: require JWT login (from #6) for all `/ui/` routes
6. **Mount in `app/main.py`**: `app.mount("/ui", ui_routes)`
7. **Tests**: Playwright or simple `TestClient` smoke tests for each view

### Files
- `app/ui/routes.py` (new)
- `app/ui/templates/base.html` (new)
- `app/ui/templates/claims.html` (new)
- `app/ui/templates/claim_detail.html` (new)
- `app/ui/templates/entities.html` (new)
- `app/ui/templates/dashboard.html` (new)
- `app/ui/static/style.css` (new)
- `app/main.py` (modify — mount UI)
- `tests/test_ui.py` (new)

---

## 10. Change Detection & Alerting

### Goal
Detect when new claims contradict/supersede existing ones, track claim version history, expose `/changes` endpoint, enable "what changed since yesterday?" queries.

### Steps
1. **Claim version history** — `claim_versions` table (migration):
   - `(id, claim_id, version INT, text, status, confidence, changed_at, changed_by, change_reason)`
   - On any claim update, insert previous state as new version row
   - Trigger or application-level: `before_update` → snapshot to `claim_versions`
2. **Contradiction detection** — `app/services/change_detection.py`:
   - When a new claim is created/updated, find existing claims for the same entity:
     - If `status` changes (e.g., "unexploited" → "exploited in the wild") → flag as status change
     - If claim text is semantically contradictory (embedding similarity > threshold + LLM verification) → flag as contradiction
   - Store detected changes in `changes` table: `(id, claim_id_old, claim_id_new, change_type, description, detected_at, resolved)`
3. **Alert generation**:
   - Each unresolved row in `changes` is an alert
   - Severity: `status_change` = high, `contradiction` = medium, `new_info` = low
   - Optional: push to webhook / Slack / email
4. **`GET /changes` endpoint** — `app/routers/changes.py`:
   - Query params: `since` (ISO timestamp), `change_type`, `resolved`, `entity_id`
   - Returns: list of changes with old/new claim details, description, severity
5. **Cron-based monitoring** — `async def detect_changes()`:
   - Runs every N minutes (configurable)
   - Checks claims created/updated since last run
   - Runs contradiction detection against existing claims
   - Generates alerts
6. **Agent query support**: natural language "what changed since yesterday?" → translate to `/changes?since=yesterday` → summarise results with LLM
7. **Tests**: create two contradictory claims → verify detection; update claim status → verify change record; query `/changes` endpoint

### Files
- `app/services/change_detection.py` (new)
- `app/routers/changes.py` (new)
- `alembic/versions/xxx_add_claim_versions_changes.py` (new)
- `app/worker.py` (modify — add scheduled change detection job)
- `tests/test_change_detection.py` (new)

---

## 11. EUVD (ENISA) Adapter

### Goal
Poll the EU Vulnerability Database (EUVD) API for new/updated vulnerabilities, ingest into the knowledge base as entities and claims. Complements NVD (#8) with EU-specific enrichment (EPSS scores, ENISA product/vendor UUIDs, EU advisories). No LLM required — structured JSON → deterministic mapping.

### API Overview
- Base: `https://euvdservices.enisa.europa.eu/api/`
- **Search**: `/search?fromDate=&toDate=&fromScore=&toScore=&fromEpss=&toEpss=&exploited=&page=&size=` (paginated, max 100/page)
- **Last vulns**: `/lastvulnerabilities` (max 8)
- **Exploited**: `/exploitedvulnerabilities` (max 8)
- **Critical**: `/criticalvulnerabilities` (max 8)
- **By ID**: `/enisaid?id=EUVD-2025-XXXXX`
- **Advisory**: `/advisory?id=oxas-adv-2024-XXXX`
- No auth required
- Response fields: `id`, `description`, `datePublished`, `dateUpdated`, `baseScore`, `baseScoreVersion`, `baseScoreVector`, `references` (\n-separated URLs), `aliases` (CVE/GSD IDs \n-separated), `assigner`, `epss`, `enisaIdProduct[]`, `enisaIdVendor[]`

### Steps
1. **Create `app/integrations/euvd/client.py`**:
   - HTTP client for EUVD API (httpx)
   - `search(from_date, to_date, min_score, exploited, page, size)` → paginated results
   - `get_by_id(euvd_id)` → single vulnerability
   - `get_exploited()` → currently exploited vulns
   - `get_critical()` → critical vulns
   - `get_advisory(advisory_id)` → ENISA advisory
   - Rate limiting: respect 429s, default 1 req/sec
2. **Create `app/integrations/euvd/adapter.py`**:
   - `ingest_euvd_vulnerability(item: dict)` → map to knowledge base:
     - EUVD ID → `Entity(kind="euvd", name=item["id"])`
     - Each CVE alias → `Entity(kind="cve", name=alias)` + relationship to EUVD entity
     - Each vendor → `Entity(kind="vendor", name=..., external_id=enisa_uuid)`
     - Each product → `Entity(kind="software", name=..., external_id=enisa_uuid, version=...)` + relationship to vendor
     - Description → `Claim(text=..., claim_type="vulnerability", severity=baseScore, confidence=1.0)`
     - CVSS vector → claim attribute
     - EPSS score → claim attribute `epss` (unique to EUVD, not in NVD)
     - Each reference URL → `Source(kind="url", url=...)`
   - Advisory ingestion: advisory text → `Claim(claim_type="advisory")`, linked to relevant entities
3. **Deduplication & cross-referencing with NVD** (#8):
   - When EUVD item has CVE alias, look up existing CVE entity from NVD adapter
   - If exists → link EUVD entity as related, merge product/version data
   - If not → create CVE entity from EUVD alias data (NVD sync will enrich later)
   - EPSS score is EUVD-only enrichment: store on the claim even if CVE came from NVD
4. **Incremental sync** — `app/integrations/euvd/sync.py`:
   - `scheduled_euvd_sync()`: query `/search?fromDate=<last_sync_date>` → page through all new/updated items
   - Store `last_sync_date` in `sync_state` table (reuse from #8)
   - Run daily via worker queue (#2)
5. **Exploited/Critical monitoring**:
   - Poll `/exploitedvulnerabilities` and `/criticalvulnerabilities` more frequently (every 4h)
   - New exploited vulns → generate alerts via change detection (#10)
   - Compare against existing `exploited` status; status change = high-priority alert
6. **CLI command**: `euvd-sync` for manual full/partial sync
7. **Optional: MCP tool** (`app/mcp/tools/euvd_lookup.py`):
   - Expose `euvd_search` and `euvd_get` as MCP tools for on-demand agent queries
   - Useful for live lookups the knowledge base hasn't ingested yet
   - Only build this after core ingestion is stable
8. **Tests**: mock EUVD API responses; test entity/claim creation; test dedup against NVD fixtures; test incremental sync; test exploited-vuln alerting

### Files
- `app/integrations/euvd/client.py` (new)
- `app/integrations/euvd/adapter.py` (new)
- `app/integrations/euvd/sync.py` (new)
- `app/cli/euvd_sync.py` (new)
- `app/mcp/tools/euvd_lookup.py` (new, optional)
- `tests/test_euvd_adapter.py` (new)
- `tests/fixtures/euvd_sample.json` (new)

---

## Dependency Order

```
#6 (Auth) ← should be early; other routes depend on tenant context
#2 (Async Queue) ← #8, #10 depend on background workers
#7 (FTS) ← independent, can run in parallel
#3 (Embeddings) ← depends on queue (#2) for batch generation
#1 (LLM Extraction) ← independent, but schema validation benefits from auth context (#6)
#8 (Adapters) ← depends on queue (#2) + auth (#6)
#4 (BBS Integration) ← independent
#5 (Ghidra Bridge) ← independent
#10 (Change Detection) ← depends on embeddings (#3) for contradiction detection + queue (#2) for cron
#9 (Analyst UI) ← depends on auth (#6), consumes all above
```

Suggested sequence: **6 → 2 → 7 → 3 → 1 → 8 → 11 → 4 → 5 → 10 → 9**

- #11 (EUVD) slots after #8 since it reuses the same adapter pattern, sync_state table, and worker infrastructure. EUVD data also cross-references with NVD entities from #8.
