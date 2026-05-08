# Z-Zoidberg / Security-Knowledge Improvement Plan

> Reset 2026-05-08. The previous TODO declared "all 22 items complete ✅". The
> `README.md` (reviewed 2026-05-07) and a code walk show that scaffolding exists
> but several spine paths are stubs. Trust the code, not old roadmap prose.
> Old item-by-item roadmap kept as section "Legacy Roadmap (status reference
> only)" at the bottom — do not treat its ✅ marks as load-bearing.

This plan focuses on three goals:

1. **Make the project usable by LLM agents in one read.** Today an agent has to
   stitch context from `AGENTS.md`, `README.md`, `bootstrap.md`,
   `AGENT_INSTRUCTIONS.md`, `mcp-tool-manifest.json`, and the live MCP
   endpoint. Several of those disagree.
2. **Close the real MCP and knowledge gaps** (ingest worker, enrichment
   providers, manifest drift, missing thin MCP wrappers around capabilities
   that already exist as REST).
3. **Slim and slick the workspace** — drop stale claims, generate manifests
   from code, archive dead files.

---

## Section A — Agent Operating Method (target end-state)

Every LLM agent (this Zoidberg session, the bootstrapped corpus host, future
hosts) follows the same loop:

```
1. Read AGENTS.md (rules, memory, red lines)        — ~40 lines
2. Read AGENT_QUICKSTART.md (NEW, see Item A1)      — single page
3. GET  /api/v1/capabilities  (NEW, see Item A2)    — live, machine-readable
4. GET  /api/v1/mcp/tools                            — live tool list
5. Use the workflow recipes from AGENT_QUICKSTART.md to call tools.
6. Append session notes to memory/YYYY-MM-DD.md.
```

No agent should ever read `mcp-tool-manifest.json` as a primary source — it is
a static fallback for offline introspection only and must be regenerated from
the live service (Item A3).

### Item A1 — Create `AGENT_QUICKSTART.md` at repo root

Single page that contains, in order:

- Service-up checklist (`docker compose up -d`, `alembic upgrade head`,
  `seed_data`, uvicorn, arq worker). Two boxes: ✅ = healthy, ❌ = with the
  exact failing symptom and pointer to fix.
- Auth: where the seeded admin key lives (`.runtime/seed-admin-*.log`,
  mode 0600). Never paste it into chat.
- Capability discovery: one curl to `/api/v1/capabilities`, one to
  `/api/v1/mcp/tools`.
- Five canonical recipes (copy-paste curl):
  1. "I have an ATT&CK ID, give me everything" → `mcp/call`
     `get_object_by_attack_id` → `get_groups_using_technique` →
     `get_datacomponents_detecting_technique`.
  2. "I have an indicator, enrich it" → `enrich/{kind}/{value}` (preferred)
     and the planned `enrich_entity` MCP tool once Item B1 lands.
  3. "I have a research corpus directory" → bootstrap.md Mode A; the
     importer endpoint planned in Item C2.
  4. "I want to know what changed" → `/changes?since=...`,
     `/api/v1/digests/...`.
  5. "I want to publish to STIX/TAXII" → `/api/v1/export/stix`, TAXII
     discovery URL.
- Honest "Known stubs" callout block: ingest worker, `enrich_entity` MCP
  tool, GraphQL resolvers, missing providers (IPinfo, GreyNoise,
  CrowdStrike), `ILIKE` search. Same list as README — single source.

Acceptance: a fresh agent that reads only `AGENT_QUICKSTART.md` plus the live
endpoints can make a successful MITRE call and a successful entity-create
call within five tool turns.

### Item A2 — Add `GET /api/v1/capabilities`

Live, machine-readable inventory. Returns:

```json
{
  "version": "<git sha or pyproject version>",
  "endpoints": ["/api/v1/entities/", ...],         // generated from app.routes
  "mcp_tools": [...],                               // same payload as /mcp/tools
  "providers": {
     "registered": ["mitre","virustotal", ...],
     "configured": ["mitre","virustotal"],          // creds present
     "missing":   ["ipinfo","greynoise","crowdstrike"]
  },
  "feature_flags": {
     "ingest_worker_pipeline": false,               // honest until Item C1 lands
     "fts_search": false,
     "graphql_resolvers": "stub"
  },
  "stale_paths": [
     "POST /api/v1/ingest/  (queues job; worker stub)",
     "POST /api/v1/mcp/call enrich_entity  (returns empty)"
  ]
}
```

The `feature_flags` and `stale_paths` arrays are the canonical truth. Update
them in code as features land. Delete the README "Partial Or Stale" block and
have it render from this endpoint instead (or at minimum link to it).

### Item A3 — Auto-generate `mcp-tool-manifest.json`

Add `python -m app.cli.dump_mcp_manifest` (and a `make manifest` target) that
serialises the live `/mcp/tools` payload plus the static `mcp_servers`
section. Run in CI; fail the build if the committed manifest drifts. Until
the script exists, mark the file `EXPERIMENTAL — see /api/v1/mcp/tools` at
the top.

### Item A4 — Single agent-rules file

Today: `AGENTS.md` (workspace rules) + `security-knowledge/AGENT_INSTRUCTIONS.md`
(15 lines, mostly wrong: dev paths, missing live endpoints, no MCP guidance).
Action: rewrite `security-knowledge/AGENT_INSTRUCTIONS.md` as a thin pointer
to root `AGENT_QUICKSTART.md`, plus the dev-loop commands (`make test`, `make
lint`, `alembic`). Three sections max.

### Item A5 — Memory / continuity hygiene

- Add `MEMORY.md` skeleton at repo root (currently absent — `AGENTS.md` says
  "main session also reads MEMORY.md"). Sections: Project Facts, People,
  Open Threads, Resolved.
- Add a daily memory rotation note in `AGENTS.md`: when distilling
  `memory/YYYY-MM-DD.md` into `MEMORY.md`, drop any line that just restates
  current `README.md` or `/api/v1/capabilities` truth.
- Forbid memory entries containing API keys, bearer tokens, JWTs, or
  pingback secrets. Existing rule in SOUL.md but not enforced — add a
  pre-commit grep for `KEY|TOKEN|SECRET=[^$]` in `memory/`.

---

## Section B — MCP Surface: Real Gaps

### Item B1 — Wire `enrich_entity` MCP tool to `EnrichmentService`

Currently `app/mcp/tools/enrich_entity.py` exists and the router dispatches to
it, but it returns empty enrichment data because the provider registry is
empty at startup (Item B2) and the tool does not call `EnrichmentService` end
to end. Tasks:

- In `enrich_entity_tool`, call `EnrichmentService.enrich(...)` for the
  resolved entity, materialise claims/evidence, return normalized provider
  output plus claim ids.
- Add integration test using a mocked VirusTotal provider proving cache
  miss → provider call → claim creation → second call hits cache.
- Update tool input schema to accept `providers: list[str] | None` and
  `force: bool = False`.

### Item B2 — Populate provider registry on import

`app/enrichment/providers/__init__.py` is empty. Providers self-register via
the `@register` decorator only when their module is imported. Action:

```python
# app/enrichment/providers/__init__.py
from . import virustotal, shodan, nvd, mitre_attack, misp, opencti  # noqa
# Future, once Item B3 lands:
# from . import ipinfo, greynoise, crowdstrike  # noqa
```

Plus: log registered providers at app startup (counter +
`structlog.info("enrichment.providers.registered", names=list_providers())`)
and surface them on `/api/v1/capabilities`.

### Item B3 — Implement missing providers: IPinfo, GreyNoise, CrowdStrike

Required by the prior roadmap and by `enrichment-policy.yaml` claims; not
present. Each provider:

- Module `app/enrichment/providers/<name>.py` subclassing
  `BaseEnrichmentProvider`.
- Capability declaration (entity kinds, batch yes/no, requires-paid-tier).
- Source-policy entry for the provider domain in `source-policy.yaml`.
- Env vars in `.env.example` and `app/config.py`.
- Mocked tests under `tests/test_enrichment_<name>.py`.
- README/`docs/enrichment.md` row.

CrowdStrike note: a public **falcon-mcp** stdio MCP server already exists
(see TOOLS.md, Item B7). Decide explicitly: do we proxy via that MCP server
(no provider needed) or do we wrap FalconPy directly? Recommendation: ship
the in-process provider so cached/policy-gated; keep the falcon-mcp stdio
config for ad-hoc analyst use.

### Item B4 — Promote existing services to first-class MCP tools

Right now MCP exposes `enrich_entity` + 31 MITRE tools. Many other useful
capabilities exist as REST but not as MCP, forcing agents to leave the MCP
contract:

| New MCP tool | Backed by |
| --- | --- |
| `search_knowledge` | `app/services/search.py` (FTS once Item C3 lands; ILIKE today) |
| `get_entity` / `list_entities` | `routers/entities.py` |
| `create_entity` / `create_claim` / `create_evidence` | corresponding routers (write scope) |
| `lookup_cve` | NVD adapter + EUVD adapter |
| `lookup_kev` | KEV adapter |
| `get_changes_since` | `routers/changes.py` |
| `export_stix_bundle` | `routers/stix.py` |
| `analyse_binary` | Ghidra bridge (item 5) — mark experimental |
| `searxng_search` | local SearXNG (TOOLS.md) — wraps `http://localhost:8888/search?format=json` |

Each tool: thin wrapper, scope-checked, schema in `MITRE_TOOL_SCHEMAS`-style
table, exercised by one mocked test, documented in `AGENT_QUICKSTART.md`.

### Item B5 — Replace ad-hoc dispatch with tool registry

`routers/mcp.py` currently has a giant `MITRE_TOOLS` dict and an `if
body.tool == "enrich_entity"` branch. After Item B4 this becomes unwieldy.
Refactor:

- `app/mcp/registry.py`: `register_tool(name, fn, schema, scope, description)`.
- Each tool module calls `register_tool(...)` at import time.
- `routers/mcp.py` iterates the registry for both `/tools` and `/call`.
- Add `description` per tool (currently missing) — agents need it for tool
  selection.
- Standardise error envelope `{"error": {"code": "...", "message": "..."}}`.

### Item B6 — Stand up an actual MCP server endpoint (stdio + SSE)

`/api/v1/mcp/call` is **not** the Model Context Protocol. It is a custom
HTTP RPC. To be usable by MCP clients (Claude Desktop, Cursor, Copilot CLI
with `mcp.json`):

- Add `app/mcp/server.py` exposing the same registry (Item B5) over the real
  MCP protocol via the official `mcp` Python SDK.
- Two transports: stdio (for desktop hosts) and SSE/HTTP at
  `/api/v1/mcp/sse` (for in-process agents).
- Provide a sample `mcp.json` snippet in `AGENT_QUICKSTART.md`.

### Item B7 — Document and ship the external MCP servers we depend on

The static manifest references `falcon-mcp`. Add a discovery section to
`AGENT_QUICKSTART.md` covering:

- `falcon-mcp` (already configured) — prerequisites, run command.
- Candidate add-ons to evaluate (track decisions, not blind adoption):
  - **github-mcp-server** (already in this CLI) — keep as agent-side, don't
    re-bundle.
  - **virustotal-mcp / shodan-mcp** community servers — only if Item B3
    in-process providers are insufficient.
  - **memory-mcp** (e.g. `mcp-server-memory` or sqlite-backed) — would
    replace ad-hoc `MEMORY.md` for cross-session recall. Open question:
    worth it given current scale? Default decision: not yet.
  - **fetch-mcp** — overlaps with our policy-gated fetcher; reject.
  - **playwright-mcp** — already implicit via `browser_pool.py`; no MCP
    wrapper needed.

---

## Section C — Knowledge Gaps (substantive)

Same list as README "Partial Or Stale" but with concrete tasks.

### Item C1 — Implement `process_ingest_job` end-to-end

Worker function in `app/worker.py` is a stub. Required pipeline:

1. Resolve source policy for URL; abort with reason if denied.
2. Fetch via `app/fetcher.py` (httpx, Playwright fallback). Persist
   `RawObject` with SHA-256.
3. Parse: HTML → trafilatura/readability; PDF → pdfminer/pypdf with page
   anchors; markdown passthrough. Persist `ParsedDocument`.
4. Chunk into `DocumentSection` rows preserving heading path + char/page
   offsets.
5. Run `app/extractors/*` to materialise CVEs, hashes, CPEs, ATT&CK refs,
   actors, malware → `Entity` + `Claim` + `Evidence` upserts.
6. Enqueue embedding job (Item is already done if Item 3 lands properly).
7. Emit audit event + webhook event.

Acceptance: `POST /api/v1/ingest/` with a known fixture URL produces the
full chain and is idempotent on re-run.

### Item C2 — Bulk corpus importer (Mode A)

Implement what `bootstrap.md` and `deep-research-prompt.md` already specify:

- `python -m app.cli.import_corpus --package <dir> [--validate] [--import]`.
- `POST /api/v1/import/corpus` (multipart tar.zst) for remote agents.
- Idempotent upserts keyed as documented in `bootstrap.md` "Importer
  Requirements".
- Reject facts without evidence by default.
- Emit audit batch + import summary.
- Tests: tiny fixture corpus (3 sources, 5 facts) imported twice, second
  run zero writes.

### Item C3 — Replace `ILIKE` search with FTS + trigram

Migrations 0004/0005 already add `search_vector` and `pg_trgm`. Action:

- Switch `app/services/search.py` to ranked `to_tsvector @@ plainto_tsquery`
  with `ts_rank_cd`, plus `pg_trgm` similarity fallback for short queries.
- Add per-kind weights (entity name > claim statement > evidence quote).
- Update tests in `tests/test_search_api.py`.

### Item C4 — Implement GraphQL resolvers

`app/graphql/schema.py` resolvers return None/[]. Wire to existing CRUD
services with dataloader batching. Add depth/cost limit (already declared).
At minimum: `entity(id)`, `entities(filter)`, `claim(id)`,
`relationships(entity_id, depth)`.

### Item C5 — Fill or delete the TBD docs

`security-knowledge/docs/*.md` are largely TBD. Either:

- Generate from code (`api_reference.md` from OpenAPI), or
- Delete and let agents read the live OpenAPI at `/openapi.json`.

Default: delete TBD files; keep `mitre_attack.md` (useful) and the new
`AGENT_QUICKSTART.md`.

### Item C6 — Source / page provenance fields

`DocumentSection` and `Evidence` lack page numbers, byte offsets, and
artifact ids needed by `bootstrap.md` Mode A imports. Add a non-destructive
migration extending the schema (or storing in `properties` JSON for now,
with a follow-up migration).

---

## Section D — Workspace Slickness

### Item D1 — Truth in advertising

- Drop the "STATUS: ALL 22 ITEMS COMPLETE ✅" header (done — this rewrite).
- Strip all ✅ marks from the legacy roadmap section below; replace with
  inline `[code: scaffolded | wired | stub | missing]` tags after a
  one-pass code audit (track in `session_state` or a follow-up doc, not
  here).
- README "Partial Or Stale" section becomes a generated artefact from
  `/api/v1/capabilities` (Item A2) — keep the prose pointer only.

### Item D2 — Remove duplicate prompts

`prompt.md` and `bootstrap.md` and `deep-research-prompt.md` overlap.
Decision matrix:

- `bootstrap.md` — keep, it is the canonical handoff for external corpus
  agents. Add a top banner pointing to `AGENT_QUICKSTART.md`.
- `deep-research-prompt.md` — keep, it defines the corpus schema. Move
  under `docs/` or rename `CORPUS_SCHEMA.md`.
- `prompt.md` — archive. It references the old item ordering and contradicts
  the new "trust the code" stance.

### Item D3 — Heartbeat is dead air

`HEARTBEAT.md` is empty (correct per AGENTS.md), but no code reads it.
Either implement the heartbeat poller (`memory/heartbeat-state.json`) or
delete the file and the AGENTS.md section. Default: implement, since
there's already cron infrastructure planned.

### Item D4 — `.openclaw` artifact

There is an `.openclaw` directory at repo root. Either documented or
ignored. Add to `.gitignore` if local-only, or document in README under
"Project Files" if it's a peer-tool config.

### Item D5 — One Makefile, one entrypoint

Add a root `Makefile` with the three commands an agent or human ever needs:

```
make agent-context  # prints AGENTS.md + AGENT_QUICKSTART.md + capabilities curl
make up             # docker compose up -d, migrate, seed
make test           # pytest -q in security-knowledge/
```

Currently the Makefile lives only inside `security-knowledge/`.

### Item D6 — Pre-commit hooks

- `ruff check && ruff format --check` (already runnable).
- Block secrets in `memory/` (Item A5).
- Block edits to existing alembic revisions (matches universal rule from
  the legacy roadmap).

---

## Section E — What's Missing (informational)

**Information missing from the project:**

- A live "what works today vs. what's promised" oracle. (Closed by Item A2.)
- Tool descriptions in MCP listings — agents currently get tool names + arg
  shapes but no semantics. (Closed by Item B5.)
- A canonical agent quickstart. (Closed by Item A1.)
- A documented decision log for which external MCP servers we adopt.
  (Closed by Item B7.)
- MEMORY.md scaffold. (Closed by Item A5.)
- An importer for the corpus format the project already specifies.
  (Closed by Item C2.)
- Page/offset provenance on evidence rows. (Closed by Item C6.)

**MCP tools/servers missing:**

- In-process: `search_knowledge`, `lookup_cve`, `lookup_kev`,
  `get_changes_since`, `export_stix_bundle`, `searxng_search`,
  CRUD wrappers for entities/claims/evidence. (Item B4.)
- Real MCP-protocol transport (stdio + SSE). (Item B6.)
- Provider implementations for IPinfo, GreyNoise, CrowdStrike. (Item B3.)
- Optional external servers to evaluate: github-mcp-server (already in CLI
  side; do not bundle), memory-mcp (defer), fetch-mcp (reject — overlaps
  policy-gated fetcher), playwright-mcp (reject — already in-process).

---

## Section F — Execution Order

Strict dependency order. Each item is small enough to land in one PR.

```
A1 (quickstart) -> A2 (capabilities endpoint) -> A3 (manifest dump) ->
A4 (collapse agent docs) -> A5 (MEMORY skeleton + secret guard) ->
B2 (provider registry import) -> B1 (enrich_entity wired) ->
B5 (tool registry refactor) -> B4 (promote services to MCP tools) ->
C3 (FTS search) -> C1 (ingest worker) -> C2 (bulk importer) ->
C6 (provenance fields) -> B3 (missing providers) ->
B6 (stdio + SSE MCP transport) -> C4 (GraphQL resolvers) ->
C5 (docs cleanup) -> D1..D6 (slickness, can interleave)
```

Stop and ask the human if:

- Adopting an external MCP server requires a new long-lived credential.
- A migration in C1/C2/C3/C6 risks data loss in `seed_data` corpora.
- The decision in B7 (proxy CrowdStrike via falcon-mcp vs. in-process
  provider) becomes contested.

---

## Legacy Roadmap (status reference only)

The original 22-item roadmap is preserved below for reference. Treat ✅ as
"scaffolding exists in code", not "feature works end-to-end". The honest
gap list is in Section C above.

## Current Repository Context

- The service described by this roadmap is `security-knowledge/`, a FastAPI + Postgres + pgvector project referenced from `README.md`.
- **`security-knowledge/` is fully implemented.** Run `make test` to verify.
- Expected service shape from the existing docs:
  - FastAPI API on port 8000. ✅
  - Postgres with pgvector. ✅
  - Redis for workers after async queue work. ✅
  - Alembic migrations. ✅
  - pytest, ruff, mypy. ✅
  - MCP-ready tool manifest. ✅
  - Policy-gated outbound HTTP via `source-policy.yaml`. ✅

## Improvements Made During Consolidation

1. **Single source of truth:** merge both plan files into this `TODO.md`; delete the old files to avoid downstream agents reading conflicting instructions.
2. **Execution-first order:** keep the composite order but move universal rules to the top so they apply to all items, not just extensions.
3. **Provider-complete enrichment:** expand the enrichment work to cover VirusTotal, MISP, OpenCTI, Shodan, IPinfo.io, GreyNoise.io, and CrowdStrike Falcon API functionality.
4. **Clear provider boundaries:** treat enrichment providers, bidirectional sync systems, and threat-intel platforms as separate adapters sharing one cache, budget, provenance, and source-policy contract.
5. **Stronger QA matrix:** every item now has implementation, migration, test, docs, source-policy, observability, idempotency, and provenance checks.
6. **Lower-LLM guardrails:** each item has explicit dependencies, target files, stop conditions, and acceptance criteria.
7. **External API drift protection:** for every vendor integration, verify the current official API docs before coding endpoints, scopes, and request/response fields.

## Composite Implementation Order

Implement in this exact order:

```text
6 -> 18 -> 2 -> 7 -> 17 -> 3 -> 1 -> 8 -> 11 -> 12 -> 15 -> 4 -> 5 -> 10 -> 13 -> 22 -> 16 -> 19 -> 9 -> 14 -> 20 -> 21
```

Order rationale:

- `6` auth and tenant context must exist before multi-tenant routes.
- `18` observability should be in early so later integrations inherit metrics, logs, and traces.
- `2` queue unlocks long-running ingestion, sync, enrichment, and alert delivery.
- `7` search is foundational for entities, digests, UI, and GraphQL.
- `17` webhooks unlock alerting for changes, KEV, enrichment, and digests.
- `15`, `13`, and `22` provide the required enrichment and external platform support.

## Universal Implementation Rules

Apply these rules to every item.

1. **Branch per item:** create `feat/<item-number>-<short-name>`.
2. **One item at a time:** never start an item whose dependencies are missing, broken, or unmerged.
3. **Small commits:** commit each completed item with `feat(#<n>): <item title>`.
4. **Migrations:** every schema change gets a new Alembic revision with both `upgrade()` and `downgrade()`. Never edit an existing revision.
5. **Tenant scoping:** every tenant-owned table must include `tenant_id UUID NOT NULL`, indexes on tenant-filtered lookups, and RLS matching item #6.
6. **Async-first:** all network and worker I/O must be async. Use `httpx.AsyncClient` unless a vendor SDK is required and no async SDK exists.
7. **Bounded concurrency:** use `asyncio.Semaphore` or queue worker limits for fan-out. Never unbounded `gather`.
8. **Configuration:** every new env var goes in `.env.example` and `app/config.py` or the existing settings module.
9. **Secrets:** never log API keys, tokens, client secrets, or auth headers. Mask secrets in logs and traces.
10. **Source policy:** every outbound HTTP target must be represented in `source-policy.yaml` with allowed status, rate limits, and terms status.
11. **Idempotency:** every pull, push, import, export, and enrichment re-run must avoid duplicates.
12. **Provenance:** every claim/entity/source created from an external system must include `external_refs` with provider, external id, URL when safe, fetched timestamp, and raw object hash when possible.
13. **Traceability:** every claim must trace to evidence or an enrichment source record.
14. **OpenAPI:** every new endpoint has tags, summary, description, request model, response model, examples, and documented errors.
15. **MCP:** where agent use is natural, add a thin MCP tool and update `mcp-tool-manifest.json`.
16. **Observability:** every new service emits at least one counter, one duration histogram, structured logs, and spans around external calls.
17. **Docs:** each item gets `docs/<item-number>-<short-name>.md` with overview, config, endpoints, CLI, operations, and QA.
18. **Tests:** add unit tests for all new code and integration tests with mocked external APIs. Coverage for touched modules must not drop.
19. **Validation:** run `ruff check`, `ruff format --check`, `mypy`, and `pytest` before committing. If the repo uses different commands, use the repo's commands and document the substitution.
20. **Stop and ask human if:** a migration risks data loss, a paid credential is required and absent, a dependency is missing, or two items conflict on schema/interface.

## Required External Provider Support

The project must support these providers before the roadmap is considered complete:

| Provider | Required support | Entity kinds | Direction |
| --- | --- | --- | --- |
| VirusTotal | Hash, IP, domain, URL reputation and relationships | `hash`, `ip_address`, `domain`, `url` | Pull enrichment |
| MISP | Pull events/attributes, push reviewed claims/events | IOC kinds, actors, malware, campaigns, galaxies | Bidirectional |
| OpenCTI | Pull/push STIX-like knowledge through GraphQL or `pycti` | indicators, vulnerabilities, actors, malware, reports, relationships | Bidirectional |
| Shodan | Host/service exposure, ports, banners, CVE/exploit lookups | `ip_address`, `domain`, `cve` | Pull enrichment |
| IPinfo.io | Geolocation, ASN, company/privacy/abuse metadata where plan allows | `ip_address`, `asn`, `organization` | Pull enrichment |
| GreyNoise.io | Internet noise, RIOT/business service, scanner classification and tags | `ip_address` | Pull enrichment |
| CrowdStrike | Falcon OAuth2 API integration for indicators, intel, detections/incidents, and optional sandbox results | `hash`, `ip_address`, `domain`, `url`, `actor`, `malware`, `incident` | Pull and optional push |

Provider implementation rules:

- Use a shared provider registry: `app/enrichment/providers/__init__.py` should expose provider names and supported entity kinds.
- Each provider must define typed raw response schemas where practical and a normalized output model.
- Cache all provider responses in a shared `enrichment_cache` table.
- Track usage in `enrichment_usage`.
- Enforce per-provider TTLs, per-minute rates, daily budgets, and monthly budgets.
- Do not auto-enrich all entities. Enrichment happens on request or through explicit trigger rules.
- Convert normalized enrichment into source-backed claims and relationships.
- Store raw responses only if permitted by the provider terms and source policy.
- Tests must mock every provider and verify cache hit, cache miss, rate/budget failure, normalization, provenance, and source-backed claim creation.

## Item 6: Authentication and Authorisation ✅

Goal: API key auth for programmatic clients, JWT auth for analyst UI, tenant context, and database RLS.

Dependencies: none.

Implement:

- `app/auth/api_key.py`: API key hashing, validation, scopes, tenant lookup.
- `app/auth/jwt.py`: login flow, JWT creation and validation.
- `app/auth/dependencies.py`: `get_current_tenant`, `get_current_user`, `require_scope`.
- `app/routers/auth.py`: login and key management endpoints.
- Alembic migration for `tenants`, `api_keys`, `users`, and RLS policies.
- App middleware or DB session hook that sets `SET LOCAL app.tenant_id`.
- Apply auth to all non-public routes.

QA:

- Test valid/invalid API keys.
- Test JWT login and expiration.
- Test scope denial returns 403.
- Test cross-tenant data is invisible under RLS.
- Test health endpoint stays public.

## Item 18: Observability ✅

Goal: structured JSON logs, Prometheus metrics, OpenTelemetry traces, and dashboards.

Dependencies: item 6 for tenant/user context where available.

Implement:

- `app/observability/logging.py` using `structlog`.
- `app/observability/metrics.py` using `prometheus-client`.
- `app/observability/tracing.py` using OpenTelemetry.
- `app/observability/worker.py` decorator for worker jobs.
- `/metrics` endpoint.
- Grafana dashboard in `ops/grafana/security-knowledge.json`.
- Prometheus alerts in `ops/prometheus/alerts.yml`.

QA:

- Test `/metrics` includes HTTP and worker metrics.
- Test logs include `request_id`, `tenant_id` when present, and no secrets.
- Test an external-call span is created with sanitized attributes.
- Test worker job instrumentation records success and failure metrics.

## Item 2: Async Queue-Based Ingestion ✅

Goal: move ingestion to Redis-backed background workers and return `202 Accepted` job IDs.

Dependencies: item 6.

Implement:

- Add `arq`.
- `app/worker.py` with Redis settings and job functions.
- Refactor ingestion routes to enqueue jobs and expose job status.
- Alembic migration adding `error_message`, `started_at`, `completed_at`, `progress_pct`.
- Docker Compose worker service.

QA:

- Test URL and document ingestion return `202`.
- Test job transitions `pending -> running -> completed`.
- Test failures store `error_message`.
- Test tenant scoping for job lookup.

## Item 7: Full-Text and Fuzzy Search ✅

Goal: replace `ILIKE` search with Postgres FTS plus trigram fallback.

Dependencies: item 6.

Implement:

- Migration enabling `pg_trgm`, adding `search_vector` columns, GIN indexes, and triggers.
- `app/services/search.py` with ranked claim/entity search.
- Update search routers to use the service.
- Fuzzy fallback for entity aliases/names.

QA:

- Test ranked search.
- Test typo/fuzzy matching.
- Test query plan uses indexes for seeded data.
- Test tenant isolation in search results.

## Item 17: Outbound Webhooks Framework ✅

Goal: reliable signed outbound webhooks for alerts, approvals, changes, KEV, enrichment, and digests.

Dependencies: items 2, 6, 18.

Implement:

- Tables for `webhook_subscriptions` and `webhook_deliveries`.
- `app/events/bus.py`, `app/events/types.py`, `app/events/filters.py`.
- `app/workers/webhook.py` for delivery retries.
- `app/routers/webhooks.py` CRUD, test-send, delivery list, replay.
- HMAC-SHA256 signatures over raw body.
- Circuit breaker after repeated failures.

QA:

- Test signature verification.
- Test filters.
- Test 2xx success, non-429 4xx permanent failure, 429/5xx retry.
- Test max attempts and circuit breaker.
- Test no secret leakage in logs.

## Item 3: Embedding Generation Pipeline ✅

Goal: real embeddings, cache, batching, and vector search.

Dependencies: items 2 and 18.

Implement:

- `app/embeddings/generator.py` using OpenAI `text-embedding-3-small` or configured equivalent.
- `app/embeddings/search.py` for vector claim/entity search.
- Migration for `embedding_cache` with `VECTOR(1536)` unless config changes dimension.
- Ingestion hook to embed claims and entity descriptions.
- Context pack integration.

QA:

- Mock embeddings provider.
- Test cache hit/miss.
- Test batch splitting and retry on 429.
- Test vector ranking.
- Test context packs include similar claims.

## Item 1: Real LLM Extraction ✅

Goal: replace LLM stubs with provider-backed structured extraction.

Dependencies: items 6 and 18.

Implement:

- `app/llm/schemas.py`: Pydantic schemas for attribution, exploit chains, product normalization, report comparison.
- `app/llm/client.py`: provider abstraction for OpenAI/Anthropic or configured provider.
- `app/llm/prompts/*.j2`: versioned prompts.
- Replace extraction stubs with schema-validated calls.
- `llm_rejection_log` table for invalid outputs.

QA:

- Mock valid and invalid LLM outputs.
- Test invalid output is rejected and never stored as a claim.
- Test token/cost metrics.
- Test retry/backoff behavior.

## Item 8: TAXII/STIX Consumer, NVD, and GitHub Advisory Adapters ✅

Goal: scheduled ingestion from NVD API v2, GitHub Advisories, and TAXII 2.1 collections.

Dependencies: items 2, 6, 7, 18.

Implement:

- `app/integrations/nvd/adapter.py`.
- `app/integrations/github/adapter.py`.
- `app/integrations/taxii/adapter.py`.
- `app/integrations/scheduler.py`.
- Migration for `sync_state`.
- CLI commands: `nvd-sync`, `ghsa-sync`, `taxii-sync`.

QA:

- Mock each API.
- Test incremental sync.
- Test idempotency.
- Test external refs and source records.
- Test source-policy coverage.

## Item 11: EUVD Adapter ✅

Goal: ingest ENISA EUVD vulnerabilities, aliases, products, vendors, EPSS, exploited and critical feeds.

Dependencies: item 8.

Implement:

- `app/integrations/euvd/client.py`.
- `app/integrations/euvd/adapter.py`.
- `app/integrations/euvd/sync.py`.
- `app/cli/euvd_sync.py`.
- Optional MCP tool after core sync is stable.

QA:

- Mock EUVD search, by-id, exploited, critical, and advisory responses.
- Test CVE alias linking to NVD entities.
- Test EPSS storage.
- Test exploited status alert via item 10 when available.

## Item 12: CISA KEV Adapter ✅

Goal: daily sync of CISA Known Exploited Vulnerabilities and alerts for newly listed CVEs.

Dependencies: items 2, 8, 17.

Implement:

- `app/integrations/kev/client.py`.
- `app/integrations/kev/schemas.py`.
- `app/integrations/kev/adapter.py`.
- `app/integrations/kev/sync.py`.
- `app/cli/kev_sync.py`.
- Add CISA to `source-policy.yaml`.

QA:

- Test KEV ingestion creates CVE, vendor, software, CWE relationships, and vulnerability claims.
- Test ETag/Last-Modified caching.
- Test idempotent re-ingestion.
- Test new-entry alert.

## Item 15: Enrichment Framework and Required Providers ✅

Goal: on-demand entity enrichment with shared cache, budget, triggers, API, MCP tool, and provider registry. This item must include VirusTotal, Shodan, IPinfo.io, GreyNoise.io, and CrowdStrike Falcon enrichment. MISP and OpenCTI are handled as platform sync items but must also plug into the same enrichment result model where useful.

Dependencies: items 2, 6, 17, 18.

Implement core framework:

- `app/enrichment/base.py`: abstract provider, result, normalized claim hints, capability metadata.
- `app/enrichment/registry.py`: provider registration and lookup.
- `app/enrichment/service.py`: enrich entity, cache lookup, provider invocation, claim/source creation.
- `app/enrichment/budget.py`: usage tracking and budget enforcement.
- `app/enrichment/triggers.py`: policy rules and queue enqueueing.
- `app/routers/enrichment.py`: enrich, get cached results, budget status.
- `app/mcp/tools/enrich_entity.py`.
- Migration for `enrichment_cache`, `enrichment_usage`, and provider audit rows.
- `enrichment-policy.yaml`.

Implement providers:

- `app/enrichment/providers/virustotal.py`
  - Supports `hash`, `ip_address`, `domain`, `url`.
  - Normalize malicious/suspicious/harmless stats, reputation, tags, relationships, detections, first/last seen.
  - Use `x-apikey`.
- `app/enrichment/providers/shodan.py`
  - Supports `ip_address`, optional `domain`, optional `cve`.
  - Normalize ports, services, banners, hostnames, org, ASN, OS, vulns, tags.
  - Use API key query parameter unless official docs now specify otherwise.
- `app/enrichment/providers/ipinfo.py`
  - Supports `ip_address`.
  - Normalize geo, ASN, company, privacy, abuse contact, hosting/anonymous flags based on account tier.
  - Use `api.ipinfo.io` endpoints for new tiers.
- `app/enrichment/providers/greynoise.py`
  - Supports `ip_address`.
  - Normalize noise, RIOT/business-service flags, classification, trust level, tags, actor/activity metadata.
  - Support community quick lookup and paid context lookup based on config.
- `app/enrichment/providers/crowdstrike.py`
  - Supports `hash`, `ip_address`, `domain`, `url`, and optional `actor`, `malware`, `incident`.
  - Authenticate via Falcon OAuth2 client id/secret and cloud base URL.
  - Prefer FalconPy when it cleanly supports the needed operation; otherwise use signed/raw HTTP through a small client wrapper.
  - Normalize indicator reputation, intel reports, detections/incidents references, sandbox verdicts when licensed, and actor/malware links.

Configuration:

- `VIRUSTOTAL_API_KEY`
- `SHODAN_API_KEY`
- `IPINFO_TOKEN`
- `GREYNOISE_API_KEY`
- `CROWDSTRIKE_CLIENT_ID`
- `CROWDSTRIKE_CLIENT_SECRET`
- `CROWDSTRIKE_BASE_URL`
- Per-provider rate, TTL, daily budget, and monthly budget settings.

QA:

- Unit-test every provider with mocked HTTP or SDK responses.
- Test unsupported entity kind fails cleanly.
- Test cache hit avoids provider calls.
- Test `force=true` bypasses cache but records usage.
- Test budget exhaustion returns 429.
- Test trigger rules enqueue only allowed providers.
- Test provider output creates source-backed claims and relationships.
- Test source-policy entries exist for all provider domains.
- Test all provider secrets are masked in logs/traces.
- Test missing credential disables the provider without breaking registry startup.

## Item 4: BugBountyScanner Integration ✅

Goal: ingest BugBountyScanner output into entities, sources, and claims.

Dependencies: items 2, 6, 7, 18.

Implement:

- `app/integrations/bbs/schemas.py`.
- `app/integrations/bbs/ingest.py`.
- `app/cli/bbs_ingest.py`.
- Parser for subdomains, URLs, ports, technologies, and nuclei findings.
- Dedup by entity name, source URL, and normalized finding key.

QA:

- Fixture with subdomains, URLs, and findings.
- Test created counts.
- Test idempotent re-run.
- Test nuclei severity maps to claim severity.

## Item 5: PyGhidra Security Knowledge Bridge ✅

Goal: extract function names, strings, imports, and IOCs from binaries and ingest them as source-backed entities/claims.

Dependencies: items 2, 6, 15.

Implement:

- `app/integrations/ghidra/bridge.py`.
- `app/integrations/ghidra/ioc_patterns.py`.
- `app/routers/analysis.py` with `POST /analyse/binary`.
- Async job integration.
- Link binary IOCs to enrichment triggers from item 15.

QA:

- Use a tiny fixture binary or mocked PyGhidra output.
- Test IOC extraction.
- Test source provenance.
- Test enrichment trigger handoff.

## Item 10: Change Detection and Alerting ✅

Goal: detect contradictions, status changes, superseded claims, and answer "what changed since yesterday?"

Dependencies: items 2, 3, 17, 18.

Implement:

- `claim_versions` and `changes` tables.
- `app/services/change_detection.py`.
- `app/routers/changes.py`.
- Worker cron job for change detection.
- Webhook events for unresolved changes.

QA:

- Test contradictory claims create a change.
- Test status change severity.
- Test `/changes?since=...`.
- Test webhook event emission.

## Item 13: MISP Bidirectional Sync ✅

Goal: pull MISP events/attributes into the knowledge base and push reviewed claims back as MISP events.

Dependencies: items 6, 10, 17, 18.

Implement:

- `app/integrations/misp/client.py` using `pymisp` or direct REST if async constraints require a wrapper.
- `app/integrations/misp/mapping.py`.
- `app/integrations/misp/inbound.py`.
- `app/integrations/misp/outbound.py`.
- `app/routers/misp.py`.
- Migration adding or extending `external_refs` on claims/entities if not already present.
- Scheduled pull and push jobs.

Required mapping:

- MISP `ip-src` and `ip-dst` -> `ip_address`.
- `domain`, `hostname` -> `domain`.
- `url`, `uri` -> `url`.
- `md5`, `sha1`, `sha256`, `filename|*` -> `hash` plus file metadata.
- `email-src`, `email-dst` -> `email`.
- Galaxies/clusters -> actor, malware, campaign, tool, attack-pattern entities.
- Tags/TLP/confidence -> claim attributes.

QA:

- Mock MISP client.
- Test every supported attribute mapping.
- Test incremental pull.
- Test idempotent push updates the same event UUID.
- Test inbound conflicts create contradiction records instead of overwriting.
- Test source-policy and provenance.

## Item 22: OpenCTI Bidirectional Sync ✅

Goal: integrate with OpenCTI as a first-class threat-intelligence platform using GraphQL or the official Python client. Pull OpenCTI knowledge into this service and optionally push approved internal knowledge back to OpenCTI.

Dependencies: items 6, 8, 10, 15, 17, 18.

Implement:

- `app/integrations/opencti/client.py`.
- `app/integrations/opencti/mapping.py`.
- `app/integrations/opencti/inbound.py`.
- `app/integrations/opencti/outbound.py`.
- `app/routers/opencti.py`.
- `app/cli/opencti_sync.py`.
- Tests in `tests/test_opencti_sync.py`.
- Fixture in `tests/fixtures/opencti_sample.json`.

Configuration:

- `OPENCTI_URL`
- `OPENCTI_TOKEN`
- `OPENCTI_VERIFY_SSL`
- `OPENCTI_SYNC_INTERVAL_SECONDS`
- Optional `OPENCTI_PUSH_ENABLED=false` by default.

Required inbound objects:

- Indicators and observables -> `ip_address`, `domain`, `url`, `hash`, `email`, or `indicator`.
- Vulnerabilities -> `cve`/`vulnerability`.
- Intrusion sets and threat actors -> `actor`.
- Malware/tools -> `malware`/`tool`.
- Reports -> `Source(kind="opencti_report")` plus linked claims.
- Relationships -> internal relationships with confidence/provenance.
- Marking definitions/TLP -> claim/source attributes.

Required outbound objects:

- Approved claims and linked entities can create or update OpenCTI reports, indicators, observables, and relationships.
- Default outbound mode is dry-run unless `OPENCTI_PUSH_ENABLED=true`.
- Store OpenCTI ids in `external_refs`.

QA:

- Mock GraphQL responses or `pycti`.
- Test pagination.
- Test markings/TLP propagation.
- Test idempotent re-sync.
- Test dry-run outbound performs no mutation.
- Test push updates existing OpenCTI objects when `external_refs` exists.
- Test contradictions are created for conflicting inbound facts.
- Test provider appears in enrichment registry as a supplemental context provider for entities with OpenCTI refs.

## Item 16: STIX 2.1 Export and TAXII Server Mode ✅

Goal: publish approved internal knowledge as STIX 2.1 bundles and TAXII 2.1 collections.

Dependencies: items 6, 8, 13, 22.

Implement:

- `app/stix/mapping.py`.
- `app/stix/builder.py`.
- `app/taxii/server.py`.
- `app/routers/stix_export.py`.
- Migration for TAXII collections and STIX object cache.
- `taxii-collections.yaml`.

QA:

- Validate bundles with `stix2` strict mode.
- Test TAXII discovery, collections, objects, manifest, pagination.
- Test collection ACLs.
- Test objects include external references/provenance.

## Item 19: GraphQL API for Relationship Graph ✅

Goal: read-only GraphQL endpoint for efficient graph traversal.

Dependencies: items 6 and 7.

Implement:

- `app/graphql/schema.py`.
- `app/graphql/types.py`.
- `app/graphql/dataloader.py`.
- `app/graphql/extensions.py`.
- Mount `/graphql`.
- Depth and cost limiting.

QA:

- Test introspection.
- Test entity with claims and relationships uses batched loaders.
- Test depth/cost rejection.
- Test tenant isolation.

## Item 9: Analyst Review UI ✅

Goal: HTMX/Jinja analyst dashboard for reviewing claims, resolving conflicts, and verifying entities.

Dependencies: items 6, 7, 10, 15.

Implement:

- `app/ui/routes.py`.
- Templates for base, dashboard, claims, claim detail, entities, graph links, detections, saved searches.
- Static CSS.
- JWT-required UI routes.
- Claim approve/reject/edit.
- Entity merge/dedup.
- Enrichment request button for eligible entities.

QA:

- Test each view returns 200 for authenticated user.
- Test unauthenticated user redirects or 401s.
- Test approve/reject HTMX flow.
- Test entity merge permission checks.

## Item 14: Detection Rule Generation ✅

Goal: generate draft Sigma, YARA, Snort, and Suricata rules from approved IOCs/TTPs.

Dependencies: items 5, 9, 10.

Implement:

- `app/detections/schemas.py`.
- Migration for `detection_rules`.
- Generators for Sigma, YARA, Snort/Suricata.
- Templates under `app/detections/templates/`.
- `app/routers/detections.py`.
- Review UI integration.

QA:

- Test generated rules validate.
- Test only approved rules export.
- Test duplicate IOCs do not create duplicate rules.
- Test source claim IDs appear in rule metadata.

## Item 20: Relationship Graph Visualisation Endpoint ✅

Goal: return graph data for Cytoscape.js, D3, and Gephi.

Dependencies: items 7 and 9.

Implement:

- `app/graph/visualisation.py`.
- `app/graph/formats.py`.
- `app/graph/palette.py`.
- `app/routers/graph.py`.
- UI graph template.
- Redis caching with invalidation.

QA:

- Test BFS depth and kind filters.
- Test Cytoscape schema.
- Test GEXF round trip.
- Test truncation and cache hit.

## Item 21: Saved Searches and Scheduled Digests ✅

Goal: saved searches with scheduled delivery via email, Slack, webhook, and inbox.

Dependencies: items 7, 9, 17.

Implement:

- Tables for saved searches, subscriptions, runs, and inbox items.
- `app/digests/dsl.py`.
- `app/digests/scheduler.py`.
- `app/digests/runner.py`.
- Channel adapters: email, Slack, webhook, inbox.
- Templates.
- `app/routers/saved_searches.py` and `app/routers/digests.py`.
- UI pages for saved searches, digests, inbox.

QA:

- Test DSL parsing and SQL translation.
- Test cron scheduling.
- Test each delivery channel with mocks.
- Test `$since` substitution.
- Test empty digest skip behavior.
- Test tenant quotas.

## Final Roadmap Acceptance Criteria (legacy — DO NOT TRUST ✅ MARKS)

The original file claimed all of the below were verified 2026-05-07. The
README review on the same day contradicts several of them. Re-verify each
against `/api/v1/capabilities` (Item A2) before relying on it.

- All 22 items implemented, tested, documented (claim: 225 files, 85 tests).
- `PLAN.md` and `PLAN-EXTENSIONS.md` do not exist. (verified)
- `TODO.md` is the only roadmap handoff file. (verified)
- All required providers configured. (FALSE: IPinfo, GreyNoise, CrowdStrike
  provider modules are missing; registry not auto-populated.)
- Fresh environment: `make docker-up && make migrate && make seed && make
  test` works. (Re-verify; memory note says local fixes were needed in
  `app/observability/logging.py`, `app/main.py`, `app/ui/routes.py`.)
- Provider QA mocked tests for all required providers. (FALSE for the three
  missing providers above.)
- No external credentials required for test suite. (Plausible; verify.)
- No secrets in logs, traces, fixtures, docs, or committed config. (Verify
  with the secret-grep proposed in Item A5.)


---

## Section G — BUGFIX backlog (added 2026-05-08)

Cross-reference the parity plan at `.copilot/session-state/<id>/plan.md`
section 7 for the full rationale. Summary:

### BUG-1 — Logout button never renders for logged-in users
`templates/base.html` correctly gates the button on `current_user`, but
every UI route in `app/ui/routes.py` and the HTML routes in
`routers/shortcuts.py` pass `current_user: None`. Same bug also hides
the Admin nav. Fix: shared `app.ui.deps.get_current_user_for_template`
that decodes the `sk_session` cookie; thread through every UI route.
Acceptance: GET `/` after login returns HTML containing `>Logout<`.

### BUG-2 — User settings: change password + BYO provider keys
The `user_provider_keys` table, `UserProviderKey` model, and
`app/auth/byok.py` Fernet helpers already exist (alembic 0002). What is
missing:

API:
- `POST /api/v1/auth/change-password` (current + new, bcrypt-verify,
  rotate, invalidate session).
- `GET /api/v1/auth/provider-keys` (list `{provider, key_hint,
  created_at}` — never plaintext).
- `PUT /api/v1/auth/provider-keys/{provider}` (encrypt + upsert).
- `DELETE /api/v1/auth/provider-keys/{provider}`.
- Allowed providers: `virustotal`, `greynoise`, `ipinfo`, `shodan`.

Provider plumbing:
- `EnrichmentService._resolve_provider_key()` checks
  `user_provider_keys` first (decrypt + flag `used_byok=true` in
  `enrichment_usage`), falls back to `settings`.
- VT/Shodan/IPinfo/GreyNoise providers receive the resolved key
  instead of reading `settings` directly.

UI:
- New `templates/settings.html` extending `base.html` with two
  sections: change-password form and per-provider key add/remove rows.
- New `GET /settings` UI route (auth required; redirect to `/login`).
- New "Settings" nav-pill in `base.html` (only when `current_user`).

Acceptance: see plan.md §7 BUG-2.

### BUG-3 — Surface new endpoints in `/api/v1/capabilities`
After BUG-1 and BUG-2, ensure capabilities lists the new routes.

### Execution slot
Run after Section A items (A1-A5) and before Section B per-kind work
(P-K1 et al.) — see plan.md §3 for the updated master order.
