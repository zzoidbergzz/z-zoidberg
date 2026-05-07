# Security Knowledge Service — Extension Plan

Companion to `PLAN.md`. Ten further improvements, all distinct from the original 11.
Same conventions: assume FastAPI app at `security-knowledge/app/`, Postgres + pgvector, Alembic migrations, pytest, arq worker (after PLAN #2), tenant-scoped models (after PLAN #6).

Numbering continues from PLAN.md (which ended at #11).

---

## 12. CISA KEV (Known Exploited Vulnerabilities) Adapter

### Goal
Daily sync of CISA's Known Exploited Vulnerabilities catalog. Cross-link with CVE entities. Trigger high-severity alerts for any new KEV entry that matches a CVE already in the knowledge base.

### Data Source
- URL: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- No auth, no rate limit advertised — be polite (1 request per sync)
- Schema: `{catalogVersion, dateReleased, count, vulnerabilities: [{cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, notes, cwes}]}`

### Steps
1. **Create `app/integrations/kev/client.py`**:
   - `async def fetch_kev_catalog() -> KEVCatalog` using httpx
   - ETag/Last-Modified caching: store last response headers in `sync_state` (reuse table from PLAN #8)
   - Returns parsed Pydantic model
2. **Pydantic schemas** in `app/integrations/kev/schemas.py`:
   - `KEVEntry(cve_id, vendor, product, name, date_added, short_description, required_action, due_date, ransomware_use: bool, notes, cwes: list[str])`
   - `KEVCatalog(catalog_version, date_released, count, vulnerabilities: list[KEVEntry])`
3. **Adapter** in `app/integrations/kev/adapter.py`:
   - `async def ingest_kev_entry(entry: KEVEntry, db)`:
     - Find or create `Entity(kind="cve", name=entry.cve_id)` (link to NVD entity if present)
     - Add/update claim: `Claim(text=entry.short_description, claim_type="vulnerability", attributes={"kev_listed": True, "ransomware_use": entry.ransomware_use, "kev_date_added": entry.date_added, "kev_due_date": entry.due_date, "required_action": entry.required_action})`
     - Vendor → `Entity(kind="vendor")`, product → `Entity(kind="software")`, link via `relationships(affects)`
     - Each CWE → relationship `weakness_class` to a `Entity(kind="cwe")`
4. **Sync orchestrator** in `app/integrations/kev/sync.py`:
   - `async def scheduled_kev_sync()` runs daily via arq (PLAN #2)
   - Diff against previous catalog: entries newly added → emit alert via Change Detection (PLAN #10)
   - Removed entries (rare) → mark claim attribute `kev_listed=False` and log
5. **CLI**: `kev-sync` Click command, supports `--force` to re-ingest entire catalog
6. **Source policy**: add `cisa.gov` to `source-policy.yaml` with `terms_status: allowed`, `allowed: true`
7. **Tests** (`tests/test_kev_adapter.py`):
   - Fixture: minimal KEV JSON (3 entries, one with ransomware flag)
   - Test new-entry ingestion creates expected entities/claims
   - Test re-ingestion is idempotent
   - Test delta detection fires alert when an entry is added between two syncs

### Files
- `app/integrations/kev/__init__.py` (new)
- `app/integrations/kev/client.py` (new)
- `app/integrations/kev/schemas.py` (new)
- `app/integrations/kev/adapter.py` (new)
- `app/integrations/kev/sync.py` (new)
- `app/cli/kev_sync.py` (new)
- `tests/test_kev_adapter.py` (new)
- `tests/fixtures/kev_sample.json` (new)
- `source-policy.yaml` (modify)

---

## 13. MISP Bidirectional Sync

### Goal
Push and pull threat data between Security Knowledge Service and a MISP instance. Inbound: pull events/attributes as entities, claims, and IOCs. Outbound: publish reviewed claims as MISP events.

### Steps
1. **MISP client** in `app/integrations/misp/client.py`:
   - Use `pymisp` library (`pip install pymisp`)
   - Config via env: `MISP_URL`, `MISP_KEY`, `MISP_VERIFY_SSL`
   - Methods: `search_events(filters)`, `get_event(id)`, `add_event(event_dict)`, `add_attribute(event_id, attribute)`, `update_attribute(...)`, `tag_event(...)`
2. **Pull adapter** in `app/integrations/misp/inbound.py`:
   - `async def pull_misp_events(since: datetime)`:
     - Query events updated since timestamp
     - For each event: create `Source(kind="misp_event", external_id=event.uuid)`
     - For each attribute: map to entity by type (`ip-src`/`ip-dst` → `ip_address`, `domain` → `domain`, `md5`/`sha1`/`sha256` → `hash`, `url` → `url`, `email-src` → `email`, etc.)
     - Build a mapping table `MISP_ATTR_TYPE_TO_ENTITY_KIND` in `app/integrations/misp/mapping.py`
     - Event tags → claim attributes; TLP tag → `claims.tlp` field
     - Galaxy clusters (threat actor, malware) → entities with relationships
3. **Push adapter** in `app/integrations/misp/outbound.py`:
   - `async def publish_claim_as_misp_event(claim_id)`:
     - Only published reviewed claims (status=approved, from PLAN #9)
     - Create MISP event: `info=claim.text`, `distribution=0` (org only by default), `analysis=2` (completed)
     - Linked entities → MISP attributes
     - Add tags: `source:security-knowledge-service`, `tlp:<claim.tlp>`, `confidence:<claim.confidence>`
     - Store returned MISP event UUID on the claim: `claim.external_refs["misp_event_uuid"]`
4. **Idempotency**:
   - Track `external_refs` JSONB on entities and claims for `misp_attribute_uuid` / `misp_event_uuid`
   - On re-push: update existing MISP event instead of creating new
   - Add migration for `external_refs JSONB DEFAULT '{}'` on entities and claims
5. **Sync state**: reuse `sync_state` table with `source_name='misp_inbound'`, store `last_synced_at`
6. **Scheduled jobs** (arq):
   - `misp_pull_sync` every 30 minutes
   - `misp_push_sync` every 5 minutes (drains a queue of approved claims awaiting publish)
7. **Conflict handling**:
   - If MISP attribute exists locally with different value, do NOT overwrite — create a contradiction record (feed into PLAN #10)
8. **API endpoints** in `app/routers/misp.py`:
   - `POST /api/v1/misp/sync/pull` — manual trigger
   - `POST /api/v1/misp/sync/push/{claim_id}` — manual publish
   - `GET /api/v1/misp/status` — last sync times, queue depth
9. **Tests** (`tests/test_misp_sync.py`):
   - Mock `pymisp.PyMISP` class
   - Test attribute → entity mapping for every supported type
   - Test idempotent push (second push updates same event UUID)
   - Test pull is incremental
   - Test contradiction creation on conflicting inbound attribute

### Files
- `app/integrations/misp/__init__.py` (new)
- `app/integrations/misp/client.py` (new)
- `app/integrations/misp/mapping.py` (new)
- `app/integrations/misp/inbound.py` (new)
- `app/integrations/misp/outbound.py` (new)
- `app/routers/misp.py` (new)
- `alembic/versions/xxx_add_external_refs.py` (new)
- `tests/test_misp_sync.py` (new)
- `requirements.txt` (modify — add `pymisp`)

---

## 14. Detection Rule Generation (Sigma / YARA / Snort)

### Goal
Auto-generate draft detection rules from extracted IOCs and TTPs. Output is human-reviewable, never auto-deployed. Each rule traces back to source claims.

### Steps
1. **Schema** in `app/detections/schemas.py`:
   - `DetectionRule(id, format: Literal["sigma","yara","snort","suricata"], title, description, rule_text, source_claim_ids: list[UUID], generated_at, status: Literal["draft","reviewed","approved","rejected"], reviewer, attack_techniques: list[str])`
2. **Migration**: `detection_rules` table with above fields + indices on `format` and `status`
3. **Generators** in `app/detections/generators/`:
   - `sigma.py`: input = list of behavioural claims with ATT&CK techniques + log sources; output = Sigma YAML
     - Use the `sigma-cli` or build templates manually with Jinja2 (`app/detections/templates/sigma_*.j2`)
     - Map ATT&CK technique → Sigma `logsource` (e.g., `T1059.001` → `product: windows, category: process_creation`)
   - `yara.py`: input = list of `hash`/`mutex`/`string` entities + binary-derived strings (PLAN #5); output = YARA rule
     - Combine string anchors with `condition: any of them` or `2 of them` based on count
     - Include `meta:` block with author, date, source claim IDs
   - `snort.py` / `suricata.py`: input = network IOC entities (IPs, domains, URLs, JA3 hashes); output = Snort/Suricata rule
     - One rule per IOC initially; group later
4. **Trigger paths**:
   - On-demand API: `POST /api/v1/detections/generate { entity_id?, claim_ids?, format }`
   - Scheduled: nightly job scans new approved claims → generates draft rules → status=`draft`
5. **Validation**:
   - Sigma: run through `sigma-cli check` (subprocess) to catch syntax errors before storing
   - YARA: compile via `yara-python` library to validate
   - Snort/Suricata: regex-based syntax check, mark suspicious
   - On validation failure → store with `status=rejected`, `error_message`
6. **Review UI** (extends PLAN #9):
   - `/ui/detections` — list draft rules; per rule: view rule text, source claims, [Approve] [Reject] [Edit]
   - Approval workflow updates status; export endpoint serves only approved rules
7. **Export endpoints** in `app/routers/detections.py`:
   - `GET /api/v1/detections?format=sigma&status=approved` — JSON list
   - `GET /api/v1/detections/bundle?format=sigma` — single concatenated bundle (Sigma rule pack, YARA `.yar`, Snort `.rules`)
8. **Tests** (`tests/test_detection_generation.py`):
   - Fixture claims for each format → assert generated rule passes validator
   - Test that approved rules appear in export; drafts do not
   - Test deduplication: same IOC twice → one rule

### Files
- `app/detections/__init__.py` (new)
- `app/detections/schemas.py` (new)
- `app/detections/generators/sigma.py` (new)
- `app/detections/generators/yara.py` (new)
- `app/detections/generators/snort.py` (new)
- `app/detections/templates/*.j2` (new)
- `app/routers/detections.py` (new)
- `alembic/versions/xxx_add_detection_rules.py` (new)
- `tests/test_detection_generation.py` (new)
- `requirements.txt` (modify — add `yara-python`, optionally `sigma-cli`)

---

## 15. On-Demand Entity Enrichment (VirusTotal / Shodan / AbuseIPDB)

### Goal
Enrich entities (IPs, domains, hashes) on demand from public reputation services. Cache aggressively. Strict per-provider rate + cost budget. Never auto-enrich every entity — only on user/agent request, or when an entity crosses a configured trigger (e.g., appears in a high-severity claim).

### Steps
1. **Provider abstraction** in `app/enrichment/base.py`:
   - `class EnrichmentProvider(ABC)` with `name`, `supported_kinds: set[str]`, `async lookup(entity) -> EnrichmentResult`
   - `EnrichmentResult(provider, entity_id, fetched_at, raw, normalised: dict, cost_units: int)`
2. **Implementations** in `app/enrichment/providers/`:
   - `virustotal.py`: `/files/{hash}`, `/ip_addresses/{ip}`, `/domains/{domain}`, `/urls/{url_id}`. Auth: `x-apikey` header.
   - `shodan.py`: `/shodan/host/{ip}`. Auth: `?key=`.
   - `abuseipdb.py`: `/api/v2/check?ipAddress=...`. Auth: `Key:` header.
   - Each respects provider rate limits (token bucket per provider)
3. **Cache table** (migration):
   - `enrichment_cache(provider TEXT, entity_kind TEXT, entity_key TEXT, result JSONB, fetched_at TIMESTAMPTZ, ttl_seconds INT, PRIMARY KEY (provider, entity_kind, entity_key))`
   - Default TTLs: VT=24h, Shodan=12h, AbuseIPDB=6h, configurable per env
4. **Service** in `app/enrichment/service.py`:
   - `async def enrich(entity_id, providers: list[str] | None = None, force: bool = False)`:
     - For each provider: check cache → return if fresh → else call provider → store
     - Convert normalised result into claims (e.g., AbuseIPDB confidence → `Claim(text="IP X has abuse confidence 89/100", attributes={"abuseipdb_score": 89})`)
     - Always record `Source(kind="enrichment", url=provider_endpoint)` and link claim → source for traceability
5. **Budget enforcement** in `app/enrichment/budget.py`:
   - Per-provider config: `daily_call_budget`, `monthly_call_budget`, `per_minute_rate`
   - Track usage in `enrichment_usage(provider, day, calls)` table
   - On budget exhaustion: raise `BudgetExceeded` → API returns 429 with detail
6. **Trigger rules** in `app/enrichment/triggers.py`:
   - Configurable rules: e.g., `if claim.severity >= 8.0 and entity.kind in {"ip_address","domain"} → enqueue enrichment`
   - Rules defined in `enrichment-policy.yaml`
   - Enqueued via arq (PLAN #2)
7. **API endpoints** in `app/routers/enrichment.py`:
   - `POST /api/v1/enrichment/{entity_id}` (body: providers, force)
   - `GET /api/v1/enrichment/{entity_id}` (returns cached + fresh)
   - `GET /api/v1/enrichment/budget` (current usage vs limits)
8. **MCP tool** in `app/mcp/tools/enrich_entity.py`: agents can request enrichment respecting budget
9. **Tests** (`tests/test_enrichment.py`):
   - Mock each provider's HTTP responses
   - Test cache hit avoids HTTP call
   - Test budget exhaustion → 429
   - Test trigger rule enqueues job

### Files
- `app/enrichment/__init__.py` (new)
- `app/enrichment/base.py` (new)
- `app/enrichment/providers/{virustotal,shodan,abuseipdb}.py` (new)
- `app/enrichment/service.py` (new)
- `app/enrichment/budget.py` (new)
- `app/enrichment/triggers.py` (new)
- `app/routers/enrichment.py` (new)
- `app/mcp/tools/enrich_entity.py` (new)
- `alembic/versions/xxx_add_enrichment_tables.py` (new)
- `enrichment-policy.yaml` (new)
- `tests/test_enrichment.py` (new)

---

## 16. STIX 2.1 Export & TAXII Server Mode

### Goal
Become a STIX 2.1 publisher. Expose internal entities/claims/relationships as STIX SDOs/SROs and serve them via a TAXII 2.1-compliant collection. Enables sharing reviewed intel with peers / SOCs / SIEMs. Complements PLAN #8 (TAXII consumer).

### Steps
1. **STIX mapping** in `app/stix/mapping.py`:
   - Map our entity kinds → STIX SDOs:
     - `cve`/`vulnerability` → `vulnerability`
     - `actor` → `threat-actor`
     - `malware` → `malware`
     - `ip_address`/`domain`/`url`/`hash` → `indicator` with `pattern`
     - `product`/`software` → `software`
     - `attack_pattern` → `attack-pattern`
     - `campaign` → `campaign`
   - Map our relationships → STIX SROs (`relationship` SDOs)
   - Use `stix2` Python library (`pip install stix2`) for serialisation + validation
2. **Builder** in `app/stix/builder.py`:
   - `def build_stix_bundle(entity_ids: list[UUID]) -> stix2.Bundle`
   - For each entity: convert + include linked claims as `external_references` and STIX `description`
   - Stable STIX IDs: derive from internal UUID via deterministic hash to allow re-export to produce same IDs
   - Set `created_by_ref` to a single Identity SDO representing this service
3. **TAXII server** in `app/taxii/server.py`:
   - Implement TAXII 2.1 endpoints under `/taxii2/`:
     - `GET /taxii2/` — discovery
     - `GET /taxii2/{api_root}/` — API root info
     - `GET /taxii2/{api_root}/collections/` — list collections
     - `GET /taxii2/{api_root}/collections/{id}/` — collection metadata
     - `GET /taxii2/{api_root}/collections/{id}/objects/` — paginated objects (supports filters: `added_after`, `match[type]`, `match[id]`)
     - `GET /taxii2/{api_root}/collections/{id}/objects/{stix_id}/` — single object
     - `GET /taxii2/{api_root}/collections/{id}/manifest/` — object manifest
   - Content types: `application/taxii+json;version=2.1`
4. **Collections** (configurable):
   - `all-approved` — every entity/claim with status=approved
   - `iocs-only` — indicators only
   - `vulnerabilities` — CVE + advisory entities only
   - Defined in `taxii-collections.yaml`; stored in `taxii_collections` table
5. **Auth**: TAXII server reuses API key auth from PLAN #6; per-collection ACL via key scopes
6. **Pagination**: cursor-based using `Range` header per TAXII spec; cursor encodes `(stix_id, modified)` tuple
7. **Caching**: cache built STIX objects in `stix_object_cache(stix_id, modified_at, json JSONB)`; rebuild on entity update via DB trigger or after-write hook
8. **One-shot export endpoint** in `app/routers/stix_export.py`:
   - `POST /api/v1/export/stix { entity_ids?, collection?, since? }` returns a downloadable bundle (`Content-Disposition: attachment`)
9. **Tests** (`tests/test_stix_export.py` + `tests/test_taxii_server.py`):
   - Validate every produced object against `stix2` strict mode
   - Test discovery → collections → objects flow against `taxii2-client`
   - Test pagination cursor stability
   - Test ACL: key without scope cannot read collection

### Files
- `app/stix/__init__.py` (new)
- `app/stix/mapping.py` (new)
- `app/stix/builder.py` (new)
- `app/taxii/server.py` (new)
- `app/routers/stix_export.py` (new)
- `alembic/versions/xxx_add_taxii_collections_cache.py` (new)
- `taxii-collections.yaml` (new)
- `tests/test_stix_export.py` (new)
- `tests/test_taxii_server.py` (new)
- `requirements.txt` (modify — add `stix2`, `taxii2-client` for tests)

---

## 17. Outbound Webhooks Framework

### Goal
Generic, reliable, signed outbound webhook system. Subscribers register URLs + event filters; the service POSTs JSON payloads with HMAC signatures, retries on failure, and tracks delivery state. Used by alerts (PLAN #10), claim approval (PLAN #9), KEV adds (#12), enrichment completions (#15).

### Steps
1. **Tables** (migration):
   - `webhook_subscriptions(id, tenant_id, url, secret, event_types text[], filters JSONB, active bool, created_at)`
   - `webhook_deliveries(id, subscription_id, event_id, payload JSONB, attempt INT, status TEXT, response_status INT, response_body TEXT, scheduled_at, delivered_at, next_retry_at, error_message)`
2. **Event bus** in `app/events/bus.py`:
   - `async def emit(event_type: str, payload: dict, tenant_id: UUID)`:
     - Look up matching subscriptions (event_type in subscription.event_types AND filters match payload)
     - Insert row in `webhook_deliveries` with status=`pending`
     - Enqueue arq job `deliver_webhook(delivery_id)`
3. **Event types catalog** in `app/events/types.py`:
   - `claim.created`, `claim.updated`, `claim.approved`, `claim.rejected`
   - `entity.created`, `entity.merged`
   - `change.detected` (contradiction/status change from PLAN #10)
   - `kev.added`, `kev.removed`
   - `enrichment.completed`
   - `vulnerability.exploited` (transitions to exploited)
   - Each documented in `docs/webhook-events.md`
4. **Delivery worker** in `app/workers/webhook.py`:
   - `async def deliver_webhook(delivery_id)`:
     - Build payload: `{event_type, event_id, occurred_at, tenant_id, data: {...}}`
     - Compute HMAC-SHA256: `signature = HMAC(subscription.secret, raw_body)`
     - Headers: `X-Webhook-Event`, `X-Webhook-Delivery`, `X-Webhook-Signature: sha256=<hex>`, `X-Webhook-Timestamp`
     - POST with 10s timeout
     - On 2xx → status=`delivered`
     - On 4xx (non-429) → status=`failed_permanent` (do not retry)
     - On 429/5xx/timeout/network → schedule retry with exponential backoff (30s, 2m, 10m, 1h, 6h; max 5 attempts)
5. **Replay protection guidance**: payload includes `event_id` (UUIDv4) and `occurred_at` so receivers can dedupe
6. **API endpoints** in `app/routers/webhooks.py`:
   - `POST /api/v1/webhooks` — create subscription (returns `secret` once)
   - `GET /api/v1/webhooks` — list
   - `PATCH /api/v1/webhooks/{id}` — update (filters, active)
   - `DELETE /api/v1/webhooks/{id}`
   - `GET /api/v1/webhooks/{id}/deliveries` — recent attempts
   - `POST /api/v1/webhooks/{id}/deliveries/{delivery_id}/replay` — manual retry
   - `POST /api/v1/webhooks/{id}/test` — sends a synthetic `webhook.test` event
7. **Filter language**: simple JSONPath-ish — `{"severity": {"$gte": 8}, "claim_type": "vulnerability"}`. Parse with a small evaluator in `app/events/filters.py`
8. **Per-subscription concurrency cap** to protect slow receivers; circuit breaker after N consecutive failures (auto-disable + email tenant admin via PLAN #6 user record)
9. **Tests** (`tests/test_webhooks.py`):
   - Test signature is verifiable
   - Test retry schedule (mock time)
   - Test filters match/non-match
   - Test 4xx no retry, 5xx retries
   - Test circuit breaker disables subscription after N failures

### Files
- `app/events/__init__.py` (new)
- `app/events/bus.py` (new)
- `app/events/types.py` (new)
- `app/events/filters.py` (new)
- `app/workers/webhook.py` (new)
- `app/routers/webhooks.py` (new)
- `alembic/versions/xxx_add_webhooks.py` (new)
- `docs/webhook-events.md` (new)
- `tests/test_webhooks.py` (new)

---

## 18. Observability: Prometheus Metrics + OpenTelemetry Tracing + Structured Logging

### Goal
Full observability stack. Every request, worker job, LLM call, DB query, and external API call is traced and counted. Logs are structured JSON with correlation IDs. A Grafana dashboard ships with the repo.

### Steps
1. **Structured logging** in `app/observability/logging.py`:
   - Use `structlog` (`pip install structlog`)
   - Bind context: `request_id`, `tenant_id`, `user_id`, `route`
   - Output JSON to stdout
   - Replace all `logging.getLogger(__name__)` calls with `structlog.get_logger()`
   - FastAPI middleware injects `request_id` (generate UUIDv4 if not in `X-Request-ID` header)
2. **Prometheus metrics** in `app/observability/metrics.py`:
   - Use `prometheus-client` (`pip install prometheus-client`)
   - Counters: `http_requests_total{method,route,status}`, `ingestion_jobs_total{status}`, `llm_calls_total{provider,model,status}`, `extractor_runs_total{extractor,status}`, `webhook_deliveries_total{status}`, `claims_created_total{claim_type}`, `enrichment_calls_total{provider,cache_hit}`
   - Histograms: `http_request_duration_seconds{method,route}`, `llm_call_duration_seconds{provider,model}`, `db_query_duration_seconds{operation}`, `extraction_duration_seconds{extractor}`
   - Gauges: `ingestion_queue_depth`, `webhook_pending_deliveries`, `llm_token_budget_remaining{provider}`
   - Expose `/metrics` endpoint (no auth; restrict via reverse proxy)
3. **OpenTelemetry tracing** in `app/observability/tracing.py`:
   - Use `opentelemetry-distro` + `opentelemetry-instrumentation-fastapi/sqlalchemy/httpx/redis`
   - OTLP exporter, endpoint via `OTEL_EXPORTER_OTLP_ENDPOINT`
   - Resource attributes: `service.name=security-knowledge-service`, `service.version=<from pyproject>`
   - Auto-instrument FastAPI, SQLAlchemy, httpx, redis (arq)
   - Manual spans for: extractor runs, LLM calls, embedding generation, contradiction detection, STIX building
   - Inject `traceparent` into outbound webhooks (PLAN #17)
4. **Initialise** in `app/main.py` (call before app instantiation):
   - `setup_logging()` → `setup_metrics()` → `setup_tracing()`
   - All env-gated; default-on in dev, controllable in prod
5. **Worker (arq) instrumentation**:
   - Wrap every job function with a decorator that creates a span + records metrics + binds log context
   - `app/observability/worker.py: instrument_job(func)`
6. **Sampling**: head-based sampler at 100% in dev, parent-based with 10% root sampling in prod (env config)
7. **Grafana dashboard** in `ops/grafana/security-knowledge.json`:
   - Panels: request rate by route, p50/p95/p99 latency, error rate, ingestion queue depth, LLM call volume + cost, extractor success rates, webhook delivery success rate, KEV/NVD/EUVD sync freshness
8. **Alerts** in `ops/prometheus/alerts.yml`:
   - `IngestionQueueBacklog` (depth > 1000 for 10m)
   - `LLMErrorRateHigh` (>10% over 15m)
   - `WebhookDeliveryFailing` (>50% failures over 30m)
   - `SyncStale` (NVD/EUVD/KEV last_sync > 26h)
9. **Tests** (`tests/test_observability.py`):
   - Test `/metrics` returns expected metric names
   - Test request adds `request_id` to logs (caplog)
   - Test span is created for an LLM call (use OTel in-memory exporter)

### Files
- `app/observability/__init__.py` (new)
- `app/observability/logging.py` (new)
- `app/observability/metrics.py` (new)
- `app/observability/tracing.py` (new)
- `app/observability/worker.py` (new)
- `app/main.py` (modify)
- `app/worker.py` (modify — apply `instrument_job`)
- `ops/grafana/security-knowledge.json` (new)
- `ops/prometheus/alerts.yml` (new)
- `tests/test_observability.py` (new)
- `requirements.txt` (modify — add `structlog`, `prometheus-client`, `opentelemetry-distro`, `opentelemetry-exporter-otlp`, `opentelemetry-instrumentation-{fastapi,sqlalchemy,httpx,redis}`)

---

## 19. GraphQL API for Relationship Graph

### Goal
Add a read-only GraphQL endpoint optimised for traversing the entity-claim-relationship graph. Avoids N+1 round trips that REST imposes for graph queries. Powered by Strawberry (`pip install strawberry-graphql[fastapi]`). Existing REST API remains primary.

### Steps
1. **Schema** in `app/graphql/schema.py`:
   - Types mirror SQLAlchemy models: `Entity`, `Claim`, `Source`, `Relationship`, `Vulnerability`, `Evidence`
   - Each type exposes related collections as resolvers (e.g., `Entity.claims`, `Entity.relationships`, `Entity.related_entities(depth, kinds)`)
   - Pagination: Relay-style connections (`edges`, `pageInfo`)
   - Filtering: per-field `where` arguments using a small filter DSL (e.g., `{ kind: { eq: "cve" }, severity: { gte: 7.0 } }`)
2. **Queries**:
   - `entity(id)`, `entities(where, first, after)`
   - `claim(id)`, `claims(where, first, after)`
   - `vulnerability(cve_id)`
   - `searchEntities(q, first)` — uses FTS from PLAN #7
   - `relationshipPath(from_id, to_id, max_depth)` — BFS over relationships, returns paths
2. **DataLoader** in `app/graphql/dataloader.py`:
   - Use `strawberry.dataloader.DataLoader` for batched loading per request
   - Loaders: `entity_by_id`, `claims_by_entity_id`, `relationships_by_entity_id`, `sources_by_claim_id`
   - Avoids N+1 across nested resolvers
3. **Auth**: reuse PLAN #6 dependencies; inject tenant_id into context; every resolver scopes by tenant
4. **Depth & cost limiting**:
   - Use `strawberry.extensions.QueryDepthLimiter(max_depth=8)`
   - Custom cost extension: each field has a cost; total query cost ≤ 1000; `relationshipPath` costs `5 * max_depth`
5. **Mounting** in `app/main.py`:
   - `from strawberry.fastapi import GraphQLRouter`
   - `graphql_app = GraphQLRouter(schema, context_getter=get_graphql_context)`
   - `app.include_router(graphql_app, prefix="/graphql")`
   - Disable GraphiQL in prod (env flag)
6. **Performance**:
   - Add DB indexes on FK columns used by loaders (most should already exist)
   - Add EXPLAIN ANALYZE test on `relationshipPath` with a sample 10k-node graph
7. **Tests** (`tests/test_graphql.py`):
   - Schema introspection test
   - Query: fetch entity with claims and relationships in one call → assert <= 4 SQL statements (counting via SQLAlchemy event listeners)
   - Test depth limit rejection
   - Test cost limit rejection
   - Test tenant isolation
   - Test `relationshipPath` returns correct shortest paths

### Files
- `app/graphql/__init__.py` (new)
- `app/graphql/schema.py` (new)
- `app/graphql/types.py` (new)
- `app/graphql/dataloader.py` (new)
- `app/graphql/extensions.py` (new — cost limiter)
- `app/main.py` (modify — mount router)
- `tests/test_graphql.py` (new)
- `requirements.txt` (modify — add `strawberry-graphql[fastapi]`)

---

## 20. Relationship Graph Visualisation Endpoint

### Goal
Return graph data in formats consumable by Cytoscape.js, D3, and Gephi. Powers the analyst UI (PLAN #9) graph view and lets external tools render the knowledge graph. Includes layout hints, node clustering, and edge bundling metadata.

### Steps
1. **Service** in `app/graph/visualisation.py`:
   - `def build_subgraph(seed_entity_ids: list[UUID], depth: int = 2, kinds: set[str] | None = None, max_nodes: int = 500)`:
     - BFS from seeds up to `depth`; respect `kinds` filter; cap at `max_nodes` (degree-prioritised when truncating)
     - Returns `Subgraph(nodes, edges, stats)`
2. **Format adapters** in `app/graph/formats.py`:
   - `to_cytoscape(subgraph)` → `{elements: {nodes: [{data: {id, label, kind, severity}}], edges: [{data: {id, source, target, kind, weight}}]}}`
   - `to_d3(subgraph)` → `{nodes: [...], links: [...]}`
   - `to_gexf(subgraph)` → GEXF XML for Gephi (use `networkx.write_gexf`)
3. **Visual attributes** computed per node:
   - `size`: log of degree (cap min/max)
   - `colour`: by `kind` (palette in `app/graph/palette.py`)
   - `shape`: e.g., diamond=actor, hexagon=vulnerability, ellipse=indicator
   - `label`: entity name truncated to 30 chars
4. **Visual attributes per edge**:
   - `weight`: relationship confidence
   - `colour`: by relationship kind (consistent palette)
   - `dashed`: true if relationship status=`tentative`
5. **Clustering** (optional):
   - Run a community detection algorithm (`networkx.algorithms.community.greedy_modularity_communities`) on the subgraph
   - Annotate each node with `cluster_id`
6. **Endpoints** in `app/routers/graph.py`:
   - `GET /api/v1/graph/subgraph?entity_ids=...&depth=2&format=cytoscape&max_nodes=500`
   - `GET /api/v1/graph/entity/{id}?depth=1&format=cytoscape` (convenience for single seed)
   - `GET /api/v1/graph/export.gexf?entity_ids=...` returns GEXF download
   - `GET /api/v1/graph/legend?format=cytoscape` returns kind→colour/shape legend
7. **Caching**:
   - Cache subgraph responses in Redis with key = hash(seeds, depth, kinds, max_nodes), TTL=5m
   - Invalidate on entity/relationship write (publish to Redis pub/sub channel `graph:invalidate`)
8. **UI integration** (extends PLAN #9):
   - `/ui/entities/{id}/graph` — Cytoscape.js page (CDN), fetches `format=cytoscape`, renders with `cose-bilkent` layout
   - Click node → navigates to entity detail; double-click expands neighbours via additional API call
9. **Performance guard**:
   - If requested subgraph would exceed `max_nodes`, return 200 with truncated graph + `truncated: true` and `total_reachable: N` in stats
   - If query time exceeds 5s, abort with 503 + suggestion to lower depth
10. **Tests** (`tests/test_graph_visualisation.py`):
    - Build a fixture graph (10 entities, varied relationships)
    - Test BFS expansion respects depth + kinds
    - Test Cytoscape output structure validates against schema
    - Test GEXF round-trips through `networkx.read_gexf`
    - Test truncation when max_nodes is small
    - Test cache hit on repeated request

### Files
- `app/graph/__init__.py` (new)
- `app/graph/visualisation.py` (new)
- `app/graph/formats.py` (new)
- `app/graph/palette.py` (new)
- `app/routers/graph.py` (new)
- `app/ui/templates/entity_graph.html` (new — depends on PLAN #9)
- `tests/test_graph_visualisation.py` (new)
- `requirements.txt` (modify — add `networkx`)

---

## 21. Saved Searches & Scheduled Digests

### Goal
Users save searches (entities, claims, vulnerabilities) with filters. The system runs them on a schedule (cron-style) and delivers digests via email, Slack, webhook (PLAN #17), or in-app inbox. Examples: "weekly: all new RCEs in vendor=Cisco with CVSS≥8", "daily: any new exploited vuln affecting our software inventory", "hourly: new claims contradicting approved ones".

### Steps
1. **Tables** (migration):
   - `saved_searches(id, tenant_id, user_id, name, description, query JSONB, kind TEXT, created_at, updated_at)` — `query` is a structured DSL (not SQL); `kind` ∈ {`entity`, `claim`, `vulnerability`, `change`}
   - `digest_subscriptions(id, saved_search_id, schedule TEXT, channel TEXT, channel_config JSONB, last_run_at, next_run_at, active bool)` — `schedule` is cron (e.g., `0 9 * * MON`); `channel` ∈ {`email`, `slack`, `webhook`, `inbox`}
   - `digest_runs(id, digest_subscription_id, started_at, completed_at, items_count, status, error_message, payload_summary JSONB)`
   - `inbox_items(id, user_id, digest_run_id, title, body, read bool, created_at)`
2. **Search DSL** in `app/digests/dsl.py`:
   - Parser for a small JSON DSL: `{kind: "vulnerability", filters: {severity: {gte: 8}, vendor: "Cisco", since: "$since"}, sort: "severity desc", limit: 50}`
   - `$since` placeholder substituted at run time with `last_run_at` (or `now - interval` on first run)
   - Translate to SQL via SQLAlchemy core, scoped by tenant
3. **Scheduler** in `app/digests/scheduler.py`:
   - arq cron job (every minute) scans `digest_subscriptions WHERE active AND next_run_at <= now()`
   - For each due subscription: enqueue `run_digest(subscription_id)`
   - Use `croniter` to compute `next_run_at` after a run completes
4. **Runner** in `app/digests/runner.py`:
   - `async def run_digest(subscription_id)`:
     - Load search; execute query; collect items
     - If items empty AND `subscription.send_empty=False` → mark complete, skip delivery
     - Render via channel adapter; record `digest_runs` + `payload_summary` (counts, top items)
5. **Channel adapters** in `app/digests/channels/`:
   - `email.py` — SMTP via `aiosmtplib`; HTML template per `kind`
   - `slack.py` — incoming webhook; Block Kit message
   - `webhook.py` — emits `digest.delivered` event into PLAN #17 bus (which handles HMAC, retries)
   - `inbox.py` — inserts row into `inbox_items`
   - All adapters take a `DigestPayload` dataclass and produce a delivery
6. **Templates** in `app/digests/templates/`:
   - Jinja2 templates per `kind` × `channel`
   - Includes deep links back to UI (PLAN #9): `https://<host>/ui/entities/{id}` etc.
7. **API endpoints** in `app/routers/saved_searches.py` and `app/routers/digests.py`:
   - `POST /api/v1/saved-searches`, `GET`, `PATCH`, `DELETE`
   - `POST /api/v1/saved-searches/{id}/preview` — runs search now, returns up to 20 items (no delivery)
   - `POST /api/v1/digests` (link saved search + schedule + channel)
   - `GET /api/v1/digests/{id}/runs` — history
   - `POST /api/v1/digests/{id}/run-now` — manual trigger
   - `GET /api/v1/inbox?unread=true` — user's inbox
   - `POST /api/v1/inbox/{id}/read`
8. **UI integration** (PLAN #9):
   - `/ui/saved-searches` — list / create / edit (form with builder, not raw JSON; preview button)
   - `/ui/digests` — manage schedules
   - `/ui/inbox` — read in-app digests
9. **Quotas**:
   - Per-tenant cap on saved searches (default 100) and active subscriptions (default 50)
   - Per-subscription cap: digests skipped if items >5000 (truncate + warn)
10. **Tests** (`tests/test_digests.py`):
    - Test DSL parsing + SQL translation
    - Test cron scheduling computes correct `next_run_at`
    - Test each channel adapter (mocked SMTP, mocked Slack webhook, captured event for webhook channel)
    - Test `$since` placeholder uses `last_run_at`
    - Test empty digest is skipped when `send_empty=False`
    - Test quota enforcement

### Files
- `app/digests/__init__.py` (new)
- `app/digests/dsl.py` (new)
- `app/digests/scheduler.py` (new)
- `app/digests/runner.py` (new)
- `app/digests/channels/{email,slack,webhook,inbox}.py` (new)
- `app/digests/templates/*.j2` (new)
- `app/routers/saved_searches.py` (new)
- `app/routers/digests.py` (new)
- `alembic/versions/xxx_add_saved_searches_digests.py` (new)
- `app/ui/templates/{saved_searches,digests,inbox}.html` (new — depends on PLAN #9)
- `tests/test_digests.py` (new)
- `requirements.txt` (modify — add `aiosmtplib`, `croniter`)

---

## Cross-Cutting Implementation Rules (apply to all 12–21)

A downstream LLM must follow these for every item above:

1. **Branch per item**: `feat/<item-number>-<short-name>` (e.g., `feat/12-cisa-kev`).
2. **Migrations**: every schema change is a new Alembic revision with both `upgrade()` and `downgrade()`. Never edit an existing revision.
3. **Tenant scoping**: every new table that holds tenant-owned data MUST include `tenant_id UUID NOT NULL` and an RLS policy mirroring PLAN #6.
4. **Async-first**: use `async def` for all I/O; use `httpx.AsyncClient` (not `requests`); use `asyncio.gather` only with bounded concurrency (`asyncio.Semaphore`).
5. **Config**: every new env var is documented in `.env.example` with a sensible default and added to `app/config.py` (`pydantic-settings`).
6. **Secrets**: never log secrets; mask provider keys in tracing/logs (use `structlog` processor).
7. **Tests**: new code requires unit tests; coverage for the touched module must not drop. Use pytest fixtures already present in `tests/conftest.py`.
8. **Docs**: each item gets a `docs/<item-number>-<name>.md` page with: overview, config, endpoints (curl examples), operational notes.
9. **OpenAPI**: every new endpoint must have a `summary`, `description`, response model, and example. The `/docs` route stays organised via tags.
10. **Linting**: `ruff check`, `ruff format`, and `mypy --strict` (where strict is already enabled) must pass before merge.
11. **Source policy**: any new outbound HTTP target (CISA, MISP, VirusTotal, Shodan, AbuseIPDB, EUVD already done, etc.) must be added to `source-policy.yaml`.
12. **Idempotency**: every external integration (push or pull) must be idempotent — re-runs MUST NOT create duplicates.
13. **Provenance**: every claim/entity created from an external system records `external_refs` (provider name + external id) so it can be traced back.
14. **MCP exposure**: where it makes agent sense (graph traversal, enrichment, KEV lookup, saved-search preview), expose a thin MCP tool wrapper alongside the REST endpoint. Add to `mcp-tool-manifest.json`.
15. **Observability hooks** (PLAN #18): every new service emits at least one counter and one histogram, and creates spans for external calls.

## Suggested Implementation Order

Building on PLAN.md's suggested sequence (6 → 2 → 7 → 3 → 1 → 8 → 11 → 4 → 5 → 10 → 9):

```
18 (Observability)         ← do early; everything else benefits from it
17 (Webhooks)              ← unblocks alerting for 10, 12, 15, 21
12 (CISA KEV)              ← cheap, immediate operational value
15 (Enrichment)            ← independent; agent value
13 (MISP)                  ← depends on 6 (auth) + 10 (contradictions)
14 (Detection rules)       ← depends on 9 (review UI) for approval flow
16 (STIX/TAXII)            ← depends on 6 (auth)
19 (GraphQL)               ← depends on 6 (auth), 7 (FTS for searchEntities)
20 (Graph visualisation)   ← depends on 9 (UI for the page); useful sooner via API
21 (Saved searches/digests)← depends on 7 (FTS), 9 (UI), 17 (webhooks)
```

Final composite order across PLAN + EXTENSIONS:
**6 → 18 → 2 → 7 → 17 → 3 → 1 → 8 → 11 → 12 → 15 → 4 → 5 → 10 → 13 → 16 → 19 → 9 → 14 → 20 → 21**
