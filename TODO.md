# Security Knowledge Service TODO

This file replaces `PLAN.md` and `PLAN-EXTENSIONS.md`. It is written as an implementation brief for a lower-capability LLM. Follow it literally, keep changes small, and verify each item before moving on.

## Current Repository Context

- The service described by this roadmap is `security-knowledge/`, a FastAPI + Postgres + pgvector project referenced from `README.md`.
- This repository root currently contains operating docs and roadmap docs. Before implementing, confirm whether `security-knowledge/` exists locally or must be cloned/restored.
- Expected service shape from the existing docs:
  - FastAPI API on port 8000.
  - Postgres with pgvector.
  - Redis for workers after async queue work.
  - Alembic migrations.
  - pytest, ruff, mypy.
  - MCP-ready tool manifest.
  - Policy-gated outbound HTTP via `source-policy.yaml`.

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

## Item 6: Authentication and Authorisation

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

## Item 18: Observability

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

## Item 2: Async Queue-Based Ingestion

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

## Item 7: Full-Text and Fuzzy Search

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

## Item 17: Outbound Webhooks Framework

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

## Item 3: Embedding Generation Pipeline

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

## Item 1: Real LLM Extraction

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

## Item 8: TAXII/STIX Consumer, NVD, and GitHub Advisory Adapters

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

## Item 11: EUVD Adapter

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

## Item 12: CISA KEV Adapter

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

## Item 15: Enrichment Framework and Required Providers

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

## Item 4: BugBountyScanner Integration

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

## Item 5: PyGhidra Security Knowledge Bridge

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

## Item 10: Change Detection and Alerting

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

## Item 13: MISP Bidirectional Sync

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

## Item 22: OpenCTI Bidirectional Sync

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

## Item 16: STIX 2.1 Export and TAXII Server Mode

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

## Item 19: GraphQL API for Relationship Graph

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

## Item 9: Analyst Review UI

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

## Item 14: Detection Rule Generation

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

## Item 20: Relationship Graph Visualisation Endpoint

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

## Item 21: Saved Searches and Scheduled Digests

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

## Final Roadmap Acceptance Criteria

The roadmap is complete only when all of the following are true:

- All items in the composite order are implemented, tested, documented, and merged.
- `PLAN.md` and `PLAN-EXTENSIONS.md` no longer exist.
- `TODO.md` remains the only roadmap handoff file.
- All required providers are configured in `.env.example`, source policy, docs, and tests.
- A fresh environment can run migrations, start API/worker, seed data, and pass tests.
- Provider QA proves VirusTotal, MISP, OpenCTI, Shodan, IPinfo.io, GreyNoise.io, and CrowdStrike functionality at least through mocked integration tests.
- No external API credentials are required to run the default test suite.
- No secrets appear in logs, traces, test fixtures, docs examples, or committed config.
