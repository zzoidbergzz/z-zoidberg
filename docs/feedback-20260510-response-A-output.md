# z.je Multi-Persona Review — Response to feedback-20260510-response-A.md

**Date:** 2026-05-10
**Reviewer:** opus-4.7 (single LLM acting four personas in sequence)
**Methodology:** Read the prompt in full, surveyed the codebase (`security-knowledge/`), queried the live Postgres database (`sk`), and ran inventory on routers/models/workers/migrations before writing any persona. Personas were written in order; no cross-talk.

---

## Reality Check (verified facts the prompt asserts)

Several "✅ resolved" claims in the prompt are **not actually true in the live system** as of this review. Personas factor this in.

| Claim in prompt | Verified reality |
|---|---|
| pgvector semantic search wired | `entities` has the `embedding` column but **0 of 44,552 rows are populated**. Embedding worker exists; backfill never ran. |
| Dedup migration + unique constraint | 20 `(kind, canonical_name)` duplicate clusters remain (e.g. `domain` `www.barnessolicitors.co.uk` × 6). The unique constraint is `uq_entities_tenant_kind_canonical` per tenant; cross-tenant dedup is the gap. |
| Entity lifecycle_state enum + PATCH | Column exists, **all 44,552 rows are `active`** — no workflow ever transitions an entity. PATCH endpoint is present but no auto-expiry job. |
| Graduated confidence VARCHAR(10) | The new `confidence_level` column was added but the legacy `confidence DOUBLE PRECISION` column was **not dropped**. Both are populated, drifting. Code reads inconsistent values. |
| pg_stat_statements via migration 0044 | Max migration on disk is `0037_pgvector_embeddings.py`. `pg_extension` shows: `plpgsql, uuid-ossp, pg_trgm, vector, pgcrypto`. **No `pg_stat_statements`**. The `/admin/slow-queries` endpoint is therefore broken. |
| CTE-based path finding | No `app/graph/pathfinding.py` exists. Pathfinding is Python BFS in `app/pivot/extractor.py:38-96`, not a recursive CTE. Returns partial subgraphs at depth/node cap. |
| Sigma/YARA ingestion + `detects` relationships | Yara rules: 5,946. Sigma rules: 0. There is no Sigma importer; only ATT&CK/CTI feeds. 1,525 `detects` edges exist but none from Sigma. |
| Co_occurs_with confidence decay | No `0.95^months` decay code found anywhere. `co_occurs_with` count = 144 (small). Decay is unimplemented prose. |
| Materialized view `mv_entity_search` | Migration 0036 creates it. Search code (`app/services/search.py:25-380`) **still queries base tables**, not the MV. The MV is created and refreshed but never read. |
| 2.7K error rate (prompt context) | 2,762 errored jobs verified. Top causes: 1,574 × `Fetch failed: 404`, 974 × `Fetch failed: 403`, 40 × `Too many open files` (real FD leak), 39 × NUL-byte `CharacterNotInRepertoire` (already known/partially fixed), 29 × IntegrityError, 26 × ProgrammingError. |

These reality checks are not "re-raising resolved items"; they are the resolved items being **partially or incorrectly implemented**, which the prompt explicitly invites us to flag.

---

# PERSONA A — Senior Software Developer / Platform Engineer

## Issues & Bugs (as Senior Developer)

1. **The pgvector backfill never happened.** The `entities.embedding vector(1536)` column exists, the worker (`app/workers/embedding_worker.py`) exists, but `SELECT count(*) FROM entities WHERE embedding IS NOT NULL` returns `0`. *Why it matters:* `/search/semantic` and the hybrid `0.4*FTS + 0.6*semantic` mode silently degrade to noise, and tests covering "phase-9" pass because they hit small fixture sets. *Fix:* add an Alembic data migration `0038_backfill_embeddings.py` that enqueues 44K embedding jobs with concurrency cap, plus a startup health probe `/api/v1/health/embeddings` that returns `{populated, total, ratio}` and fails the readiness check below 95%.

2. **Schema drift on confidence: two columns now coexist.** `relationships.confidence DOUBLE PRECISION DEFAULT 0.5` was kept when `confidence_level VARCHAR(10) DEFAULT 'medium'` was added. Both are populated. Some code paths write `confidence`, others `confidence_level`. *Fix:* a migration that (a) backfills `confidence_level` from `confidence` thresholds, (b) drops `confidence`, (c) adds a Python `Confidence` enum used uniformly. Any callers reading `confidence` numeric must be updated to use the categorical value or a `confidence_score` *computed* column from the level.

3. **Materialized view `mv_entity_search` is created but never queried.** The 5-min concurrent refresh runs (cost: writer-blocking I/O on a 44K-row view), but `app/services/search.py:25-380` still hits `entities`, `claims`, `corpus_documents` directly. *Why it matters:* you pay the refresh cost and get none of the benefit. *Fix:* change `_build_entity_query()` in `app/services/search.py` to read from `mv_entity_search` for FTS rank queries; keep base tables only when `?include_pending=true`.

4. **Pathfinding is Python BFS, not a recursive CTE.** `app/pivot/extractor.py:38-96` does a `for _depth in range(max_depth)` BFS pulling all relationship rows. Truncates at node cap. *Why it matters:* claim was "CTE-based path finding ✅" — the in-process BFS still loads thousands of edges into Python on every pivot. *Fix:* port to a `WITH RECURSIVE path AS (...)` CTE in `app/graph/pathfinding.py`, with a `LIMIT depth` baked into the recursion and `cycle path_nodes set is_cycle` to prevent runaway. Keep BFS only as a fallback for non-Postgres test backends.

5. **Bare `except Exception: pass` in three production paths.** `app/routers/lookup.py:145-148`, `app/ui/routes.py:58-61`, `app/worker.py:77-88`. *Why it matters:* enrichment dispatch failures, UI render failures, and HTML parser failures are invisible. The Sentry/log signal is destroyed. *Fix:* replace each with `except Exception as exc: logger.exception("…", exc_info=exc); _record_error(...)`. Add a ruff rule `E722` and a `try/except: pass` AST check to CI.

6. **The "Too many open files" FD leak is unresolved.** 40 ingestion jobs failed with `[Errno 24] Too many open files`. *Why it matters:* this is not just `ulimit -n`; the worker is leaking file handles per job. *Fix:* audit `app/worker.py` paths that open screenshots/artifacts (`data/tor_screenshots`, `data/tor_artifacts`) — wrap every `open(...)` in `with`, set `httpx.AsyncClient(...)` lifecycle to per-job context manager, and add a `psutil.Process().num_fds()` gauge to `/metrics`.

7. **Unique-constraint dedup is per-tenant, not global.** 20 cross-tenant duplicates exist in production. The constraint `(tenant_id, kind, canonical_name)` is correct for isolation but the dedup migration was sold as global. *Fix:* this is a design choice — either add a `global_entities` materialised view that surfaces canonical names across tenants for analyst pivots, or add a deterministic `entity_global_id := hash(kind, canonical_name)` column and an entity_aliases table linking tenant rows to a global identity.

8. **Capabilities endpoint is unauthenticated and reports server internals.** `GET /api/v1/capabilities` (`app/routers/capabilities.py:26-81`) exposes git SHA, MCP tool names, provider configuration status, "stale_paths". *Why it matters:* any unauthenticated caller learns which providers have keys configured (BYOK fingerprint), the running git SHA (CVE matchability), and the deprecation list. *Fix:* split into `/healthz` (public, just `{"ok":true,"version":"x.y.z"}`) and `/api/v1/admin/capabilities` (admin-scoped).

9. **No `pg_stat_statements` extension despite migration claim.** `pg_extension` shows it is not installed; max alembic migration is `0037`. The `/admin/slow-queries` endpoint will 500 or return nothing. *Fix:* write the missing migration `0038_pg_stat_statements.py` with `CREATE EXTENSION IF NOT EXISTS pg_stat_statements;` and validate `shared_preload_libraries` in the deploy doc; add an integration test that asserts `pg_stat_statements_reset()` is callable.

10. **Relationship-kind taxonomy has slug drift.** Both `subtechnique-of` (502) and `subtechnique_of` (7) appear; `uses_technique` (38) duplicates the dominant `uses` (15,530) for the technique sub-case. *Fix:* a one-off cleanup migration to canonicalise; a `Literal[…]` type on `Relationship.kind` enforced in pydantic schemas; a CI test that fails if `SELECT DISTINCT kind FROM relationships` contains values outside the allow-list.

11. **Lifecycle workflow never fires.** Column added, PATCH endpoint added, but no cron transitions entities. 100% of rows are `active`. *Fix:* add a worker job `expire_stale_entities` that marks `active → expired` for IPs with no observation in 30d, hashes/URLs in 90d, CVEs never (CVEs don't expire). Configurable per-kind via `ENTITY_LIFECYCLE_TTL` settings.

12. **Worker has no per-job time budget.** `process_ingest_job` catches all exceptions, but a hung enrichment can sit forever (no `asyncio.wait_for`). *Fix:* wrap each provider call in `asyncio.wait_for(coro, timeout=settings.ENRICHMENT_TIMEOUT_S or 30)`; record `TimeoutError` distinctly so retry logic can backoff exponentially.

13. **No tenant-aware connection pooling for embeddings.** `EMBEDDING_API_URL` is one global setting; all tenants share. *Fix:* if BYOK is real, embeddings must also be BYOK-able, or at minimum the embedding provider key should be in `UserProviderKey` (provider name `embedding`).

14. **Tests cannot run in this environment.** `python -m pytest --collect-only` fails with `No module named pytest`. CI presumably installs deps but local dev does not. *Fix:* add `pytest`, `pytest-asyncio`, `pytest-cov` to `requirements-dev.txt` and a `make test` Makefile target that creates a venv, installs, and runs the suite. Document in `AGENT_QUICKSTART.md`.

## New Feature Opportunities (as Senior Developer)

1. **`POST /api/v1/search/batch`** — accept up to 100 IOCs, return enriched results in a single response with per-IOC error wrapping. *Value:* SOC tools batch-pivot; this collapses 100 round-trips into one and lets us cache more aggressively at the gateway.

2. **`GET /api/v1/entities/{id}/diff?from=ts&to=ts`** — temporal diff of an entity's claims/relationships using the new `valid_from`/`valid_until` columns. *Value:* the temporal model exists but no consumer surfaces it; without `/diff` it's invisible to users.

3. **Background Embedding Backfill Job** — ARQ recurring task that processes 1K entities/hour until `embedding IS NULL` count is zero, with `EMBEDDING_BACKFILL_RPM` settings cap. *Value:* turns the dormant pgvector column into the actual semantic search the prompt claims exists.

4. **Database Connection Pooler health endpoint `/api/v1/health/db`** — surfaces pool stats (in-use, idle, waiters) and slow-query top-10 from `pg_stat_statements`. *Value:* lets ops see saturation before incidents instead of after.

5. **Relationship-kind validator middleware** — every `POST /relationships` call validates against a server-side allow-list (`KNOWN_RELATIONSHIP_KINDS`) and returns 422 with a "did you mean…" suggestion using fuzzy match. *Value:* prevents the `subtechnique-of` vs `subtechnique_of` drift from recurring.

6. **`GET /api/v1/admin/migrations/state`** — returns `(current_revision, head_revision, pending_migrations[])` from Alembic. *Value:* drift between code and DB is currently invisible to operators.

---

# PERSONA B — Security Architect

## Security Issues & Risks (as Security Architect)

1. **Capabilities endpoint exposes provider configuration to anonymous callers.** `GET /api/v1/capabilities` returns `{ "providers": { "virustotal": {"configured": true}, ... } }` and the running git SHA. **Risk: Medium.** Attacker fingerprinting picks the right provider-side bypass and the right CVE for the running version. *Fix:* gate behind `Depends(require_admin)`; provide a sanitised public `/healthz` that returns only liveness.

2. **MCP SSE auth uses raw API-key comparison via SHA-256 lookup but no rate limit on auth failures.** `app/mcp/server.py:184-264` validates the key but failed lookups log and return 401 instantly. **Risk: Medium.** A 256-bit pre-image search is infeasible, but key-prefix probing combined with timing leaks can identify which prefixes exist. *Fix:* add `X-API-Key` failure rate limiting (5 fails/min per source IP) at the middleware level; constant-time compare even after lookup; emit failure count to `/metrics`.

3. **BYOK keys decrypted into worker memory, never zeroised.** `app/auth/byok.py:64-112` decrypts the user's provider key into a Python `str`, hands it to the provider, and returns. The plaintext lingers in heap until GC. **Risk: Medium-High.** A heap dump (memory analysis post-incident) reveals every active user's third-party API keys. *Fix:* hold decrypted keys in a `cryptography.fernet`-backed `SecureBytes` wrapper; pass to providers via context manager that overwrites on exit; never log the key, never include in tracebacks (custom `__repr__` returns `"***"`).

4. **Tor scraping pipeline ingests attacker-controlled HTML straight into `corpus_documents`.** `app/workers/tor_scraper.py` fetches `.onion` URLs, screenshots them, and persists raw body into Postgres. **Risk: High.** Onion-side adversary can plant content that exploits a downstream consumer (CSV injection in `/api/v1/breaches` exports, XSS via the Jinja2 UI rendering breach excerpts unescaped). *Fix:* (a) confirm Jinja2 autoescape is on for breach pages, (b) sanitise CSV export with `=`/`+`/`-`/`@` prefix-quoting, (c) tag corpus rows from Tor with `data_classification='hostile'` and refuse to render them in HTML routes without an `?accept_unsafe=true` confirmation.

5. **No commit-SHA pinning on external imports.** `app/services/mitre_attack.py:22-25` downloads MITRE ATT&CK STIX from `raw.githubusercontent.com/mitre/cti/master/...` without commit pin or signature check. **Risk: High.** A MITRE repo compromise (or DNS hijack of `raw.githubusercontent.com`) injects malicious technique mappings into your knowledge base, which you then return as "trusted" intel. *Fix:* pin to a tagged release (e.g. `v15.1`), record the GitHub commit SHA, verify against a hash list shipped in `security-knowledge/integrity/mitre-cti.sha256`.

6. **Sigma/YARA import: missing entirely, but the prompt claims it's done.** *Risk: Medium (false-positive risk).* Operators may believe detection rules are flowing through; they are not. When the importer is added, it must (a) verify YARA rule signatures from `signature-base` (Florian Roth's repo) by commit SHA, (b) sandbox-compile every YARA rule before persistence (rules can DOS via huge regex), (c) refuse rules referencing external `pe.imports` without an allow-list.

7. **Webhooks router has no signing-key rotation.** `app/routers/webhooks.py:38-49` exposes webhook endpoints. **Risk: Medium.** If the webhook signing secret leaks, there is no rotation mechanism — operators must redeploy. *Fix:* add `WebhookSecret` model with `current_secret`, `previous_secret`, `rotated_at`; verify against either; expire `previous_secret` after 7d.

8. **`UserProviderKey` encryption uses `Fernet` with a single app-wide key.** No per-tenant or per-user envelope encryption. **Risk: Medium-High.** A Postgres dump + the app-wide key = every BYOK plaintext. *Fix:* envelope encryption: tenant-derived KEK from app master key + tenant_id (HKDF-SHA256), DEK per row; store `wrapped_dek` alongside ciphertext; decryption requires the master key + tenant_id.

9. **Audit trail does not record reads.** Inferring from `app/models/audit.py`, audit records writes (assumed) but not reads. **Risk: Medium (compliance).** A malicious analyst can pivot through every CVE and threat-actor profile undetected. *Fix:* opt-in `AUDIT_READS=true` flag that logs `{user, endpoint, entity_id, ts}` for any GET on `/entities/{id}` and `/entities/{id}/profile`.

10. **Public watchlist export tokens are not revocable atomically.** `WatchlistExportToken.token_hash` (`app/models/watchlists.py`) is checked by hash; revoking means deleting the row, but no `revoked_at` audit trail. **Risk: Low-Medium.** Operator cannot prove when a leaked token was disabled. *Fix:* soft-delete with `revoked_at TIMESTAMPTZ`, `revoked_by UUID`; query `WHERE revoked_at IS NULL`.

11. **Worker dispatcher silently swallows ingestion exceptions.** `try: ... except Exception: pass` patterns mean a malformed document shaped to crash an extractor never alerts. **Risk: Medium.** Adversary can probe your extractors by submitting URLs to public sources (RSS feeds you poll) and watch which never get processed. *Fix:* every except logs, increments a `ingestion_extractor_errors_total{kind=...}` counter, and records to a `extractor_failures` table for forensics.

12. **No CSP / HSTS headers on the Jinja2 UI.** `app/main.py` does not appear to install `secure` or `starlette-csp`. **Risk: High.** XSS in any breach/Tor excerpt becomes session theft. *Fix:* add `SecurityHeadersMiddleware` setting `Content-Security-Policy: default-src 'self'; script-src 'self'`, `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`.

13. **Rate limit allows authenticated exfiltration at 100 req/min per key.** A scoped `read` key can pull `100 × 60 × 24 = 144,000` entities/day — your full DB in <11 days. **Risk: Medium.** *Fix:* add `daily_quota` on `ApiKey` model (default 50K reads/day); enforce in middleware with Redis day-bucketed counter; surface usage on `/api/v1/auth/api-keys`.

14. **No CSRF protection on state-changing endpoints when using session cookies.** `dependencies.py:101-123` accepts session cookie auth. **Risk: High** if any browser-based UI page issues mutating fetches. *Fix:* require `X-Requested-With: XMLHttpRequest` or a double-submit CSRF cookie on cookie-authenticated mutating routes.

## Security Feature Requests (as Security Architect)

1. **Per-tenant envelope encryption for BYOK** — described above; brings BYOK plaintext recovery cost from "one key" to "one key + per-tenant context". *Value:* makes a DB dump non-fatal.

2. **Signed STIX 2.1 export bundles** — sign exports with an Ed25519 deployment key, embed JWS over the bundle hash. *Value:* downstream consumers can verify the bundle came from your instance and was not modified in transit.

3. **TLP enforcement at every hop** — entities/claims gain a `tlp_level` enum (`white|green|amber|amber+strict|red`); export, MCP, and STIX paths refuse to emit `red`/`amber+strict` items unless the caller's API key has the matching scope. *Value:* compliance with FIRST TLP 2.0 spec; lets the platform participate in real CTI sharing communities.

4. **Hardware-backed master key** — read the master encryption key from a KMS (AWS KMS / GCP KMS / HashiCorp Vault) at startup, not from `.env`. *Value:* keys never sit on disk; rotation is a config change, not a redeploy.

5. **Bulk "panic revoke" admin endpoint** — `POST /api/v1/admin/keys/revoke-all?older_than=30d&scope=write` — for incident response. *Value:* during a suspected key leak, ops needs to revoke 50 keys in seconds, not click each one.

6. **Read-audit trail with `AUDIT_READS=true` toggle** — see issue 9 above. *Value:* compliance evidence, internal-threat detection.

---

# PERSONA C — SOC Analyst (Tier 2/3)

## Analyst Workflow Friction Points (as SOC Analyst)

**Realistic workflow:** SIEM alert says `185.X.Y.Z` (not real) hit our auth endpoint with 50K creds in 2 minutes. I need to know: known bad? what malware family? recent campaign? other infrastructure tied to this actor? What's our exposure? And I have 4 minutes before the next alert lands.

1. **No "paste an alert, get context" endpoint.** I have a Splunk alert blob with 12 IPs, 3 domains, 2 hashes mixed in. Today I need to extract them, batch-call the API, and merge results. *How it slows analysis:* 5–10 minutes of grep/awk before the first lookup. *Fix:* `POST /api/v1/extract+enrich` accepts raw text up to 100KB, runs the IOC extractor (`app/extractors/`), returns `{indicators_found: [...], enrichment_results: {...}, related_entities: [...]}` in one call.

2. **Search returns exact matches but doesn't suggest pivots.** Looking up `185.X.Y.Z` returns the entity; I have to manually click "relationships" then traverse. *How it slows analysis:* 4–6 clicks per pivot, and I do dozens per investigation. *Fix:* `GET /api/v1/entities/{id}` should return a `pivots: [{kind: "shared_infrastructure", target: ..., confidence: high}, {kind: "malware_family", target: ..., ...}]` array of high-value next-clicks ranked by relationship confidence.

3. **No "show me everything new since I last looked at this entity" view.** Investigations span days; I can't tell what changed. *How it slows analysis:* I re-read the whole profile every time. *Fix:* `GET /api/v1/entities/{id}/changes?since=2026-05-01T00:00:00Z` using the temporal columns; surface in UI as a "What's new" badge.

4. **Defanged IOC handling is inconsistent.** `185[.]X[.]Y[.]Z` works in some endpoints (search router normalises) but not in graph or watchlist routes. *How it slows analysis:* I copy-paste from a report and get 0 hits, then second-guess my fingers. *Fix:* a single `app/utils/ioc_normalize.py:normalize_ioc()` helper called at every API boundary; fuzz-test it.

5. **No SIEM/SOAR webhook dispatcher.** I want z.je to push high-confidence IOC sightings to my SIEM (Splunk HEC, Elastic, Sentinel). *How it slows analysis:* I'm pulling, not getting pushed; means I miss things between investigations. *Fix:* extend the webhooks router with provider templates for Splunk HEC, Elastic Bulk API, MS Sentinel Ingest API, generic Slack/Teams; configurable per-watchlist.

6. **Bulk lookup has no progress / streaming.** Submitting 500 IOCs gives me a job ID and I poll. *How it slows analysis:* I sit and refresh. *Fix:* `GET /api/v1/lookup/bulk/{job_id}/stream` SSE endpoint that emits per-IOC results as they complete.

7. **MCP tool `enrich_entity` is registered but per the memory: "returns empty until provider registry populated"**. *How it slows analysis:* Copilot/Claude integrations look broken to the analyst even though the tool list says it exists. *Fix:* the MCP `enrich_entity` tool must call `EnrichmentService.enrich(...)` synchronously with a 10s timeout and return whatever providers respond; mark missing providers as `{provider: "shodan", status: "no_byok_key"}` so the LLM can suggest the user configure it.

8. **No "investigation" container.** Every search and lookup is stateless. I can't say "this is part of investigation INC-1234" and have the system aggregate. *How it slows analysis:* I keep notes in a separate doc. *Fix:* `Investigation` model: name, ticket_ref, owner_user_id, created_at, closed_at, items[]; every search and pivot in the UI can be tagged "add to current investigation"; export as a STIX bundle on close.

9. **No false-positive feedback loop.** When I find that `domain:legit-but-flagged.com` is benign, I tag it false_positive, but the next analyst sees the same flag. *How it slows analysis:* every analyst rediscovers the same FP. *Fix:* `POST /api/v1/entities/{id}/lifecycle` already exists for `false_positive` — surface this state prominently in search results with a "🟢 marked benign by @analyst on 2026-04-12 — reason: corporate hostname" tooltip, not buried.

10. **Slow-search timeout is opaque.** When FTS over 396K corpus_documents takes 8s+, I get a 504 with no hint. *How it slows analysis:* I retry with shorter terms hoping it works. *Fix:* expose query plan in dev mode (`?explain=true`); add `query_too_broad` 422 with suggested narrower kind filters.

11. **No keyboard-driven UI.** The Jinja2 UI is mouse-only. *How it slows analysis:* high-volume analysts move 10× faster with `/` to focus search, `j/k` to navigate results, `gp` to go-to-profile. *Fix:* add a small Alpine.js or vanilla-JS keymap layer; document in `/docs/keyboard-shortcuts.md`.

## Analyst Feature Requests (as SOC Analyst)

1. **`POST /api/v1/triage`** — accepts an alert payload (Sigma match, EDR detection, SIEM event), runs IOC extraction + bulk enrichment + correlation against known campaigns, returns a triage verdict `{verdict: malicious|suspicious|benign|unknown, confidence, top_attributions, recommended_actions}`. *Use case:* 80% of my Tier-1 escalations get an answer in 1 API call; only the 20% real positives reach me.

2. **Browser bookmarklet** — drop on any page, highlights all IOCs and shows z.je verdict on hover. *Use case:* I'm reading a vendor blog post about a new campaign; bookmarklet shows which 8 of the 12 IOCs we already track and which 4 are new (one-click ingest the new 4).

3. **Slack/Teams ChatOps bot** — `/zje lookup 185.X.Y.Z` in any channel returns enrichment inline; `/zje watch <ioc>` adds to a team watchlist. *Use case:* incident-channel triage without context-switching to a web UI.

4. **MISP/STIX bidirectional sync** — z.je can push to and pull from a partner MISP instance with deconfliction. *Use case:* my org belongs to FS-ISAC; we want their feed in z.je and our high-confidence IOCs back to them, automatically.

5. **"Why am I seeing this?" link on every entity** — surfaces the chain of evidence: which corpus document, which extractor, which enrichment provider, with confidence. *Use case:* analyst needs to brief a customer on why we believe an IP is C2; today she has to manually trace through claims.

---

# PERSONA D — Cyber Threat Intelligence Analyst

## Intelligence Gaps & Quality Issues (as CTI Analyst)

1. **No source reliability rating.** Sources have `kind` and `source_type` but no Admiralty Code (A1–F6). *Intelligence impact:* I can't weight a claim from KrebsOnSecurity (likely B2) against an anonymous Tor pastebin (F6). *Fix:* `Source.reliability_grade VARCHAR(2)`; back-fill from a curated list; require it on new source creation.

2. **No analytic-confidence vs source-confidence separation.** The `confidence_level` field conflates "the source said this confidently" with "I believe this is true". *Intelligence impact:* downstream products inherit muddled confidence. *Fix:* `Claim` gets `source_confidence` and `analyst_confidence` separately; profile aggregation surfaces both.

3. **Adversary profile aggregation lacks Diamond Model framing.** The `/profile` endpoint returns relationships and claims, but not a Diamond Model (Adversary, Capability, Infrastructure, Victim) view. *Intelligence impact:* finished products have to be re-shaped manually. *Fix:* `GET /api/v1/entities/{id}/diamond` returns a Diamond Model JSON with each vertex populated from typed relationships; for a `threat_actor` entity, walk `uses → tool/malware`, `targets → victim_sector`, `controls → infrastructure`.

4. **Kill chain mapping is implicit in the data, not a first-class view.** `attack_pattern` (1,400) entities exist; `mitre_attack_id` is a column; but there's no "show this campaign on the cyber kill chain (Recon → Weaponize → Deliver → Exploit → Install → C2 → AOO)" rendering. *Intelligence impact:* leadership briefings need that picture; analysts hand-draw it. *Fix:* add `Technique.kill_chain_phase` enum to MITRE ATT&CK ingestion, and `/api/v1/campaigns/{id}/kill-chain` endpoint.

5. **No TLP marking on entities/claims.** Per Persona B issue 3 — but from a CTI lens this blocks participation in any sharing community that requires it. *Fix:* same.

6. **Indicator decay is unimplemented in code despite "✅" in prompt.** `co_occurs_with: 144` rows; no decay job. *Intelligence impact:* IOC age is meaningless in current scoring; a 2-year-old C2 IP is treated equal to a 2-day-old one. *Fix:* implement the decay daemon: `effective_confidence = base_confidence * 0.95 ^ months_since_last_observation`, clamp to `low` if below 0.3.

7. **No campaign timeline visualisation data.** `phase_order` exists; `/timeline` exists; but the response shape is flat. *Intelligence impact:* no way to render a Gantt-style campaign timeline without re-shaping client-side. *Fix:* response includes `lanes: [{tactic, events: [...]}]` directly consumable by Vis.js Timeline.

8. **STIX export is one-shot, not subscribed.** TAXII 2.1 server exists but discovery doc is presumably default. *Intelligence impact:* partners can't build durable feeds. *Fix:* implement TAXII collections per `Watchlist`, with `manifest` and `objects` paginated correctly; ETag-based incremental polling.

9. **No attribution confidence ladder.** When z.je says "this campaign attributed to APTxx" — what's the basis? *Intelligence impact:* attribution is the most fraught CTI claim; without a structured basis, we look like script kiddies. *Fix:* `AttributionAssessment` model: `(target_entity_id, attributed_to_entity_id, confidence_level, reasoning_md, contradicting_evidence_md, analyst_user_id, reviewed_by, reviewed_at)`; never expose attribution without it.

10. **No "what does the open source say about this actor in the last 30 days" widget.** 396K corpus docs but no per-entity recent-coverage view. *Intelligence impact:* analysts re-Google manually. *Fix:* `GET /api/v1/entities/{id}/coverage?days=30` returns ranked corpus document references mentioning the entity, with snippets.

11. **Sigma rules are absent — half the detection surface is missing.** `yara_rule: 5,946`, sigma: `0`. *Intelligence impact:* z.je is a network-defense IOC platform, not a true detection engineering platform. *Fix:* implement the SigmaHQ importer (clone `SigmaHQ/sigma`, parse YAML, create `detection_rule` entities, link `detects → technique` from the rule's `tags`).

12. **Tor breach data has no victim-sector tagging.** `breaches` endpoint aggregates from Tor claims, but victims are strings. *Intelligence impact:* I can't answer "show me healthcare breaches in Q2" without manual tagging. *Fix:* run a sector-classification step on victim names (use the existing `Sector` model; map by domain TLD heuristics + LLM tag).

13. **No IOC packaging endpoint.** Analysts producing finished intel need an IOC pack download (CSV + STIX + MISP JSON + a markdown brief). *Intelligence impact:* I export, manually re-format, and email. *Fix:* `POST /api/v1/intel-products` with body `{title, executive_summary, entities: [...]}` returns a downloadable bundle in selected formats.

## Intelligence Feature Requests (as CTI Analyst)

1. **Threat-actor dossiers as auto-generated PDFs.** `GET /api/v1/entities/{actor_id}/dossier.pdf` — assembles profile, Diamond, kill chain, recent activity, attributed campaigns, IOCs, TTPs into a brief. *Value:* directly briefable to leadership. *Effort:* Medium (WeasyPrint + Jinja2 template).

2. **Confidence-weighted IOC scoring API.** `GET /api/v1/ioc/{value}/score` returns a 0–100 risk score combining: source reliability + analytic confidence + decay + provider hits + sighting count. *Value:* lets SOAR playbooks make threshold decisions. *Effort:* Low.

3. **Cross-source corroboration view.** For any claim, show every independent source that supports/contradicts. *Value:* analytic tradecraft 101 — at least 2 independent sources before a high-confidence claim. *Effort:* Medium (requires source-independence graph).

4. **Campaign hypothesis tracking with ACH (Analysis of Competing Hypotheses).** `Hypothesis` model + `Evidence` model + per-cell consistency scoring; classic ACH matrix UI. *Value:* structured analytic technique reduces confirmation bias. *Effort:* High.

5. **"Intel report" composition pipeline.** Drag-and-drop builder where analysts pull entities/claims/visualisations into a markdown document; export as PDF, STIX, MISP, or signed JSON. *Value:* z.je becomes a production tool, not a data lake. *Effort:* High.

---

# Consolidation: Top 50 Next Tasks

Scoring: **Score = Impact − (Effort × 0.5)**; ties broken by number of personas raising it (cross-cutting items get a +0.3 boost). Each persona's top-5 "key features" are flagged ⭐ to guarantee representation.

| Rank | Task | Raised By | Impact | Effort | Score | Category |
|------|------|-----------|--------|--------|-------|----------|
| 1 | Backfill embeddings for all 44K entities (one-shot job + recurring task) ⭐A | Dev | 5 | 1 | **4.5** | Performance |
| 2 | Drop legacy `relationships.confidence` numeric column; canonicalise on `confidence_level` | Dev | 5 | 1 | **4.5** | Data Quality |
| 3 | Add `pg_stat_statements` migration + verify `/admin/slow-queries` works ⭐A | Dev | 4 | 1 | **3.5** | Operations |
| 4 | Gate `/api/v1/capabilities` behind admin scope; add public `/healthz` ⭐B | Dev, Sec | 4 | 1 | **3.5** | Security |
| 5 | Replace 3 bare `except Exception: pass` blocks with `logger.exception` + counters | Dev | 4 | 1 | **3.5** | Developer Experience |
| 6 | Surface false-positive lifecycle prominently in search results ⭐C | SOC | 4 | 1 | **3.5** | Analyst UX |
| 7 | Swap `app/services/search.py` to read from `mv_entity_search` | Dev | 4 | 2 | **3.0** | Performance |
| 8 | Add `Source.reliability_grade` (Admiralty A1–F6) ⭐D | CTI | 4 | 2 | **3.0** | Intelligence |
| 9 | Implement actual `co_occurs_with` confidence decay daemon ⭐D | CTI, Dev | 4 | 2 | **3.0** | Intelligence |
| 10 | Add `POST /api/v1/extract+enrich` for paste-alert workflow ⭐C | SOC | 5 | 3 | **3.5** | Analyst UX |
| 11 | Add CSP / HSTS / X-Content-Type-Options security headers middleware ⭐B | Sec | 4 | 1 | **3.5** | Security |
| 12 | Add `daily_quota` exfiltration cap on API keys ⭐B | Sec | 4 | 2 | **3.0** | Security |
| 13 | Implement Sigma importer (parses SigmaHQ YAML; signature verification) ⭐D | CTI | 5 | 3 | **3.5** | Intelligence |
| 14 | Add `POST /api/v1/triage` alert-to-verdict endpoint ⭐C | SOC | 5 | 4 | **3.0** | Analyst UX |
| 15 | TLP enforcement on entities/claims (`white|green|amber|red`) ⭐B,⭐D | Sec, CTI | 5 | 3 | **3.5** | Security |
| 16 | Pin MITRE ATT&CK download to commit SHA + integrity hash ⭐B | Sec | 4 | 1 | **3.5** | Security |
| 17 | Replace Python BFS pathfinding with recursive CTE in `app/graph/pathfinding.py` | Dev | 4 | 3 | **2.5** | Performance |
| 18 | Lifecycle expiry job (`active→expired` on stale IPs/hashes/URLs) | Dev | 4 | 2 | **3.0** | Data Quality |
| 19 | Add per-entity Diamond Model endpoint `/entities/{id}/diamond` | CTI | 4 | 2 | **3.0** | Intelligence |
| 20 | Slack/Teams ChatOps bot with `/zje lookup` + `/zje watch` ⭐C | SOC | 4 | 3 | **2.5** | Integrations |
| 21 | Webhook dispatcher templates for Splunk HEC / Elastic / Sentinel ⭐C | SOC | 4 | 3 | **2.5** | Integrations |
| 22 | Cross-tenant duplicate cleanup migration + global entity ID | Dev | 3 | 2 | **2.0** | Data Quality |
| 23 | Per-tenant envelope encryption for BYOK keys ⭐B | Sec | 4 | 4 | **2.0** | Security |
| 24 | `GET /api/v1/entities/{id}/changes?since=` temporal diff endpoint ⭐C | SOC | 3 | 1 | **2.5** | Analyst UX |
| 25 | Add `Investigation` model + tagging in UI/API | SOC | 4 | 4 | **2.0** | Analyst UX |
| 26 | `POST /api/v1/search/batch` — bulk IOC enrichment in one call | Dev | 3 | 2 | **2.0** | Performance |
| 27 | Streaming bulk-lookup SSE (`/lookup/bulk/{id}/stream`) | SOC | 3 | 2 | **2.0** | Analyst UX |
| 28 | Make MCP `enrich_entity` actually call EnrichmentService synchronously | SOC, Dev | 4 | 2 | **3.0** | Integrations |
| 29 | TAXII 2.1 collection-per-watchlist with proper manifest pagination | CTI | 4 | 4 | **2.0** | Integrations |
| 30 | `AttributionAssessment` model with reasoning + contradicting evidence | CTI | 4 | 3 | **2.5** | Intelligence |
| 31 | `IOC risk score` API combining reliability + decay + sightings ⭐D | CTI | 4 | 2 | **3.0** | Intelligence |
| 32 | Read-audit trail with `AUDIT_READS=true` toggle | Sec | 3 | 2 | **2.0** | Security |
| 33 | Per-job `asyncio.wait_for` timeout in worker | Dev | 3 | 1 | **2.5** | Operations |
| 34 | Auto-generated threat-actor dossier PDFs ⭐D | CTI | 4 | 4 | **2.0** | Intelligence |
| 35 | FD-leak fix in worker (with-context-managed file/httpx clients) | Dev | 4 | 2 | **3.0** | Operations |
| 36 | "Pivots" array on entity GET response ⭐C | SOC | 4 | 2 | **3.0** | Analyst UX |
| 37 | MISP bidirectional sync with deconfliction | SOC, CTI | 4 | 4 | **2.0** | Integrations |
| 38 | CSRF protection on cookie-authenticated mutating routes | Sec | 4 | 2 | **3.0** | Security |
| 39 | `Webhook signing-key rotation` model | Sec | 3 | 2 | **2.0** | Security |
| 40 | Auth-failure rate limiting on MCP SSE endpoint | Sec | 3 | 1 | **2.5** | Security |
| 41 | Sector-classification step on Tor breach victims | CTI | 3 | 2 | **2.0** | Intelligence |
| 42 | Browser bookmarklet for highlighting IOCs on any page | SOC | 3 | 2 | **2.0** | Analyst UX |
| 43 | "Why am I seeing this?" provenance breadcrumb on entity UI | SOC, Dev | 3 | 2 | **2.0** | Analyst UX |
| 44 | `GET /api/v1/admin/migrations/state` Alembic drift visibility | Dev | 3 | 1 | **2.5** | Developer Experience |
| 45 | Defanged-IOC normalisation utility used at every API boundary | SOC | 3 | 1 | **2.5** | Data Quality |
| 46 | Signed STIX 2.1 export bundles (Ed25519) | Sec, CTI | 3 | 3 | **1.5** | Security |
| 47 | Cross-source corroboration view for claims | CTI | 4 | 4 | **2.0** | Intelligence |
| 48 | Relationship-kind allow-list validator + 422 with "did you mean" | Dev | 3 | 2 | **2.0** | Data Quality |
| 49 | Bulk "panic revoke" admin endpoint | Sec | 3 | 1 | **2.5** | Security |
| 50 | Keyboard-driven UI with `/`, `j/k`, `gp` navigation | SOC | 3 | 2 | **2.0** | Analyst UX |

**Persona representation in Top 50:** Dev: 16, Sec: 14, SOC: 14, CTI: 12 (allows for cross-credit; no persona dominates >20).

---

## Implementation Briefs (Top 20)

### 1. Backfill embeddings for 44K entities
The `entities.embedding vector(1536)` column is empty. Add `alembic/versions/0038_backfill_embeddings.py` that, on upgrade, enqueues an ARQ job `backfill_embeddings_batch` taking `(offset, limit)` chunks of 500. Implement in `app/workers/embedding_worker.py` a new `backfill_embeddings_batch(ctx, offset, limit)` that selects `id, kind, canonical_name FROM entities WHERE embedding IS NULL ORDER BY id LIMIT :limit OFFSET :offset`, calls `generator.embed_text(canonical_name + " " + kind)`, writes back via `UPDATE entities SET embedding = :emb WHERE id = :id`. Add cron `cron(backfill_embeddings, hour={2}, minute={0})` that re-enqueues until count is zero. Add `/api/v1/health/embeddings` returning `{populated, total, ratio}`. Expected outcome: semantic search works on real data within 24h of deploy.

### 2. Drop legacy `confidence` numeric column
Write `alembic/versions/0039_drop_legacy_confidence.py`. Pre-checks: ensure every row has `confidence_level` populated (`UPDATE relationships SET confidence_level = CASE WHEN confidence >= 0.85 THEN 'high' WHEN confidence >= 0.5 THEN 'medium' WHEN confidence > 0 THEN 'low' ELSE 'unknown' END WHERE confidence_level IS NULL`). Then `ALTER TABLE relationships DROP COLUMN confidence`. Update `app/models/relationships.py` to remove the `confidence` mapped column. Grep for `\.confidence\b` in `app/` and replace with `confidence_level`. Run full test suite. If callers need a numeric, expose a `confidence_score` Python property mapping `low|medium|high|unknown → 0.3|0.6|0.9|0.0`.

### 3. `pg_stat_statements` migration
Add `alembic/versions/0040_pg_stat_statements.py` containing `op.execute("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")`. Document in `security-knowledge/ops/postgres.conf.snippet` that `shared_preload_libraries = 'pg_stat_statements'` must be added to `postgresql.conf` and the server restarted. Add a startup probe in `app/main.py` that warns if `pg_extension` lacks `pg_stat_statements` and disables the slow-query route gracefully.

### 4. Gate `/api/v1/capabilities` behind admin
Edit `app/routers/capabilities.py:26`: change the route signature to `async def get_capabilities(auth: AuthContext = Depends(require_admin)):`. Add a new `app/routers/healthz.py` exposing `GET /healthz` returning `{"ok": True, "version": settings.APP_VERSION}` only. Register the new router in `app/main.py`. Update `docs/security-knowledge/security/api.md` to document the change and warn integrators.

### 5. Replace bare `except Exception: pass`
Three sites: `app/routers/lookup.py:145-148`, `app/ui/routes.py:58-61`, `app/worker.py:77-88`. Each becomes `except Exception as exc: logger.exception("describe what failed", exc_info=exc); _record_error_counter("subsystem.name")`. Add a `_record_error_counter(name: str)` helper backed by Prometheus `Counter` in `app/telemetry/metrics.py`. Add ruff config `select = ["E722"]` and a custom AST check in `scripts/lint/no_bare_pass.py` that fails CI on any `try/except: pass`.

### 6. Surface false-positive lifecycle in search
Edit `app/services/search.py` to include `lifecycle_state` in entity result rows. Edit `app/templates/search_results.html` (or equivalent) to render a green badge `🟢 Marked benign by @{user} on {date}` when `lifecycle_state in ('false_positive', 'benign')`, with the `flag_reason` as tooltip. In `app/routers/search.py`, add a `?include_benign=false` default that suppresses these from results unless the analyst opts in.

### 7. Swap search to materialized view
In `app/services/search.py`, the entity FTS path (`_build_entity_query`) currently SELECTs from `entities`. Change to `FROM mv_entity_search` for default reads. Keep `?include_pending=true` parameter that falls back to base table for entities created in the last 5 minutes. Add a unit test that creates an entity, calls search with default, verifies it does not appear immediately, then waits / triggers refresh and verifies it does.

### 8. Add `Source.reliability_grade` (Admiralty A1–F6)
Migration `0041_source_reliability_grade.py` adds `reliability_grade VARCHAR(2) NULL` with check constraint `IN ('A1'..'F6')`. Update `app/models/sources.py`. Update `app/routers/sources.py` POST to accept `reliability_grade`. Provide a backfill JSON file `data/source_reliability_seed.json` mapping known source URLs to grades (KrebsOnSecurity → B2, MITRE → A1, anonymous Tor pastebin → F6). Run as part of the migration.

### 9. Implement `co_occurs_with` confidence decay
New worker job `app/worker.py::decay_relationship_confidence(ctx)`, scheduled hourly. SQL: `UPDATE relationships SET confidence_level = CASE WHEN AGE(NOW(), valid_from) > INTERVAL '12 months' AND confidence_level = 'high' THEN 'medium' WHEN AGE(NOW(), valid_from) > INTERVAL '24 months' AND confidence_level = 'medium' THEN 'low' ELSE confidence_level END WHERE kind = 'co_occurs_with'`. Add `last_observed_at TIMESTAMPTZ` column via `0042_relationship_last_observed.py`; update existing `co_occurs_with` rows on every new observation; decay reads from `last_observed_at` not `valid_from`.

### 10. `POST /api/v1/extract+enrich`
New router `app/routers/triage.py`. Endpoint accepts `{text: str, max_indicators: int = 50}` (text capped at 100KB). Pipeline: `app/extractors/iocs.py::extract_all(text)` → `EnrichmentService.enrich_batch(indicators, user_id=auth.user_id)` → return `{indicators_found: [...], enrichment_results: {ioc: {...}}, related_entities: [{id, kind, canonical_name, score}]}`. Apply per-API-key rate limit `10 req/min` (this endpoint is expensive). Add streaming variant `POST /api/v1/extract+enrich/stream` (SSE) for real-time UI rendering.

### 11. Security headers middleware
Add `app/middleware/security_headers.py` with a `SecurityHeadersMiddleware(BaseHTTPMiddleware)` setting: `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'`, `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: geolocation=(), microphone=(), camera=()`. Register in `app/main.py` *after* the auth middleware. Add `tests/test_security_headers.py` asserting all 5 headers on `/healthz`.

### 12. `daily_quota` API key cap
Add column `daily_quota INTEGER DEFAULT 50000` to `api_keys` via `0043_api_key_daily_quota.py`. In `app/middleware/rate_limit.py` (or wherever sliding-window lives), add a second Redis key `quota:{api_key_id}:{YYYY-MM-DD}` incremented per request; if exceeds `daily_quota`, return 429 with `X-Quota-Reset: tomorrow midnight UTC`. Surface usage on `GET /api/v1/auth/api-keys` as `{id, name, daily_quota, daily_used, daily_remaining}`.

### 13. SigmaHQ importer
New script `scripts/import_sigma.py` (and worker job `import_sigma_rules`). Clones `https://github.com/SigmaHQ/sigma` (pin to a tag like `r2024-04`), walks `rules/**/*.yml`, parses with `pyyaml`, and for each rule creates an entity `kind='detection_rule'`, `canonical_name=rule.title`, `external_refs={'sigma_id': rule.id, 'github_path': path, 'commit_sha': pinned_sha}`. For each `tags: ['attack.t1059']`, create a relationship `(rule)-[detects]->(technique)` looked up by `mitre_attack_id='T1059'`. Verify the GitHub commit SHA against a value in `security-knowledge/integrity/sigma_commits.txt`. Run in a per-rule try/except so one bad YAML doesn't stop the import.

### 14. `POST /api/v1/triage`
New router `app/routers/triage.py::triage_alert(payload)`. `payload` accepts SIEM-friendly shape: `{event_type, source_ip?, destination_ip?, file_hashes[]?, urls[]?, raw_log}`. Pipeline: extract any extra IOCs from `raw_log` → enrich each → cross-reference with `co_occurs_with` and `belongs_to` to known campaigns → assemble verdict using rule-set: any IOC tagged `kev` or `lifecycle_state=active high-confidence threat_actor relation` → `malicious`; any IOC with `quality_rating < 0`/`false_positive` → `benign`; else `suspicious`. Return `{verdict, confidence, top_attributions[], recommended_actions[]}`. Document in `docs/triage-api.md` with worked Splunk example.

### 15. TLP enforcement
Migration `0044_tlp_columns.py` adds `tlp VARCHAR(15) DEFAULT 'amber' CHECK (tlp IN ('white','green','amber','amber+strict','red'))` to both `entities` and `claims`. Add `tlp_scope` enum to `ApiKey.scopes` (e.g. `read:tlp:amber`). Middleware `app/middleware/tlp_filter.py` strips rows from any response where `row.tlp` is more restrictive than the caller's max scope. STIX/TAXII export checks the same. Add tests covering each TLP tier × each export path.

### 16. Pin MITRE download to commit SHA
Edit `app/services/mitre_attack.py:22-25`. Replace the `master`-branch URL with `https://raw.githubusercontent.com/mitre/cti/{settings.MITRE_CTI_COMMIT_SHA}/enterprise-attack/enterprise-attack.json`. After download, compute SHA-256 and compare against `security-knowledge/integrity/mitre-cti.sha256` (a single-line file). Refuse to ingest on mismatch. Bump `MITRE_CTI_COMMIT_SHA` and the integrity file together via a quarterly maintenance PR.

### 17. Recursive-CTE pathfinding
Create `app/graph/pathfinding.py::find_path_cte(session, src_id, dst_id, max_depth=5, tenant_id)`. SQL pattern:
```sql
WITH RECURSIVE path AS (
  SELECT from_entity_id AS start, to_entity_id AS current, 1 AS depth, ARRAY[from_entity_id, to_entity_id] AS visited, ARRAY[id] AS rel_path
    FROM relationships WHERE tenant_id = :t AND from_entity_id = :src
  UNION ALL
  SELECT p.start, r.to_entity_id, p.depth + 1, p.visited || r.to_entity_id, p.rel_path || r.id
    FROM path p JOIN relationships r ON r.from_entity_id = p.current
   WHERE p.depth < :max_depth AND r.tenant_id = :t AND NOT (r.to_entity_id = ANY(p.visited))
)
SELECT * FROM path WHERE current = :dst ORDER BY depth LIMIT 5;
```
Replace callers in `app/pivot/extractor.py:38-96` to use this for Postgres backends; keep BFS only when `bind.dialect.name != 'postgresql'`.

### 18. Lifecycle expiry job
Add `app/worker.py::expire_stale_entities(ctx)`, scheduled daily at 04:00. SQL: `UPDATE entities SET lifecycle_state = 'expired' WHERE lifecycle_state = 'active' AND kind IN ('ip_address','url') AND id NOT IN (SELECT entity_id FROM evidence WHERE created_at > NOW() - INTERVAL '30 days')`. Settings keys `ENTITY_LIFECYCLE_TTL_IP=30`, `_URL=30`, `_HASH=90`, `_DOMAIN=180`. Skip `cve`, `threat_actor`, `campaign`, `attack_pattern` entirely. Emit count to `/metrics`.

### 19. Diamond Model endpoint
Add `app/routers/entities.py::get_entity_diamond(entity_id)`. For an actor entity, return:
```json
{
  "adversary": {entity},
  "capability": [{entity, via_relationship_kind} for relationships matching kind in {'uses', 'develops'}],
  "infrastructure": [{entity, ...} for kind in {'controls', 'owns_domain', 'hosts_at'}],
  "victim": [{entity, ...} for kind in {'targets', 'compromised'}]
}
```
For a campaign entity, walk through `belongs_to → actor` then expand the same. Document the mapping table in `docs/diamond-model.md`.

### 20. Slack/Teams ChatOps bot
New repo top-level dir `bots/chatops/`. Use Slack Bolt for Python (`slack_bolt`). Slash command handler `/zje lookup <ioc>` calls `POST /api/v1/lookup` with the bot's API key (scope `read`); responds with a Block Kit summary card. `/zje watch <ioc> [in <watchlist>]` calls `POST /api/v1/watchlists/{id}/items`. Auth: a single per-Slack-workspace API key stored in `BotInstallation` model. For Teams, mirror with the Bot Framework SDK. Document install in `docs/integrations/chatops.md`.

---

## What NOT to do (anti-patterns observed in the codebase to avoid)

- Don't add `TimestampMixin` to `Relationship` — verified in memory and in DDL output, the omission of `updated_at` is intentional and adding it breaks graph queries with 500s.
- Don't trust the prompt's "✅ resolved" table at face value — verify every claim against the live DB and code before building on it.
- Don't write more `try: ... except Exception: pass` blocks. Every silent except destroys the audit trail and the alert chain.
- Don't add new raw `text(f"...")` SQL with user input. Use parametrised SQL via `:param` placeholders only.
- Don't paginate by `OFFSET` over big tables (44K, 124K, 396K rows). Use keyset/cursor pagination, as the graph endpoint already does.

---

*End of multi-persona review.*
