# z.je Platform — Multi-Persona Review & Next 50 Tasks

## Instructions for the Receiving LLM

You are performing a structured analysis of the **z.je** threat intelligence platform.

Read this document fully before generating any output. Your response must follow the exact structure specified below. Do **not** skip any persona or condense the consolidation step.

---

## Context: What Is z.je?

**z.je** is a self-hosted multi-tenant threat intelligence knowledge platform built on:
- **Stack:** FastAPI + PostgreSQL (asyncpg/SQLAlchemy) + Redis + ARQ async workers
- **Data at rest:** 44,209 entities, 124,026 relationships, 396,024 corpus documents (349K CVEs, 46K Exploit-DB), 118,018 claims, 7,702 enrichment cache entries
- **Capabilities:** REST API, GraphQL, STIX 2.1 export, TAXII 2.1, MCP SSE, Jinja2 UI
- **Enrichment providers:** 16+ (VirusTotal, Shodan, GreyNoise, AbuseIPDB, URLScan, CrowdStrike, MITRE ATT&CK, NVD, OTX, BGP HE, IPInfo, Recorded Future, MISP, OpenCTI)
- **Ingestion sources:** RSS feeds, NVD, Exploit-DB, KEV, MISP, Tor onion scraping
- **Auth model:** Multi-tenant RLS, API keys (BYOK), admin invite codes
- **Workers:** ARQ async job queue with 37K+ completed ingestion jobs, 2.7K errors

### Already Implemented (Phases 0–23 Complete)

The following were previously identified as weaknesses and have already been resolved:

| # | Issue | Resolution |
|---|---|---|
| 1 | Duplicate entities | ✅ Dedup migration + unique constraint |
| 2 | Investigation_context_for hairball | ✅ Moved to separate `investigation_context` table |
| 3 | CORS wildcard | ✅ Tightened to `CORS_ORIGINS` config |
| 4 | Entity lifecycle state | ✅ `lifecycle_state` enum + PATCH endpoint |
| 5 | Temporal relationship modeling | ✅ `valid_from`/`valid_until` columns + `?at=` filter |
| 6 | Graduated confidence scoring | ✅ `confidence VARCHAR(10)` enum + `source_type` |
| 7 | Search materialized view | ✅ `mv_entity_search` + 5-min cron refresh |
| 8 | OSV fallback for CVE freshness | ✅ OSV fallback in corpus refresh worker |
| 9 | pgvector semantic search | ✅ Embeddings wired to search; `/search/semantic` endpoint |
| 10 | Corpus→graph linking | ✅ `corpus_document_id` FK on claims + `references_corpus` relationships |
| 11 | RAG-backed `/ask` endpoint | ✅ Context injection from entity/claim search |
| 12 | Adversary profile aggregation | ✅ `GET /api/v1/entities/{id}/profile` |
| 13 | CVE detail page | ✅ `GET /api/v1/cve/{cve_id}` with NVD/EPSS/KEV aggregation |
| 14 | Enrichment quality feedback | ✅ `quality_rating` + `flag_reason` + `/rate` + `/flag` endpoints |
| 15 | Sigma/YARA ingestion & TTP linking | ✅ SigmaHQ import script + `detects` relationships |
| 16 | Onion data classification | ✅ `data_classification` + retention policy + weekly purge cron |
| 17 | Per-API-key rate limiting | ✅ Redis sliding-window middleware + 429 with `Retry-After` |
| 18 | CTE-based path finding | ✅ Recursive CTE replaces NetworkX all-load approach |
| 19 | Graph stats endpoint | ✅ `GET /api/v1/graph/stats` with Redis 5m cache |
| 20 | Graph pagination | ✅ Cursor-based keyset pagination on graph endpoint |
| 21 | Campaign phase ordering | ✅ `phase_order` column + `/entities/{id}/timeline` |
| 22 | Schema-ified `external_refs` | ✅ Typed columns for CVE/domain/hash/malware/detection_rule |
| 23 | Provenance view | ✅ `GET /api/v1/entities/{id}/provenance` |
| 24 | Breach dashboard | ✅ `GET /api/v1/breaches` aggregated from Tor claims |
| 25 | Search prefix shortcuts | ✅ `cve:`, `ip:`, `actor:`, `domain:`, `hash:`, `malware:`, `campaign:` |
| 26 | Data freshness monitoring | ✅ `GET /api/v1/health/freshness` |
| 27 | Slow query monitoring | ✅ `GET /api/v1/admin/slow-queries` + pg_stat_statements + Slack alerts |
| 28 | Co_occurs_with confidence decay | ✅ `last_observed_at` + 0.95^months decay on access |

---

## Your Task

Using the **four personas** defined below, you will analyse the z.je platform as it stands **after** the resolved items above have been implemented. Your goal is to identify the **next wave** of improvements — bugs that remain, new feature opportunities opened by the resolved items, and areas the original feedback didn't surface.

Each persona must give an **independent** analysis. Do not let one persona's output influence another's before they are written. Write each persona section in full before moving to the next.

---

## Persona Definitions

### PERSONA A — Senior Software Developer / Platform Engineer

**Mindset:** Systems thinking, correctness, maintainability, scalability, developer experience. Focused on code quality, API design, data model correctness, performance under load, testability, and operational reliability. Sceptical of tech debt and over-engineering. Wants things to fail loudly and fail correctly.

**Your job as this persona:**
1. Review the existing resolved items above — what *new* problems do their implementations likely introduce? (e.g., the MV refresh cron could block writers under load; the CTE path finder still has no depth cap in the query planner)
2. Identify any remaining architectural weaknesses the original feedback **missed** entirely
3. Propose **new features** that emerge from having the resolved foundations in place (e.g., now that embeddings exist, what's the next logical capability?)
4. Give **concrete opinions** — not wishy-washy "consider X". Say "X is broken because Y, fix it by doing Z"

Output format:
```
### Issues & Bugs (as Senior Developer)
[numbered list, each with: what, why it matters, how to fix]

### New Feature Opportunities (as Senior Developer)
[numbered list, each with: what, the value it creates]
```

---

### PERSONA B — Security Architect

**Mindset:** Threat modelling, defence in depth, zero-trust, data classification, compliance posture, cryptographic correctness, secrets management, audit completeness. Assumes adversarial conditions. Thinks in attack trees, not user stories.

**Your job as this persona:**
1. Model the attack surface that has **changed** now that the resolved items are in place (e.g., the provenance endpoint exposes document metadata — is that a SSRF or info-leak vector?)
2. Identify authentication, authorisation, and cryptographic weaknesses the original report didn't fully address
3. Consider supply-chain risks in the ingestion pipeline (Tor scraping, Sigma imports from GitHub, OSV data)
4. Propose security hardening and compliance features (audit trails, key rotation, zero-trust networking)
5. Be paranoid. Surface things that "probably won't happen" but have high impact if they do.

Output format:
```
### Security Issues & Risks (as Security Architect)
[numbered list, each with: threat, risk level (Critical/High/Medium/Low), fix]

### Security Feature Requests (as Security Architect)
[numbered list, each with: feature, security value it provides]
```

---

### PERSONA C — SOC Analyst (Tier 2/3)

**Mindset:** Alert fatigue, workflow efficiency, pivot-heavy investigation, triage speed. Lives in the search bar and the alert queue. Values low noise, fast pivots, actionable context, and tool integrations that don't require switching contexts. Hates false positives, hates missing context, hates slow tools.

**Your job as this persona:**
1. Walk through a realistic investigation workflow using z.je as it exists now (post-phase-23): receive an alert, pivot to z.je, enrich, correlate, conclude
2. Identify every point of friction, missing data, or dead end in that workflow
3. Propose **analyst-facing features** that would make z.je the first tool opened, not the last resort
4. Consider integrations with SIEM/SOAR tools, ticketing systems, and other analyst tooling
5. Focus ruthlessly on time-to-insight and reducing clicks-to-answer

Output format:
```
### Analyst Workflow Friction Points (as SOC Analyst)
[numbered list, each with: what the friction is, how it slows analysis, what would fix it]

### Analyst Feature Requests (as SOC Analyst)
[numbered list, each with: feature, why analysts need it, example use case]
```

---

### PERSONA D — Cyber Threat Intelligence Analyst (Strategic/Operational)

**Mindset:** Attribution, campaign tracking, actor profiling, TTP mapping, indicator lifecycle management, intelligence sharing. Thinks in kill chains, Diamond Models, and STIX bundles. Cares about source reliability, analytic confidence, and intelligence products that brief to leadership.

**Your job as this persona:**
1. Assess z.je's value as a CTI platform now that the foundational improvements (confidence scoring, temporal modeling, adversary profiles, corpus linking) are in place
2. Identify gaps in **intelligence coverage** — what's still missing from the entity model, the relationship taxonomy, the enrichment pipeline?
3. Propose **intelligence workflow features** that turn z.je from a data store into an intelligence production tool
4. Think about products: finished intelligence reports, threat briefings, TLP-aware sharing, IOC packages for downstream consumers
5. Consider the analyst's job end-to-end: collection → processing → analysis → production → dissemination

Output format:
```
### Intelligence Gaps & Quality Issues (as CTI Analyst)
[numbered list, each with: gap, intelligence impact, recommended remediation]

### Intelligence Feature Requests (as CTI Analyst)
[numbered list, each with: feature, intelligence value, effort estimate (Low/Medium/High)]
```

---

## Consolidation Step (Do This Last)

After writing all four persona sections in full, perform the following synthesis:

1. Collect all items raised across all four personas
2. Score each item on two axes:
   - **Impact** (1–5): How much does this improve the platform's usefulness, security, or reliability?
   - **Effort** (1–5): How hard is this to implement? (1 = a config change, 5 = a multi-week feature)
3. Prioritise using **Impact − (Effort × 0.5)** as the ranking score — high impact, low effort wins
4. Deduplicate items that multiple personas raised (credit all personas who raised it; give it a boost in ranking)
5. Output the **Top 50 Next Tasks** in ranked order

Output format for each task:
```
### Top 50 Next Tasks

| Rank | Task | Raised By | Impact | Effort | Score | Category |
|------|------|-----------|--------|--------|-------|----------|
| 1 | ... | Dev, SOC | 5 | 1 | 4.5 | Security |
...
```

Then, for tasks ranked 1–20, provide a **one-paragraph implementation brief** (what it is, why it matters, how to implement it, what code/files to change). These briefs are for a lower-level LLM to execute — be specific about file paths, function names, migration patterns, and expected outcomes.

---

## Ground Rules for Your Response

- **Be concrete.** "Improve search" is not a valid task. "Add a `POST /api/v1/search/batch` endpoint that accepts a list of IOCs and returns enriched results in one call" is.
- **Be honest about the platform.** If a resolved item was implemented poorly (e.g., the MV refresh lacks error handling), say so.
- **Do not re-raise already-resolved items** unless the implementation introduced a new problem.
- **Each persona must raise at least 8 distinct issues and 5 feature requests** before consolidation.
- **The Top 50 must span all four personas** — no single persona should dominate more than 20 of the 50 slots.
- **Category labels for the Top 50:** Security, Performance, Data Quality, Intelligence, Analyst UX, Developer Experience, Operations, Integrations

---

## Platform Files Reference (for context)

The platform codebase lives at `security-knowledge/` within the repository. Key locations:

```
security-knowledge/
├── app/
│   ├── main.py                    # FastAPI app, all router registrations, middleware
│   ├── config.py                  # Settings (Pydantic BaseSettings, env-driven)
│   ├── models/
│   │   ├── entities.py            # Entity model, EntityKind enum
│   │   ├── relationships.py       # Relationship model (no updated_at — intentional)
│   │   ├── claims.py              # Claim model (corpus_document_id FK added)
│   │   └── ...
│   ├── routers/
│   │   ├── entities.py            # CRUD + /profile + /timeline + /provenance + /lifecycle
│   │   ├── search.py              # FTS + semantic + prefix shortcuts + ?kind= filter
│   │   ├── graph.py               # /graph/ (paginated) + /graph/path + /graph/stats
│   │   ├── capabilities.py        # GET /api/v1/capabilities — live inventory
│   │   ├── breaches.py            # GET /api/v1/breaches — Tor-sourced breach aggregation
│   │   ├── health_freshness.py    # GET /api/v1/health/freshness
│   │   ├── admin_perf.py          # GET /api/v1/admin/slow-queries
│   │   └── ...
│   ├── graph/
│   │   ├── pathfinding.py         # CTE recursive pathfinding (find_path_cte)
│   │   └── visualisation.py      # Graph builder with cursor pagination
│   ├── enrichment/
│   │   ├── service.py             # EnrichmentService (BYOK, user_id-aware)
│   │   ├── registry.py            # Provider registry
│   │   └── providers/             # 16+ provider implementations
│   ├── embeddings/
│   │   ├── generator.py           # Embedding generation (wired post-phase-9)
│   │   └── search.py              # Vector search (wired post-phase-9)
│   ├── auth/
│   │   ├── api_key.py             # SHA-256 API key validation
│   │   └── byok.py                # BYOK provider key resolution
│   ├── mcp/
│   │   └── server.py              # MCP SSE server + auth middleware
│   └── worker.py                  # ARQ worker, all cron jobs and job functions
├── alembic/
│   └── versions/                  # Migrations 0001–0044 (0044 = pg_stat_statements)
└── tests/                         # 40+ test files, baseline: 360 pass / 20 fail
```

### Key Data Model Notes
- **Relationships table has `created_at` only — no `updated_at`.** Do not add `TimestampMixin`. This is intentional to avoid graph query 500s.
- **`EntityKind` enum** now includes: `ip`, `domain`, `hash`, `url`, `cve`, `malware`, `threat_actor`, `campaign`, `technique`, `tactic`, `tool`, `vulnerability`, `detection_rule`
- **Confidence** on relationships is now `VARCHAR(10)` enum: `low`, `medium`, `high`, `unknown`
- **Temporal** on relationships: `valid_from TIMESTAMPTZ`, `valid_until TIMESTAMPTZ` (NULL = open-ended)
- **Entity lifecycle_state:** `active`, `expired`, `retired`, `false_positive`, `benign`
- **MV `mv_entity_search`** refreshes every 5 minutes concurrently; index on `id`
- **Rate limiting:** Redis sliding-window per API key; default 100 req/min; 429 + `Retry-After`
- **pg_stat_statements** is enabled via migration 0044

---

## Begin Your Analysis

Start with PERSONA A (Software Developer), then B (Security Architect), then C (SOC Analyst), then D (CTI Analyst), then the Consolidation. Do not interleave. Do not summarise early. Write each section completely before moving to the next.
