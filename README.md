# Zoidberg Workspace

Security data platform, intelligence tools, and agent services — all running on this host.

## 🦞 Security Knowledge Service

**Location:** `security-knowledge/` | **Port:** 8000 | **Stack:** FastAPI + Postgres + pgvector + Redis

A policy-aware threat intelligence ingestion, normalisation, search, context-pack, and enrichment service designed for LLM agents. MCP-ready. **All 22 roadmap items implemented.**

### Architecture

```
Feed Discovery → Policy-Gated Fetch → Parse → Extract → Normalise → Store → Search → Context Pack
                                                   ↓
                              Enrichment (VT/Shodan/IPinfo/GreyNoise/CrowdStrike)
                                                   ↓
                           MISP ↔ OpenCTI ↔ STIX/TAXII ↔ NVD ↔ GHSA ↔ KEV ↔ EUVD
```

### API Endpoints (40+)

#### Core
| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | /api/v1/health | Service health (public) |
| POST | /api/v1/sources/discover | Discover from RSS/Feedly/TAXII/NVD/GHSA feeds |
| GET | /api/v1/sources | List source records |
| GET | /api/v1/sources/{id} | Get source metadata |
| POST | /api/v1/sources/{id}/fetch | Fetch source URL (policy-gated, async) |
| POST | /api/v1/sources/{id}/parse | Parse source content (async) |
| POST | /api/v1/sources/{id}/extract | Full extraction pipeline (async) |
| POST | /api/v1/ingestion/url | Ingest a URL directly — returns 202 job ID |
| POST | /api/v1/ingestion/feed-item | Ingest from a feed — returns 202 job ID |
| POST | /api/v1/entities/search | FTS + trigram ranked entity search |
| GET | /api/v1/entities/{id} | Entity profile with claims & relationships |
| GET | /api/v1/entities/{id}/relationships | Entity relationship graph |
| POST | /api/v1/vulnerabilities/search | Search vulnerabilities |
| GET | /api/v1/vulnerabilities/{cve_id} | CVE profile (CVSS, KEV, EPSS, patches) |
| POST | /api/v1/iocs/search | IOC lookup (IPs, domains, hashes, URLs) |
| POST | /api/v1/claims/search | Search claims |
| GET | /api/v1/claims/{id}/trace | Trace claim → evidence → source |
| POST | /api/v1/claims/{id}/review | Analyst review of claim |
| POST | /api/v1/reports/compare | Compare reports (agreements, conflicts) |
| POST | /api/v1/context-pack | Token-budgeted context pack for LLM agents |

#### Auth
| POST | /api/v1/auth/login | JWT login |
| POST/GET/DELETE | /api/v1/auth/keys | API key management |

#### Enrichment
| POST | /api/v1/enrichment/enrich | Enrich entity via providers |
| GET | /api/v1/enrichment/{entity_id}/results | Cached enrichment results |
| GET | /api/v1/enrichment/budget | Provider budget status |

#### Webhooks
| CRUD | /api/v1/webhooks/subscriptions | Manage subscriptions |
| POST | /api/v1/webhooks/subscriptions/{id}/test | Send test event |
| GET | /api/v1/webhooks/subscriptions/{id}/deliveries | Delivery history |

#### Integrations
| POST | /api/v1/misp/sync/pull | Pull from MISP |
| POST | /api/v1/misp/sync/push | Push reviewed claims to MISP |
| POST | /api/v1/opencti/sync/pull | Pull from OpenCTI |
| POST | /api/v1/opencti/sync/push | Push to OpenCTI |
| GET | /api/v1/stix/bundle | Export STIX 2.1 bundle |
| GET | /taxii2/ | TAXII 2.1 discovery + collections |
| GET/POST | /graphql | GraphQL entity graph traversal |

#### Detection & Analysis
| POST | /api/v1/analyse/binary | Binary IOC extraction (PyGhidra) |
| POST/GET | /api/v1/detections | Generate/list Sigma/YARA/Snort/Suricata rules |
| GET | /api/v1/changes | Change detection feed |
| GET | /api/v1/graph/{entity_id} | Cytoscape/D3/GEXF graph export |
| CRUD | /api/v1/saved-searches | Saved searches + digest subscriptions |
| GET | /api/v1/digests/inbox | Digest inbox |

### Data Model (29 tables)

#### Core (12)
- **source_records**, **fetch_outcomes**, **raw_objects**, **parsed_documents**, **document_sections**, **evidence**, **chunk_embeddings**, **entities**, **claims**, **relationships**, **ingestion_jobs**, **audit_events**

#### Auth (3)
- **tenants**, **api_keys**, **users** — with database RLS policies (tenant-isolated)

#### Extensions (14)
- **webhook_subscriptions**, **webhook_deliveries** — HMAC-signed outbound events
- **enrichment_cache**, **enrichment_usage** — shared provider cache + budget
- **claim_versions**, **changes** — change detection + contradiction tracking
- **detection_rules** — Sigma/YARA/Snort/Suricata generated rules
- **sync_state**, **taxii_collections** — adapter state + TAXII server
- **saved_searches**, **digest_subscriptions**, **digest_runs**, **inbox_items** — digests
- **embedding_cache**, **llm_rejection_log** — LLM pipeline safety

### Enrichment Providers (7)

| Provider | Entity Kinds | Auth |
|----------|-------------|------|
| VirusTotal | hash, ip_address, domain, url | `x-apikey` |
| Shodan | ip_address, domain, cve | API key |
| IPinfo.io | ip_address | Bearer token |
| GreyNoise.io | ip_address (noise/RIOT) | API key |
| CrowdStrike | hash, ip, domain, url, actor, malware | OAuth2 Falcon |
| MISP | all IOC kinds + galaxies | REST key |
| OpenCTI | indicators, vulns, actors, reports | GraphQL token |

### Intelligence Feed Adapters (6)

| Adapter | Schedule | Notes |
|---------|----------|-------|
| NVD API v2 | Daily incremental | `modStartDate` cursor |
| GitHub Security Advisories | Daily | GraphQL pagination |
| TAXII 2.1 Consumer | Configurable | Added `added_after` |
| ENISA EUVD | Daily | EPSS + exploited/critical feeds |
| CISA KEV | Daily | ETag caching, webhook alert on new entry |
| BugBountyScanner | On-demand CLI | Subdomains, URLs, nuclei findings |

### Ingestion Pipeline

1. **Feed discovery** — RSS/Atom, direct URL, TAXII, NVD, GHSA, KEV, EUVD, BBS
2. **Async queue** — ARQ workers, 202 Accepted job IDs, `pending→running→completed`
3. **Policy-gated fetching** — robots.txt, per-domain rate limits, circuit breaker
4. **Parsing** — Markdown, HTML, JSON advisory, plain text
5. **Extraction** — 16 deterministic extractors + LLM structured extraction
6. **Entity resolution** — External ID → canonical name → create (no destructive merge)
7. **Claim/evidence linkage** — Every fact traces to source text spans
8. **Embedding generation** — OpenAI `text-embedding-3-small`, cached, batched

### Source Policy System

Per-domain config in `source-policy.yaml` covering all 10+ provider/feed domains:
- `allowed` / `blocked`, rate limits, concurrency, delay
- robots.txt enforcement, terms_status

### Deterministic Extractors (16)

CVE IDs, CWE IDs, CVSS vectors, IPv4, domains, URLs, SHA-256/SHA-1/MD5 hashes, ATT&CK technique IDs, CPEs, PURLs, TLP markings, ISO 8601 dates, emails, YARA/Sigma/Snort/Suricata rule references

### Seeded Data (4 sources)

1. CVE-2026-12345 advisory (ExampleCorp WebGateway RCE)
2. Operation Shadow Gate threat report (APT-EXAMPLE)
3. VictimCorp breach investigation (IR-2026-042)
4. APT-EXAMPLE IOC feed

### MCP Tool Manifest

12 tools, 5 resources, 4 prompts — see `mcp-tool-manifest.json`

### Agent Instructions

Full decision guidance in `AGENT_INSTRUCTIONS.md` — covers vulnerability triage, IOC hunts, threat actor research, breach investigation, detection engineering, patch prioritisation.

### Quick Commands

```bash
make docker-up      # Start Postgres + Redis
make migrate        # Run Alembic migrations
make seed           # Load sample data
make test           # Run 85 tests (all passing)
make lint           # ruff check
make typecheck      # mypy
curl localhost:8000/api/v1/health
```

### Key Stats

| Metric | Count |
|--------|-------|
| API endpoints | 40+ |
| DB tables | 29 |
| Unit tests | 85 |
| Deterministic extractors | 16 |
| Entity types | 20 |
| Relationship types | 14 |
| Enrichment providers | 7 |
| Feed adapters | 6 |
| MCP tools | 12 |
| Alembic migrations | 1 (initial, composite) |
| Source files | 179 |

---

## 🔍 BugBountyScanner

**Location:** `BugBountyScanner/` | **Stack:** Bash + Go tools

Automated bug bounty reconnaissance script by Cas van Cooten.

### Installed Recon Tools

| Tool | Purpose |
|------|---------|
| subfinder | Subdomain discovery |
| amass | Subdomain enumeration + OSINT |
| nuclei | Vulnerability scanning (templates) |
| httpx | HTTP probing & tech detection |
| ffuf | Web fuzzer (dirs, vhosts, params) |
| gowitness | Screenshot web services |
| gau | URL discovery from Wayback/CommonCrawl |
| gospider | Web spider |
| gf | Pattern-based grep for URLs |
| subjack | Subdomain takeover detection |
| qsreplace | URL query string manipulation |

### Usage

```bash
cd ~/workspace/BugBountyScanner
./BugBountyScanner.sh -d target.com -o    # Full recon
./BugBountyScanner.sh -d target.com       # Recon without screenshots
```

---

## 🐉 PyGhidra MCP

**Status:** Installed + configured in OpenClaw MCP servers

Python MCP server for Ghidra reverse engineering. Enables LLM-driven binary analysis through Ghidra's decompiler and project system.

```bash
pyghidra-mcp [INPUT_PATHS]...
```

Configured as `mcp.servers.pyghidra` in OpenClaw config.

---

## 🔎 SearXNG

**Port:** 8888 | **Container:** `searx`

Local privacy-respecting meta search engine.

```bash
curl -s "http://localhost:8888/search?q=QUERY&format=json"
```

---

## 🌐 gh-pages Site

**URL:** https://mzje.github.io/z-zoidberg/  
**Repo:** `mzje/z-zoidberg` on branch `gh-pages`

NEVER publish sensitive/personal/high-risk content without approval.

---

## Key Stats

| Metric | Count |
|--------|-------|
| API endpoints | 20 |
| DB tables | 12 |
| Unit tests | 95 |
| Deterministic extractors | 16 |
| Entity types | 20 |
| Relationship types | 14 |
| MCP tools | 12 |
| Recon tools | 11 |
| Seed sources | 4 |
