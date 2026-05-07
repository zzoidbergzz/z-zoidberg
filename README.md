# Zoidberg Workspace

Security data platform, intelligence tools, and agent services — all running on this host.

## 🦞 Security Knowledge Service

**Location:** `security-knowledge/` | **Port:** 8000 | **Stack:** FastAPI + Postgres + pgvector

A policy-aware threat intelligence ingestion, normalisation, search, and context-pack service designed for LLM agents. MCP-ready.

### Architecture

```
Feed Discovery → Policy-Gated Fetch → Parse → Extract → Normalise → Store → Search → Context Pack
```

### 20 API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | /api/v1/health | Service health |
| POST | /api/v1/sources/discover | Discover from RSS/Feedly feeds |
| GET | /api/v1/sources | List source records |
| GET | /api/v1/sources/{id} | Get source metadata |
| POST | /api/v1/sources/{id}/fetch | Fetch source URL (policy-gated) |
| POST | /api/v1/sources/{id}/parse | Parse source content |
| POST | /api/v1/sources/{id}/extract | Full extraction pipeline |
| POST | /api/v1/ingestion/url | Ingest a URL directly |
| POST | /api/v1/ingestion/feed-item | Ingest from a feed |
| POST | /api/v1/entities/search | Search entities (actors, malware, vulns, etc.) |
| GET | /api/v1/entities/{id} | Entity profile with claims & relationships |
| GET | /api/v1/entities/{id}/relationships | Entity relationship graph |
| POST | /api/v1/vulnerabilities/search | Search vulnerabilities |
| GET | /api/v1/vulnerabilities/{cve_id} | CVE profile (CVSS, exploitation, patches) |
| POST | /api/v1/iocs/search | IOC lookup (IPs, domains, hashes, URLs) |
| POST | /api/v1/claims/search | Search claims |
| GET | /api/v1/claims/{id}/trace | Trace claim → evidence → source |
| POST | /api/v1/claims/{id}/review | Analyst review of claim |
| POST | /api/v1/reports/compare | Compare reports (agreements, conflicts) |
| POST | /api/v1/context-pack | Token-budgeted context pack for LLM agents |

### Data Model (12 tables)

- **source_records** — Discovered items with metadata & policy status
- **fetch_outcomes** — Fetch attempt records (HTTP status, blocked reasons)
- **raw_objects** — Immutable raw content (local FS, S3-ready)
- **parsed_documents** — Structured document output
- **document_sections** — Semantic text sections (summary, IOCs, mitigations, etc.)
- **evidence** — Source-backed text excerpts with hash & provenance
- **chunk_embeddings** — Vector embeddings (pgvector, mock provider)
- **entities** — Normalised security objects (vulnerability, actor, malware, product, etc.)
- **claims** — Extracted assertions linked to evidence with confidence
- **relationships** — Graph edges between entities (affects, exploits, mitigates, etc.)
- **ingestion_jobs** — Job tracking
- **audit_events** — Full audit trail

### Ingestion Pipeline

1. **Feed discovery** — RSS/Atom, Feedly (API + mock mode), direct URL, TAXII/STIX stub, GitHub Advisory stub, NVD stub
2. **URL canonicalisation** — Strip tracking params, normalise host, dedup hashes
3. **Policy-gated fetching** — robots.txt, per-domain rate limits, 401/403/429 = stop, retry only transient
4. **Browser fallback** — Playwright, 3-layer guard (global toggle + policy allowlist + CAPTCHA detection)
5. **Parsing** — Markdown, HTML, JSON advisory, plain text (PDF stub)
6. **Extraction** — 16 deterministic extractors + LLM stub
7. **Entity resolution** — External ID → canonical name → create (no destructive merge)
8. **Claim/evidence linkage** — Every fact traces to source text spans
9. **Embedding generation** — Mock provider with OpenAI abstraction ready

### Source Policy System

Per-domain config in `source-policy.yaml`:
- `allowed` / `blocked` domains
- `use_browser` allowlist with reason
- Rate limits, concurrency, delay
- robots.txt enforcement
- HTTP status handling (stop vs retry)
- `terms_status`: allowed / unknown / restricted

### Deterministic Extractors (16)

CVE IDs, CWE IDs, CVSS vectors, IPv4, domains, URLs, SHA-256/SHA-1/MD5 hashes, ATT&CK technique IDs, CPEs, PURLs, TLP markings, dates, emails, YARA/Sigma/Snort/Suricata references

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
make docker-up      # Start service
make seed           # Load sample data
make test           # Run 95 tests
curl localhost:8000/api/v1/health
```

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
