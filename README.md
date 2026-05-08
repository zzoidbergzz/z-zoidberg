# z.je — OSINT Research Platform

The `security-knowledge/` FastAPI service is live at **https://z.je** and powers the z.je analyst workspace. It merges the OSINT lookup/pivot/fingerprint interface from `mzje/z` with the threat-intelligence knowledge base scaffolding of the original security-knowledge project.

## What's Live

### Auth & Access
- Everything requires login — no content is exposed without an authenticated session.
- `POST /api/v1/auth/login` — email + password → JWT + httpOnly `sk_session` cookie (7 days).
- `POST /api/v1/auth/register` — account creation (status `pending`; awaits admin approval).
- `POST /api/v1/auth/logout` — clears session cookie.
- `POST /api/v1/auth/token` — API key → JWT for programmatic access.
- Bootstrap admin `m@z.je` is created automatically on first startup from `.env`.
- **On approval**, the admin panel auto-generates a personal API key (shown ONCE in the approval dialog) with `read write enrichment watch` scopes.
- **First-login BYOK prompt**: a non-blocking banner appears site-wide until the user adds at least one provider key in `/settings` (or dismisses for 7 days).

### Browser UI (all at root paths on https://z.je)

| Path | Page |
|---|---|
| `/` | OSINT research: lookup, bulk lookup, path finder, enrichment, graph |
| `/fp` | Browser fingerprint — server metadata + client JS entropy, logged to DB |
| `/investigation` | Group entities into named investigations |
| `/graph` | Pivot graph explorer |
| `/entities` | Entity browser |
| `/search` | Full-text search |
| `/claims` | Browse + author structured claims |
| `/digests` | Recurring digest subscriptions |
| `/admin` | Admin panel (admin role required): stats, pending approvals, user list, source health, audit |
| `/settings` | Account, password, BYOK provider keys |
| `/login` | Login page |
| `/register` | Account registration |

All `/ui/*` paths redirect permanently to their root equivalents.

### API

| Area | Endpoint |
|---|---|
| Auth | `POST /api/v1/auth/login`, `POST /api/v1/auth/logout`, `POST /api/v1/auth/token`, `POST /api/v1/auth/register`, `GET/PATCH /api/v1/auth/me` |
| Lookup | `POST /api/v1/lookup`, `POST /api/v1/lookup/bulk`, `GET /api/v1/lookup/{entity_id}/results`, `GET /api/v1/lookup/{id}/graph`, `GET /api/v1/lookup/{id}/history` |
| Investigations | `GET/POST /api/v1/lookup/investigations`, `GET /api/v1/lookup/investigations/{id}` |
| Shortcuts | `GET /ip`, `GET /ua`, `GET /headers`, `GET /fp`, `POST /fp/collect` |
| Knowledge CRUD | `GET/POST /api/v1/entities/`, `GET/POST /api/v1/claims/`, `GET/POST /api/v1/evidence/` |
| Search & ingest | `GET /api/v1/search/`, `POST /api/v1/ingest/` |
| Enrichment | `POST /api/v1/enrich/{entity_id}`, `GET /api/v1/enrich/{kind}/{value}/stream` |
| MCP | `GET /api/v1/mcp/tools`, `POST /api/v1/mcp/call` |
| MITRE ATT&CK | `GET /api/v1/mitre/...` (30+ query tools) |
| Export & graph | `GET /api/v1/export/stix`, `GET /api/v1/graph/`, `GET /graphql` |
| Other | webhooks, digests, detections, audit, admin, sectors, pingback, TAXII |

### Enrichment Providers (active)
- **IPinfo** — IP geo, ASN, org, abuse (token in `.env`)
- **GreyNoise** — IP noise classification (key in `.env`)
- VirusTotal, Shodan, NVD, MITRE, MISP, OpenCTI (configured when keys are present)

### Stack
FastAPI · PostgreSQL + pgvector · Alembic · SQLAlchemy async · Redis/ARQ · Jinja2/HTMX · vis-network graph · Strawberry GraphQL · STIX/TAXII

## Deployment

- **Host:** https://z.je  
- **Process:** uvicorn on port 8010, proxied by Apache 2.4  
- **Apache config:** `/etc/apache2/sites-available/zje-sk-proxy.conf`  
- **Service directory:** `security-knowledge/`

```bash
cd security-knowledge
. .venv/bin/activate
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8010
```

### Cloning to a fresh box (loopback / dev / replica)

`security-knowledge/scripts/install.sh` is a one-shot bootstrap. On the source machine run `dump_db.sh` first to capture the live DB (entities, relationships, claims, the full ~395k corpus_documents — CVE/GCVE/Exploit-DB), then ship the dump to the target and let `install.sh` restore it.

```bash
# 1. on the source (z.je)
cd security-knowledge && scripts/dump_db.sh
# → writes dumps/sk_<utc>.dump (custom-format, compressed, ~hundreds of MB)
scp dumps/sk_*.dump newhost:/tmp/

# 2. on the target machine (loopback only, then later open up as needed)
git clone git@github.com:mzje/z-zoidberg.git && cd z-zoidberg/security-knowledge
scripts/install.sh --dump /tmp/sk_*.dump
# → installs deps, creates pg role+db, restores dump, starts on 127.0.0.1:8000
```

Empty install (no prod data, just migrations + seed pack):
```bash
scripts/install.sh
```

Env knobs (all optional, sensible defaults):  
`PG_USER PG_PASS PG_DB PG_HOST PG_PORT REDIS_URL BIND_ADDR BIND_PORT`. Default bind is `127.0.0.1:8000` so the box is loopback-only until you front it with a reverse proxy.

## Project Files

| File | Purpose |
|---|---|
| `AGENTS.md` | Agent operating rules: startup reads, memory, safety, heartbeat. |
| `SOUL.md`, `USER.md`, `IDENTITY.md` | Agent persona and user identity context. |
| `TOOLS.md` | Local SearXNG and gh-pages publishing notes. |
| `HEARTBEAT.md` | Heartbeat checklist (empty = no heartbeat calls needed). |
| `TODO.md` | Improvement roadmap. |
| `deep-research-prompt.md` | Prompt for producing an import-ready cybersecurity research corpus. |
| `bootstrap.md` | Handoff for MCP-aware corpus ingestion on another LLM host. |

## MCP Examples

```bash
# List tools
curl -H "X-API-Key: $SK_API_KEY" https://z.je/api/v1/mcp/tools

# Query MITRE technique
curl -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tool":"get_object_by_attack_id","args":{"attack_id":"T1059"}}' \
  https://z.je/api/v1/mcp/call

# Enrich an IP
curl -H "X-API-Key: $SK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"entity_kind":"ip","entity_value":"8.8.8.8"}' \
  https://z.je/api/v1/mcp/call -d '{"tool":"enrich_entity","args":{...}}'
```

## Dark-Moon MCP Integration

[Dark-Moon](https://github.com/ASCIT31/Dark-Moon) is an autonomous pentesting platform that
wraps 50+ security tools (naabu, nuclei, httpx, subfinder, and more) inside a Docker toolbox
and exposes them via a FastMCP stdio server. The bridge in `security-knowledge/app/mcp/dark_moon_bridge.py`
discovers Dark-Moon tools at startup via MCP JSON-RPC and registers them with the `dm_` prefix.

### Enabling

1. Clone Dark-Moon and install its dependencies:
   ```bash
   git clone https://github.com/ASCIT31/Dark-Moon /opt/dark-moon
   cd /opt/dark-moon && pip install -r mcp/requirements.txt
   ```
2. Pull and start the Docker toolbox (see upstream README):
   ```bash
   docker compose -f /opt/dark-moon/docker-compose.yml up -d
   ```
3. Add to `security-knowledge/.env`:
   ```env
   DARK_MOON_ENABLED=true
   DARK_MOON_PATH=/opt/dark-moon/mcp
   DARK_MOON_PYTHON=/opt/dark-moon/.venv/bin/python   # optional
   DARK_MOON_DOCKER_CONTAINER=darkmoon               # default
   DARK_MOON_DOCKER_TIMEOUT=300                      # seconds
   DARK_MOON_OUTPUT_DIR=/opt/darkmoon/out
   ```
4. Restart: `sudo systemctl restart security-knowledge`

### Tool prefix convention

All Dark-Moon tools are registered as `dm_<upstream_name>`:

| MCP tool name | Upstream name | Description |
|---|---|---|
| `dm_get_session` | `get_session` | Current MCP session ID |
| `dm_health_check` | `health_check` | Container + tool health |
| `dm_check_tool` | `check_tool` | Check one tool is available |
| `dm_diagnose` | `diagnose` | Full environment diagnostics |
| `dm_execute_command` | `execute_command` | Run a whitelisted command in container |
| `dm_list_allowed_tools` | `list_allowed_tools` | All 30+ available tools |
| `dm_list_workflows` | `list_workflows` | Pre-built security workflows |
| `dm_run_workflow` | `run_workflow` | Execute port scan, subdomain discovery, vuln scan, etc. |

### Examples

```bash
# List all registered tools (look for dm_* entries)
curl -s -H "X-API-Key: <key>" https://z.je/api/v1/mcp/tools | python3 -m json.tool | grep dm_

# Health check
curl -X POST -H "X-API-Key: <key>" -H "Content-Type: application/json" \
  -d '{"tool":"dm_health_check","args":{}}' \
  https://z.je/api/v1/mcp/call

# Run a port scan workflow
curl -X POST -H "X-API-Key: <key>" -H "Content-Type: application/json" \
  -d '{"tool":"dm_run_workflow","args":{"workflow":"port_scan","method":"scan_ports","params":{"target":"example.com"}}}' \
  https://z.je/api/v1/mcp/call
```

### License note

Dark-Moon is licensed under **GPL v3**. It is invoked as an independent subprocess (external tool),
not incorporated into this codebase, so it does not impose GPL requirements on this project.

## Known Gaps

- ~~Historical backfill is **not** performed~~ — now in progress: full MITRE CVE List V5, GCVE, and ExploitDB corpora are imported into `corpus_documents` (FTS-indexed) and refreshed daily via arq cron at 03:17 UTC (see `scripts/refresh_corpora.sh`).
- Enrichment runs on-demand for IPs/CVEs/URLs; an idempotent backfill sweep is available via `scripts/enrich_backfill.py` (typical coverage after first sweep: CVEs ~30%, hashes ~10%, URLs near-100% via urlscan).
- GraphQL resolvers return empty data.
- MISP/OpenCTI bidirectional sync is incomplete.
- Apache catch-all proxy means non-app paths (e.g. `/lookup.txt`) are answered by FastAPI rather than the filesystem.

## Scheduled Jobs (arq cron)

| Job | Cadence | Purpose |
|---|---|---|
| `poll_feeds` | every 5 min | Polls each `SourceRecord` whose `next_poll_at` has elapsed (per-source `poll_interval` honored) |
| `send_digests` | hourly at :02 | Dispatches scheduled digest emails / webhooks (each digest's own cron schedule is checked inside) |
| `refresh_corpora` | daily 03:17 UTC | `git pull` cvelistV5/gcve/exploitdb, then re-runs idempotent importers |
| `check_ioc_watches` | event-driven | Fired after every enrichment cache miss; notifies subscribers of matched IOCs |

## Roadmap — 10 Enhancement Ideas

1. **Vector embeddings for semantic search** — embed `corpus_documents.body_text` with a local model (e.g. bge-small) into `pgvector`, expose `/search?mode=semantic` and an MCP `semantic_search` tool. Lets users find "kernel memory disclosure CVE in Linux io_uring" without knowing exact wording.
2. **CVE ↔ ExploitDB ↔ MITRE auto-linking** — background job that parses `body_text` of every corpus_document for CVE ids and ATT&CK technique ids, builds explicit edges in a `corpus_links` table, then surfaces them as "Related" panels in the entity detail UI and an MCP `entity_neighbors(id)` tool.
3. **Diff-aware feed ingestion** — per-source `last_modified` / `etag` headers + If-Modified-Since on RSS/Atom; for git-backed corpora track last-pulled SHA and only re-import touched files. Cuts daily refresh work by >95%.
4. **User saved searches + email alerts** — let users save any `/search?q=...` URL with a cadence (hourly/daily). Worker job runs each saved search, diffs against last result set, emails new hits. Backed by existing digests pipeline.
5. **Per-tenant sigma/yara rule library** — extend `detections` to store sigma + yara rules, auto-test against new ingested documents (regex/IoC match for sigma, hash+content match for yara), surface hits as `claims` with provenance.
6. **OAuth/SSO (GitHub, Google, Entra)** — replace password-only auth with optional OAuth providers; map external email→User. Adds enterprise viability and removes the "first-login admin approval" friction for trusted IdPs.
7. **TAXII 2.1 collection per tenant** — current TAXII is global; expose `/taxii2/collections/{tenant_id}/objects` so each tenant's STIX bundles are isolated. Enables MISP/OpenCTI peering with proper segregation.
8. **MCP rate-limit + per-key quotas** — currently all authenticated MCP calls share global enrichment provider quotas. Add per-API-key rate limits + per-key BYOK provider preference (`provider_keys.preferred_for_key_id`) so heavy users supply their own quotas.
9. **Public take-down / abuse contact lookup** — for any domain/IP/URL entity, auto-resolve abuse@ contact via WHOIS + RDAP + abuse.net, store on the entity, expose in UI + MCP. Massively speeds responder workflow.
10. **Audit log streaming + immutable WORM mode** — current `audit_events` are mutable rows; add an append-only forwarder (Kafka/SIEM webhook) plus optional S3 Object Lock archival, gated by `settings.AUDIT_WORM=true`. Compliance-friendly and tamper-evident.

---

> The live service at https://z.je is the source of truth. Treat code over roadmap prose.
