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

- Historical backfill is **not** performed — feeds only expose the recent N items so the knowledge base grows from the moment ingestion starts.
- Enrichment runs on-demand for IPs/CVEs/URLs; a backfill sweep across all pre-existing entities is not yet automated (typical coverage after first day: CVEs ~17%, hashes ~5%, URLs near-100% via urlscan).
- GraphQL resolvers return empty data.
- MISP/OpenCTI bidirectional sync is incomplete.
- Apache catch-all proxy means non-app paths (e.g. `/lookup.txt`) are answered by FastAPI rather than the filesystem.

---

> The live service at https://z.je is the source of truth. Treat code over roadmap prose.
