# z.je — OSINT Research Platform

The `security-knowledge/` FastAPI service is live at **https://z.je** and powers the z.je analyst workspace. It merges the OSINT lookup/pivot/fingerprint interface from `mzje/z` with the threat-intelligence knowledge base scaffolding of the original security-knowledge project.

## What's Live

### Auth & Access
- Everything requires login — no content is exposed without an authenticated session.
- `POST /api/v1/auth/login` — email + password → JWT + httpOnly `sk_session` cookie (7 days).
- `POST /api/v1/auth/register` — account creation (pending approval by admin).
- `POST /api/v1/auth/logout` — clears session cookie.
- `POST /api/v1/auth/token` — API key → JWT for programmatic access.
- Bootstrap admin `m@z.je` is created automatically on first startup from `.env`.

### Browser UI (all at root paths on https://z.je)

| Path | Page |
|---|---|
| `/` | OSINT research: lookup, bulk lookup, path finder, enrichment, graph |
| `/fp` | Browser fingerprint — server metadata + client JS entropy, logged to DB |
| `/investigation` | Group entities into named investigations |
| `/graph` | Pivot graph explorer |
| `/entities` | Entity browser |
| `/search` | Full-text search |
| `/admin` | Admin panel (admin role required) |
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

## Known Gaps

- Ingestion worker (`process_ingest_job`) is a stub — creates job record but does not fetch/parse/embed.
- Search uses `ILIKE` rather than the FTS/trigram migrations.
- GraphQL resolvers return empty data.
- MISP/OpenCTI bidirectional sync is incomplete.

---

> The live service at https://z.je is the source of truth. Treat code over roadmap prose.
