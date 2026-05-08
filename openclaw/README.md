# OpenClaw MCP Integration

Connect Zoidberg (your OpenClaw agent) to the Security Knowledge platform via MCP.

## Quick Start

### 1. Create an API key

```bash
cd security-knowledge
python -c "
import asyncio, uuid
from app.database import AsyncSessionLocal
from app.models.auth import ApiKey, User, UserRole, UserStatus
from sqlalchemy import select

async def main():
    async with AsyncSessionLocal() as db:
        # Find admin user
        res = await db.execute(select(User).where(User.role == UserRole.admin))
        admin = res.scalar_one_or_none()
        if not admin:
            print('No admin user found. Bootstrap the service first.')
            return
        key = ApiKey(
            id=uuid.uuid4(),
            tenant_id=admin.tenant_id,
            user_id=admin.id,
            name='openclaw-mcp',
            key_hash='',  # set by set_raw_key
            scopes='superadmin',
            active=True,
        )
        raw = await key.set_raw_key()
        db.add(key)
        await db.commit()
        print(f'API Key: {raw}')

asyncio.run(main())
"
```

### 2. Configure OpenClaw

Add to your OpenClaw MCP config (via `openclaw` CLI or gateway config):

**SSE Transport (remote / hosted):**

```json
{
  "mcpServers": {
    "security-knowledge": {
      "transport": "sse",
      "url": "https://your-sk-host/api/v1/mcp/sse",
      "headers": {
        "X-API-Key": "<your-api-key>"
      }
    }
  }
}
```

**Stdio Transport (local):**

```json
{
  "mcpServers": {
    "security-knowledge": {
      "command": "python",
      "args": ["-m", "app.mcp.server"],
      "cwd": "/path/to/z-zoidberg/security-knowledge",
      "env": {
        "SK_API_KEY": "<your-api-key>",
        "DATABASE_URL": "postgresql+asyncpg://sk:sk@localhost/sk"
      }
    }
  }
}
```

### 3. Use from OpenClaw

Once connected, all 13+ MCP tools are available:

| Tool | Description |
|------|-------------|
| `enrich_entity` | Enrich an IOC with all configured providers |
| `lookup_cve` | Look up CVE details with CVSS and references |
| `search_knowledge` | Full-text search across the knowledge base |
| `list_entities` | List entities with optional type filter |
| `get_entity` | Get a single entity with relationships |
| `create_entity` | Create a new threat entity |
| `create_claim` | Add a claim to an existing entity |
| `create_evidence` | Attach evidence to a claim |
| `export_stix_bundle` | Export entities as STIX 2.1 bundle |
| `get_changes_since` | Get entities changed since a timestamp |
| `mitre_lookup_technique` | Look up MITRE ATT&CK techniques |
| `mitre_search` | Search MITRE ATT&CK by keyword |
| `mitre_sector_mapping` | Map techniques to industry sectors |
| `searxng_search` | Private web search via SearXNG |

## Architecture

```
OpenClaw Agent
    │
    ▼ SSE / HTTP
┌──────────────────┐
│  /api/v1/mcp/sse │  ← Starlette SSE transport
│  /api/v1/mcp/call│  ← REST fallback
└──────┬───────────┘
       │
  ┌────▼────┐
  │ Registry │  ← 13+ tools, auto-discovered
  └────┬────┘
       │
  ┌────▼──────────────┐
  │ EnrichmentService │  ← 11 providers, budget-gated
  │ SearchService     │  ← FTS + pg_trgm hybrid
  │ MITREService      │  ← ATT&CK technique mapping
  │ IngestionService  │  │ Feed poller worker
  └───────────────────┘
```

## API Key Scopes

| Scope | Access |
|-------|--------|
| `superadmin` | Full access to all tools |
| `read` | Lookup, search, list, get |
| `write` | Create entities, claims, evidence |
| `enrichment` | Trigger enrichment lookups |
| `export` | STIX export, context packs |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SK_API_KEY` | Yes | API key for authentication |
| `DATABASE_URL` | Stdio only | PostgreSQL connection string |
| `BOOTSTRAP_ADMIN_TENANT` | Stdio only | Tenant ID for auth context |

## Security Notes

- API keys are bcrypt-hashed in the database; the raw key is shown once at creation
- SSE transport authenticates every request via `X-API-Key` header
- All MCP tool calls respect RBAC scopes
- BYOK provider keys are encrypted at rest with `BYOK_ENCRYPTION_KEY`
