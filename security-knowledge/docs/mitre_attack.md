# MITRE ATT&CK Integration

The Security Knowledge service embeds the MITRE ATT&CK knowledge base via `mitreattack-python`.

## Setup

Download STIX data (requires `admin` scope API key):

```bash
curl -H "X-API-Key: $SK_API_KEY" "https://your-host/api/v1/mitre/download?domain=enterprise"
```

This downloads ~50MB of STIX 2.0 data and caches it at `MITRE_ATTACK_DATA_DIR` (default: `~/.cache/sk-mitre-data`).

## REST Endpoints

All endpoints require at minimum `read` scope.

| Endpoint | Description |
|---|---|
| `GET /api/v1/mitre/status` | Loaded domains, data dir |
| `GET /api/v1/mitre/download?domain=enterprise` | Download/refresh STIX (admin) |
| `GET /api/v1/mitre/techniques` | List all techniques |
| `GET /api/v1/mitre/techniques/{id}` | Get by ATT&CK ID (e.g. T1059) |
| `GET /api/v1/mitre/techniques/{id}/groups` | Groups using technique |
| `GET /api/v1/mitre/techniques/{id}/mitigations` | Mitigations for technique |
| `GET /api/v1/mitre/techniques/{id}/detections` | Data components detecting technique |
| `GET /api/v1/mitre/techniques/{id}/examples` | Procedure examples |
| `GET /api/v1/mitre/techniques/{id}/campaigns` | Campaigns using technique |
| `GET /api/v1/mitre/subtechniques/{id}` | Subtechniques of technique |
| `GET /api/v1/mitre/groups` | List all threat actor groups |
| `GET /api/v1/mitre/groups/{id}` | Get group (e.g. G0016) |
| `GET /api/v1/mitre/groups/{id}/techniques` | Techniques used by group |
| `GET /api/v1/mitre/groups/{id}/software` | Software used by group |
| `GET /api/v1/mitre/groups/{id}/campaigns` | Campaigns attributed to group |
| `GET /api/v1/mitre/software` | List all malware/tools |
| `GET /api/v1/mitre/software/{id}` | Get software (e.g. S0001) |
| `GET /api/v1/mitre/software/{id}/techniques` | Techniques used by software |
| `GET /api/v1/mitre/campaigns` | List all campaigns |
| `GET /api/v1/mitre/campaigns/{id}` | Get campaign (e.g. C0001) |
| `GET /api/v1/mitre/campaigns/{id}/techniques` | Techniques used by campaign |
| `GET /api/v1/mitre/mitigations` | List all mitigations |
| `GET /api/v1/mitre/mitigations/{id}/techniques` | Techniques mitigated by mitigation |
| `GET /api/v1/mitre/tactics` | List all tactics |
| `GET /api/v1/mitre/search?q=...` | Search by name |
| `GET /api/v1/mitre/search?content=...` | Search by content |
| `GET /api/v1/mitre/revoked` | Revoked techniques |
| `GET /api/v1/mitre/changes?since=YYYY-MM-DD&type=created` | Objects created/modified after date |

## MCP Tool Protocol

All 30+ MITRE ATT&CK query tools are available via the MCP tool dispatch endpoint:

```bash
POST /api/v1/mcp/call
{"tool": "get_object_by_attack_id", "args": {"attack_id": "T1059"}}
```

See `GET /api/v1/mcp/tools` for the full tool list.

## Seed MITRE Entities into the Knowledge DB

```bash
python -m seed.seed_knowledge --mitre
```

This imports all techniques, groups, software, and campaigns as `Entity` records linked by `mitre_attack_id` and `stix_id`.

## Configuration

```
MITRE_ATTACK_DATA_DIR=~/.cache/sk-mitre-data
MITRE_ATTACK_DEFAULT_DOMAIN=enterprise
```
