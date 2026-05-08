# z.je Security Knowledge API Reference

- **Base URL:** https://z.je
- **Auth:** `X-API-Key: <your-api-key>`
- **Swagger UI:** https://z.je/docs
- **ReDoc:** https://z.je/redoc
- **OpenAPI JSON:** https://z.je/openapi.json

## Quick API Calls

```bash
API="https://z.je"
KEY="YxjXShQyv8L_-X_1Qb6DDSF9JvPXGer5_yTztqgvCAQ"

# List MCP tools
curl -s -H "X-API-Key: $KEY" "$API/api/v1/mcp/tools"

# Call MCP tool
curl -s -H "X-API-Key: $KEY" -X POST "$API/api/v1/mcp/call" \
  -H "Content-Type: application/json" \
  -d '{"tool":"lookup_cve","args":{"cve_id":"CVE-2024-3094"}}'

# Search knowledge base
curl -s -H "X-API-Key: $KEY" "$API/api/v1/search/?q=CVE-2024&limit=5"

# Enrich IOC
curl -s -H "X-API-Key: $KEY" -X POST "$API/api/v1/mcp/call" \
  -H "Content-Type: application/json" \
  -d '{"tool":"enrich_entity","args":{"entity_kind":"ip","entity_value":"8.8.8.8"}}'
```

## 43 MCP Tools

### Core
- `enrich_entity` — Enrich IOC with all providers (entity_kind, entity_value)
- `lookup_cve` — CVE details with CVSS (cve_id)
- `search_knowledge` — FTS across knowledge base (query, limit)
- `list_entities` — List entities (kind, limit, offset)
- `get_entity` — Single entity with relationships (entity_id)
- `create_entity` — Create threat entity (name, kind, description)
- `create_claim` — Add claim to entity (entity_id, claim_text, source)
- `create_evidence` — Attach evidence to claim (claim_id, evidence_text, source_url)
- `export_stix_bundle` — Export as STIX 2.1 (entity_ids)
- `get_changes_since` — Changed entities since timestamp (since)
- `searxng_search` — Private web search (query)

### MITRE ATT&CK (30+ tools)
- `get_all_techniques`, `get_all_subtechniques`, `get_all_groups`, `get_all_software`, `get_all_mitigations`, `get_all_tactics`, `get_all_campaigns`
- `get_object_by_attack_id`, `get_object_by_stix_id`, `get_objects_by_name`, `get_objects_by_content`
- `get_techniques_used_by_group`, `get_software_used_by_group`, `get_campaigns_attributed_to_group`
- `get_groups_using_technique`, `get_groups_using_software`, `get_techniques_used_by_software`
- `get_subtechniques_of_technique`, `get_parent_technique_of_subtechnique`
- `get_techniques_by_tactic`, `get_techniques_by_platform`
- `get_mitigations_mitigating_technique`, `get_datacomponents_detecting_technique`
- `get_procedure_examples_by_technique`, `get_techniques_used_by_campaign`, `get_campaigns_using_technique`
- `get_techniques_mitigated_by_mitigation`
- `get_objects_created_after`, `get_objects_modified_after`
- `get_revoked_techniques`, `get_groups_by_alias`, `get_software_by_alias`

## 11 Enrichment Providers
VirusTotal, Shodan, CrowdStrike, GreyNoise, IPinfo, AbuseIPDB, BGP.he.net, MISP, OpenCTI, NVD, MITRE ATT&CK

## Verified Working
- ✅ Auth via X-API-Key
- ✅ 115 REST endpoints
- ✅ 43 MCP tools
- ✅ Swagger UI (/docs) + ReDoc (/redoc)
- ✅ CVE lookup with CVSS details
- ✅ IOC enrichment (AbuseIPDB, BGP.he confirmed)
- ✅ Knowledge search (FTS)
- ✅ SSE transport at /api/v1/mcp/sse
