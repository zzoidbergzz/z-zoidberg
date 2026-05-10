"""C2 Workbench enrichment provider.

Returns matching C2 framework data from c2workbench.com API
for malware, hash, tool, and framework entities.
"""

import httpx
import structlog

from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register

logger = structlog.get_logger(__name__)

_C2WB_API = "https://www.c2workbench.com/api/frameworks"


@register
class C2WorkbenchProvider(BaseEnrichmentProvider):
    name = "c2workbench"
    kind = "framework"
    supported_kinds = {"malware", "hash", "tool", "framework", "actor"}

    def __init__(self, api_key: str | None = None, **kw):
        super().__init__(api_key=api_key)

    async def enrich(self, entity_kind: str, entity_value: str) -> dict:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(_C2WB_API, params={"search": entity_value})
                if resp.status_code != 200:
                    return {}
                data = resp.json()
        except httpx.HTTPError as exc:
            logger.error("c2workbench: http error", error=str(exc))
            return {}

        frameworks = data if isinstance(data, list) else data.get("frameworks", data.get("items", []))
        matches = []
        query_lower = entity_value.lower()
        for fw in frameworks:
            name = (fw.get("canonical_name") or "").lower()
            desc = (fw.get("description") or "").lower()
            aliases = fw.get("aliases") or []
            alias_match = any(query_lower in (a or "").lower() for a in aliases)
            if query_lower in name or query_lower in desc or alias_match:
                matches.append({
                    "name": fw.get("canonical_name"),
                    "type": fw.get("framework_type"),
                    "description": fw.get("unique_description") or fw.get("description"),
                    "language": fw.get("primary_language"),
                    "maturity": fw.get("estimated_maturity"),
                    "supported_os": fw.get("supported_os", []),
                    "capabilities": (fw.get("capability_tags") or [])[:15],
                    "popularity": fw.get("popularity_score"),
                    "c2wb_link": f"https://www.c2workbench.com/framework/{fw.get('canonical_name', '')}",
                })
            if len(matches) >= 5:
                break

        if not matches:
            return {}

        return {
            "value": entity_value,
            "matches": matches,
            "total": len(matches),
        }
