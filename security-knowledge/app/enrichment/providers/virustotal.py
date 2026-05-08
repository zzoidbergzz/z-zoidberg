import httpx
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register
from app.config import settings


@register
class VirusTotalProvider(BaseEnrichmentProvider):
    name = "virustotal"
    kind = "indicator"
    supported_kinds = {"ip", "ip_address", "domain", "url", "hash", "indicator"}

    async def enrich(self, entity_kind: str, entity_value: str) -> dict:
        api_key = self.api_key_override or settings.VIRUSTOTAL_API_KEY
        if not api_key:
            return {}
        kind_map = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}
        resource_type = kind_map.get(entity_kind)
        if not resource_type:
            return {}
        url = f"https://www.virustotal.com/api/v3/{resource_type}/{entity_value}"
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers={"x-apikey": api_key})
            if resp.status_code == 404:
                return {}
            resp.raise_for_status()
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "value": entity_value,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": attrs.get("reputation"),
            }
