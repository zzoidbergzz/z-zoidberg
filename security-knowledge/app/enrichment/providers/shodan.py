import httpx
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register
from app.config import settings


@register
class ShodanProvider(BaseEnrichmentProvider):
    name = "shodan"
    kind = "ip"
    supported_kinds = {"ip", "ip_address"}

    async def enrich(self, entity_kind: str, entity_value: str) -> dict:
        if entity_kind not in ("ip", "ip_address"):
            return {}
        api_key = self.api_key_override or settings.SHODAN_API_KEY
        if not api_key:
            return {}
        url = f"https://api.shodan.io/shodan/host/{entity_value}?key={api_key}"
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url)
            if resp.status_code == 404:
                return {}
            resp.raise_for_status()
            data = resp.json()
            return {
                "ip": entity_value,
                "org": data.get("org"),
                "country": data.get("country_name"),
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "tags": data.get("tags", []),
            }
