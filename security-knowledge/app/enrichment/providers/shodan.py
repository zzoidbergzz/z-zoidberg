import httpx
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register
from app.config import settings


@register
class ShodanProvider(BaseEnrichmentProvider):
    name = "shodan"
    kind = "ip"

    async def enrich(self, entity_kind: str, entity_value: str) -> dict:
        if entity_kind not in ("ip",):
            return {}
        if not settings.SHODAN_API_KEY:
            return {}
        url = f"https://api.shodan.io/shodan/host/{entity_value}?key={settings.SHODAN_API_KEY}"
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
