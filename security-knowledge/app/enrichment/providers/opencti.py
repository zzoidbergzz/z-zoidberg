import httpx
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register
from app.config import settings


@register
class OpenCTIProvider(BaseEnrichmentProvider):
    name = "opencti"
    kind = "indicator"

    async def enrich(self, entity_kind: str, entity_value: str) -> dict:
        if not settings.OPENCTI_URL or not settings.OPENCTI_TOKEN:
            return {}
        query = """
        query SearchStixObjects($search: String!) {
          stixCoreObjects(search: $search, first: 5) {
            edges { node { id entity_type ... on StixDomainObject { description } } }
          }
        }
        """
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                f"{settings.OPENCTI_URL}/graphql",
                json={"query": query, "variables": {"search": entity_value}},
                headers={"Authorization": f"Bearer {settings.OPENCTI_TOKEN}"},
            )
            if resp.status_code != 200:
                return {}
            data = resp.json()
            edges = data.get("data", {}).get("stixCoreObjects", {}).get("edges", [])
            return {
                "value": entity_value,
                "opencti_objects": [e["node"] for e in edges],
            }
