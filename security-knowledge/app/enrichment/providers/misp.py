try:
    from pymisp import ExpandedPyMISP
    HAS_PYMISP = True
except ImportError:
    HAS_PYMISP = False

from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register
from app.config import settings


@register
class MISPProvider(BaseEnrichmentProvider):
    name = "misp"
    kind = "indicator"

    async def enrich(self, entity_kind: str, entity_value: str) -> dict:
        if not HAS_PYMISP or not settings.MISP_URL or not settings.MISP_KEY:
            return {}
        misp = ExpandedPyMISP(settings.MISP_URL, settings.MISP_KEY, ssl=settings.MISP_VERIFYCERT)
        result = misp.search(value=entity_value, pythonify=True)
        events = result if isinstance(result, list) else []
        return {
            "value": entity_value,
            "misp_events": [{"id": e.id, "info": e.info} for e in events[:10]],
        }
