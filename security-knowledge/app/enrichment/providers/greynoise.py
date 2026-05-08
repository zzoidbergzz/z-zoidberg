"""GreyNoise enrichment provider — IP internet noise classification."""
from __future__ import annotations

import httpx

from app.config import settings
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register


@register
class GreyNoiseProvider(BaseEnrichmentProvider):
    name = "greynoise"
    kind = "ip"
    supported_kinds = {"ip", "ip_address", "indicator"}

    _BASE = "https://api.greynoise.io/v3"

    async def enrich(self, entity_kind: str, entity_value: str) -> dict:
        api_key = self.api_key_override or settings.GREYNOISE_API_KEY
        if not api_key:
            return {}
        if entity_kind not in ("ip", "ip_address", "indicator"):
            return {}

        headers = {"key": api_key}
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{self._BASE}/community/{entity_value}",
                headers=headers,
            )
            if resp.status_code == 404:
                return {"ip": entity_value, "noise": False, "riot": False, "classification": "unknown"}
            if resp.status_code == 429:
                return {}  # rate limited — return empty so caller can retry
            resp.raise_for_status()
            data = resp.json()

        return {
            "ip": data.get("ip"),
            "noise": data.get("noise", False),
            "riot": data.get("riot", False),
            "classification": data.get("classification"),
            "name": data.get("name"),
            "link": data.get("link"),
            "last_seen": data.get("last_seen"),
            "message": data.get("message"),
        }

    async def health_check(self) -> bool:
        return bool(settings.GREYNOISE_API_KEY)
