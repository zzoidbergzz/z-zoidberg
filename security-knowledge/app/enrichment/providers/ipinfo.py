"""IPinfo enrichment provider — IP geolocation, ASN, org, and abuse data."""
from __future__ import annotations

import httpx

from app.config import settings
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register


@register
class IPinfoProvider(BaseEnrichmentProvider):
    name = "ipinfo"
    kind = "ip"

    async def enrich(self, entity_kind: str, entity_value: str) -> dict:
        if not settings.IPINFO_TOKEN:
            return {}
        if entity_kind not in ("ip", "indicator"):
            return {}

        url = f"https://ipinfo.io/{entity_value}/json"
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers={"Authorization": f"Bearer {settings.IPINFO_TOKEN}"})
            if resp.status_code == 404:
                return {}
            resp.raise_for_status()
            data = resp.json()

        abuse = data.get("abuse", {})
        return {
            "ip": data.get("ip"),
            "hostname": data.get("hostname"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "org": data.get("org"),
            "asn": data.get("asn", {}).get("asn") if isinstance(data.get("asn"), dict) else None,
            "timezone": data.get("timezone"),
            "latitude": data.get("loc", "").split(",")[0] if data.get("loc") else None,
            "longitude": data.get("loc", "").split(",")[1] if data.get("loc") and "," in data.get("loc", "") else None,
            "abuse_email": abuse.get("email"),
            "abuse_network": abuse.get("network"),
        }

    async def health_check(self) -> bool:
        return bool(settings.IPINFO_TOKEN)
