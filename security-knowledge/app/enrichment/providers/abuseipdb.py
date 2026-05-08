"""AbuseIPDB enrichment provider — IP abuse confidence scoring."""

from __future__ import annotations

import httpx

from app.config import settings
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register


@register
class AbuseIPDBProvider(BaseEnrichmentProvider):
    name = "abuseipdb"
    kind = "ip"
    supported_kinds = {"ip", "ip_address", "indicator"}

    _BASE = "https://api.abuseipdb.com/api/v2"

    async def enrich(self, entity_kind: str, entity_value: str) -> dict:
        api_key = self.api_key_override or settings.ABUSEIPDB_API_KEY
        if not api_key:
            return {}
        if entity_kind not in ("ip", "ip_address", "indicator"):
            return {}

        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": entity_value, "maxAgeInDays": 90, "verbose": True}

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{self._BASE}/check", headers=headers, params=params)
            if resp.status_code == 422:
                # Not a valid IP (e.g. domain passed through indicator kind)
                return {}
            if resp.status_code == 429:
                return {}  # rate limited
            resp.raise_for_status()
            data = resp.json().get("data", {})

        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        last_reported = data.get("lastReportedAt")
        hostnames = data.get("hostnames") or []

        return {
            "ip": data.get("ipAddress"),
            "abuse_score": score,
            "total_reports": reports,
            "last_reported_at": last_reported,
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "hostnames": hostnames[:10],
            "is_public": data.get("isPublic"),
            "is_whitelisted": data.get("isWhitelisted"),
            "is_tor": data.get("isTor"),
            "is_proxy": data.get("isDatacenter") or data.get("isProxy"),
            "num_distinct_users": data.get("numDistinctUsers"),
            "abuseipdb_link": f"https://www.abuseipdb.com/check/{entity_value}",
        }

    async def health_check(self) -> bool:
        return bool(settings.ABUSEIPDB_API_KEY)
