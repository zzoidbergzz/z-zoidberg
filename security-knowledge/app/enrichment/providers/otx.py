"""AlienVault OTX enrichment provider.

Queries the OTX API for pulse data, IOCs, and threat intelligence
related to an entity. Follows the same BYOK pattern as other providers.

Config:
  OTX_KEY  — API key (required, or user-supplied via BYOK)
  OTX_BASE_URL — defaults to https://otx.alienvault.com
  ENRICHMENT_TTL_OTX — cache TTL in seconds (default 86400)
"""
from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register
from app.config import settings

logger = structlog.get_logger(__name__)

_OTX_BASE = "https://otx.alienvault.com"


@register
class OTXProvider(BaseEnrichmentProvider):
    name = "otx"
    kind = "indicator"
    supported_kinds = {
        "ip_address", "domain", "url", "hash", "cve",
        "malware", "threat_actor", "email",
    }

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key_override = api_key

    def _key(self) -> str | None:
        return self.api_key_override or getattr(settings, "OTX_KEY", "")

    async def enrich(self, entity_kind: str, entity_value: str) -> dict[str, Any]:
        key = self._key()
        if not key:
            return {}

        # Map entity kind to OTX section
        section = self._section_for_kind(entity_kind, entity_value)
        if not section:
            # Fallback: search OTX for the value
            return await self._search(entity_value, key)

        url = f"{_OTX_BASE}/api/v1/indicators/{section}/{entity_value}/general"
        headers = {"X-OTX-API-KEY": key}

        result: dict[str, Any] = {"value": entity_value, "source": "otx"}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                # General info
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    result["otx_info"] = {
                        "pulse_count": data.get("pulse_info", {}).get("count", 0),
                        "sections": data.get("sections", []),
                        "type_title": data.get("type_title", ""),
                        "base_indicator": {
                            "id": data.get("indicator", {}).get("id", ""),
                            "title": data.get("indicator", {}).get("title", ""),
                            "description": data.get("indicator", {}).get("description", "")[:500],
                            "threat_score": data.get("indicator", {}).get("threat_score"),
                            "observed_at": data.get("indicator", {}).get("observed_at", ""),
                        } if data.get("indicator") else None,
                    }

                    # Get pulses (threat intel reports referencing this indicator)
                    pulses = data.get("pulse_info", {}).get("pulses", [])
                    result["otx_pulses"] = [
                        {
                            "id": p.get("id", ""),
                            "name": p.get("name", ""),
                            "description": (p.get("description", "") or "")[:300],
                            "author": p.get("author", {}).get("username", ""),
                            "modified": p.get("modified_text", ""),
                            "tags": p.get("tags", [])[:10],
                            "targeted_countries": p.get("targeted_countries", [])[:5],
                            "attack_ids": [a.get("attack_id", "") for a in p.get("attack_ids", [])[:10]],
                            "industries": p.get("industries", [])[:5],
                        }
                        for p in pulses[:10]
                    ]

                # Try malware-specific endpoint for hashes
                if entity_kind == "hash" and len(entity_value) in (32, 40, 64):
                    mal_url = f"{_OTX_BASE}/api/v1/indicators/{section}/{entity_value}/malware"
                    mal_resp = await client.get(mal_url, headers=headers)
                    if mal_resp.status_code == 200:
                        mal_data = mal_resp.json()
                        result["otx_malware"] = mal_data.get("data", [])[:5]

                # Try URL list for domains/IPs
                if entity_kind in ("domain", "ip_address"):
                    url_list_url = f"{_OTX_BASE}/api/v1/indicators/{section}/{entity_value}/url_list"
                    url_resp = await client.get(url_list_url, headers=headers)
                    if url_resp.status_code == 200:
                        url_data = url_resp.json()
                        result["otx_url_list"] = url_data.get("url_list", [])[:10]

        except Exception as e:
            logger.warning("otx_enrichment_failed", error=str(e), entity=entity_value)

        return result if len(result) > 2 else {}

    async def _search(self, query: str, key: str) -> dict[str, Any]:
        """Search OTX for a general query term."""
        url = f"{_OTX_BASE}/api/v1/search/pulses"
        headers = {"X-OTX-API-KEY": key}
        params = {"q": query, "limit": 5}

        result: dict[str, Any] = {"value": query, "source": "otx"}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    result["otx_pulses"] = [
                        {
                            "id": p.get("id", ""),
                            "name": p.get("name", ""),
                            "description": (p.get("description", "") or "")[:300],
                            "author": p.get("author", {}).get("username", ""),
                            "tags": p.get("tags", [])[:10],
                        }
                        for p in data.get("results", [])[:5]
                    ]
        except Exception as e:
            logger.warning("otx_search_failed", error=str(e))

        return result if len(result) > 2 else {}

    @staticmethod
    def _section_for_kind(kind: str, value: str) -> str:
        """Map entity kind + value to OTX indicator section."""
        if kind == "ip_address":
            return "IPv4"
        if kind == "domain":
            return "domain"
        if kind == "url":
            return "url"
        if kind == "hash":
            v = value.lower()
            if len(v) == 32:
                return "file"  # MD5
            if len(v) == 40:
                return "file"  # SHA1
            if len(v) == 64:
                return "file"  # SHA256
        if kind == "cve":
            return "cve"
        if kind == "email":
            return "email"
        return ""

    async def health_check(self) -> bool:
        key = self._key()
        if not key:
            return False
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{_OTX_BASE}/api/v1/user/me",
                    headers={"X-OTX-API-KEY": key},
                )
                return resp.status_code == 200
        except:
            return False
