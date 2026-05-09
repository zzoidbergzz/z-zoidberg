<<<<<<< HEAD
"""Recorded Future enrichment provider (BYOK).

Queries the Recorded Future API for threat intelligence, risk scores,
and entity context. Follows the same BYOK pattern as other providers.

Config:
  RECORDED_FUTURE_API — API key (required, or user-supplied via BYOK)
  RECORDED_FUTURE_BASE_URL — defaults to https://api.recordedfuture.com/v2
  ENRICHMENT_TTL_RF — cache TTL in seconds (default 86400)
"""
from __future__ import annotations
from typing import Any
import httpx
import structlog
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register
from app.config import settings

logger = structlog.get_logger(__name__)
_RF_BASE = "https://api.recordedfuture.com/v2"
=======
"""Recorded Future enrichment provider.

BYOK: set RecordedFutureAPI in .env or via admin settings.
API docs: https://api.recordedfuture.com/index.html
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from app.config import settings
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register

logger = structlog.get_logger(__name__)

_SUPPORTED_KINDS = {"ip_address", "domain", "hash", "cve", "url"}
>>>>>>> 06b0054cfce62f7f038d3eed0a7ce1c535c54010


@register
class RecordedFutureProvider(BaseEnrichmentProvider):
    name = "recordedfuture"
<<<<<<< HEAD
    kind = "indicator"
    supported_kinds = {
        "ip_address", "domain", "url", "hash", "cve",
        "malware", "threat_actor",
    }

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key_override = api_key

    def _key(self) -> str | None:
        return self.api_key_override or getattr(settings, "RECORDED_FUTURE_API", "")

    async def enrich(self, entity_kind: str, entity_value: str) -> dict[str, Any]:
        key = self._key()
        if not key:
            return {}

        rf_type = self._map_type(entity_kind, entity_value)
        if not rf_type:
            return await self._search(entity_value, key)

        url = f"{_RF_BASE}/intelligence/{rf_type}/{entity_value}"
        headers = {"X-RFToken": key}
        result: dict[str, Any] = {"value": entity_value, "source": "recordedfuture"}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    result["rf_risk"] = {
                        "score": data.get("risk", {}).get("score"),
                        "criticality": data.get("risk", {}).get("criticality"),
                        "criticality_label": data.get("risk", {}).get("criticalityLabel", ""),
                    }
                    result["rf_entity"] = {
                        "name": data.get("entity", {}).get("name", ""),
                        "type": data.get("entity", {}).get("type", ""),
                        "description": (data.get("entity", {}).get("description") or "")[:500],
                    }
                    # Threat lists
                    result["rf_threat_lists"] = data.get("threatLists", [])
                    # Related entities
                    refs = data.get("entity", {}).get("relatedEntities", {})
                    if refs:
                        result["rf_related"] = {
                            k: v[:5] for k, v in refs.items() if isinstance(v, list)
                        }
        except Exception as e:
            logger.warning("rf_enrichment_failed", error=str(e), entity=entity_value)

        return result if len(result) > 2 else {}

    async def _search(self, query: str, key: str) -> dict[str, Any]:
        url = f"{_RF_BASE}/search"
        headers = {"X-RFToken": key}
        params = {"query": query, "limit": 5}
        result: dict[str, Any] = {"value": query, "source": "recordedfuture"}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    result["rf_results"] = data.get("data", [])[:5]
        except Exception as e:
            logger.warning("rf_search_failed", error=str(e))
        return result if len(result) > 2 else {}

    @staticmethod
    def _map_type(kind: str, value: str) -> str:
        mapping = {
            "ip_address": "ip",
            "domain": "domain",
            "url": "url",
            "hash": "hash",
            "cve": "vulnerability",
            "malware": "malware",
            "threat_actor": "threatactor",
        }
        return mapping.get(kind, "")

    async def health_check(self) -> bool:
        key = self._key()
        if not key:
            return False
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{_RF_BASE}/intelligence", headers={"X-RFToken": key})
                return resp.status_code in (200, 401)  # 401 = key present but invalid
        except:
            return False
=======
    display_name = "Recorded Future"

    async def enrich(self, kind: str, value: str) -> dict[str, Any]:
        if not settings.RECORDED_FUTURE_API_KEY:
            return {"provider": self.name, "status": "skipped", "error": "No API key configured"}

        if kind not in _SUPPORTED_KINDS:
            return {"provider": self.name, "status": "skipped", "error": f"Unsupported kind: {kind}"}

        headers = {"X-RFToken": settings.RECORDED_FUTURE_API_KEY}
        base = "https://api.recordedfuture.com/v2"

        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                if kind == "ip_address":
                    resp = await client.get(f"{base}/ip/{value}", params={"fields": "risk,internal"}, headers=headers)
                elif kind == "domain":
                    resp = await client.get(f"{base}/domain/{value}", params={"fields": "risk,internal"}, headers=headers)
                elif kind == "hash":
                    resp = await client.get(f"{base}/hash/{value}", headers=headers)
                elif kind == "cve":
                    resp = await client.get(f"{base}/vulnerability/{value}", headers=headers)
                elif kind == "url":
                    # Use search for URLs
                    resp = await client.get(f"{base}/search", params={"q": value, "limit": 5}, headers=headers)
                else:
                    return {"provider": self.name, "status": "skipped"}

                resp.raise_for_status()
                elapsed = int((time.monotonic() - t0) * 1000)

                return {
                    "provider": self.name,
                    "status": "ok",
                    "data": resp.json(),
                    "elapsed_ms": elapsed,
                }

        except httpx.HTTPStatusError as exc:
            elapsed = int((time.monotonic() - t0) * 1000)
            return {
                "provider": self.name,
                "status": "error",
                "error": f"HTTP {exc.response.status_code}",
                "elapsed_ms": elapsed,
            }
        except Exception as exc:
            elapsed = int((time.monotonic() - t0) * 1000)
            return {
                "provider": self.name,
                "status": "error",
                "error": str(exc),
                "elapsed_ms": elapsed,
            }
>>>>>>> 06b0054cfce62f7f038d3eed0a7ce1c535c54010
