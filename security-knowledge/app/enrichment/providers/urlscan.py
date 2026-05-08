"""urlscan.io enrichment provider — read-only search API.

We deliberately use the public **search** endpoint
(``GET /api/v1/search/?q=...``) rather than ``/scan/`` so that:

  * we don't consume the 1000/day private-scan quota, and
  * we never accidentally publish a user-supplied URL on urlscan's
    public results feed.

Search quota is 1000 req/day, 120 req/min — comfortably above our
default per-tenant daily budget of 800.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlparse

import httpx
import structlog

from app.config import settings
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register

logger = structlog.get_logger(__name__)

_SEARCH_URL = "https://urlscan.io/api/v1/search/"
_SEARCH_LINK = "https://urlscan.io/search/#"


@register
class UrlscanProvider(BaseEnrichmentProvider):
    name = "urlscan"
    kind = "url"
    supported_kinds = {"url", "ip_address", "ip"}

    def __init__(self, api_key: str | None = None) -> None:
        super().__init__(api_key=api_key)
        self.api_key = api_key or settings.URLSCAN_API_KEY

    # ------------------------------------------------------------------ #
    # internals
    # ------------------------------------------------------------------ #

    async def _search(self, query: str) -> dict[str, Any] | None:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["API-Key"] = self.api_key
        params = {"q": query, "size": 10}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(_SEARCH_URL, headers=headers, params=params)
            if resp.status_code == 429:
                logger.warning("urlscan: rate limited (429)")
                return None
            if resp.status_code == 401:
                logger.warning("urlscan: unauthorized (401) — check API key")
                return None
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            logger.error("urlscan: http status error", status=exc.response.status_code)
            return None
        except httpx.HTTPError as exc:
            logger.error("urlscan: http error", error=str(exc))
            return None

    @staticmethod
    def _shape_result(item: dict[str, Any]) -> dict[str, Any]:
        task = item.get("task") or {}
        page = item.get("page") or {}
        verdicts = (item.get("verdicts") or {}).get("overall") or {}
        return {
            "task_time": task.get("time"),
            "task_url": task.get("url"),
            "page_domain": page.get("domain"),
            "page_ip": page.get("ip"),
            "page_country": page.get("country"),
            "page_server": page.get("server"),
            "malicious": bool(verdicts.get("malicious")),
            "score": verdicts.get("score"),
            "screenshot": item.get("screenshot"),
            "result": item.get("result"),
        }

    def _summarise(self, query: str, payload: dict[str, Any]) -> dict[str, Any]:
        results = payload.get("results") or []
        shaped = [self._shape_result(r) for r in results[:5]]
        unique_ips = sorted({r["page_ip"] for r in shaped if r.get("page_ip")})
        unique_domains = sorted({r["page_domain"] for r in shaped if r.get("page_domain")})
        any_malicious = any(r.get("malicious") for r in shaped)
        latest = shaped[0]["task_time"] if shaped else None
        return {
            "total_results": payload.get("total", len(results)),
            "results": shaped,
            "latest_scan_time": latest,
            "any_malicious": any_malicious,
            "unique_ips": unique_ips,
            "unique_domains": unique_domains,
            "urlscan_search_link": f"{_SEARCH_LINK}{quote(query, safe='')}",
        }

    # ------------------------------------------------------------------ #
    # public
    # ------------------------------------------------------------------ #

    async def enrich(self, entity_kind: str, entity_value: str) -> dict[str, Any]:
        if not self.api_key:
            return {}
        if entity_kind not in self.supported_kinds:
            return {}

        if entity_kind == "url":
            query = f'page.url:"{entity_value}"'
            payload = await self._search(query)
            if payload is None:
                return {}
            if not (payload.get("results") or []):
                # Fall back to a domain search — better recall than an exact-URL match.
                host = urlparse(entity_value).hostname
                if host:
                    fallback_query = f"domain:{host}"
                    fallback_payload = await self._search(fallback_query)
                    if fallback_payload is not None:
                        return self._summarise(fallback_query, fallback_payload)
            return self._summarise(query, payload)

        # IP kinds
        query = f'page.ip:"{entity_value}"'
        payload = await self._search(query)
        if payload is None:
            return {}
        return self._summarise(query, payload)

    async def health_check(self) -> bool:
        return bool(self.api_key)
