"""urlscan.io enrichment provider — read-only search API + opt-in rescan.

We deliberately use the public **search** endpoint
(``GET /api/v1/search/?q=...``) for lookups so that:

  * we don't consume the 1000/day private-scan quota, and
  * we never accidentally publish a user-supplied URL on urlscan's
    public results feed.

When ``enable_rescan`` is True (and the entity kind is ``url`` or
``domain``), we additionally submit the target via ``POST /api/v1/scan/``
with ``visibility="unlisted"`` (cheaper quota, results not on the public
feed), return a ``requested/pending`` rescan block, and let the background
poller persist the completed result back into the enrichment cache.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import quote, urlparse

import httpx
import structlog

from app.config import settings
from app.enrichment import budget
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.providers._rescan_common import utcnow_iso
from app.enrichment.registry import register

logger = structlog.get_logger(__name__)

_SEARCH_URL = "https://urlscan.io/api/v1/search/"
_SEARCH_LINK = "https://urlscan.io/search/#"
_SCAN_URL = "https://urlscan.io/api/v1/scan/"
_RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"

_PENDING_STATUS = "requested/pending"
_RESCAN_POLL_SECONDS = 60.0
_RESCAN_BUDGET_KEY = "urlscan_submit"

# Cap concurrent rescans per process — module global per spec.
_RESCAN_SEMAPHORE = asyncio.Semaphore(3)


@register
class UrlscanProvider(BaseEnrichmentProvider):
    name = "urlscan"
    kind = "url"
    supported_kinds = {"url", "domain", "ip_address", "ip"}

    def __init__(self, api_key: str | None = None, enable_rescan: bool = True) -> None:
        super().__init__(api_key=api_key)
        self.api_key = api_key or settings.URLSCAN_API_KEY
        self.enable_rescan = enable_rescan

    # ------------------------------------------------------------------ #
    # internals — search
    # ------------------------------------------------------------------ #

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if self.api_key:
            h["API-Key"] = self.api_key
        return h

    @staticmethod
    def _scan_target(entity_kind: str, entity_value: str) -> str | None:
        if entity_kind == "domain":
            host = urlparse(entity_value).hostname or entity_value
            host = host.strip().strip(".")
            if not host:
                return None
            return f"https://{host}/"
        return entity_value

    @staticmethod
    def _search_query(entity_kind: str, entity_value: str) -> str:
        if entity_kind == "domain":
            host = urlparse(entity_value).hostname or entity_value
            host = host.strip().strip(".")
            return f'domain:"{host}"'
        return f'page.url:"{entity_value}"'

    async def _search(self, query: str) -> dict[str, Any] | None:
        params = {"q": query, "size": 10}
        try:
            async with httpx.AsyncClient(timeout=15, headers=self._headers()) as client:
                resp = await client.get(_SEARCH_URL, params=params)
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
    # internals — rescan
    # ------------------------------------------------------------------ #

    @staticmethod
    def _shape_result_payload(payload: dict[str, Any]) -> dict[str, Any]:
        verdicts_overall = ((payload.get("verdicts") or {}).get("overall")) or {}
        page = payload.get("page") or {}
        task = payload.get("task") or {}
        lists = payload.get("lists") or {}
        ips = lists.get("ips") or []
        countries = lists.get("countries") or []
        return {
            "malicious": bool(verdicts_overall.get("malicious")),
            "score": verdicts_overall.get("score"),
            "page_domain": page.get("domain"),
            "page_ip": page.get("ip"),
            "page_country": page.get("country"),
            "ips": list(ips),
            "ips_count": len(ips),
            "countries": list(countries),
            "screenshot_url": task.get("screenshotURL"),
            "report_url": task.get("reportURL"),
        }

    @staticmethod
    def _diff(before: dict[str, Any] | None, after: dict[str, Any]) -> dict[str, Any]:
        before = before or {}
        before_score = before.get("score") or 0
        after_score = after.get("score") or 0
        before_ips = set(before.get("ips") or ([before.get("page_ip")] if before.get("page_ip") else []))
        after_ips = set(after.get("ips") or [])
        before_domains = {before.get("page_domain")} if before.get("page_domain") else set()
        after_domains = {after.get("page_domain")} if after.get("page_domain") else set()
        before_countries = set(before.get("countries") or ([before.get("page_country")] if before.get("page_country") else []))
        after_countries = set(after.get("countries") or [])
        return {
            "malicious_changed": bool(before.get("malicious")) != bool(after.get("malicious")),
            "score_diff": after_score - before_score,
            "new_ips": sorted(after_ips - before_ips),
            "new_domains": sorted(after_domains - before_domains - {None}),
            "new_countries": sorted(after_countries - before_countries),
        }

    async def _submit(self, client: httpx.AsyncClient, url: str) -> tuple[str | None, str | None]:
        body = {
            "url": url,
            "visibility": "unlisted",
            "tags": ["security-knowledge", "auto-rescan"],
        }
        try:
            resp = await client.post(_SCAN_URL, json=body)
        except httpx.HTTPError as exc:
            return None, f"submit_http_error:{exc.__class__.__name__}"
        if resp.status_code == 429:
            return None, "submit_rate_limited_429"
        if resp.status_code == 401:
            return None, "submit_unauthorized_401"
        if resp.status_code >= 400:
            return None, f"submit_status_{resp.status_code}"
        try:
            data = resp.json()
        except ValueError:
            return None, "submit_invalid_json"
        uuid = data.get("uuid")
        if not uuid:
            return None, "submit_no_uuid"
        return uuid, None

    async def _request_rescan(self, url: str, before: dict[str, Any] | None = None) -> dict[str, Any]:
        submitted_at = utcnow_iso()
        async with httpx.AsyncClient(timeout=20, headers=self._headers()) as client:
            uuid, err = await self._submit(client, url)
            if err:
                return {"submitted_at": submitted_at, "scan_id": uuid, "errors": [err]}
            pending: dict[str, Any] = {
                "submitted_at": submitted_at,
                "scan_id": uuid,
                "status": _PENDING_STATUS,
                "poll_after_seconds": _RESCAN_POLL_SECONDS,
                "scan_url": _RESULT_URL.format(uuid=uuid),
                "errors": [],
            }
            if before is not None:
                pending["before"] = before
            return pending

    async def _maybe_rescan(
        self, url: str, before: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        if not self.enable_rescan:
            return None
        if not getattr(settings, "URLSCAN_RESCAN_ENABLED", True):
            return None
        if not self.api_key:
            return None
        if not await budget.check_and_increment(
            _RESCAN_BUDGET_KEY,
            daily=getattr(settings, "URLSCAN_SUBMIT_DAILY_BUDGET", 900),
        ):
            return {"skipped": "budget_exhausted"}
        async with _RESCAN_SEMAPHORE:
            try:
                return await self._request_rescan(url, before=before)
            except Exception as exc:  # never raise out of provider
                logger.error("urlscan: rescan unexpected error", error=str(exc))
                return {"errors": [f"unexpected:{exc.__class__.__name__}"]}

    # ------------------------------------------------------------------ #
    # public
    # ------------------------------------------------------------------ #

    async def enrich(self, entity_kind: str, entity_value: str) -> dict[str, Any]:
        if not self.api_key:
            return {}
        if entity_kind not in self.supported_kinds:
            return {}

        if entity_kind in {"url", "domain"}:
            query = self._search_query(entity_kind, entity_value)
            payload = await self._search(query)
            summary: dict[str, Any] | None = None
            if payload is None:
                summary = None
            elif not (payload.get("results") or []):
                # Fall back to a domain search — better recall than an exact-URL match.
                host = urlparse(entity_value).hostname or entity_value
                host = host.strip().strip(".")
                if host:
                    fallback_query = f'domain:"{host}"'
                    fallback_payload = await self._search(fallback_query)
                    if fallback_payload is not None:
                        summary = self._summarise(fallback_query, fallback_payload)
                if summary is None:
                    summary = self._summarise(query, payload)
            else:
                summary = self._summarise(query, payload)

            scan_target = self._scan_target(entity_kind, entity_value)
            rescan_before = (summary or {}).get("results", [None])[:1]
            before_baseline = rescan_before[0] if rescan_before else None
            rescan = await self._maybe_rescan(scan_target, before_baseline) if scan_target else None
            if summary is None:
                summary = {}
            if rescan is not None:
                summary["rescan"] = rescan
            return summary

        # IP kinds — no rescan path (IPs cannot be submitted to a URL scanner)
        query = f'page.ip:"{entity_value}"'
        payload = await self._search(query)
        if payload is None:
            return {}
        return self._summarise(query, payload)

    async def health_check(self) -> bool:
        return bool(self.api_key)
