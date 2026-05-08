"""
VirusTotal enrichment provider.

Free-tier constraints (2025):
  - 4 requests / minute
  - 500 requests / day
  - 15.5 K requests / month
  - Must NOT be used in commercial products/services

The module-level rate limiter enforces the per-minute cap with a sliding
window of timestamps so we never burst past 4 req/min.

For ``kind == "url"`` and when ``enable_rescan`` is True, the provider
additionally re-submits the URL via ``POST /api/v3/urls``, polls the
returned analysis until it completes, then re-fetches the URL object so
callers receive a ``rescan`` block containing before/after detection
stats plus a delta. The submit path is independently quota-gated.
"""

import asyncio
import base64
import time
from collections import deque

import httpx
import structlog

from app.config import settings
from app.enrichment import budget
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.providers._rescan_common import utcnow_iso
from app.enrichment.registry import register

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Per-minute rate-limiter (module-level, shared across all requests)
# ---------------------------------------------------------------------------

_rate_lock = asyncio.Lock()
_req_timestamps: deque[float] = deque()
_VT_MAX_PER_MINUTE = 4


async def _rate_limit() -> None:
    """Block until we have capacity under the 4 req/min sliding window."""
    async with _rate_lock:
        now = time.monotonic()
        while _req_timestamps and (now - _req_timestamps[0]) > 60.0:
            _req_timestamps.popleft()
        if len(_req_timestamps) >= _VT_MAX_PER_MINUTE:
            sleep_for = 60.0 - (now - _req_timestamps[0]) + 0.05
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            now = time.monotonic()
            while _req_timestamps and (now - _req_timestamps[0]) > 60.0:
                _req_timestamps.popleft()
        _req_timestamps.append(time.monotonic())


# ---------------------------------------------------------------------------
# Rescan tunables
# ---------------------------------------------------------------------------

_RESCAN_OVERALL_TIMEOUT = 180.0
_RESCAN_POLL_INTERVAL = 6.0
_RESCAN_POLL_DEADLINE = 150.0
_RESCAN_BUDGET_KEY = "virustotal_submit"
_RESCAN_SEMAPHORE = asyncio.Semaphore(3)

_VT_BASE = "https://www.virustotal.com/api/v3"


def _vt_url_id(url: str) -> str:
    """Return the canonical VT URL identifier (urlsafe base64, no padding)."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------

# Maps entity kind → VT API resource path segment.
_KIND_MAP: dict[str, str | None] = {
    "ip": "ip_addresses",
    "ip_address": "ip_addresses",
    "domain": "domains",
    "hostname": "domains",
    "hash": "files",
    "md5": "files",
    "sha1": "files",
    "sha256": "files",
    "url": "urls",
    "indicator": None,
}


@register
class VirusTotalProvider(BaseEnrichmentProvider):
    name = "virustotal"
    kind = "indicator"
    supported_kinds = {"ip", "ip_address", "domain", "hostname", "url", "hash", "md5", "sha1", "sha256", "indicator"}

    def __init__(self, api_key: str | None = None, enable_rescan: bool = True) -> None:
        super().__init__(api_key=api_key)
        self.enable_rescan = enable_rescan

    def _api_key(self) -> str:
        return self.api_key_override or settings.VIRUSTOTAL_API_KEY

    # ------------------------------------------------------------------ #
    # Lookup helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _shape_url_attrs(attrs: dict) -> dict:
        results = attrs.get("last_analysis_results") or {}
        # Engines flagging malicious/suspicious, capped at 5 detections
        flagged = [
            (engine, (info or {}).get("category"))
            for engine, info in results.items()
            if (info or {}).get("category") in ("malicious", "suspicious")
        ][:5]
        return {
            "stats": dict(attrs.get("last_analysis_stats") or {}),
            "reputation": attrs.get("reputation"),
            "total_votes": dict(attrs.get("total_votes") or {}),
            "top_detections": [{"engine": e, "category": c} for e, c in flagged],
            "last_analysis_date": attrs.get("last_analysis_date"),
        }

    @staticmethod
    def _diff(before: dict | None, after: dict) -> dict:
        b = before or {}
        bs = b.get("stats") or {}
        as_ = after.get("stats") or {}
        keys = ("malicious", "suspicious", "harmless", "undetected", "timeout")
        stats_diff = {k: int(as_.get(k, 0)) - int(bs.get(k, 0)) for k in keys}
        before_flagged = {d["engine"] for d in (b.get("top_detections") or [])}
        after_flagged = [d for d in (after.get("top_detections") or []) if d["engine"] not in before_flagged]
        b_rep = b.get("reputation") or 0
        a_rep = after.get("reputation") or 0
        return {
            "stats_diff": stats_diff,
            "reputation_diff": a_rep - b_rep,
            "new_detections": after_flagged,
        }

    async def _vt_get(self, client: httpx.AsyncClient, path: str) -> tuple[httpx.Response | None, str | None]:
        try:
            resp = await client.get(f"{_VT_BASE}{path}")
        except httpx.HTTPError as exc:
            return None, f"http_error:{exc.__class__.__name__}"
        return resp, None

    async def _fetch_url_snapshot(
        self, client: httpx.AsyncClient, url: str
    ) -> tuple[dict | None, str | None]:
        await _rate_limit()
        resp, err = await self._vt_get(client, f"/urls/{_vt_url_id(url)}")
        if err:
            return None, err
        if resp.status_code == 404:
            return None, "not_found"
        if resp.status_code == 429:
            return None, "rate_limited_429"
        if resp.status_code >= 400:
            return None, f"status_{resp.status_code}"
        try:
            data = resp.json()
        except ValueError:
            return None, "invalid_json"
        attrs = (data.get("data") or {}).get("attributes") or {}
        return self._shape_url_attrs(attrs), None

    async def _submit_url(
        self, client: httpx.AsyncClient, url: str
    ) -> tuple[str | None, str | None]:
        await _rate_limit()
        try:
            resp = await client.post(f"{_VT_BASE}/urls", data={"url": url})
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
        analysis_id = (data.get("data") or {}).get("id")
        if not analysis_id:
            return None, "submit_no_analysis_id"
        return analysis_id, None

    async def _poll_analysis(
        self, client: httpx.AsyncClient, analysis_id: str
    ) -> tuple[bool, str | None]:
        loop = asyncio.get_event_loop()
        deadline = loop.time() + _RESCAN_POLL_DEADLINE
        while loop.time() < deadline:
            await _rate_limit()
            resp, err = await self._vt_get(client, f"/analyses/{analysis_id}")
            if err:
                return False, err
            if resp.status_code == 429:
                await asyncio.sleep(_RESCAN_POLL_INTERVAL)
                continue
            if resp.status_code >= 400:
                return False, f"poll_status_{resp.status_code}"
            try:
                payload = resp.json()
            except ValueError:
                return False, "poll_invalid_json"
            status = ((payload.get("data") or {}).get("attributes") or {}).get("status")
            if status == "completed":
                return True, None
            await asyncio.sleep(_RESCAN_POLL_INTERVAL)
        return False, "poll_deadline_exceeded"

    async def _do_rescan(self, url: str, before: dict | None, api_key: str) -> dict:
        submitted_at = utcnow_iso()
        async with httpx.AsyncClient(timeout=30, headers={"x-apikey": api_key}) as client:
            analysis_id, err = await self._submit_url(client, url)
            if err:
                return {"submitted_at": submitted_at, "scan_id": analysis_id, "errors": [err]}
            ok, err = await self._poll_analysis(client, analysis_id)
            completed_at = utcnow_iso()
            if not ok:
                return {
                    "submitted_at": submitted_at,
                    "completed_at": completed_at,
                    "scan_id": analysis_id,
                    "errors": [err or "poll_failed"],
                }
            after, err = await self._fetch_url_snapshot(client, url)
            if err or after is None:
                return {
                    "submitted_at": submitted_at,
                    "completed_at": completed_at,
                    "scan_id": analysis_id,
                    "errors": [err or "after_fetch_failed"],
                }
            return {
                "submitted_at": submitted_at,
                "completed_at": completed_at,
                "scan_id": analysis_id,
                "before": before,
                "after": after,
                "delta": self._diff(before, after),
                "errors": [],
            }

    async def _maybe_rescan(self, url: str, before: dict | None, api_key: str) -> dict | None:
        if not self.enable_rescan:
            return None
        if not getattr(settings, "VIRUSTOTAL_RESCAN_ENABLED", True):
            return None
        if not api_key:
            return None
        if not await budget.check_and_increment(
            _RESCAN_BUDGET_KEY,
            daily=getattr(settings, "VIRUSTOTAL_SUBMIT_DAILY_BUDGET", 400),
        ):
            return {"skipped": "budget_exhausted"}
        async with _RESCAN_SEMAPHORE:
            try:
                return await asyncio.wait_for(
                    self._do_rescan(url, before, api_key), timeout=_RESCAN_OVERALL_TIMEOUT
                )
            except asyncio.TimeoutError:
                return {"errors": [f"timeout_after_{int(_RESCAN_OVERALL_TIMEOUT)}s"]}
            except Exception as exc:
                logger.error("virustotal: rescan unexpected error", error=str(exc))
                return {"errors": [f"unexpected:{exc.__class__.__name__}"]}

    # ------------------------------------------------------------------ #
    # Public
    # ------------------------------------------------------------------ #

    async def enrich(self, entity_kind: str, entity_value: str) -> dict:
        api_key = self._api_key()
        if not api_key:
            return {}

        resource_type = _KIND_MAP.get(entity_kind)
        if not resource_type:
            return {}

        await _rate_limit()

        # URLs require base64url-encoded identifiers in the v3 API.
        path_id = _vt_url_id(entity_value) if resource_type == "urls" else entity_value
        url = f"{_VT_BASE}/{resource_type}/{path_id}"
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(url, headers={"x-apikey": api_key})
                if resp.status_code == 404:
                    base = {"value": entity_value, "not_found": True}
                    if resource_type == "urls":
                        rescan = await self._maybe_rescan(entity_value, None, api_key)
                        if rescan is not None:
                            base["rescan"] = rescan
                    return base
                if resp.status_code == 429:
                    logger.warning("virustotal: rate-limited (429), backing off 60s")
                    await asyncio.sleep(60)
                    return {}
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            logger.error("virustotal: http error", error=str(exc))
            return {}

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        votes = attrs.get("total_votes", {})

        result: dict = {
            "value": entity_value,
            "resource_type": resource_type,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "reputation": attrs.get("reputation"),
            "votes_malicious": votes.get("malicious", 0),
            "votes_harmless": votes.get("harmless", 0),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "last_modification_date": attrs.get("last_modification_date"),
            "tags": attrs.get("tags", []),
            "categories": attrs.get("categories", {}),
            "vt_link": f"https://www.virustotal.com/gui/{resource_type.rstrip('s')}/{entity_value}",
        }

        if resource_type == "ip_addresses":
            result.update(
                {
                    "country": attrs.get("country"),
                    "continent": attrs.get("continent"),
                    "as_owner": attrs.get("as_owner"),
                    "asn": attrs.get("asn"),
                    "network": attrs.get("network"),
                    "whois": attrs.get("whois", "")[:2000],
                    "regional_internet_registry": attrs.get("regional_internet_registry"),
                }
            )
        elif resource_type == "domains":
            result.update(
                {
                    "registrar": attrs.get("registrar"),
                    "creation_date": attrs.get("creation_date"),
                    "last_dns_records": attrs.get("last_dns_records", [])[:20],
                    "popularity_ranks": attrs.get("popularity_ranks", {}),
                    "jarm": attrs.get("jarm"),
                }
            )
        elif resource_type == "files":
            result.update(
                {
                    "file_type": attrs.get("type_description"),
                    "file_size": attrs.get("size"),
                    "md5": attrs.get("md5"),
                    "sha1": attrs.get("sha1"),
                    "sha256": attrs.get("sha256"),
                    "ssdeep": attrs.get("ssdeep"),
                    "tlsh": attrs.get("tlsh"),
                    "meaningful_name": attrs.get("meaningful_name"),
                    "names": attrs.get("names", [])[:10],
                    "signature_info": attrs.get("signature_info"),
                    "popular_threat_classification": attrs.get("popular_threat_classification"),
                }
            )

        if resource_type == "urls":
            before_snapshot = self._shape_url_attrs(attrs)
            rescan = await self._maybe_rescan(entity_value, before_snapshot, api_key)
            if rescan is not None:
                result["rescan"] = rescan

        return result
