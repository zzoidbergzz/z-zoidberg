"""Recorded Future integration client.

BYOK: set RecordedFutureAPI in .env or via admin settings.
API docs: https://api.recordedfuture.com/index.html
"""
from __future__ import annotations

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger(__name__)


class RecordedFutureClient:
    BASE = "https://api.recordedfuture.com/v2"

    def __init__(self, api_key: str | None = None):
        self._api_key = api_key or settings.RECORDED_FUTURE_API_KEY
        if not self._api_key:
            logger.warning("recorded_future_no_api_key")

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    def _headers(self) -> dict:
        return {"X-RFToken": self._api_key} if self._api_key else {}

    async def lookup_ip(self, ip: str, fields: str = "risk,internal,locations") -> dict | None:
        """Lookup an IP address in Recorded Future."""
        if not self.configured:
            return None
        async with httpx.AsyncClient(timeout=20) as client:
            try:
                resp = await client.get(
                    f"{self.BASE}/ip/{ip}",
                    params={"fields": fields},
                    headers=self._headers(),
                )
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as exc:
                logger.warning("rf_lookup_ip_error", ip=ip, error=str(exc))
                return None

    async def lookup_domain(self, domain: str, fields: str = "risk,internal") -> dict | None:
        """Lookup a domain in Recorded Future."""
        if not self.configured:
            return None
        async with httpx.AsyncClient(timeout=20) as client:
            try:
                resp = await client.get(
                    f"{self.BASE}/domain/{domain}",
                    params={"fields": fields},
                    headers=self._headers(),
                )
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as exc:
                logger.warning("rf_lookup_domain_error", domain=domain, error=str(exc))
                return None

    async def lookup_hash(self, hash_value: str) -> dict | None:
        """Lookup a file hash in Recorded Future."""
        if not self.configured:
            return None
        async with httpx.AsyncClient(timeout=20) as client:
            try:
                resp = await client.get(
                    f"{self.BASE}/hash/{hash_value}",
                    headers=self._headers(),
                )
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as exc:
                logger.warning("rf_lookup_hash_error", hash=hash_value[:16], error=str(exc))
                return None

    async def lookup_vulnerability(self, cve_id: str) -> dict | None:
        """Lookup a CVE/vulnerability in Recorded Future."""
        if not self.configured:
            return None
        async with httpx.AsyncClient(timeout=20) as client:
            try:
                resp = await client.get(
                    f"{self.BASE}/vulnerability/{cve_id}",
                    headers=self._headers(),
                )
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as exc:
                logger.warning("rf_lookup_vuln_error", cve=cve_id, error=str(exc))
                return None

    async def search(self, query: str, limit: int = 20, entity_type: str | None = None) -> dict | None:
        """Full-text search across Recorded Future."""
        if not self.configured:
            return None
        params = {"q": query, "limit": limit}
        if entity_type:
            params["type"] = entity_type
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.get(
                    f"{self.BASE}/search",
                    params=params,
                    headers=self._headers(),
                )
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as exc:
                logger.warning("rf_search_error", query=query[:50], error=str(exc))
                return None

    async def get_threat_assessment(self, entity: str, entity_type: str = "IpAddress") -> dict | None:
        """Get risk score and threat assessment for an entity."""
        if not self.configured:
            return None
        async with httpx.AsyncClient(timeout=20) as client:
            try:
                resp = await client.get(
                    f"{self.BASE}/threat/assessment",
                    params={"entity": entity, "type": entity_type},
                    headers=self._headers(),
                )
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPError as exc:
                logger.warning("rf_threat_assessment_error", entity=entity[:50], error=str(exc))
                return None


# Singleton
rf_client = RecordedFutureClient()
