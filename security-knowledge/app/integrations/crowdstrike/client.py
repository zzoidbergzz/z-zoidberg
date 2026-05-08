"""CrowdStrike Falcon API client.

Implements OAuth2 token management (auto-refresh) and exposes the Intel,
IOC, and Spotlight service collection endpoints used for feed ingestion.

API patterns follow the falconpy SDK (https://github.com/CrowdStrike/falconpy)
but use httpx directly to avoid a hard dependency on the SDK in environments
where only specific service collections are needed.

Supported feeds
---------------
- ``/intel/combined/reports/v1``     — threat-intel reports
- ``/intel/combined/actors/v1``      — threat actors
- ``/intel/combined/indicators/v1``  — threat indicators (IOCs)
- ``/spotlight/combined/vulnerabilities/v1`` — vulnerability data
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger(__name__)

_TOKEN_EXPIRY_BUFFER = 60  # seconds before expiry to refresh


class FalconClient:
    """Async CrowdStrike Falcon API client with automatic token refresh."""

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self._client_id = client_id or settings.CROWDSTRIKE_CLIENT_ID
        self._client_secret = client_secret or settings.CROWDSTRIKE_CLIENT_SECRET
        self._base_url = (base_url or settings.CROWDSTRIKE_BASE_URL).rstrip("/")
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    async def _get_token(self) -> str:
        """Return a valid bearer token, refreshing if necessary."""
        if self._token and time.time() < self._token_expires_at - _TOKEN_EXPIRY_BUFFER:
            return self._token

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self._base_url}/oauth2/token",
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            body = resp.json()

        self._token = body["access_token"]
        expires_in = body.get("expires_in", 1800)
        self._token_expires_at = time.time() + expires_in
        logger.debug("crowdstrike_token_refreshed", expires_in=expires_in)
        return self._token

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict:
        token = await self._get_token()
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self._base_url}{path}",
                params=params or {},
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
            )
            resp.raise_for_status()
            return resp.json()

    # ------------------------------------------------------------------
    # Intel — reports
    # ------------------------------------------------------------------

    async def get_intel_reports(
        self,
        limit: int = 100,
        offset: int = 0,
        sort: str = "last_modified_date|desc",
        filter: str | None = None,
    ) -> dict:
        """Fetch combined intel reports.

        Returns the raw Falcon API response body.  Use
        ``normalize_report`` from the normalizer module to convert items
        to the internal format.
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset, "sort": sort}
        if filter:
            params["filter"] = filter
        return await self._get("/intel/combined/reports/v1", params)

    # ------------------------------------------------------------------
    # Intel — actors
    # ------------------------------------------------------------------

    async def get_intel_actors(
        self,
        limit: int = 100,
        offset: int = 0,
        sort: str = "last_modified_date|desc",
        filter: str | None = None,
    ) -> dict:
        """Fetch combined threat actors."""
        params: dict[str, Any] = {"limit": limit, "offset": offset, "sort": sort}
        if filter:
            params["filter"] = filter
        return await self._get("/intel/combined/actors/v1", params)

    # ------------------------------------------------------------------
    # Intel — indicators
    # ------------------------------------------------------------------

    async def get_intel_indicators(
        self,
        limit: int = 500,
        offset: int = 0,
        sort: str = "last_updated|desc",
        filter: str | None = None,
        include_deleted: bool = False,
    ) -> dict:
        """Fetch combined threat indicators (IOCs).

        Uses ``/intel/combined/indicators/v1`` which returns full object
        details without a second lookup.
        """
        params: dict[str, Any] = {
            "limit": limit,
            "offset": offset,
            "sort": sort,
            "include_deleted": include_deleted,
        }
        if filter:
            params["filter"] = filter
        return await self._get("/intel/combined/indicators/v1", params)

    # ------------------------------------------------------------------
    # Spotlight — vulnerabilities
    # ------------------------------------------------------------------

    async def get_spotlight_vulnerabilities(
        self,
        limit: int = 400,
        after: str | None = None,
        filter: str | None = None,
        sort: str = "created_timestamp|desc",
    ) -> dict:
        """Fetch Spotlight vulnerability data for the tenant."""
        params: dict[str, Any] = {"limit": limit, "sort": sort}
        if after:
            params["after"] = after
        if filter:
            params["filter"] = filter
        return await self._get("/spotlight/combined/vulnerabilities/v1", params)

    # ------------------------------------------------------------------
    # Detections summary (for heartbeat / alerting integrations)
    # ------------------------------------------------------------------

    async def get_detections_summary(
        self,
        limit: int = 100,
        filter: str | None = None,
    ) -> dict:
        """Query detection summaries via ``/detects/entities/summaries/GET/v1``."""
        # First fetch IDs
        filter_param = {"filter": filter} if filter else {}
        id_resp = await self._get(
            "/detects/queries/detects/v1", {"limit": limit, **filter_param}
        )
        ids = (id_resp.get("resources") or [])[:limit]
        if not ids:
            return {"resources": []}
        token = await self._get_token()
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{self._base_url}/detects/entities/summaries/GET/v1",
                json={"ids": ids},
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
            resp.raise_for_status()
            return resp.json()
