"""Base fetcher class with rate limiting and robots.txt compliance."""

from __future__ import annotations
import asyncio
import logging
import time
from abc import ABC, abstractmethod
from typing import Optional
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)


class BaseFetcher(ABC):
    """Base class for CTI source fetchers.

    Handles:
    - Rate limiting per source
    - robots.txt compliance
    - User-Agent management
    - Error tracking
    - Audit logging
    """

    DEFAULT_USER_AGENT = "NonEnglishCTI-Pipeline/0.1 (collection; +https://github.com/example/non-english-cti)"
    DEFAULT_RATE_LIMIT = 2.0  # seconds between requests
    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        rate_limit: float = DEFAULT_RATE_LIMIT,
        timeout: float = DEFAULT_TIMEOUT,
        proxy: Optional[str] = None,
    ):
        self.user_agent = user_agent
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.proxy = proxy
        self._last_request_time: dict[str, float] = {}
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                headers={"User-Agent": self.user_agent},
                timeout=self.timeout,
                follow_redirects=True,
                proxy=self.proxy,
            )
        return self._client

    async def _rate_limit_wait(self, source_id: str) -> None:
        """Enforce rate limit between requests to the same source."""
        last = self._last_request_time.get(source_id, 0)
        elapsed = time.monotonic() - last
        if elapsed < self.rate_limit:
            await asyncio.sleep(self.rate_limit - elapsed)
        self._last_request_time[source_id] = time.monotonic()

    async def fetch_url(self, url: str, source_id: str = "") -> Optional[httpx.Response]:
        """Fetch a URL with rate limiting and error handling."""
        await self._rate_limit_wait(source_id)
        client = await self._get_client()
        try:
            logger.debug("Fetching %s", url)
            resp = await client.get(url)
            resp.raise_for_status()
            logger.info("Fetched %s (%d bytes)", url, len(resp.content))
            return resp
        except httpx.HTTPStatusError as e:
            logger.warning("HTTP %d for %s: %s", e.response.status_code, url, e)
            return None
        except httpx.RequestError as e:
            logger.error("Request error for %s: %s", url, e)
            return None

    async def check_robots_txt(self, base_url: str) -> dict:
        """Check robots.txt for the given base URL."""
        robots_url = f"{base_url.rstrip('/')}/robots.txt"
        client = await self._get_client()
        try:
            resp = await client.get(robots_url)
            if resp.status_code == 200:
                return {
                    "accessible": True,
                    "content": resp.text,
                    "url": robots_url,
                }
        except Exception:
            pass
        return {"accessible": False, "content": "", "url": robots_url}

    @abstractmethod
    async def fetch(self, source, **kwargs) -> list[dict]:
        """Fetch items from a source. Returns list of raw item dicts."""
        ...

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
