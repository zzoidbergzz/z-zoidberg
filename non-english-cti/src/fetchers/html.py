"""HTML advisory fetcher using trafilatura."""

from __future__ import annotations
import logging
from typing import Optional

import trafilatura
from .base import BaseFetcher

logger = logging.getLogger(__name__)


class HTMLFetcher(BaseFetcher):
    """Fetches and extracts content from static HTML pages."""

    async def fetch(self, source, max_items: int = 50) -> list[dict]:
        """Fetch items from an HTML source.

        For listing pages, extracts links and then fetches each advisory.
        For single pages, extracts content directly.
        """
        items = []

        for endpoint in source.feeds_endpoints:
            if endpoint.type not in ("html", "sitemap"):
                continue

            resp = await self.fetch_url(endpoint.url, str(source.source_id))
            if resp is None:
                continue

            content = self._extract_content(resp.text, endpoint.url)
            if content:
                items.append({
                    "title": content.get("title", ""),
                    "url": endpoint.url,
                    "body": content.get("text", ""),
                    "published_at": None,
                    "author": source.source_name,
                    "tags": [],
                })

        logger.info("Fetched %d HTML items from %s", len(items), source.source_name)
        return items[:max_items]

    def _extract_content(self, html: str, url: str) -> Optional[dict]:
        """Extract main content from HTML using trafilatura."""
        try:
            downloaded = trafilatura.bare_extraction(
                html,
                url=url,
                include_links=True,
                include_tables=True,
                include_formatting=False,
            )
            if downloaded:
                return {
                    "title": downloaded.get("title", ""),
                    "text": downloaded.get("text", ""),
                    "author": downloaded.get("author", ""),
                    "date": downloaded.get("date", ""),
                }
        except Exception as e:
            logger.warning("Content extraction failed for %s: %s", url, e)

        return None
