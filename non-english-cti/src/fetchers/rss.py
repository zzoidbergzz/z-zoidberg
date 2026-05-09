"""RSS/Atom feed fetcher using feedparser."""

from __future__ import annotations
import logging
from datetime import datetime
from typing import Optional
from urllib.parse import urljoin

import feedparser
from .base import BaseFetcher

logger = logging.getLogger(__name__)


class RSSFetcher(BaseFetcher):
    """Fetches and parses RSS/Atom feeds."""

    async def fetch(self, source, max_items: int = 100) -> list[dict]:
        """Fetch RSS items from a source.

        Returns list of dicts with:
        - title, url, body, published_at, author, tags
        """
        feed_urls = []
        if source.collection_method == "rss" and source.feeds_endpoints:
            feed_urls = [ep.url for ep in source.feeds_endpoints if ep.type == "rss"]
        elif source.feeds_endpoints:
            feed_urls = [ep.url for ep in source.feeds_endpoints if ep.type == "rss"]

        if not feed_urls:
            # Try the source URL directly as a feed
            feed_urls = [source.url]

        all_items = []
        for feed_url in feed_urls:
            items = await self._fetch_feed(feed_url, str(source.source_id), max_items)
            all_items.extend(items)

        logger.info("Fetched %d items from %s", len(all_items), source.source_name)
        return all_items[:max_items]

    async def _fetch_feed(self, feed_url: str, source_id: str, max_items: int) -> list[dict]:
        """Fetch and parse a single RSS feed."""
        resp = await self.fetch_url(feed_url, source_id)
        if resp is None:
            return []

        # feedparser can parse from bytes
        feed = feedparser.parse(resp.content)

        if feed.bozo and not feed.entries:
            logger.warning("Feed parse error for %s: %s", feed_url, feed.bozo_exception)
            return []

        items = []
        for entry in feed.entries[:max_items]:
            item = {
                "title": entry.get("title", ""),
                "url": entry.get("link", ""),
                "body": self._extract_body(entry),
                "published_at": self._parse_date(entry),
                "author": entry.get("author", ""),
                "tags": [tag.get("term", "") for tag in entry.get("tags", [])],
                "feed_url": feed_url,
            }
            if item["title"] or item["body"]:
                items.append(item)

        return items

    @staticmethod
    def _extract_body(entry) -> str:
        """Extract body text from a feed entry."""
        # Try content first, then summary
        if hasattr(entry, "content") and entry.content:
            return entry.content[0].get("value", "")
        if hasattr(entry, "summary"):
            return entry.summary
        if hasattr(entry, "description"):
            return entry.description
        return ""

    @staticmethod
    def _parse_date(entry) -> Optional[datetime]:
        """Parse publication date from entry."""
        for field in ("published_parsed", "updated_parsed", "created_parsed"):
            parsed = entry.get(field)
            if parsed:
                try:
                    from time import mktime
                    return datetime.fromtimestamp(mktime(parsed))
                except Exception:
                    continue
        return None
