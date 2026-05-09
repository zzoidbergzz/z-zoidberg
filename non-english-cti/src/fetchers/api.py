"""JSON API fetcher."""

from __future__ import annotations
import logging
from typing import Optional

from .base import BaseFetcher

logger = logging.getLogger(__name__)


class APIFetcher(BaseFetcher):
    """Fetches data from JSON APIs."""

    async def fetch(self, source, max_items: int = 100, params: Optional[dict] = None) -> list[dict]:
        """Fetch items from a JSON API source."""
        items = []

        for endpoint in source.feeds_endpoints:
            if endpoint.type != "api":
                continue

            resp = await self.fetch_url(endpoint.url, str(source.source_id))
            if resp is None:
                continue

            try:
                data = resp.json()
                parsed = self._parse_response(data, endpoint.url)
                items.extend(parsed)
            except Exception as e:
                logger.warning("JSON parse error for %s: %s", endpoint.url, e)

        logger.info("Fetched %d API items from %s", len(items), source.source_name)
        return items[:max_items]

    def _parse_response(self, data, url: str) -> list[dict]:
        """Parse JSON API response into standard items."""
        items = []

        # Handle common response formats
        if isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            # Try common wrapper keys
            for key in ("data", "results", "items", "records", "vulnerabilities", "advisories"):
                if key in data and isinstance(data[key], list):
                    records = data[key]
                    break
            else:
                # Single item
                records = [data]
        else:
            return items

        for record in records[:100]:
            if not isinstance(record, dict):
                continue
            item = {
                "title": record.get("title", record.get("name", "")),
                "url": record.get("url", record.get("link", url)),
                "body": record.get("description", record.get("summary", record.get("content", ""))),
                "published_at": record.get("published_at", record.get("date", record.get("created", None))),
                "author": record.get("author", record.get("source", "")),
                "tags": record.get("tags", []),
                "raw_data": record,
            }
            if item["title"] or item["body"]:
                items.append(item)

        return items
