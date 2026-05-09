#!/usr/bin/env python3
"""Source health check — verify sources are reachable and returning data."""

import asyncio
import sys
import logging

sys.path.insert(0, "src")
from fetchers.rss import RSSFetcher
from fetchers.api import APIFetcher
from registry import SourceRegistry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def check_sources(catalogue_path: str):
    """Check health of all sources in the catalogue."""
    registry = SourceRegistry(catalogue_path)
    rss_fetcher = RSSFetcher()
    api_fetcher = APIFetcher()

    results = {"healthy": [], "degraded": [], "unhealthy": [], "unknown": []}

    for source_id, source in registry.sources.items():
        status = "unknown"
        detail = ""

        if source.collection_method == "rss" or any(ep.type == "rss" for ep in source.feeds_endpoints):
            for ep in source.feeds_endpoints:
                if ep.type == "rss":
                    resp = await rss_fetcher.fetch_url(ep.url, source_id)
                    if resp and resp.status_code == 200:
                        status = "healthy"
                        detail = f"RSS OK ({len(resp.content)} bytes)"
                    elif resp:
                        status = "degraded"
                        detail = f"RSS HTTP {resp.status_code}"
                    else:
                        status = "unhealthy"
                        detail = "RSS unreachable"
                    break
        elif source.collection_method == "api" or any(ep.type == "api" for ep in source.feeds_endpoints):
            for ep in source.feeds_endpoints:
                if ep.type == "api":
                    resp = await api_fetcher.fetch_url(ep.url, source_id)
                    if resp and resp.status_code == 200:
                        status = "healthy"
                        detail = f"API OK ({len(resp.content)} bytes)"
                    elif resp:
                        status = "degraded"
                        detail = f"API HTTP {resp.status_code}"
                    else:
                        status = "unhealthy"
                        detail = "API unreachable"
                    break

        results[status].append({
            "name": source.source_name,
            "url": source.url,
            "method": source.collection_method,
            "detail": detail,
        })
        print(f"[{status.upper()}] {source.source_name} ({source.collection_method}): {detail}")

    await rss_fetcher.close()
    await api_fetcher.close()
    print(f"\nSummary: {len(results['healthy'])} healthy, {len(results['degraded'])} degraded, {len(results['unhealthy'])} unhealthy, {len(results['unknown'])} unknown")
    return results


if __name__ == "__main__":
    catalogue = sys.argv[1] if len(sys.argv) > 1 else "catalogue/sources.yaml"
    asyncio.run(check_sources(catalogue))
