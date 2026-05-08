import httpx
from app.config import settings


class BBSClient:
    """Threat intelligence BBS/forum scraper integration."""

    async def fetch_feed(self, feed_url: str) -> list[dict]:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(feed_url)
            resp.raise_for_status()
            return resp.json()
