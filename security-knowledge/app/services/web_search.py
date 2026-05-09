from __future__ import annotations

from typing import Any

import httpx

from app.config import settings


async def searxng_search(
    query: str,
    *,
    categories: str = "general",
    limit: int = 10,
    timeout: int = 15,
) -> list[dict[str, Any]]:
    if not query.strip():
        return []

    params = {
        "format": "json",
        "q": query,
        "categories": categories,
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.get(f"{settings.SEARXNG_BASE_URL.rstrip('/')}/search", params=params)
        resp.raise_for_status()
        payload = resp.json()

    out: list[dict[str, Any]] = []
    for item in payload.get("results", [])[: max(limit, 0)]:
        out.append(
            {
                "title": item.get("title", ""),
                "url": item.get("url", ""),
                "content": item.get("content", ""),
                "score": item.get("score", 0.0),
                "engine": item.get("engine", ""),
                "category": item.get("category", ""),
            }
        )
    return out
