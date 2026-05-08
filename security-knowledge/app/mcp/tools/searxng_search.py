"""MCP tool: web search via local SearXNG instance."""

from __future__ import annotations

import httpx

from app.mcp.registry import register_tool

_SEARXNG_BASE = "http://localhost:8888"


async def _searxng_search(args: dict, db, auth) -> dict:
    query = args.get("query")
    if not query:
        return {"error": {"code": "missing_arg", "message": "Missing required arg: query"}}
    categories = args.get("categories", "general")
    limit = int(args.get("limit", 10))

    params = {"format": "json", "q": query, "categories": categories}
    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(f"{_SEARXNG_BASE}/search", params=params)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            return {"error": {"code": "searxng_error", "message": str(exc)}}

    results = data.get("results", [])[:limit]
    return {
        "query": query,
        "results": [
            {
                "title": r.get("title", ""),
                "url": r.get("url", ""),
                "content": r.get("content", ""),
                "score": r.get("score"),
            }
            for r in results
        ],
        "count": len(results),
    }


register_tool(
    name="searxng_search",
    fn=_searxng_search,
    schema={
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {"type": "string"},
            "categories": {"type": "string", "default": "general"},
            "limit": {"type": "integer", "default": 10},
        },
    },
    description="Web search via local SearXNG instance",
    scope="read",
)
