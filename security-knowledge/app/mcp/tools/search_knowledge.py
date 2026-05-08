"""MCP tool: full-text + trigram search across entities and claims."""

from __future__ import annotations

from app.mcp.registry import register_tool
from app.services.search import full_text_search


async def _search_knowledge(args: dict, db, auth) -> dict:
    query = args.get("query", "")
    limit = int(args.get("limit", 20))
    if not query:
        return {"error": {"code": "missing_arg", "message": "Missing required arg: query"}}
    results = await full_text_search(db, str(auth.tenant_id), query, limit)
    return {"results": results, "count": len(results)}


register_tool(
    name="search_knowledge",
    fn=_search_knowledge,
    schema={
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer", "default": 20},
        },
    },
    description="Full-text + trigram search across entities and claims",
    scope="read",
)
