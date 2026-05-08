"""MCP tool: render entity relationship graph."""

from __future__ import annotations

import uuid

from app.graph.visualisation import build_graph
from app.mcp.registry import register_tool


async def _get_entity_graph(args: dict, db, auth) -> dict:
    entity_id = args.get("entity_id")
    eid = None
    if entity_id:
        try:
            eid = uuid.UUID(entity_id)
        except ValueError:
            return {"error": "entity_id must be a UUID"}
    depth = min(int(args.get("depth", 2)), 5)
    fmt = args.get("format", "vis")
    if fmt not in ("vis", "cytoscape"):
        return {"error": "format must be 'vis' or 'cytoscape'"}
    return await build_graph(db, str(auth.tenant_id), eid, depth, fmt)


register_tool(
    name="get_entity_graph",
    fn=_get_entity_graph,
    schema={
        "type": "object",
        "properties": {
            "entity_id": {"type": "string", "description": "Optional UUID of root entity; omit for tenant overview"},
            "depth": {"type": "integer", "description": "Hops from root (1-5, default 2)"},
            "format": {"type": "string", "description": "vis | cytoscape (default vis)"},
        },
    },
    description="Build a relationship graph rooted at an entity (or tenant-wide if no entity_id).",
    scope="read",
)
