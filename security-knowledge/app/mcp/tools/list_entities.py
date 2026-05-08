"""MCP tool: list entities with optional kind filter."""

from __future__ import annotations

import uuid

from sqlalchemy import select

from app.mcp.registry import register_tool
from app.models.entities import Entity


async def _list_entities(args: dict, db, auth) -> dict:
    kind = args.get("kind")
    limit = int(args.get("limit", 50))
    offset = int(args.get("offset", 0))

    stmt = select(Entity).where(Entity.tenant_id == uuid.UUID(str(auth.tenant_id)))
    if kind:
        stmt = stmt.where(Entity.kind == kind)
    stmt = stmt.offset(offset).limit(limit)

    result = await db.execute(stmt)
    entities = result.scalars().all()
    return {
        "entities": [
            {
                "id": str(e.id),
                "kind": e.kind,
                "canonical_name": e.canonical_name,
                "mitre_attack_id": e.mitre_attack_id,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in entities
        ],
        "count": len(entities),
    }


register_tool(
    name="list_entities",
    fn=_list_entities,
    schema={
        "type": "object",
        "properties": {
            "kind": {"type": "string", "description": "Filter by entity kind"},
            "limit": {"type": "integer", "default": 50},
            "offset": {"type": "integer", "default": 0},
        },
    },
    description="List entities, optionally filtered by kind",
    scope="read",
)
