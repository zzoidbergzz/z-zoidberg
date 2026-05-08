"""MCP tool: create a new entity (requires write scope)."""

from __future__ import annotations

import uuid

from app.mcp.registry import register_tool
from app.models.entities import Entity


async def _create_entity(args: dict, db, auth) -> dict:
    name = args.get("name")
    kind = args.get("kind")
    if not name:
        return {"error": {"code": "missing_arg", "message": "Missing required arg: name"}}
    if not kind:
        return {"error": {"code": "missing_arg", "message": "Missing required arg: kind"}}

    entity = Entity(
        id=uuid.uuid4(),
        tenant_id=uuid.UUID(str(auth.tenant_id)),
        kind=kind,
        canonical_name=name,
        external_refs={},
    )
    db.add(entity)
    await db.commit()
    await db.refresh(entity)
    return {
        "id": str(entity.id),
        "kind": entity.kind,
        "canonical_name": entity.canonical_name,
        "created_at": entity.created_at.isoformat() if entity.created_at else None,
    }


register_tool(
    name="create_entity",
    fn=_create_entity,
    schema={
        "type": "object",
        "required": ["name", "kind"],
        "properties": {
            "name": {"type": "string"},
            "kind": {"type": "string"},
        },
    },
    description="Create a new entity (requires write scope)",
    scope="write",
)
