"""MCP tool: fetch a single entity by UUID."""

from __future__ import annotations

import uuid

from sqlalchemy import select

from app.mcp.registry import register_tool
from app.models.entities import Entity


async def _get_entity(args: dict, db, auth) -> dict:
    entity_id = args.get("entity_id")
    if not entity_id:
        return {"error": {"code": "missing_arg", "message": "Missing required arg: entity_id"}}
    try:
        eid = uuid.UUID(entity_id)
    except ValueError:
        return {"error": {"code": "invalid_arg", "message": "entity_id must be a valid UUID"}}
    result = await db.execute(
        select(Entity).where(Entity.id == eid, Entity.tenant_id == uuid.UUID(str(auth.tenant_id)))
    )
    entity = result.scalar_one_or_none()
    if entity is None:
        return {"error": {"code": "not_found", "message": "Entity not found"}}
    return {
        "id": str(entity.id),
        "kind": entity.kind,
        "canonical_name": entity.canonical_name,
        "mitre_attack_id": entity.mitre_attack_id,
        "external_refs": entity.external_refs,
        "created_at": entity.created_at.isoformat() if entity.created_at else None,
        "updated_at": entity.updated_at.isoformat() if entity.updated_at else None,
    }


register_tool(
    name="get_entity",
    fn=_get_entity,
    schema={
        "type": "object",
        "required": ["entity_id"],
        "properties": {
            "entity_id": {"type": "string", "description": "UUID of the entity"},
        },
    },
    description="Get a single entity by UUID",
    scope="read",
)
