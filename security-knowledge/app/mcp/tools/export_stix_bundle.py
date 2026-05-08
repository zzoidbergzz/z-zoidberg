"""MCP tool: export entities as a STIX 2.1 bundle."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select

from app.mcp.registry import register_tool
from app.models.entities import Entity
from app.stix.builder import build_stix_bundle


async def _export_stix_bundle(args: dict, db, auth) -> dict:
    entity_ids_raw: list[str] | None = args.get("entity_ids")
    since_raw: str | None = args.get("since")

    tenant_uuid = uuid.UUID(str(auth.tenant_id))
    stmt = select(Entity).where(Entity.tenant_id == tenant_uuid)

    if entity_ids_raw:
        try:
            eids = [uuid.UUID(eid) for eid in entity_ids_raw]
        except ValueError:
            return {"error": {"code": "invalid_arg", "message": "entity_ids must be valid UUIDs"}}
        stmt = stmt.where(Entity.id.in_(eids))

    if since_raw:
        try:
            since_dt = datetime.fromisoformat(since_raw)
        except ValueError:
            return {"error": {"code": "invalid_arg", "message": "since must be an ISO 8601 datetime"}}
        stmt = stmt.where(Entity.updated_at >= since_dt)

    result = await db.execute(stmt.limit(500))
    entities = list(result.scalars().all())
    bundle = build_stix_bundle(entities, [])
    return bundle


register_tool(
    name="export_stix_bundle",
    fn=_export_stix_bundle,
    schema={
        "type": "object",
        "properties": {
            "entity_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional list of entity UUIDs to include",
            },
            "since": {"type": "string", "description": "Optional ISO 8601 datetime filter"},
        },
    },
    description="Export entities as a STIX 2.1 bundle",
    scope="read",
)
