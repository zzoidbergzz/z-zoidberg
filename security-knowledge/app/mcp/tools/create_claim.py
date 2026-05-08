"""MCP tool: create a claim on an entity (requires write scope)."""

from __future__ import annotations

import uuid

from app.mcp.registry import register_tool
from app.models.claims import Claim


async def _create_claim(args: dict, db, auth) -> dict:
    claim_type = args.get("claim_type")
    value = args.get("value")
    if not claim_type:
        return {"error": {"code": "missing_arg", "message": "Missing required arg: claim_type"}}
    if value is None:
        return {"error": {"code": "missing_arg", "message": "Missing required arg: value"}}

    entity_id_raw = args.get("entity_id")
    entity_id = uuid.UUID(entity_id_raw) if entity_id_raw else None
    confidence = float(args.get("confidence", 1.0))

    claim = Claim(
        id=uuid.uuid4(),
        tenant_id=uuid.UUID(str(auth.tenant_id)),
        entity_id=entity_id,
        claim_type=claim_type,
        value=value,
        confidence=confidence,
        external_refs={},
    )
    db.add(claim)
    await db.commit()
    await db.refresh(claim)
    return {
        "id": str(claim.id),
        "claim_type": claim.claim_type,
        "entity_id": str(claim.entity_id) if claim.entity_id else None,
        "confidence": claim.confidence,
        "created_at": claim.created_at.isoformat() if claim.created_at else None,
    }


register_tool(
    name="create_claim",
    fn=_create_claim,
    schema={
        "type": "object",
        "required": ["claim_type", "value"],
        "properties": {
            "entity_id": {"type": "string"},
            "claim_type": {"type": "string"},
            "value": {"type": "object"},
            "confidence": {"type": "number", "default": 1.0},
        },
    },
    description="Create a claim on an entity (requires write scope)",
    scope="write",
)
