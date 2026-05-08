"""MCP tool: create evidence supporting a claim or entity (requires write scope)."""

from __future__ import annotations

import uuid

from app.mcp.registry import register_tool
from app.models.evidence import Evidence


async def _create_evidence(args: dict, db, auth) -> dict:
    title = args.get("title")
    content = args.get("content")
    if not title:
        return {"error": {"code": "missing_arg", "message": "Missing required arg: title"}}
    if content is None:
        return {"error": {"code": "missing_arg", "message": "Missing required arg: content"}}

    claim_id_raw = args.get("claim_id")
    entity_id_raw = args.get("entity_id")
    claim_id = uuid.UUID(claim_id_raw) if claim_id_raw else None
    entity_id = uuid.UUID(entity_id_raw) if entity_id_raw else None
    source_url = args.get("source_url")
    confidence = float(args.get("confidence", 1.0))

    evidence = Evidence(
        id=uuid.uuid4(),
        tenant_id=uuid.UUID(str(auth.tenant_id)),
        claim_id=claim_id,
        entity_id=entity_id,
        title=title,
        content=content,
        source_url=source_url,
        confidence=confidence,
    )
    db.add(evidence)
    await db.commit()
    await db.refresh(evidence)
    return {
        "id": str(evidence.id),
        "title": evidence.title,
        "claim_id": str(evidence.claim_id) if evidence.claim_id else None,
        "entity_id": str(evidence.entity_id) if evidence.entity_id else None,
        "created_at": evidence.created_at.isoformat() if evidence.created_at else None,
    }


register_tool(
    name="create_evidence",
    fn=_create_evidence,
    schema={
        "type": "object",
        "required": ["title", "content"],
        "properties": {
            "title": {"type": "string"},
            "content": {"type": "string"},
            "claim_id": {"type": "string"},
            "entity_id": {"type": "string"},
            "source_url": {"type": "string"},
            "confidence": {"type": "number", "default": 1.0},
        },
    },
    description="Create evidence supporting a claim or entity (requires write scope)",
    scope="write",
)
