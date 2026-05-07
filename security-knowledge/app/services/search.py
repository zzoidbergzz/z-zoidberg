from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from app.models.entities import Entity
from app.models.claims import Claim
import structlog

logger = structlog.get_logger(__name__)


async def full_text_search(
    db: AsyncSession, tenant_id: str, query: str, limit: int = 20
) -> list[dict[str, Any]]:
    """Return flat list of search results across entities and claims."""
    results = []

    entity_result = await db.execute(
        select(Entity).where(
            Entity.tenant_id == tenant_id,
            or_(Entity.name.ilike(f"%{query}%"), Entity.description.ilike(f"%{query}%"))
        ).limit(limit)
    )
    for entity in entity_result.scalars().all():
        results.append({
            "kind": "entity",
            "id": str(entity.id),
            "name": entity.name,
            "score": 1.0,
        })

    claim_result = await db.execute(
        select(Claim).where(
            Claim.tenant_id == tenant_id,
            or_(Claim.subject.ilike(f"%{query}%"), Claim.predicate.ilike(f"%{query}%"))
        ).limit(limit)
    )
    for claim in claim_result.scalars().all():
        results.append({
            "kind": "claim",
            "id": str(claim.id),
            "name": f"{claim.subject} {claim.predicate} {claim.object}",
            "score": 1.0,
        })

    return results[:limit]
