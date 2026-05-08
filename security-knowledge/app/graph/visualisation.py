from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.entities import Entity
from app.models.relationships import Relationship
from app.graph.formats import to_vis_js, to_cytoscape
import uuid


async def build_graph(
    db: AsyncSession,
    tenant_id: str,
    entity_id: uuid.UUID | None = None,
    depth: int = 2,
    fmt: str = "vis",
) -> dict:
    entity_q = select(Entity).where(Entity.tenant_id == tenant_id).limit(100)
    if entity_id:
        entity_q = entity_q.where(Entity.id == entity_id)
    entities = list((await db.execute(entity_q)).scalars().all())

    entity_ids = [e.id for e in entities]
    rel_q = select(Relationship).where(
        Relationship.tenant_id == tenant_id,
        Relationship.from_entity_id.in_(entity_ids),
    )
    relationships = list((await db.execute(rel_q)).scalars().all())

    if fmt == "cytoscape":
        return {"elements": to_cytoscape(entities, relationships)}
    return to_vis_js(entities, relationships)
