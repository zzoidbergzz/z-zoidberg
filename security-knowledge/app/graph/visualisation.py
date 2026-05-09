import uuid

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.graph.formats import to_cytoscape, to_vis_js
from app.models.entities import Entity
from app.models.relationships import Relationship


async def build_graph(
    db: AsyncSession,
    tenant_id: str,
    entity_id: uuid.UUID | None = None,
    depth: int = 2,
    fmt: str = "vis",
) -> dict:
    relationships: list[Relationship] = []
    max_nodes = 900
    max_edges = 3000

    if entity_id is not None:
        # Focused subgraph: BFS around the requested entity, including both
        # inbound and outbound edges so users always see linked nodes.
        max_depth = max(1, min(int(depth), 5))
        seen_ids: set[uuid.UUID] = {entity_id}
        frontier: set[uuid.UUID] = {entity_id}
        seen_rels: set[uuid.UUID] = set()

        for _ in range(max_depth):
            if not frontier:
                break
            rows = (
                await db.execute(
                    select(Relationship).where(
                        Relationship.tenant_id == tenant_id,
                        or_(
                            Relationship.from_entity_id.in_(frontier),
                            Relationship.to_entity_id.in_(frontier),
                        ),
                    )
                )
            ).scalars().all()
            next_frontier: set[uuid.UUID] = set()
            for rel in rows:
                if rel.id in seen_rels:
                    continue
                seen_rels.add(rel.id)
                relationships.append(rel)
                if len(relationships) >= max_edges:
                    break
                if rel.from_entity_id not in seen_ids:
                    next_frontier.add(rel.from_entity_id)
                if rel.to_entity_id not in seen_ids:
                    next_frontier.add(rel.to_entity_id)
            if len(relationships) >= max_edges:
                break
            remaining_capacity = max_nodes - len(seen_ids)
            if remaining_capacity <= 0:
                break
            if len(next_frontier) > remaining_capacity:
                next_frontier = set(sorted(next_frontier, key=str)[:remaining_capacity])
            seen_ids.update(next_frontier)
            frontier = next_frontier

        entities = (
            await db.execute(
                select(Entity).where(
                    Entity.tenant_id == tenant_id,
                    Entity.id.in_(seen_ids),
                )
            )
        ).scalars().all()
        entities = list(entities)
        entity_ids = {e.id for e in entities}
        relationships = [
            rel for rel in relationships
            if rel.from_entity_id in entity_ids and rel.to_entity_id in entity_ids
        ]
    else:
        rel_rows = (
            await db.execute(
                select(Relationship)
                .where(Relationship.tenant_id == tenant_id)
                .order_by(Relationship.created_at.desc())
                .limit(max_edges)
            )
        ).scalars().all()
        relationships = list(rel_rows)
        related_ids: set[uuid.UUID] = set()
        for rel in relationships:
            if len(related_ids) < max_nodes:
                related_ids.add(rel.from_entity_id)
            if len(related_ids) < max_nodes:
                related_ids.add(rel.to_entity_id)
            if len(related_ids) >= max_nodes:
                break

        if related_ids:
            entities = (
                await db.execute(
                    select(Entity).where(
                        Entity.tenant_id == tenant_id,
                        Entity.id.in_(related_ids),
                    )
                )
            ).scalars().all()
            entities = list(entities)
            entity_ids = {e.id for e in entities}
            relationships = [
                rel for rel in relationships
                if rel.from_entity_id in entity_ids and rel.to_entity_id in entity_ids
            ]
        else:
            entities = list(
                (
                    await db.execute(
                        select(Entity)
                        .where(Entity.tenant_id == tenant_id)
                        .order_by(Entity.updated_at.desc())
                        .limit(100)
                    )
                ).scalars().all()
            )

    if fmt == "cytoscape":
        return {"elements": to_cytoscape(entities, relationships)}
    return to_vis_js(entities, relationships)
