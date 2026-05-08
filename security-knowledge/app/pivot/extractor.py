from __future__ import annotations
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entities import Entity
from app.models.relationships import Relationship
from app.pivot.config import PIVOT_CONFIG
from app.pivot.graph import shortest_path, connected_clusters


class PivotEngine:
    def __init__(self, db: AsyncSession, tenant_id: str) -> None:
        self.db = db
        self.tenant_id = tenant_id

    async def _load_relationships(self, entity_ids: set[str]) -> list[dict[str, Any]]:
        """Load all relationships touching any of the given entity IDs."""
        uuids = [uuid.UUID(eid) for eid in entity_ids]
        result = await self.db.execute(
            select(Relationship).where(
                Relationship.tenant_id == uuid.UUID(self.tenant_id),
                Relationship.from_entity_id.in_(uuids) | Relationship.to_entity_id.in_(uuids),
            )
        )
        return [
            {
                "source_entity": str(r.from_entity_id),
                "target_entity": str(r.to_entity_id),
                "relation_type": r.kind,
                "confidence": r.confidence,
            }
            for r in result.scalars().all()
        ]

    async def get_graph(
        self,
        entity_id: str,
        max_depth: int | None = None,
        max_nodes: int | None = None,
    ) -> dict[str, Any]:
        """BFS-expand the relationship graph from entity_id up to max_depth hops."""
        max_depth = max_depth or PIVOT_CONFIG["max_manual_depth"]
        max_nodes = max_nodes or PIVOT_CONFIG["max_nodes_per_query"]

        visited: set[str] = {entity_id}
        frontier: set[str] = {entity_id}
        all_rels: list[dict[str, Any]] = []

        for _depth in range(max_depth):
            if not frontier or len(visited) >= max_nodes:
                break
            rels = await self._load_relationships(frontier)
            new_frontier: set[str] = set()
            for rel in rels:
                all_rels.append(rel)
                for node in (rel["source_entity"], rel["target_entity"]):
                    if node not in visited and len(visited) < max_nodes:
                        visited.add(node)
                        new_frontier.add(node)
            frontier = new_frontier

        # Deduplicate relationships
        seen_rels: set[tuple] = set()
        unique_rels = []
        for r in all_rels:
            key = (r["source_entity"], r["target_entity"], r["relation_type"])
            if key not in seen_rels:
                seen_rels.add(key)
                unique_rels.append(r)

        # Fetch entity metadata for visited nodes
        uuids = [uuid.UUID(eid) for eid in visited]
        entities_result = await self.db.execute(
            select(Entity).where(
                Entity.tenant_id == uuid.UUID(self.tenant_id),
                Entity.id.in_(uuids),
            )
        )
        nodes = {
            str(e.id): {"id": str(e.id), "kind": e.kind, "canonical_name": e.canonical_name}
            for e in entities_result.scalars().all()
        }

        clusters = connected_clusters(unique_rels)

        return {
            "root": entity_id,
            "nodes": list(nodes.values()),
            "edges": unique_rels,
            "clusters": clusters,
            "node_count": len(nodes),
            "edge_count": len(unique_rels),
        }

    async def find_path(self, source_id: str, target_id: str) -> list[str]:
        """Find the shortest relationship path between two entities."""
        # Load all tenant relationships for path search
        result = await self.db.execute(
            select(Relationship).where(
                Relationship.tenant_id == uuid.UUID(self.tenant_id),
            )
        )
        rels = [
            {
                "source_entity": str(r.from_entity_id),
                "target_entity": str(r.to_entity_id),
                "relation_type": r.kind,
                "confidence": r.confidence,
            }
            for r in result.scalars().all()
        ]
        return shortest_path(rels, source_id, target_id)
