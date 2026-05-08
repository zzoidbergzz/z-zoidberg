import uuid

import strawberry
from fastapi import Depends
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from strawberry.fastapi import BaseContext, GraphQLRouter
from strawberry.types import Info

from app.auth.dependencies import AuthContext, Scope, get_auth
from app.database import get_db
from app.graphql.types import ClaimType, EntityType, RelationshipType
from app.models.claims import Claim
from app.models.entities import Entity
from app.models.relationships import Relationship

MAX_DEPTH = 5


class GraphQLContext(BaseContext):
    def __init__(self, db: AsyncSession, auth: AuthContext) -> None:
        self.db = db
        self.auth = auth


async def get_context(
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
) -> GraphQLContext:
    return GraphQLContext(db=db, auth=auth)


def _entity_to_type(e: Entity) -> EntityType:
    return EntityType(
        id=strawberry.ID(str(e.id)),
        name=e.canonical_name,
        kind=e.kind,
        description=None,
        confidence=None,
        tenant_id=strawberry.ID(str(e.tenant_id)),
    )


def _claim_to_type(c: Claim) -> ClaimType:
    return ClaimType(
        id=strawberry.ID(str(c.id)),
        subject=str(c.entity_id) if c.entity_id else "",
        predicate=c.claim_type,
        object=str(c.value),
        tenant_id=strawberry.ID(str(c.tenant_id)),
    )


def _rel_to_type(r: Relationship) -> RelationshipType:
    return RelationshipType(
        id=strawberry.ID(str(r.id)),
        source_id=strawberry.ID(str(r.from_entity_id)),
        target_id=strawberry.ID(str(r.to_entity_id)),
        kind=r.kind,
        tenant_id=strawberry.ID(str(r.tenant_id)),
    )


@strawberry.type
class Query:
    @strawberry.field
    async def entity(self, info: Info, id: strawberry.ID) -> EntityType | None:
        ctx: GraphQLContext = info.context
        try:
            eid = uuid.UUID(str(id))
        except ValueError:
            return None
        result = await ctx.db.execute(select(Entity).where(Entity.id == eid, Entity.tenant_id == ctx.auth.tenant_id))
        e = result.scalar_one_or_none()
        return _entity_to_type(e) if e else None

    @strawberry.field
    async def entities(
        self,
        info: Info,
        kind: str | None = None,
        limit: int = 20,
    ) -> list[EntityType]:
        ctx: GraphQLContext = info.context
        limit = min(limit, 200)
        q = select(Entity).where(Entity.tenant_id == ctx.auth.tenant_id).limit(limit)
        if kind:
            q = q.where(Entity.kind == kind)
        result = await ctx.db.execute(q)
        return [_entity_to_type(e) for e in result.scalars().all()]

    @strawberry.field
    async def claim(self, info: Info, id: strawberry.ID) -> ClaimType | None:
        ctx: GraphQLContext = info.context
        try:
            cid = uuid.UUID(str(id))
        except ValueError:
            return None
        result = await ctx.db.execute(select(Claim).where(Claim.id == cid, Claim.tenant_id == ctx.auth.tenant_id))
        c = result.scalar_one_or_none()
        return _claim_to_type(c) if c else None

    @strawberry.field
    async def claims(
        self,
        info: Info,
        subject: str | None = None,
        limit: int = 20,
    ) -> list[ClaimType]:
        ctx: GraphQLContext = info.context
        limit = min(limit, 200)
        q = select(Claim).where(Claim.tenant_id == ctx.auth.tenant_id).limit(limit)
        if subject:
            try:
                eid = uuid.UUID(subject)
                q = q.where(Claim.entity_id == eid)
            except ValueError:
                pass
        result = await ctx.db.execute(q)
        return [_claim_to_type(c) for c in result.scalars().all()]

    @strawberry.field
    async def relationships(
        self,
        info: Info,
        entity_id: strawberry.ID,
        depth: int = 1,
    ) -> list[RelationshipType]:
        if depth > MAX_DEPTH:
            raise ValueError(f"depth exceeds maximum of {MAX_DEPTH}")
        ctx: GraphQLContext = info.context
        try:
            eid = uuid.UUID(str(entity_id))
        except ValueError:
            return []

        seen_entity_ids: set[uuid.UUID] = {eid}
        frontier: set[uuid.UUID] = {eid}
        seen_rel_ids: set[uuid.UUID] = set()
        all_rels: list[Relationship] = []

        for _ in range(depth):
            if not frontier:
                break
            frontier_list = list(frontier)
            q = select(Relationship).where(
                Relationship.tenant_id == ctx.auth.tenant_id,
                or_(
                    Relationship.from_entity_id.in_(frontier_list),
                    Relationship.to_entity_id.in_(frontier_list),
                ),
            )
            result = await ctx.db.execute(q)
            rels = result.scalars().all()
            next_frontier: set[uuid.UUID] = set()
            for r in rels:
                if r.id not in seen_rel_ids:
                    seen_rel_ids.add(r.id)
                    all_rels.append(r)
                for nid in (r.from_entity_id, r.to_entity_id):
                    if nid not in seen_entity_ids:
                        seen_entity_ids.add(nid)
                        next_frontier.add(nid)
            frontier = next_frontier

        return [_rel_to_type(r) for r in all_rels]


@strawberry.type
class Mutation:
    @strawberry.mutation
    async def create_entity(
        self,
        info: Info,
        name: str,
        kind: str,
    ) -> EntityType:
        ctx: GraphQLContext = info.context
        ctx.auth.require_scope(Scope.write)
        entity = Entity(
            tenant_id=uuid.UUID(ctx.auth.tenant_id),
            canonical_name=name,
            kind=kind,
        )
        ctx.db.add(entity)
        await ctx.db.flush()
        await ctx.db.refresh(entity)
        return _entity_to_type(entity)


schema = strawberry.Schema(query=Query, mutation=Mutation)
graphql_router = GraphQLRouter(schema, context_getter=get_context)
