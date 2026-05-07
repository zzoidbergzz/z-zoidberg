import strawberry
from strawberry.fastapi import GraphQLRouter
from typing import Optional
from app.graphql.types import EntityType, ClaimType, RelationshipType


@strawberry.type
class Query:
    @strawberry.field
    async def entity(self, id: strawberry.ID) -> Optional[EntityType]:
        return None

    @strawberry.field
    async def entities(self, kind: Optional[str] = None, limit: int = 20) -> list[EntityType]:
        return []

    @strawberry.field
    async def claims(self, subject: Optional[str] = None, limit: int = 20) -> list[ClaimType]:
        return []


@strawberry.type
class Mutation:
    @strawberry.mutation
    async def placeholder(self) -> str:
        return "ok"


schema = strawberry.Schema(query=Query, mutation=Mutation)
graphql_router = GraphQLRouter(schema)
