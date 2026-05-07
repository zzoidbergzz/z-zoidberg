import strawberry
from typing import Optional
import uuid


@strawberry.type
class EntityType:
    id: strawberry.ID
    name: str
    kind: str
    description: Optional[str] = None
    confidence: Optional[int] = None
    tenant_id: strawberry.ID


@strawberry.type
class ClaimType:
    id: strawberry.ID
    subject: str
    predicate: str
    object: str
    tenant_id: strawberry.ID


@strawberry.type
class RelationshipType:
    id: strawberry.ID
    source_id: strawberry.ID
    target_id: strawberry.ID
    kind: str
    tenant_id: strawberry.ID
