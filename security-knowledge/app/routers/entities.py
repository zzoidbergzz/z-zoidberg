from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from pydantic import BaseModel
from typing import Optional, Any
import uuid
from app.database import get_db
from app.auth.dependencies import require_read, require_write
from app.models.entities import Entity, EntityKind
from app.models.relationships import Relationship

router = APIRouter(prefix="/entities", tags=["entities"])


class EntityCreate(BaseModel):
    name: str
    kind: EntityKind


class EntityOut(BaseModel):
    id: uuid.UUID
    canonical_name: str
    kind: str
    tenant_id: uuid.UUID
    mitre_attack_id: Optional[str] = None
    external_refs: dict[str, Any] = {}
    created_at: Optional[Any] = None
    updated_at: Optional[Any] = None
    model_config = {"from_attributes": True}

    @property
    def name(self) -> str:
        return self.canonical_name


@router.get("/", response_model=list[EntityOut])
async def list_entities(
    kind: Optional[EntityKind] = None,
    limit: int = Query(20, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    auth = Depends(require_read),
):
    q = select(Entity).where(Entity.tenant_id == auth.tenant_id).limit(limit).offset(offset)
    if kind:
        q = q.where(Entity.kind == kind)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/", response_model=EntityOut, status_code=201)
async def create_entity(
    body: EntityCreate,
    db: AsyncSession = Depends(get_db),
    auth = Depends(require_write),
):
    entity = Entity(
        tenant_id=auth.tenant_id,
        canonical_name=body.name,
        kind=body.kind,
    )
    db.add(entity)
    await db.flush()
    await db.refresh(entity)
    return entity


@router.get("/{entity_id}", response_model=EntityOut)
async def get_entity(
    entity_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth = Depends(require_read),
):
    result = await db.execute(
        select(Entity).where(Entity.id == entity_id, Entity.tenant_id == auth.tenant_id)
    )
    entity = result.scalar_one_or_none()
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")
    return entity


class RelatedEntity(BaseModel):
    id: uuid.UUID
    canonical_name: str
    kind: str


class RelationshipEdge(BaseModel):
    id: uuid.UUID
    kind: str
    direction: str
    confidence: float
    peer: RelatedEntity


@router.get("/{entity_id}/relationships", response_model=list[RelationshipEdge])
async def get_entity_relationships(
    entity_id: uuid.UUID,
    limit: int = Query(50, le=500),
    db: AsyncSession = Depends(get_db),
    auth = Depends(require_read),
):
    from sqlalchemy import literal_column
    sql = text(
        """
        SELECT r.id AS rel_id, r.kind AS rel_kind, r.confidence,
               CASE WHEN r.from_entity_id = :eid THEN 'out' ELSE 'in' END AS direction,
               e.id AS peer_id, e.canonical_name AS peer_name, e.kind AS peer_kind
        FROM relationships r
        JOIN entities e
          ON e.id = CASE WHEN r.from_entity_id = :eid THEN r.to_entity_id ELSE r.from_entity_id END
        WHERE r.tenant_id = :tid
          AND (r.from_entity_id = :eid OR r.to_entity_id = :eid)
        LIMIT :lim
        """
    )
    rows = (await db.execute(sql, {"eid": entity_id, "tid": auth.tenant_id, "lim": limit})).mappings().all()
    return [
        RelationshipEdge(
            id=r["rel_id"],
            kind=r["rel_kind"],
            direction=r["direction"],
            confidence=float(r["confidence"]),
            peer=RelatedEntity(id=r["peer_id"], canonical_name=r["peer_name"], kind=r["peer_kind"]),
        )
        for r in rows
    ]
