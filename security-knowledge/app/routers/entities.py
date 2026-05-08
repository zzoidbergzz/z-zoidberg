from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional, Any
import uuid
from app.database import get_db
from app.auth.dependencies import require_read, require_write
from app.models.entities import Entity, EntityKind

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
