import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import AuthContext, require_read, require_write
from app.database import get_db
from app.models.evidence import Evidence

router = APIRouter(prefix="/evidence", tags=["evidence"])


class EvidenceCreate(BaseModel):
    title: str
    content: str
    source_url: str | None = None
    entity_id: uuid.UUID | None = None


class EvidenceOut(BaseModel):
    id: uuid.UUID
    title: str
    content: str
    source_url: str | None
    text_snippet: str | None = None
    confidence: float
    tenant_id: uuid.UUID
    created_at: datetime | None = None
    model_config = {"from_attributes": True}


def _tenant_id(auth: AuthContext | dict) -> str:
    if isinstance(auth, dict):
        return str(auth["tenant_id"])
    return str(auth.tenant_id)


@router.get("/", response_model=list[EvidenceOut])
async def list_evidence(
    limit: int = Query(20, le=200),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext | dict = Depends(require_read),
):
    result = await db.execute(
        select(Evidence)
        .where(Evidence.tenant_id == _tenant_id(auth))
        .order_by(Evidence.created_at.desc())
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/entity/{entity_id}", response_model=list[EvidenceOut])
async def list_entity_evidence(
    entity_id: uuid.UUID,
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext | dict = Depends(require_read),
):
    result = await db.execute(
        select(Evidence)
        .where(Evidence.entity_id == entity_id, Evidence.tenant_id == _tenant_id(auth))
        .order_by(Evidence.created_at.desc())
        .limit(limit)
    )
    return result.scalars().all()


@router.post("/", response_model=EvidenceOut, status_code=201)
async def create_evidence(
    body: EvidenceCreate,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext | dict = Depends(require_write),
):
    ev = Evidence(tenant_id=_tenant_id(auth), **body.model_dump())
    db.add(ev)
    await db.flush()
    await db.refresh(ev)
    return ev
