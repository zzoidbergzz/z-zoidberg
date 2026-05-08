from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
import uuid
from app.database import get_db
from app.auth.dependencies import require_read, require_write
from app.models.evidence import Evidence

router = APIRouter(prefix="/evidence", tags=["evidence"])


class EvidenceCreate(BaseModel):
    title: str
    content: str
    source_url: Optional[str] = None
    entity_id: Optional[uuid.UUID] = None


class EvidenceOut(BaseModel):
    id: uuid.UUID
    title: str
    content: str
    source_url: Optional[str]
    tenant_id: uuid.UUID
    model_config = {"from_attributes": True}


@router.get("/", response_model=list[EvidenceOut])
async def list_evidence(
    limit: int = Query(20, le=200),
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_read),
):
    result = await db.execute(select(Evidence).where(Evidence.tenant_id == auth.tenant_id).limit(limit))
    return result.scalars().all()


@router.post("/", response_model=EvidenceOut, status_code=201)
async def create_evidence(
    body: EvidenceCreate,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_write),
):
    ev = Evidence(tenant_id=auth.tenant_id, **body.model_dump())
    db.add(ev)
    await db.flush()
    await db.refresh(ev)
    return ev
