from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
import uuid
from app.database import get_db
from app.auth.dependencies import require_read, require_write
from app.models.digests import DigestSubscription

router = APIRouter(prefix="/digests", tags=["digests"])


class DigestSubCreate(BaseModel):
    name: str
    frequency: str = "daily"
    channels: list[str] = []
    filters: dict = {}


class DigestSubOut(BaseModel):
    id: uuid.UUID
    name: str
    frequency: str
    active: bool
    tenant_id: uuid.UUID
    model_config = {"from_attributes": True}


@router.get("/", response_model=list[DigestSubOut])
async def list_digests(
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_read),
):
    result = await db.execute(
        select(DigestSubscription).where(DigestSubscription.tenant_id == auth["tenant_id"])
    )
    return result.scalars().all()


@router.post("/", response_model=DigestSubOut, status_code=201)
async def create_digest(
    body: DigestSubCreate,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_write),
):
    sub = DigestSubscription(tenant_id=auth["tenant_id"], **body.model_dump())
    db.add(sub)
    await db.flush()
    await db.refresh(sub)
    return sub
