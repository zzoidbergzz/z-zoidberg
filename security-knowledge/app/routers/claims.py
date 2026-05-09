from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional, Any
from datetime import datetime
import uuid
from app.database import get_db
from app.auth.dependencies import require_read, require_write
from app.models.claims import Claim

router = APIRouter(prefix="/claims", tags=["claims"])


class ClaimCreate(BaseModel):
    statement: str
    claim_type: str = "general"
    confidence: float = 0.5
    subject: Optional[str] = None
    predicate: Optional[str] = None
    object: Optional[str] = None


class ClaimOut(BaseModel):
    id: uuid.UUID
    statement: str
    claim_type: str
    confidence: float
    tenant_id: uuid.UUID
    model_config = {"from_attributes": True}


@router.get("/", response_model=list[ClaimOut])
async def list_claims(
    limit: int = Query(20, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_read),
):
    q = select(Claim).where(Claim.tenant_id == auth.tenant_id).limit(limit).offset(offset)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/", response_model=ClaimOut, status_code=201)
async def create_claim(
    body: ClaimCreate,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_write),
):
    # Build statement from subject/predicate/object if provided
    statement = body.statement
    if body.subject and body.predicate and body.object:
        statement = f"{body.subject} {body.predicate} {body.object}"
    claim = Claim(
        tenant_id=auth.tenant_id,
        statement=statement,
        claim_type=body.claim_type,
        confidence=body.confidence,
    )
    db.add(claim)
    await db.flush()
    await db.refresh(claim)
    return claim


class ClaimDetailOut(BaseModel):
    id: uuid.UUID
    entity_id: Optional[uuid.UUID] = None
    claim_type: str
    value: dict = {}
    confidence: float
    status: str
    created_at: Optional[datetime] = None
    model_config = {"from_attributes": True}


@router.get("/entity/{entity_id}", response_model=list[ClaimDetailOut])
async def list_entity_claims(
    entity_id: uuid.UUID,
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    auth = Depends(require_read),
):
    q = select(Claim).where(
        Claim.entity_id == entity_id,
        Claim.tenant_id == auth.tenant_id,
    ).order_by(Claim.created_at.desc()).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()
