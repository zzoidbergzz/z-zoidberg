from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
import uuid
from app.database import get_db
from app.auth.dependencies import require_read, require_write
from app.models.sources import SourceRecord

router = APIRouter(prefix="/sources", tags=["sources"])


class SourceOut(BaseModel):
    id: uuid.UUID
    url: str
    source_type: Optional[str]
    tenant_id: uuid.UUID
    model_config = {"from_attributes": True}


@router.get("/", response_model=list[SourceOut])
async def list_sources(
    limit: int = Query(20, le=200),
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_read),
):
    result = await db.execute(
        select(SourceRecord).where(SourceRecord.tenant_id == auth["tenant_id"]).limit(limit)
    )
    return result.scalars().all()
