from fastapi import APIRouter, Depends, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from typing import Optional, List
import uuid
from datetime import datetime
from app.database import get_db
from app.auth.dependencies import require_write, get_auth, AuthContext
from app.services.ingestion import create_ingestion_job
from app.models.jobs import IngestionJob

router = APIRouter(prefix="/ingest", tags=["ingest"])


class IngestRequest(BaseModel):
    source_url: str
    source_type: str = "generic"
    priority: int = 5


class IngestOut(BaseModel):
    job_id: uuid.UUID
    status: str


class JobSummary(BaseModel):
    id: uuid.UUID
    status: str
    source_url: Optional[str]
    source_type: str
    created_at: datetime

    class Config:
        from_attributes = True


@router.post("/", response_model=IngestOut, status_code=202)
async def ingest(
    body: IngestRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_write),
):
    job = await create_ingestion_job(db, auth.tenant_id, body.source_url, body.source_type)
    return IngestOut(job_id=job.id, status=job.status)


@router.get("/jobs", response_model=List[JobSummary])
async def list_jobs(
    limit: int = Query(20, le=100),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
):
    result = await db.execute(
        select(IngestionJob)
        .where(IngestionJob.tenant_id == uuid.UUID(auth.tenant_id))
        .order_by(desc(IngestionJob.created_at))
        .limit(limit)
    )
    return result.scalars().all()
