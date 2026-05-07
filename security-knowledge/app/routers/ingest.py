from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional
import uuid
from app.database import get_db
from app.auth.dependencies import require_write
from app.services.ingestion import create_ingestion_job

router = APIRouter(prefix="/ingest", tags=["ingest"])


class IngestRequest(BaseModel):
    source_url: str
    source_type: str = "generic"
    priority: int = 5


class IngestOut(BaseModel):
    job_id: uuid.UUID
    status: str


@router.post("/", response_model=IngestOut, status_code=202)
async def ingest(
    body: IngestRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_write),
):
    job = await create_ingestion_job(db, auth["tenant_id"], body.source_url, body.source_type)
    return IngestOut(job_id=job.id, status=job.status)
