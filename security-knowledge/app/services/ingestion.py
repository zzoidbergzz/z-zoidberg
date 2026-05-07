import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.jobs import IngestionJob
import structlog

logger = structlog.get_logger(__name__)


async def create_ingestion_job(
    db: AsyncSession,
    tenant_id: str | uuid.UUID,
    source_url: str,
    source_type: str = "generic",
    priority: int = 5,
) -> IngestionJob:
    job = IngestionJob(
        tenant_id=uuid.UUID(str(tenant_id)) if isinstance(tenant_id, str) else tenant_id,
        source_url=source_url,
        source_type=source_type,
        priority=priority,
        status="pending",
    )
    db.add(job)
    await db.flush()
    logger.info("ingestion_job_created", job_id=str(job.id), source_url=source_url)
    return job


async def get_job(db: AsyncSession, job_id: uuid.UUID) -> IngestionJob | None:
    from sqlalchemy import select
    result = await db.execute(select(IngestionJob).where(IngestionJob.id == job_id))
    return result.scalar_one_or_none()
