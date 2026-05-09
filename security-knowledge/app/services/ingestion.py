"""Ingestion service — creates jobs and enqueues them to the ARQ worker.

OTel trace context is injected at enqueue time so the worker span is a child
of the current HTTP request span.
"""
from __future__ import annotations

import uuid

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.fetcher import validate_url_for_fetch
from app.models.jobs import IngestionJob
from app.observability.trace_propagation import get_traceparent

logger = structlog.get_logger(__name__)


async def create_ingestion_job(
    db: AsyncSession,
    tenant_id: str | uuid.UUID,
    source_url: str,
    source_type: str = "generic",
    priority: int = 5,
) -> IngestionJob:
    """Persist an IngestionJob row and enqueue it to the ARQ worker.

    The current OTel trace context is captured and stored in the job record
    so the worker can reconstruct the parent span when it picks up the job.
    """
    validation_error = await validate_url_for_fetch(source_url)
    if validation_error:
        raise ValueError(f"Invalid source_url: {validation_error}")

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

    # Enqueue to ARQ — inject OTel traceparent so worker span inherits context
    try:
        from arq import create_pool
        from arq.connections import RedisSettings
        from app.config import settings

        pool = await create_pool(RedisSettings.from_dsn(settings.REDIS_URL))
        await pool.enqueue_job(
            "process_ingest_job",
            str(job.id),
            _otel_ctx=get_traceparent(),
        )
        await pool.aclose()
    except Exception as exc:
        # Non-fatal: job is persisted in DB, can be retried manually
        logger.warning("arq_enqueue_failed", job_id=str(job.id), error=str(exc))

    return job


async def enqueue_enrichment(
    entity_id: str,
    tenant_id: str,
    provider: str = "all",
    force_refresh: bool = False,
) -> None:
    """Enqueue an enrichment job with trace context propagation."""
    try:
        from arq import create_pool
        from arq.connections import RedisSettings
        from app.config import settings

        pool = await create_pool(RedisSettings.from_dsn(settings.REDIS_URL))
        await pool.enqueue_job(
            "run_enrichment",
            entity_id,
            tenant_id,
            provider=provider,
            force_refresh=force_refresh,
            _otel_ctx=get_traceparent(),
        )
        await pool.aclose()
    except Exception as exc:
        logger.warning("arq_enrich_enqueue_failed", entity_id=entity_id, error=str(exc))


async def get_job(db: AsyncSession, job_id: uuid.UUID) -> IngestionJob | None:
    from sqlalchemy import select
    result = await db.execute(select(IngestionJob).where(IngestionJob.id == job_id))
    return result.scalar_one_or_none()
