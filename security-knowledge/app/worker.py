"""ARQ background worker."""
from arq import create_pool
from arq.connections import RedisSettings
from app.config import settings
import structlog

logger = structlog.get_logger(__name__)


async def process_ingest_job(ctx, job_id: str) -> dict:
    logger.info("processing_ingest_job", job_id=job_id)
    # TODO: full ingestion pipeline
    return {"job_id": job_id, "status": "complete"}


async def run_enrichment(ctx, entity_id: str, tenant_id: str) -> dict:
    logger.info("running_enrichment", entity_id=entity_id)
    return {"entity_id": entity_id, "status": "complete"}


async def send_digests(ctx) -> dict:
    logger.info("sending_digests")
    return {"status": "complete"}


async def startup(ctx):
    logger.info("worker_starting")


async def shutdown(ctx):
    logger.info("worker_stopping")


class WorkerSettings:
    functions = [process_ingest_job, run_enrichment, send_digests]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL)
    max_jobs = 10
    job_timeout = 300
