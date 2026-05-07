import structlog
import time
from app.observability.metrics import ingestion_jobs_total

logger = structlog.get_logger(__name__)


async def record_job_start(job_id: str, job_type: str) -> None:
    logger.info("job_started", job_id=job_id, job_type=job_type)


async def record_job_end(job_id: str, job_type: str, status: str, elapsed: float) -> None:
    ingestion_jobs_total.labels(status=status).inc()
    logger.info("job_ended", job_id=job_id, job_type=job_type, status=status, elapsed=elapsed)
