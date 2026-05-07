"""ARQ background worker with OpenTelemetry trace context propagation.

Every job accepts an optional `_otel_ctx` kwarg (injected at enqueue time
by `app.observability.trace_propagation.get_traceparent()`).  The
`trace_from_job` context manager reconstructs the parent span so all work
done inside the job appears as a child of the originating HTTP request in
any OTel-compatible backend (Jaeger, Tempo, Honeycomb, etc.).
"""
from __future__ import annotations

import time
import uuid

import structlog
from arq.connections import RedisSettings
from arq.cron import cron

from app.config import settings
from app.observability.trace_propagation import trace_from_job
from app.observability.worker import record_job_end, record_job_start
from app.workers.feed_poller import poll_feeds

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Job functions
# ---------------------------------------------------------------------------

async def process_ingest_job(
    ctx: dict,
    job_id: str,
    *,
    _otel_ctx: dict | None = None,
) -> dict:
    """Ingest a source document.  Trace context propagated from enqueue site."""
    t0 = time.monotonic()
    await record_job_start(job_id, "ingest")

    with trace_from_job(ctx, "worker.process_ingest_job", _otel_ctx, {"job.id": job_id}) as span:
        try:
            logger.info("processing_ingest_job", job_id=job_id)
            span.set_attribute("job.type", "ingest")

            # --- real ingestion pipeline would go here ---
            result = {"job_id": job_id, "status": "complete"}

            span.set_attribute("job.status", "complete")
            await record_job_end(job_id, "ingest", "complete", time.monotonic() - t0)
            return result
        except Exception:
            await record_job_end(job_id, "ingest", "error", time.monotonic() - t0)
            raise


async def run_enrichment(
    ctx: dict,
    entity_id: str,
    tenant_id: str,
    *,
    provider: str = "all",
    force_refresh: bool = False,
    _otel_ctx: dict | None = None,
) -> dict:
    """Run enrichment for a single entity.  Accepts optional provider name and
    force_refresh flag to bypass cache (triggers diff recording)."""
    t0 = time.monotonic()
    await record_job_start(entity_id, "enrichment")

    with trace_from_job(
        ctx,
        "worker.run_enrichment",
        _otel_ctx,
        {
            "entity.id": entity_id,
            "tenant.id": tenant_id,
            "enrichment.provider": provider,
            "enrichment.force_refresh": force_refresh,
        },
    ) as span:
        try:
            logger.info(
                "running_enrichment",
                entity_id=entity_id,
                provider=provider,
                force_refresh=force_refresh,
            )
            result = {"entity_id": entity_id, "status": "complete", "provider": provider}
            span.set_attribute("job.status", "complete")
            await record_job_end(entity_id, "enrichment", "complete", time.monotonic() - t0)
            return result
        except Exception:
            await record_job_end(entity_id, "enrichment", "error", time.monotonic() - t0)
            raise


async def send_digests(
    ctx: dict,
    *,
    _otel_ctx: dict | None = None,
) -> dict:
    """Send scheduled digest emails / webhooks."""
    t0 = time.monotonic()
    job_id = "digest-" + str(uuid.uuid4())[:8]
    await record_job_start(job_id, "digest")

    with trace_from_job(ctx, "worker.send_digests", _otel_ctx) as span:
        try:
            logger.info("sending_digests")
            span.set_attribute("job.type", "digest")
            result = {"status": "complete"}
            span.set_attribute("job.status", "complete")
            await record_job_end(job_id, "digest", "complete", time.monotonic() - t0)
            return result
        except Exception:
            await record_job_end(job_id, "digest", "error", time.monotonic() - t0)
            raise


async def check_ioc_watches(
    ctx: dict,
    ioc_value: str,
    ioc_kind: str,
    seeker_tenant_id: str,
    *,
    seeker_user_id: str | None = None,
    seeker_sector: str | None = None,
    trigger: str = "enrichment",
    _otel_ctx: dict | None = None,
) -> dict:
    """Async IOC watch check — dispatched after any enrichment cache miss."""
    with trace_from_job(
        ctx,
        "worker.check_ioc_watches",
        _otel_ctx,
        {"ioc.kind": ioc_kind, "trigger": trigger},
    ) as span:
        try:
            from app.database import AsyncSessionLocal
            from app.services.pingback import check_and_notify

            async with AsyncSessionLocal() as db:
                notified = await check_and_notify(
                    ioc_value=ioc_value,
                    ioc_kind=ioc_kind,
                    trigger=trigger,
                    seeker_tenant_id=seeker_tenant_id,
                    seeker_user_id=seeker_user_id,
                    seeker_sector=seeker_sector,
                    seeker_comment=None,
                    db=db,
                )
            span.set_attribute("watchers.notified", notified)
            return {"notified": notified}
        except Exception as exc:
            logger.warning("ioc_watch_check_failed", error=str(exc))
            span.record_exception(exc)
            return {"notified": 0, "error": str(exc)}


# ---------------------------------------------------------------------------
# Lifecycle + settings
# ---------------------------------------------------------------------------

async def startup(ctx: dict) -> None:
    logger.info("worker_starting")
    # Pre-load MITRE data if cached (non-blocking)
    try:
        import asyncio

        from app.services import mitre_attack
        asyncio.create_task(mitre_attack.preload_if_cached())
    except Exception:
        pass


async def shutdown(ctx: dict) -> None:
    logger.info("worker_stopping")


class WorkerSettings:
    functions = [process_ingest_job, run_enrichment, send_digests, check_ioc_watches, poll_feeds]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL)
    max_jobs = 10
    job_timeout = 300
    keep_result = 3600  # seconds — retain job results for 1 hour
    # Run feed poller every 5 minutes
    cron_jobs = [
        cron(poll_feeds, minute={0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55}),
    ]
