from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.digests import DigestSubscription, DigestRun
from app.digests.scheduler import is_due, compute_next_run
import structlog

logger = structlog.get_logger(__name__)


async def run_pending_digests(db: AsyncSession) -> int:
    result = await db.execute(select(DigestSubscription).where(DigestSubscription.active == True))  # noqa: E712
    subs = result.scalars().all()
    count = 0
    for sub in subs:
        if not is_due(sub):
            continue
        run = DigestRun(
            subscription_id=sub.id,
            tenant_id=sub.tenant_id,
            status="running",
        )
        db.add(run)
        await db.flush()
        try:
            # TODO: build digest content and dispatch
            run.status = "complete"
            run.item_count = 0
        except Exception as exc:
            run.status = "failed"
            run.error = str(exc)
            logger.error("digest_run_failed", sub_id=str(sub.id), error=str(exc))
        sub.next_run_at = compute_next_run(sub.frequency)
        count += 1
    await db.flush()
    return count
