import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.webhooks import WebhookSubscription, WebhookDelivery
from app.events.types import BaseEvent
from app.events.filters import matches_filter
import structlog

logger = structlog.get_logger(__name__)


async def dispatch_webhooks(db: AsyncSession, event: BaseEvent) -> None:
    result = await db.execute(
        select(WebhookSubscription).where(
            WebhookSubscription.tenant_id == event.tenant_id,
            WebhookSubscription.active == True,  # noqa: E712
        )
    )
    subscriptions = result.scalars().all()

    for sub in subscriptions:
        if not matches_filter(event, sub.filters or {}):
            continue
        payload = event.model_dump(mode="json")
        delivery = WebhookDelivery(
            subscription_id=sub.id,
            payload=payload,
            status="pending",
        )
        db.add(delivery)
        await db.flush()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    sub.url,
                    json=payload,
                    headers={"X-Event-Type": event.event_type, "X-Delivery-Id": str(delivery.id)},
                )
                delivery.status = "success" if resp.status_code < 400 else "failed"
                delivery.response_status = resp.status_code
        except Exception as exc:
            delivery.status = "failed"
            delivery.error = str(exc)
            logger.warning("webhook_delivery_failed", subscription_id=str(sub.id), error=str(exc))
    await db.flush()
