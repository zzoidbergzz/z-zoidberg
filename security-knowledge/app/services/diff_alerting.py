"""Differential enrichment alerting service.

When ``force_refresh_enrichment()`` or a worker job detects that enrichment
data has changed for an IOC (new hash, IP moved ASN, domain expired, etc.),
this service:

1. Looks up all active ``IocWatch`` rows matching the IOC value hash.
2. Creates an ``InboxItem`` in the watcher's inbox for each watcher.
3. Fires any registered webhooks with event type ``enrichment.diff``.
4. Logs a structured event for OTel / SIEM downstream.

Privacy: The diff payload delivered to watchers never includes the raw
identity of who performed the refresh — only the change summary.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.digests import InboxItem
from app.models.pingback import IocWatch
from app.models.webhooks import WebhookSubscription, WebhookDelivery

logger = structlog.get_logger(__name__)


def _hash_ioc(value: str) -> str:
    return hashlib.sha256(value.lower().strip().encode()).hexdigest()


def _diff_human_summary(diff: dict[str, Any]) -> str:
    """Produce a short human-readable summary of a diff dict."""
    parts: list[str] = []
    if diff.get("added"):
        parts.append(f"{len(diff['added'])} field(s) added")
    if diff.get("removed"):
        parts.append(f"{len(diff['removed'])} field(s) removed")
    if diff.get("changed"):
        keys = ", ".join(list(diff["changed"].keys())[:5])
        parts.append(f"{len(diff['changed'])} field(s) changed ({keys})")
    return "; ".join(parts) if parts else "no changes"


async def notify_diff_watchers(
    *,
    entity_value: str,
    entity_kind: str,
    provider: str,
    diff_summary: dict[str, Any],
    has_changes: bool,
    diff_id: str | uuid.UUID | None = None,
    db: AsyncSession,
) -> int:
    """Notify all IOC watchers when enrichment data has changed.

    Args:
        entity_value: The raw IOC value (e.g. "1.2.3.4", "evil.com")
        entity_kind:  Entity kind string (e.g. "ip_address", "domain")
        provider:     Enrichment provider name (e.g. "shodan", "virustotal")
        diff_summary: Output of ``compute_diff()`` — {added, removed, changed}
        has_changes:  True if diff contains any actual changes
        diff_id:      Optional DB row ID of the EnrichmentDiff for linking
        db:           Async SQLAlchemy session

    Returns:
        Number of watchers notified.
    """
    if not has_changes:
        return 0

    value_hash = _hash_ioc(entity_value)
    human_summary = _diff_human_summary(diff_summary)

    # 1. Find all active watches for this IOC value
    result = await db.execute(
        select(IocWatch).where(
            IocWatch.ioc_value_hash == value_hash,
            IocWatch.active.is_(True),
        )
    )
    watches = result.scalars().all()

    if not watches:
        return 0

    notified = 0

    for watch in watches:
        subject = f"Enrichment change detected: {entity_kind} [{entity_value[:40]}]"
        body_data = {
            "event": "enrichment.diff",
            "entity_kind": entity_kind,
            "entity_value": entity_value,
            "provider": provider,
            "summary": human_summary,
            "diff": diff_summary,
            "diff_id": str(diff_id) if diff_id else None,
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }
        body_text = (
            f"An enrichment provider ({provider}) has reported changes for a "
            f"watched {entity_kind}.\n\n"
            f"Change summary: {human_summary}\n\n"
            f"This alert was generated automatically. No seeker identity is included."
        )

        # 2. Inbox notification
        if watch.notify_inbox:
            inbox_item = InboxItem(
                tenant_id=watch.tenant_id,
                user_id=watch.user_id,
                subject=subject,
                body=body_text,
                source_type="enrichment_diff",
                metadata_=body_data,
            )
            db.add(inbox_item)
            logger.info(
                "diff_alert_inbox",
                watch_id=str(watch.id),
                user_id=str(watch.user_id),
                provider=provider,
            )

        # 3. Webhook delivery
        if watch.notify_webhook:
            await _deliver_webhook_for_watch(
                watch=watch,
                event_type="enrichment.diff",
                payload=body_data,
                db=db,
            )

        notified += 1

    if notified:
        await db.flush()
        logger.info(
            "diff_alerts_sent",
            entity_kind=entity_kind,
            provider=provider,
            human_summary=human_summary,
            watchers_notified=notified,
        )

    return notified


async def _deliver_webhook_for_watch(
    *,
    watch,
    event_type: str,
    payload: dict[str, Any],
    db: AsyncSession,
) -> None:
    """Look up webhook subscriptions for the watcher's tenant and fire them."""

    result = await db.execute(
        select(WebhookSubscription).where(
            WebhookSubscription.tenant_id == watch.tenant_id,
            WebhookSubscription.active.is_(True),
        )
    )
    subs = result.scalars().all()

    for sub in subs:
        # Check event type filter
        if sub.event_types and event_type not in sub.event_types and "enrichment.diff" not in sub.event_types:
            continue

        t0 = time.monotonic()
        delivery = WebhookDelivery(
            subscription_id=sub.id,
            event_type=event_type,
            payload=payload,
            status="pending",
        )
        db.add(delivery)
        await db.flush()

        # Fire the webhook (best-effort, non-blocking to main request)
        try:
            import asyncio
            asyncio.create_task(
                _fire_webhook(delivery_id=delivery.id, sub=sub, payload=payload, db=db)
            )
        except RuntimeError:
            # No running event loop — skip (e.g. tests)
            pass


async def _fire_webhook(
    *,
    delivery_id: uuid.UUID,
    sub,
    payload: dict[str, Any],
    db: AsyncSession,
) -> None:
    """HTTP POST the webhook payload. Updates delivery row with result."""
    import hmac as _hmac

    t0 = time.monotonic()
    headers: dict[str, str] = {"Content-Type": "application/json", **(sub.headers or {})}

    if sub.secret:
        body_bytes = json.dumps(payload).encode()
        sig = _hmac.new(sub.secret.encode(), body_bytes, hashlib.sha256).hexdigest()
        headers["X-Signature-SHA256"] = f"sha256={sig}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(sub.url, json=payload, headers=headers)
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        result = await db.execute(
            select(WebhookDelivery).where(WebhookDelivery.id == delivery_id)
        )
        delivery = result.scalar_one_or_none()
        if delivery:
            delivery.status = "delivered" if resp.is_success else "failed"
            delivery.success = resp.is_success
            delivery.response_status = resp.status_code
            delivery.response_body = resp.text[:2000]
            delivery.duration_ms = elapsed_ms
            await db.flush()

        logger.info("webhook_delivered", url=sub.url, status=resp.status_code, elapsed_ms=elapsed_ms)
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        logger.warning("webhook_delivery_failed", url=sub.url, error=str(exc))
        try:
            result = await db.execute(
                select(WebhookDelivery).where(WebhookDelivery.id == delivery_id)
            )
            delivery = result.scalar_one_or_none()
            if delivery:
                delivery.status = "failed"
                delivery.success = False
                delivery.error = str(exc)
                delivery.duration_ms = elapsed_ms
                await db.flush()
        except Exception:
            pass
