"""Pingback service: check watches and notify watchers on IOC sightings."""
from __future__ import annotations
import hashlib
import uuid
from datetime import datetime, timezone
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.pingback import IocWatch, IocSighting, IocContact
from app.models.digests import InboxItem
from app.models.sectors import Sector, SectorMembership
import structlog

logger = structlog.get_logger(__name__)


def _hash_ioc(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()


async def check_and_notify(
    ioc_value: str,
    ioc_kind: str,
    trigger: str,
    seeker_tenant_id: str,
    seeker_user_id: str | None,
    seeker_sector: str | None,
    seeker_comment: str | None,
    db: AsyncSession,
) -> int:
    """
    Looks up active watches for this IOC value hash.
    For each matching watch:
    - Creates IocSighting (increments watch.sighting_count, sets last_sighted_at)
    - If mode='contact' AND seeker_user_id is not the watcher: creates IocContact
    - Creates InboxItem for watcher
    - If sector context matches and info_sharing_enabled: sets sector_share='full'
    Returns count of watchers notified.
    """
    ioc_hash = _hash_ioc(ioc_value)
    now = datetime.now(timezone.utc)

    result = await db.execute(
        select(IocWatch).where(
            IocWatch.ioc_value_hash == ioc_hash,
            IocWatch.active == True,  # noqa: E712
        )
    )
    watches = result.scalars().all()

    count = 0
    for watch in watches:
        # Don't notify watcher if they are the seeker
        if seeker_user_id and str(watch.user_id) == seeker_user_id:
            continue

        # Determine sector sharing
        sector_share = "limited"
        if seeker_sector and watch.sector_context and seeker_sector == watch.sector_context:
            # Check sector info_sharing_enabled
            sector_result = await db.execute(
                select(Sector).where(Sector.slug == seeker_sector, Sector.active == True)  # noqa
            )
            sector = sector_result.scalar_one_or_none()
            if sector and sector.info_sharing_enabled:
                sector_share = "full"

        sighting = IocSighting(
            watch_id=watch.id,
            ioc_value_hash=ioc_hash,
            trigger=trigger,
            seeker_tenant_id=uuid.UUID(seeker_tenant_id) if seeker_tenant_id else None,
            seeker_message=seeker_comment,
            seen_at=now,
            delivered=False,
            seeker_sector=seeker_sector if sector_share == "full" else None,
            sector_share=sector_share,
            seeker_comment=seeker_comment if sector_share == "full" else None,
        )
        db.add(sighting)
        await db.flush()

        # Increment watch counters
        await db.execute(
            update(IocWatch)
            .where(IocWatch.id == watch.id)
            .values(
                sighting_count=IocWatch.sighting_count + 1,
                last_sighted_at=now,
            )
        )

        # Create contact if mode='contact'
        if watch.mode == "contact" and seeker_user_id:
            contact = IocContact(
                sighting_id=sighting.id,
                watch_id=watch.id,
                ioc_value_hash=ioc_hash,
                seeker_user_id=uuid.UUID(seeker_user_id),
                seeker_tenant_id=uuid.UUID(seeker_tenant_id) if seeker_tenant_id else None,
                watcher_user_id=watch.user_id,
                seeker_message=seeker_comment,
                status="pending",
                created_at=now,
                updated_at=now,
            )
            db.add(contact)
            await db.flush()

        # Create inbox item for watcher
        if watch.notify_inbox:
            inbox = InboxItem(
                tenant_id=watch.tenant_id,
                user_id=watch.user_id,
                subject=f"IOC Sighting: {watch.ioc_value_display}",
                body=f"A {trigger} event triggered a sighting on your watched IOC.",
                read=False,
                source_type="ping" if watch.mode == "ping" else "contact_request",
                metadata_={
                    "watch_id": str(watch.id),
                    "sighting_id": str(sighting.id),
                    "ioc_value_hash": ioc_hash,
                    "trigger": trigger,
                },
            )
            db.add(inbox)

        count += 1

    if count:
        await db.flush()

    return count
