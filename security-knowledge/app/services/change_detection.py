import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.changes import Change
import structlog

logger = structlog.get_logger(__name__)


async def record_change(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    resource_type: str,
    resource_id: str,
    change_type: str,
    diff: dict,
    summary: str = "",
    source: str = "system",
    entity_id: uuid.UUID | None = None,
) -> Change:
    change = Change(
        tenant_id=tenant_id,
        resource_type=resource_type,
        resource_id=resource_id,
        change_type=change_type,
        diff=diff,
        summary=summary,
        source=source,
        entity_id=entity_id,
    )
    db.add(change)
    await db.flush()
    return change
