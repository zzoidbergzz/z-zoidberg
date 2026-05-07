from pydantic import BaseModel
from typing import Any
import uuid
from datetime import datetime, timezone


class BaseEvent(BaseModel):
    event_id: str = str(uuid.uuid4())
    event_type: str
    occurred_at: datetime = datetime.now(timezone.utc)
    tenant_id: str
    payload: dict[str, Any] = {}


class EntityCreatedEvent(BaseEvent):
    event_type: str = "entity.created"


class EntityUpdatedEvent(BaseEvent):
    event_type: str = "entity.updated"


class ClaimCreatedEvent(BaseEvent):
    event_type: str = "claim.created"


class EnrichmentCompleteEvent(BaseEvent):
    event_type: str = "enrichment.complete"


class IngestJobCompleteEvent(BaseEvent):
    event_type: str = "ingest.job.complete"
