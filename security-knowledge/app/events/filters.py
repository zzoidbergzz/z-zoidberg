from app.events.types import BaseEvent


def matches_filter(event: BaseEvent, filters: dict) -> bool:
    if not filters:
        return True
    event_types = filters.get("event_types", [])
    if event_types and event.event_type not in event_types:
        return False
    tenant = filters.get("tenant_id")
    if tenant and event.tenant_id != tenant:
        return False
    return True
