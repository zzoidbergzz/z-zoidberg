from app.events.types import BaseEvent


def matches_filter(event: BaseEvent, filters: dict) -> bool:
    """Check if an event matches enrichment trigger filters."""
    if not filters:
        return True
    entity_kinds = filters.get("entity_kinds", [])
    if entity_kinds:
        payload_kind = event.payload.get("kind", "")
        if payload_kind not in entity_kinds:
            return False
    return True
