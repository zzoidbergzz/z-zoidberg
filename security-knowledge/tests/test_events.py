import pytest
import asyncio
from app.events.types import EntityCreatedEvent
from app.events.filters import matches_filter
from app.events import bus


def test_entity_created_event_defaults():
    event = EntityCreatedEvent(tenant_id="t1", payload={"entity_id": "e1"})
    assert event.event_type == "entity.created"
    assert event.tenant_id == "t1"


def test_filter_no_filters_passes_all():
    event = EntityCreatedEvent(tenant_id="t1")
    assert matches_filter(event, {}) is True


def test_filter_by_event_type_match():
    event = EntityCreatedEvent(tenant_id="t1")
    assert matches_filter(event, {"event_types": ["entity.created"]}) is True


def test_filter_by_event_type_no_match():
    event = EntityCreatedEvent(tenant_id="t1")
    assert matches_filter(event, {"event_types": ["claim.created"]}) is False


def test_filter_by_tenant():
    event = EntityCreatedEvent(tenant_id="t1")
    assert matches_filter(event, {"tenant_id": "t2"}) is False
    assert matches_filter(event, {"tenant_id": "t1"}) is True


@pytest.mark.asyncio
async def test_publish_to_subscriber():
    received = []
    
    async def handler(event):
        received.append(event)
    
    # Save original subscribers
    original = list(bus._subscribers)
    bus._subscribers.clear()
    bus.subscribe(handler)
    
    event = EntityCreatedEvent(tenant_id="t1")
    await bus.publish(event)
    
    assert len(received) == 1
    assert received[0].event_type == "entity.created"
    
    # Restore
    bus._subscribers.clear()
    bus._subscribers.extend(original)
