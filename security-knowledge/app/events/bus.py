import asyncio
from typing import Callable, Awaitable
from app.events.types import BaseEvent
import structlog

logger = structlog.get_logger(__name__)

_subscribers: list[Callable[[BaseEvent], Awaitable[None]]] = []


def subscribe(handler: Callable[[BaseEvent], Awaitable[None]]) -> None:
    _subscribers.append(handler)


async def publish(event: BaseEvent) -> None:
    logger.debug("event_published", event_type=event.event_type, tenant=event.tenant_id)
    tasks = [asyncio.create_task(handler(event)) for handler in _subscribers]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
