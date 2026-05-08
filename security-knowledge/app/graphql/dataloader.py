import uuid
from typing import Any

from strawberry.dataloader import DataLoader


async def load_entities_by_ids(keys: list[uuid.UUID]) -> list[Any]:
    # Placeholder: in production, batch-load from DB
    return [None] * len(keys)


entity_loader = DataLoader(load_fn=load_entities_by_ids)
