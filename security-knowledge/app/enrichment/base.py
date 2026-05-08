from abc import ABC, abstractmethod
from typing import Any


class BaseEnrichmentProvider(ABC):
    name: str = "base"
    kind: str = "generic"

    @abstractmethod
    async def enrich(self, entity_kind: str, entity_value: str) -> dict[str, Any]:
        ...

    async def health_check(self) -> bool:
        return True
