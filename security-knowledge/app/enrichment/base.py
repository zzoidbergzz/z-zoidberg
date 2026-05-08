from abc import ABC, abstractmethod
from typing import Any, ClassVar


class BaseEnrichmentProvider(ABC):
    name: str = "base"
    kind: str = "generic"
    # Set of canonical entity kinds this provider can enrich. Empty set
    # means "all kinds" for backward compatibility with providers that
    # have not yet declared support; new providers should always populate
    # this so dispatch can skip them for irrelevant lookups.
    supported_kinds: ClassVar[set[str]] = set()

    def __init__(self, api_key: str | None = None) -> None:
        # Optional per-call override for BYOK; providers that do not
        # honour user-supplied keys can ignore this.
        self.api_key_override = api_key

    @abstractmethod
    async def enrich(self, entity_kind: str, entity_value: str) -> dict[str, Any]:
        ...

    async def health_check(self) -> bool:
        return True
