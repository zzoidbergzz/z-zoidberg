from typing import Type
from app.enrichment.base import BaseEnrichmentProvider

_registry: dict[str, Type[BaseEnrichmentProvider]] = {}


def register(cls: Type[BaseEnrichmentProvider]) -> Type[BaseEnrichmentProvider]:
    _registry[cls.name] = cls
    return cls


def get_provider(name: str) -> Type[BaseEnrichmentProvider] | None:
    return _registry.get(name)


def list_providers() -> list[str]:
    return list(_registry.keys())
