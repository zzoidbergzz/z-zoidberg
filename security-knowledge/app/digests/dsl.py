"""Simple DSL for digest query filters."""
from pydantic import BaseModel
from typing import Any


class DigestFilter(BaseModel):
    entity_kinds: list[str] = []
    keywords: list[str] = []
    min_confidence: int = 0
    since_days: int = 7
    tags: list[str] = []


def matches(entity: dict[str, Any], filt: DigestFilter) -> bool:
    if filt.entity_kinds and entity.get("kind") not in filt.entity_kinds:
        return False
    conf = entity.get("confidence", 0) or 0
    if conf < filt.min_confidence:
        return False
    if filt.keywords:
        text = (entity.get("name", "") + " " + (entity.get("description") or "")).lower()
        if not any(kw.lower() in text for kw in filt.keywords):
            return False
    return True
